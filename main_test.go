package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// upstream: TLS server (cert valid for 127.0.0.1 and example.com) recording request headers.
func upstream(t *testing.T) (*httptest.Server, *x509.CertPool, chan http.Header) {
	seen := make(chan http.Header, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool, seen
}

func testTransport(pool *x509.CertPool) *transports {
	return &transports{base: func() *http.Transport {
		tr := newTransport()
		tr.TLSClientConfig.RootCAs = pool
		return tr
	}}
}

func do(tr *transports, target, proxy string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	req.Header.Set("X-Test", "1")
	if proxy != "" {
		req.Header.Set(proxyHeader, proxy)
	}
	rec := httptest.NewRecorder()
	forward(tr, rec, req)
	return rec
}

// fakeProxy counts accepted conns and records what each was asked to reach.
type fakeProxy struct {
	ln    net.Listener
	mu    sync.Mutex
	hits  int
	lines []string // CONNECT target or SOCKS5 destination as received
	auth  []string // Proxy-Authorization (CONNECT) or user:pass (SOCKS5)
}

func newFakeProxy(t *testing.T, handle func(*fakeProxy, net.Conn)) *fakeProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.hits++
			p.mu.Unlock()
			go handle(p, c)
		}
	}()
	return p
}

func (p *fakeProxy) record(line, auth string) {
	p.mu.Lock()
	p.lines = append(p.lines, line)
	p.auth = append(p.auth, auth)
	p.mu.Unlock()
}

func (p *fakeProxy) snapshot() (int, []string, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hits, append([]string(nil), p.lines...), append([]string(nil), p.auth...)
}

func pipe(a, b net.Conn) {
	go func() { io.Copy(a, b); a.Close() }()
	io.Copy(b, a)
	b.Close()
}

// HTTP CONNECT proxy: dial whatever it is asked to.
func connectHandler(p *fakeProxy, c net.Conn) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		c.Close()
		return
	}
	p.record(req.Host, req.Header.Get("Proxy-Authorization"))
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		c.Close()
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	pipe(c, up)
}

// SOCKS5 proxy (RFC 1928/1929); resolves FQDNs itself, mapping example.com -> 127.0.0.1.
func socksHandler(p *fakeProxy, c net.Conn) {
	defer c.Close()
	b := make([]byte, 262)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return
	}
	methods := make([]byte, b[1])
	io.ReadFull(c, methods)
	auth := ""
	if strings.Contains(string(methods), "\x02") {
		c.Write([]byte{5, 2})
		io.ReadFull(c, b[:2])
		user := make([]byte, b[1])
		io.ReadFull(c, user)
		io.ReadFull(c, b[:1])
		pass := make([]byte, b[0])
		io.ReadFull(c, pass)
		auth = string(user) + ":" + string(pass)
		c.Write([]byte{1, 0})
	} else {
		c.Write([]byte{5, 0})
	}
	if _, err := io.ReadFull(c, b[:4]); err != nil {
		return
	}
	var host string
	switch b[3] {
	case 1:
		io.ReadFull(c, b[:4])
		host = net.IP(b[:4]).String()
	case 3:
		io.ReadFull(c, b[:1])
		name := make([]byte, b[0])
		io.ReadFull(c, name)
		host = "fqdn:" + string(name)
	default:
		return
	}
	io.ReadFull(c, b[:2])
	port := binary.BigEndian.Uint16(b[:2])
	p.record(host, auth)
	dial := strings.TrimPrefix(host, "fqdn:")
	if dial == "example.com" {
		dial = "127.0.0.1"
	}
	up, err := net.Dial("tcp", net.JoinHostPort(dial, strconv.Itoa(int(port))))
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	pipe(c, up)
}

func assertNoProxyHeaders(t *testing.T, h http.Header) {
	t.Helper()
	if h.Get(proxyHeader) != "" || h.Get("Proxy-Authorization") != "" {
		t.Fatalf("proxy headers leaked upstream: %v", h)
	}
	if h.Get("X-Test") != "1" {
		t.Fatalf("normal header lost: %v", h)
	}
}

func TestHTTPConnectProxy(t *testing.T) {
	srv, pool, seen := upstream(t)
	p := newFakeProxy(t, connectHandler)
	rec := do(testTransport(pool), srv.URL+"/x", "http://user:secret@"+p.ln.Addr().String())
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	assertNoProxyHeaders(t, <-seen)
	hits, lines, auth := p.snapshot()
	if hits != 1 || lines[0] != strings.TrimPrefix(srv.URL, "https://") {
		t.Fatalf("proxy hits=%d lines=%v", hits, lines)
	}
	if auth[0] != "Basic dXNlcjpzZWNyZXQ=" { // user:secret
		t.Fatalf("proxy auth not sent to proxy")
	}
}

func TestSOCKS5HostnameResolvedByProxy(t *testing.T) {
	srv, pool, seen := upstream(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	for _, scheme := range []string{"socks5h", "socks5"} {
		p := newFakeProxy(t, socksHandler)
		rec := do(testTransport(pool), "https://example.com:"+port+"/x", scheme+"://u:pw@"+p.ln.Addr().String())
		if rec.Code != 200 {
			t.Fatalf("%s: got %d %q", scheme, rec.Code, rec.Body.String())
		}
		assertNoProxyHeaders(t, <-seen)
		_, lines, auth := p.snapshot()
		if len(lines) != 1 || lines[0] != "fqdn:example.com" {
			t.Fatalf("%s: hostname not sent to proxy: %v", scheme, lines)
		}
		if auth[0] != "u:pw" {
			t.Fatalf("%s: socks auth missing", scheme)
		}
	}
}

func TestMissingOrEmptyHeaderIsDirect(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	srv, pool, seen := upstream(t)
	for _, empty := range []bool{false, true} {
		req := httptest.NewRequest("GET", srv.URL+"/x", nil)
		req.Header.Set("X-Test", "1")
		if empty {
			req.Header.Set(proxyHeader, "")
		}
		rec := httptest.NewRecorder()
		forward(testTransport(pool), rec, req)
		if rec.Code != 200 {
			t.Fatalf("direct: got %d %q", rec.Code, rec.Body.String())
		}
		assertNoProxyHeaders(t, <-seen)
	}
}

func TestBadProxyRejectedWithoutDirect(t *testing.T) {
	srv, pool, seen := upstream(t)
	for _, v := range []string{"ftp://user:secret@127.0.0.1:1", "user:secret@127.0.0.1:1", "http://user:secret@", "://secret"} {
		rec := do(testTransport(pool), srv.URL+"/x", v)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%d for bad proxy", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Fatalf("credential echoed: %q", rec.Body.String())
		}
	}
	select {
	case <-seen:
		t.Fatal("bad proxy fell back to direct")
	default:
	}
}

func TestProxyErrorHasNoCredentials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // closed port -> dial error
	for _, scheme := range []string{"http", "https", "socks5h"} {
		rec := do(&transports{}, "https://example.com/x", scheme+"://user:s3cr%2Ft@"+addr)
		body := rec.Body.String()
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("%s: got %d %q", scheme, rec.Code, body)
		}
		if strings.Contains(body, "s3cr") || strings.Contains(body, "user") {
			t.Fatalf("%s: credential in error: %q", scheme, body)
		}
	}
}

// net/http's h2 pool is keyed by authority only: one shared Transport reused a
// direct h2 conn for later proxied requests. Each proxy must get its own conns.
func TestH2ConnsNotSharedAcrossProxies(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr := testTransport(pool) // one runtime pool for the whole sequence
	a := newFakeProxy(t, connectHandler)
	b := newFakeProxy(t, connectHandler)
	for i, proxy := range []string{"", "http://" + a.ln.Addr().String(), "http://" + b.ln.Addr().String(), "", "http://" + a.ln.Addr().String()} {
		rec := do(tr, srv.URL+"/"+strconv.Itoa(i), proxy)
		if rec.Code != 200 || rec.Body.String() != "HTTP/2.0" {
			t.Fatalf("req %d: got %d %q", i, rec.Code, rec.Body.String())
		}
	}
	ha, _, _ := a.snapshot()
	hb, _, _ := b.snapshot()
	if ha != 1 || hb != 1 { // A reused for its 2nd request; direct never through a proxy
		t.Fatalf("proxy A hits=%d, B hits=%d; want 1 and 1", ha, hb)
	}
}

func TestResponseHopHeadersStripped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Upstream-Hop")
		w.Header().Set("X-Upstream-Hop", "leak")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Kept", "1")
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	rec := do(testTransport(pool), srv.URL+"/x", "")
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	for _, h := range []string{"Connection", "Keep-Alive", "X-Upstream-Hop"} {
		if rec.Header().Get(h) != "" {
			t.Fatalf("%s relayed downstream", h)
		}
	}
	if rec.Header().Get("X-Kept") != "1" {
		t.Fatalf("normal response header lost: %v", rec.Header())
	}
}

func TestRequestConnectionTokensStripped(t *testing.T) {
	srv, pool, seen := upstream(t)
	req := httptest.NewRequest("GET", srv.URL+"/x", nil)
	req.Header.Set("Connection", "X-Drop-Me")
	req.Header.Set("X-Drop-Me", "leak")
	req.Header.Set("X-Test", "1")
	rec := httptest.NewRecorder()
	forward(testTransport(pool), rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	got := <-seen
	assertNoProxyHeaders(t, got)
	if got.Get("X-Drop-Me") != "" {
		t.Fatalf("Connection-listed header relayed upstream: %v", got)
	}
}

func TestBodyTooLarge(t *testing.T) {
	srv, pool, seen := upstream(t)
	req := httptest.NewRequest("POST", srv.URL+"/x", io.LimitReader(zeroReader{}, maxBodyBytes+1))
	rec := httptest.NewRecorder()
	forward(testTransport(pool), rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", rec.Code)
	}
	select {
	case <-seen:
		t.Fatal("oversized body reached upstream")
	default:
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

// ccextra sends no Accept-Encoding on purpose; net/http must add gzip upstream
// (matching the official language_server) and hand back decompressed bytes.
func TestGzipNegotiatedAndDecompressed(t *testing.T) {
	var enc atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc.Store(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, "data: 1\n\n")
		zw.Close()
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	rec := do(testTransport(pool), srv.URL+"/x", "")
	if rec.Code != 200 {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if got, _ := enc.Load().(string); got != "gzip" {
		t.Fatalf("upstream Accept-Encoding = %q, want gzip", got)
	}
	if body := rec.Body.String(); body != "data: 1\n\n" {
		t.Fatalf("body not decompressed: %q", body)
	}
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("Content-Encoding leaked for a decompressed body: %v", rec.Header())
	}
}

func startUnixSidecar(t *testing.T, pool *x509.CertPool) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gohttp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	tr := testTransport(pool)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forward(tr, w, r)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func dialUnixGet(t *testing.T, sock, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	host := strings.TrimPrefix(target, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: test\r\n\r\n", target, host); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	return c
}

func TestResponseHeadersFlushedBeforeBody(t *testing.T) {
	release := make(chan struct{})
	var closeOnce sync.Once
	t.Cleanup(func() { closeOnce.Do(func() { close(release) }) })

	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: 1\n\n")
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)

	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	c := dialUnixGet(t, startUnixSidecar(t, pool), up.URL+"/x")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("headers did not arrive before body: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	closeOnce.Do(func() { close(release) })
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "data: 1\n\n" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestUpstreamTruncateAbortsDownstream(t *testing.T) {
	run := func(t *testing.T, h2 bool) {
		gotFirst := make(chan struct{})
		var firstOnce sync.Once
		signalFirst := func() { firstOnce.Do(func() { close(gotFirst) }) }
		t.Cleanup(signalFirst)

		up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !h2 {
				c, bw, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				bw.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: 1\n\n\r\n")
				bw.Flush()
				select {
				case <-gotFirst:
				case <-time.After(5 * time.Second):
				}
				c.Close()
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: 1\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-gotFirst:
			case <-time.After(5 * time.Second):
			}
			panic(http.ErrAbortHandler)
		}))
		up.EnableHTTP2 = h2
		up.StartTLS()
		t.Cleanup(up.Close)

		pool := x509.NewCertPool()
		pool.AddCert(up.Certificate())
		c := dialUnixGet(t, startUnixSidecar(t, pool), up.URL+"/x")
		var out []byte
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				out = append(out, buf[:n]...)
				if strings.Contains(string(out), "data: 1") {
					signalFirst()
				}
			}
			if err != nil {
				break
			}
		}
		raw := string(out)
		if !strings.Contains(raw, "data: 1") {
			t.Fatalf("missing initial chunk before abort: %q", raw)
		}
		if strings.HasSuffix(raw, "0\r\n\r\n") {
			t.Fatalf("downstream received clean chunked EOF on upstream abort: %q", raw)
		}
	}

	t.Run("h1", func(t *testing.T) { run(t, false) })
	t.Run("h2", func(t *testing.T) { run(t, true) })
}

func TestH2PingReplacesFrozenConn(t *testing.T) {
	if h2 := newTransport().HTTP2; h2 == nil || h2.SendPingTimeout != 15*time.Second || h2.PingTimeout != 5*time.Second {
		t.Fatalf("newTransport HTTP2 ping config = %+v, want SendPingTimeout 15s, PingTimeout 5s", h2)
	}

	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	var conns atomic.Int32
	var freezeFirst atomic.Bool
	unblock := make(chan struct{})
	var relayMu sync.Mutex
	var relayConns []net.Conn
	t.Cleanup(func() {
		close(unblock)
		relayMu.Lock()
		defer relayMu.Unlock()
		for _, c := range relayConns {
			c.Close()
		}
	})

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id := conns.Add(1)
			s, err := net.Dial("tcp", up.Listener.Addr().String())
			if err != nil {
				c.Close()
				continue
			}
			relayMu.Lock()
			relayConns = append(relayConns, c, s)
			relayMu.Unlock()
			relay := func(dst, src net.Conn) {
				buf := make([]byte, 32*1024)
				for {
					n, err := src.Read(buf)
					if n > 0 {
						if id == 1 && freezeFirst.Load() {
							<-unblock
							return
						}
						if _, werr := dst.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			go relay(s, c)
			go relay(c, s)
		}
	}()

	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	tr := &transports{base: func() *http.Transport {
		x := newTransport()
		x.TLSClientConfig.RootCAs = pool
		x.HTTP2 = &http.HTTP2Config{SendPingTimeout: 40 * time.Millisecond, PingTimeout: 40 * time.Millisecond}
		return x
	}}

	target := "https://" + ln.Addr().String() + "/ping"
	if rec := do(tr, target, ""); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("first req failed: %d %q", rec.Code, rec.Body.String())
	}
	freezeFirst.Store(true)

	var lastCode int
	var lastBody string
	for range 20 {
		rec := do(tr, target, "")
		lastCode, lastBody = rec.Code, rec.Body.String()
		if lastCode == http.StatusOK && lastBody == "ok" && conns.Load() >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("did not recover via new h2 conn (conns=%d last=%d %q)", conns.Load(), lastCode, lastBody)
}

func TestH2PostBodyReplayedOnRefusedStream(t *testing.T) {
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		io.WriteString(w, "replayed:"+string(b))
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	tlsCfg := up.TLS.Clone()
	tlsCfg.NextProtos = []string{"h2"}

	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if conns.Add(1) == 1 {
				go handleRefusedPostH2Conn(tls.Server(c, tlsCfg))
				continue
			}
			s, err := net.Dial("tcp", up.Listener.Addr().String())
			if err != nil {
				c.Close()
				continue
			}
			go pipe(c, s)
		}
	}()

	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	tr := testTransport(pool)
	target := "https://" + ln.Addr().String()

	if rec := do(tr, target+"/1", ""); rec.Code != http.StatusOK || rec.Body.String() != "replayed:" {
		t.Fatalf("warmup req: %d %q", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, target+"/2", strings.NewReader("hello=world"))
	rec := httptest.NewRecorder()
	forward(tr, rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "replayed:hello=world" {
		t.Fatalf("post replay failed: %d %q (conns=%d)", rec.Code, rec.Body.String(), conns.Load())
	}
	if conns.Load() < 2 {
		t.Fatalf("expected retry on new conn, conns=%d", conns.Load())
	}
}

func handleRefusedPostH2Conn(c net.Conn) {
	defer c.Close()
	preface := make([]byte, 24)
	if _, err := io.ReadFull(c, preface); err != nil {
		return
	}
	c.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}) // empty server SETTINGS

	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		sid := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
		payload := make([]byte, n)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
		if typ == 4 && flags&1 == 0 {
			c.Write([]byte{0, 0, 0, 4, 1, 0, 0, 0, 0}) // SETTINGS ACK
		} else if sid == 1 && flags&1 != 0 {
			c.Write([]byte{0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88})                           // HEADERS :status 200
			c.Write(append([]byte{0, 0, 9, 0, 1, 0, 0, 0, 1}, []byte("replayed:")...)) // DATA END_STREAM
		} else if sid == 3 && typ == 0 && flags&1 != 0 {
			c.Write([]byte{0, 0, 4, 3, 0, 0, 0, 0, 3, 0, 0, 0, 7})             // RST_STREAM REFUSED_STREAM
			c.Write([]byte{0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}) // GOAWAY LastStreamID=1
		}
	}
}
