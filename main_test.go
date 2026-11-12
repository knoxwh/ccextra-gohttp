package main

import (
	"bufio"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
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
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
