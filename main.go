// ccextra-gohttp is ccextra's HTTP sidecar.
//
// It accepts HTTP/1.1 requests on a local Unix socket, in absolute form
// ("POST https://host/path HTTP/1.1"), and performs them over HTTPS with Go's
// stock net/http client and TLS stack. Responses are relayed as they arrive;
// redirects are not followed. An optional per-request X-Ccextra-Proxy header
// selects an outbound proxy.
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// proxyHeader carries the proxy URL already resolved by ccextra (http, https,
// socks5, socks5h). Missing/empty = direct. Stripped before forwarding; its
// value is never logged or echoed (it may hold credentials).
const proxyHeader = "X-Ccextra-Proxy"

// hopHeaders are connection-scoped and must not be relayed in either direction
// (RFC 9110 §7.6.1); net/http rebuilds Transfer-Encoding framing on each side.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// maxBodyBytes caps buffered request bodies. Bodies are read fully so that
// http.NewRequest can set GetBody and the HTTP/2 layer can replay the request
// on a REFUSED_STREAM; streams that exceed the cap are rejected rather than
// spooled to disk.
const maxBodyBytes = 32 << 20

func main() {
	sock := flag.String("socket", "", "Unix socket path (required)")
	flag.Parse()
	if *sock == "" {
		log.Fatal("-socket is required")
	}

	syscall.Umask(0o077) // new dir -> 0700, socket -> 0600
	if err := os.MkdirAll(filepath.Dir(*sock), 0o700); err != nil {
		log.Fatal(err)
	}
	// A stale socket file is fine to replace; a live one means another sidecar
	// owns it, and silently unlinking it would split traffic between instances.
	if c, err := net.Dial("unix", *sock); err == nil {
		c.Close()
		log.Fatalf("socket %s already in use", *sock)
	}
	os.Remove(*sock)
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*sock, 0o600); err != nil {
		log.Fatal(err)
	}

	tr := &transports{}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; ln.Close(); os.Remove(*sock); os.Exit(0) }()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forward(tr, w, r)
		}),
		// Slow-client guard only. ReadTimeout/WriteTimeout stay 0: request bodies
		// and response streams (SSE) may legitimately live for a long time.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	log.Fatal(srv.Serve(ln))
}

func newTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone() // HTTP/2 stays on (ForceAttemptHTTP2)
	tr.Proxy = nil                                        // never the environment; set per proxy in transports.get
	// No TLS session resumption: keeps the ClientHello stable for JA4 pinning
	// (no session_ticket / pre_shared_key extensions).
	tr.TLSClientConfig = &tls.Config{ClientSessionCache: nil}
	// Keep compression on: ccextra relies on net/http's gzip negotiation
	// (see TestGzipNegotiatedAndDecompressed).
	tr.HTTP2 = &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 5 * time.Second}
	return tr
}

// transports holds one Transport per proxy (key = raw header value, "" = direct).
// net/http's HTTP/2 pool is keyed by target authority only, so a shared Transport
// would reuse an h2 conn across proxies (or direct); one Transport each isolates them.
// socks5/socks5h: net/http's SOCKS5 client sends the hostname to the proxy
// (remote DNS); https via http(s) proxy uses CONNECT.
type transports struct {
	mu   sync.Mutex
	m    map[string]*http.Transport
	base func() *http.Transport // nil = newTransport (tests swap in custom RootCAs)
}

func (p *transports) get(key string, u *url.URL) *http.Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	if tr := p.m[key]; tr != nil {
		return tr
	}
	mk := p.base
	if mk == nil {
		mk = newTransport
	}
	tr := mk()
	tr.Proxy = http.ProxyURL(u) // u == nil -> (nil, nil) = direct
	if p.m == nil {
		p.m = make(map[string]*http.Transport)
	}
	p.m[key] = tr
	return tr
}

// parseProxy validates the header value; errors never include the value.
func parseProxy(v string) (*url.URL, bool) {
	if v == "" {
		return nil, true
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return nil, false
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
		return u, true
	}
	return nil, false
}

// redact removes proxy userinfo from an error message.
func redact(msg string, u *url.URL) string {
	if u == nil || u.User == nil {
		return msg
	}
	msg = strings.ReplaceAll(msg, u.User.String(), "***")
	if p, ok := u.User.Password(); ok && p != "" {
		msg = strings.ReplaceAll(msg, p, "***")
	}
	return msg
}

func forward(p *transports, w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme != "https" || r.URL.Host == "" {
		http.Error(w, "request-target must be absolute https:// URL", http.StatusBadRequest)
		return
	}
	raw := r.Header.Get(proxyHeader)
	proxy, ok := parseProxy(raw)
	if !ok {
		http.Error(w, "invalid "+proxyHeader+" (want http/https/socks5/socks5h URL)", http.StatusBadRequest)
		return
	}
	var body io.Reader
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(b) > maxBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		body = bytes.NewReader(b) // replayable: NewRequest sets GetBody for *bytes.Reader
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out.Header = r.Header.Clone()
	out.Header.Del(proxyHeader)
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	dropConnectionTokens(out.Header, r.Header)

	resp, err := p.get(raw, proxy).RoundTrip(out) // no redirect following: status passed through as-is
	if err != nil {
		http.Error(w, redact(err.Error(), proxy), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	for _, h := range hopHeaders {
		w.Header().Del(h) // upstream's framing/connection headers must not be replayed
	}
	dropConnectionTokens(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	rc := http.NewResponseController(w)
	rc.Flush() // forward response headers before waiting for first body chunk
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			rc.Flush() // keep SSE streaming
		}
		if err != nil {
			if err != io.EOF {
				panic(http.ErrAbortHandler)
			}
			return
		}
	}
}

// dropConnectionTokens deletes from dst the extra per-hop header names that
// src's Connection header lists.
func dropConnectionTokens(dst, src http.Header) {
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				dst.Del(name)
			}
		}
	}
}
