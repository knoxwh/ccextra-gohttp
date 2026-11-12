// ccextra-gohttp: forwards absolute-form HTTP/1.1 requests received on a
// local Unix socket to their https:// target using Go's default net/http TLS.
// An optional per-request X-Ccextra-Proxy header selects an outbound proxy.
package main

import (
	"crypto/tls"
	"flag"
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
)

// proxyHeader carries the proxy URL already resolved by ccextra (http, https,
// socks5, socks5h). Missing/empty = direct. Stripped before forwarding; its
// value is never logged or echoed (it may hold credentials).
const proxyHeader = "X-Ccextra-Proxy"

var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

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

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forward(tr, w, r)
	})))
}

func newTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()     // HTTP/2 stays on (ForceAttemptHTTP2)
	tr.Proxy = nil                                            // never the environment; set per proxy in transports.get
	tr.TLSClientConfig = &tls.Config{ClientSessionCache: nil} // no resumption -> no ext 35/41
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
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out.ContentLength = r.ContentLength
	out.Header = r.Header.Clone()
	out.Header.Del(proxyHeader)
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}

	resp, err := p.get(raw, proxy).RoundTrip(out) // no redirect following: status passed through as-is
	if err != nil {
		http.Error(w, redact(err.Error(), proxy), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	rc := http.NewResponseController(w)
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
			return
		}
	}
}
