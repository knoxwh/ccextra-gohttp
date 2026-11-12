// ccextra-gohttp: forwards absolute-form HTTP/1.1 requests received on a
// local Unix socket to their https:// target using Go's default net/http TLS.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

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

	tr := http.DefaultTransport.(*http.Transport).Clone()     // HTTP/2 stays on (ForceAttemptHTTP2)
	tr.Proxy = nil                                            // v1: direct only
	tr.TLSClientConfig = &tls.Config{ClientSessionCache: nil} // no resumption -> no ext 35/41

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; ln.Close(); os.Remove(*sock); os.Exit(0) }()

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forward(tr, w, r)
	})))
}

func forward(tr *http.Transport, w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme != "https" || r.URL.Host == "" {
		http.Error(w, "request-target must be absolute https:// URL", http.StatusBadRequest)
		return
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out.ContentLength = r.ContentLength
	out.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}

	resp, err := tr.RoundTrip(out) // no redirect following: status passed through as-is
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
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
