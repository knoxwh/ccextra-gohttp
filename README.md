# ccextra-gohttp

Tiny sidecar: takes HTTP/1.1 requests on a local Unix socket and sends them to the
target over HTTPS with Go's standard `net/http` (default Go TLS ClientHello, HTTP/2 on,
no session cache). Stdlib only.

Build: `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o ccextra-gohttp .`
The ClientHello comes from the Go toolchain: after a rebuild or Go upgrade, run
`./ja4test/run.sh` and check JA4 still matches the target it prints.

Run: `./ccextra-gohttp -socket /path/to/private/dir/gohttp.sock`
(dir created 0700, socket 0600, removed on SIGINT/SIGTERM; no TCP listener; exits if
the socket is already served by another instance). With `-exit-on-stdin-eof` it also
exits (removing the socket) once stdin reaches EOF: ccextra passes it and keeps the pipe's
write end, so the sidecar follows its parent even after kill -9. Off by default.

Protocol: send an absolute-form request line, e.g. `POST https://host/path HTTP/1.1`, with
the real headers/body; status, headers and body (streamed, SSE ok) come back as-is.
Redirects are not followed. Hop-by-hop headers (and any header named in `Connection`) are
dropped in both directions. Compression is negotiated by net/http as usual: if the caller
sends no `Accept-Encoding`, `gzip` is advertised upstream and the response is decompressed
(and `Content-Encoding` removed) before it is relayed, matching the official
language_server. Request bodies are buffered so they can be replayed on HTTP/2 retries,
capped at 32 MiB (413 beyond that).
Request headers must arrive within 10s; idle client connections close after 90s.

Proxy: optional per-request header `X-Ccextra-Proxy: <url>` (`http`, `https`, `socks5`,
`socks5h`). Missing/empty = direct. Environment proxies (`HTTP(S)_PROXY`, `ALL_PROXY`) are
never read. https targets go through http(s) proxies via CONNECT; for SOCKS5 the hostname is
sent to the proxy (remote DNS for both `socks5` and `socks5h`). Any other value -> 400, no
direct fallback. The header is stripped before forwarding and never logged or echoed.
Example:
`curl --unix-socket gohttp.sock --request-target https://www.google.com/generate_204 http://x/`

JA4 loopback test: `./ja4test/run.sh` (needs python3 + openssl). Expected:
`t13d1312h2_f57a46bbacb6_f50d94e863eb` (JA3 `03117a8ed39ef02427ebbc39f121275c`).
The client's cert check fails on purpose after the ClientHello is captured.
`VIA_CONNECT=1 ./ja4test/run.sh` runs the same capture through a local HTTP CONNECT proxy.
