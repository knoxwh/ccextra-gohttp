# ccextra-gohttp

Tiny sidecar: takes HTTP/1.1 requests on a local Unix socket and sends them to the
target over HTTPS with Go's standard `net/http` (default Go TLS ClientHello, HTTP/2 on,
no session cache, direct connection, no proxy). Stdlib only.

Build: `CGO_ENABLED=0 go build -o ccextra-gohttp .`

Run: `./ccextra-gohttp -socket /path/to/private/dir/gohttp.sock`
(dir created 0700, socket 0600, removed on SIGINT/SIGTERM; no TCP listener)

Protocol: send an absolute-form request line, e.g. `POST https://host/path HTTP/1.1`, with
the real headers/body; status, headers and body (streamed, SSE ok) come back as-is.
Redirects are not followed. Example:
`curl --unix-socket gohttp.sock --request-target https://www.google.com/generate_204 http://x/`

JA4 loopback test: `./ja4test/run.sh` (needs python3 + openssl). Expected:
`t13d1312h2_f57a46bbacb6_f50d94e863eb` (JA3 `03117a8ed39ef02427ebbc39f121275c`).
The client's cert check fails on purpose after the ClientHello is captured.
