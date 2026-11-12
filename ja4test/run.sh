#!/bin/sh
# Loopback JA4: sidecar -> local TLS capture server (self-signed; client verify is
# expected to fail AFTER the ClientHello is captured, so no InsecureSkipVerify).
set -e
D=$(cd "$(dirname "$0")" && pwd); T=$(mktemp -d); PORT=${PORT:-18443}
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 \
  -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
(cd "$D/.." && CGO_ENABLED=0 go build -o "$T/gohttp" .)
"$T/gohttp" -socket "$T/s/gohttp.sock" & SP=$!
python3 "$D/cap.py" "$PORT" "$T/hello.json" "$T" & CP=$!
sleep 1
curl -s --unix-socket "$T/s/gohttp.sock" --request-target "https://localhost:$PORT/ja4" http://x/ || true
echo; wait $CP; kill $SP; wait $SP 2>/dev/null || true
echo "go: $(go version)"; ls -ld "$T/s"
echo "target JA4: t13d1312h2_f57a46bbacb6_f50d94e863eb  JA3: 03117a8ed39ef02427ebbc39f121275c"
rm -rf "$T"
