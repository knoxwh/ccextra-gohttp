#!/bin/sh
# Loopback JA4: sidecar -> local TLS capture server (self-signed; client verify is
# expected to fail AFTER the ClientHello is captured, so no InsecureSkipVerify).
# VIA_CONNECT=1: go through a local HTTP CONNECT proxy (X-Ccextra-Proxy header).
set -e
D=$(cd "$(dirname "$0")" && pwd); T=$(mktemp -d); PORT=${PORT:-18443}
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 \
  -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
(cd "$D/.." && CGO_ENABLED=0 go build -o "$T/gohttp" .)
"$T/gohttp" -socket "$T/s/gohttp.sock" & SP=$!
python3 "$D/cap.py" "$PORT" "$T/hello.json" "$T" & CP=$!
PH=
if [ -n "$VIA_CONNECT" ]; then
  PPORT=${PPORT:-18080}; python3 -u "$D/connect.py" "$PPORT" >"$T/proxy.log" & PP=$!
  PH="X-Ccextra-Proxy: http://127.0.0.1:$PPORT"
fi
sleep 1
curl -s --unix-socket "$T/s/gohttp.sock" ${PH:+-H "$PH"} --request-target "https://localhost:$PORT/ja4" http://x/ || true
[ -n "$PP" ] && kill $PP 2>/dev/null
echo; wait $CP; kill $SP; wait $SP 2>/dev/null || true
echo "go: $(go version)"; ls -ld "$T/s"
echo "target JA4: t13d1312h2_f57a46bbacb6_f50d94e863eb  JA3: 03117a8ed39ef02427ebbc39f121275c"
if [ -n "$VIA_CONNECT" ]; then # the JA4 above only counts if it went through the tunnel
  cat "$T/proxy.log"
  grep -q '^proxy got: CONNECT ' "$T/proxy.log" || { echo "FAIL: request did not go through the CONNECT proxy" >&2; rm -rf "$T"; exit 1; }
fi
rm -rf "$T"
