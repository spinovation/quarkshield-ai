#!/bin/sh
# Generate the origin TLS keypair on first start if none was mounted. Cloudflare
# "Full" mode only needs a valid-looking cert at the origin; mount a real one at
# /app/certs to replace it.
set -e
CERT="${SSL_CERT_PATH:-/app/certs/cert.pem}"
KEY="${SSL_KEY_PATH:-/app/certs/key.pem}"
if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
  mkdir -p "$(dirname "$CERT")"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 825 \
    -subj "/CN=${TLS_CN:-quarkshield.ai}" >/dev/null 2>&1
  chmod 600 "$KEY"
fi
exec "$@"
