#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/infra/certs/local"
CONF="$OUT_DIR/netguard-local-openssl.cnf"

mkdir -p "$OUT_DIR"

cat > "$CONF" <<'EOF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = 192.168.56.15
O = NetGuard Local

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = 192.168.56.15
DNS.1 = localhost
DNS.2 = netguard.local
EOF

openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout "$OUT_DIR/netguard-local.key" \
  -out "$OUT_DIR/netguard-local.crt" \
  -config "$CONF"

printf 'Certificado local gerado em %s\n' "$OUT_DIR"
