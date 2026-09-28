$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$outDir = Join-Path $root "infra\certs\local"
$conf = Join-Path $outDir "netguard-local-openssl.cnf"

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

@"
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
"@ | Set-Content -LiteralPath $conf -Encoding ASCII

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "OpenSSL nao encontrado no PATH. Instale OpenSSL ou use o certificado interno gerado pelo Caddy em runtime."
}

& openssl req -x509 -nodes -newkey rsa:2048 -days 825 `
    -keyout (Join-Path $outDir "netguard-local.key") `
    -out (Join-Path $outDir "netguard-local.crt") `
    -config $conf

Write-Host "Certificado local gerado em $outDir"
