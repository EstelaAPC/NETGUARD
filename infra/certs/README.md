# Certificados locais do NetGuard

O ambiente Docker usa Caddy com `tls internal`, entao os certificados reais sao gerados em runtime no volume Docker `caddy_data`.

Nao versionar arquivos `.key`, `.crt`, `.pem` ou `.pfx` reais nesta pasta.

Para gerar um certificado local opcional fora do Caddy, use:

```bash
./scripts/generate-local-cert.sh
```

No Windows:

```powershell
.\scripts\generate-local-cert.ps1
```

Esses scripts gravam artefatos em `infra/certs/local/`, que fica ignorado pelo Git.
