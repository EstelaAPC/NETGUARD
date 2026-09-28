# HTTPS do NetGuard

Data da revisao: 2026-05-08

## Arquitetura

O acesso oficial da plataforma passa pelo container `reverse-proxy`, baseado em Caddy:

- `https://netguard.local/` entrega o frontend React e e o acesso oficial recomendado.
- `https://192.168.56.15/` tambem entrega o frontend React.
- `https://192.168.56.15/api/*` roteia para a FastAPI interna `api:8000`.
- `https://netguard.local/grafana/` roteia para o Grafana interno `grafana:3000`.
- `http://192.168.56.15/` redireciona para HTTPS com status `308`.

No Compose atual, a configuracao versionada do Caddy fica em `infra/Caddyfile.runtime`. Os caminhos antigos `infra/caddy/Caddyfile` e `infra/caddy-runtime/Caddyfile` nao devem ser usados neste ambiente porque podem existir como diretorios locais criados com permissao de `root` na VM.

As portas diretas antigas continuam expostas para debug:

- frontend direto: `https://192.168.56.15:8081`
- API direta: `http://192.168.56.15:8000`
- Grafana direto: `http://192.168.56.15:3000`
- syslog UDP: `514`
- banco: `5432`

Use `https://netguard.local/` como caminho oficial para operacao e demonstracao.

Observacao: a porta direta `8081` do frontend usa HTTPS. `http://192.168.56.15:8081` retorna erro de protocolo e nao deve ser usado.

## Por que Caddy

O Caddy foi escolhido porque simplifica HTTPS em laboratorio Docker, consegue emitir certificados locais com `tls internal`, faz reverse proxy com pouca configuracao e permite migrar para ACME/Let's Encrypt em producao sem trocar a arquitetura.

## Certificado local

Para o IP local `192.168.56.15`, o Compose usa `tls internal` no Caddy. O certificado real e gerado em runtime e fica no volume Docker `netguard_caddy_data`.

Nao versionar chaves privadas. A pasta `infra/certs/` existe apenas para documentacao e certificados locais gerados manualmente, que ficam ignorados pelo Git.

Scripts opcionais para gerar certificado local manual:

```bash
./scripts/generate-local-cert.sh
```

```powershell
.\scripts\generate-local-cert.ps1
```

O navegador pode exibir `NET::ERR_CERT_AUTHORITY_INVALID` enquanto a CA local do Caddy nao estiver instalada no Windows. Esse aviso e esperado em laboratorio ate a importacao da CA local.

## Confiar no certificado no Windows

Opcao simples para laboratorio: abrir `https://192.168.56.15/`, avancar pelo aviso do navegador e validar a plataforma.

Opcao mais limpa: exportar a CA local do volume do Caddy e importar em "Autoridades de Certificacao Raiz Confiaveis" no Windows. O arquivo fica dentro do volume `netguard_caddy_data`, em caminho equivalente a:

```text
/data/caddy/pki/authorities/local/root.crt
```

No projeto, a CA publica exportada fica em:

```text
infra/certs/netguard-caddy-root.crt
```

Somente importe certificados de ambientes que voce controla. Nunca copie ou importe `root.key` nem arquivos `.key`; eles sao chaves privadas.

Passo a passo no Windows:

1. Pressione `Win + R`.
2. Execute `certmgr.msc`.
3. Abra `Autoridades de Certificacao Raiz Confiaveis`.
4. Abra `Certificados`.
5. Clique com o botao direito em `Certificados`.
6. Selecione `Todas as tarefas`.
7. Selecione `Importar`.
8. Escolha `infra/certs/netguard-caddy-root.crt`.
9. Conclua o assistente.
10. Reinicie o navegador.

## Nome local no Windows

O Caddy aceita `netguard.local` e `netguard` no certificado local. Para usar o nome no Windows, crie uma entrada DNS local ou adicione ao arquivo `hosts` do Windows, em modo administrador:

```text
192.168.56.15 netguard.local
192.168.56.15 netguard
```

Depois acesse:

```text
https://netguard.local/
```

Se o nome nao resolver, o navegador nao chega ao NetGuard. Se o nome resolver mas a CA ainda nao estiver importada, o aviso `NET::ERR_CERT_AUTHORITY_INVALID` continua aparecendo.

## Variaveis importantes

```env
NETGUARD_PUBLIC_URL=https://netguard.local
NETGUARD_CORS_ORIGINS=https://192.168.56.15,https://netguard.local,https://netguard,https://localhost,https://localhost:8081,https://127.0.0.1:8081,https://192.168.56.15:8081
VITE_API_URL=/api
GRAFANA_PUBLIC_URL=/grafana
GRAFANA_ROOT_URL=https://netguard.local/grafana/
```

O frontend deve usar `/api`, evitando mixed content e evitando chamadas diretas para `http://192.168.56.15:8000`.
O embed do Grafana tambem deve usar `/grafana`, pela mesma origem do frontend. Evite configurar `GRAFANA_PUBLIC_URL` com `https://192.168.56.15/grafana` quando o acesso oficial for `https://netguard.local/`, porque o navegador bloqueia iframe cross-origin com `X-Frame-Options: SAMEORIGIN`.

## Validacao

```bash
docker compose -p netguard config --quiet
docker compose -p netguard up -d --build
docker compose -p netguard ps -a
```

```bash
curl -I http://192.168.56.15/
curl -k -I https://192.168.56.15/
curl -k https://192.168.56.15/api/health
curl -k https://192.168.56.15/api/health/deep
curl -k https://192.168.56.15/api/alerts/summary
curl -k https://192.168.56.15/api/alerts/channels
curl -k https://192.168.56.15/api/alerts/incidents
curl -k https://192.168.56.15/api/alerts/notifications
curl -k https://192.168.56.15/api/housekeeper/status
curl -k -I https://192.168.56.15/grafana/
curl -k -I https://netguard.local/
curl -k -I --resolve netguard.local:443:192.168.56.15 https://netguard.local/
```

Resultado esperado:

- HTTP retorna `308` para HTTPS.
- HTTPS raiz retorna `200`.
- `https://netguard.local/` retorna `200` quando o nome esta resolvido para `192.168.56.15`.
- `--resolve netguard.local:443:192.168.56.15` valida o SNI/nome local mesmo antes de criar a entrada no Windows.
- endpoints `/api/*` retornam `200`.
- Grafana em `/grafana/` retorna `200`.
- headers minimos aparecem: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` e `Permissions-Policy`.

HSTS nao foi habilitado por padrao porque o ambiente usa certificado local/self-signed e isso pode atrapalhar testes no navegador.

## Dominio real e Let's Encrypt

Para producao, crie DNS apontando para o servidor, por exemplo:

```text
netguard.seudominio.com
```

Depois ajuste o `Caddyfile` para usar o dominio real e remova `tls internal`. Com DNS publico e portas 80/443 acessiveis, o Caddy pode emitir certificado via ACME/Let's Encrypt automaticamente.

Nao ative Let's Encrypt para IP local. ACME precisa de dominio valido e alcance publico.

## Evidencias para TCC

- `docker compose -p netguard ps -a` mostrando `netguard-reverse-proxy` healthy.
- `curl -I http://192.168.56.15/` mostrando `308`.
- `curl -k https://192.168.56.15/api/health` mostrando `{"status":"ok","database":"ok"}`.
- navegador abrindo `https://192.168.56.15/`.
- navegador abrindo `https://netguard.local/` sem aviso depois da CA importada.
- print do certificado `infra/certs/netguard-caddy-root.crt` importado em `Autoridades de Certificacao Raiz Confiaveis`.
- tela `Monitoramento > Alertas` via HTTPS.
- `curl -k -I https://192.168.56.15/grafana/` mostrando `200`.
- este documento aberto no repositorio.
