# Validacao final do NetGuard para TCC

Data da revisao: 2026-04-27

Este documento consolida a auditoria final do NetGuard como MVP academico demonstravel. O objetivo e elevar estabilidade, rastreabilidade e clareza operacional, usando SolarWinds e Zabbix apenas como referencia de maturidade. O NetGuard nao deve ser apresentado como equivalente funcional a essas plataformas comerciais.

Atualizacao de runtime em 2026-05-08: a VM `192.168.56.15` agora possui reverse proxy HTTPS com Caddy. O acesso oficial e `https://netguard.local/`, a API publica fica em `https://netguard.local/api/*` e o Grafana fica em `https://netguard.local/grafana/`. As portas diretas antigas continuam apenas para debug.

Atualizacao de fechamento em 2026-05-20: autenticacao, RBAC e auditoria foram reforcados. As rotas internas exigem token, usuarios possuem perfis `admin`, `operator`, `viewer` e `auditor`, e acoes administrativas sao bloqueadas no backend. A validacao runtime desta rodada foi feita por SSH direto na VM porque o `docker.exe` nao estava disponivel no PATH do Codex no Windows; todos os comandos Docker foram executados dentro da VM `192.168.56.15`, sem apagar volumes.

## Arquitetura resumida

- `reverse-proxy`: Caddy em `80/443`, com redirect HTTP para HTTPS e rotas `/`, `/api/*` e `/grafana/*`.
- `web`: frontend React publicado oficialmente em `https://netguard.local/` e direto para debug em `https://192.168.56.15:8081`.
- `api`: FastAPI em `http://localhost:8000`.
- `db`: PostgreSQL/TimescaleDB em `5432`.
- `grafana`: dashboards oficiais em `https://netguard.local/grafana/` e direto para debug em `http://192.168.56.15:3000`.
- `poller`: coleta ICMP/TCP e persistencia de disponibilidade, RTT e perda.
- `snmp-poller`: coleta SNMP v2c de interfaces, status, erros, descartes e contadores de trafego com preferencia por `ifHCInOctets`/`ifHCOutOctets`.
- `syslog` e `syslog-collector`: recebimento UDP/514 e persistencia de eventos.
- `anomaly-engine`: calculo de anomalias em `anomaly_scores`.
- `anomaly-to-incident`: promocao de anomalias/syslog para incidentes e alertas.
- `loop-risk-migrate`: aplicacao idempotente das migrations SQL sem apagar dados.

## Variaveis de ambiente

Use `.env.example` como referencia. Segredos reais devem ficar apenas no `.env` local, em variaveis do host ou em mecanismo de secrets do ambiente.

Campos sensiveis incluem senhas de banco/Grafana, senha inicial de usuario, SMTP, webhooks, tokens, user keys e headers customizados.

Variaveis de autenticacao:

- `NETGUARD_AUTH_ENABLED=true`
- `NETGUARD_AUTH_SECRET`: segredo usado para assinar tokens.
- `NETGUARD_AUTH_TOKEN_TTL_MINUTES`: validade do token.
- `NETGUARD_SERVICE_TOKEN`: token interno para workers chamarem endpoints protegidos.
- `NETGUARD_DEFAULT_USER_PASSWORD`: senha usada apenas no bootstrap quando nao houver admin ativo.

No banco atual validado em 2026-05-20, `admin@netguard.local` autenticou com `123456`. Se o banco for novo e a variavel nao for definida, o fallback do compose e `change-me-123`; documente ou altere isso no `.env` local antes da apresentacao.

O cooldown padrao de canais de alerta e `ALERT_CHANNEL_COOLDOWN_SEC=600`, mantendo a protecao anti-spam de 10 minutos para demonstracao e operacao do MVP.

Para o frontend, mantenha `NETGUARD_CORS_ORIGINS` alinhado ao endereco usado no navegador, por exemplo `https://localhost:8081` ou `https://192.168.56.15:8081`. No Docker, a UI usa `/api` como proxy HTTPS interno para a FastAPI e evita mixed content no navegador.

## Como subir o ambiente

Nao use `docker compose down -v` durante a validacao, para nao apagar dados.

Ambiente oficial para entrega: VM Linux `192.168.56.15`, via Docker Context SSH `netguard-vm`.

```bash
docker --context netguard-vm compose -p netguard config --quiet
docker --context netguard-vm compose -p netguard up -d --build
docker --context netguard-vm compose -p netguard ps -a
```

Nao rode `docker compose ...` sem `--context netguard-vm` para validacao oficial, pois isso usa o Docker Desktop local do Windows.

O procedimento completo do contexto remoto esta em `docs/docker-context-vm.md`.

Comando local alternativo, apenas para desenvolvimento:

```bash
docker compose up -d --build
docker compose ps
```

Em pastas UNC no Windows, o Compose pode nao conseguir inferir o nome do projeto. Nesse caso use:

```bash
docker compose -p netguard up -d --build
docker compose -p netguard ps
```

Servicos esperados: `db`, `api`, `web`, `poller`, `snmp-poller`, `syslog`, `syslog-collector`, `anomaly-engine`, `anomaly-to-incident`, `grafana` e, no laboratorio, `lab-linux-01`.

## Validacao da API

```bash
curl -i http://localhost:8000/health
curl -i http://localhost:8000/health/deep
curl -i http://localhost:8000/metrics/overview
curl -i http://localhost:8000/hosts
curl -i http://localhost:8000/metrics/latest
curl -i http://localhost:8000/incidents
curl -i http://localhost:8000/alerts/summary
curl -i http://localhost:8000/alerts/channels
curl -i http://localhost:8000/alerts/incidents
curl -i http://localhost:8000/alerts/notifications
curl -i http://localhost:8000/housekeeper/status
curl -k https://192.168.56.15/api/health
curl -k https://192.168.56.15/api/health/deep
curl -k https://192.168.56.15/api/alerts/summary
curl -k https://192.168.56.15/api/housekeeper/status
```

`/health` valida conectividade basica com o banco. `/health/deep` valida tabelas essenciais e lista migrations aplicadas.

Com autenticacao habilitada, os endpoints internos devem ser chamados com `Authorization: Bearer <token>`. Validacao de seguranca esperada:

- `GET /hosts` sem token retorna `401`.
- Admin acessa `GET /users`, `GET /audit-logs`, discovery, templates e canais.
- Viewer acessa leitura, mas recebe `403` em `POST /users`, `POST /discovery/scan` e `POST /alerts/test`.
- Worker usa `X-NetGuard-Service-Token` nos endpoints internos permitidos de alertas.

## Validacao do frontend

Abrir:

- `https://192.168.56.15/login`
- `https://192.168.56.15/monitoring/overview`
- `https://192.168.56.15/data-collection/hosts`
- `https://192.168.56.15/monitoring/signals`
- `https://192.168.56.15/monitoring/incidents`
- `https://192.168.56.15/monitoring/alerts`

As chamadas da UI usam `VITE_API_URL` quando definido; no Docker o valor padrao e `/api`, atendido pelo reverse proxy HTTPS e proxyado internamente para `api:8000`. O frontend omite o cabecalho `Authorization` quando nao existe token valido.

O certificado HTTPS local e gerado pelo Caddy com `tls internal`. O navegador pode exibir aviso de certificado nao confiavel; para entrega em ambiente real, substitua por dominio com certificado confiavel.

## Validacao de coleta

```bash
docker compose logs poller --tail=100
docker compose logs snmp-poller --tail=100
docker compose logs syslog-collector --tail=100
docker compose logs anomaly-engine --tail=100
docker compose logs anomaly-to-incident --tail=100
```

Metricas esperadas:

- `host.alive`
- `icmp.rtt_ms`
- `icmp.loss_pct`
- `tcp.alive`, quando ICMP falhar e TCP responder
- `snmp.if.in_octets|ifIndex=N`
- `snmp.if.out_octets|ifIndex=N`
- `snmp.if.in_errors|ifIndex=N`
- `snmp.if.out_errors|ifIndex=N`
- `snmp.if.in_discards|ifIndex=N`
- `snmp.if.out_discards|ifIndex=N`
- `snmp.if.oper_status|ifIndex=N`
- `snmp.if.admin_status|ifIndex=N`

## Validacao de alertas

```bash
curl -i -X POST http://localhost:8000/alerts/test \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "Switch-Core-01",
    "device_ip": "192.168.0.10",
    "problem_type": "INTERFACE_DOWN",
    "description": "Interface Gi1/0/24 indisponivel",
    "severity": "HIGH"
  }'
```

Anti-spam:

1. Executar o mesmo `POST /alerts/test` duas vezes em menos de 10 minutos.
2. Confirmar que o segundo retorno tem `notification_suppressed=true`.
3. Confirmar registro em `incident_notifications` com `provider='anti_spam'` ou `delivery_status='suppressed'`.

Consultas:

```sql
SELECT id, device_name, device_ip, problem_type, severity, status,
       first_detected_at, last_detected_at, resolved_at, notification_sent
FROM incidents
ORDER BY updated_at DESC
LIMIT 10;

SELECT id, incident_id, channel, provider, delivery_status, error, sent_at
FROM incident_notifications
ORDER BY sent_at DESC
LIMIT 20;
```

Resolver incidente:

```bash
curl -i -X POST http://localhost:8000/incidents/1/resolve \
  -H "Content-Type: application/json" \
  -d '{"send_recovery_notification": true}'
```

## Validacao de canais

Providers suportados no MVP:

- E-mail
- Telegram
- Discord
- Slack
- Microsoft Teams
- Google Chat
- Mattermost
- Rocket.Chat
- Pushover
- Webhook generico

Fluxo:

1. Abrir `Monitoramento > Alertas`.
2. Criar canal fake ou desativado.
3. Confirmar mascaramento de webhook/token/senha/header no retorno.
4. Testar canal.
5. Confirmar que sucesso ou falha fica registrado em `incident_notifications`.
6. Confirmar que canais desativados nao enviam.
7. Confirmar que `min_severity` filtra alertas abaixo do minimo.

## Roteiro ponta a ponta

1. Ambiente sobe: `docker compose up -d --build`, `docker compose ps`, `/health`.
2. Host monitorado: confirmar `lab-linux-01` em Hosts e metricas recentes.
3. Incidente: criar via `/alerts/test` ou gerar falha no laboratorio.
4. Anti-spam: repetir alerta e validar supressao.
5. Canal: criar canal fake/desativado e testar registro controlado.
6. Resolucao: resolver pela API e pela interface; conferir `resolved_at`.
7. Dashboard: validar cards de disponibilidade, incidentes, alertas e metricas.

## Checklist de prints para TCC

- `docker compose ps`
- `GET /health`
- `GET /health/deep`
- `GET /alerts/summary`
- Dashboard
- Hosts/Ativos
- Metricas/Sinais recentes
- Incidentes
- Monitoramento > Alertas
- Formulario de Media Types/canais
- Resultado de teste de canal
- Consulta `incident_notifications`
- Consulta `schema_migrations`
- Grafana
- Logs limpos da API
- Logs dos workers
- Incidente resolvido com `resolved_at`

## Resultados desta auditoria local

Validado neste ambiente em 2026-04-27:

- `docker compose -p netguard up -d --build`: OK. O ambiente subiu direto da pasta UNC apos remover bind mounts de runtime frageis e empacotar initdb, scripts de migracao, provisioning do Grafana e UI legada em imagens proprias.
- `docker compose -p netguard ps -a`: OK. `db`, `api` e `web` ficaram `healthy`; `grafana`, `poller`, `snmp-poller`, `syslog`, `syslog-collector`, `anomaly-engine`, `anomaly-to-incident`, `lab-linux-01`, `lab-snmpd`, `iperf3` e `ui` ficaram `Up`; `loop-risk-migrate` e `lab-bootstrap` finalizaram com `Exited (0)`.
- Portas validadas: API `8000`, frontend HTTPS `8081`, Grafana `3000`, banco `5432`, syslog UDP `514`, UI legada `3100`.
- `GET /health`: HTTP 200, `{"status":"ok","database":"ok"}`.
- `GET /health/deep`: HTTP 200, sem tabelas ausentes, com 15 migrations registradas.
- Endpoints HTTP 200: `/hosts`, `/metrics/overview`, `/metrics/latest`, `/incidents`, `/alerts/summary`, `/alerts/channels`, `/alerts/incidents`, `/alerts/notifications`.
- Rotas web HTTPS 200: `/`, `/monitoring/overview`, `/data-collection/hosts`, `/monitoring/incidents`, `/monitoring/alerts`.
- Proxy HTTPS da UI validado: `https://localhost:8081/api/health` e `https://localhost:8081/api/alerts/summary` retornaram HTTP 200, evitando chamada direta HTTP da pagina para a API.
- Grafana HTTP 200 em `http://localhost:3000/`.
- Banco validado com dados reais: `schema_migrations=15`, `metrics=234`, `anomaly_scores=117`, `syslog_events=12`, `incident_notifications=3`, `incidents_open=0`, `incidents_resolved=1`.
- `python -m py_compile api/alert_service.py api/main.py`: OK usando o Python empacotado do Codex, pois o `python` do Windows aponta para o alias da Microsoft Store.
- `python -m unittest discover -s api/tests`: OK, 23 testes.
- `npm.cmd run build` em `netguard-frontend`: OK, build Vite gerado em `dist/`.
- `npm.cmd test`: pendente por ausencia de script `test` no `package.json`.
- `npm.cmd audit --audit-level=moderate`: falhou com 12 vulnerabilidades transitivas reportadas, sendo 6 moderadas e 6 altas. O build passou, mas deve ser tratado como item de manutencao antes de uso fora do laboratorio.
- Seguranca: existe apenas `.env.example` na raiz; variaveis sensiveis documentadas com valor vazio ou placeholder. A busca por `Bearer null`, `Bearer undefined`, senha padrao antiga e padroes comuns de token/webhook encontrou apenas exemplos mascarados ou valores dummy de testes.
- Logs validados: API com startup e endpoints 200 sem stack trace; web Nginx ativo; `poller` coletando ICMP do `lab-linux-01`; `loop-risk-migrate` idempotente ignorando migrations ja aplicadas e concluindo com sucesso. `snmp-poller`, `anomaly-engine` e `syslog-collector` nao emitiram linhas recentes no tail curto, mas permaneceram `Up` e as tabelas `metrics`, `anomaly_scores` e `syslog_events` tinham dados persistidos.
- Browser visual interno do Codex nao foi executado porque o runtime `node_repl/js` do plugin de navegador nao estava disponivel nesta sessao. A validacao de frontend foi feita por build Vite e rotas HTTP 200.

Estado do Docker Context SSH em 2026-04-27:

- `netguard-vm` existe e aponta para `ssh://netguard@192.168.56.15`.
- `docker context use netguard-vm` foi aplicado para evitar uso acidental do Docker Desktop local.
- `C:\Users\Rodig\.ssh\config` foi criado com alias `netguard-vm` e chave `~/.ssh/id_ed25519`.
- `ssh netguard@192.168.56.15` ainda falha em modo nao interativo com `Permission denied (publickey,password)`.
- `docker --context netguard-vm ps/info` nao conseguiu concluir enquanto a chave publica do Windows nao estiver autorizada na VM.
- A VM respondeu API e Grafana por IP, mas a web da VM ainda respondeu HTTP em `http://192.168.56.15:8081`, indicando que o rebuild HTTPS preparado no codigo ainda precisa ser aplicado no engine remoto.
- Proximo passo necessario: autorizar a chave `C:\Users\Rodig\.ssh\id_ed25519.pub` no `~netguard/.ssh/authorized_keys` da VM e executar `docker --context netguard-vm compose -p netguard up -d --build`.

## Resultados da validacao em runtime na VM em 2026-05-08

Validado sem apagar dados e sem `docker compose down -v`:

- `docker compose -p netguard config --quiet`: OK.
- `docker compose -p netguard up -d --build`: OK.
- `docker compose -p netguard ps -a`: `netguard-reverse-proxy`, `api`, `db`, `web`, `housekeeper`, `poller`, `snmp-poller`, `syslog`, `syslog-collector`, `anomaly-engine`, `anomaly-to-incident` e `grafana` em execucao; `reverse-proxy`, `api`, `db` e `web` saudaveis.
- `http://192.168.56.15/`: HTTP `308` para `https://192.168.56.15/`.
- `https://192.168.56.15/`: HTTP `200` com headers `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` e `Permissions-Policy`.
- `https://192.168.56.15/api/health`: HTTP `200`, banco OK.
- `https://192.168.56.15/api/health/deep`: HTTP `200`, sem tabelas ausentes.
- `https://192.168.56.15/api/alerts/summary`, `/alerts/channels`, `/alerts/incidents`, `/alerts/notifications` e `/housekeeper/status`: HTTP `200`.
- `https://192.168.56.15/grafana/`: HTTP `200` com `GF_SERVER_SERVE_FROM_SUB_PATH=true`.
- Frontend servido por HTTPS com bundle usando `/api`; busca no JS publicado encontrou `0` ocorrencias de `http://192.168.56.15:8000` e `0` ocorrencias de `Bearer null`.
- CORS para `Origin: https://192.168.56.15`: `access-control-allow-origin` correto e sem wildcard com credenciais.

Alertas e incidentes validados no banco:

- `HOST_DOWN`: incidente `785`, host `lab-linux-01`, severidade critical, resolvido, com Telegram `success`.
- `SNMP_COLLECTION_SILENCE`: incidente `810`, Switch Lab `192.168.56.20`, severidade high, resolvido, com Telegram `success`.
- `SYSLOG_COLLECTION_SILENCE`: incidentes `811` e `813`, Switch Lab, resolvidos, com Telegram `success`.
- `LOOP_RISK`: incidente `821`, Switch Lab `192.168.56.20`, aberto com evidencias Gi0/23 e Gi0/24 apos simulacao controlada; repeticao do mesmo sinal atualizou o mesmo incidente, sem criar churn. Depois que os sinais envelheceram, o incidente foi resolvido automaticamente.
- `incident_notifications`: envios Telegram recentes tiveram `delivery_status='success'` para HOST_DOWN, ICMP, SNMP, SYSLOG e LOOP_RISK; depois das 22:06 a VM perdeu resolucao DNS externa para `api.telegram.org`, gerando falhas `[Errno -3] Temporary failure in name resolution` e cooldown do canal. A falha antiga HTTP 400 de MarkdownV2 nao se repetiu.

Bug corrigido durante a validacao: uma linha de MAC flapping podia ser classificada como `BROADCAST_STORM` quando o raw/processo tinha a palavra generica `loop`; a ordem de deteccao foi ajustada para priorizar sinais especificos como `MAC_FLAPPING`, STP e flap antes de `BROADCAST_STORM`.

Bloqueio externo observado: no fim da validacao, a VM nao resolvia `api.telegram.org` e tambem nao alcancava `1.1.1.1`. A tabela de rotas mostrou entradas estaticas para `192.168.1.0/24` e `192.168.1.1` via `eth1`, enquanto o gateway real esta em `eth0`. O usuario `netguard` nao possui sudo sem senha para remover essas rotas em runtime. Isso afeta apenas o envio externo Telegram enquanto a rota/DNS da VM estiver quebrada; os incidentes continuam abrindo e resolvendo.

Housekeeper:

- `/housekeeper/status`: `enabled=true`, `interval_sec=3600`, `batch_rows=50000`.
- Retencao ativa: metrics 30 dias, syslog 14 dias, anomaly_scores 30 dias, ai_insights 30 dias, incident_notifications 180 dias, incidentes resolvidos 180 dias.
- Ultima execucao registrada: `housekeeper_runs.id=1`, status `success`.
- Removidos na execucao: `syslog_events=96484`, demais categorias `0`.
- Incidentes abertos nao foram apagados. O estado final pode apresentar `SYSLOG_COLLECTION_SILENCE` aberto para o Switch Lab se o simulador nao estiver enviando syslog recente; isso e esperado porque o host esta marcado como fonte syslog esperada.

Volumes observados no banco durante a validacao:

- `metrics`: cerca de 766 mil registros, com dados recentes em 2026-05-08.
- `syslog_events`: cerca de 28 mil registros apos limpeza de retencao.
- `anomaly_scores`: cerca de 461 mil registros, com dados recentes em 2026-05-08.

Artefatos:

- Instalador Windows existente em `installer/windows/dist/NetGuardInstaller.exe`, tamanho `41472` bytes.
- README do instalador presente em `installer/windows/README.md`.
- Documentacao HTTPS: `docs/https-netguard.md`.

Observacao honesta: a validacao visual pelo navegador embutido do Codex nao executou porque o plugin local de browser falhou ao iniciar o `app-server`. A validacao de frontend foi feita por HTTP/HTTPS real, HTML/JS servido pelo proxy e endpoints da API.

## Resultados da reconferencia em 2026-05-19

Validado na VM `192.168.56.15`, sem apagar volumes e sem `docker compose down -v`.

- Problema encontrado: o checkout estava na branch `main`, que era anterior ao trabalho completo de produto. A branch `feat/product-architecture-next` continha a tela de Alertas em abas, HTTPS, IA/Insights, docs, migracoes e workers atualizados.
- Correcao aplicada: restaurado o conteudo funcional da branch de produto no workspace ativo. O fast-forward direto foi bloqueado porque `infra/caddy/Caddyfile` existia como diretorio vazio `root:root` na VM; por isso o Compose passou a usar `infra/caddy-runtime/Caddyfile`.
- Correcao adicional: scripts `.sh` estavam com CRLF apos manipulacao via Windows/SMB, quebrando o `loop-risk-migrate` com `set: illegal option -`. Os scripts foram convertidos para LF e `.gitattributes` foi criado para preservar finais de linha corretos.
- `docker compose -p netguard config --quiet`: OK.
- `docker compose -p netguard up -d --build`: OK.
- `docker compose -p netguard ps -a`: API, web, reverse-proxy, banco, Grafana, poller, snmp-poller, syslog, syslog-collector, anomaly-engine, anomaly-to-incident, housekeeper e lab-linux-01 em execucao; `loop-risk-migrate` e `lab-bootstrap` terminaram com `Exited (0)`.
- HTTPS: `https://192.168.56.15/monitoring/alerts`, `https://192.168.56.15:8081/monitoring/alerts` e `https://192.168.56.15/grafana/` retornaram HTTP 200.
- API direta: `/health`, `/health/deep`, `/alerts/summary`, `/alerts/channels`, `/alerts/incidents`, `/alerts/notifications`, `/hosts`, `/metrics/overview` e `/metrics/latest` retornaram HTTP 200.
- Relatorios/templates: `/templates`, `/reports/availability`, `/reports/incidents`, `/reports/alerts` e `/sla/summary` retornaram HTTP 200.
- `schema_migrations`: versoes `001_netguard`, `003_syslog`, `004_snmp`, `007_anomaly`, `008_loop_risk_pipeline`, `009_profiles_and_discovery`, `010_host_groups`, `011_monitoring_templates`, `012_operation_v2`, `013_ai_insights`, `014_collection_policy`, `015_alerts`, `016_alert_channels`, `017_alert_channel_media_catalog` e `018_incident_alert_compatibility` registradas.
- Testes: `python -m py_compile /app/alert_service.py /app/main.py` OK no container da API. `python -m unittest discover -s /app/tests` OK, 25 testes, executado com `api/tests` montado como leitura.
- Frontend: `npm run build` OK em `netguard-frontend`, com avisos nao bloqueantes de Browserslist/Baseline e chunk maior que 500 kB.
- Alertas: `/alerts/summary` retornou contadores reais; `/alerts/channels` retornou canais com segredo mascarado. A tela `Alerts.jsx` contem abas `Alertas abertos`, `Historico de alertas`, `Canais de notificacao` e `Templates/Regras`.
- IA/Insights: o backend contem respostas rapidas e contexto para perguntas sobre MTTR, MTTD, anomalias, STP/Loop Guard, Zabbix/SolarWinds e artigo/TCC, sem prometer vantagem percentual sem experimento controlado.

## Limitacoes conhecidas do MVP

- Autenticacao/RBAC e simples: ha login e controle visual de rota, mas nao ha JWT real nem hashing de senha no escopo atual.
- SNMP real implementado no poller dedicado e v2c. SNMPv3 deve ser tratado como proximo trabalho, salvo se implementado depois.
- Alertas externos reais dependem de credenciais fornecidas localmente pelo usuario; o repositorio nao deve conter tokens, senhas ou URLs reais.
- Sem topologia completa de rede, `loop_risk` e previsoes devem ser apresentados como apoio operacional, nao diagnostico definitivo.
- O NetGuard e um MVP academico demonstravel, nao substitui suites comerciais maduras.

## Proximos trabalhos

- JWT real, hashing de senha e protecao dos endpoints administrativos.
- Suporte SNMPv3 completo.
- Templates por fabricante mais amplos para Cisco, Aruba, Dell e HPE.
- Testes automatizados de API com banco efemero.
- Pipeline CI com build de frontend e compose.
- Retencao/compactacao de metricas conforme volume real do laboratorio.

## Atualizacao tecnica em 2026-05-20: templates, discovery e correlacao

Validado na VM oficial `192.168.56.15`, sem apagar dados e sem `docker compose down -v`.

Implementacoes adicionadas:

- Migration idempotente `019_monitoring_items_discovery_correlation`.
- Tabelas `monitoring_items`, `network_discovery_runs`, `network_discovery_results`, `syslog_interface_correlations` e `audit_events`.
- Expansao de `discovered_interfaces` para inventario SNMP de interfaces.
- Templates iniciais: `Generic SNMP Switch`, `Cisco Catalyst 2960`, `Cisco IOS Switch`, `Aruba AOS-CX`, `Aruba/HPE Switch`, `Dell Switch`, `Linux Host` e `ICMP Only`.
- Itens reais de monitoramento por host/template com protocolo, OID, intervalo, timeout, tentativas, retencao, ultima coleta e ultimo erro.
- Poller SNMP atualizado para materializar itens por template, respeitar itens habilitados, coletar scalars SNMP e atualizar inventario de interfaces.
- Collector Syslog atualizado para reconhecer sinais Cisco/STP/loop/storm/link flap/MAC flapping e correlacionar eventos com interfaces SNMP.
- Discovery por CIDR com ICMP/SNMP v2c, classificacao de vendor/template sugerido e importacao explicita.
- Tela `Coleta de dados > Descoberta de rede` com formulario real, resultados, selecao e importacao.
- Aba `Monitoramento` no detalhe do host com protocolos, itens, inventario, correlacoes e evidencias de loop.
- Saude do host ajustada para `Saudavel`, `Degradado`, `Critico` ou `Indisponivel` considerando incidentes de coleta, host down e loop risk.

Endpoints validados:

- `GET /health`: HTTP 200.
- `GET /health/deep`: HTTP 200, incluindo migration `019_monitoring_items_discovery_correlation`.
- `GET /templates`: HTTP 200.
- `GET /templates/289/items`: HTTP 200, 19 itens para `Cisco Catalyst 2960`.
- `GET /hosts/10/monitoring-items`: HTTP 200, 19 itens.
- `GET /hosts/10/interfaces`: HTTP 200, 24 interfaces.
- `GET /hosts/10/correlations`: HTTP 200.
- `GET /hosts/10/loop-risk/evidence`: HTTP 200 apos correcao de bug no calculo de severidade derivada de `anomaly_scores.score`.
- `GET /alerts/summary`, `/alerts/channels`, `/alerts/incidents?limit=5` e `/alerts/notifications?limit=5`: HTTP 200.
- `POST /discovery/scan` com `192.168.56.15/32`: HTTP 200, run `1` concluida e `GET /discovery/runs/1/results` retornou 1 resultado.

Comandos executados e resultados:

- `python3 -m py_compile api/main.py`: OK na VM.
- `docker compose -p netguard config --quiet`: OK.
- `docker compose -p netguard up -d --build`: OK antes da correcao final.
- `docker compose -p netguard up -d --build api`: OK apos correcao pontual em `/loop-risk/evidence`.
- `docker compose -p netguard ps -a`: API, banco, web, reverse-proxy, Grafana, pollers e collectors em execucao; `loop-risk-migrate` e `lab-bootstrap` terminaram com `Exited (0)`.
- `docker compose -p netguard exec -T api python -m py_compile /app/main.py /app/alert_service.py`: OK.
- `docker compose -p netguard run --rm -T -v /home/netguard/netguard/api/tests:/app/tests:ro api python -m unittest discover -s /app/tests`: OK, 25 testes.
- `npm run build` em `netguard-frontend`: OK, somente avisos nao bloqueantes de Browserslist/Baseline e chunk grande.
- `docker compose -p netguard up -d --build grafana`: OK apos ajuste do painel `Host monitorado`.

Observacoes de logs:

- Logs recentes da API: startup OK e endpoints principais HTTP 200.
- Logs recentes de `anomaly-engine`, `anomaly-to-incident` e `snmp-poller` com `--since=2m`: sem erros ativos.
- Erros antigos vistos em `anomaly-engine` e `anomaly-to-incident` ocorreram durante restart de banco/API no rebuild e nao continuaram depois.
- Logs do `poller` mostram coletas ICMP/TCP em execucao; hosts indisponiveis do laboratorio continuam gerando sinais esperados.
- Painel Grafana `Host monitorado`: consulta ajustada de `time_series` para `table` numerico para evitar `No data` em stat simples. O arquivo provisionado dentro do container foi conferido com `"format": "table"`.

Documentacao detalhada:

- `docs/monitoramento-discovery-correlacao.md`

Limitacoes desta entrega:

- SNMPv3 segue como roadmap; SNMP v2c e o caminho validado.
- Discovery e sincrono e limitado a ate 256 enderecos no MVP.
- Parametros de item ficam persistidos e parte deles ja afeta a coleta SNMP, mas retencao por item ainda exige evolucao do housekeeper.
- Campos de bps no inventario foram preparados; calculo fino por delta entre coletas ainda e evolucao futura.
- RBAC forte de endpoints administrativos ainda e limitacao do MVP.
