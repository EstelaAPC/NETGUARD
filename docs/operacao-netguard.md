# Operacao NetGuard

## Ambiente oficial

Use a VM Linux `192.168.56.15` como ambiente oficial de validacao. No Windows, execute Docker sempre com contexto remoto:

```powershell
docker --context netguard-vm compose -p netguard config --quiet
docker --context netguard-vm compose -p netguard up -d --build
docker --context netguard-vm compose -p netguard ps -a
```

Nao use `docker compose ...` sem contexto para a entrega oficial.

## URLs

- Web: `https://192.168.56.15:8081`
- API: `http://192.168.56.15:8000`
- Grafana: `http://192.168.56.15:3000`

## Login, usuarios e permissoes

O NetGuard usa autenticacao obrigatoria nas rotas internas. Perfis disponiveis:

- `admin`: acesso total, usuarios, discovery, templates, hosts, canais, incidentes e IA.
- `operator`: operacao NOC, leitura, resolucao de incidente, teste de alerta e IA.
- `viewer`: leitura operacional.
- `auditor`: leitura para evidencias, historico e relatorios.

No banco atual validado em 2026-05-20, o usuario `admin@netguard.local` autenticou com `123456`. Em banco novo, se `NETGUARD_DEFAULT_USER_PASSWORD` nao for definido, o compose usa o fallback `change-me-123` apenas para bootstrap inicial. Troque por senha local segura antes de apresentacao publica.

Endpoints uteis:

- `POST /auth/login`
- `POST /auth/logout`
- `GET /auth/me`
- `POST /auth/change-password`
- `GET /users`
- `GET /audit-logs`

Usuarios criados por admin recebem senha temporaria e devem alterar senha antes de usar rotas internas.

## Validacao diaria

```powershell
curl.exe http://192.168.56.15:8000/health
curl.exe http://192.168.56.15:8000/health/deep
curl.exe -k https://192.168.56.15:8081/api/health
curl.exe -k https://192.168.56.15:8081/monitoring/alerts
curl.exe http://192.168.56.15:3000
```

## Operacao de alertas

1. Acesse `Monitoramento > Alertas`.
2. Verifique incidentes abertos, resolvidos e notificacoes.
3. Cadastre canais em estilo Media Types.
4. Teste canais sem segredo real.
5. Confirme registro em `incident_notifications`.

## Operacao de incidentes

- Use filtros por status, severidade, host e periodo.
- Resolva incidentes pela tela ou endpoint de resolucao.
- Use acknowledgement como roadmap operacional ate o endpoint dedicado estar pronto.

## Operacao de relatorios

Endpoints disponiveis:

- `GET /reports/events`
- `GET /reports/availability`
- `GET /reports/incidents`
- `GET /reports/alerts`
- `GET /sla/summary`

Esses endpoints fornecem base para evidencias de disponibilidade, incidentes, alertas e SLA simples.

## Operacao de discovery e templates

- Acesse `Coleta de dados > Descoberta de rede`.
- Informe um CIDR de laboratorio, por exemplo `192.168.56.0/24`.
- No MVP, nao use ranges maiores que `/24`; o backend bloqueia varreduras acima de 256 enderecos.
- Use ICMP para localizar hosts ativos e SNMP v2c para identificar `sysName`, `sysDescr`, `sysObjectID` e `sysUpTime`.
- A importacao de hosts descobertos exige acao explicita do operador.
- Para switches Cisco 2960, aplique o template `Cisco Catalyst 2960` e valide a aba `Monitoramento` no detalhe do host.

Endpoints uteis:

- `POST /discovery/scan`
- `GET /discovery/runs`
- `GET /discovery/runs/{run_id}/results`
- `POST /discovery/import`
- `GET /hosts/{host_id}/monitoring-items`
- `GET /hosts/{host_id}/interfaces`
- `GET /hosts/{host_id}/correlations`
- `GET /hosts/{host_id}/loop-risk/evidence`

## IA operacional

Use `IA / Insights` para perguntas operacionais e de artigo/TCC. O backend monta um `active_operational_brief` com host, incidente, impacto, evidencias, acoes e limites. Quando o Ollama local demora, o NetGuard responde pelo brief estruturado para nao travar a demonstracao.

Prompts bons para banca:

- `O que esta acontecendo com o Switch Lab e o que devo fazer agora?`
- `Quais evidencias sustentam esse incidente?`
- `Quais comandos Cisco eu devo usar para validar?`
- `Como explicar MTTR/MTTD no artigo sem prometer superioridade ao Zabbix ou SolarWinds?`

## Relatorio tecnico de fechamento

Consulte `docs/relatorio-tecnico-tcc-final.md` para a rodada de validacao de 2026-05-20, incluindo arquivos alterados, endpoints validados, RBAC, discovery `/24`, HTTPS e limitacoes reais.
