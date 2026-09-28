# Evidências do módulo de alertas

## Objetivo

O módulo de alertas do NetGuard registra incidentes de rede e envia notificações automáticas por canais configuráveis. A implementação mantém o alerta desacoplado da lógica de monitoramento, permitindo integração futura com SNMP, Zabbix, ping, syslog, análise de vulnerabilidades ou outros coletores.

## Arquitetura resumida

- `api/alert_service.py`: concentra a regra de negócio de alertas, anti-spam, resolução e envio.
- `api/main.py`: expõe endpoints REST para simulação, resolução, histórico, canais e resumo.
- PostgreSQL/TimescaleDB: persiste incidentes, tentativas de notificação e canais configuráveis.
- Frontend React: exibe a tela **Monitoramento > Alertas**, com incidentes, notificações e canais.

## Endpoints implementados

```text
POST   /alerts
POST   /alerts/test
POST   /incidents/{incident_id}/resolve
POST   /alerts/incidents/{incident_id}/resolve
GET    /alerts/incidents
GET    /alerts/notifications
GET    /alerts/summary
GET    /alerts/channels
POST   /alerts/channels
PUT    /alerts/channels/{channel_id}
PATCH  /alerts/channels/{channel_id}/toggle
DELETE /alerts/channels/{channel_id}
POST   /alerts/channels/{channel_id}/test
```

## Regra anti-spam

Se já existir incidente ativo para o mesmo `device_ip` e `problem_type` nos últimos 10 minutos, o NetGuard não envia nova notificação. O incidente é atualizado com nova `last_detected_at` e a supressão é registrada em `incident_notifications`.

Status considerados ativos:

- `open`
- `OPEN`
- `acknowledged`
- `ACKNOWLEDGED`

Incidentes `resolved`, `RESOLVED`, `closed` ou `CLOSED` não são tratados como ativos para anti-spam.

## Tabelas utilizadas

- `incidents`: histórico operacional do problema detectado.
- `incident_notifications`: histórico das tentativas de envio, sucesso, erro ou supressão.
- `alert_channels`: mídias configuráveis de notificação, com provedor, severidade mínima e configuração em JSONB.

## Variáveis de ambiente

As variáveis continuam disponíveis como fallback quando não há nenhum canal salvo no banco. Quando existem canais cadastrados, o envio considera apenas canais ativos e compatíveis com a severidade mínima:

```bash
ALERT_EMAIL_ENABLED=true
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
ALERT_EMAIL_TO=

ALERT_WEBHOOK_ENABLED=true
WEBHOOK_PROVIDER=discord
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

## Configuração de canais de notificação

O NetGuard passou a contar com uma interface de configuração de canais de notificação, permitindo que a equipe técnica cadastre mídias de alerta como e-mail, Telegram, Discord, Slack, Microsoft Teams, Google Chat, Mattermost, Rocket.Chat, Pushover e Webhook genérico. Cada canal pode ser ativado ou desativado individualmente, possuir severidade mínima para disparo e ser testado diretamente pela interface. Essa funcionalidade permite adaptar a comunicação de incidentes ao fluxo operacional da equipe, mantendo rastreabilidade por meio do registro das tentativas de envio na tabela `incident_notifications`.

Tipos suportados:

- E-mail via SMTP;
- Telegram via bot token e chat ID;
- Discord, Slack, Microsoft Teams, Google Chat, Mattermost e Rocket.Chat via webhook;
- Pushover via app token e user key;
- Webhook genérico para bridges, filas, ITSMs e automações.

O guia operacional detalhado foi criado em `docs/canais-alerta-netguard.md`, usando como referência os templates locais de mídia do Zabbix em `refs/zabbix/templates/media`.

Campos sensíveis são mascarados no retorno da API e na tela. Se o usuário não alterar o valor mascarado durante a edição, o backend preserva o segredo anterior.

Os canais também permitem personalizar o modelo da mensagem em estilo Markdown, com placeholders como `{device_name}`, `{device_ip}`, `{group_name}`, `{problem_name}`, `{summary}`, `{impact}`, `{action}`, `{evidence_summary}`, `{affected_context}`, `{problem_type}`, `{item}`, `{severity_label}`, `{started_at}`, `{resolved_at}`, `{duration}` e `{incident_url}`. O modelo padrão foi inspirado em mensagens operacionais do Zabbix, diferenciando problema detectado e recuperação.

## Alertas automáticos de sinais operacionais

Além do endpoint manual `POST /alerts/test`, o serviço `anomaly-to-incident` publica automaticamente sinais operacionais no `AlertService`. Isso cobre eventos de syslog, incidentes promovidos por correlação, previsões/anomalias acima do limiar configurado e recuperações de incidentes resolvidos recentemente.

Fontes contempladas:

- `syslog_events`: storm control, MAC flapping, broadcast storm, loop, STP e flap de interface;
- `incidents`: `LOOP_RISK`, `EARLY_WARNING` e demais incidentes ativos ainda sem envio;
- `anomaly_scores`: previsões acima de `PREDICTION_ALERT_MIN_SCORE`, agrupadas por host;
- recuperações: incidentes `RESOLVED` com `resolved_at` recente e sem envio de recuperação registrado.

O envio continua passando pelo `AlertService`, preservando anti-spam de 10 minutos, severidade mínima por canal, histórico em `incident_notifications` e mascaramento de credenciais. Para laboratório, `SYSLOG_ALERT_MIN_SEVERITY=info` permite alertar inclusive sinais informativos; `PREDICTION_ALERT_MIN_SCORE=0.50` reduz ruído e transforma previsões em um único resumo por host com os principais itens, podendo ser reduzido para `0.25` ou `0.0` em demonstrações controladas. Eventos de interface `up` são tratados como recuperação de incidente aberto, previsões baixas antigas pendentes não são reenviadas, e incidentes automáticos sem nova detecção podem ser resolvidos após `AUTO_RESOLVE_AFTER_MINUTES`.

## Comandos de teste

Rebuild da API:

```bash
docker compose up -d --build api web anomaly-to-incident
```

Teste de alerta:

```bash
curl -i -X POST http://localhost:8000/alerts/test \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "Switch-Core-01",
    "device_ip": "192.168.0.10",
    "problem_type": "INTERFACE_DOWN",
    "description": "Interface Gi1/0/24 indisponível",
    "severity": "HIGH"
  }'
```

Consulta por IP:

```sql
SELECT id, device_name, device_ip, problem_type, severity, status, notification_sent, updated_at
FROM incidents
WHERE split_part(device_ip::text, '/', 1) = '192.168.0.10'
  AND problem_type = 'INTERFACE_DOWN'
ORDER BY updated_at DESC;
```

Consulta das notificações:

```sql
SELECT id, incident_id, channel, provider, delivery_status, error, sent_at
FROM incident_notifications
ORDER BY sent_at DESC
LIMIT 10;
```

Logs:

```bash
docker compose logs api --tail=100
```

## Resultado esperado

- `POST /alerts/test` retorna HTTP 200.
- O incidente é criado ou atualizado em `incidents`.
- O segundo envio em menos de 10 minutos retorna `notification_suppressed=true`.
- `incident_notifications` registra envio, erro ou supressão.
- Falha de envio externo não impede a criação do incidente.
- Canais configurados no banco respeitam `enabled` e `min_severity`.

## Evidência validada

“O módulo de alertas do NetGuard foi validado em ambiente Docker integrado. O endpoint POST /alerts/test retornou HTTP 200, registrando o incidente de teste no banco de dados. O segundo envio do mesmo alerta dentro do intervalo de 10 minutos foi corretamente tratado pela regra anti-spam, retornando notification_suppressed=true. A tabela incident_notifications registrou a supressão com channel=alert, provider=anti_spam e delivery_status=suppressed. Os logs da API não apresentaram erros durante o teste.”

Validação complementar em 2026-04-27:

- `GET /alerts/summary`, `/alerts/channels`, `/alerts/incidents` e `/alerts/notifications`: HTTP 200.
- Banco: `incident_notifications=3`, `incidents_open=0`, `incidents_resolved=1`.
- Canal fake/desativado: falha externa registrada de forma controlada, sem quebrar criação de incidente e sem stack trace no log final da API.
- Anti-spam: segundo alerta equivalente reutilizou o incidente existente e registrou supressão.
- Resolução: incidente de teste ficou com status `RESOLVED` e `resolved_at` preenchido.

## Texto curto para o TCC

O módulo de alertas amplia o NetGuard com rastreabilidade operacional de incidentes e comunicação automática para equipes técnicas. A solução registra o histórico do problema, evita alertas repetidos por meio de uma regra anti-spam de 10 minutos e permite envio por canais configuráveis como e-mail, Telegram, Discord, Slack, Microsoft Teams, Google Chat, Mattermost, Rocket.Chat, Pushover e Webhook genérico. Todas as tentativas de envio são persistidas, possibilitando auditoria e evidências de funcionamento durante a operação.

## Prints recomendados

- Tela **Monitoramento > Alertas** com incidentes recentes.
- Formulário de criação de canal Discord, Telegram ou E-mail.
- Resultado do botão **Testar envio**.
- Consulta SQL em `incidents` mostrando o incidente `INTERFACE_DOWN`.
- Consulta SQL em `incident_notifications` mostrando `delivery_status=suppressed`.
- Logs da API após teste sem erro.

## Evidências finais complementares

Para o fechamento do TCC, complemente os prints acima com:

- `docker compose ps` com `db`, `api` e `web` saudáveis.
- `GET /health` e `GET /health/deep`.
- `GET /alerts/summary`.
- Consulta de `schema_migrations`.
- Logs de `poller`, `snmp-poller`, `syslog-collector`, `anomaly-engine` e `anomaly-to-incident`.
- Incidente resolvido exibindo `resolved_at`.

O roteiro completo de validação final está em `docs/validacao-final-netguard.md`.
