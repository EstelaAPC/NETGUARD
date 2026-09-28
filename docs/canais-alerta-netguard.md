# Guia de canais de alerta do NetGuard

Este guia adapta a ideia de **Media Types** do Zabbix para o NetGuard. A referencia local usada fica em `refs/zabbix/templates/media`, que contem modelos para Telegram, Discord, Slack, MS Teams, Mattermost, Rocket.Chat, Pushover, PagerDuty, Opsgenie, GLPI, Jira, ServiceNow e outros.

No NetGuard, os canais ficam em **Monitoramento > Alertas** e sao persistidos na tabela `alert_channels`.

## Templates de mensagem

As mensagens seguem um formato operacional parecido com os modelos de mídia do Zabbix, com emojis, blocos curtos e link direto para a tela de alertas. Cada canal pode manter o modelo padrão ou definir templates próprios para problema e recuperação.

Placeholders disponíveis:

```text
{device_name}      Host/dispositivo
{device_ip}        IP do dispositivo
{group_name}       Grupo do host, quando disponível
{problem_name}     Nome amigável do problema
{problem_type}     Tipo técnico do problema
{item}             Item/metric/interface relacionada
{value}            Valor observado no problema
{severity_label}   Severidade formatada
{started_at}       Início no fuso NETGUARD_ALERT_TIMEZONE
{resolved_at}      Data de resolução
{duration}         Duração do incidente
{incident_url}     Link para Monitoramento > Alertas
```

Exemplo de template de problema:

```text
🚨 Problema detectado: {problem_name}

🖥️ Host: {device_name}
🌐 IP: {device_ip}
👥 Grupo: {group_name}
📍 Item: {item}
❗ Trigger: {problem_type}
📊 Valor: {value}
🕒 Início: {started_at}
📌 Gravidade: {severity_label}

🔗 Acesse: {incident_url}
```

Exemplo de template de recuperação:

```text
✅ Problema resolvido após {duration}

🖥️ Host: {device_name}
👥 Grupo: {group_name}
📛 Problema: {problem_name}
📌 Gravidade: {severity_label}
📊 Valor: Up (1)
📅 Resolvido em: {resolved_at}

🔗 Acesse: {incident_url}
```

## Canais suportados diretamente

| Canal | Uso recomendado | Segredo mascarado |
| --- | --- | --- |
| E-mail | NOC, grupos de suporte, auditoria | `smtp_password` |
| Telegram | Plantao, grupos tecnicos, resposta rapida | `bot_token` |
| Discord | Times tecnicos e laboratorios | `webhook_url` |
| Slack | Operacao corporativa e canais de incidentes | `webhook_url` |
| Microsoft Teams | Ambientes Microsoft 365 | `webhook_url` |
| Google Chat | Ambientes Google Workspace | `webhook_url` |
| Mattermost | Chat corporativo self-hosted | `webhook_url` |
| Rocket.Chat | Chat corporativo self-hosted | `webhook_url` |
| Pushover | Push mobile direto para plantao | `app_token`, `user_key` |
| Webhook generico | Jira, GLPI, ServiceNow, automacoes e bridges | `webhook_url`, `headers` |

## Telegram

Requisitos:

- Bot criado no Telegram pelo `@BotFather`;
- token do bot;
- `chat_id` do usuario, grupo ou canal;
- NetGuard com acesso a internet para `api.telegram.org`.

Passo a passo:

1. No Telegram, abra `@BotFather`.
2. Execute `/newbot`.
3. Informe o nome do bot.
4. Informe o username terminando em `bot`.
5. Guarde o token gerado.
6. Envie uma mensagem para o bot ou adicione o bot ao grupo.
7. Acesse `https://api.telegram.org/bot<TOKEN>/getUpdates` e localize o `chat.id`.
8. No NetGuard, crie um canal `Telegram` com `Bot Token`, `Chat ID` e severidade minima.
9. Clique em **Testar envio**.

## Discord

1. No servidor Discord, abra o canal de destino.
2. Acesse **Editar canal > Integracoes > Webhooks**.
3. Crie um webhook e copie a URL.
4. No NetGuard, crie um canal `Discord` e cole a URL.
5. Defina a severidade minima e teste.

## Slack

1. Crie ou selecione um Slack App.
2. Ative **Incoming Webhooks**.
3. Instale o app no workspace e escolha o canal.
4. Copie a URL `https://hooks.slack.com/services/...`.
5. No NetGuard, crie um canal `Slack`.

## Microsoft Teams

1. No Teams, crie um workflow com gatilho de webhook.
2. Configure a acao para postar card no chat ou canal.
3. Copie a URL HTTP POST do workflow.
4. No NetGuard, crie um canal `Microsoft Teams`.

O NetGuard envia um Adaptive Card com os principais campos do incidente.

## Google Chat

1. Em um espaco do Google Chat, crie ou copie um webhook de entrada.
2. No NetGuard, crie um canal `Google Chat`.
3. Cole a URL e teste.

## Mattermost e Rocket.Chat

1. Crie uma integracao de **Incoming Webhook** no canal desejado.
2. Copie a URL.
3. No NetGuard, escolha `Mattermost` ou `Rocket.Chat`.
4. Opcionalmente ajuste `Username` ou `Alias`.

## Pushover

1. Crie uma aplicacao no Pushover para obter o `App Token`.
2. Copie o `User Key` da conta de destino.
3. No NetGuard, crie um canal `Pushover`.
4. Opcionalmente defina `Device`, `Priority` e `Sound`.

## Webhook generico

Use para bridges, filas, automacoes ou ferramentas que nao tenham canal nativo. O NetGuard envia um JSON com:

```json
{
  "title": "[NetGuard] Alerta critico detectado",
  "body": "Dispositivo: Switch-Core-01...",
  "status": "OPEN",
  "severity": "HIGH",
  "device_name": "Switch-Core-01",
  "device_ip": "192.168.0.10",
  "problem_type": "INTERFACE_DOWN",
  "description": "Interface Gi1/0/24 indisponivel",
  "timestamp": "2026-04-27T12:00:00+00:00",
  "incident_id": 358,
  "recovery": false
}
```

Se precisar de autenticacao, configure headers em JSON:

```json
{
  "Authorization": "Bearer TOKEN_DO_MIDDLEWARE"
}
```

O NetGuard mascara os headers ao retornar pela API.

## Anti-spam

O anti-spam continua centralizado no `AlertService`: se o mesmo `device_ip` e `problem_type` ja tiver incidente ativo nos ultimos 10 minutos, o envio e suprimido e a tentativa e registrada em `incident_notifications`.

## Observacoes de seguranca

- Nao registre tokens, senhas ou URLs reais no Git.
- Use `.env.example` apenas como modelo.
- Na interface e na API, campos sensiveis sao mascarados.
- Ao editar um canal, manter o valor mascarado preserva o segredo ja salvo.
- Testes com credenciais reais devem ser feitos somente no ambiente local do usuario.

## Validacao local

Em 2026-04-27, a API respondeu HTTP 200 para `/alerts/channels`, `/alerts/incidents`, `/alerts/notifications` e `/alerts/summary`. Canais fake/desativados puderam ser criados e testados sem segredo real; falhas externas ficaram registradas em `incident_notifications` e nao impediram o fluxo de incidente. O cooldown de canais ficou configurado em 600 segundos para manter anti-spam de 10 minutos.

## Fontes usadas na pesquisa

- Zabbix 7.2 media templates locais: `refs/zabbix/templates/media`.
- Telegram Bot API: https://core.telegram.org/bots/api
- Slack Incoming Webhooks: https://api.slack.com/messaging/webhooks
- Microsoft Teams Incoming Webhooks/Workflows: https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498
- Microsoft Teams Adaptive Cards: https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using
- Mattermost Incoming Webhooks: https://docs.mattermost.com/integrations-guide/incoming-webhooks.html
- Pushover Message API: https://pushover.net/api
