# Arquitetura NetGuard

O NetGuard e uma plataforma de monitoramento corporativo em evolucao, organizada em containers e orientada a telemetria, incidentes e rastreabilidade.

## Componentes

- `web`: frontend React, publicado em HTTPS na porta `8081`.
- `api`: FastAPI, porta `8000`, centraliza hosts, metricas, incidentes, alertas, relatorios e healthchecks.
- `db`: PostgreSQL/TimescaleDB, porta `5432`, armazena ativos, metricas, incidentes, notificacoes, syslog, anomalias e configuracoes.
- `poller`: coleta ICMP/TCP e disponibilidade.
- `snmp-poller`: coleta SNMP v2c, interfaces, erros, descartes e contadores.
- `syslog` e `syslog-collector`: recepcao UDP/514 e persistencia de eventos.
- `anomaly-engine`: gera scores em `anomaly_scores`.
- `anomaly-to-incident`: transforma sinais em incidentes e aciona o AlertService.
- `grafana`: dashboards tecnicos e operacionais.

## Fluxo operacional

1. Ativos sao cadastrados manualmente ou preparados por discovery/template.
2. Workers coletam ICMP, TCP, SNMP e syslog.
3. Metricas e eventos sao persistidos no banco.
4. Anomalias e sinais viram incidentes.
5. AlertService aplica anti-spam, severidade minima e canais ativos.
6. UI, API e Grafana exibem estado, historico e evidencias.

## Limites atuais

- SNMPv3, traps, flow monitoring, IPAM e NCM permanecem no roadmap.
- RBAC forte e auditoria completa ainda precisam ser implementados para postura enterprise.
- HTTPS local usa certificado autoassinado; ambiente produtivo deve usar certificado confiavel.
