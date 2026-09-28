# Evidencias recomendadas para o TCC

## Docker e runtime

- `docker context show`
- `docker --context netguard-vm ps`
- `docker --context netguard-vm compose -p netguard ps -a`
- Logs da API: `docker --context netguard-vm compose -p netguard logs api --tail=100`
- Logs dos workers: `poller`, `snmp-poller`, `syslog-collector`, `anomaly-engine`, `anomaly-to-incident`

## API

- `GET /health`
- `GET /health/deep`
- `GET /hosts`
- `GET /metrics/overview`
- `GET /metrics/latest`
- `GET /incidents`
- `GET /alerts/summary`
- `GET /alerts/channels`
- `GET /alerts/incidents`
- `GET /alerts/notifications`
- `GET /reports/availability`
- `GET /sla/summary`

## Interface

- Dashboard principal.
- Hosts/Ativos.
- Host drill-down.
- Metricas.
- Incidentes.
- Monitoramento > Alertas.
- Formulario de canais Media Types.
- Discovery.
- Templates.
- Grafana.

## Banco

Prints SQL recomendados:

```sql
SELECT version FROM schema_migrations ORDER BY version;
SELECT metric, count(*) FROM metrics GROUP BY metric ORDER BY metric;
SELECT status, count(*) FROM incidents GROUP BY status ORDER BY status;
SELECT provider, delivery_status, count(*) FROM incident_notifications GROUP BY provider, delivery_status;
```

## Cenarios demonstraveis

1. Ambiente sobe pela VM.
2. Host `lab-linux-01` aparece saudavel.
3. Metricas ICMP e SNMP sao persistidas.
4. Incidente e criado por `/alerts/test`.
5. Segundo alerta equivalente e suprimido por anti-spam.
6. Canal fake/desativado registra falha controlada.
7. Incidente e resolvido e recebe `resolved_at`.
8. SLA simples e relatorio de disponibilidade respondem pela API.

## Pendencias a expor com honestidade

- SNMPv3, traps, flow monitoring, IPAM e NCM sao roadmap.
- RBAC forte e auditoria completa ainda nao estao no nivel enterprise.
- HTTPS local usa certificado autoassinado.
- Docker Context remoto depende de SSH key autorizada na VM.
