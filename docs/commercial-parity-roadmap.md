# Commercial parity roadmap do NetGuard

Objetivo: aproximar o NetGuard de uma plataforma corporativa de monitoramento, usando Zabbix e SolarWinds como benchmark funcional, sem declarar equivalencia total. A classificacao abaixo separa o que esta completo, parcial, ausente ou planejado no NetGuard atual.

## Fases de implementacao

### Fase 1 - Estabilizacao comercial minima

- Docker estavel, healthchecks, migrations idempotentes e logs operacionais.
- Testes backend e build frontend.
- `.env.example` seguro, sem segredos reais.
- HTTPS na web, CORS alinhado e proxy `/api` para evitar mixed content.
- Docker Context oficial para executar Compose no Docker Engine da VM Linux.

### Fase 2 - Paridade operacional essencial

- Discovery orientado a rede e hosts.
- Inventario, grupos e templates de monitoramento.
- Triggers configuraveis, incidentes, alertas e Media Types.
- Dashboard operacional, historico de metricas, acknowledgement e resolucao.
- Relatorios basicos e SLA simples.

### Fase 3 - Recursos avancados

- Topologia, path analysis estilo NetPath e correlacao de causa raiz.
- SLA por janela/servico, relatorios exportaveis e escalonamento.
- Janelas de manutencao, silenciamento, SNMP traps e syslog avancado.

### Fase 4 - Recursos enterprise

- RBAC forte, auditoria, multi-tenant e API publica versionada.
- Alta disponibilidade, hardening, IPAM, flow monitoring.
- Configuracao de dispositivos, backup/export/import e NCM.

## Matriz de paridade

| Funcionalidade | Zabbix/SolarWinds possuem? | NetGuard possui? | Status no NetGuard | Prioridade | Esforco | Acao recomendada | Arquivos afetados |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Auto-discovery de rede | Sim | Parcial | Parcial | P0 critico | medio | Evoluir de discovery por host para scan CIDR com ping, TCP, SNMP e promocao controlada. | `api/main.py`, `infra/initdb`, `netguard-frontend/src/pages/Discovery.jsx` |
| Cadastro manual de ativos | Sim | Sim | Completo | P0 critico | baixo | Manter CRUD, validacoes e filtros. | `api/main.py`, `netguard-frontend/src/pages/Hosts.jsx` |
| Inventario | Sim | Parcial | Parcial | P1 importante | medio | Expandir tags, fabricante, modelo, localizacao, owner e ciclo de vida. | `infra/initdb/010_host_groups.sql`, `api/main.py` |
| SNMP v2c | Sim | Sim | Completo | P0 critico | baixo | Manter ifMIB, ifHC counters e fallback. | `poller/snmp/snmp_poller.py` |
| SNMPv3 | Sim | Nao comprovado | Planejado | P1 importante | medio | Adicionar auth/priv, user, protocol, passphrases e testes de laboratorio. | `poller/snmp/snmp_poller.py`, `.env.example` |
| ICMP | Sim | Sim | Completo | P0 critico | baixo | Manter timeout/retry e historico. | `poller/main.py` |
| TCP checks | Sim | Parcial | Parcial | P1 importante | medio | Expor checks TCP configuraveis por host/template. | `poller/main.py`, `monitoring_templates` |
| Syslog | Sim | Sim | Parcial | P1 importante | baixo | Melhorar parsing, severidades e filtros. | `poller/syslog/collector.py`, `api/main.py` |
| SNMP traps | Sim | Nao | Ausente | P2 evolucao | alto | Criar collector UDP/162 e normalizador. | novo worker, `infra/initdb` |
| Metricas historicas | Sim | Sim | Completo | P0 critico | baixo | Manter limites e indices. | `metrics`, `api/main.py` |
| Dashboards | Sim | Sim | Parcial | P0 critico | medio | Ampliar cards comerciais e drill-down. | `Dashboard.jsx`, `api/main.py` |
| Grafana | Sim | Sim | Completo | P1 importante | baixo | Manter provisioning e evidencias. | `infra/grafana-provisioning` |
| Graficos no frontend | Sim | Parcial | Parcial | P1 importante | medio | Adicionar charts nativos para metricas e SLA. | `Metrics.jsx`, `HostMonitoring.jsx` |
| Incidentes | Sim | Sim | Parcial | P0 critico | medio | Expandir owner, comentarios, historico e filtros. | `api/main.py`, `Incidents.jsx` |
| Triggers | Sim | Parcial | Parcial | P0 critico | alto | Criar schema de triggers configuraveis e engine dedicado. | `infra/initdb`, `poller/anomaly_to_incident` |
| Anomalias | Sim | Sim | Parcial | P1 importante | medio | Documentar thresholds e reduzir ruido. | `poller/anomaly`, `api/main.py` |
| Alertas | Sim | Sim | Completo | P0 critico | baixo | Manter anti-spam, falhas controladas e auditoria. | `api/alert_service.py` |
| Media Types | Sim | Sim | Completo | P0 critico | baixo | Manter providers e mascaramento. | `api/main.py`, `Alerts.jsx` |
| Anti-spam | Sim | Sim | Completo | P0 critico | baixo | Manter cooldown de 10 minutos e registros. | `api/alert_service.py` |
| Escalacao | Sim | Parcial | Planejado | P1 importante | medio | Reenvio de criticos abertos apos janela configuravel. | `api/alert_service.py`, `infra/initdb` |
| Acknowledgement | Sim | Parcial | Parcial | P1 importante | medio | Criar endpoint/tela de ACK e historico. | `api/main.py`, `Incidents.jsx` |
| SLA | Sim | Parcial | Parcial | P1 importante | baixo | Implementado SLA simples por disponibilidade; evoluir por servico/janela. | `api/main.py` |
| Relatorios | Sim | Parcial | Parcial | P1 importante | baixo | Implementados endpoints basicos de disponibilidade, incidentes e alertas; evoluir export CSV/PDF. | `api/main.py`, `Relatorios.jsx` |
| Mapas/topologia | Sim | Parcial | Planejado | P1 importante | alto | Criar grafo host-link-status com incidente associado. | `api/main.py`, nova pagina |
| NetPath/path analysis | SolarWinds sim | Nao | Planejado | P2 evolucao | alto | Implementar traceroute/hops com historico. | novo worker/API |
| Flow monitoring | SolarWinds sim | Nao | Ausente | P2 evolucao | alto | Planejar NetFlow/sFlow/IPFIX collector. | novo worker, `infra/initdb` |
| IPAM | SolarWinds sim | Nao | Ausente | P2 evolucao | alto | Planejar cadastro de sub-redes, ocupacao e conflitos. | novo modulo |
| RBAC | Sim | Parcial | Parcial | P0 critico | medio | Trocar login simples por JWT, hash e roles efetivos. | `api/main.py`, `Admin.jsx` |
| Auditoria | Sim | Parcial | Planejado | P1 importante | medio | Registrar alteracoes admin, ACK, canais e hosts. | `infra/initdb`, `api/main.py` |
| Logs | Sim | Sim | Parcial | P1 importante | baixo | Padronizar niveis e correlacao por incidente. | workers, API |
| Backup/export | Sim | Nao | Planejado | P2 evolucao | medio | Exportar configuracao, hosts, templates e canais sem segredo. | novo endpoint |
| Templates de dispositivos | Sim | Sim | Parcial | P1 importante | medio | Expandir templates Linux, Switch SNMP, ICMP, TCP e Syslog; vendors Cisco/Aruba/Dell/HPE. | `011_monitoring_templates.sql`, `Templates.jsx` |
| Multi-vendor | Sim | Parcial | Planejado | P1 importante | alto | Criar profiles/OIDs por vendor e autodeteccao. | `poller/snmp`, `infra/initdb` |
| API publica | Sim | Parcial | Parcial | P1 importante | medio | Versionar `/api/v1`, autenticar e documentar OpenAPI operacional. | `api/main.py` |
| Healthchecks | Sim | Sim | Completo | P0 critico | baixo | Manter `/health`, `/health/deep` e healthchecks Compose. | `api/main.py`, `docker-compose.yml` |
| Documentacao | Sim | Sim | Parcial | P0 critico | baixo | Consolidar operacao, evidencias, paridade e limitacoes. | `README.md`, `docs/*` |
| Testes automatizados | Sim | Sim | Parcial | P0 critico | medio | Ampliar testes para relatorios, SLA, discovery, triggers e RBAC. | `api/tests` |
| Seguranca | Sim | Parcial | Parcial | P0 critico | medio | Fortalecer RBAC, TLS confiavel, secrets e auditoria. | `.env.example`, `api/main.py`, Compose |

## Melhorias implementadas nesta rodada

- Endpoints de relatorio operacional:
  - `GET /reports/availability`
  - `GET /reports/incidents`
  - `GET /reports/alerts`
  - `GET /sla/summary`
- CORS padrao passou a incluir origens HTTPS da web.
- Documentacao do Docker Context SSH remoto criada em `docs/docker-context-vm.md`.

## Lacunas honestas restantes

- A VM ainda nao esta acessivel via SSH key para o Codex; sem isso, `docker --context netguard-vm ps` nao consegue provar o engine remoto.
- A web HTTPS ja foi preparada no codigo, mas ainda precisa ser aplicada no Docker Engine da VM com `docker --context netguard-vm compose -p netguard up -d --build`.
- SNMPv3, traps, NetFlow/sFlow/IPFIX, IPAM e NCM seguem como roadmap tecnico.
- RBAC forte e auditoria ainda sao os maiores gaps para uso corporativo real.
