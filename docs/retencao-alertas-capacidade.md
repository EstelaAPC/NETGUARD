# Retencao, alertas e capacidade do NetGuard

## Alertas de indisponibilidade

O NetGuard gera incidente e envia alerta pelos canais configurados quando:

- o host para de responder disponibilidade (`HOST_DOWN`);
- a coleta ICMP fica sem telemetria recente (`ICMP_COLLECTION_SILENCE`);
- a coleta SNMP para de chegar para host com SNMP habilitado (`SNMP_COLLECTION_SILENCE`);
- o syslog para de chegar para host marcado como fonte esperada de syslog (`SYSLOG_COLLECTION_SILENCE`).

Quando a telemetria volta, o incidente aberto e resolvido pelo mesmo fluxo de alertas, com notificacao de recuperacao quando o canal permite.

Parametros principais:

```env
AVAILABILITY_ALERTS_ENABLED=true
AVAILABILITY_ICMP_STALE_MULTIPLIER=4
AVAILABILITY_SNMP_STALE_MULTIPLIER=4
AVAILABILITY_SYSLOG_STALE_SEC=300
AVAILABILITY_HOST_DOWN_SAMPLES=2
AVAILABILITY_MIN_STALE_SEC=60
```

Exemplo: com ICMP a cada 15 segundos e multiplicador 4, o NetGuard considera silencio ICMP depois de 60 segundos sem `host.alive`. Para `HOST_DOWN`, o padrao exige 2 amostras recentes em `host.alive=0`.

## Housekeeper

O NetGuard agora possui um servico `housekeeper`, equivalente operacional ao conceito de limpeza periodica do Zabbix. Ele roda em ciclo e limpa dados antigos por politica de retencao.

Retencao padrao:

```env
HOUSEKEEPER_ENABLED=true
HOUSEKEEPER_INTERVAL_SEC=3600
HOUSEKEEPER_BATCH_ROWS=50000
RETENTION_METRICS_DAYS=30
RETENTION_SYSLOG_DAYS=14
RETENTION_ANOMALY_SCORES_DAYS=30
RETENTION_AI_INSIGHTS_DAYS=30
RETENTION_NOTIFICATIONS_DAYS=180
RETENTION_RESOLVED_INCIDENTS_DAYS=180
```

O housekeeper remove:

- metricas antigas de `metrics`;
- eventos antigos de `syslog_events`;
- scores antigos de `anomaly_scores`;
- insights expirados ou antigos de `ai_insights`;
- historico antigo de `incident_notifications`;
- incidentes resolvidos antigos.

Incidentes abertos nao sao removidos pelo housekeeper.

Status operacional:

```text
GET /housekeeper/status
```

Esse endpoint mostra a politica atual e a ultima execucao registrada em `housekeeper_runs`.

## Capacidade simultanea de hosts

Eu nao vou cravar um numero unico sem benchmark do hardware real, porque o gargalo muda conforme intervalo, numero de interfaces SNMP, volume de syslog, disco do PostgreSQL/Timescale e recursos da VM.

Faixas conservadoras para a arquitetura atual:

- VM pequena, 2 vCPU e 4 GB RAM: cerca de 100 a 300 hosts simples com ICMP e SNMP basico.
- VM media, 4 vCPU e 8 GB RAM: cerca de 500 a 1500 hosts, dependendo do numero de interfaces e do intervalo.
- Ambientes maiores precisam separar banco, ajustar intervalos, reduzir cardinalidade de labels e medir escrita por segundo.

Regra pratica para switches: um switch de 24 portas com SNMP a cada 15 segundos pode gerar centenas de linhas por minuto, porque cada porta tem varios contadores. O numero de hosts suportado cai se todos forem switches grandes com muitas interfaces e syslog intenso.

Antes de vender como capacidade garantida, rode benchmark com:

- total de hosts;
- media de interfaces por host;
- intervalo ICMP/SNMP;
- eventos syslog por minuto;
- CPU/RAM/disco da VM;
- latencia media do banco;
- linhas gravadas por segundo.

## Instalador Windows

A base do instalador esta em:

```text
installer/windows/NetGuardInstaller.ps1
installer/windows/build-installer.ps1
```

Ele entrega uma interface para instalar/atualizar/iniciar/parar o NetGuard e sobe o Docker Compose por tras. Para uma versao comercial final, o recomendado e gerar o EXE, assinar digitalmente, trocar senhas padrao no primeiro acesso e validar privilegios administrativos no inicio.
