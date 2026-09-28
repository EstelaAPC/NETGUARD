# Centro de Testes Reproduzíveis do `lab-linux-01`

Este guia concentra os cenários operacionais do host de laboratório `lab-linux-01`.

Objetivos:

- execução simples
- comportamento seguro e reversível
- repetição fácil para demonstração de TCC
- comandos curtos e previsíveis

## Pré-requisitos

1. Subir o ambiente:

```bash
docker compose up -d --build
```

2. Garantir a aplicação da migração do pipeline `loop_risk`:

```bash
docker compose up -d loop-risk-migrate
```

3. Confirmar que o host de laboratório está saudável:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control status
```

4. Se quiser limpar a demo antes de começar:

Linux/macOS:

```bash
sh scripts/demo-reset.sh
```

PowerShell:

```powershell
.\scripts\demo-reset.ps1
```

## Comando padrão

Sem wrapper:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control <cenario> [parametros...]
```

Com wrapper PowerShell:

```powershell
.\scripts\run-lab-scenario.ps1 <cenario> [parametros...]
```

## Resumo dos cenários

| Cenário | Comando | Efeito esperado no NetGuard | Recuperação |
| --- | --- | --- | --- |
| `preloop` | `preloop 1/1/10` | gera os quatro sinais precursores e tende a abrir `loop_risk` | automático, sem rollback |
| `snmp_down` | `snmp_down` | SNMP para de responder; métricas SNMP deixam de atualizar | `snmp_up` |
| `snmp_up` | `snmp_up` | SNMP volta a responder | imediato |
| `host_loss` | `host_loss` ou `host_loss 120` | bloqueia ICMP e UDP/161; `host.alive` tende a cair e SNMP para | `host_recover` ou auto-recuperação se usar segundos |
| `host_recover` | `host_recover` | remove o bloqueio do `host_loss` | imediato |
| `high_cpu` | `high_cpu 60 2` | gera carga alta local por 60 s com 2 workers; marca o evento em syslog | automático ou `high_cpu_stop` |
| `syslog_burst` | `syslog_burst 40 0.05` | envia uma enxurrada controlada de syslogs | automático |
| `service_fail` | `service_fail` | interrompe o `rsyslog`, simulando falha do encaminhamento de syslog | `service_recover` |
| `service_recover` | `service_recover` | restaura o `rsyslog` | imediato |

## Detalhes por cenário

### 1. `preloop`

Comando:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control preloop 1/1/10
```

O que faz:

- envia `STP_TOPOLOGY_CHANGE`
- envia `MAC_FLAPPING`
- envia `INTERFACE_FLAP`
- envia `BROADCAST_STORM`

O que observar:

- aba `Syslog`
- aba `Previsões`
- aba `Incidentes`

### 2. `snmp_down`

Comando:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control snmp_down
```

O que faz:

- interrompe apenas o `snmpd`
- mantém o host acessível
- registra o evento `SNMP_DOWN` em syslog antes da parada

O que observar:

- métricas SNMP deixam de receber novos pontos
- o host continua respondendo a ICMP

Rollback:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control snmp_up
```

### 3. `snmp_up`

Comando:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control snmp_up
```

O que faz:

- restaura o `snmpd`
- registra `SNMP_UP` em syslog

O que observar:

- métricas SNMP voltam a entrar no host

### 4. `host_loss`

Comandos:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control host_loss
docker compose exec -T lab-linux-01 netguard-lab-control host_loss 120
```

O que faz:

- bloqueia `ICMP echo-request` e `ICMP echo-reply`
- bloqueia `UDP/161`
- simula perda do host para a visão do monitoramento

O que observar:

- `host.alive` tende a cair para `0`
- `icmp.loss_pct` tende a subir para `100`
- novas métricas SNMP deixam de chegar

Recuperação manual:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control host_recover
```

### 5. `host_recover`

Comando:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control host_recover
```

O que faz:

- remove as regras aplicadas por `host_loss`
- registra `HOST_RECOVER` em syslog

O que observar:

- ICMP volta
- SNMP volta a responder
- o host tende a retornar ao estado operacional

### 6. `high_cpu`

Comandos:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control high_cpu
docker compose exec -T lab-linux-01 netguard-lab-control high_cpu 90 3
```

O que faz:

- cria carga local com loops de CPU
- por padrão roda por `60` segundos com `2` workers
- emite `HIGH_CPU_START` e `HIGH_CPU_END` em syslog

O que observar:

- timeline e syslog do host
- possível impacto indireto no comportamento do host durante a demonstração

Parada manual, se necessário:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control high_cpu_stop
```

### 7. `syslog_burst`

Comando:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control syslog_burst 40 0.05
```

O que faz:

- envia uma sequência controlada de mensagens `SYSLOG_BURST_SEQ_*`
- o primeiro parâmetro é a quantidade
- o segundo parâmetro é a pausa entre mensagens, em segundos

O que observar:

- aba de syslog do host
- comportamento do coletor sob rajada curta

### 8. `service_fail`

Comando:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control service_fail
```

O que faz:

- emite `SERVICE_FAIL_RSYSLOG`
- interrompe o `rsyslog`
- simula falha do serviço de encaminhamento de syslog

O que observar:

- novos `logger` do host deixam de ser encaminhados
- o host continua existindo, mas a trilha de syslog fica interrompida

Rollback:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control service_recover
```

### 9. `service_recover`

Comando:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control service_recover
```

O que faz:

- restaura o `rsyslog`
- emite `SERVICE_RECOVER_RSYSLOG`

O que observar:

- os eventos do host voltam a ser encaminhados normalmente

## Sequência sugerida para demo

1. `status`
2. `preloop 1/1/10`
3. verificar `Previsões`
4. verificar `Incidentes`
5. `snmp_down`
6. `snmp_up`
7. `host_loss 120`
8. `syslog_burst 30 0.03`
9. `high_cpu 60 2`
10. `service_fail`
11. `service_recover`

## Observações de segurança

- `host_loss` usa apenas regras locais de firewall no próprio container.
- `high_cpu` tem encerramento automático e também pode ser parado manualmente.
- `service_fail` afeta apenas o `rsyslog` do host de laboratório.
- `snmp_down` afeta apenas o `snmpd` do host de laboratório.
- o reset de demo limpa apenas artefatos de `loop_risk` do `lab-linux-01`.
