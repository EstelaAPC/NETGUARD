# Demonstração do TCC: NetGuard

Este roteiro foi pensado para uma apresentação curta, segura e repetível, com foco em:

- monitoramento por host
- correlação de sinais precursores
- geração de incidente
- previsão de `loop_risk`

O ativo principal da demonstração é o `lab-linux-01`, com IP `172.30.10.10`.

---

## 1. Preparação do ambiente

Suba o ambiente:

```bash
docker compose up -d --build
```

Garanta a aplicação idempotente do pipeline `loop_risk` no banco ativo:

```bash
docker compose up -d loop-risk-migrate
```

Confirme o bootstrap do host de laboratório:

```bash
curl -X POST http://localhost:8000/lab/bootstrap
```

Se quiser começar de um estado limpo para a banca:

Linux/macOS:

```bash
sh scripts/demo-reset.sh
```

PowerShell:

```powershell
.\scripts\demo-reset.ps1
```

Confirme o estado do host:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control status
```

No NetGuard, valide:

1. Acesse `Monitoramento > Por host`.
2. Abra o host `lab-linux-01`.
3. Confirme:
   - cadastro ativo
   - saúde operacional
   - métricas SNMP chegando
   - syslog do host visível
   - abas `Incidentes` e `Previsões` limpas após o reset

---

## 2. Fluxo recomendado de demonstração

### Etapa 1. Contextualização

Mensagem sugerida:

> “O NetGuard monitora ativos de rede e infraestrutura, correlaciona telemetria SNMP com eventos de syslog e antecipa incidentes operacionais antes da falha se consolidar.”

O que mostrar:

1. Tela `Monitoramento > Por host`.
2. Destaque visual do `lab-linux-01` como host principal da demonstração.
3. Abertura da tela de detalhe do host.

### Etapa 2. Situação normal

Mensagem sugerida:

> “Neste primeiro momento, o host está operacional, com coleta de disponibilidade, SNMP e syslog.”

O que mostrar na tela do host:

1. Cards de resumo.
2. Estado de saúde.
3. Aba `SNMP`.
4. Timeline operacional.

### Etapa 3. Geração de sinais precursores

Execute:

```bash
docker compose exec -T lab-linux-01 netguard-lab-control preloop 1/1/10
```

Mensagem sugerida:

> “Agora eu vou injetar sinais sintéticos controlados que representam pré-condições típicas de um possível loop de camada 2.”

O que observar:

1. Aba `Syslog`.
2. Eventos:
   - `STP_TOPOLOGY_CHANGE`
   - `MAC_FLAPPING`
   - `INTERFACE_FLAP`
   - `BROADCAST_STORM`
3. Timeline operacional do host.

### Etapa 4. Correlação e predição

Mensagem sugerida:

> “O sistema correlaciona esses eventos em uma janela temporal curta e produz um score de risco operacional.”

O que mostrar:

1. Aba `Previsões`.
2. Registro `loop_risk`.
3. Score, evidências e recomendação operacional.

### Etapa 5. Incidente aberto automaticamente

Mensagem sugerida:

> “Quando a correlação atinge o limiar definido, o NetGuard transforma a predição em incidente operacional nativo.”

O que mostrar:

1. Aba `Incidentes`.
2. Incidente `loop_risk`.
3. Badge de severidade.
4. Evidências consolidadas.
5. Recomendação operacional.

### Etapa 6. Reinício limpo da demonstração

Se precisar repetir a apresentação:

Linux/macOS:

```bash
sh scripts/demo-reset.sh
```

PowerShell:

```powershell
.\scripts\demo-reset.ps1
```

Mensagem sugerida:

> “Como este é um laboratório controlado, eu consigo limpar os artefatos de teste do `loop_risk` e repetir a demonstração do zero.”

---

## 3. Verificações rápidas por API

Predições do host:

```bash
curl http://localhost:8000/hosts/8/predictions
```

Incidentes do host:

```bash
curl http://localhost:8000/hosts/8/incidents
```

Syslog do host:

```bash
curl "http://localhost:8000/hosts/8/syslog?limit=20"
```

---

## 4. Ordem ideal para uma banca de 5 a 7 minutos

1. Mostrar a lista `Por host`.
2. Abrir o `lab-linux-01`.
3. Apresentar resumo, saúde e SNMP.
4. Disparar `preloop`.
5. Atualizar a tela.
6. Mostrar syslog.
7. Mostrar previsão `loop_risk`.
8. Mostrar incidente `loop_risk`.
9. Encerrar com a narrativa de antecipação de falha.

---

## 5. Checklist antes da apresentação

1. `docker compose ps`
2. `docker compose up -d loop-risk-migrate`
3. `curl -X POST http://localhost:8000/lab/bootstrap`
4. `docker compose exec -T lab-linux-01 netguard-lab-control status`
5. `sh scripts/demo-reset.sh` ou `.\scripts\demo-reset.ps1`
6. Confirmar acesso ao front
7. Confirmar que `lab-linux-01` aparece em `Monitoramento > Por host`
8. Confirmar que SNMP recente está chegando
9. Deixar um terminal preparado com o comando `preloop`
10. Deixar a tela do host já aberta

---

## 6. Referências operacionais

- Cenários reproduzíveis: [LAB_SCENARIOS.md](/\\192.168.56.15\netguard\docs\LAB_SCENARIOS.md)
- Host principal do laboratório: `lab-linux-01`
- IP do host principal: `172.30.10.10`
