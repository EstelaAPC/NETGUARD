# Relatorio Final de Validacao do NetGuard para TCC

Data da validacao: 08/05/2026

## 1. Objetivo da validacao

O objetivo desta validacao foi comprovar que o NetGuard esta operacional em ambiente de laboratorio, com acesso seguro via HTTPS, monitoramento de ativos, coleta de telemetria, geracao de incidentes, envio de alertas, dashboards, retencao configuravel e rotinas de limpeza periodica.

A validacao tambem teve como objetivo registrar evidencias tecnicas para anexar ao TCC, sem apagar dados existentes e sem utilizar `docker compose down -v`.

## 2. Ambiente utilizado

O ambiente validado roda em uma VM Linux acessivel em `192.168.56.15`, utilizando Docker Compose.

Endereco oficial de acesso:

```text
https://netguard.local/
```

O nome `netguard.local` aponta para `192.168.56.15` no ambiente Windows. O certificado local do Caddy foi exportado e importado no Windows para remover o aviso `NET::ERR_CERT_AUTHORITY_INVALID`.

Ativos principais do laboratorio:

| Item | Endereco | Observacao |
|---|---:|---|
| NetGuard VM | `192.168.56.15` | Plataforma principal |
| Switch Lab | `192.168.56.20` | Emulador de switch fixo para testes |
| Ollama / IA | `192.168.56.1:11434` | Servico de IA separado do Switch Lab |

## 3. Arquitetura final

A arquitetura final utiliza um reverse proxy HTTPS com Caddy na entrada da plataforma.

Fluxo principal:

```text
Navegador Windows
  -> https://netguard.local/
  -> Caddy reverse proxy
  -> Frontend React
  -> /api/*
  -> FastAPI
  -> PostgreSQL/TimescaleDB
```

Rotas oficiais:

| Recurso | URL |
|---|---|
| Frontend | `https://netguard.local/` |
| API | `https://netguard.local/api/*` |
| Grafana | `https://netguard.local/grafana/` |

Portas antigas foram mantidas apenas para debug:

| Recurso | URL de debug |
|---|---|
| Frontend direto | `https://192.168.56.15:8081` |
| API direta | `http://192.168.56.15:8000` |
| Grafana direto | `http://192.168.56.15:3000` |

## 4. Servicos Docker

Os principais servicos Docker validados foram:

| Servico | Funcao |
|---|---|
| `reverse-proxy` | Caddy HTTPS, redirecionamento HTTP para HTTPS e roteamento |
| `web` | Frontend React |
| `api` | API FastAPI |
| `db` | PostgreSQL/TimescaleDB |
| `grafana` | Dashboards |
| `poller` | Coleta ICMP/TCP |
| `snmp-poller` | Coleta SNMP |
| `syslog` | Recebimento UDP/514 |
| `syslog-collector` | Processamento de syslog |
| `anomaly-engine` | Calculo de anomalias |
| `anomaly-to-incident` | Promocao de sinais para incidentes |
| `housekeeper` | Limpeza periodica por retencao |
| `lab-linux-01` | Host Linux de laboratorio |

O Docker Compose foi validado com os containers principais em execucao, banco saudavel e sem apagar volumes.

## 5. Endpoints validados

Endpoints validados via HTTPS:

```text
https://netguard.local/
https://netguard.local/api/health
https://netguard.local/api/health/deep
https://netguard.local/api/alerts/summary
https://netguard.local/api/alerts/channels
https://netguard.local/api/alerts/incidents
https://netguard.local/api/alerts/notifications
https://netguard.local/api/housekeeper/status
https://netguard.local/grafana/
```

Tambem foi validado que:

- `http://192.168.56.15/` redireciona para HTTPS;
- a API responde via `/api/*` pelo reverse proxy;
- o frontend usa rota relativa `/api`, evitando mixed content;
- o Grafana responde pelo subcaminho `/grafana/`.

## 6. Funcionalidades validadas

Funcionalidades validadas no ambiente:

- acesso HTTPS pelo navegador;
- frontend React operacional;
- API FastAPI saudavel;
- banco PostgreSQL/TimescaleDB saudavel;
- coleta ICMP;
- coleta SNMP;
- recebimento e processamento de syslog;
- calculo de anomalias;
- geracao de incidentes;
- notificacoes por Telegram;
- Media Types/canais de notificacao;
- dashboards Grafana;
- housekeeper de retencao;
- instalador Windows;
- documentacao operacional.

O Switch Lab ficou fixo em `192.168.56.20`, evitando conflito com a IA/Ollama em `192.168.56.1:11434`.

## 7. Alertas e incidentes

Os seguintes alertas e incidentes foram validados:

| Tipo | Resultado |
|---|---|
| `HOST_DOWN` | Incidente gerado e resolvido |
| `ICMP_COLLECTION_SILENCE` | Incidente gerado e resolvido |
| `SNMP_COLLECTION_SILENCE` | Incidente gerado e resolvido |
| `SYSLOG_COLLECTION_SILENCE` | Incidente gerado para host com syslog esperado |
| `LOOP_RISK` | Incidente gerado com evidencia nas portas Gi0/23 e Gi0/24 |

O `LOOP_RISK` foi validado com consolidacao para evitar churn, mantendo um unico incidente ativo por switch durante a janela de risco.

O Telegram foi validado com envios bem-sucedidos. Tambem foi observada falha externa de DNS/Internet para `api.telegram.org`; essa falha foi registrada como erro de notificacao e nao impediu a abertura, atualizacao ou resolucao de incidentes.

## 8. HTTPS e seguranca

O HTTPS foi implementado com Caddy usando certificado local interno.

Itens validados:

- reverse proxy Caddy em `80/443`;
- redirecionamento de HTTP para HTTPS;
- certificado local exportado para `infra/certs/netguard-caddy-root.crt`;
- CA local importada no Windows;
- acesso por nome `https://netguard.local/`;
- API e Grafana roteados pelo mesmo dominio;
- ausencia de mixed content no frontend;
- headers basicos de seguranca no proxy.

O aviso `NET::ERR_CERT_AUTHORITY_INVALID` e esperado antes da importacao da CA local do Caddy no Windows. Apos importar a CA em "Autoridades de Certificacao Raiz Confiaveis" e reiniciar o navegador, o acesso por `https://netguard.local/` passa a ser confiavel no ambiente local.

Nenhuma chave privada foi copiada para o projeto. Apenas o certificado publico `root.crt` foi exportado.

## 9. Housekeeper e retencao

Foi implementado e validado um housekeeper semelhante ao conceito usado por ferramentas de monitoramento maduras, como o Zabbix, para limpeza periodica de dados antigos.

O endpoint validado foi:

```text
https://netguard.local/api/housekeeper/status
```

Retencoes configuraveis documentadas:

| Dado | Retencao |
|---|---:|
| Metricas | 30 dias |
| Syslog | 14 dias |
| Anomalias | 30 dias |
| Insights de IA | 30 dias |
| Notificacoes | 180 dias |
| Incidentes resolvidos | 180 dias |

O housekeeper nao remove incidentes abertos e nao apaga dados recentes.

## 10. Limitacoes conhecidas

O NetGuard nao deve ser apresentado como equivalente ao Zabbix, SolarWinds ou outras suites comerciais maduras.

Ele se aproxima conceitualmente dessas ferramentas em recursos como:

- monitoramento de hosts;
- coleta SNMP, ICMP e syslog;
- alertas;
- incidentes;
- Media Types;
- dashboards;
- retencao e limpeza periodica.

Limitacoes conhecidas:

- o certificado HTTPS e local, adequado para laboratorio;
- `netguard.local` depende de DNS local ou arquivo `hosts` no Windows;
- envio Telegram depende de DNS e Internet funcionais na VM;
- o ambiente ainda e de laboratorio, nao uma arquitetura HA;
- capacidades finais de escala dependem de benchmark com quantidade real de hosts, interfaces, volume de syslog e recursos da VM.

## 11. Evidencias recomendadas

Prints e evidencias recomendadas para o TCC:

1. `docker compose -p netguard ps -a` mostrando containers principais.
2. Navegador acessando `https://netguard.local/`.
3. Certificado confiavel no navegador.
4. Certificado `netguard-caddy-root.crt` importado no Windows.
5. `https://netguard.local/api/health` retornando status saudavel.
6. `https://netguard.local/api/health/deep` validando banco e migrations.
7. Tela de hosts monitorados com Switch Lab em `192.168.56.20`.
8. Tela de alertas e incidentes.
9. Incidente `HOST_DOWN`.
10. Incidente `ICMP_COLLECTION_SILENCE`.
11. Incidente `SNMP_COLLECTION_SILENCE`.
12. Incidente `SYSLOG_COLLECTION_SILENCE`.
13. Incidente `LOOP_RISK` com Gi0/23 e Gi0/24.
14. Tela de Media Types/canais.
15. Registro de notificacoes Telegram.
16. `https://netguard.local/api/housekeeper/status`.
17. Grafana em `https://netguard.local/grafana/`.
18. Arquivo do instalador Windows.
19. Documentacao de retencao e HTTPS.

## 12. Conclusao tecnica

A validacao demonstrou que o NetGuard esta funcional como plataforma de monitoramento em laboratorio, com acesso HTTPS, reverse proxy, frontend, API, banco, dashboards, coleta de telemetria, anomalias, incidentes, alertas, Media Types e retencao configuravel.

O sistema foi validado sem apagar dados e sem utilizar `docker compose down -v`.

Tecnicamente, o NetGuard apresenta uma base coerente para um MVP academico de monitoramento de redes. Ele nao substitui ferramentas comerciais maduras, mas se aproxima conceitualmente delas ao implementar componentes essenciais como monitoramento, incidentes, notificacoes, dashboards e housekeeper de retencao.
