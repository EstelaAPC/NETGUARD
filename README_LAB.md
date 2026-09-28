# NetGuard — README do LAB (VirtualBox + Aruba AOS-CX + Docker)

Este guia configura um laboratório **reproduzível** para o NetGuard rodar com:
- 1 VM Linux (Kali/Debian/Ubuntu) = **VM do NetGuard** (Docker + DB + Grafana + pollers)
- 2 VMs Aruba AOS-CX Simulator = **SWITCH-CORE** e **SWITCH-ACCESS**
- Coleta **SNMPv2c** e **Syslog** (remoto) dos switches para o NetGuard
- Detecção de **anomalias** (EWMA + z-score) e geração de **incidentes**

> Objetivo: qualquer pessoa (ex.: Will) clonar o repo, subir o docker-compose e repetir o lab.

---

## 1) Pré-requisitos

### Hardware recomendado
- 16 GB RAM (mínimo funcional)
- CPU com virtualização (VT-x/AMD-V)
- Espaço em disco: 40–60 GB livres

### Software
- VirtualBox instalado
- Git instalado
- Docker + Docker Compose instalados na VM do NetGuard

---

## 2) Topologia do LAB

- **SWITCH-CORE** ↔ **SWITCH-ACCESS** (trunk/uplink):
  - CORE `1/1/1` <-> ACCESS `1/1/1`
- **VM NetGuard** conectada ao ACCESS:
  - ACCESS `1/1/2` (access VLAN 10) <-> NIC do NetGuard na rede interna

### Plano de IP (sugestão)
- VLAN 10 (LAB): `10.10.10.0/24`
  - SWITCH-CORE SVI VLAN10: `10.10.10.1/24`
  - SWITCH-ACCESS (se precisar SVI): `10.10.10.5/24`
  - VM NetGuard (na VLAN10): `10.10.10.10/24`

- MGMT dos switches (acesso Web/SSH):
  - SWITCH-CORE mgmt: `192.168.1.50/24`
  - SWITCH-ACCESS mgmt: `192.168.1.51/24`

> O gateway do mgmt depende da sua rede local. Se você não precisa de internet nos switches, pode ignorar rota default neles.

---

## 3) Configuração das Redes no VirtualBox

### 3.0 Switch Lab fixo no Windows

Para os testes do NetGuard, o emulador de switch do Windows fica fixo em:

- Nome no NetGuard: `Switch Lab`
- IP do emulador de switch: `192.168.56.20`
- SNMP v2c: comunidade `netguard`, porta `161`

Na VM `NetGuard`, esse IP deve sair por uma NIC dedicada ligada ao `VirtualBox Host-Only Ethernet Adapter #2`.
Configuracao fixa validada:

- VM `NetGuard`, adaptador 3: `VirtualBox Host-Only Ethernet Adapter #2`
- Interface Linux: `eth2`
- IP da VM nessa interface: `192.168.56.16/32`
- Rota persistente: `192.168.56.20/32` via `eth2`

O IP `192.168.56.20` nao deve ser usado para Ollama/IA. Na VM oficial, a IA usa `http://192.168.56.1:11434`.

### 3.1 VM NetGuard (Linux)
Configurar **2 adaptadores**:

**Adaptador 1 (Internet)**
- Tipo: NAT (ou Bridge se preferir)
- Objetivo: permitir `apt`, `docker pull`, etc.

**Adaptador 2 (LAB)**
- Tipo: Rede Interna
- Nome: `USER_VLAN` (ou outro nome fixo, mas use o mesmo em todo lugar)
- Objetivo: conectar NetGuard no SWITCH-ACCESS via VLAN 10

> A interface do NetGuard na rede interna deve receber IP `10.10.10.10/24`.

### 3.2 SWITCH-CORE e SWITCH-ACCESS (AOS-CX Simulator)
Em cada switch:
- Adaptador 1: (opcional) NAT/Bridge para mgmt (se você quiser acessar pela sua rede local)
- Adaptador 2: Rede Interna `USER_VLAN` (para o tráfego do lab)
- Adaptador 3: Rede Interna `TRUNK_NET` (para interligar CORE <-> ACCESS)

> O “TRUNK_NET” deve ser a mesma rede interna nos dois switches para simular o cabo entre eles.

Resumo de redes internas sugeridas:
- `USER_VLAN` = NetGuard + porta de acesso no SWITCH-ACCESS
- `TRUNK_NET` = CORE <-> ACCESS

---

## 4) Subir o NetGuard via Docker (na VM NetGuard)

### 4.1 Clonar o repositório
```bash
cd ~
git clone <URL_DO_REPO> netguard
cd ~/netguard
docker compose up -d --build
```

### 4.2 Host Docker dedicado para demonstracao

O compose sobe um host leve chamado `lab-linux-01`, pensado para a banca:

- hostname: `lab-linux-01`
- IP fixo: `172.30.10.10`
- SNMP v2c: comunidade `netguard`
- syslog remoto: encaminhado automaticamente para o servico `syslog`
- eventos sinteticos: script `netguard-preloop-demo`

Esse host pode ser cadastrado no NetGuard sem depender do IP da bridge Docker.

### 4.3 Cadastro recomendado no NetGuard

Cadastrar um host com:

- Nome: `lab-linux-01`
- IP: `172.30.10.10`
- SNMP profile:
  - version: `v2c`
  - community: `netguard`
  - port: `161`
  - timeout: `1`
  - retries: `1`
  - enabled: `true`

Profiles recomendados:

- `ICMP Basic`
- `Generic IF-MIB`
- `SNMP System`

Depois do cadastro:

1. abrir a edicao do host
2. executar a descoberta de interfaces
3. selecionar pelo menos a interface `eth0`
4. abrir a area `Monitoramento > Por host`

### 4.4 Gerar syslogs sinteticos de pre-loop

Para emitir os quatro sinais precursores usados na demonstracao:

```bash
docker compose exec lab-linux-01 netguard-preloop-demo 1/1/10
```

O script envia eventos no formato ja entendido pelo pipeline atual:

- `STP_TOPOLOGY_CHANGE`
- `MAC_FLAPPING`
- `INTERFACE_FLAP`
- `BROADCAST_STORM`

### 4.5 Validacao rapida do host de demo

Ver IP do container:

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' netguard-lab-linux-01
```

Testar SNMP:

```bash
docker compose exec lab-linux-01 snmpwalk -v2c -c netguard localhost 1.3.6.1.2.1.1
```

Ver logs locais do host:

```bash
docker compose exec lab-linux-01 sh -lc 'tail -n 20 /var/log/syslog'
```
