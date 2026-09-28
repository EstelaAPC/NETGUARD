# NetGuard Switch Simulator

Simulador Windows em Python para comportamento de gerenciamento de um switch L2/L3, pensado para testes do NetGuard.

## Estrutura sugerida

```text
tools/netguard-switch-simulator/
|-- app.py
|-- requirements.txt
|-- run_netguard_switch_simulator.bat
|-- README.md
|-- config/
|   `-- default_config.json
|-- data/
|-- logs/
`-- simulator/
    |-- __init__.py
    |-- app_controller.py
    |-- config.py
    |-- gui.py
    |-- logging_utils.py
    |-- models.py
    |-- network_utils.py
    |-- services.py
    `-- simulation.py
```

## Como executar no Windows

Use `run_netguard_switch_simulator.bat`.

Ou manualmente:

```powershell
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

## Observações importantes

- O simulador nao cria uma interface de rede real no Windows.
- O IP de gerenciamento precisa existir de fato em alguma interface do Windows para bindar SNMP, syslog e traps nesse IP.
- O ping so funcionara se esse IP estiver realmente configurado localmente.
- O software simula gerenciamento e eventos operacionais; nao implementa switching por ASIC nem bridge real do Windows.

## Funcionalidades

- GUI dark mode com `customtkinter` e fallback para `tkinter`
- Persistencia em JSON
- 24 portas simuladas com estados, VLAN, mode, speed, duplex, flap, burst de erro, discards, storm e loop
- SNMP v2c em Python com GET, GETNEXT, GETBULK e SET parcial
- OIDs de system, interfaces, contadores 32/64-bit e bridge/STP basicos
- Traps para `linkUp`, `linkDown`, loop, storm, MAC flapping e topologia STP
- Syslog RFC 3164 com mensagens no estilo de switch real
- STP/RSTP simplificado com reeleicao, TCN, loop protegido e loop sem bloqueio

## Arquivos gerados

- `data/runtime_config.json`
- `logs/netguard_switch_simulator.log`
- `logs/startup_error.log`
