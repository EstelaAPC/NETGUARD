from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .models import AppConfig, DeviceConfig, InterfaceState, SimulationConfig, SnmpConfig, StpConfig, SyslogConfig


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    path = project_root() / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    path = project_root() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def runtime_config_path() -> Path:
    return data_dir() / "runtime_config.json"


def default_config_path() -> Path:
    return project_root() / "config" / "default_config.json"


def build_default_interfaces() -> list[InterfaceState]:
    interfaces: list[InterfaceState] = []
    for index in range(1, 25):
        is_uplink = index >= 23
        connected = index <= 8 or index in (23,)
        speed = 10_000 if is_uplink else 1_000
        mac = f"02:42:56:{index:02x}:{(index * 7) % 256:02x}:{(index * 13) % 256:02x}"
        interfaces.append(
            InterfaceState(
                if_index=index,
                name=f"Gi0/{index}",
                speed_mbps=speed,
                description="Uplink" if is_uplink else f"Access Port {index}",
                mode="trunk" if is_uplink else "access",
                vlan_access=999 if is_uplink else 1,
                admin_up=True,
                oper_up=connected,
                connected=connected,
                stp_state="forwarding" if connected else "discarding",
                stp_role="designated" if connected else "disabled",
                link_partner=f"endpoint-{index:02d}" if connected else "",
                mac_address=mac,
            )
        )
    return interfaces


def _decode_config(payload: dict) -> AppConfig:
    config = AppConfig(
        device=DeviceConfig(**payload.get("device", {})),
        snmp=SnmpConfig(**payload.get("snmp", {})),
        syslog=SyslogConfig(**payload.get("syslog", {})),
        stp=StpConfig(**payload.get("stp", {})),
        simulation=SimulationConfig(**payload.get("simulation", {})),
        interfaces=[InterfaceState.from_dict(item) for item in payload.get("interfaces", [])],
    )
    if not config.interfaces:
        config.interfaces = build_default_interfaces()
    return config


def load_config() -> AppConfig:
    source = runtime_config_path() if runtime_config_path().exists() else default_config_path()
    payload = json.loads(source.read_text(encoding="utf-8"))
    config = _decode_config(payload)
    if not runtime_config_path().exists():
        save_config(config)
    return config


def save_config(config: AppConfig) -> None:
    runtime_config_path().write_text(
        json.dumps(asdict(config), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
