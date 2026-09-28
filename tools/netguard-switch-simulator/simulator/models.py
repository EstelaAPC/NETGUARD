from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DeviceConfig:
    hostname: str = "NetGuard-SW01"
    description: str = "NetGuard Simulated Switch"
    contact: str = "NetGuard Lab"
    location: str = "NetGuard Test Bench"
    sys_object_id: str = "1.3.6.1.4.1.53864.1.1"
    management_ip: str = "192.168.56.20"
    management_prefix: int = 24
    gateway: str = "192.168.56.1"


@dataclass
class SnmpConfig:
    enabled: bool = True
    bind_port: int = 161
    community: str = "netguard"
    trap_host: str = "192.168.56.15"
    trap_port: int = 162


@dataclass
class SyslogConfig:
    enabled: bool = True
    bind_port: int = 0
    remote_host: str = "192.168.56.15"
    remote_port: int = 514


@dataclass
class StpConfig:
    enabled: bool = True
    loop_guard_enabled: bool = True
    auto_block_on_loop: bool = True
    root_bridge_id: str = "32768.00:11:22:33:44:55"
    bridge_priority: int = 32768
    topology_change_count: int = 0


@dataclass
class SimulationConfig:
    tick_interval_ms: int = 1000
    normal_baseline_octets: int = 2200
    storm_multiplier: int = 40
    loop_multiplier: int = 75
    mac_aging_seconds: int = 300
    ui_refresh_ms: int = 1000


@dataclass
class InterfaceState:
    if_index: int
    name: str
    speed_mbps: int
    duplex: str = "full"
    description: str = ""
    mode: str = "access"
    vlan_access: int = 1
    admin_up: bool = True
    oper_up: bool = False
    connected: bool = False
    flap_enabled: bool = False
    flap_interval_sec: int = 10
    next_flap_due: float = 0.0
    error_burst_active: int = 0
    discards_boost: int = 0
    storm_active: bool = False
    errdisable: bool = False
    local_loop_peer: int | None = None
    mac_address: str = ""
    if_type: int = 6
    mtu: int = 1500
    stp_state: str = "discarding"
    stp_role: str = "disabled"
    link_partner: str = ""
    in_octets: int = 0
    out_octets: int = 0
    hc_in_octets: int = 0
    hc_out_octets: int = 0
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    last_change: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "InterfaceState":
        return cls(**payload)


@dataclass
class AppConfig:
    device: DeviceConfig = field(default_factory=DeviceConfig)
    snmp: SnmpConfig = field(default_factory=SnmpConfig)
    syslog: SyslogConfig = field(default_factory=SyslogConfig)
    stp: StpConfig = field(default_factory=StpConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    interfaces: list[InterfaceState] = field(default_factory=list)
