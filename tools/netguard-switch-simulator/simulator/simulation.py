from __future__ import annotations

import copy
import queue
import random
import threading
import time
from typing import Any

from pysnmp.proto.api import v2c

from .models import AppConfig, InterfaceState
from .services import SnmpAgentService, SyslogClient, TrapSender, oid_tuple


class SwitchSimulator:
    def __init__(self, config: AppConfig, logger) -> None:
        self.config = config
        self.logger = logger
        self.event_queue: queue.Queue[dict[str, str]] = queue.Queue()
        self.lock = threading.RLock()
        self.start_time = time.time()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.snmp_queries = 0
        self.traps_sent = 0
        self.syslog_sent = 0
        self.total_errors = 0
        self.loop_id_counter = 0
        self.active_loops: dict[int, dict[str, Any]] = {}
        self.mac_table: dict[str, dict[str, Any]] = {}
        self.last_topology_change = time.time()
        self.snmp_service = SnmpAgentService(
            bind_ip=self.config.device.management_ip,
            port=self.config.snmp.bind_port,
            community=self.config.snmp.community,
            get_snapshot=self.build_snapshot,
            set_value=self.apply_snmp_set,
            log_event=self.log_event,
            on_query=self.increment_snmp_queries,
        )
        self.syslog_client = SyslogClient(
            bind_ip=self.config.device.management_ip,
            bind_port=self.config.syslog.bind_port,
            remote_host=self.config.syslog.remote_host,
            remote_port=self.config.syslog.remote_port,
            log_event=self.log_event,
        )
        self.trap_sender = TrapSender(
            bind_ip=self.config.device.management_ip,
            community=self.config.snmp.community,
            remote_host=self.config.snmp.trap_host,
            remote_port=self.config.snmp.trap_port,
            log_event=self.log_event,
        )
        self._seed_mac_table()

    def start(self) -> None:
        self.stop()
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run_loop, name="switch-simulation", daemon=True)
        self.thread.start()
        self.restart_services()
        self.log_event("info", "Simulacao do switch iniciada.")

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        self.thread = None
        self.snmp_service.stop()
        self.syslog_client.close()
        self.trap_sender.close()

    def restart_services(self) -> dict[str, str]:
        with self.lock:
            if self.config.snmp.enabled:
                snmp_status = self.snmp_service.reconfigure(
                    self.config.device.management_ip,
                    self.config.snmp.bind_port,
                    self.config.snmp.community,
                ).message
                trap_status = self.trap_sender.reconfigure(
                    self.config.device.management_ip,
                    self.config.snmp.community,
                    self.config.snmp.trap_host,
                    self.config.snmp.trap_port,
                ).message
            else:
                self.snmp_service.stop()
                self.trap_sender.close()
                snmp_status = "SNMP desabilitado"
                trap_status = "Traps desabilitadas"
            if self.config.syslog.enabled:
                syslog_status = self.syslog_client.reconfigure(
                    self.config.device.management_ip,
                    self.config.syslog.bind_port,
                    self.config.syslog.remote_host,
                    self.config.syslog.remote_port,
                ).message
            else:
                self.syslog_client.close()
                syslog_status = "Syslog desabilitado"
        return {"snmp": snmp_status, "syslog": syslog_status, "traps": trap_status}

    def update_config(self, config: AppConfig) -> dict[str, str]:
        with self.lock:
            old_interfaces = {item.if_index: item for item in self.config.interfaces}
            self.config = copy.deepcopy(config)
            for interface in self.config.interfaces:
                old = old_interfaces.get(interface.if_index)
                if old is None:
                    continue
                for field in (
                    "in_octets",
                    "out_octets",
                    "hc_in_octets",
                    "hc_out_octets",
                    "in_errors",
                    "out_errors",
                    "in_discards",
                    "out_discards",
                    "last_change",
                    "storm_active",
                    "flap_enabled",
                    "next_flap_due",
                    "error_burst_active",
                    "local_loop_peer",
                ):
                    setattr(interface, field, getattr(old, field))
            self.snmp_service.get_snapshot = self.build_snapshot
            self.snmp_service.set_value = self.apply_snmp_set
            return self.restart_services()

    def increment_snmp_queries(self) -> None:
        with self.lock:
            self.snmp_queries += 1

    def log_event(self, level: str, message: str) -> None:
        getattr(self.logger, level, self.logger.info)(message)
        self.event_queue.put({"timestamp": time.strftime("%H:%M:%S"), "level": level.upper(), "message": message})

    def dequeue_events(self, limit: int = 200) -> list[dict[str, str]]:
        items: list[dict[str, str]] = []
        for _ in range(limit):
            try:
                items.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return items

    def build_snapshot(self) -> dict[str, Any]:
        with self.lock:
            interfaces = [copy.deepcopy(item) for item in self.config.interfaces]
            stats = {
                "hostname": self.config.device.hostname,
                "description": self.config.device.description,
                "management_ip": f"{self.config.device.management_ip}/{self.config.device.management_prefix}",
                "gateway": self.config.device.gateway,
                "snmp_status": self.snmp_service.status.message,
                "snmp_queries": self.snmp_queries,
                "traps_sent": self.traps_sent,
                "syslog_sent": self.syslog_sent,
                "uptime": int(time.time() - self.start_time),
                "interfaces_up": sum(1 for item in interfaces if item.oper_up),
                "interfaces_down": sum(1 for item in interfaces if not item.oper_up),
                "loops_active": len(self.active_loops),
                "total_errors": self.total_errors,
                "tc_count": self.config.stp.topology_change_count,
                "stp_enabled": self.config.stp.enabled,
                "loop_guard_enabled": self.config.stp.loop_guard_enabled,
                "auto_block_on_loop": self.config.stp.auto_block_on_loop,
                "root_bridge_id": self.config.stp.root_bridge_id,
                "mac_table_size": len(self.mac_table),
            }
            return {
                "config": copy.deepcopy(self.config),
                "interfaces": interfaces,
                "stats": stats,
                "active_loops": copy.deepcopy(list(self.active_loops.values())),
                "mac_table": copy.deepcopy(self.mac_table),
                "snmp_oid_map": self._build_snmp_oid_map(interfaces),
            }

    def get_uptime_centisecs(self) -> int:
        return int((time.time() - self.start_time) * 100)

    def set_interface_admin(self, if_index: int, admin_up: bool) -> None:
        with self.lock:
            interface = self._get_interface(if_index)
            interface.admin_up = admin_up
            new_oper = admin_up and interface.connected and not interface.errdisable
            if interface.oper_up != new_oper:
                interface.oper_up = new_oper
                interface.last_change = time.time()
                self._emit_link_event(interface, up=new_oper)

    def trigger_error_burst(self, if_index: int, seconds: int = 10) -> None:
        with self.lock:
            interface = self._get_interface(if_index)
            interface.error_burst_active = max(interface.error_burst_active, seconds)
            self.log_event("warning", f"Erro burst ativado em {interface.name} por {seconds}s.")

    def trigger_discards(self, if_index: int, amount: int = 100) -> None:
        with self.lock:
            interface = self._get_interface(if_index)
            interface.discards_boost += amount
            self.total_errors += amount
            self.log_event("warning", f"Discards incrementados em {interface.name} (+{amount}).")

    def trigger_storm(self, if_index: int, enabled: bool) -> None:
        with self.lock:
            interface = self._get_interface(if_index)
            interface.storm_active = enabled
            action = "ativada" if enabled else "desativada"
            self.log_event("warning", f"Broadcast storm {action} em {interface.name}.")
            if enabled:
                self._send_syslog(f"%STORMCTRL-3-FIRE: Broadcast storm detected on {interface.name}")
                self._send_trap("1.3.6.1.4.1.53864.1.0.2", interface)

    def trigger_flap(self, if_index: int, enabled: bool, interval_sec: int = 10) -> None:
        with self.lock:
            interface = self._get_interface(if_index)
            interface.flap_enabled = enabled
            interface.flap_interval_sec = max(2, interval_sec)
            interface.next_flap_due = time.time() + interface.flap_interval_sec
            action = "habilitado" if enabled else "desabilitado"
            self.log_event("info", f"Flap {action} em {interface.name} com intervalo {interface.flap_interval_sec}s.")

    def toggle_errdisable(self, if_index: int) -> None:
        with self.lock:
            interface = self._get_interface(if_index)
            interface.errdisable = not interface.errdisable
            if interface.errdisable:
                interface.oper_up = False
                interface.stp_state = "discarding" if self.config.stp.enabled else "disabled"
                interface.stp_role = "disabled"
                self.log_event("warning", f"{interface.name} entrou em err-disable.")
                self._send_syslog(f"%PM-4-ERR_DISABLE: {interface.name} placed in err-disable state")
                self._send_trap("1.3.6.1.6.3.1.1.5.3", interface)
            else:
                interface.oper_up = interface.admin_up and interface.connected
                self.log_event("info", f"{interface.name} saiu de err-disable.")
                if interface.oper_up:
                    self._emit_link_event(interface, up=True)

    def set_loop_between(self, first_if: int, second_if: int, protected: bool) -> None:
        with self.lock:
            first = self._get_interface(first_if)
            second = self._get_interface(second_if)
            self.loop_id_counter += 1
            loop_id = self.loop_id_counter
            first.local_loop_peer = second_if
            second.local_loop_peer = first_if
            self.active_loops[loop_id] = {
                "id": loop_id,
                "ports": (first_if, second_if),
                "protected": protected,
                "since": time.strftime("%H:%M:%S"),
                "blocked_port": None,
            }
            self._process_loop(loop_id)

    def clear_loops(self) -> None:
        with self.lock:
            for loop in self.active_loops.values():
                for if_index in loop["ports"]:
                    interface = self._get_interface(if_index)
                    interface.local_loop_peer = None
                    interface.stp_state = "forwarding" if self.config.stp.enabled and interface.oper_up else "discarding"
                    interface.stp_role = "designated" if self.config.stp.enabled and interface.oper_up else "disabled"
            self.active_loops.clear()
            self.log_event("info", "Todos os loops simulados foram removidos.")

    def trigger_tcn(self) -> None:
        with self.lock:
            self.config.stp.topology_change_count += 1
            self.last_topology_change = time.time()
            self.log_event("warning", "TCN manual disparado.")
            self._send_syslog("%SPANTREE-5-TOPOTRAP: Topology Change Notice generated manually")
            self._send_trap("1.3.6.1.4.1.53864.1.0.4")

    def reelect_root(self) -> None:
        with self.lock:
            mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
            self.config.stp.root_bridge_id = f"{self.config.stp.bridge_priority}.{mac}"
            self.config.stp.topology_change_count += 1
            self.last_topology_change = time.time()
            self.log_event("warning", f"Root bridge reeleito para {self.config.stp.root_bridge_id}.")
            self._send_syslog(f"%SPANTREE-5-ROOTCHANGE: Root bridge changed to {self.config.stp.root_bridge_id}")
            self._send_trap("1.3.6.1.4.1.53864.1.0.4")

    def apply_snmp_set(self, oid: tuple[int, ...], value: object) -> bool:
        with self.lock:
            if oid == oid_tuple("1.3.6.1.2.1.1.5.0"):
                self.config.device.hostname = _pyasn1_to_str(value)
                return True
            if oid == oid_tuple("1.3.6.1.2.1.1.4.0"):
                self.config.device.contact = _pyasn1_to_str(value)
                return True
            if oid == oid_tuple("1.3.6.1.2.1.1.6.0"):
                self.config.device.location = _pyasn1_to_str(value)
                return True
            admin_prefix = oid_tuple("1.3.6.1.2.1.2.2.1.7")
            if oid[: len(admin_prefix)] == admin_prefix and len(oid) == len(admin_prefix) + 1:
                self.set_interface_admin(oid[-1], int(value) == 1)
                return True
        return False

    def _run_loop(self) -> None:
        while not self.stop_event.is_set():
            start = time.time()
            with self.lock:
                self._tick_interfaces()
                self._age_mac_table()
                self._tick_loops()
            elapsed = time.time() - start
            time.sleep(max(self.config.simulation.tick_interval_ms / 1000 - elapsed, 0.1))

    def _tick_interfaces(self) -> None:
        now = time.time()
        for interface in self.config.interfaces:
            # The simulator mutates link state and counters here instead of in the UI thread.
            if interface.flap_enabled and now >= interface.next_flap_due:
                interface.oper_up = not interface.oper_up if interface.admin_up else False
                interface.last_change = now
                interface.next_flap_due = now + interface.flap_interval_sec
                self._emit_link_event(interface, up=interface.oper_up)

            if not interface.admin_up or interface.errdisable:
                interface.oper_up = False
                interface.stp_state = "discarding" if self.config.stp.enabled else "disabled"
                interface.stp_role = "disabled"
                continue

            if interface.connected and not interface.oper_up:
                interface.oper_up = True
                interface.last_change = now

            multiplier = 1
            baseline = self.config.simulation.normal_baseline_octets
            if interface.storm_active:
                multiplier = max(multiplier, self.config.simulation.storm_multiplier)
                interface.in_discards += 15
                interface.out_discards += 10
                self.total_errors += 25
            if interface.local_loop_peer and interface.oper_up:
                multiplier = max(multiplier, self.config.simulation.loop_multiplier)
                interface.in_errors += 5
                interface.out_errors += 5
                interface.in_discards += 30
                interface.out_discards += 25
                self.total_errors += 65
                self._learn_random_mac(interface.if_index, flapping=True)
            if interface.error_burst_active > 0:
                interface.error_burst_active -= 1
                interface.in_errors += 20
                interface.out_errors += 12
                self.total_errors += 32
            if interface.discards_boost > 0:
                step = min(interface.discards_boost, 25)
                interface.in_discards += step
                interface.out_discards += step // 2
                interface.discards_boost -= step

            if interface.oper_up:
                delta = baseline * multiplier + random.randint(100, 900)
                interface.in_octets = (interface.in_octets + delta) % (2**32)
                interface.out_octets = (interface.out_octets + delta + random.randint(10, 300)) % (2**32)
                interface.hc_in_octets += delta
                interface.hc_out_octets += delta + random.randint(10, 300)
                if self.config.stp.enabled and interface.stp_role == "disabled":
                    interface.stp_state = "forwarding"
                    interface.stp_role = "designated"

    def _tick_loops(self) -> None:
        for loop_id in list(self.active_loops.keys()):
            self._process_loop(loop_id, periodic=True)

    def _process_loop(self, loop_id: int, periodic: bool = False) -> None:
        loop = self.active_loops.get(loop_id)
        if not loop:
            return
        first = self._get_interface(loop["ports"][0])
        second = self._get_interface(loop["ports"][1])
        if not (first.oper_up and second.oper_up):
            return
        if (
            loop["protected"]
            and self.config.stp.enabled
            and self.config.stp.loop_guard_enabled
            and self.config.stp.auto_block_on_loop
        ):
            blocked = second
            blocked.stp_state = "blocking"
            blocked.stp_role = "alternate"
            loop["blocked_port"] = blocked.if_index
            if not periodic:
                self.config.stp.topology_change_count += 1
                self.last_topology_change = time.time()
                self.log_event("warning", f"Loop protegido entre {first.name} e {second.name}; {blocked.name} bloqueada por STP.")
                self._send_syslog(f"%SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocked {blocked.name} after loop detection")
                self._send_syslog(f"%SPANTREE-5-TOPOTRAP: Topology Change on loop-protected segment {first.name}/{second.name}")
                self._send_trap("1.3.6.1.6.3.1.1.5.3", blocked)
                self._send_trap("1.3.6.1.4.1.53864.1.0.4", blocked)
            return
        first.stp_state = "forwarding" if self.config.stp.enabled else "disabled"
        second.stp_state = "forwarding" if self.config.stp.enabled else "disabled"
        first.stp_role = "designated" if self.config.stp.enabled else "disabled"
        second.stp_role = "designated" if self.config.stp.enabled else "disabled"
        if not periodic:
            self.log_event("warning", f"Loop sem bloqueio ativo entre {first.name} e {second.name}.")
            self._send_syslog(f"%SPANTREE-5-TOPOTRAP: Unprotected loop active on {first.name} and {second.name}")
            self._send_syslog(f"%SPANTREE-2-LOOPGUARD_BLOCK: Loop detected but containment disabled for {first.name}/{second.name}")
            self._send_trap("1.3.6.1.4.1.53864.1.0.1", first)
        self._send_unprotected_loop_noise(first, second)

    def _send_unprotected_loop_noise(self, first: InterfaceState, second: InterfaceState) -> None:
        self._learn_random_mac(first.if_index, flapping=True)
        self._learn_random_mac(second.if_index, flapping=True)
        self._send_syslog(f"%SW_MATM-4-MACFLAP_NOTIF: Host MAC flapping between ports {first.name} and {second.name}")
        self._send_syslog(f"%STORMCTRL-3-FIRE: Broadcast storm detected on {first.name} and {second.name}")
        self._send_trap("1.3.6.1.4.1.53864.1.0.2", first)
        self._send_trap("1.3.6.1.4.1.53864.1.0.3", second)

    def _seed_mac_table(self) -> None:
        for interface in self.config.interfaces:
            if interface.connected:
                for offset in range(1, 4):
                    mac = f"00:16:3e:{interface.if_index:02x}:{offset:02x}:{(interface.if_index * offset) % 255:02x}"
                    self.mac_table[mac] = {"if_index": interface.if_index, "age": time.time()}

    def _learn_random_mac(self, if_index: int, flapping: bool = False) -> None:
        mac = "00:25:96:{:02x}:{:02x}:{:02x}".format(
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
        )
        previous = self.mac_table.get(mac)
        if flapping and previous and previous["if_index"] != if_index:
            self.log_event("warning", f"MAC flapping detectado: {mac} entre Gi0/{previous['if_index']} e Gi0/{if_index}.")
        self.mac_table[mac] = {"if_index": if_index, "age": time.time()}

    def _age_mac_table(self) -> None:
        cutoff = time.time() - self.config.simulation.mac_aging_seconds
        expired = [mac for mac, payload in self.mac_table.items() if payload["age"] < cutoff]
        for mac in expired:
            del self.mac_table[mac]

    def _emit_link_event(self, interface: InterfaceState, up: bool) -> None:
        state_word = "up" if up else "down"
        self.log_event("info", f"{interface.name} mudou para {state_word}.")
        if up:
            self._send_syslog(f"%LINK-3-UPDOWN: Interface {interface.name}, changed state to up")
            self._send_syslog(f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {interface.name}, changed state to up")
            self._send_trap("1.3.6.1.6.3.1.1.5.4", interface)
        else:
            self._send_syslog(f"%LINK-3-UPDOWN: Interface {interface.name}, changed state to down")
            self._send_syslog(f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {interface.name}, changed state to down")
            self._send_trap("1.3.6.1.6.3.1.1.5.3", interface)

    def _send_syslog(self, message: str) -> None:
        if not self.config.syslog.enabled:
            return
        status = self.syslog_client.send(self.config.device.hostname, message)
        if status.ok:
            self.syslog_sent += 1

    def _send_trap(self, trap_oid: str, interface: InterfaceState | None = None) -> None:
        if not self.config.snmp.enabled:
            return
        extra = []
        if interface is not None:
            extra.extend(
                [
                    ("1.3.6.1.2.1.2.2.1.1.1", interface.if_index),
                    ("1.3.6.1.2.1.2.2.1.2.1", interface.name),
                ]
            )
        status = self.trap_sender.send_trap(self.get_uptime_centisecs(), trap_oid, extra)
        if status.ok:
            self.traps_sent += 1

    def _get_interface(self, if_index: int) -> InterfaceState:
        for interface in self.config.interfaces:
            if interface.if_index == if_index:
                return interface
        raise KeyError(f"Interface {if_index} inexistente.")

    def _build_snmp_oid_map(self, interfaces: list[InterfaceState]) -> dict[tuple[int, ...], object]:
        # This OID map is rebuilt from the live simulated state so queries see recent changes.
        oid_map: dict[tuple[int, ...], object] = {
            oid_tuple("1.3.6.1.2.1.1.1.0"): v2c.OctetString(self.config.device.description),
            oid_tuple("1.3.6.1.2.1.1.2.0"): v2c.ObjectIdentifier(oid_tuple(self.config.device.sys_object_id)),
            oid_tuple("1.3.6.1.2.1.1.3.0"): v2c.TimeTicks(self.get_uptime_centisecs()),
            oid_tuple("1.3.6.1.2.1.1.4.0"): v2c.OctetString(self.config.device.contact),
            oid_tuple("1.3.6.1.2.1.1.5.0"): v2c.OctetString(self.config.device.hostname),
            oid_tuple("1.3.6.1.2.1.1.6.0"): v2c.OctetString(self.config.device.location),
            oid_tuple("1.3.6.1.2.1.2.1.0"): v2c.Integer(len(interfaces)),
            oid_tuple("1.3.6.1.2.1.17.1.2.0"): v2c.Integer(len(interfaces)),
            oid_tuple("1.3.6.1.2.1.17.2.1.0"): v2c.Integer(3),
            oid_tuple("1.3.6.1.2.1.17.2.2.0"): v2c.Integer(self.config.stp.bridge_priority),
            oid_tuple("1.3.6.1.2.1.17.2.3.0"): v2c.TimeTicks(int((time.time() - self.last_topology_change) * 100)),
            oid_tuple("1.3.6.1.2.1.17.2.4.0"): v2c.Counter32(self.config.stp.topology_change_count),
            oid_tuple("1.3.6.1.2.1.17.2.5.0"): v2c.OctetString(self.config.stp.root_bridge_id),
        }
        for interface in interfaces:
            idx = interface.if_index
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.1.{idx}")] = v2c.Integer(idx)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.2.{idx}")] = v2c.OctetString(interface.name)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.3.{idx}")] = v2c.Integer(interface.if_type)
            if_speed = min(interface.speed_mbps * 1_000_000, 4_294_967_295)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.5.{idx}")] = v2c.Gauge32(if_speed)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.6.{idx}")] = v2c.OctetString(hexValue=interface.mac_address.replace(':', ''))
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.7.{idx}")] = v2c.Integer(1 if interface.admin_up else 2)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.8.{idx}")] = v2c.Integer(1 if interface.oper_up else 2)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.10.{idx}")] = v2c.Counter32(interface.in_octets)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.13.{idx}")] = v2c.Counter32(interface.in_discards)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.14.{idx}")] = v2c.Counter32(interface.in_errors)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.16.{idx}")] = v2c.Counter32(interface.out_octets)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.19.{idx}")] = v2c.Counter32(interface.out_discards)
            oid_map[oid_tuple(f"1.3.6.1.2.1.2.2.1.20.{idx}")] = v2c.Counter32(interface.out_errors)
            oid_map[oid_tuple(f"1.3.6.1.2.1.31.1.1.1.6.{idx}")] = v2c.Counter64(interface.hc_in_octets)
            oid_map[oid_tuple(f"1.3.6.1.2.1.31.1.1.1.10.{idx}")] = v2c.Counter64(interface.hc_out_octets)
        return oid_map


def _pyasn1_to_str(value: object) -> str:
    try:
        return bytes(value).decode("utf-8", errors="ignore")
    except Exception:
        return str(value)
