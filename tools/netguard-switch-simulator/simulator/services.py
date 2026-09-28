from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import Callable

from pyasn1.codec.ber import decoder, encoder
from pysnmp.proto.api import v2c


LogFn = Callable[[str, str], None]
SnapshotFn = Callable[[], dict]
SetValueFn = Callable[[tuple[int, ...], object], bool]
CounterFn = Callable[[], None]


def oid_tuple(oid_text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid_text.split("."))


@dataclass
class ServiceStatus:
    ok: bool
    message: str


class UdpBoundSender:
    def __init__(self, bind_ip: str, bind_port: int):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.socket: socket.socket | None = None

    def open(self) -> ServiceStatus:
        try:
            self.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.bind_ip, self.bind_port))
            self.socket = sock
            return ServiceStatus(True, f"Bind UDP em {self.bind_ip}:{sock.getsockname()[1]}")
        except OSError as exc:
            self.socket = None
            return ServiceStatus(False, f"Falha ao bindar UDP em {self.bind_ip}:{self.bind_port}: {exc}")

    def sendto(self, payload: bytes, host: str, port: int) -> None:
        if self.socket is None:
            status = self.open()
            if not status.ok:
                raise OSError(status.message)
        assert self.socket is not None
        self.socket.sendto(payload, (host, port))

    def close(self) -> None:
        if self.socket is not None:
            try:
                self.socket.close()
            finally:
                self.socket = None


class SyslogClient:
    def __init__(self, bind_ip: str, bind_port: int, remote_host: str, remote_port: int, log_event: LogFn):
        self.log_event = log_event
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.sender = UdpBoundSender(bind_ip, bind_port)

    def reconfigure(self, bind_ip: str, bind_port: int, remote_host: str, remote_port: int) -> ServiceStatus:
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.sender.bind_ip = bind_ip
        self.sender.bind_port = bind_port
        return self.sender.open()

    def send(self, hostname: str, message: str) -> ServiceStatus:
        import time

        payload = f"<189>{time.strftime('%b %d %H:%M:%S')} {hostname} {message}".encode("utf-8", errors="ignore")
        try:
            self.sender.sendto(payload, self.remote_host, self.remote_port)
            return ServiceStatus(True, "Syslog enviado")
        except OSError as exc:
            self.log_event("error", f"Falha ao enviar syslog: {exc}")
            return ServiceStatus(False, str(exc))

    def close(self) -> None:
        self.sender.close()


class TrapSender:
    def __init__(self, bind_ip: str, community: str, remote_host: str, remote_port: int, log_event: LogFn):
        self.log_event = log_event
        self.community = community
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.sender = UdpBoundSender(bind_ip, 0)

    def reconfigure(self, bind_ip: str, community: str, remote_host: str, remote_port: int) -> ServiceStatus:
        self.community = community
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.sender.bind_ip = bind_ip
        self.sender.bind_port = 0
        return self.sender.open()

    def send_trap(self, uptime_centisecs: int, trap_oid: str, extra_binds: list[tuple[str, object]] | None = None) -> ServiceStatus:
        try:
            message = v2c.Message()
            v2c.apiMessage.setDefaults(message)
            v2c.apiMessage.setCommunity(message, self.community)

            pdu = v2c.SNMPv2TrapPDU()
            v2c.apiTrapPDU.setDefaults(pdu)
            var_binds = [
                (v2c.ObjectIdentifier(oid_tuple("1.3.6.1.2.1.1.3.0")), v2c.TimeTicks(int(uptime_centisecs))),
                (v2c.ObjectIdentifier(oid_tuple("1.3.6.1.6.3.1.1.4.1.0")), v2c.ObjectIdentifier(oid_tuple(trap_oid))),
            ]
            for oid_text, value in extra_binds or []:
                var_binds.append((v2c.ObjectIdentifier(oid_tuple(oid_text)), _coerce_value(value)))
            v2c.apiTrapPDU.setVarBinds(pdu, var_binds)
            v2c.apiMessage.setPDU(message, pdu)
            self.sender.sendto(encoder.encode(message), self.remote_host, self.remote_port)
            return ServiceStatus(True, "Trap enviada")
        except OSError as exc:
            self.log_event("error", f"Falha ao enviar trap: {exc}")
            return ServiceStatus(False, str(exc))

    def close(self) -> None:
        self.sender.close()


def _coerce_value(value: object) -> object:
    if isinstance(value, bool):
        return v2c.Integer(int(value))
    if isinstance(value, int):
        return v2c.Integer(value)
    if isinstance(value, bytes):
        return v2c.OctetString(value)
    if isinstance(value, tuple):
        return v2c.ObjectIdentifier(value)
    return v2c.OctetString(str(value))


class SnmpAgentService:
    def __init__(
        self,
        bind_ip: str,
        port: int,
        community: str,
        get_snapshot: SnapshotFn,
        set_value: SetValueFn,
        log_event: LogFn,
        on_query: CounterFn,
    ) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.community = community
        self.get_snapshot = get_snapshot
        self.set_value = set_value
        self.log_event = log_event
        self.on_query = on_query
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None
        self.status = ServiceStatus(False, "SNMP parado")

    def start(self) -> ServiceStatus:
        self.stop()
        self._stop_event.clear()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.bind_ip, self.port))
            sock.settimeout(0.5)
            self._socket = sock
        except OSError as exc:
            self.status = ServiceStatus(False, f"Falha ao bindar SNMP em {self.bind_ip}:{self.port}: {exc}")
            self.log_event("error", self.status.message)
            return self.status

        self._thread = threading.Thread(target=self._serve, name="snmp-agent", daemon=True)
        self._thread.start()
        self.status = ServiceStatus(True, f"SNMP ouvindo em {self.bind_ip}:{self.port}")
        self.log_event("info", self.status.message)
        return self.status

    def stop(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._thread = None
        self.status = ServiceStatus(False, "SNMP parado")

    def reconfigure(self, bind_ip: str, port: int, community: str) -> ServiceStatus:
        self.bind_ip = bind_ip
        self.port = port
        self.community = community
        return self.start()

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop_event.is_set():
            try:
                data, address = self._socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                response = self._handle_request(data)
                if response:
                    self._socket.sendto(response, address)
            except Exception as exc:  # pragma: no cover - network safety
                self.log_event("error", f"Erro ao processar SNMP: {exc}")

    def _handle_request(self, data: bytes) -> bytes | None:
        # The SNMP agent is intentionally minimal and answers directly from a live OID map.
        message, _ = decoder.decode(data, asn1Spec=v2c.Message())
        community = bytes(v2c.apiMessage.getCommunity(message)).decode("utf-8", errors="ignore")
        pdu = v2c.apiMessage.getPDU(message)
        self.on_query()

        response_message = v2c.Message()
        v2c.apiMessage.setDefaults(response_message)
        v2c.apiMessage.setCommunity(response_message, community)

        if community != self.community:
            rsp = _build_response_pdu(pdu, [], error_status=16, error_index=1)
            v2c.apiMessage.setPDU(response_message, rsp)
            return encoder.encode(response_message)

        snapshot = self.get_snapshot()
        oid_map = snapshot["snmp_oid_map"]
        ordered_oids = sorted(oid_map.keys())

        if pdu.isSameTypeWith(v2c.GetRequestPDU()):
            rsp_binds = []
            for oid, _ in v2c.apiPDU.getVarBinds(pdu):
                key = tuple(int(part) for part in oid)
                rsp_binds.append((v2c.ObjectIdentifier(key), oid_map.get(key, v2c.NoSuchInstance(""))))
            rsp = _build_response_pdu(pdu, rsp_binds)
        elif pdu.isSameTypeWith(v2c.GetNextRequestPDU()):
            rsp = _build_response_pdu(pdu, _next_response_binds(v2c.apiPDU.getVarBinds(pdu), ordered_oids, oid_map))
        elif pdu.isSameTypeWith(v2c.GetBulkRequestPDU()):
            non_repeaters = int(v2c.apiBulkPDU.getNonRepeaters(pdu))
            max_repetitions = int(v2c.apiBulkPDU.getMaxRepetitions(pdu))
            request_binds = list(v2c.apiBulkPDU.getVarBinds(pdu))
            response_binds = []
            for index, (oid, _) in enumerate(request_binds):
                current = tuple(int(part) for part in oid)
                if index < non_repeaters:
                    next_oid = _next_oid(current, ordered_oids)
                    response_binds.append((v2c.ObjectIdentifier(next_oid or current), oid_map.get(next_oid, v2c.EndOfMibView(""))))
                    continue
                walk_oid = current
                for _ in range(max_repetitions):
                    next_oid = _next_oid(walk_oid, ordered_oids)
                    if next_oid is None:
                        response_binds.append((v2c.ObjectIdentifier(walk_oid), v2c.EndOfMibView("")))
                        break
                    response_binds.append((v2c.ObjectIdentifier(next_oid), oid_map[next_oid]))
                    walk_oid = next_oid
            rsp = _build_response_pdu(pdu, response_binds)
        elif pdu.isSameTypeWith(v2c.SetRequestPDU()):
            response_binds = []
            error_status = 0
            error_index = 0
            for index, (oid, value) in enumerate(v2c.apiPDU.getVarBinds(pdu), start=1):
                key = tuple(int(part) for part in oid)
                if not self.set_value(key, value):
                    error_status = 17
                    error_index = index
                    break
                response_binds.append((v2c.ObjectIdentifier(key), value))
            rsp = _build_response_pdu(pdu, response_binds, error_status=error_status, error_index=error_index)
        else:
            rsp = _build_response_pdu(pdu, [], error_status=5, error_index=1)

        v2c.apiMessage.setPDU(response_message, rsp)
        return encoder.encode(response_message)


def _next_response_binds(request_binds, ordered_oids, oid_map):
    response_binds = []
    for oid, _ in request_binds:
        key = tuple(int(part) for part in oid)
        next_oid = _next_oid(key, ordered_oids)
        if next_oid is None:
            response_binds.append((v2c.ObjectIdentifier(key), v2c.EndOfMibView("")))
        else:
            response_binds.append((v2c.ObjectIdentifier(next_oid), oid_map[next_oid]))
    return response_binds


def _build_response_pdu(request_pdu, var_binds, error_status: int = 0, error_index: int = 0):
    response = v2c.ResponsePDU()
    v2c.apiPDU.setDefaults(response)
    v2c.apiPDU.setRequestID(response, v2c.apiPDU.getRequestID(request_pdu))
    v2c.apiPDU.setErrorStatus(response, error_status)
    v2c.apiPDU.setErrorIndex(response, error_index)
    v2c.apiPDU.setVarBinds(response, var_binds)
    return response


def _next_oid(current_oid: tuple[int, ...], ordered_oids: list[tuple[int, ...]]) -> tuple[int, ...] | None:
    for candidate in ordered_oids:
        if candidate > current_oid:
            return candidate
    return None
