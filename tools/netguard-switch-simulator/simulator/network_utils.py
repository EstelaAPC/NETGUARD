from __future__ import annotations

import ipaddress
import socket

try:
    import psutil
except Exception:  # pragma: no cover - optional runtime fallback
    psutil = None


def iter_local_ipv4_addresses() -> list[str]:
    found: set[str] = set()
    if psutil is not None:
        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if getattr(entry, "family", None) == socket.AF_INET and entry.address:
                    found.add(entry.address)
    try:
        _, _, ips = socket.gethostbyname_ex(socket.gethostname())
        found.update(ips)
    except Exception:
        pass
    return sorted(found)


def ip_exists_locally(ip_text: str) -> bool:
    return ip_text in set(iter_local_ipv4_addresses())


def validate_ipv4(ip_text: str) -> str:
    return str(ipaddress.ip_address(ip_text))


def validate_prefix(prefix: str | int) -> int:
    value = int(prefix)
    if not 0 <= value <= 32:
        raise ValueError("Prefixo IPv4 deve estar entre 0 e 32.")
    return value
