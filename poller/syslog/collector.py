import json
import os
import re
import time
from datetime import datetime

import psycopg2

LOG_PATH = os.getenv("SYSLOG_FILE", "/var/log/netguard/syslog.log")
STATE_FILE = os.getenv("SYSLOG_STATE_FILE", "/var/log/netguard/syslog-collector.offset")
DB_DSN = os.getenv("NETGUARD_DB_DSN")
DB_CONNECT_RETRY_SEC = float(os.getenv("DB_CONNECT_RETRY_SEC", "5"))
DB_CONNECT_RETRY_MAX_SEC = float(os.getenv("DB_CONNECT_RETRY_MAX_SEC", "60"))

LINE_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<srcip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:?\s*"
    r"(?P<rest>.*)$"
)

ARUBA_EVENT_RE = re.compile(
    r"Event\|(?P<eid>\d+)\|(?P<sev>[^|]+)\|(?P<subsys>[^|]+)\|(?P<slot>[^|]*)\|(?P<iface>[^|]*)\|(?P<msg>.*)$"
)
INTERFACE_TOKEN_REGEX = (
    r"(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Port-channel|Ethernet|Loopback|Vlan|Te|Gi|Fa|Po|Eth|Lo)"
    r"\d+(?:/\d+)*(?:\.\d+)?"
)
INTERFACE_PAIR_PATTERN = re.compile(
    rf"({INTERFACE_TOKEN_REGEX})\s*<->\s*({INTERFACE_TOKEN_REGEX})",
    re.IGNORECASE,
)
INTERFACE_TOKEN_PATTERN = re.compile(INTERFACE_TOKEN_REGEX, re.IGNORECASE)
SYSLOG_PROCESS_EVENT_PATTERN = re.compile(
    r"^%?(?P<subsystem>[A-Za-z][A-Za-z0-9_]*)(?:-(?P<level>[0-7])-(?P<code>[A-Za-z0-9_]+))?$"
)
SYSLOG_LEVEL_TO_SEVERITY = {
    "0": "critical",
    "1": "critical",
    "2": "high",
    "3": "high",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "info",
}
SYSLOG_SUBSYSTEM_KEYWORDS = [
    ("LOGGINGHOST_STARTSTOP", "logging"),
    ("LOGGING HOST", "logging"),
    ("LOOPGUARD", "spantree"),
    ("SPANTREE", "spantree"),
    ("SPANNING-TREE", "spantree"),
    ("STP TOPOLOGY CHANGE", "spantree"),
    ("STP", "spantree"),
    ("TOPO_CHANGE", "spantree"),
    ("TOPOLOGY CHANGE", "spantree"),
    ("TCN", "spantree"),
    ("MACFLAP", "sw_matm"),
    ("MAC FLAP", "sw_matm"),
    ("MAC FLAPPING", "sw_matm"),
    ("SW_MATM", "sw_matm"),
    ("STORMCTRL", "stormctrl"),
    ("STORM_CONTROL", "stormctrl"),
    ("BROADCAST STORM", "stormctrl"),
    ("STORM CONTROL", "stormctrl"),
    ("LINK-3-UPDOWN", "link"),
    ("LINEPROTO", "lineproto"),
    ("LINE PROTOCOL ON INTERFACE", "lineproto"),
    ("INTERFACE CHANGED STATE", "link"),
    ("CHANGED STATE TO", "link"),
    ("ERR_DISABLE", "pm"),
    ("FLAPPING", "link"),
    ("ERR-RECOVER", "pm"),
    ("PORTAS:", "system"),
    ("CONFIGURAÇÃO SALVA", "system"),
    ("CONFIG:", "system"),
    ("INICIADO", "system"),
    ("TESTE DE SYSLOG MANUAL", "manual"),
    ("BURST DE ERROS", "counters"),
    ("DISCARD", "counters"),
    ("COUNTERS", "counters"),
    ("LOOP", "loop"),
]
ASSET_SYSLOG_HOST_ALIAS_KEYS = (
    "syslog_hostnames",
    "syslog_hostname",
    "simulator_hostname",
    "host_aliases",
    "aliases",
)
ASSET_SYSLOG_SRC_IP_ALIAS_KEYS = (
    "syslog_src_ips",
    "syslog_src_ip",
    "simulator_src_ip",
    "src_ip_aliases",
    "ip_aliases",
)

SNMP_POLLING_DEBUG_PATTERNS = [
    re.compile(r"\bSNMP\s+0x[0-9A-Fa-f]+\b.*\bOID\(s\)\b", re.IGNORECASE),
    re.compile(r"\bSNMP\s+(?:GET|GETNEXT|GETBULK|GET-NEXT|GET-BULK)\b(?:.*\bOID\(s\)\b)?", re.IGNORECASE),
]
SNMP_PROCESS_DEBUG_PATTERNS = [
    re.compile(r"\bConnection from UDP:\b", re.IGNORECASE),
]

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def parse_ts(mon, day, hms):
    now = datetime.now()
    dt = datetime(now.year, MONTHS[mon], int(day), *map(int, hms.split(":")))
    if dt > now and (dt - now).days > 1:
        dt = dt.replace(year=now.year - 1)
    return dt


def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def load_offset():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as handle:
            return max(0, int(handle.read().strip() or "0"))
    except (FileNotFoundError, ValueError):
        return 0


def save_offset(offset):
    ensure_parent_dir(STATE_FILE)
    with open(STATE_FILE, "w", encoding="utf-8") as handle:
        handle.write(str(max(0, int(offset))))


def open_stream(path, offset):
    handle = open(path, "r", encoding="utf-8", errors="replace")
    size = os.path.getsize(path)
    safe_offset = min(max(0, offset), size)
    handle.seek(safe_offset)
    return handle, safe_offset


def follow(path):
    current_handle = None
    current_offset = load_offset()

    while True:
        if not os.path.exists(path):
            time.sleep(0.5)
            continue

        if current_handle is None:
            current_handle, current_offset = open_stream(path, current_offset)
            save_offset(current_offset)

        line = current_handle.readline()
        if line:
            current_offset = current_handle.tell()
            save_offset(current_offset)
            yield line.rstrip("\n")
            continue

        try:
            current_size = os.path.getsize(path)
        except FileNotFoundError:
            current_handle.close()
            current_handle = None
            current_offset = 0
            save_offset(current_offset)
            time.sleep(0.2)
            continue

        current_position = current_handle.tell()
        if current_size < current_position:
            current_handle.close()
            current_handle = None
            current_offset = 0
            save_offset(current_offset)
            continue

        time.sleep(0.2)


def normalize_asset_tags(tags):
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, str) and tags.strip():
        try:
            loaded = json.loads(tags)
        except json.JSONDecodeError:
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return {}


def tag_values(tags, keys):
    values = []
    for key in keys:
        raw = tags.get(key)
        if raw is None:
            continue
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(item).strip() for item in raw if str(item).strip())
        else:
            text = str(raw).strip()
            if text:
                values.append(text)
    return values


def asset_tags_match_syslog(tags, hostname, src_ip):
    normalized_tags = normalize_asset_tags(tags)
    hostname_key = str(hostname or "").strip().lower()
    src_ip_key = str(src_ip or "").strip()

    hostname_aliases = [item.lower() for item in tag_values(normalized_tags, ASSET_SYSLOG_HOST_ALIAS_KEYS)]
    src_ip_aliases = tag_values(normalized_tags, ASSET_SYSLOG_SRC_IP_ALIAS_KEYS)

    return (hostname_key and hostname_key in hostname_aliases) or (src_ip_key and src_ip_key in src_ip_aliases)


def resolve_asset_id(cur, hostname, src_ip, cache):
    cache_key = (str(src_ip), str(hostname).lower())
    if cache_key in cache:
        return cache[cache_key]

    cur.execute(
        """
        select id
        from assets
        where ip::text = %s
           or lower(name) = lower(%s)
        order by
          case when ip::text = %s then 0 else 1 end,
          case when lower(name) = lower(%s) then 0 else 1 end,
          id
        limit 1
        """,
        (src_ip, hostname, src_ip, hostname),
    )
    row = cur.fetchone()
    asset_id = row[0] if row else None

    if asset_id is None:
        cur.execute(
            """
            select id, tags
            from assets
            where enabled = true
            order by id
            """
        )
        for candidate in cur.fetchall():
            if asset_tags_match_syslog(candidate[1], hostname, src_ip):
                asset_id = candidate[0]
                break

    cache[cache_key] = asset_id
    return asset_id


def is_noise_syslog(process_name, rest):
    process_text = str(process_name or "").lower()
    message_text = str(rest or "")

    for pattern in SNMP_POLLING_DEBUG_PATTERNS:
        if pattern.search(message_text):
            return True

    if process_text in {"snmpd", "snmptrapd"}:
        for pattern in SNMP_PROCESS_DEBUG_PATTERNS:
            if pattern.search(message_text):
                return True

    if process_text in {"snmpd", "snmp", "snmptrapd"} and re.search(r"\bSNMP\s+(?:GET|GETNEXT|GETBULK)\b", message_text, re.IGNORECASE):
        if "trap" not in message_text.lower():
            return True

    return False


def normalize_iface_name(value):
    text = str(value or "").strip()
    if not text:
        return None

    text = re.sub(r"^[<>\[(]+", "", text)
    text = re.sub(r"[>\]),.;:]+$", "", text)
    replacements = (
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("Port-channel", "Po"),
        ("Ethernet", "Eth"),
        ("Loopback", "Lo"),
        ("Vlan", "Vlan"),
    )
    lowered = text.lower()
    for prefix, short in replacements:
        if lowered.startswith(prefix.lower()):
            return short + text[len(prefix):]
    return text


def extract_interface_hint(*parts):
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        pair = INTERFACE_PAIR_PATTERN.search(text)
        if pair:
            left = normalize_iface_name(pair.group(1))
            right = normalize_iface_name(pair.group(2))
            if left and right:
                return f"{left}<->{right}"
        for token in INTERFACE_TOKEN_PATTERN.findall(text):
            normalized = normalize_iface_name(token)
            if normalized:
                return normalized
    return None


def extract_interface_hints(*parts):
    hints = []
    seen = set()
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        pair = INTERFACE_PAIR_PATTERN.search(text)
        if pair:
            for token in (pair.group(1), pair.group(2)):
                normalized = normalize_iface_name(token)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    hints.append(normalized)
        for token in INTERFACE_TOKEN_PATTERN.findall(text):
            normalized = normalize_iface_name(token)
            if normalized and normalized not in seen:
                seen.add(normalized)
                hints.append(normalized)
    return hints


def normalize_syslog_subsystem(value):
    text = str(value or "").strip()
    if not text:
        return None
    text = text.lstrip("%").rstrip(":")
    proc_match = SYSLOG_PROCESS_EVENT_PATTERN.match(text)
    if proc_match:
        text = proc_match.group("subsystem")
    return text.lower().replace(" ", "_")


def infer_syslog_severity(severity, process, message, raw):
    normalized = str(severity or "").strip().lower()
    upper_text = " ".join(str(part or "").upper() for part in (process, message, raw))
    if normalized:
        if normalized.isdigit():
            return SYSLOG_LEVEL_TO_SEVERITY.get(normalized)
        return normalized

    if "CHANGED STATE TO UP" in upper_text:
        return "notice"
    if "CHANGED STATE TO DOWN" in upper_text:
        return "warning"
    if "LOGGINGHOST_STARTSTOP" in upper_text or "LOGGING HOST" in upper_text:
        return "info"

    process_match = SYSLOG_PROCESS_EVENT_PATTERN.match(str(process or "").strip().rstrip(":"))
    if process_match and process_match.group("level"):
        return SYSLOG_LEVEL_TO_SEVERITY.get(process_match.group("level"))

    if any(token in upper_text for token in ("UNPROTECTED", "ERR_DISABLE", "LOOP DETECTADO")):
        return "high"
    if any(
        token in upper_text
        for token in (
            "LOOPGUARD_BLOCK",
            "LOOPGUARD BLOCK",
            "LOOPGUARD_BLOCKED",
            "LOOPGUARD",
            "BROADCAST STORM",
            "STORMCTRL",
            "STORM CONTROL",
            "STORM_CONTROL",
            "MACFLAP",
            "MAC FLAP",
            "MAC FLAPPING",
            "BURST DE ERROS",
            "CHANGED STATE TO DOWN",
            "LINK-3-UPDOWN",
            "LINEPROTO",
            "LINE PROTOCOL",
            "STP BLOCKING",
            "STP BLOCKED",
        )
    ):
        return "warning"
    if any(token in upper_text for token in ("TOPOTRAP", "DESABILITADO", "CHANGED STATE TO UP")):
        return "notice"
    if any(token in upper_text for token in ("TESTE DE SYSLOG MANUAL", "INICIADO", "CONFIGURAÇÃO SALVA", "PORTAS:")):
        return "info"
    return None


def infer_syslog_subsystem(subsystem, process, message, raw):
    normalized = normalize_syslog_subsystem(subsystem)
    if normalized:
        return normalized

    process_text = str(process or "").strip().lstrip("%").rstrip(":")
    proc_match = SYSLOG_PROCESS_EVENT_PATTERN.match(process_text)
    if proc_match:
        return normalize_syslog_subsystem(proc_match.group("subsystem"))

    upper_text = " ".join(str(part or "").upper() for part in (process, message, raw))
    for token, mapped in SYSLOG_SUBSYSTEM_KEYWORDS:
        if token in upper_text:
            return mapped
    return None


def enrich_syslog_fields(process, severity, subsystem, iface, message, raw):
    resolved_iface = normalize_iface_name(iface)
    if not resolved_iface:
        resolved_iface = extract_interface_hint(iface, message, raw)

    return (
        infer_syslog_severity(severity, process, message, raw),
        infer_syslog_subsystem(subsystem, process, message, raw),
        resolved_iface,
    )


def has_correlation_schema(cur):
    cur.execute("select to_regclass('syslog_interface_correlations')")
    row = cur.fetchone()
    return bool(row and row[0])


def normalize_iface_for_compare(value):
    normalized = normalize_iface_name(value)
    if not normalized:
        return ""
    return re.sub(r"[^a-z0-9/.\-]", "", normalized.lower())


def correlate_syslog_event(cur, asset_id, event_id, iface, message, raw):
    if not asset_id or not event_id or not has_correlation_schema(cur):
        return
    hints = extract_interface_hints(iface, message, raw)
    if not hints and iface:
        hints = [iface]
    if not hints:
        return

    cur.execute(
        """
        SELECT id, ifindex, ifdescr, if_name, if_alias
        FROM discovered_interfaces
        WHERE asset_id=%s
        """,
        (asset_id,),
    )
    interfaces = cur.fetchall()
    for hint in hints:
        normalized_hint = normalize_iface_for_compare(hint)
        if not normalized_hint:
            continue
        best = None
        for row in interfaces:
            candidates = [
                normalize_iface_for_compare(row[2]),
                normalize_iface_for_compare(row[3]),
                normalize_iface_for_compare(row[4]),
            ]
            if normalized_hint in candidates:
                best = row
                break
        evidence = {"source": "syslog_collector", "hint": hint}
        cur.execute(
            """
            INSERT INTO syslog_interface_correlations (
                asset_id, syslog_event_id, interface_id, ifindex,
                normalized_iface, confidence, evidence
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT DO NOTHING
            """,
            (
                asset_id,
                event_id,
                best[0] if best else None,
                best[1] if best else None,
                hint,
                0.95 if best else 0.60,
                json.dumps(evidence),
            ),
        )


def main():
    if not DB_DSN:
        raise SystemExit("NETGUARD_DB_DSN nao definido")

    wait_sec = DB_CONNECT_RETRY_SEC
    while True:
        try:
            conn = psycopg2.connect(DB_DSN)
            break
        except psycopg2.OperationalError as exc:
            print(f"[syslog-collector] aguardando banco ficar pronto: {exc}", flush=True)
            time.sleep(wait_sec)
            wait_sec = min(DB_CONNECT_RETRY_MAX_SEC, max(DB_CONNECT_RETRY_SEC, wait_sec * 2))

    conn.autocommit = True
    cur = conn.cursor()
    asset_cache = {}

    for raw in follow(LOG_PATH):
        match = LINE_RE.match(raw)
        if not match:
            continue

        ts = parse_ts(match["mon"], match["day"], match["hms"])
        host = match["host"]
        src_ip = match["srcip"]
        proc = str(match["proc"] or "").rstrip(":")
        pid = int(match["pid"]) if match["pid"] else None
        rest = (match["rest"] or "").lstrip()

        if is_noise_syslog(proc, rest):
            continue

        event_id = severity = subsystem = slot = iface = None
        msg = rest

        event_match = ARUBA_EVENT_RE.search(rest)
        if event_match:
            event_id = int(event_match["eid"])
            severity = event_match["sev"]
            subsystem = event_match["subsys"]
            slot = event_match["slot"] or None
            iface = event_match["iface"] or None
            msg = (event_match["msg"] or "").strip()

        if not iface:
            iface = extract_interface_hint(rest, msg, raw)
        else:
            iface = normalize_iface_name(iface) or extract_interface_hint(rest, msg, raw)

        severity, subsystem, iface = enrich_syslog_fields(proc, severity, subsystem, iface, msg, raw)

        asset_id = resolve_asset_id(cur, host, src_ip, asset_cache)

        cur.execute(
            """
            insert into syslog_events (ts, hostname, src_ip, asset_id, process, pid, event_id, severity, subsystem, slot, iface, message, raw)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            returning id
            """,
            (ts, host, src_ip, asset_id, proc, pid, event_id, severity, subsystem, slot, iface, msg, raw),
        )
        inserted = cur.fetchone()
        if inserted:
            correlate_syslog_event(cur, asset_id, inserted[0], iface, msg, raw)


if __name__ == "__main__":
    main()
