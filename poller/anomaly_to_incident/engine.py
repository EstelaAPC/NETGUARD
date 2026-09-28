# -*- coding: utf-8 -*-
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import psycopg2
from psycopg2.extras import RealDictCursor

DB = os.getenv("DATABASE_URL") or os.getenv("NETGUARD_DB_DSN")
ENGINE_STARTED_AT = datetime.now(timezone.utc)
INTERVAL = int(os.getenv("ENGINE_INTERVAL_SEC", "30"))
WINDOW_MIN = int(os.getenv("WINDOW_MIN", "10"))
MIN_HITS = int(os.getenv("MIN_HITS", "3"))
MIN_Z = float(os.getenv("MIN_Z", "2.0"))
RUN_ONCE = os.getenv("RUN_ONCE", "false").lower() in ("1", "true", "yes")
NETGUARD_API_URL = os.getenv("NETGUARD_API_URL", "").strip().rstrip("/")
NETGUARD_SERVICE_TOKEN = os.getenv("NETGUARD_SERVICE_TOKEN", "").strip()
ALERT_NOTIFY_TIMEOUT_SEC = float(os.getenv("ALERT_NOTIFY_TIMEOUT_SEC", "5"))
ALERT_NOTIFY_PENDING_LOOKBACK_HOURS = int(os.getenv("ALERT_NOTIFY_PENDING_LOOKBACK_HOURS", "6"))
ALERT_NOTIFY_PENDING_LIMIT = int(os.getenv("ALERT_NOTIFY_PENDING_LIMIT", "20"))
ALERT_NOTIFY_PENDING_MIN_SEVERITY = os.getenv("ALERT_NOTIFY_PENDING_MIN_SEVERITY", "MEDIUM").strip().upper()
ALERT_NOTIFY_RECENT_MINUTES = int(os.getenv("ALERT_NOTIFY_RECENT_MINUTES", "10"))
ALERT_NOTIFY_RECOVERIES_ENABLED = os.getenv("ALERT_NOTIFY_RECOVERIES_ENABLED", "true").lower() in ("1", "true", "yes", "on")
ALERT_NOTIFY_RECOVERY_LOOKBACK_HOURS = int(os.getenv("ALERT_NOTIFY_RECOVERY_LOOKBACK_HOURS", "6"))
AUTO_RESOLVE_ALERTS_ENABLED = os.getenv("AUTO_RESOLVE_ALERTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
AUTO_RESOLVE_AFTER_MINUTES = int(os.getenv("AUTO_RESOLVE_AFTER_MINUTES", "5"))
AUTO_RESOLVE_MAX_PER_CYCLE = int(os.getenv("AUTO_RESOLVE_MAX_PER_CYCLE", "5"))
AUTO_RESOLVE_STARTUP_GRACE_MINUTES = int(os.getenv("AUTO_RESOLVE_STARTUP_GRACE_MINUTES", "1"))

SIGNAL_ALERTS_ENABLED = os.getenv("SIGNAL_ALERTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
SYSLOG_ALERTS_ENABLED = os.getenv("SYSLOG_ALERTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
SYSLOG_ALERT_LOOP_COMPONENTS_ENABLED = os.getenv("SYSLOG_ALERT_LOOP_COMPONENTS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
SYSLOG_ALERT_INTERFACE_FLAP_ENABLED = os.getenv("SYSLOG_ALERT_INTERFACE_FLAP_ENABLED", "true").lower() in ("1", "true", "yes", "on")
SYSLOG_ALERT_INTERFACE_FLAP_MIN_EVENTS = int(os.getenv("SYSLOG_ALERT_INTERFACE_FLAP_MIN_EVENTS", "4"))
SYSLOG_ALERT_INTERFACE_FLAP_WINDOW_SEC = int(os.getenv("SYSLOG_ALERT_INTERFACE_FLAP_WINDOW_SEC", "120"))
SYSLOG_ALERT_INTERFACE_FLAP_MIN_SEVERITY = os.getenv("SYSLOG_ALERT_INTERFACE_FLAP_MIN_SEVERITY", "notice").strip().lower()
PREDICTION_ALERTS_ENABLED = os.getenv("PREDICTION_ALERTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
SIGNAL_ALERT_LOOKBACK_SEC = int(os.getenv("SIGNAL_ALERT_LOOKBACK_SEC", "120"))
SIGNAL_ALERT_LIMIT = int(os.getenv("SIGNAL_ALERT_LIMIT", "80"))
SIGNAL_ALERT_CACHE_TTL_SEC = int(os.getenv("SIGNAL_ALERT_CACHE_TTL_SEC", "600"))
SYSLOG_ALERT_MIN_SEVERITY = os.getenv("SYSLOG_ALERT_MIN_SEVERITY", "info").strip().lower()
PREDICTION_ALERT_MIN_SCORE = float(os.getenv("PREDICTION_ALERT_MIN_SCORE", "0.50"))
PREDICTION_ALERT_TOP_ITEMS = int(os.getenv("PREDICTION_ALERT_TOP_ITEMS", "5"))
AVAILABILITY_ALERTS_ENABLED = os.getenv("AVAILABILITY_ALERTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
AVAILABILITY_ICMP_STALE_MULTIPLIER = float(os.getenv("AVAILABILITY_ICMP_STALE_MULTIPLIER", "4"))
AVAILABILITY_SNMP_STALE_MULTIPLIER = float(os.getenv("AVAILABILITY_SNMP_STALE_MULTIPLIER", "4"))
AVAILABILITY_SYSLOG_STALE_SEC = int(os.getenv("AVAILABILITY_SYSLOG_STALE_SEC", "300"))
AVAILABILITY_HOST_DOWN_SAMPLES = int(os.getenv("AVAILABILITY_HOST_DOWN_SAMPLES", "2"))
AVAILABILITY_MIN_STALE_SEC = int(os.getenv("AVAILABILITY_MIN_STALE_SEC", "60"))
AVAILABILITY_SNMP_MIN_STALE_SEC = int(os.getenv("AVAILABILITY_SNMP_MIN_STALE_SEC", "180"))
AVAILABILITY_RECOVERY_TYPES = {
    "HOST_DOWN",
    "ICMP_COLLECTION_SILENCE",
    "COLLECTION_SILENCE",
    "HOST_UNAVAILABLE",
    "UNAVAILABLE",
}
SNMP_RECOVERY_TYPES = {"SNMP_COLLECTION_SILENCE"}
INTERFACE_RECOVERY_TYPES = {"INTERFACE_DOWN", "IFOPERSTATUS_DOWN", "IF_OPER_STATUS_DOWN"}

LOOP_WINDOW_SEC = int(os.getenv("LOOP_RISK_WINDOW_SEC", "60"))
LOOP_OPEN_SCORE = float(os.getenv("LOOP_RISK_OPEN_SCORE", "0.75"))
LOOP_RISK_STALE_RESOLVE_SEC = int(
    os.getenv("LOOP_RISK_STALE_RESOLVE_SEC", str(max(LOOP_WINDOW_SEC * 3, 1800)))
)
LOOP_RISK_STALE_RESOLVE_NOTIFY = os.getenv("LOOP_RISK_STALE_RESOLVE_NOTIFY", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
LOOP_RISK_CLEAN_CYCLES = int(os.getenv("LOOP_RISK_CLEAN_CYCLES", "3"))
LOOP_RISK_HIGH_CLEAN_CYCLES = int(os.getenv("LOOP_RISK_HIGH_CLEAN_CYCLES", "2"))
LOOP_RISK_CRITICAL_CLEAN_CYCLES = int(os.getenv("LOOP_RISK_CRITICAL_CLEAN_CYCLES", "3"))
LOOP_RISK_NOTIFICATION_COOLDOWN_MINUTES = int(os.getenv("LOOP_RISK_NOTIFICATION_COOLDOWN_MINUTES", "30"))
DB_CONNECT_RETRY_SEC = float(os.getenv("DB_CONNECT_RETRY_SEC", "5"))
DB_CONNECT_RETRY_MAX_SEC = float(os.getenv("DB_CONNECT_RETRY_MAX_SEC", "60"))

ALLOWED_METRICS = (
    "snmp.if.in_errors.delta",
    "snmp.if.out_errors.delta",
    "snmp.if.in_discards.delta",
    "snmp.if.out_discards.delta",
)

LOOP_SIGNAL_WEIGHTS = {
    "STP_TOPOLOGY_CHANGE": 0.20,
    "MAC_FLAPPING": 0.70,
    "INTERFACE_FLAP": 0.10,
    "BROADCAST_STORM": 0.75,
}

LOOP_STRONG_SCORE_FLOOR = 0.80
LOOP_MEDIUM_SCORE_FLOOR = 0.76
LOOP_WEAK_SCORE_CAP = 0.20
LOOP_INELIGIBLE_SCORE_CAP = 0.35
LOOP_REPEATED_STP_EVENTS = 3
LOOP_REPEATED_FLAP_EVENTS = 4

LOOP_SIGNAL_PATTERNS = {
    "MAC_FLAPPING": [
        "MAC_FLAPPING",
        "MAC FLAPPING",
        "MACFLAP",
        "MAC FLAP",
        "MAC-FLAP",
        "MAC MOVE",
        "MAC-MOVE",
        "MAC ADDRESS FLAP",
        "MAC ADDRESS MOVE",
    ],
    "STP_TOPOLOGY_CHANGE": [
        "STP_TOPOLOGY_CHANGE",
        "STP ",
        "SPANTREE",
        "SPAN TREE",
        "SPANNING TREE",
        "BPDU GUARD",
        "BPDUGUARD",
        "STP TOPOLOGY CHANGE",
        "TOPOLOGY_CHANGE",
        "TOPOLOGY CHANGE",
        "TOPOLOGY CHANGE NOTIFICATION",
        "SPANNING TREE TOPOLOGY CHANGE",
        "TCN",
        "LOOPGUARD",
        "LOOPGUARD_BLOCK",
        "LOOP GUARD BLOCK",
        "STP BLOCKING",
        "STP BLOCKED",
        "PORT BLOCKED",
    ],
    "BROADCAST_STORM": [
        "BROADCAST_STORM",
        "BROADCAST STORM",
        "STORM CONTROL",
        "STORM_CONTROL",
        "STORM-CONTROL",
        "STORMCTRL",
        "ERR-DISABLE STORM",
        "ERR_DISABLE STORM",
        "LOOP DETECT",
        "LOOP DETECTED",
        "LOOP ATIVO",
        "ACTIVE LOOP",
    ],
    "INTERFACE_FLAP": [
        "INTERFACE_FLAP",
        "INTERFACE FLAP",
        "LINKDOWN",
        "LINKUP",
        "LINK FLAP",
        "PORT FLAP",
        "CHANGED STATE TO DOWN",
        "CHANGED STATE TO UP",
        "WENT DOWN",
        "WENT UP",
        "LINK DOWN",
        "LINK UP",
        "FLAPPED DOWN",
        "FLAPPED UP",
        "FLAPPED",
        "LINEPROTO 5 UPDOWN",
        "LINE PROTOCOL",
        "LINK-3-UPDOWN",
        "LINEPROTO",
        "ERR_DISABLE",
    ],
}

LOOP_RECOVERY_PATTERNS = [
    "RESETADO",
    "RESETADA",
    "RESETADOS",
    "RESETADAS",
    "LIMPO",
    "LIMPA",
    "LIMPOS",
    "LIMPAS",
    "CLEARED",
    "CLEAR",
    "RECOVERED",
    "RECOVERY",
    "ERR_RECOVER",
    "ERR RECOVER",
    "ERRDISABLE RECOVERY",
    "ERR-DISABLE RECOVERY",
    "ERRDISABLE RECOVER",
    "ERR-DISABLE RECOVER",
    "RESOLVED",
    "NORMALIZADO",
    "NORMALIZADA",
    "SEM LOOP",
    "NO LOOP",
    "BLOCKING",
    "BLOCKED",
    "DISCARDING",
]

LOOP_RECOVERY_CONTEXT_PATTERNS = [
    "LOOP",
    "STORM",
    "FLAP",
    "MAC FLAP",
    "ERR DISABLE",
    "ERR-DISABLE",
    "ERRDISABLE",
    "ERR_RECOVER",
    "STP",
    "SPANTREE",
    "SPANNING TREE",
    "BLOCKING",
    "DISCARDING",
]

PERSISTENT_LOOP_PROBLEM_PREFIXES = (
    "LOOP_RISK",
    "SYSLOG_LOOP",
    "SYSLOG_BROADCAST_STORM",
    "SYSLOG_MAC_FLAPPING",
    "SYSLOG_STP_TOPOLOGY_CHANGE",
    "SYSLOG_STORM_CONTROL",
    "SYSLOG_STORMCTRL",
)

NORMALIZE_PATTERN_RE = re.compile(r"[^A-Z0-9]+")
INTERFACE_TOKEN_REGEX = (
    r"(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Port-channel|Ethernet|Loopback|Vlan|Te|Gi|Fa|Po|Eth|Lo)"
    r"\d+(?:/\d+)*(?:\.\d+)?"
)
INTERFACE_TOKEN_PATTERN = re.compile(INTERFACE_TOKEN_REGEX, re.IGNORECASE)
INTERFACE_PAIR_PATTERN = re.compile(
    rf"({INTERFACE_TOKEN_REGEX})\s*<->\s*({INTERFACE_TOKEN_REGEX})",
    re.IGNORECASE,
)
INTERFACE_BETWEEN_PAIR_PATTERN = re.compile(
    rf"between\s+interfaces?\s+({INTERFACE_TOKEN_REGEX})\s+(?:and|e)\s+({INTERFACE_TOKEN_REGEX})",
    re.IGNORECASE,
)
LOOP_VLAN_PATTERN = re.compile(r"\bVLAN\s*0*([0-9]{1,4})\b", re.IGNORECASE)
SIGNAL_CONTEXT_PRIORITY = {
    "BROADCAST_STORM": 0,
    "MAC_FLAPPING": 1,
    "STP_TOPOLOGY_CHANGE": 2,
    "INTERFACE_FLAP": 3,
}
SIGNAL_LABELS = {
    "BROADCAST_STORM": "Tempestade de broadcast",
    "MAC_FLAPPING": "MAC flapping",
    "STP_TOPOLOGY_CHANGE": "Mudança de topologia STP",
    "INTERFACE_FLAP": "Flap de interface",
}

SIGNAL_IMPACTS = {
    "BROADCAST_STORM": "Pode degradar a VLAN, aumentar latência, perda de pacotes e CPU dos switches.",
    "MAC_FLAPPING": "Pode indicar loop físico, redundância indevida ou agregação incorreta entre portas.",
    "STP_TOPOLOGY_CHANGE": "Pode indicar mudança de caminho L2, instabilidade ou reconvergência de spanning tree.",
    "INTERFACE_FLAP": "Pode causar perda intermitente de conectividade no enlace conectado.",
}

SIGNAL_ACTIONS = {
    "BROADCAST_STORM": "Identifique a porta/VLAN de origem, valide STP e storm-control, e isole a porta se o tráfego continuar subindo.",
    "MAC_FLAPPING": "Confira as portas envolvidas, agregação, redundância física e possibilidade de loop entre switches.",
    "STP_TOPOLOGY_CHANGE": "Verifique alterações recentes, raiz STP, portas bloqueadas e eventos de reconvergência.",
    "INTERFACE_FLAP": "Verifique cabo/SFP, speed/duplex, energia do equipamento remoto e histórico de link up/down.",
}

METRIC_LABELS = {
    "snmp.if.in_errors.delta": "erros de entrada",
    "snmp.if.out_errors.delta": "erros de saida",
    "snmp.if.in_discards.delta": "descartes de entrada",
    "snmp.if.out_discards.delta": "descartes de saida",
    "snmp.if.in_octets.delta": "trafego de entrada",
    "snmp.if.out_octets.delta": "trafego de saida",
}

SYSLOG_SEVERITY_RANKS = {
    "debug": 0,
    "trace": 0,
    "info": 1,
    "informational": 1,
    "notice": 1,
    "low": 1,
    "warning": 2,
    "warn": 2,
    "medium": 2,
    "error": 3,
    "err": 3,
    "high": 3,
    "critical": 4,
    "crit": 4,
    "fatal": 4,
    "emergency": 4,
    "alert": 4,
}
ALERT_SEVERITY_RANKS = {
    "low": 1,
    "info": 1,
    "notice": 1,
    "warning": 2,
    "warn": 2,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
SIGNAL_ALERT_CACHE: dict[str, float] = {}

LOOP_RECOMMENDATION = (
    "Correlação temporal de syslog indica risco de loop L2. "
    "Verificar STP, MAC flapping, flap de interface, tempestade de broadcast, "
    "conectividade redundante indevida e ação de isolamento da porta afetada."
)


def service_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if NETGUARD_SERVICE_TOKEN:
        headers["X-NetGuard-Service-Token"] = NETGUARD_SERVICE_TOKEN
    return headers


def notify_alert_service(incident_id: int | None) -> None:
    if not incident_id or not NETGUARD_API_URL:
        return

    url = f"{NETGUARD_API_URL}/alerts/incidents/{incident_id}/notify"
    payload = json.dumps({"force": False}).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers=service_headers(),
        method="POST",
    )
    try:
        with urlopen(request, timeout=ALERT_NOTIFY_TIMEOUT_SEC) as response:
            response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        print(f"Falha ao acionar AlertService para incident_id={incident_id}: {exc}", flush=True)


def should_notify_incident(cur, incident_id: int | None) -> bool:
    if not incident_id:
        return False
    cur.execute(
        """
        select not exists (
          select 1
          from incident_notifications n
          where n.incident_id = %s
            and n.sent_at >= now() - (%s || ' minutes')::interval
        ) as should_notify
        """,
        (incident_id, max(1, ALERT_NOTIFY_RECENT_MINUTES)),
    )
    row = cur.fetchone()
    return bool(row and row.get("should_notify"))


def should_notify_loop_fingerprint(cur, incident_id: int | None, fingerprint: str) -> bool:
    if not incident_id:
        return False
    normalized_fingerprint = str(fingerprint or "").strip()
    if not normalized_fingerprint:
        return should_notify_incident(cur, incident_id)

    cooldown_minutes = max(1, LOOP_RISK_NOTIFICATION_COOLDOWN_MINUTES)
    cur.execute(
        """
        select not exists (
          select 1
          from incident_notifications n
          join incidents i on i.id = n.incident_id
          where n.sent_at >= now() - (%s || ' minutes')::interval
            and lower(coalesce(n.provider, '')) <> 'anti_spam'
            and (
              i.id = %s
              or i.key = %s
              or coalesce(i.details->>'loop_fingerprint', '') = %s
            )
        ) as should_notify
        """,
        (cooldown_minutes, incident_id, normalized_fingerprint, normalized_fingerprint),
    )
    row = cur.fetchone()
    return bool(row and row.get("should_notify"))


def notify_recovery_service(incident_id: int | None, send_recovery_notification: bool = True) -> None:
    if not incident_id or not NETGUARD_API_URL:
        return

    url = f"{NETGUARD_API_URL}/alerts/incidents/{incident_id}/resolve"
    payload = json.dumps({"send_recovery_notification": bool(send_recovery_notification)}).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers=service_headers(),
        method="POST",
    )
    try:
        with urlopen(request, timeout=ALERT_NOTIFY_TIMEOUT_SEC) as response:
            response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        print(f"Falha ao acionar recuperacao para incident_id={incident_id}: {exc}", flush=True)


def post_alert_problem(payload: dict) -> None:
    if not NETGUARD_API_URL:
        return

    url = f"{NETGUARD_API_URL}/alerts"
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=service_headers(),
        method="POST",
    )
    try:
        with urlopen(request, timeout=ALERT_NOTIFY_TIMEOUT_SEC) as response:
            response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        print(
            f"Falha ao registrar alerta automatico problem_type={payload.get('problem_type')}: {exc}",
            flush=True,
        )


def should_emit_signal_alert(cache_key: str) -> bool:
    now_ts = time.time()
    for key, expires_at in list(SIGNAL_ALERT_CACHE.items()):
        if expires_at <= now_ts:
            SIGNAL_ALERT_CACHE.pop(key, None)

    if SIGNAL_ALERT_CACHE.get(cache_key, 0) > now_ts:
        return False

    SIGNAL_ALERT_CACHE[cache_key] = now_ts + max(60, SIGNAL_ALERT_CACHE_TTL_SEC)
    return True


def alert_ts(value) -> str:
    if isinstance(value, datetime):
        ts = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def clamp_text(value: str | None, limit: int = 1800) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def safe_problem_type(prefix: str, *parts: str | None) -> str:
    fragments = [prefix]
    for part in parts:
        fragment = NORMALIZE_PATTERN_RE.sub("_", str(part or "").upper()).strip("_")
        if fragment:
            fragments.append(fragment[:48])
    problem_type = "_".join(fragments).strip("_")
    return (problem_type or prefix)[:120]


def syslog_severity_rank(value: str | None) -> int:
    return SYSLOG_SEVERITY_RANKS.get(str(value or "").strip().lower(), 1)


def alert_severity_rank(value: str | None) -> int:
    return ALERT_SEVERITY_RANKS.get(str(value or "").strip().lower(), 1)


def is_loop_component_problem_type(value: str | None) -> bool:
    problem_type = str(value or "").strip().upper()
    return is_persistent_loop_problem_type(problem_type) or problem_type.startswith("SYSLOG_INTERFACE_FLAP")


def is_persistent_loop_problem_type(value: str | None) -> bool:
    problem_type = str(value or "").strip().upper()
    return any(problem_type.startswith(prefix) for prefix in PERSISTENT_LOOP_PROBLEM_PREFIXES)


def sql_persistent_loop_problem_filter(column: str = "problem_type") -> str:
    expression = f"upper(coalesce({column}, ''))"
    checks = [f"{expression} = 'LOOP_RISK'"]
    checks.extend(
        f"{expression} like '{prefix}%%'"
        for prefix in PERSISTENT_LOOP_PROBLEM_PREFIXES
        if prefix != "LOOP_RISK"
    )
    return "(" + " or ".join(checks) + ")"


def sql_alert_severity_rank(column: str = "severity") -> str:
    return (
        f"case "
        f"when lower(coalesce({column}, '')) in ('critical', 'critica') then 4 "
        f"when lower(coalesce({column}, '')) in ('high', 'alta') then 3 "
        f"when lower(coalesce({column}, '')) in ('medium', 'warning', 'warn', 'media', 'atencao') then 2 "
        f"else 1 end"
    )


def sql_incident_activity_ts() -> str:
    return (
        "greatest("
        "coalesce(last_detected_at, '-infinity'::timestamptz), "
        "coalesce(last_seen_at, '-infinity'::timestamptz), "
        "coalesce(updated_at, '-infinity'::timestamptz), "
        "coalesce(opened_at, '-infinity'::timestamptz), "
        "coalesce(created_at, '-infinity'::timestamptz)"
        ")"
    )


def syslog_alert_severity(value: str | None) -> str:
    rank = syslog_severity_rank(value)
    if rank >= 4:
        return "CRITICAL"
    if rank == 3:
        return "HIGH"
    if rank == 2:
        return "MEDIUM"
    return "LOW"


def prediction_alert_severity(score: float | None) -> str:
    numeric = float(score or 0)
    if numeric >= 0.90:
        return "CRITICAL"
    if numeric >= 0.75:
        return "HIGH"
    if numeric >= 0.50:
        return "MEDIUM"
    return "LOW"


def event_value_hint(message: str | None) -> str:
    state = event_oper_state(message)
    if state == "up":
        return "Up (1)"
    if state == "down":
        return "Down (0)"
    text = str(message or "").upper()
    if "INDISPON" in text or "FAILED" in text:
        return "Down (0)"
    if "RECOVER" in text or "RESOLV" in text:
        return "Up (1)"
    return "Evento detectado"


def event_oper_state(message: str | None) -> str | None:
    text = str(message or "").upper()
    if (
        re.search(r"\b(CHANGED STATE TO|STATE TO|LINK)\s+DOWN\b", text)
        or re.search(r"\bFLAPPED\s+DOWN\b", text)
        or "INDISPON" in text
        or "FAILED" in text
    ):
        return "down"
    if (
        re.search(r"\b(CHANGED STATE TO|STATE TO|LINK)\s+UP\b", text)
        or re.search(r"\bFLAPPED\s+UP\b", text)
    ) and "SHUTDOWN" not in text:
        return "up"
    return None


def display_focus(value: str | None) -> str:
    text = str(value or "").strip()
    if not text or text == "host":
        return "host"
    return text.replace("<->", " e ").replace("↔", " e ")


def signal_problem_name(signal: str | None, focus: str | None, fallback: str | None = None) -> str:
    signal_key = str(signal or "SYSLOG").strip().upper()
    focus_label = display_focus(focus)
    if signal_key == "BROADCAST_STORM":
        return f"Tempestade de broadcast em {focus_label}" if focus_label != "host" else "Tempestade de broadcast"
    if signal_key == "MAC_FLAPPING":
        return f"MAC flapping entre {focus_label}" if focus_label != "host" else "MAC flapping detectado"
    if signal_key == "STP_TOPOLOGY_CHANGE":
        return f"Mudanca de topologia STP em {focus_label}" if focus_label != "host" else "Mudanca de topologia STP"
    if signal_key == "INTERFACE_FLAP":
        return f"Flap de interface em {focus_label}" if focus_label != "host" else "Flap de interface"
    return clamp_text(fallback or signal_key, 180)


def metric_label(metric: str | None) -> str:
    value = str(metric or "").strip()
    return METRIC_LABELS.get(value, value or "metrica")


def prediction_focus(row: dict) -> str:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    key = str(row.get("key") or "host")
    iface = details.get("ifName")
    if not iface and "=" in key:
        iface = key.split("=", 1)[1]
    return str(iface or key or "host")


def prediction_item_summary(row: dict) -> dict:
    score = float(row.get("score") or 0.0)
    metric = str(row.get("metric") or "prediction")
    focus = prediction_focus(row)
    return {
        "metric": metric,
        "label": metric_label(metric),
        "focus": focus,
        "key": str(row.get("key") or "host"),
        "score": score,
        "score_pct": int(round(score * 100)),
    }


def notify_pending_incidents(cur) -> None:
    if not NETGUARD_API_URL:
        return

    min_rank = alert_severity_rank(ALERT_NOTIFY_PENDING_MIN_SEVERITY)
    cur.execute(
        f"""
        select id, problem_type
        from incidents
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and coalesce(opening_notification_sent, notification_sent, false) = false
          and coalesce(updated_at, last_seen_at, opened_at, created_at) >= now() - (%s || ' hours')::interval
          and upper(coalesce(problem_type, '')) not like 'PREDICTION_%%'
          and (
            %s
            or (
              not {sql_persistent_loop_problem_filter()}
              and upper(coalesce(problem_type, '')) not like 'SYSLOG_INTERFACE_FLAP%%'
            )
          )
          and (
            coalesce(details->>'source', '') <> 'prediction_signal'
            or upper(coalesce(problem_type, '')) = 'PREDICTIVE_ANOMALY'
          )
          and {sql_alert_severity_rank()} >= %s
          and not exists (
            select 1
            from incident_notifications n
            where n.incident_id = incidents.id
              and n.sent_at >= now() - (%s || ' minutes')::interval
          )
        order by coalesce(updated_at, last_seen_at, opened_at, created_at) desc, id desc
        limit %s
        """,
        (
            max(1, ALERT_NOTIFY_PENDING_LOOKBACK_HOURS),
            SYSLOG_ALERT_LOOP_COMPONENTS_ENABLED,
            min_rank,
            max(1, ALERT_NOTIFY_RECENT_MINUTES),
            max(1, ALERT_NOTIFY_PENDING_LIMIT),
        ),
    )
    for row in cur.fetchall():
        notify_alert_service(row.get("id"))


def find_open_signal_incident_id(cur, device_ip: str, problem_type: str) -> int | None:
    cur.execute(
        """
        select id, problem_type
        from incidents
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and split_part(coalesce(device_ip::text, src_ip::text), '/', 1) = %s
          and upper(coalesce(problem_type, '')) = upper(%s)
        order by coalesce(last_detected_at, last_seen_at, updated_at, opened_at, created_at) desc, id desc
        limit 1
        """,
        (device_ip, problem_type),
    )
    row = cur.fetchone()
    if not row:
        return None
    return int(row.get("id"))


def to_utc_datetime(value):
    if not isinstance(value, datetime):
        return None
    resolved = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return resolved.astimezone(timezone.utc)


def incident_reference_at(row: dict):
    return (
        to_utc_datetime(row.get("first_detected_at"))
        or to_utc_datetime(row.get("opened_at"))
        or to_utc_datetime(row.get("created_at"))
    )


def sample_is_after_incident(sample_ts, row: dict) -> bool:
    sample_at = to_utc_datetime(sample_ts)
    if sample_at is None:
        return False
    opened_at = incident_reference_at(row)
    if opened_at is None:
        return True
    return sample_at > opened_at


def find_open_signal_incidents(cur, asset: dict, problem_types: set[str] | list[str] | tuple[str, ...]) -> list[dict]:
    normalized_types = [str(item or "").strip().upper() for item in problem_types if str(item or "").strip()]
    if not normalized_types:
        return []
    device_ip = ip_without_cidr(asset.get("ip"))
    cur.execute(
        """
        select id, opened_at, first_detected_at, created_at, problem_type, incident_type, details
        from incidents
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and (
            asset_id = %s
            or split_part(coalesce(device_ip::text, src_ip::text), '/', 1) = %s
          )
          and (
            upper(coalesce(problem_type, '')) = any(%s)
            or upper(coalesce(incident_type, '')) = any(%s)
          )
        order by coalesce(last_detected_at, last_seen_at, updated_at, opened_at, created_at) desc, id desc
        """,
        (int(asset.get("id")), device_ip, normalized_types, normalized_types),
    )
    return list(cur.fetchall() or [])


def record_recovery_evidence(
    cur,
    incident_id: int,
    *,
    telemetry_type: str,
    sample_ts,
    observed_value: str,
    reason: str,
    automatic: bool = True,
) -> None:
    details_patch = {
        "resolution_source": "automatic" if automatic else "manual",
        "resolved_by": "netguard-auto-resolver" if automatic else "operator",
        "recovery_telemetry_type": telemetry_type,
        "recovery_sample_at": alert_ts(sample_ts),
        "recovery_value": str(observed_value or "").strip() or "-",
        "recovery_evidence": str(reason or "").strip() or "Telemetria voltou ao estado normal.",
        "recovery_reason": str(reason or "").strip() or "Telemetria voltou ao estado normal.",
    }
    cur.execute(
        """
        update incidents
        set details = coalesce(details, '{}'::jsonb) || %s::jsonb,
            updated_at = now()
        where id = %s
        """,
        (json.dumps(details_patch, ensure_ascii=False), incident_id),
    )


def resolve_open_incidents_from_recovery(
    cur,
    asset: dict,
    problem_types: set[str] | list[str] | tuple[str, ...],
    *,
    telemetry_type: str,
    sample_ts,
    observed_value: str,
    reason: str,
    send_recovery_notification: bool = True,
) -> int:
    resolved = 0
    for row in find_open_signal_incidents(cur, asset, problem_types):
        if not sample_is_after_incident(sample_ts, row):
            continue
        incident_id = int(row.get("id"))
        record_recovery_evidence(
            cur,
            incident_id,
            telemetry_type=telemetry_type,
            sample_ts=sample_ts,
            observed_value=observed_value,
            reason=reason,
            automatic=True,
        )
        notify_recovery_service(incident_id, send_recovery_notification=send_recovery_notification)
        resolved += 1
    return resolved


def resolve_open_signal_incident(cur, device_ip: str, problem_type: str) -> bool:
    incident_id = find_open_signal_incident_id(cur, device_ip, problem_type)
    if not incident_id:
        return False
    notify_recovery_service(incident_id, send_recovery_notification=True)
    return True


def find_open_loop_risk_incident_id(cur, asset_id: int) -> int | None:
    cur.execute(
        """
        select id
        from incidents
        where asset_id = %s
          and lower(coalesce(status, '')) in ('open', 'acknowledged')
          and (
            lower(coalesce(incident_type, '')) = 'loop_risk'
            or upper(coalesce(problem_type, '')) = 'LOOP_RISK'
          )
        order by updated_at desc, id desc
        limit 1
        """,
        (asset_id,),
    )
    row = cur.fetchone()
    if not row:
        return None
    return int(row.get("id"))


def resolve_open_loop_risk_incident(cur, asset_id: int) -> bool:
    incident_id = find_open_loop_risk_incident_id(cur, asset_id)
    if not incident_id:
        return False
    notify_recovery_service(incident_id, send_recovery_notification=True)
    return True


def loop_recovery_value(row: dict, focus: str | None = None) -> str:
    text = f"{row.get('process') or ''} {row.get('message') or ''} {row.get('raw') or ''}".upper()
    focus_label = display_focus(focus)
    suffix = f" em {focus_label}" if focus_label and focus_label != "host" else ""
    if "LOOPGUARD" in text or "LOOP GUARD" in text:
        return f"Loop Guard bloqueou a condicao de loop{suffix}"
    if "SPANTREE" in text or "SPANNING TREE" in text or "STP" in text:
        return f"STP bloqueou a condicao de loop{suffix}"
    if "SEM LOOP" in text or "NO LOOP" in text:
        return "Sem loop detectado"
    return f"Sinal de recuperacao de loop{suffix}"


def resolve_open_loop_signal_incidents(cur, device_ip: str, recovery_value: str, evidence: str | None = None) -> None:
    if not device_ip:
        return

    details = {
        "recovery_value": recovery_value,
        "recovery_evidence": clamp_text(evidence or recovery_value),
        "recovery_source": "syslog_recovery_signal",
    }
    cur.execute(
        f"""
        update incidents
        set details = coalesce(details, '{{}}'::jsonb) || %s::jsonb,
            updated_at = now()
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and split_part(coalesce(device_ip::text, src_ip::text), '/', 1) = %s
          and {sql_persistent_loop_problem_filter()}
        returning id
        """,
        (json.dumps(details, ensure_ascii=False), device_ip),
    )
    for row in cur.fetchall():
        notify_recovery_service(row.get("id"), send_recovery_notification=True)


def record_loop_recovery_hint(cur, asset_id: int, recovery_value: str, evidence: str | None = None, sample_ts=None) -> None:
    details = {
        "last_recovery_hint": recovery_value,
        "last_recovery_hint_at": alert_ts(sample_ts),
        "last_recovery_hint_evidence": clamp_text(evidence or recovery_value),
        "recovery_hint_note": (
            "Sinal de contenção observado. O NetGuard só encerra loop_risk após ciclos limpos "
            "sem BROADCAST_STORM, MAC_FLAPPING, LOOP, LOOPGUARD, STORM_CONTROL ou STP crítico."
        ),
    }
    cur.execute(
        f"""
        update incidents
        set details = coalesce(details, '{{}}'::jsonb) || %s::jsonb,
            updated_at = now()
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and asset_id = %s
          and {sql_persistent_loop_problem_filter()}
        """,
        (json.dumps(details, ensure_ascii=False), int(asset_id)),
    )


def has_recent_loop_signals(cur, asset_id: int, since) -> bool:
    cur.execute(
        """
        select ts, severity, subsystem, iface, message, raw
        from syslog_events
        where asset_id = %s
          and ts > %s
        order by ts desc, id desc
        """,
        (int(asset_id), since),
    )
    stp_medium_count = 0
    flap_medium_count = 0
    for row in cur.fetchall():
        if detect_loop_recovery_signal(row.get("message"), row.get("raw")):
            continue
        signal = detect_loop_signal(row.get("message"), row.get("raw"))
        if not signal:
            continue
        focus, interfaces, interface_pair = resolve_event_focus(row)
        focus, interfaces, interface_pair = normalize_loop_event_focus(focus, interfaces, interface_pair)
        event = {
            "signal": signal,
            "focus": focus,
            "iface": focus,
            "interfaces": interfaces,
            "interface_pair": interface_pair,
            "severity": row.get("severity"),
            "subsystem": row.get("subsystem"),
            "message": row.get("message"),
            "raw": row.get("raw"),
        }
        strength = loop_event_strength(event)
        if strength == "strong":
            return True
        if signal == "STP_TOPOLOGY_CHANGE" and strength == "medium":
            stp_medium_count += 1
        elif signal == "INTERFACE_FLAP" and strength == "medium":
            flap_medium_count += 1
        if stp_medium_count >= LOOP_REPEATED_STP_EVENTS or flap_medium_count >= LOOP_REPEATED_FLAP_EVENTS:
            return True
    return False


def loop_clean_cycles_for_severity(severity: str | None) -> int:
    normalized = str(severity or "").strip().lower()
    if normalized in {"critical", "critica"}:
        return max(1, LOOP_RISK_CRITICAL_CLEAN_CYCLES)
    if normalized in {"high", "alta"}:
        return max(1, LOOP_RISK_HIGH_CLEAN_CYCLES)
    return max(1, min(LOOP_RISK_CLEAN_CYCLES, LOOP_RISK_HIGH_CLEAN_CYCLES))


def latest_loop_score(cur, asset_id: int) -> tuple[float | None, str | None]:
    cur.execute(
        """
        select score, ts
        from anomaly_scores
        where asset_id = %s
          and metric = 'loop_risk'
        order by ts desc, key desc
        limit 1
        """,
        (int(asset_id),),
    )
    row = cur.fetchone()
    if not row:
        return None, None
    try:
        score = float(row.get("score")) if row.get("score") is not None else None
    except (TypeError, ValueError):
        score = None
    return score, alert_ts(row.get("ts")) if row.get("ts") else None


def resolve_clean_loop_risk_incidents(cur) -> None:
    if not AUTO_RESOLVE_ALERTS_ENABLED or not NETGUARD_API_URL:
        return

    min_clean_cycles = min(
        max(1, LOOP_RISK_HIGH_CLEAN_CYCLES),
        max(1, LOOP_RISK_CRITICAL_CLEAN_CYCLES),
        max(1, LOOP_RISK_CLEAN_CYCLES),
    )
    min_clean_seconds = max(1, INTERVAL) * min_clean_cycles
    clean_cycles = min_clean_cycles
    clean_seconds = min_clean_seconds
    details = {
        "recovery_value": "Sem novas evidências fortes de loop após ciclos limpos",
        "recovery_evidence": (
            f"Nenhum novo BROADCAST_STORM, MAC_FLAPPING, LOOP, LOOPGUARD, STORM_CONTROL ou "
            f"STP crítico por pelo menos {clean_cycles} ciclo(s) limpo(s). Janela efetiva: {clean_seconds}s."
        ),
        "recovery_source": "loop_risk_clean_cycles",
        "clean_cycles": clean_cycles,
        "clean_window_seconds": clean_seconds,
    }
    cur.execute(
        f"""
        select
          id,
          asset_id,
          severity,
          details,
          coalesce(last_detected_at, last_seen_at, opened_at, created_at) as activity_at
        from incidents
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and (
            lower(coalesce(incident_type, '')) = 'loop_risk'
            or upper(coalesce(problem_type, '')) = 'LOOP_RISK'
          )
          and coalesce(last_detected_at, last_seen_at, opened_at, created_at)
              < now() - (%s || ' seconds')::interval
        order by activity_at asc, id asc
        limit %s
        """,
        (
            min_clean_seconds,
            max(1, AUTO_RESOLVE_MAX_PER_CYCLE * 2),
        ),
    )
    for row in cur.fetchall():
        asset_id = row.get("asset_id")
        if asset_id is None:
            continue
        details_current = row.get("details") if isinstance(row.get("details"), dict) else {}
        clean_cycles = loop_clean_cycles_for_severity(row.get("severity"))
        clean_seconds = max(1, INTERVAL) * clean_cycles
        now_utc = datetime.now(timezone.utc)
        activity_at = to_utc_datetime(row.get("activity_at")) or (now_utc - timedelta(seconds=clean_seconds))
        quiet_seconds = max(0, int((now_utc - activity_at).total_seconds()))
        if quiet_seconds < clean_seconds:
            continue
        since = activity_at
        if has_recent_loop_signals(cur, int(asset_id), since):
            continue

        score, score_at = latest_loop_score(cur, int(asset_id))
        contexts = details_current.get("affected_contexts") or []
        recovery_hint = str(details_current.get("last_recovery_hint") or "").strip()
        recovery_hint_at = str(details_current.get("last_recovery_hint_at") or "").strip()
        context_text = ", ".join(str(item) for item in contexts[:4]) if contexts else "host"
        score_text = "sem score recente" if score is None else f"score final {int(round(score * 100))}%"
        hint_text = f" Sinal de mitigacao: {recovery_hint}." if recovery_hint else ""
        details = {
            "recovery_value": "Loop mitigado sem novas evidencias fortes",
            "recovery_evidence": (
                f"Interfaces/contexto: {context_text}. "
                f"{quiet_seconds}s sem novos MACFLAP, STORM_CONTROL, broadcast storm, LOOP, LOOPGUARD ou BPDU Guard. "
                f"{score_text}. Ciclos limpos exigidos: {clean_cycles} ({clean_seconds}s).{hint_text}"
            ),
            "recovery_source": "loop_risk_clean_cycles",
            "clean_cycles": clean_cycles,
            "clean_window_seconds": clean_seconds,
            "quiet_seconds_without_strong_events": quiet_seconds,
            "recovery_sample_at": alert_ts(now_utc),
            "recovery_contexts": contexts[:6],
            "final_score": score,
            "final_score_at": score_at,
            "stp_status": recovery_hint if recovery_hint else None,
            "stp_status_at": recovery_hint_at if recovery_hint_at else None,
        }

        cur.execute(
            """
            update incidents
            set details = coalesce(details, '{}'::jsonb) || %s::jsonb,
                updated_at = now()
            where id = %s
            returning id
            """,
            (
                json.dumps(details, ensure_ascii=False),
                int(row["id"]),
            ),
        )
        resolved = cur.fetchone()
        if resolved:
            notify_recovery_service(resolved.get("id"), send_recovery_notification=True)


def resolve_stale_loop_risk_incidents(cur) -> None:
    if not AUTO_RESOLVE_ALERTS_ENABLED or not NETGUARD_API_URL:
        return
    if LOOP_RISK_STALE_RESOLVE_SEC <= 0:
        return

    activity_ts = sql_incident_activity_ts()
    stale_seconds = max(LOOP_WINDOW_SEC * 2, LOOP_RISK_STALE_RESOLVE_SEC)
    details = {
        "recovery_value": "Sem novas evidências de loop na janela configurada",
        "recovery_evidence": (
            f"Incidente de risco de loop sem atualização por mais de {stale_seconds}s; "
            f"a janela atual de correlação é de {LOOP_WINDOW_SEC}s."
        ),
        "recovery_source": "loop_risk_stale_timeout",
        "stale_after_seconds": stale_seconds,
    }
    cur.execute(
        f"""
        update incidents
        set details = coalesce(details, '{{}}'::jsonb) || %s::jsonb,
            updated_at = now()
        where id in (
            select id
            from incidents
            where lower(coalesce(status, '')) in ('open', 'acknowledged')
              and (
                lower(coalesce(incident_type, '')) = 'loop_risk'
                or upper(coalesce(problem_type, '')) = 'LOOP_RISK'
              )
              and {activity_ts} < now() - (%s || ' seconds')::interval
            order by {activity_ts} asc, id asc
            limit %s
        )
        returning id
        """,
        (
            json.dumps(details, ensure_ascii=False),
            stale_seconds,
            max(1, AUTO_RESOLVE_MAX_PER_CYCLE),
        ),
    )
    for row in cur.fetchall():
        notify_recovery_service(
            row.get("id"),
            send_recovery_notification=True,
        )


def resolve_stale_alert_incidents(cur) -> None:
    if not AUTO_RESOLVE_ALERTS_ENABLED or not NETGUARD_API_URL:
        return

    startup_floor = ENGINE_STARTED_AT - timedelta(minutes=max(0, AUTO_RESOLVE_STARTUP_GRACE_MINUTES))
    min_rank = alert_severity_rank(ALERT_NOTIFY_PENDING_MIN_SEVERITY)
    activity_ts = sql_incident_activity_ts()
    cur.execute(
        f"""
        select id, problem_type
        from incidents
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and {activity_ts}
              < now() - (%s || ' minutes')::interval
          and {activity_ts} >= %s
          and (
            coalesce(details->>'source', '') in ('syslog_signal', 'prediction_signal', 'anomaly_to_incident')
            or upper(coalesce(problem_type, '')) in ('LOOP_RISK', 'EARLY_WARNING', 'PREDICTIVE_ANOMALY')
            or upper(coalesce(problem_type, '')) like 'SYSLOG_%%'
          )
          and not {sql_persistent_loop_problem_filter()}
          and upper(coalesce(problem_type, '')) not like 'PREDICTION_%%'
          and {sql_alert_severity_rank()} >= %s
        order by {activity_ts} asc, id asc
        limit %s
        """,
        (
            max(1, AUTO_RESOLVE_AFTER_MINUTES),
            startup_floor,
            min_rank,
            max(1, AUTO_RESOLVE_MAX_PER_CYCLE),
        ),
    )
    for row in cur.fetchall():
        notify_recovery_service(row.get("id"), send_recovery_notification=True)


def resolve_stale_syslog_loop_component_incidents(cur) -> None:
    if not AUTO_RESOLVE_ALERTS_ENABLED or not NETGUARD_API_URL:
        return
    if SYSLOG_ALERT_LOOP_COMPONENTS_ENABLED:
        return

    activity_ts = sql_incident_activity_ts()
    details = {
        "recovery_value": "Componente syslog de loop consolidado no incidente principal",
        "recovery_evidence": (
            "Eventos SYSLOG_LOOP/SYSLOG_STP/SYSLOG_STORM sao tratados como evidencias do LOOP_RISK principal "
            "e sao encerrados sem notificacao de recuperacao individual para evitar spam."
        ),
        "recovery_source": "syslog_loop_component_silent_close",
    }
    cur.execute(
        f"""
        update incidents
        set details = coalesce(details, '{{}}'::jsonb) || %s::jsonb,
            updated_at = now()
        where id in (
            select id
            from incidents
            where lower(coalesce(status, '')) in ('open', 'acknowledged')
              and upper(coalesce(problem_type, '')) like 'SYSLOG_%%'
              and (
                {sql_persistent_loop_problem_filter()}
                or upper(coalesce(problem_type, '')) like 'SYSLOG_INTERFACE_FLAP%%'
              )
              and {activity_ts} < now() - (%s || ' minutes')::interval
            order by {activity_ts} asc, id asc
            limit %s
        )
        returning id
        """,
        (
            json.dumps(details, ensure_ascii=False),
            max(1, AUTO_RESOLVE_AFTER_MINUTES),
            max(1, AUTO_RESOLVE_MAX_PER_CYCLE),
        ),
    )
    for row in cur.fetchall():
        notify_recovery_service(row.get("id"), send_recovery_notification=True)


def resolve_legacy_stale_alert_incidents(cur) -> None:
    if not AUTO_RESOLVE_ALERTS_ENABLED or not NETGUARD_API_URL:
        return

    startup_floor = ENGINE_STARTED_AT - timedelta(minutes=max(0, AUTO_RESOLVE_STARTUP_GRACE_MINUTES))
    min_rank = alert_severity_rank(ALERT_NOTIFY_PENDING_MIN_SEVERITY)
    activity_ts = sql_incident_activity_ts()
    cur.execute(
        f"""
        select id, problem_type
        from incidents
        where lower(coalesce(status, '')) in ('open', 'acknowledged')
          and {activity_ts}
              < now() - (%s || ' minutes')::interval
          and {activity_ts} < %s
          and (
            coalesce(details->>'source', '') in ('syslog_signal', 'prediction_signal', 'anomaly_to_incident')
            or upper(coalesce(problem_type, '')) in ('LOOP_RISK', 'EARLY_WARNING', 'PREDICTIVE_ANOMALY')
            or upper(coalesce(problem_type, '')) like 'SYSLOG_%%'
          )
          and not {sql_persistent_loop_problem_filter()}
          and upper(coalesce(problem_type, '')) not like 'PREDICTION_%%'
          and {sql_alert_severity_rank()} >= %s
        order by {activity_ts} asc, id asc
        limit %s
        """,
        (
            max(1, AUTO_RESOLVE_AFTER_MINUTES),
            startup_floor,
            min_rank,
            max(1, AUTO_RESOLVE_MAX_PER_CYCLE),
        ),
    )
    for row in cur.fetchall():
        notify_recovery_service(row.get("id"), send_recovery_notification=True)


def notify_pending_recoveries(cur) -> None:
    if not ALERT_NOTIFY_RECOVERIES_ENABLED or not NETGUARD_API_URL:
        return

    startup_floor = ENGINE_STARTED_AT - timedelta(minutes=max(0, AUTO_RESOLVE_STARTUP_GRACE_MINUTES))
    min_rank = alert_severity_rank(ALERT_NOTIFY_PENDING_MIN_SEVERITY)
    cur.execute(
        f"""
        select id, problem_type
        from incidents
        where lower(coalesce(status, '')) = 'resolved'
          and resolved_at is not null
          and resolved_at >= now() - (%s || ' hours')::interval
          and resolved_at >= %s
          and coalesce(opening_notification_sent, notification_sent, false) = true
          and coalesce(recovery_notification_sent, false) = false
          and coalesce(details->>'recovery_notification_suppressed', '') <> 'true'
          and upper(coalesce(problem_type, '')) not like 'PREDICTION_%%'
          and {sql_alert_severity_rank()} >= %s
          and not exists (
            select 1
            from incident_notifications n
            where n.incident_id = incidents.id
              and n.sent_at >= incidents.resolved_at
              and lower(coalesce(n.delivery_status, '')) = 'success'
              and lower(coalesce(n.provider, '')) <> 'anti_spam'
          )
          and not exists (
            select 1
            from incident_notifications n
            where n.incident_id = incidents.id
              and n.sent_at >= incidents.resolved_at
              and n.sent_at >= now() - (%s || ' minutes')::interval
          )
        order by resolved_at desc, id desc
        limit %s
        """,
        (
            max(1, ALERT_NOTIFY_RECOVERY_LOOKBACK_HOURS),
            startup_floor,
            min_rank,
            max(1, ALERT_NOTIFY_RECENT_MINUTES),
            max(1, AUTO_RESOLVE_MAX_PER_CYCLE),
        ),
    )
    for row in cur.fetchall():
        notify_recovery_service(row.get("id"))


def normalize_iface_name(value: str | None) -> str | None:
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


def extract_iface_pair(*parts: str | None) -> dict | None:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        match = INTERFACE_PAIR_PATTERN.search(text) or INTERFACE_BETWEEN_PAIR_PATTERN.search(text)
        if not match:
            continue
        left = normalize_iface_name(match.group(1))
        right = normalize_iface_name(match.group(2))
        if left and right:
            return {
                "left": left,
                "right": right,
                "label": f"{left}<->{right}",
            }
    return None


def extract_ifaces(*parts: str | None) -> list[str]:
    seen = set()
    interfaces: list[str] = []
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        for token in INTERFACE_TOKEN_PATTERN.findall(text):
            normalized = normalize_iface_name(token)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            interfaces.append(normalized)
    return interfaces


def extract_loop_vlan(*parts: str | None) -> str | None:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        match = LOOP_VLAN_PATTERN.search(text)
        if not match:
            continue
        try:
            value = int(match.group(1))
        except (TypeError, ValueError):
            continue
        if value < 0:
            continue
        return f"VLAN{value:04d}"
    return None


def is_svi_interface(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith("vlan")


def is_physical_loop_interface(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith(("fa", "gi", "te", "eth"))


def is_loop_management_noise(message: str | None, raw: str | None) -> bool:
    text = f"{message or ''} {raw or ''}".upper()
    return (
        is_logginghost_event(message, raw)
        or "LOGGINGHOST_STARTSTOP" in text
        or "LOGGING HOST" in text
    )


def normalize_loop_event_focus(focus: str, interfaces: list[str], interface_pair: str | None) -> tuple[str, list[str], str | None]:
    physical_ifaces = [iface for iface in interfaces if is_physical_loop_interface(iface)]
    if interface_pair and all(is_physical_loop_interface(iface) for iface in extract_ifaces(interface_pair)):
        return interface_pair, physical_ifaces, interface_pair
    if is_svi_interface(focus):
        return "host", physical_ifaces, None
    if physical_ifaces and not is_physical_loop_interface(focus):
        return physical_ifaces[0], physical_ifaces, None
    if focus and focus != "host" and not is_physical_loop_interface(focus):
        return "host", physical_ifaces, None
    return focus or "host", physical_ifaces, interface_pair


def loop_event_text(event: dict) -> str:
    return f"{event.get('message') or ''} {event.get('raw') or ''}".upper()


def is_logginghost_event(message: str | None, raw: str | None) -> bool:
    text = f"{message or ''} {raw or ''}".upper()
    return "LOGGINGHOST_STARTSTOP" in text or "LOGGING HOST" in text


def is_link_up_only_event(message: str | None, raw: str | None) -> bool:
    text = f"{message or ''} {raw or ''}".upper()
    if "CHANGED STATE TO UP" in text or "WENT UP" in text or "LINK UP" in text:
        return True
    if "DOWN" in text or "ERR_DISABLE" in text or "ERR-DISABLE" in text:
        return False
    return any(
        token in text
        for token in (
            "LINE PROTOCOL ON INTERFACE",
            "LINKUP",
        )
    )


def physical_event_interfaces(event: dict) -> list[str]:
    interfaces = list(event.get("interfaces") or [])
    focus = str(event.get("focus") or "").strip()
    if focus and focus not in interfaces:
        interfaces.append(focus)
    return [iface for iface in interfaces if is_physical_loop_interface(iface)]


def loop_event_strength(event: dict) -> str:
    signal = str(event.get("signal") or "").upper()
    text = loop_event_text(event)
    physical_ifaces = physical_event_interfaces(event)

    if is_loop_management_noise(event.get("message"), event.get("raw")):
        return "weak"
    if signal in {"MAC_FLAPPING", "BROADCAST_STORM"}:
        return "strong"
    if any(token in text for token in ("MACFLAP", "MAC FLAP", "MAC FLAPPING", "BROADCAST STORM", "STORM_CONTROL", "STORM CONTROL", "STORMCTRL")):
        return "strong"
    if any(token in text for token in ("LOOPGUARD", "LOOP GUARD", "BPDU GUARD", "BPDUGUARD", "STP BLOCK", "PORT BLOCK", "LOOP DETECT")):
        return "strong"
    if (
        re.search(r"\bLOOP\b", text)
        and "LOOPBACK" not in text
        and (physical_ifaces or any(token in text for token in ("LOOPGUARD", "LOOP GUARD", "STORM", "MACFLAP", "BPDU")))
    ):
        return "strong"

    if signal == "STP_TOPOLOGY_CHANGE" and physical_ifaces:
        return "medium"
    if signal == "INTERFACE_FLAP" and physical_ifaces and not is_link_up_only_event(event.get("message"), event.get("raw")):
        return "medium"

    return "weak"


def evaluate_loop_risk_gate(events: list[dict], snmp_loop_state: dict[str, dict] | None = None) -> dict:
    strong_events = [event for event in events if loop_event_strength(event) == "strong"]
    medium_events = [event for event in events if loop_event_strength(event) == "medium"]
    weak_events = [event for event in events if loop_event_strength(event) == "weak"]

    physical_ifaces = sorted(
        {
            iface
            for event in events
            for iface in physical_event_interfaces(event)
        }
    )
    stp_medium_count = sum(1 for event in medium_events if str(event.get("signal") or "") == "STP_TOPOLOGY_CHANGE")
    flap_medium_count = sum(1 for event in medium_events if str(event.get("signal") or "") == "INTERFACE_FLAP")
    snmp_error_discard_count = 0
    for entry in (snmp_loop_state or {}).values():
        iface_name = str(entry.get("ifName") or "").strip()
        if iface_name and not is_physical_loop_interface(iface_name):
            continue
        if physical_ifaces and iface_name and iface_name not in physical_ifaces:
            continue
        metrics = entry.get("metrics") or {}
        for metric_name in (
            "snmp.if.in_errors",
            "snmp.if.out_errors",
            "snmp.if.in_discards",
            "snmp.if.out_discards",
        ):
            metric_row = metrics.get(metric_name) or {}
            if float(metric_row.get("value") or 0) > 0:
                snmp_error_discard_count += 1

    eligible = False
    reason = "Evidencias fracas ou informativas nao abrem LOOP_RISK."
    if strong_events:
        eligible = True
        reason = "Evidencia forte de loop L2 presente."
    elif stp_medium_count >= LOOP_REPEATED_STP_EVENTS:
        eligible = True
        reason = "Mudanca de topologia STP repetida na janela."
    elif stp_medium_count >= 2 and snmp_error_discard_count > 0:
        eligible = True
        reason = "STP repetido com erros ou descartes SNMP relacionados."
    elif flap_medium_count >= LOOP_REPEATED_FLAP_EVENTS and len(physical_ifaces) >= 2 and snmp_error_discard_count > 0:
        eligible = True
        reason = "Flap recorrente em portas fisicas com erros ou descartes SNMP."

    return {
        "eligible": eligible,
        "reason": reason,
        "strong_count": len(strong_events),
        "medium_count": len(medium_events),
        "weak_count": len(weak_events),
        "stp_medium_count": stp_medium_count,
        "flap_medium_count": flap_medium_count,
        "snmp_error_discard_count": snmp_error_discard_count,
        "physical_interfaces": physical_ifaces,
    }


def resolve_event_focus(row: dict) -> tuple[str, list[str], str | None]:
    pair = extract_iface_pair(row.get("iface"), row.get("message"), row.get("raw"))
    interfaces = extract_ifaces(row.get("iface"), row.get("message"), row.get("raw"))

    if pair:
        return pair["label"], [pair["left"], pair["right"]], pair["label"]

    normalized_iface = normalize_iface_name(row.get("iface"))
    if normalized_iface:
        return normalized_iface, [normalized_iface], None

    if len(interfaces) == 1:
        return interfaces[0], interfaces, None

    return "host", interfaces, None


def correlate_trap_focus(events: list[dict]) -> None:
    flap_candidates = [
        event for event in events
        if event.get("signal") == "INTERFACE_FLAP" and event.get("focus") not in ("", "host")
    ]
    for event in events:
        message = str(event.get("message") or "").upper()
        if event.get("signal") != "INTERFACE_FLAP" or "SNMP TRAP" not in message or event.get("focus") != "host":
            continue
        for candidate in flap_candidates:
            if abs((event["ts"] - candidate["ts"]).total_seconds()) <= 6:
                event["focus"] = candidate.get("focus") or "host"
                event["interfaces"] = list(candidate.get("interfaces") or [])
                event["interface_pair"] = candidate.get("interface_pair")
                event["evidence"] = f"{event['signal']}:{event['focus']}"
                break


def build_signal_contexts(events: list[dict]) -> list[dict]:
    buckets: dict[tuple[str, str, str], dict] = {}
    for event in events:
        signal = str(event.get("signal") or "")
        focus = str(event.get("focus") or "host")
        if is_svi_interface(focus):
            focus = "host"
        vlan = str(event.get("vlan") or "").strip()
        vlan_key = vlan or "no_vlan"
        bucket = buckets.get((signal, focus, vlan_key))
        if bucket is None:
            bucket = {
                "signal": signal,
                "label": SIGNAL_LABELS.get(signal, signal.replace("_", " ").title()),
                "focus": focus,
                "interfaces": [],
                "vlans": [],
                "count": 0,
                "first_seen_at": event.get("ts").isoformat() if event.get("ts") else None,
                "last_seen_at": event.get("ts").isoformat() if event.get("ts") else None,
            }
            buckets[(signal, focus, vlan_key)] = bucket

        bucket["count"] += 1
        for iface in event.get("interfaces") or []:
            if not is_physical_loop_interface(iface):
                continue
            if iface not in bucket["interfaces"]:
                bucket["interfaces"].append(iface)
        if vlan and vlan not in bucket["vlans"]:
            bucket["vlans"].append(vlan)
        if event.get("ts") and bucket.get("last_seen_at") and event["ts"].isoformat() > bucket["last_seen_at"]:
            bucket["last_seen_at"] = event["ts"].isoformat()
        if event.get("ts") and bucket.get("first_seen_at") and event["ts"].isoformat() < bucket["first_seen_at"]:
            bucket["first_seen_at"] = event["ts"].isoformat()

    items = list(buckets.values())
    items.sort(
        key=lambda item: (
            SIGNAL_CONTEXT_PRIORITY.get(str(item.get("signal") or ""), 9),
            -int(item.get("count") or 0),
            str(item.get("focus") or ""),
        )
    )
    return items


def dedupe_preserve_order(values: list[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def build_evidences(events: list[dict], snmp_hints: list[dict], snmp_loop_evidence: list[str] | None = None) -> list[str]:
    evidence_counts: dict[str, int] = {}

    for event in events:
        if loop_event_strength(event) == "weak":
            continue
        focus = str(event.get("focus") or "").strip()
        if is_svi_interface(focus):
            continue
        evidence = str(event.get("evidence") or "").strip()
        if not evidence:
            continue
        evidence_counts[evidence] = evidence_counts.get(evidence, 0) + 1

    ordered = sorted(
        evidence_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )
    evidences = [
        f"{name} x{count}" if count > 1 else name
        for name, count in ordered
    ]

    for hint in snmp_hints[:4]:
        key = str(hint.get("key") or "").strip()
        metric = str(hint.get("metric") or "").strip()
        if not key or not metric:
            continue
        evidences.append(f"SNMP_DEGRADATION:{key}:{metric}")

    for item in snmp_loop_evidence or []:
        text = str(item or "").strip()
        if text:
            evidences.append(text)

    return dedupe_preserve_order(evidences)[:5]


def build_affected_contexts(signal_contexts: list[dict]) -> list[str]:
    contexts: list[str] = []
    seen = set()
    for item in signal_contexts:
        focus = str(item.get("focus") or "").strip()
        if not focus or focus == "host" or focus in seen:
            continue
        if is_svi_interface(focus):
            continue
        if "<->" not in focus and not is_physical_loop_interface(focus):
            continue
        seen.add(focus)
        contexts.append(focus)
    return contexts


def stable_loop_context_key(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return "host"

    pair = extract_iface_pair(text)
    if pair:
        left = safe_loop_context_key(pair["left"])
        right = safe_loop_context_key(pair["right"])
        ordered = sorted([left, right])
        return f"pair_{ordered[0]}_{ordered[1]}"

    ifaces = extract_ifaces(text)
    if len(ifaces) >= 2 and ("<->" in text or " between " in text.lower() or " entre " in text.lower()):
        ordered = sorted(safe_loop_context_key(iface) for iface in ifaces[:2])
        return f"pair_{ordered[0]}_{ordered[1]}"

    return safe_loop_context_key(text)


def build_loop_fingerprint(asset_id: int, signal_contexts: list[dict], fallback_key: str = "host") -> tuple[str, list[str]]:
    fallback_context = stable_loop_context_key(fallback_key)
    contexts = build_affected_contexts(signal_contexts)
    if not contexts:
        contexts = [fallback_key or "host"]
    elif fallback_context != "host" and fallback_key:
        contexts = [fallback_key] + [context for context in contexts if context != fallback_key]

    normalized_contexts = sorted(
        {
            stable_loop_context_key(context)
            for context in contexts
            if str(context or "").strip()
        }
    )
    vlan_contexts = sorted(
        {
            stable_loop_context_key(vlan)
            for item in signal_contexts
            for vlan in (item.get("vlans") or [])
            if str(vlan or "").strip()
        }
    )
    for vlan_context in vlan_contexts:
        if vlan_context not in normalized_contexts:
            normalized_contexts.append(vlan_context)
    if not normalized_contexts:
        normalized_contexts = ["host"]

    context_key = "+".join(normalized_contexts[:6])
    fingerprint = f"loop_risk:{int(asset_id)}:{context_key}"
    return fingerprint, normalized_contexts


def consolidate_duplicate_loop_incidents(cur, canonical_id: int | None, asset_id: int, key: str, affected_contexts: list[str], detected_at) -> None:
    if not canonical_id:
        return

    match_contexts = sorted(
        {
            stable_loop_context_key(context)
            for context in affected_contexts
            if str(context or "").strip()
        }
    )
    raw_contexts = sorted(
        {
            str(context or "").strip().lower()
            for context in affected_contexts
            if str(context or "").strip()
        }
    )
    context_json = json.dumps(match_contexts)
    raw_context_json = json.dumps(raw_contexts)
    details = {
        "deduplicated_into_incident_id": int(canonical_id),
        "deduplication_source": "loop_fingerprint_consolidation",
        "deduplication_reason": "Incidente de loop duplicado para o mesmo host/contexto operacional.",
    }
    cur.execute(
        """
        update incidents i
        set status = 'resolved',
            resolved_at = coalesce(i.resolved_at, %s),
            updated_at = %s,
            details = coalesce(i.details, '{}'::jsonb) || %s::jsonb
        where i.id <> %s
          and lower(coalesce(i.status, '')) in ('open', 'acknowledged')
          and i.asset_id = %s
          and (
            lower(coalesce(i.incident_type, '')) = 'loop_risk'
            or upper(coalesce(i.problem_type, '')) = 'LOOP_RISK'
          )
          and (
            i.key = %s
            or coalesce(i.details->>'loop_fingerprint', '') = %s
            or exists (
              select 1
              from jsonb_array_elements_text(coalesce(i.details->'affected_contexts', '[]'::jsonb)) existing_context
              join jsonb_array_elements_text(%s::jsonb) current_context
                on lower(existing_context.value) = current_context.value
            )
            or exists (
              select 1
              from jsonb_array_elements_text(coalesce(i.details->'affected_contexts', '[]'::jsonb)) existing_context
              join jsonb_array_elements_text(%s::jsonb) current_context
                on regexp_replace(lower(existing_context.value), '[^a-zA-Z0-9_.:-]+', '_', 'g') = current_context.value
            )
          )
        returning i.id
        """,
        (
            detected_at,
            detected_at,
            json.dumps(details, ensure_ascii=False),
            int(canonical_id),
            int(asset_id),
            key,
            key,
            raw_context_json,
            context_json,
        ),
    )
    rows = cur.fetchall()
    if rows:
        ids = ", ".join(str(row.get("id")) for row in rows)
        print(f"[LOOP] incidentes duplicados consolidados no incidente {canonical_id}: {ids}", flush=True)
        for row in rows:
            notify_recovery_service(row.get("id"), send_recovery_notification=True)


def build_opening_reason(signal_contexts: list[dict], window_sec: int) -> str:
    if not signal_contexts:
        return (
            f"Correlacao temporal de sinais de rede na janela de {window_sec}s indicou risco de loop L2."
        )

    by_signal: dict[str, dict] = {}
    for item in signal_contexts:
        signal = str(item.get("signal") or "")
        if signal and signal not in by_signal:
            by_signal[signal] = item
    loop_context = by_signal.get("BROADCAST_STORM")
    mac_context = by_signal.get("MAC_FLAPPING")
    flap_context = by_signal.get("INTERFACE_FLAP")
    vlan_context = next((item for item in signal_contexts if item.get("vlans")), None)
    vlan_label = str((vlan_context or {}).get("vlans", [None])[0] or "").strip()

    parts: list[str] = []
    if loop_context and mac_context and "<->" in str(mac_context.get("focus") or ""):
        parts.append(
            f"Broadcast storm com MAC flapping entre {display_focus(mac_context['focus'])}"
        )
    elif loop_context and mac_context and loop_context.get("focus") == mac_context.get("focus"):
        parts.append(
            f"Correlacao entre storm e MAC flapping em {loop_context['focus']}"
        )
    elif loop_context:
        parts.append(f"Broadcast storm em {loop_context['focus']}")
    elif mac_context:
        parts.append(f"MAC flapping em {mac_context['focus']}")

    if flap_context and flap_context.get("focus") != (loop_context or {}).get("focus"):
        parts.append(f"flap recorrente adicional em {flap_context['focus']}")

    if not parts and flap_context:
        parts.append(f"flap recorrente de interface em {flap_context['focus']}")

    if vlan_label:
        parts.append(vlan_label)

    if not parts:
        return f"Correlacao temporal de sinais de rede na janela de {window_sec}s indicou risco de loop L2."

    return f"{'; '.join(parts)} na janela temporal de {window_sec}s, compativel com risco de loop L2."


def get_ifname(cur, asset_id: int, ifindex: str) -> str | None:
    cur.execute(
        """
        select labels->>'ifName' as ifname
        from metrics
        where asset_id = %s
          and metric like %s
          and labels ? 'ifName'
        order by ts desc
        limit 1
        """,
        (asset_id, f"snmp.if.%|ifIndex={ifindex}"),
    )
    row = cur.fetchone()
    return row["ifname"] if row and row.get("ifname") else None


def upsert_incident(cur, asset_id, hostname, src_ip, metric, key, hits, zmax, ifname, group_name=None):
    inc_key = f"{asset_id}|{metric}|{key}|degradation"
    nice_iface = f"{key} ({ifname})" if ifname else key
    title = f"Early warning: degradacao provavel em {hostname} {nice_iface}"

    details = {
        "metric": metric,
        "key": key,
        "ifName": ifname,
        "group_name": group_name,
        "hits": int(hits),
        "z_max": float(zmax),
        "source": "anomaly_to_incident",
        "problem_name": f"Degradacao provavel em {hostname}",
        "summary": f"{hits} leituras recentes de {metric} ficaram fora do padrao em {nice_iface}.",
        "item": nice_iface,
        "value": f"z-score maximo {float(zmax):.2f}",
        "impact": "Pode indicar erro fisico, descarte por fila, saturacao ou negociacao incorreta na interface.",
        "action": "Cheque cabo/SFP, speed/duplex, contadores de erro/descarte e saturacao da interface.",
        "evidence_summary": f"{metric} em {nice_iface}; {hits} ocorrencias; z-score maximo {float(zmax):.2f}",
        "window_min": int(WINDOW_MIN),
        "recommendation": (
            "Degradacao detectada por aumento de errors/discards. "
            "Checar cabo/SFP, duplex/speed, CRC, fila/queue, loop L2 e saturacao."
        ),
    }

    cur.execute(
        """
        insert into incidents (
          opened_at, last_seen_at, asset_id, hostname, src_ip, incident_type,
          key, severity, title, details, device_name, device_ip, problem_type,
          description, first_detected_at, last_detected_at, notification_sent,
          created_at, updated_at
        )
        values (
          now(), now(), %s, %s, %s, 'early_warning', %s, 'warning', %s,
          %s::jsonb, %s, %s, 'EARLY_WARNING', %s, now(), now(), false, now(), now()
        )
        on conflict (key) where status='open'
        do update set
          last_seen_at = now(),
          last_detected_at = now(),
          updated_at = now(),
          asset_id = excluded.asset_id,
          device_name = excluded.device_name,
          device_ip = excluded.device_ip,
          problem_type = excluded.problem_type,
          description = excluded.description,
          severity = excluded.severity,
          title = excluded.title,
          first_detected_at = coalesce(incidents.first_detected_at, excluded.first_detected_at),
          details = incidents.details || excluded.details
        returning id
        """,
        (
            asset_id,
            hostname,
            src_ip,
            inc_key,
            title,
            json.dumps(details),
            hostname,
            src_ip,
            title,
        ),
    )
    row = cur.fetchone()
    return int(row["id"]) if row and row.get("id") is not None else None


def process_degradation_incidents(cur):
    since = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MIN)

    cur.execute(
        """
        select s.asset_id, a.name as hostname, a.ip as src_ip,
               coalesce(g.path, g.name) as group_name,
               s.metric, s.key, count(*) as hits, max(abs(s.z)) as zmax
        from anomaly_scores s
        join assets a on a.id = s.asset_id
        left join host_groups g on g.id = a.group_id
        where s.ts > %s
          and s.metric = any(%s)
          and abs(s.z) >= %s
        group by s.asset_id, a.name, a.ip, coalesce(g.path, g.name), s.metric, s.key
        having count(*) >= %s
        order by zmax desc
        """,
        (since, list(ALLOWED_METRICS), MIN_Z, MIN_HITS),
    )
    rows = cur.fetchall()

    for row in rows:
        key = row["key"]
        ifindex = key.split("=")[-1] if "=" in key else None
        ifname = get_ifname(cur, row["asset_id"], ifindex) if ifindex else None

        incident_id = upsert_incident(
            cur,
            row["asset_id"],
            row["hostname"],
            row["src_ip"],
            row["metric"],
            row["key"],
            row["hits"],
            float(row["zmax"]),
            ifname,
            row.get("group_name"),
        )
        if should_notify_incident(cur, incident_id):
            notify_alert_service(incident_id)


def normalize_loop_text(message: str | None, raw: str | None) -> tuple[str, str]:
    raw_upper = f"{message or ''} {raw or ''}".upper()
    normalized = NORMALIZE_PATTERN_RE.sub(" ", raw_upper).strip()
    return raw_upper, f" {normalized} "


def detect_loop_signal(message: str | None, raw: str | None) -> str | None:
    raw_upper, normalized = normalize_loop_text(message, raw)
    if is_logginghost_event(message, raw):
        return None
    if detect_loop_recovery_signal(message, raw):
        return None

    signal_order = ("MAC_FLAPPING", "BROADCAST_STORM", "STP_TOPOLOGY_CHANGE", "INTERFACE_FLAP")
    for signal in signal_order:
        patterns = LOOP_SIGNAL_PATTERNS.get(signal, [])
        for pattern in patterns:
            raw_pattern = pattern.upper()
            normalized_pattern = f" {NORMALIZE_PATTERN_RE.sub(' ', raw_pattern).strip()} "
            if raw_pattern in raw_upper or normalized_pattern in normalized:
                if signal == "INTERFACE_FLAP":
                    interfaces = extract_ifaces(message, raw)
                    if is_link_up_only_event(message, raw):
                        return None
                    if interfaces and not any(is_physical_loop_interface(iface) for iface in interfaces):
                        return None
                return signal

    return None


def detect_loop_recovery_signal(message: str | None, raw: str | None) -> bool:
    raw_upper, normalized = normalize_loop_text(message, raw)
    has_recovery = False
    for pattern in LOOP_RECOVERY_PATTERNS:
        raw_pattern = pattern.upper()
        normalized_pattern = f" {NORMALIZE_PATTERN_RE.sub(' ', raw_pattern).strip()} "
        if raw_pattern in raw_upper or normalized_pattern in normalized:
            has_recovery = True
            break
    if not has_recovery:
        return False

    for pattern in LOOP_RECOVERY_CONTEXT_PATTERNS:
        raw_pattern = pattern.upper()
        normalized_pattern = f" {NORMALIZE_PATTERN_RE.sub(' ', raw_pattern).strip()} "
        if raw_pattern in raw_upper or normalized_pattern in normalized:
            return True
    return False


def metric_ifindex(metric: str | None, labels: dict | None = None) -> str | None:
    text = str(metric or "").strip()
    if not text:
        return None
    match = re.search(r"ifIndex=(\d+)", text)
    if match:
        return match.group(1)
    if isinstance(labels, dict):
        label_value = labels.get("ifIndex")
        if label_value is not None:
            label_text = str(label_value).strip()
            if label_text:
                return label_text
    return None


def metric_base_name(metric: str | None) -> str:
    text = str(metric or "").strip()
    if not text:
        return ""
    return text.split("|", 1)[0]


def loop_metric_label(metric: str | None) -> str:
    base = metric_base_name(metric)
    return METRIC_LABELS.get(base, metric_label(base))


def interpret_interface_metric_value(metric: str | None, value: float | int | None) -> str:
    base = metric_base_name(metric)
    if base == "snmp.if.oper_status":
        return "up(1)" if int(float(value or 0)) == 1 else "down"
    if base == "snmp.if.admin_status":
        return "up(1)" if int(float(value or 0)) == 1 else "down"
    if base.endswith(".delta"):
        return f"{float(value or 0):g}"
    return f"{float(value or 0):g}"


def load_recent_loop_snmp_state(cur, asset_id: int, since: datetime) -> dict[str, dict]:
    cur.execute(
        """
        select distinct on (metric)
               metric, ts, value, labels
        from metrics
        where asset_id = %s
          and ts > %s
          and (
            metric like 'snmp.if.oper_status|ifIndex=%%'
            or metric like 'snmp.if.admin_status|ifIndex=%%'
            or metric like 'snmp.if.in_errors|ifIndex=%%'
            or metric like 'snmp.if.out_errors|ifIndex=%%'
            or metric like 'snmp.if.in_discards|ifIndex=%%'
            or metric like 'snmp.if.out_discards|ifIndex=%%'
            or metric like 'snmp.if.in_octets|ifIndex=%%'
            or metric like 'snmp.if.out_octets|ifIndex=%%'
        )
        order by metric, ts desc
        """,
        (asset_id, since),
    )
    state: dict[str, dict] = {}
    for row in cur.fetchall():
        labels = parse_json_object(row.get("labels"))
        ifindex = metric_ifindex(row.get("metric"), labels)
        if not ifindex:
            continue
        metric = metric_base_name(row.get("metric"))
        try:
            value = float(row.get("value"))
        except (TypeError, ValueError):
            continue
        bucket = state.setdefault(
            str(ifindex),
            {
                "ifIndex": str(ifindex),
                "ifName": str(labels.get("ifName") or labels.get("ifDescr") or "").strip() or None,
                "last_seen_at": row.get("ts"),
                "metrics": {},
            },
        )
        if row.get("ts") and bucket.get("last_seen_at") and row["ts"] > bucket["last_seen_at"]:
            bucket["last_seen_at"] = row["ts"]
        if not bucket.get("ifName"):
            bucket["ifName"] = str(labels.get("ifName") or labels.get("ifDescr") or "").strip() or None
        bucket["metrics"][metric] = {
            "value": value,
            "ts": row.get("ts"),
        }
    return state


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
    normalized_tags = normalize_asset_tags(tags)
    values = []
    for key in keys:
        raw = normalized_tags.get(key)
        if raw is None:
            continue
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(item).strip() for item in raw if str(item).strip())
        else:
            text = str(raw).strip()
            if text:
                values.append(text)
    return values


def safe_loop_context_key(value):
    normalized = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", str(value or "host").strip().lower()).strip("_")
    return normalized or "host"


def load_asset_maps(cur):
    cur.execute(
        """
        select a.id, a.name, a.ip, coalesce(a.tags, '{}'::jsonb) as tags, coalesce(g.path, g.name) as group_name
        from assets a
        left join host_groups g on g.id = a.group_id
        where a.enabled = true
        """
    )
    rows = cur.fetchall()

    by_id = {}
    by_ip = {}
    by_name = {}
    for row in rows:
        asset = {
            "asset_id": int(row["id"]),
            "name": row["name"],
            "ip": str(row["ip"]),
            "group_name": row.get("group_name"),
        }
        by_id[asset["asset_id"]] = asset
        by_ip[asset["ip"]] = asset
        by_name[str(asset["name"]).lower()] = asset
        for alias_ip in tag_values(row.get("tags"), ASSET_SYSLOG_SRC_IP_ALIAS_KEYS):
            by_ip[alias_ip] = asset
        for alias_hostname in tag_values(row.get("tags"), ASSET_SYSLOG_HOST_ALIAS_KEYS):
            by_name[alias_hostname.lower()] = asset

    return by_id, by_ip, by_name


def load_recent_snmp_hints(cur, since):
    cur.execute(
        """
        select asset_id, key, metric, count(*) as hits, max(abs(z)) as zmax
        from anomaly_scores
        where ts > %s
          and metric = any(%s)
          and abs(z) >= %s
        group by asset_id, key, metric
        order by max(abs(z)) desc, count(*) desc
        """,
        (since, list(ALLOWED_METRICS), MIN_Z),
    )
    rows = cur.fetchall()

    hints_by_asset = {}
    for row in rows:
        hints_by_asset.setdefault(int(row["asset_id"]), []).append(
            {
                "key": row["key"],
                "metric": row["metric"],
                "hits": int(row["hits"]),
                "zmax": float(row["zmax"] or 0.0),
            }
        )

    return hints_by_asset


def process_recurrent_interface_flap_alerts(cur) -> None:
    if not SYSLOG_ALERT_INTERFACE_FLAP_ENABLED or not NETGUARD_API_URL:
        return

    min_events = max(2, SYSLOG_ALERT_INTERFACE_FLAP_MIN_EVENTS)
    window_sec = max(10, SYSLOG_ALERT_INTERFACE_FLAP_WINDOW_SEC)
    min_rank = syslog_severity_rank(SYSLOG_ALERT_INTERFACE_FLAP_MIN_SEVERITY)
    cur.execute(
        """
        select
          s.id,
          s.ts,
          s.asset_id,
          coalesce(a.name, nullif(s.hostname, ''), 'unknown') as hostname,
          split_part(coalesce(a.ip::text, s.src_ip::text), '/', 1) as src_ip,
          s.process,
          s.event_id,
          s.severity,
          s.subsystem,
          s.iface,
          s.message,
          s.raw,
          coalesce(g.path, g.name) as group_name
        from syslog_events s
        left join assets a on a.id = s.asset_id
        left join host_groups g on g.id = a.group_id
        where s.ts >= now() - (%s || ' seconds')::interval
        order by s.ts desc, s.id desc
        limit %s
        """,
        (
            window_sec,
            max(SIGNAL_ALERT_LIMIT * 4, min_events * 8),
        ),
    )

    groups: dict[str, dict] = {}
    for row in cur.fetchall():
        if syslog_severity_rank(row.get("severity")) < min_rank:
            continue
        if detect_loop_signal(row.get("message"), row.get("raw")) != "INTERFACE_FLAP":
            continue

        device_ip = str(row.get("src_ip") or "").strip()
        if not device_ip:
            continue

        focus, interfaces, interface_pair = resolve_event_focus(row)
        problem_type = safe_problem_type("SYSLOG", "INTERFACE_FLAP", focus)
        group_key = f"{device_ip}:{problem_type}"
        group = groups.setdefault(
            group_key,
            {
                "device_ip": device_ip,
                "hostname": str(row.get("hostname") or "unknown"),
                "group_name": row.get("group_name") or "Sem grupo",
                "focus": focus,
                "problem_type": problem_type,
                "interfaces": [],
                "interface_pair": interface_pair,
                "first_ts": row.get("ts"),
                "last_ts": row.get("ts"),
                "count": 0,
                "up_count": 0,
                "down_count": 0,
                "unknown_count": 0,
                "samples": [],
            },
        )

        group["count"] += 1
        state = event_oper_state(row.get("message"))
        if state == "up":
            group["up_count"] += 1
        elif state == "down":
            group["down_count"] += 1
        else:
            group["unknown_count"] += 1

        for iface in interfaces:
            if iface not in group["interfaces"]:
                group["interfaces"].append(iface)

        ts = row.get("ts")
        if ts and (not group.get("first_ts") or ts < group["first_ts"]):
            group["first_ts"] = ts
        if ts and (not group.get("last_ts") or ts > group["last_ts"]):
            group["last_ts"] = ts

        if len(group["samples"]) < 5:
            group["samples"].append(clamp_text(row.get("message") or row.get("raw") or "interface flap", 180))

    for group in groups.values():
        count = int(group["count"])
        if count < min_events:
            continue

        focus_label = display_focus(group.get("focus"))
        problem_name = f"Flap recorrente de interface em {focus_label}"
        description = (
            f"{count} eventos de up/down em {focus_label} nos ultimos {window_sec}s "
            f"({group['down_count']} down, {group['up_count']} up)."
        )
        severity = "HIGH" if count >= max(min_events * 2, 8) else "MEDIUM"

        post_alert_problem(
            {
                "device_name": group["hostname"],
                "device_ip": group["device_ip"],
                "problem_type": group["problem_type"],
                "description": description,
                "severity": severity,
                "detected_at": alert_ts(group.get("last_ts")),
                "details": {
                    "source": "syslog_signal",
                    "problem_name": problem_name,
                    "summary": description,
                    "trigger": "Flap recorrente de interface",
                    "item": focus_label,
                    "group_name": group["group_name"],
                    "value": f"{count} eventos em {window_sec}s",
                    "impact": SIGNAL_IMPACTS["INTERFACE_FLAP"],
                    "action": SIGNAL_ACTIONS["INTERFACE_FLAP"],
                    "evidence_summary": "; ".join(group["samples"]),
                    "affected_context": focus_label,
                    "interfaces": group["interfaces"],
                    "interface_pair": group.get("interface_pair"),
                    "flap_count": count,
                    "up_count": group["up_count"],
                    "down_count": group["down_count"],
                    "window_sec": window_sec,
                },
            }
        )


def process_syslog_signal_alerts(cur) -> None:
    if not SYSLOG_ALERTS_ENABLED or not NETGUARD_API_URL:
        return

    process_recurrent_interface_flap_alerts(cur)

    min_rank = syslog_severity_rank(SYSLOG_ALERT_MIN_SEVERITY)
    cur.execute(
        """
        select
          s.id,
          s.ts,
          s.asset_id,
          coalesce(a.name, nullif(s.hostname, ''), 'unknown') as hostname,
          split_part(coalesce(a.ip::text, s.src_ip::text), '/', 1) as src_ip,
          s.process,
          s.event_id,
          s.severity,
          s.subsystem,
          s.iface,
          s.message,
          s.raw,
          coalesce(g.path, g.name) as group_name
        from syslog_events s
        left join assets a on a.id = s.asset_id
        left join host_groups g on g.id = a.group_id
        where s.ts >= now() - (%s || ' seconds')::interval
        order by s.ts desc, s.id desc
        limit %s
        """,
        (
            max(10, SIGNAL_ALERT_LOOKBACK_SEC),
            max(1, SIGNAL_ALERT_LIMIT),
        ),
    )

    for row in cur.fetchall():
        if syslog_severity_rank(row.get("severity")) < min_rank:
            continue

        device_ip = str(row.get("src_ip") or "").strip()
        if not device_ip:
            continue

        focus, interfaces, interface_pair = resolve_event_focus(row)
        if detect_loop_recovery_signal(row.get("message"), row.get("raw")):
            evidence = clamp_text(row.get("raw") or row.get("message") or "")
            if row.get("asset_id") is not None:
                record_loop_recovery_hint(
                    cur,
                    int(row.get("asset_id")),
                    loop_recovery_value(row, focus),
                    evidence,
                    row.get("ts"),
                )
            continue

        signal = detect_loop_signal(row.get("message"), row.get("raw"))
        signal_key = signal or str(row.get("subsystem") or row.get("process") or "syslog")
        signal_label = SIGNAL_LABELS.get(signal_key, str(signal_key).replace("_", " ").strip().title() or "Syslog")
        problem_type = safe_problem_type("SYSLOG", signal_key, focus)
        if is_persistent_loop_problem_type(problem_type) and not SYSLOG_ALERT_LOOP_COMPONENTS_ENABLED:
            continue
        if str(signal_key).upper() == "INTERFACE_FLAP":
            # Interface flap is handled in an aggregated pass above. Resolving on
            # every "up" event hides real flapping because up/down can alternate
            # many times inside the same collection window.
            continue
        if str(signal_key).upper() in LOOP_SIGNAL_WEIGHTS and not SYSLOG_ALERT_LOOP_COMPONENTS_ENABLED:
            continue

        message = clamp_text(row.get("message") or signal_label, 260)
        raw_message = clamp_text(row.get("raw") or row.get("message") or message)
        item = focus if focus and focus != "host" else str(row.get("subsystem") or signal_key)
        problem_name = signal_problem_name(signal_key, focus, message)

        cache_key = f"syslog:{device_ip}:{problem_type}"
        if not should_emit_signal_alert(cache_key):
            continue

        post_alert_problem(
            {
                "device_name": str(row.get("hostname") or "unknown"),
                "device_ip": device_ip,
                "problem_type": problem_type,
                "description": problem_name,
                "severity": syslog_alert_severity(row.get("severity")),
                "detected_at": alert_ts(row.get("ts")),
                "details": {
                    "source": "syslog_signal",
                    "problem_name": problem_name,
                    "summary": f"{signal_label} recebido pelo syslog. Mensagem original: {message}",
                    "trigger": signal_label,
                    "item": item,
                    "group_name": row.get("group_name") or "Sem grupo",
                    "value": event_value_hint(row.get("message") or raw_message),
                    "impact": SIGNAL_IMPACTS.get(str(signal_key).upper(), "Evento de syslog relevante para investigacao."),
                    "action": SIGNAL_ACTIONS.get(str(signal_key).upper(), "Verifique o host no NetGuard e correlacione com eventos recentes."),
                    "evidence_summary": raw_message,
                    "affected_context": display_focus(focus),
                    "subsystem": row.get("subsystem"),
                    "iface": row.get("iface"),
                    "interfaces": interfaces,
                    "interface_pair": interface_pair,
                    "event_id": row.get("event_id"),
                    "process": row.get("process"),
                    "raw": raw_message,
                },
            }
        )


def process_prediction_signal_alerts(cur) -> None:
    if not PREDICTION_ALERTS_ENABLED or not NETGUARD_API_URL:
        return

    cur.execute(
        """
        select
          s.ts,
          s.asset_id,
          a.name as hostname,
          split_part(a.ip::text, '/', 1) as src_ip,
          coalesce(g.path, g.name) as group_name,
          s.metric,
          s.key,
          s.score,
          s.z,
          s.value,
          s.details
        from anomaly_scores s
        join assets a on a.id = s.asset_id
        left join host_groups g on g.id = a.group_id
        where s.ts >= now() - (%s || ' seconds')::interval
          and coalesce(s.score, 0) >= %s
        order by s.ts desc, s.score desc
        limit %s
        """,
        (
            max(10, SIGNAL_ALERT_LOOKBACK_SEC),
            max(0.0, PREDICTION_ALERT_MIN_SCORE),
            max(1, SIGNAL_ALERT_LIMIT),
        ),
    )

    grouped: dict[int, list[dict]] = {}
    for row in cur.fetchall():
        metric = str(row.get("metric") or "prediction")
        if metric == "loop_risk":
            continue
        grouped.setdefault(int(row.get("asset_id")), []).append(row)

    for asset_id, rows in grouped.items():
        rows.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
        top_rows = rows[: max(1, PREDICTION_ALERT_TOP_ITEMS)]
        top_items = [prediction_item_summary(row) for row in top_rows]
        max_score = float(top_rows[0].get("score") or 0.0)
        max_score_pct = int(round(max_score * 100))
        first_row = top_rows[0]
        device_ip = str(first_row.get("src_ip") or "").strip()
        if not device_ip:
            continue

        problem_type = "PREDICTIVE_ANOMALY"
        cache_key = f"prediction:{asset_id}:{problem_type}"
        if not should_emit_signal_alert(cache_key):
            continue

        summary_items = [
            f"{item['label']} em {display_focus(item['focus'])} ({item['score_pct']}%)"
            for item in top_items
        ]
        hostname = str(first_row.get("hostname") or "unknown")
        title = f"Anomalia preditiva em {hostname} - maior score {max_score_pct}%"
        description = (
            f"{len(rows)} metricas apresentaram comportamento fora do padrao. "
            f"Principais: {'; '.join(summary_items)}."
        )
        action = (
            "Abra o host no NetGuard, compare as interfaces listadas e priorize as de maior score. "
            "Se houver erros/descartes, verifique cabo/SFP, duplex, fila e saturacao antes de isolar a porta."
        )

        post_alert_problem(
            {
                "device_name": hostname,
                "device_ip": device_ip,
                "problem_type": problem_type,
                "description": description,
                "severity": prediction_alert_severity(max_score),
                "detected_at": alert_ts(first_row.get("ts")),
                "details": {
                    "source": "prediction_signal",
                    "problem_name": title,
                    "summary": description,
                    "trigger": "Anomalia preditiva",
                    "item": "Resumo de metricas SNMP",
                    "group_name": first_row.get("group_name") or "Sem grupo",
                    "value": f"Maior score {max_score_pct}%",
                    "score": max_score,
                    "score_pct": max_score_pct,
                    "top_predictions": top_items,
                    "affected_contexts": [display_focus(item["focus"]) for item in top_items],
                    "impact": "Ainda e um alerta preditivo: indica tendencia anormal antes de uma falha confirmada.",
                    "action": action,
                    "evidence_summary": "; ".join(summary_items),
                    "recommendation": description,
                },
            }
        )


def process_signal_alerts(cur) -> None:
    if not SIGNAL_ALERTS_ENABLED:
        return

    try:
        process_syslog_signal_alerts(cur)
    except Exception as exc:
        print(f"Falha ao processar alertas de syslog: {exc}", flush=True)

    try:
        process_prediction_signal_alerts(cur)
    except Exception as exc:
        print(f"Falha ao processar alertas de previsao: {exc}", flush=True)


def ip_without_cidr(value) -> str:
    return str(value or "").strip().split("/", 1)[0]


def parse_seconds(value, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(float(str(value).strip())))
    except (TypeError, ValueError):
        return max(minimum, int(default))


def parse_bool(value, default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def parse_json_object(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            loaded = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return {}


def collection_policy_seconds(template_definition, override) -> tuple[int, int]:
    definition = template_definition if isinstance(template_definition, dict) else {}
    policy = definition.get("collection_policy") if isinstance(definition.get("collection_policy"), dict) else {}
    override_policy = override if isinstance(override, dict) else {}

    icmp_interval = (
        override_policy.get("icmp_interval_sec")
        or override_policy.get("poll_interval_sec")
        or policy.get("icmp_interval_sec")
        or policy.get("poll_interval_sec")
        or INTERVAL
    )
    snmp_interval = (
        override_policy.get("snmp_interval_sec")
        or policy.get("snmp_interval_sec")
        or os.getenv("SNMP_INTERVAL_SEC", "30")
    )
    return parse_seconds(icmp_interval, INTERVAL, 5), parse_seconds(snmp_interval, 30, 5)


def snmp_expected(snmp_profile, tags=None, has_monitoring_items: bool = False, snmp_items_enabled: bool = False) -> bool:
    profile = parse_json_object(snmp_profile)
    normalized_tags = normalize_asset_tags(tags)

    if "enabled" in profile:
        return parse_bool(profile.get("enabled"), True)

    for key in ("snmp_expected", "snmp"):
        if key in normalized_tags:
            return parse_bool(normalized_tags.get(key), False)

    if has_monitoring_items:
        return bool(snmp_items_enabled)

    return bool(profile)


def syslog_expected(tags) -> bool:
    normalized = normalize_asset_tags(tags)
    explicit = normalized.get("syslog_expected")
    if explicit is not None:
        return parse_bool(explicit, False)
    if normalized.get("syslog_silence_sec") is not None:
        return True
    if normalized.get("syslog_heartbeat") is not None:
        return parse_bool(normalized.get("syslog_heartbeat"), False)
    return False


def relation_exists(cur, name: str) -> bool:
    cur.execute("select to_regclass(%s) as regclass", (name,))
    row = cur.fetchone()
    return bool(row and row.get("regclass"))


def seconds_since(now: datetime, value) -> float | None:
    if not isinstance(value, datetime):
        return None
    ts = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return max(0.0, (now - ts.astimezone(timezone.utc)).total_seconds())


def load_availability_assets(cur) -> list[dict]:
    templates_ready = relation_exists(cur, "monitoring_templates")
    groups_ready = relation_exists(cur, "host_groups")
    host_items_ready = relation_exists(cur, "host_monitoring_items")
    monitoring_items_ready = relation_exists(cur, "monitoring_items")
    template_select = "coalesce(t.definition, '{}'::jsonb)" if templates_ready else "'{}'::jsonb"
    group_select = "coalesce(g.path, g.name)" if groups_ready else "NULL::text"
    template_join = "left join monitoring_templates t on t.id = a.template_id" if templates_ready else ""
    group_join = "left join host_groups g on g.id = a.group_id" if groups_ready else ""
    item_exists_checks = []
    snmp_item_checks = []
    if host_items_ready:
        item_exists_checks.append("exists (select 1 from host_monitoring_items hmi where hmi.host_id = a.id)")
        snmp_item_checks.append(
            "exists (select 1 from host_monitoring_items hmi where hmi.host_id = a.id and lower(hmi.protocol) = 'snmp' and hmi.enabled = true)"
        )
    if monitoring_items_ready:
        item_exists_checks.append("exists (select 1 from monitoring_items mi where mi.host_id = a.id)")
        snmp_item_checks.append(
            "exists (select 1 from monitoring_items mi where mi.host_id = a.id and lower(mi.protocol) = 'snmp' and mi.enabled = true)"
        )
    has_monitoring_items_select = " OR ".join(item_exists_checks) if item_exists_checks else "false"
    snmp_items_enabled_select = " OR ".join(snmp_item_checks) if snmp_item_checks else "false"

    cur.execute(
        f"""
        select a.id,
               a.name,
               split_part(a.ip::text, '/', 1) as ip,
               coalesce(a.snmp_profile, '{{}}'::jsonb) as snmp_profile,
               coalesce(a.tags, '{{}}'::jsonb) as tags,
               coalesce(a.collection_policy_override, '{{}}'::jsonb) as collection_policy_override,
               {template_select} as template_definition,
               {group_select} as group_name,
               ({has_monitoring_items_select}) as has_monitoring_items,
               ({snmp_items_enabled_select}) as snmp_items_enabled
        from assets a
        {template_join}
        {group_join}
        where a.enabled = true
        order by a.id
        """
    )
    return list(cur.fetchall())


def load_latest_host_alive(cur, asset_ids: list[int]) -> dict[int, dict]:
    cur.execute(
        """
        select distinct on (asset_id) asset_id, ts, value
        from metrics
        where asset_id = any(%s)
          and metric = 'host.alive'
        order by asset_id, ts desc
        """,
        (asset_ids,),
    )
    return {int(row["asset_id"]): row for row in cur.fetchall()}


def load_recent_host_alive_counts(cur, asset_ids: list[int], sample_limit: int) -> dict[int, dict]:
    cur.execute(
        """
        select asset_id,
               count(*) as sample_count,
               count(*) filter (where value <= 0) as down_count
        from (
          select asset_id,
                 value,
                 row_number() over (partition by asset_id order by ts desc) as rn
          from metrics
          where asset_id = any(%s)
            and metric = 'host.alive'
        ) latest
        where rn <= %s
        group by asset_id
        """,
        (asset_ids, max(1, sample_limit)),
    )
    return {int(row["asset_id"]): row for row in cur.fetchall()}


def load_latest_snmp_metric(cur, asset_ids: list[int]) -> dict[int, dict]:
    cur.execute(
        """
        select distinct on (asset_id) asset_id, ts
        from metrics
        where asset_id = any(%s)
          and metric like 'snmp.%%'
        order by asset_id, ts desc
        """,
        (asset_ids,),
    )
    return {int(row["asset_id"]): row for row in cur.fetchall()}


def load_latest_interface_oper_up(cur, asset_ids: list[int]) -> dict[int, dict[str, dict]]:
    cur.execute(
        """
        select distinct on (asset_id, metric) asset_id, metric, value, ts, labels
        from metrics
        where asset_id = any(%s)
          and metric like 'snmp.if.oper_status|ifIndex=%%'
        order by asset_id, metric, ts desc
        """,
        (asset_ids,),
    )
    by_asset: dict[int, dict[str, dict]] = {}
    for row in cur.fetchall():
        try:
            value = float(row.get("value"))
        except (TypeError, ValueError):
            continue
        if int(value) != 1:
            continue
        metric = str(row.get("metric") or "")
        match = re.search(r"ifIndex=(\d+)", metric)
        ifindex = match.group(1) if match else ""
        if not ifindex:
            labels = parse_json_object(row.get("labels"))
            ifindex = str(labels.get("ifIndex") or "").strip()
        if ifindex:
            by_asset.setdefault(int(row["asset_id"]), {})[ifindex] = row
    return by_asset


def load_latest_syslog_event(cur, asset_ids: list[int]) -> dict[int, dict]:
    cur.execute(
        """
        select distinct on (asset_id) asset_id, ts, severity, subsystem, iface, message
        from syslog_events
        where asset_id = any(%s)
        order by asset_id, ts desc
        """,
        (asset_ids,),
    )
    return {int(row["asset_id"]): row for row in cur.fetchall()}


def emit_availability_problem(
    asset: dict,
    problem_type: str,
    severity: str,
    description: str,
    trigger: str,
    item: str,
    value: str,
    impact: str,
    action: str,
    evidence: str,
    detected_at,
) -> None:
    device_ip = ip_without_cidr(asset.get("ip"))
    cache_key = f"availability:{device_ip}:{problem_type}"
    if not should_emit_signal_alert(cache_key):
        return

    post_alert_problem(
        {
            "device_name": str(asset.get("name") or device_ip or "unknown"),
            "device_ip": device_ip,
            "problem_type": problem_type,
            "description": description,
            "severity": severity,
            "detected_at": alert_ts(detected_at),
            "details": {
                "source": "availability_watchdog",
                "problem_name": description,
                "summary": description,
                "trigger": trigger,
                "item": item,
                "group_name": asset.get("group_name") or "Sem grupo",
                "value": value,
                "impact": impact,
                "action": action,
                "evidence_summary": evidence,
                "affected_context": item,
            },
        }
    )


def resolve_availability_problem(
    cur,
    asset: dict,
    problem_type: str,
    *,
    telemetry_type: str = "telemetry",
    sample_ts=None,
    observed_value: str = "",
    reason: str = "Telemetria valida posterior ao incidente confirmou recuperacao.",
    send_recovery_notification: bool = True,
) -> None:
    resolve_open_incidents_from_recovery(
        cur,
        asset,
        {problem_type},
        telemetry_type=telemetry_type,
        sample_ts=sample_ts or datetime.now(timezone.utc),
        observed_value=observed_value,
        reason=reason,
        send_recovery_notification=send_recovery_notification,
    )


def incident_interface_indexes(row: dict) -> set[str]:
    details = parse_json_object(row.get("details"))
    candidates = [
        details.get("ifIndex"),
        details.get("ifindex"),
        details.get("interface_index"),
        details.get("interfaceIndex"),
        details.get("context"),
        details.get("affected_context"),
        details.get("item"),
        details.get("key"),
    ]
    indexes: set[str] = set()
    for candidate in candidates:
        text = str(candidate or "").strip()
        if not text:
            continue
        for match in re.findall(r"ifIndex\s*[=:]\s*(\d+)", text, flags=re.IGNORECASE):
            indexes.add(match)
        if text.isdigit():
            indexes.add(text)
    return indexes


def auto_resolve_interface_incidents(cur, asset: dict, oper_up_by_ifindex: dict[str, dict]) -> None:
    if not oper_up_by_ifindex:
        return
    for row in find_open_signal_incidents(cur, asset, INTERFACE_RECOVERY_TYPES):
        candidate_indexes = incident_interface_indexes(row)
        if not candidate_indexes:
            candidate_indexes = set(oper_up_by_ifindex.keys())
        for ifindex in candidate_indexes:
            metric_row = oper_up_by_ifindex.get(str(ifindex))
            if not metric_row or not sample_is_after_incident(metric_row.get("ts"), row):
                continue
            incident_id = int(row.get("id"))
            record_recovery_evidence(
                cur,
                incident_id,
                telemetry_type="SNMP ifOperStatus",
                sample_ts=metric_row.get("ts"),
                observed_value=f"ifIndex={ifindex}; ifOperStatus=up(1)",
                reason="Nova coleta SNMP posterior ao incidente indica ifOperStatus up.",
                automatic=True,
            )
            notify_recovery_service(incident_id, send_recovery_notification=True)
            break


def process_availability_alerts(cur) -> None:
    if not AVAILABILITY_ALERTS_ENABLED or not NETGUARD_API_URL:
        return

    assets = load_availability_assets(cur)
    if not assets:
        return

    asset_ids = [int(row["id"]) for row in assets]
    now = datetime.now(timezone.utc)
    latest_alive = load_latest_host_alive(cur, asset_ids)
    alive_counts = load_recent_host_alive_counts(cur, asset_ids, max(1, AVAILABILITY_HOST_DOWN_SAMPLES))
    latest_snmp = load_latest_snmp_metric(cur, asset_ids)
    latest_syslog = load_latest_syslog_event(cur, asset_ids)
    latest_interface_up = load_latest_interface_oper_up(cur, asset_ids)

    for asset in assets:
        asset["ip"] = ip_without_cidr(asset.get("ip"))
        asset_id = int(asset["id"])
        icmp_interval, snmp_interval = collection_policy_seconds(
            asset.get("template_definition"),
            asset.get("collection_policy_override"),
        )
        icmp_stale_after = max(AVAILABILITY_MIN_STALE_SEC, int(icmp_interval * AVAILABILITY_ICMP_STALE_MULTIPLIER))
        snmp_stale_after = max(
            AVAILABILITY_MIN_STALE_SEC,
            AVAILABILITY_SNMP_MIN_STALE_SEC,
            int(snmp_interval * AVAILABILITY_SNMP_STALE_MULTIPLIER),
        )
        syslog_stale_after = max(
            AVAILABILITY_MIN_STALE_SEC,
            parse_seconds(normalize_asset_tags(asset.get("tags")).get("syslog_silence_sec"), AVAILABILITY_SYSLOG_STALE_SEC),
        )

        alive = latest_alive.get(asset_id)
        alive_age = seconds_since(now, alive.get("ts")) if alive else None
        alive_value = float(alive.get("value") or 0) if alive else None
        if alive and alive_value and alive_value > 0:
            resolve_open_incidents_from_recovery(
                cur,
                asset,
                AVAILABILITY_RECOVERY_TYPES - {"ICMP_COLLECTION_SILENCE", "COLLECTION_SILENCE"},
                telemetry_type="ICMP",
                sample_ts=alive.get("ts"),
                observed_value=f"host.alive={alive_value:g}",
                reason="Nova coleta ICMP posterior ao incidente confirmou host up.",
            )
        if alive and alive_age is not None and alive_age <= icmp_stale_after and alive_value and alive_value > 0:
            resolve_open_incidents_from_recovery(
                cur,
                asset,
                {"ICMP_COLLECTION_SILENCE", "COLLECTION_SILENCE"},
                telemetry_type="ICMP",
                sample_ts=alive.get("ts"),
                observed_value=f"host.alive={alive_value:g}",
                reason="Nova coleta ICMP recente confirmou disponibilidade dentro da janela esperada.",
            )
        elif not alive or alive_age is None or alive_age > icmp_stale_after:
            last_seen = alive.get("ts") if alive else None
            age_text = f"{int(alive_age)}s sem host.alive" if alive_age is not None else "sem host.alive registrado"
            emit_availability_problem(
                asset,
                "ICMP_COLLECTION_SILENCE",
                "HIGH",
                f"Sem telemetria ICMP recente para {asset.get('name')}",
                "Silencio de ICMP",
                "ICMP",
                age_text,
                "O NetGuard deixou de receber confirmacao de disponibilidade ICMP do host.",
                "Validar conectividade, rota, firewall e se o poller ICMP esta alcancando o host.",
                f"Limite {icmp_stale_after}s; ultima amostra {alert_ts(last_seen) if last_seen else 'inexistente'}",
                now,
            )
        else:
            counts = alive_counts.get(asset_id) or {}
            sample_count = int(counts.get("sample_count") or 0)
            down_count = int(counts.get("down_count") or 0)
            if sample_count >= max(1, AVAILABILITY_HOST_DOWN_SAMPLES) and down_count >= sample_count:
                emit_availability_problem(
                    asset,
                    "HOST_DOWN",
                    "CRITICAL",
                    f"{asset.get('name')} parou de responder disponibilidade",
                    "Host sem resposta",
                    "ICMP/TCP",
                    "host.alive=0",
                    "O host pode estar indisponivel ou inacessivel pela rede de monitoramento.",
                    "Validar energia, enlace, rota, firewall e acesso ao IP monitorado.",
                    f"{sample_count} amostras recentes de host.alive em 0; ultima amostra {alert_ts(alive.get('ts'))}",
                    alive.get("ts") or now,
                )

        if snmp_expected(
            asset.get("snmp_profile"),
            asset.get("tags"),
            bool(asset.get("has_monitoring_items")),
            bool(asset.get("snmp_items_enabled")),
        ):
            snmp = latest_snmp.get(asset_id)
            snmp_age = seconds_since(now, snmp.get("ts")) if snmp else None
            if snmp and snmp_age is not None and snmp_age <= snmp_stale_after:
                resolve_availability_problem(
                    cur,
                    asset,
                    "SNMP_COLLECTION_SILENCE",
                    telemetry_type="SNMP",
                    sample_ts=snmp.get("ts"),
                    observed_value=f"amostra SNMP em {alert_ts(snmp.get('ts'))}",
                    reason="Nova amostra SNMP recente posterior ao incidente confirmou recuperacao da telemetria.",
                )
            else:
                last_seen = snmp.get("ts") if snmp else None
                age_text = f"{int(snmp_age)}s sem SNMP" if snmp_age is not None else "sem SNMP registrado"
                emit_availability_problem(
                    asset,
                    "SNMP_COLLECTION_SILENCE",
                    "HIGH",
                    f"Sem telemetria SNMP recente para {asset.get('name')}",
                    "Silencio de SNMP",
                    "SNMP",
                    age_text,
                    "O host ainda pode pingar, mas o NetGuard perdeu leitura SNMP recente.",
                    "Validar community/credencial, ACL, porta UDP 161, perfil SNMP e carga do poller.",
                    f"Limite {snmp_stale_after}s; ultima amostra {alert_ts(last_seen) if last_seen else 'inexistente'}",
                    now,
                )
        else:
            resolve_availability_problem(
                cur,
                asset,
                "SNMP_COLLECTION_SILENCE",
                telemetry_type="perfil de monitoramento",
                sample_ts=now,
                observed_value="SNMP nao esperado para este host",
                reason="O perfil atual do host nao exige SNMP; incidente antigo de silencio SNMP foi encerrado.",
            )

        if syslog_expected(asset.get("tags")):
            syslog = latest_syslog.get(asset_id)
            syslog_age = seconds_since(now, syslog.get("ts")) if syslog else None
            if syslog and syslog_age is not None and syslog_age <= syslog_stale_after:
                resolve_availability_problem(cur, asset, "SYSLOG_COLLECTION_SILENCE")
            else:
                last_seen = syslog.get("ts") if syslog else None
                age_text = f"{int(syslog_age)}s sem syslog" if syslog_age is not None else "sem syslog associado"
                emit_availability_problem(
                    asset,
                    "SYSLOG_COLLECTION_SILENCE",
                    "MEDIUM",
                    f"Sem eventos syslog recentes para {asset.get('name')}",
                    "Silencio de syslog",
                    "Syslog",
                    age_text,
                    "Eventos operacionais podem estar deixando de chegar ao NetGuard.",
                    "Validar destino syslog, UDP 514, NAT/origem, hostname/IP de alias e geracao de eventos no equipamento.",
                    f"Limite {syslog_stale_after}s; ultimo evento {alert_ts(last_seen) if last_seen else 'inexistente'}",
                    now,
                )
        else:
            resolve_availability_problem(
                cur,
                asset,
                "SYSLOG_COLLECTION_SILENCE",
                telemetry_type="perfil de monitoramento",
                sample_ts=now,
                observed_value="Syslog nao esperado para este host",
                reason="O perfil atual do host nao exige syslog; incidente antigo de silencio syslog foi encerrado.",
            )

        auto_resolve_interface_incidents(cur, asset, latest_interface_up.get(asset_id) or {})


def choose_primary_iface(events: list[dict], snmp_hints: list[dict]) -> str:
    counts: dict[str, int] = {}
    for event in events:
        iface = str(event.get("iface") or "").strip()
        if not iface or iface.lower() == "unknown":
            continue
        if not is_physical_loop_interface(iface) and "<->" not in iface:
            continue
        counts[iface] = counts.get(iface, 0) + 1

    for hint in snmp_hints:
        key = str(hint.get("key") or "").strip()
        if not key:
            continue
        if key.lower().startswith("ifindex="):
            continue
        if not is_physical_loop_interface(key) and "<->" not in key:
            continue
        counts[key] = counts.get(key, 0) + int(hint.get("hits") or 0)

    if not counts:
        return "host"

    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def compute_loop_score(
    signal_counts: dict[str, int],
    events: list[dict],
    snmp_hints: list[dict],
    snmp_loop_state: dict[str, dict] | None = None,
) -> float:
    gate = evaluate_loop_risk_gate(events, snmp_loop_state)
    base_score = sum(
        LOOP_SIGNAL_WEIGHTS[signal]
        for signal in LOOP_SIGNAL_WEIGHTS
        if signal_counts.get(signal, 0) > 0
    )

    repeated_hits = sum(max(0, count - 1) for count in signal_counts.values())
    repeat_bonus = min(0.20, repeated_hits * 0.05)

    concentration_bonus = 0.0
    if signal_counts.get("BROADCAST_STORM", 0) >= 1:
        concentration_bonus = max(concentration_bonus, 0.30)
    if signal_counts.get("MAC_FLAPPING", 0) >= 2:
        concentration_bonus = max(concentration_bonus, 0.25)
    if signal_counts.get("STP_TOPOLOGY_CHANGE", 0) >= 2:
        concentration_bonus = max(concentration_bonus, 0.15)
    if signal_counts.get("INTERFACE_FLAP", 0) >= 2:
        concentration_bonus = max(concentration_bonus, 0.10)
    if signal_counts.get("STP_TOPOLOGY_CHANGE", 0) > 0 and signal_counts.get("BROADCAST_STORM", 0) > 0:
        concentration_bonus = max(concentration_bonus, 0.20)
    if signal_counts.get("MAC_FLAPPING", 0) > 0 and signal_counts.get("INTERFACE_FLAP", 0) > 0:
        concentration_bonus = max(concentration_bonus, 0.15)

    severities = [str(event.get("severity") or "").lower() for event in events]
    severity_bonus = 0.0
    if any(severity in ("critical", "high") for severity in severities):
        severity_bonus = 0.10
    elif any(severity in ("warning", "notice") for severity in severities):
        severity_bonus = 0.05

    distinct_keys = len({str(hint.get("key") or "") for hint in snmp_hints if hint.get("key")})
    snmp_bonus = 0.0
    if distinct_keys:
        snmp_bonus = min(
            0.20,
            distinct_keys * 0.08 + (0.04 if any(float(hint.get("zmax") or 0.0) >= MIN_Z * 2 for hint in snmp_hints) else 0.0),
        )

    loop_snmp_bonus = 0.0
    loop_snmp_evidence = 0
    if snmp_loop_state:
        for entry in snmp_loop_state.values():
            iface_name = str(entry.get("ifName") or "").strip()
            if iface_name and not is_physical_loop_interface(iface_name):
                continue
            if gate["physical_interfaces"] and iface_name and iface_name not in gate["physical_interfaces"]:
                continue
            metrics = entry.get("metrics") or {}
            in_errors = metrics.get("snmp.if.in_errors") or {}
            out_errors = metrics.get("snmp.if.out_errors") or {}
            in_discards = metrics.get("snmp.if.in_discards") or {}
            out_discards = metrics.get("snmp.if.out_discards") or {}

            iface_noise = sum(
                1
                for metric_row in (in_errors, out_errors, in_discards, out_discards)
                if float(metric_row.get("value") or 0) > 0
            )
            if iface_noise:
                loop_snmp_evidence += iface_noise
                loop_snmp_bonus = max(loop_snmp_bonus, min(0.15, 0.05 * iface_noise))

    if signal_counts.get("STP_TOPOLOGY_CHANGE", 0) > 0 and loop_snmp_evidence:
        loop_snmp_bonus = max(loop_snmp_bonus, 0.10)

    interface_consistency_bonus = 0.0
    unique_contexts = {
        stable_loop_context_key(str(event.get("focus") or "host"))
        for event in events
        if str(event.get("focus") or "").strip() and str(event.get("focus") or "").strip() != "host"
    }
    unique_vlans = {
        stable_loop_context_key(vlan)
        for event in events
        for vlan in (event.get("vlan"),)
        if str(vlan or "").strip()
    }
    if len(unique_contexts) == 1 and len(unique_vlans) <= 1 and len(events) >= 2:
        interface_consistency_bonus = 0.10
    elif len(unique_contexts) >= 2:
        interface_consistency_bonus = 0.05

    score = min(
        1.0,
        base_score
        + repeat_bonus
        + concentration_bonus
        + severity_bonus
        + snmp_bonus
        + loop_snmp_bonus
        + interface_consistency_bonus,
    )
    if gate["strong_count"] > 0:
        return max(score, LOOP_STRONG_SCORE_FLOOR)
    if gate["eligible"]:
        return max(score, LOOP_MEDIUM_SCORE_FLOOR)
    if gate["medium_count"] == 0:
        return min(score, LOOP_WEAK_SCORE_CAP)
    return min(score, LOOP_INELIGIBLE_SCORE_CAP)


def upsert_prediction_score(cur, ts, asset_id, key, score, evidences, signal_counts, event_count, snmp_hints, signal_contexts, opening_reason, loop_gate=None):
    affected_contexts = build_affected_contexts(signal_contexts)
    details = {
        "source": "syslog_correlation",
        "window_sec": LOOP_WINDOW_SEC,
        "score_pct": int(round(score * 100)),
        "evidences": evidences,
        "signal_counts": signal_counts,
        "event_count": int(event_count),
        "snmp_hints": snmp_hints,
        "signal_contexts": signal_contexts,
        "affected_contexts": affected_contexts,
        "loop_gate": loop_gate or {},
        "vlan_contexts": sorted(
            {
                str(vlan or "").strip()
                for item in signal_contexts
                for vlan in (item.get("vlans") or [])
                if str(vlan or "").strip()
            }
        ),
        "opening_reason": opening_reason,
        "recommendation": LOOP_RECOMMENDATION,
    }

    cur.execute(
        """
        insert into anomaly_scores
        (ts, asset_id, metric, key, score, z, value, baseline_mean, baseline_std, details)
        values (%s,%s,'loop_risk',%s,%s,%s,%s,%s,%s,%s::jsonb)
        on conflict (ts, asset_id, metric, key)
        do update set
          score = excluded.score,
          z = excluded.z,
          value = excluded.value,
          baseline_mean = excluded.baseline_mean,
          baseline_std = excluded.baseline_std,
          details = excluded.details
        """,
        (
            ts,
            asset_id,
            key,
            float(score),
            float(score * 4),
            float(score * 100),
            None,
            None,
            json.dumps(details),
        ),
    )


def upsert_loop_risk_incident(cur, asset_id, hostname, src_ip, latest_ts, score, evidences, signal_counts, key, snmp_hints, signal_contexts, opening_reason, group_name=None, loop_gate=None):
    severity = "critical" if score >= 0.90 else "high" if score >= LOOP_OPEN_SCORE else "warning"
    title = f"Risco de loop L2 em {hostname}"
    detected_at = datetime.now(timezone.utc)

    affected_contexts = build_affected_contexts(signal_contexts)
    details = {
        "source": "anomaly_to_incident",
        "group_name": group_name,
        "loop_fingerprint": key,
        "loop_context_key": key.rsplit(":", 1)[-1],
        "problem_name": f"Risco de loop L2 em {hostname}",
        "summary": opening_reason,
        "trigger": "Loop L2 provavel",
        "item": ", ".join(affected_contexts[:3]) if affected_contexts else key,
        "value": f"Score {int(round(score * 100))}%",
        "impact": "Pode causar broadcast storm, MAC flapping, perda de pacotes e instabilidade no dominio L2.",
        "action": "Valide STP/Loop Guard, isole uma das portas suspeitas e confirme se storm, MAC flapping e flap cessam.",
        "evidence_summary": "; ".join(evidences[:5]) if evidences else opening_reason,
        "score": float(score),
        "score_pct": int(round(score * 100)),
        "window_sec": int(LOOP_WINDOW_SEC),
        "evidences": evidences,
        "signal_counts": signal_counts,
        "snmp_hints": snmp_hints,
        "signal_contexts": signal_contexts,
        "affected_contexts": affected_contexts,
        "loop_gate": loop_gate or {},
        "opening_reason": opening_reason,
        "latest_event_at": alert_ts(latest_ts),
        "recommendation": LOOP_RECOMMENDATION,
        "clean_cycles_required": max(1, LOOP_RISK_CLEAN_CYCLES),
    }

    legacy_key = f"loop_risk:{asset_id}:active"
    match_contexts = sorted(
        {
            stable_loop_context_key(context)
            for context in affected_contexts
            if str(context or "").strip()
        }
    )
    raw_contexts = sorted(
        {
            str(context or "").strip().lower()
            for context in affected_contexts
            if str(context or "").strip()
        }
    )
    context_json = json.dumps(match_contexts)
    raw_context_json = json.dumps(raw_contexts)
    cur.execute(
        """
        update incidents
        set key = %s,
            last_seen_at = %s,
            last_detected_at = %s,
            updated_at = %s,
            asset_id = %s,
            device_name = %s,
            device_ip = %s,
            problem_type = 'LOOP_RISK',
            description = %s,
            severity = %s,
            title = %s,
            first_detected_at = coalesce(first_detected_at, %s),
            details = coalesce(details, '{}'::jsonb) || %s::jsonb
        where id = (
            select id
            from incidents
            where lower(coalesce(status, '')) in ('open', 'acknowledged')
              and (
                key = %s
                or key = %s
                or coalesce(details->>'loop_fingerprint', '') = %s
                or exists (
                  select 1
                  from jsonb_array_elements_text(coalesce(incidents.details->'affected_contexts', '[]'::jsonb)) existing_context
                  join jsonb_array_elements_text(%s::jsonb) current_context
                    on lower(existing_context.value) = current_context.value
                )
                or exists (
                  select 1
                  from jsonb_array_elements_text(coalesce(incidents.details->'affected_contexts', '[]'::jsonb)) existing_context
                  join jsonb_array_elements_text(%s::jsonb) current_context
                    on regexp_replace(lower(existing_context.value), '[^a-zA-Z0-9_.:-]+', '_', 'g') = current_context.value
                )
              )
              and (
                asset_id = %s
                or split_part(coalesce(device_ip::text, src_ip::text), '/', 1) = %s
              )
              and (
                lower(coalesce(incident_type, '')) = 'loop_risk'
                or upper(coalesce(problem_type, '')) = 'LOOP_RISK'
              )
            order by
              case
                when key = %s or coalesce(details->>'loop_fingerprint', '') = %s then 0
                when key = %s then 1
                else 2
              end,
              coalesce(opened_at, created_at, updated_at, last_seen_at, last_detected_at) asc,
              id asc
            limit 1
        )
        returning id
        """,
        (
            key,
            detected_at,
            latest_ts,
            detected_at,
            asset_id,
            hostname,
            src_ip,
            opening_reason,
            severity,
            title,
            latest_ts,
            json.dumps(details, ensure_ascii=False),
            key,
            legacy_key,
            key,
            raw_context_json,
            context_json,
            asset_id,
            ip_without_cidr(src_ip),
            key,
            key,
            legacy_key,
        ),
    )
    row = cur.fetchone()
    if row and row.get("id") is not None:
        incident_id = int(row["id"])
        consolidate_duplicate_loop_incidents(cur, incident_id, asset_id, key, affected_contexts, detected_at)
        return incident_id

    cur.execute(
        """
        insert into incidents
          (
            opened_at, last_seen_at, asset_id, hostname, src_ip, incident_type,
            key, severity, title, details, device_name, device_ip, problem_type,
            description, first_detected_at, last_detected_at, notification_sent,
            created_at, updated_at
          )
        values
          (
            %s, %s, %s, %s, %s, 'loop_risk', %s, %s, %s, %s::jsonb,
            %s, %s, 'LOOP_RISK', %s, %s, %s, false, %s, %s
          )
        on conflict (key) where status='open'
        do update set
          last_seen_at = excluded.last_seen_at,
          last_detected_at = excluded.last_detected_at,
          updated_at = excluded.updated_at,
          asset_id = excluded.asset_id,
          device_name = excluded.device_name,
          device_ip = excluded.device_ip,
          problem_type = excluded.problem_type,
          description = excluded.description,
          severity = excluded.severity,
          title = excluded.title,
          first_detected_at = coalesce(incidents.first_detected_at, excluded.first_detected_at),
          details = incidents.details || excluded.details
        returning id
        """,
        (
            detected_at,
            detected_at,
            asset_id,
            hostname,
            src_ip,
            key,
            severity,
            title,
            json.dumps(details),
            hostname,
            src_ip,
            opening_reason,
            latest_ts,
            detected_at,
            detected_at,
            detected_at,
        ),
    )
    row = cur.fetchone()
    incident_id = int(row["id"]) if row and row.get("id") is not None else None
    consolidate_duplicate_loop_incidents(cur, incident_id, asset_id, key, affected_contexts, detected_at)
    return incident_id


def process_loop_risk(cur):
    since = datetime.now(timezone.utc) - timedelta(seconds=LOOP_WINDOW_SEC)
    by_id, by_ip, by_name = load_asset_maps(cur)
    snmp_hints_by_asset = load_recent_snmp_hints(cur, since)

    cur.execute(
        """
        select ts, hostname, src_ip, asset_id, severity, subsystem, iface, message, raw
        from syslog_events
        where ts > %s
        order by ts asc
        """,
        (since,),
    )
    rows = cur.fetchall()

    grouped: dict[int, dict] = {}
    last_recovery_by_asset: dict[int, datetime] = {}

    for row in rows:
        asset = None
        if row.get("asset_id") is not None:
            asset = by_id.get(int(row["asset_id"]))
        if asset is None:
            asset = by_ip.get(str(row["src_ip"])) or by_name.get(str(row["hostname"]).lower())
        if asset is None:
            continue

        if detect_loop_recovery_signal(row.get("message"), row.get("raw")):
            asset_id = int(asset["asset_id"])
            focus, _interfaces, _interface_pair = resolve_event_focus(row)
            evidence = clamp_text(row.get("raw") or row.get("message") or "")
            last_recovery_by_asset[asset_id] = row["ts"]
            record_loop_recovery_hint(
                cur,
                asset_id,
                loop_recovery_value(row, focus),
                evidence,
                row.get("ts"),
            )
            continue

        signal = detect_loop_signal(row.get("message"), row.get("raw"))
        if signal is None:
            continue

        asset_id = asset["asset_id"]
        recovery_ts = last_recovery_by_asset.get(int(asset_id))
        if recovery_ts is not None and row["ts"] <= recovery_ts:
            continue
        group = grouped.setdefault(
            asset_id,
            {
                "hostname": asset["name"],
                "src_ip": asset["ip"],
                "group_name": asset.get("group_name"),
                "events": [],
                "signal_counts": {},
                "latest_ts": row["ts"],
            },
        )

        focus, interfaces, interface_pair = resolve_event_focus(row)
        focus, interfaces, interface_pair = normalize_loop_event_focus(focus, interfaces, interface_pair)
        vlan = extract_loop_vlan(row.get("message"), row.get("raw"))
        evidence = f"{signal}:{focus}" + (f":{vlan}" if vlan else "")

        group["events"].append(
            {
                "ts": row["ts"],
                "signal": signal,
                "iface": focus,
                "focus": focus,
                "interfaces": interfaces,
                "interface_pair": interface_pair,
                "vlan": vlan,
                "severity": row.get("severity"),
                "subsystem": row.get("subsystem"),
                "message": row.get("message"),
                "raw": row.get("raw"),
                "evidence": evidence,
            }
        )
        group["signal_counts"][signal] = group["signal_counts"].get(signal, 0) + 1
        if row["ts"] > group["latest_ts"]:
            group["latest_ts"] = row["ts"]

    for asset_id, group in grouped.items():
        correlate_trap_focus(group["events"])
        snmp_hints = snmp_hints_by_asset.get(asset_id, [])
        snmp_loop_state = load_recent_loop_snmp_state(cur, asset_id, since)
        loop_gate = evaluate_loop_risk_gate(group["events"], snmp_loop_state)
        relevant_events = [
            event for event in group["events"]
            if loop_event_strength(event) in {"strong", "medium"}
        ]
        signal_contexts = build_signal_contexts(relevant_events)
        snmp_loop_evidence = []
        for ifindex, entry in snmp_loop_state.items():
            iface_name = str(entry.get("ifName") or f"ifIndex={ifindex}").strip()
            if iface_name and not is_physical_loop_interface(iface_name):
                continue
            if loop_gate["physical_interfaces"] and iface_name and iface_name not in loop_gate["physical_interfaces"]:
                continue
            metrics = entry.get("metrics") or {}
            in_errors = metrics.get("snmp.if.in_errors")
            out_errors = metrics.get("snmp.if.out_errors")
            in_discards = metrics.get("snmp.if.in_discards")
            out_discards = metrics.get("snmp.if.out_discards")
            for metric_name, metric_row in (
                ("snmp.if.in_errors", in_errors),
                ("snmp.if.out_errors", out_errors),
                ("snmp.if.in_discards", in_discards),
                ("snmp.if.out_discards", out_discards),
            ):
                if metric_row and float(metric_row.get("value") or 0) > 0:
                    snmp_loop_evidence.append(
                        f"SNMP:{iface_name}: {loop_metric_label(metric_name)}={interpret_interface_metric_value(metric_name, metric_row.get('value'))}"
                    )

        score = compute_loop_score(group["signal_counts"], group["events"], snmp_hints, snmp_loop_state)
        opening_reason = build_opening_reason(signal_contexts, LOOP_WINDOW_SEC)

        evidences = build_evidences(group["events"], snmp_hints, snmp_loop_evidence)

        primary_iface = choose_primary_iface(group["events"], snmp_hints)
        primary_pair = next((event.get("interface_pair") for event in group["events"] if event.get("interface_pair")), None)
        prediction_key = primary_pair or (primary_iface if primary_iface != "host" else "host")
        loop_fingerprint, _fingerprint_contexts = build_loop_fingerprint(asset_id, signal_contexts, prediction_key)

        upsert_prediction_score(
            cur,
            group["latest_ts"],
            asset_id,
            prediction_key,
            score,
            evidences,
            group["signal_counts"],
            len(group["events"]),
            snmp_hints,
            signal_contexts,
            opening_reason,
            loop_gate,
        )

        if score >= LOOP_OPEN_SCORE and loop_gate["eligible"]:
            incident_id = upsert_loop_risk_incident(
                cur,
                asset_id,
                group["hostname"],
                group["src_ip"],
                group["latest_ts"],
                score,
                evidences,
                group["signal_counts"],
                loop_fingerprint,
                snmp_hints,
                signal_contexts,
                opening_reason,
                group.get("group_name"),
                loop_gate,
            )
            if should_notify_loop_fingerprint(cur, incident_id, loop_fingerprint):
                notify_alert_service(incident_id)


def main():
    if not DB:
        raise SystemExit("DATABASE_URL/NETGUARD_DB_DSN nao definido")

    wait_sec = DB_CONNECT_RETRY_SEC
    while True:
        try:
            conn = psycopg2.connect(DB, cursor_factory=RealDictCursor)
            break
        except psycopg2.OperationalError as exc:
            print(f"[engine] aguardando banco ficar pronto: {exc}", flush=True)
            time.sleep(wait_sec)
            wait_sec = min(DB_CONNECT_RETRY_MAX_SEC, max(DB_CONNECT_RETRY_SEC, wait_sec * 2))

    conn.autocommit = True
    cur = conn.cursor()

    while True:
        process_degradation_incidents(cur)
        process_loop_risk(cur)
        resolve_clean_loop_risk_incidents(cur)
        resolve_stale_loop_risk_incidents(cur)
        process_signal_alerts(cur)
        process_availability_alerts(cur)
        resolve_stale_syslog_loop_component_incidents(cur)
        resolve_legacy_stale_alert_incidents(cur)
        resolve_stale_alert_incidents(cur)
        notify_pending_incidents(cur)
        notify_pending_recoveries(cur)

        if RUN_ONCE:
            break

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
