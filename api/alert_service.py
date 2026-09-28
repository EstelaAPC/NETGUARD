import json
import logging
import os
import re
import smtplib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import escape as html_escape
from typing import Any, Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    from ollama_client import OllamaClient, OllamaClientError
except ImportError:
    try:
        from api.ollama_client import OllamaClient, OllamaClientError
    except ImportError:
        OllamaClient = None

        class OllamaClientError(RuntimeError):
            pass


ALERT_TITLE = "[NetGuard] Problema detectado"
RECOVERY_TITLE = "[NetGuard] Incidente resolvido"
ALERT_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALERT_STATUSES = {"OPEN", "ACKNOWLEDGED", "RESOLVED"}
ACTIVE_STATUS_VALUES = {"open", "acknowledged"}
DEFAULT_ANTI_SPAM_MINUTES = 10
ALERT_CHANNEL_PROVIDERS = {
    "email",
    "discord",
    "telegram",
    "slack",
    "msteams",
    "google_chat",
    "mattermost",
    "rocketchat",
    "pushover",
    "webhook",
}
WEBHOOK_URL_PROVIDERS = {
    "discord",
    "slack",
    "msteams",
    "google_chat",
    "mattermost",
    "rocketchat",
    "webhook",
}
SEVERITY_RANKS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
SEVERITY_LABELS = {
    "LOW": "Baixa ℹ️",
    "MEDIUM": "Média ⚠️",
    "HIGH": "Alta 🔥",
    "CRITICAL": "Crítica 💀",
}
DEFAULT_ALERT_TIMEZONE = "America/Sao_Paulo"
DEFAULT_NETGUARD_PUBLIC_URL = "http://192.168.56.15:8081"
DEFAULT_PROBLEM_TEMPLATE = """🚨 {severity_label} | {problem_name}

O que aconteceu: {friendly_summary}
Impacto provável: {friendly_impact}
Ação recomendada: {friendly_action}
Evidências principais: {friendly_evidence}
Comandos úteis: {friendly_commands}

Host: {device_name}
IP: {device_ip}
Grupo: {group_name}
Contexto: {affected_context}
Valor: {value}
Início: {started_at}

Acesse: {incident_url}"""
DEFAULT_RECOVERY_TEMPLATE = """✅ Recuperado | {problem_name}

O que foi recuperado: {friendly_summary}
Evidência de normalização: {friendly_evidence}
Status atual: {recovery_value}

Host: {device_name}
Grupo: {group_name}
Duração: {duration}
Resolvido em: {resolved_at}

Acesse: {incident_url}"""

CHANNEL_FAILURE_COOLDOWNS: dict[tuple[str, str], float] = {}
TELEGRAM_MARKDOWN_V2_RE = re.compile(r"([_*\[\]()~`>#+\-=|{}.!])")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        return default


def notification_error_text(exc: Exception) -> str:
    text = str(exc) or exc.__class__.__name__
    for secret_name in (
        "SMTP_PASSWORD",
        "DISCORD_WEBHOOK_URL",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "WEBHOOK_URL",
    ):
        secret = os.getenv(secret_name)
        if secret:
            text = text.replace(secret, "***")
    return text[:500]


def channel_cooldown_seconds() -> int:
    return max(5, env_int("ALERT_CHANNEL_COOLDOWN_SEC", 600))


def notification_retry_after_seconds(exc: Exception) -> Optional[int]:
    match = re.search(r"retry_after=(\d+)", str(exc or ""))
    if not match:
        return None
    try:
        return max(1, int(match.group(1)))
    except ValueError:
        return None


def telegram_text_for_parse_mode(text: str, parse_mode: str) -> str:
    safe_text = str(text or "")
    if len(safe_text) > 3900:
        safe_text = safe_text[:3897].rstrip() + "..."
    normalized = str(parse_mode or "").strip().lower()
    if normalized == "markdownv2":
        return TELEGRAM_MARKDOWN_V2_RE.sub(r"\\\1", safe_text)
    if normalized == "markdown":
        return (
            safe_text.replace("\\", "\\\\")
            .replace("_", "\\_")
            .replace("*", "\\*")
            .replace("[", "\\[")
            .replace("`", "\\`")
        )
    return safe_text


def telegram_severity_badge(value: str) -> str:
    normalized = normalize_severity(value)
    return {
        "LOW": "🔵 Baixa",
        "MEDIUM": "🟡 Média",
        "HIGH": "🟠 Alta",
        "CRITICAL": "🔴 Crítica",
    }.get(normalized, normalized)


def telegram_escape(value: Any) -> str:
    return html_escape(clean_text(value, ""), quote=False)


def telegram_lines_from_text(value: Any, limit: int = 4) -> list[str]:
    raw = clean_text(value, "")
    if not raw:
        return []
    parts = [item.strip(" -•\t") for item in re.split(r";|\n", raw) if item.strip(" -•\t")]
    if not parts:
        parts = [raw]
    return parts[:limit]


def build_telegram_alert_html(notification: Any) -> str:
    context = dict(notification.context or {})
    if not context:
        context = build_template_context(
            notification.problem,
            notification.timestamp,
            notification.status,
            recovery=notification.recovery,
        )

    if notification.recovery:
        header = '? <b>NetGuard | Recuperado</b>'
        status_line = f"<b>Incidente:</b> {telegram_escape(context.get('problem_name'))}"
        time_line = f"<b>Resolvido em:</b> {telegram_escape(context.get('resolved_at'))}"
    else:
        header = f"?? <b>NetGuard | {telegram_escape(telegram_severity_badge(notification.problem.severity))}</b>"
        status_line = f"<b>Problema:</b> {telegram_escape(context.get('problem_name'))}"
        time_line = f"<b>In?cio:</b> {telegram_escape(context.get('started_at'))}"

    lines = [
        header,
        '',
        status_line,
        f"<b>Host:</b> {telegram_escape(context.get('device_name'))} ({telegram_escape(context.get('device_ip'))})",
        f"<b>Grupo:</b> {telegram_escape(context.get('group_name'))}",
        time_line,
    ]

    if notification.recovery:
        lines.extend(
            [
                f"<b>Dura??o:</b> {telegram_escape(context.get('duration'))}",
                f"<b>Status atual:</b> {telegram_escape(context.get('recovery_value'))}",
            ]
        )
    else:
        if context.get('affected_context'):
            lines.append(f"<b>Contexto:</b> {telegram_escape(context.get('affected_context'))}")
        if context.get('value'):
            lines.append(f"<b>Valor:</b> {telegram_escape(context.get('value'))}")

    summary = clean_text(context.get('friendly_summary') or context.get('summary'), '')
    if summary:
        section_title = 'O que foi recuperado' if notification.recovery else 'O que aconteceu'
        lines.extend(['', f"<b>{section_title}:</b> {telegram_escape(summary)}"])

    impact = clean_text(context.get('friendly_impact') or context.get('impact'), '')
    if impact and not notification.recovery:
        lines.append(f"<b>Impacto prov?vel:</b> {telegram_escape(impact)}")

    action = clean_text(context.get('friendly_action') or context.get('action'), '')
    if action and not notification.recovery:
        lines.extend(['', '<b>A??o recomendada:</b>'])
        lines.extend(f"- {telegram_escape(item)}" for item in telegram_lines_from_text(action, limit=3))

    evidence = telegram_lines_from_text(context.get('friendly_evidence') or context.get('evidence_summary'), limit=5)
    if evidence:
        section_title = 'Evid?ncia de normaliza??o' if notification.recovery else 'Evid?ncias principais'
        lines.extend(['', f"<b>{section_title}:</b>"])
        lines.extend(f"- {telegram_escape(item)}" for item in evidence)

    commands = telegram_lines_from_text(context.get('friendly_commands'), limit=5)
    if commands and not notification.recovery:
        lines.extend(['', '<b>Comandos ?teis:</b>'])
        lines.extend(f"- <code>{telegram_escape(item)}</code>" for item in commands)

    incident_url = clean_text(context.get('incident_url'), '')
    if incident_url:
        lines.extend(['', f'<a href="{html_escape(incident_url, quote=True)}">Abrir no NetGuard</a>'])

    text = '\n'.join(line for line in lines if line is not None)
    if len(text) > 3900:
        text = text[:3897].rstrip() + '...'
    return text


def ensure_aware_utc(value: Optional[datetime]) -> datetime:
    resolved = value or utc_now()
    if resolved.tzinfo is None:
        resolved = resolved.replace(tzinfo=timezone.utc)
    return resolved.astimezone(timezone.utc)


def serialize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: serialize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [serialize_value(item) for item in value]
    return value


def normalize_problem_type(value: str) -> str:
    normalized = re.sub(r"[^A-Z0-9_.:-]+", "_", str(value or "").strip().upper()).strip("_")
    if not normalized:
        raise ValueError("problem_type is required")
    return normalized


def normalize_severity(value: str) -> str:
    normalized = str(value or "").strip().upper()
    if normalized not in ALERT_SEVERITIES:
        raise ValueError("severity must be one of LOW, MEDIUM, HIGH or CRITICAL")
    return normalized


def severity_allows(problem_severity: str, min_severity: str) -> bool:
    problem_rank = SEVERITY_RANKS.get(normalize_severity(problem_severity), 0)
    min_rank = SEVERITY_RANKS.get(normalize_severity(min_severity or "LOW"), 1)
    return problem_rank >= min_rank


def severity_rank_value(value: Any) -> int:
    try:
        return SEVERITY_RANKS.get(normalize_severity(str(value or "LOW")), 0)
    except ValueError:
        return 0


def severity_label(value: str) -> str:
    try:
        normalized = normalize_severity(value)
    except ValueError:
        normalized = "LOW"
    return SEVERITY_LABELS.get(normalized, normalized)


def storage_status(value: str) -> str:
    normalized = str(value or "").strip().upper()
    if normalized not in ALERT_STATUSES:
        raise ValueError("status must be one of OPEN, ACKNOWLEDGED or RESOLVED")
    return normalized.lower()


def output_status(value: Optional[str]) -> str:
    normalized = str(value or "OPEN").strip().upper()
    if normalized == "CLOSED":
        return "RESOLVED"
    if normalized in ALERT_STATUSES:
        return normalized
    return normalized


def active_status_sql(column: str = "status") -> str:
    return f"LOWER(COALESCE({column}, '')) IN ('open', 'acknowledged')"


def ip_text_sql(column: str) -> str:
    return f"SPLIT_PART(BTRIM({column}::text), '/', 1)"


def ip_without_cidr(value: Any) -> str:
    return str(value or "").strip().split("/", 1)[0]


def local_alert_timezone():
    name = os.getenv("NETGUARD_ALERT_TIMEZONE", DEFAULT_ALERT_TIMEZONE).strip() or DEFAULT_ALERT_TIMEZONE
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return timezone.utc


def format_alert_datetime(value: Optional[datetime]) -> str:
    if value is None:
        return "-"
    resolved = ensure_aware_utc(value).astimezone(local_alert_timezone())
    return resolved.strftime("%Y.%m.%d às %H:%M:%S")


def format_alert_short_datetime(value: Optional[datetime]) -> str:
    if value is None:
        return "-"
    resolved = ensure_aware_utc(value).astimezone(local_alert_timezone())
    return resolved.strftime("%d/%m/%Y %H:%M")


def format_duration(started_at: Optional[datetime], ended_at: Optional[datetime]) -> str:
    if started_at is None or ended_at is None:
        return "-"
    seconds = max(0, int((ensure_aware_utc(ended_at) - ensure_aware_utc(started_at)).total_seconds()))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def clean_text(value: Any, fallback: str = "-") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def alert_ai_enabled() -> bool:
    return env_bool("ALERT_OLLAMA_ENABLED", True)


def alert_ai_timeout_seconds() -> float:
    return max(3.0, float(os.getenv("ALERT_OLLAMA_TIMEOUT_SEC", "12").strip() or "12"))


def split_text_items(value: Any, *, limit: int = 6) -> list[str]:
    if isinstance(value, (list, tuple)):
        items = [str(item or "").strip() for item in value]
    else:
        raw = str(value or "").strip()
        items = [item.strip(" -•\t") for item in re.split(r";|\n", raw) if item.strip(" -•\t")]
    unique: list[str] = []
    for item in items:
        text = re.sub(r"\s+", " ", item).strip()
        if text and text not in unique:
            unique.append(text)
        if len(unique) >= limit:
            break
    return unique


def normalize_interface_label(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text.replace("<->", " <-> ")


def human_severity_label(value: str) -> str:
    return {
        "LOW": "baixa",
        "MEDIUM": "media",
        "HIGH": "alta",
        "CRITICAL": "critica",
    }.get(normalize_severity(value), "baixa")


def problem_vlan(details: dict[str, Any]) -> str:
    for key in ("vlan", "vlan_id", "vlan_context"):
        value = str(details.get(key) or "").strip()
        if value:
            return value
    for item in list(details.get("signal_contexts") or [])[:6]:
        if isinstance(item, dict):
            vlans = item.get("vlans") or []
            if vlans:
                return str(vlans[0] or "").strip()
    return ""


def problem_interfaces(details: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("interface_pair", "affected_context", "ifName", "iface", "interface", "item", "key"):
        raw = details.get(key)
        if isinstance(raw, (list, tuple)):
            values.extend(str(item or "").strip() for item in raw)
        elif raw:
            values.append(str(raw).strip())
    for item in list(details.get("affected_contexts") or [])[:6]:
        if item:
            values.append(str(item).strip())
    normalized: list[str] = []
    for value in values:
        text = normalize_interface_label(value)
        if text and text.lower() != "host" and text not in normalized:
            normalized.append(text)
    return normalized[:4]


def evidence_priority(value: str) -> tuple[int, str]:
    text = str(value or "").upper()
    if any(token in text for token in ("STORM_CONTROL", "BROADCAST_STORM", "MAC_FLAPPING", "MACFLAP", "LOOPGUARD", "BPDU", "ERR_DISABLE", "ERR-DISABLE")):
        return (0, text)
    if any(token in text for token in ("LOOP", "STP", "SPANTREE", "TOPOLOGY_CHANGE")):
        return (1, text)
    if any(token in text for token in ("SNMP:", "ERROR", "DISCARD", "LOSS", "LATENCIA", "LATENCY")):
        return (2, text)
    if any(token in text for token in ("INTERFACE_FLAP", "LINEPROTO", "LINK")):
        return (3, text)
    return (4, text)


def top_evidences(details: dict[str, Any], *, limit: int = 5) -> list[str]:
    items: list[str] = []
    for source in (
        details.get("evidences"),
        details.get("evidence"),
        details.get("signal_contexts"),
        details.get("snmp_hints"),
        details.get("evidence_summary"),
        details.get("raw"),
        details.get("last_recovery_hint_evidence"),
        details.get("recovery_evidence"),
    ):
        if isinstance(source, list):
            for item in source:
                if isinstance(item, dict):
                    label = clean_text(
                        item.get("label")
                        or item.get("signal")
                        or item.get("metric")
                        or item.get("key"),
                        "",
                    )
                    focus = clean_text(item.get("focus") or item.get("ifName") or item.get("iface"), "")
                    count = item.get("count")
                    text = label
                    if focus and focus.lower() != "host":
                        text = f"{label} em {focus}" if label else focus
                    if count and str(count).isdigit() and int(count) > 1:
                        text = f"{text} x{count}"
                    if text:
                        items.append(text)
                else:
                    items.extend(split_text_items(item, limit=2))
        else:
            items.extend(split_text_items(source, limit=4))
    deduped: list[str] = []
    for item in items:
        text = re.sub(r"\s+", " ", str(item or "")).strip(" ;")
        if text and text not in deduped:
            deduped.append(text)
    deduped.sort(key=evidence_priority)
    return deduped[:limit]


def recommended_commands(problem: "AlertProblem", details: dict[str, Any], *, limit: int = 5) -> list[str]:
    problem_type = str(problem.problem_type or "").upper()
    interfaces = problem_interfaces(details)
    vlan = problem_vlan(details)
    commands: list[str] = []
    if "LOOP_RISK" in problem_type:
        commands.extend(
            [
                "show logging | include STP|LOOP|STORM|MACFLAP|ERR",
                f"show spanning-tree vlan {vlan}" if vlan else "show spanning-tree",
                "show interfaces status",
                "show interfaces counters errors",
            ]
        )
        commands.extend(f"show interfaces {iface}" for iface in interfaces[:2] if iface)
    elif "SNMP_COLLECTION_SILENCE" in problem_type:
        commands.extend(
            [
                f"snmpwalk -v2c -c <community> {problem.device_ip} 1.3.6.1.2.1.1",
                "show running-config | include snmp-server",
                "show access-lists",
            ]
        )
    elif "HOST_DOWN" in problem_type or "ICMP_COLLECTION_SILENCE" in problem_type:
        commands.extend(
            [
                f"ping {problem.device_ip}",
                f"traceroute {problem.device_ip}",
                "show interfaces status",
                "show ip interface brief",
            ]
        )
    elif "INTERFACE_FLAP" in problem_type:
        commands.extend(["show interfaces status", "show interfaces counters errors"])
        commands.extend(f"show interfaces {iface}" for iface in interfaces[:2] if iface)
    deduped: list[str] = []
    for item in commands:
        text = str(item or "").strip()
        if text and text not in deduped:
            deduped.append(text)
        if len(deduped) >= limit:
            break
    return deduped


def fallback_operational_sections(
    problem: "AlertProblem",
    details: dict[str, Any],
    *,
    recovery: bool = False,
    context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    context = context or {}
    problem_name = human_problem_name(problem.problem_type)
    interfaces = problem_interfaces(details)
    vlan = problem_vlan(details)
    interface_text = ", ".join(interfaces[:3]) if interfaces else "host"
    severity = human_severity_label(problem.severity)
    evidences = top_evidences(details, limit=5)
    evidence_text = "; ".join(evidences) if evidences else "Nao ha evidencias suficientes para concluir a causa raiz."
    commands = recommended_commands(problem, details)
    commands_text = "; ".join(commands) if commands else "Abra o host no NetGuard e valide o contexto operacional."
    problem_type = str(problem.problem_type or "").upper()
    icmp_state = str(details.get("icmp_state") or details.get("host_alive_state") or "").strip()

    if recovery:
        summary = f"{problem_name} voltou ao estado normal."
        if "LOOP_RISK" in problem_type and interfaces:
            summary = f"O risco de loop L2 deixou de apresentar sinais fortes em {interface_text}."
        impact = "O incidente foi encerrado e o ambiente voltou ao estado esperado no ultimo ciclo confirmado."
        action = "Mantenha acompanhamento operacional e confirme se o incidente nao volta a aparecer."
        return {
            "summary": summary,
            "impact": impact,
            "action": action,
            "evidence": evidence_text,
            "commands": commands_text,
            "source": "fallback",
        }

    if "LOOP_RISK" in problem_type:
        summary = f"O NetGuard identificou risco de loop L2 com severidade {severity} em {interface_text}."
        if vlan:
            summary += f" VLAN em foco: {vlan}."
        impact = "O segmento pode sofrer broadcast storm, MAC flapping, perda de pacotes e instabilidade nas portas envolvidas."
        action = "Valide STP, confira as portas envolvidas, contenha o enlace redundante indevido e confirme se os sinais fortes cessaram."
    elif "SNMP_COLLECTION_SILENCE" in problem_type:
        summary = f"O host parou de responder via SNMP. Estado ICMP atual: {icmp_state or 'nao informado'}."
        impact = "O ativo pode continuar acessivel por rede, mas o NetGuard perdeu visibilidade SNMP para metricas e interfaces."
        action = "Verifique community, ACL, servico SNMP, rota de gerencia e firewall."
    elif "HOST_DOWN" in problem_type:
        summary = "O host nao responde e foi tratado como indisponivel."
        impact = "Servicos dependentes podem estar fora do ar ou degradados ate a conectividade ser restabelecida."
        action = "Confira energia, cabo, VLAN, gateway, interface de uplink e alcance ICMP a partir do NetGuard."
    elif "ICMP_COLLECTION_SILENCE" in problem_type:
        summary = "O NetGuard nao recebeu telemetria ICMP recente do host."
        impact = "A disponibilidade do ativo ficou sem confirmacao recente e pode haver perda de alcance ou falha transitória."
        action = "Valide conectividade ICMP, rota, firewall e estabilidade do host no periodo."
    elif "INTERFACE_FLAP" in problem_type:
        summary = f"O NetGuard observou oscilacao de interface em {interface_text}."
        impact = "O enlace pode estar instavel e afetar conectividade do equipamento ligado a essa porta."
        action = "Cheque cabo, SFP, energia do equipamento remoto e historico de link up/down."
    else:
        summary = first_text(details.get("summary"), problem.description, default=f"Incidente {problem_name} detectado.")
        impact = infer_impact(problem, details)
        action = infer_action(problem, details)

    return {
        "summary": summary,
        "impact": impact,
        "action": action,
        "evidence": evidence_text,
        "commands": commands_text,
        "source": "fallback",
    }


def extract_json_object(value: str) -> Optional[dict[str, Any]]:
    text = str(value or "").strip()
    if not text:
        return None
    candidates = [text]
    if "```" in text:
        candidates.extend(re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S))
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    return None


def ai_operational_sections(
    problem: "AlertProblem",
    details: dict[str, Any],
    *,
    recovery: bool = False,
    context: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    if not alert_ai_enabled() or OllamaClient is None:
        return None
    context = context or {}
    payload = {
        "problem_type": problem.problem_type,
        "problem_name": human_problem_name(problem.problem_type),
        "device_name": problem.device_name,
        "device_ip": problem.device_ip,
        "severity": problem.severity,
        "status": context.get("status") or ("RESOLVED" if recovery else "OPEN"),
        "group_name": context.get("group_name"),
        "affected_context": context.get("affected_context"),
        "interfaces": problem_interfaces(details),
        "vlan": problem_vlan(details),
        "value": context.get("value"),
        "duration": context.get("duration"),
        "recovery_value": context.get("recovery_value"),
        "icmp_state": details.get("icmp_state") or details.get("host_alive_state"),
        "snmp_metrics": split_text_items(details.get("snmp_hints"), limit=4),
        "syslog_events": split_text_items(details.get("raw"), limit=3),
        "evidences": top_evidences(details, limit=5),
        "commands": recommended_commands(problem, details),
        "recovery_evidence": clean_text(details.get("recovery_evidence"), ""),
    }
    system = (
        "Voce eh o assistente operacional do NetGuard. "
        "Use apenas os dados fornecidos. Nao invente fatos, causas, VLANs, portas ou metricas ausentes. "
        "Responda em JSON puro com as chaves: what_happened, impact, action, evidence, commands. "
        "Cada valor deve ser string curta, exceto commands que pode ser array de strings curtas. "
        "Se nao houver evidencias suficientes para causa raiz, inclua exatamente: "
        "\"Nao ha evidencias suficientes para concluir a causa raiz.\""
    )
    prompt = (
        f"Modo: {'recovery' if recovery else 'opening'}\n"
        "Dados do incidente em JSON:\n"
        f"{json.dumps(payload, ensure_ascii=True)}"
    )
    try:
        result = OllamaClient(timeout_sec=alert_ai_timeout_seconds()).generate(
            system=system,
            prompt=prompt,
            temperature=0.1,
            num_predict=300,
        )
    except OllamaClientError:
        return None
    data = extract_json_object(result.response)
    if not data:
        return None
    commands = data.get("commands")
    if isinstance(commands, str):
        commands_list = split_text_items(commands, limit=5)
    elif isinstance(commands, list):
        commands_list = [str(item or "").strip() for item in commands if str(item or "").strip()][:5]
    else:
        commands_list = []
    return {
        "summary": clean_text(data.get("what_happened"), ""),
        "impact": clean_text(data.get("impact"), ""),
        "action": clean_text(data.get("action"), ""),
        "evidence": clean_text(data.get("evidence"), ""),
        "commands": "; ".join(commands_list),
        "source": "ollama",
        "model": getattr(result, "model", ""),
    }


def build_incident_key(device_ip: str, problem_type: str) -> str:
    return f"alert|{device_ip}|{problem_type.lower()}"


def _fingerprint_part(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", text):
        text = text.split("/", 1)[0]
    return re.sub(r"[^a-z0-9_.:-]+", "_", text).strip("_")


def build_notification_fingerprint(problem: Any) -> str:
    details = dict(problem.details or {})
    for key in ("notification_fingerprint", "incident_fingerprint", "loop_fingerprint", "fingerprint"):
        explicit = _fingerprint_part(details.get(key))
        if explicit:
            return explicit

    context_values = []
    for key in ("interface_pair", "affected_context", "ifName", "iface", "interface", "item", "key", "vlan"):
        value = details.get(key)
        if isinstance(value, (list, tuple)):
            context_values.extend(value)
        else:
            context_values.append(value)

    contexts = sorted({_fingerprint_part(value) for value in context_values if _fingerprint_part(value)})
    context = "+".join(contexts[:6]) or "host"
    return "|".join(
        part
        for part in (
            _fingerprint_part(problem.device_ip),
            _fingerprint_part(problem.problem_type),
            context,
        )
        if part
    )


def notification_fingerprint_has_specific_context(fingerprint: str) -> bool:
    text = str(fingerprint or "").strip().lower()
    if not text:
        return False
    return not text.endswith("|host")


def safe_identifier(value: str, fallback: str) -> str:
    candidate = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate):
        return candidate
    return fallback


@dataclass(frozen=True)
class AlertConfig:
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    alert_email_to: str = ""
    smtp_use_tls: bool = True
    webhook_enabled: bool = False
    webhook_provider: str = "discord"
    discord_webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_parse_mode: str = ""
    slack_webhook_url: str = ""
    msteams_webhook_url: str = ""
    google_chat_webhook_url: str = ""
    mattermost_webhook_url: str = ""
    mattermost_username: str = "NetGuard"
    rocketchat_webhook_url: str = ""
    rocketchat_alias: str = "NetGuard"
    pushover_app_token: str = ""
    pushover_user_key: str = ""
    pushover_device: str = ""
    pushover_priority: int = 0
    pushover_sound: str = ""
    generic_webhook_url: str = ""
    generic_webhook_headers: dict[str, str] = field(default_factory=dict)
    anti_spam_minutes: int = DEFAULT_ANTI_SPAM_MINUTES


def load_alert_config() -> AlertConfig:
    smtp_port = env_int("SMTP_PORT", 587)
    return AlertConfig(
        email_enabled=env_bool("ALERT_EMAIL_ENABLED", False),
        smtp_host=os.getenv("SMTP_HOST", "").strip(),
        smtp_port=smtp_port,
        smtp_user=os.getenv("SMTP_USER", "").strip(),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_from=os.getenv("SMTP_FROM", "").strip(),
        alert_email_to=os.getenv("ALERT_EMAIL_TO", "").strip(),
        smtp_use_tls=env_bool("SMTP_USE_TLS", smtp_port != 25),
        webhook_enabled=env_bool("ALERT_WEBHOOK_ENABLED", False),
        webhook_provider=os.getenv("WEBHOOK_PROVIDER", "discord").strip().lower(),
        discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", "").strip(),
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", "").strip(),
        telegram_parse_mode=os.getenv("TELEGRAM_PARSE_MODE", "").strip(),
        anti_spam_minutes=max(1, env_int("ALERT_ANTI_SPAM_MINUTES", DEFAULT_ANTI_SPAM_MINUTES)),
    )


@dataclass(frozen=True)
class AlertProblem:
    device_name: str
    device_ip: str
    problem_type: str
    description: str
    severity: str
    details: dict[str, Any] = field(default_factory=dict)
    detected_at: Optional[datetime] = None

    def normalized(self) -> "AlertProblem":
        device_name = str(self.device_name or "").strip()
        device_ip = str(self.device_ip or "").strip()
        description = str(self.description or "").strip()
        details = dict(self.details or {})
        if not device_name:
            raise ValueError("device_name is required")
        if not device_ip:
            raise ValueError("device_ip is required")
        if not description:
            raise ValueError("description is required")
        return AlertProblem(
            device_name=device_name,
            device_ip=device_ip,
            problem_type=normalize_problem_type(self.problem_type),
            description=description,
            severity=normalize_severity(self.severity),
            details=details,
            detected_at=ensure_aware_utc(self.detected_at) if self.detected_at else None,
        )


@dataclass(frozen=True)
class AlertNotification:
    title: str
    body: str
    problem: AlertProblem
    incident_id: Optional[int]
    status: str
    timestamp: datetime
    recovery: bool = False
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AlertChannel:
    id: Optional[int]
    name: str
    provider: str
    enabled: bool
    min_severity: str
    config: dict[str, Any]

    def normalized(self) -> "AlertChannel":
        provider = str(self.provider or "").strip().lower()
        if provider not in ALERT_CHANNEL_PROVIDERS:
            allowed = ", ".join(sorted(ALERT_CHANNEL_PROVIDERS))
            raise ValueError(f"provider must be one of {allowed}")
        name = str(self.name or provider).strip() or provider
        return AlertChannel(
            id=self.id,
            name=name,
            provider=provider,
            enabled=bool(self.enabled),
            min_severity=normalize_severity(self.min_severity or "LOW"),
            config=dict(self.config or {}),
        )


@dataclass
class NotificationResult:
    channel: str
    provider: Optional[str]
    status: str
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "provider": self.provider,
            "status": self.status,
            "error": self.error,
        }


@dataclass
class AlertResult:
    incident: dict[str, Any]
    created: bool
    updated: bool
    notification_sent: bool
    notification_suppressed: bool
    notification_results: list[NotificationResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident.get("id"),
            "status": output_status(self.incident.get("status")),
            "severity": str(self.incident.get("severity") or "").upper(),
            "notification_sent": self.notification_sent,
            "notification_suppressed": self.notification_suppressed,
            "created": self.created,
            "updated": self.updated,
            "incident": serialize_value(self.incident),
            "notifications": [item.to_dict() for item in self.notification_results],
        }


class SmtpEmailSender:
    def __init__(self, config: AlertConfig):
        self.config = config

    def send(self, notification: AlertNotification) -> None:
        recipients = [item.strip() for item in self.config.alert_email_to.split(",") if item.strip()]
        if not self.config.smtp_host or not self.config.smtp_from or not recipients:
            raise RuntimeError("SMTP_HOST, SMTP_FROM and ALERT_EMAIL_TO must be configured")

        message = EmailMessage()
        message["Subject"] = notification.title
        message["From"] = self.config.smtp_from
        message["To"] = ", ".join(recipients)
        message.set_content(notification.body)

        with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=10) as smtp:
            if self.config.smtp_use_tls:
                smtp.starttls()
            if self.config.smtp_user or self.config.smtp_password:
                smtp.login(self.config.smtp_user, self.config.smtp_password)
            smtp.send_message(message)


def channel_alert_config(channel: AlertChannel) -> AlertConfig:
    resolved = channel.normalized()
    config = resolved.config or {}

    if resolved.provider == "email":
        return AlertConfig(
            email_enabled=True,
            smtp_host=str(config.get("smtp_host") or "").strip(),
            smtp_port=int(config.get("smtp_port") or 587),
            smtp_user=str(config.get("smtp_user") or "").strip(),
            smtp_password=str(config.get("smtp_password") or ""),
            smtp_from=str(config.get("smtp_from") or "").strip(),
            alert_email_to=str(config.get("alert_email_to") or "").strip(),
            smtp_use_tls=bool(config.get("use_tls", True)),
        )

    if resolved.provider == "discord":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="discord",
            discord_webhook_url=str(config.get("webhook_url") or "").strip(),
        )

    if resolved.provider == "telegram":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="telegram",
            telegram_bot_token=str(config.get("bot_token") or "").strip(),
            telegram_chat_id=str(config.get("chat_id") or "").strip(),
            telegram_parse_mode=str(config.get("parse_mode") or "").strip(),
        )

    if resolved.provider == "slack":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="slack",
            slack_webhook_url=str(config.get("webhook_url") or "").strip(),
        )

    if resolved.provider == "msteams":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="msteams",
            msteams_webhook_url=str(config.get("webhook_url") or "").strip(),
        )

    if resolved.provider == "google_chat":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="google_chat",
            google_chat_webhook_url=str(config.get("webhook_url") or "").strip(),
        )

    if resolved.provider == "mattermost":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="mattermost",
            mattermost_webhook_url=str(config.get("webhook_url") or "").strip(),
            mattermost_username=str(config.get("username") or "NetGuard").strip(),
        )

    if resolved.provider == "rocketchat":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="rocketchat",
            rocketchat_webhook_url=str(config.get("webhook_url") or "").strip(),
            rocketchat_alias=str(config.get("alias") or "NetGuard").strip(),
        )

    if resolved.provider == "pushover":
        return AlertConfig(
            webhook_enabled=True,
            webhook_provider="pushover",
            pushover_app_token=str(config.get("app_token") or "").strip(),
            pushover_user_key=str(config.get("user_key") or "").strip(),
            pushover_device=str(config.get("device") or "").strip(),
            pushover_priority=int(config.get("priority") or 0),
            pushover_sound=str(config.get("sound") or "").strip(),
        )

    return AlertConfig(
        webhook_enabled=True,
        webhook_provider="webhook",
        generic_webhook_url=str(config.get("webhook_url") or "").strip(),
        generic_webhook_headers={
            str(key): str(value)
            for key, value in (config.get("headers") or {}).items()
            if str(key).strip()
        } if isinstance(config.get("headers"), dict) else {},
    )


def env_alert_channels(config: AlertConfig) -> list[AlertChannel]:
    channels: list[AlertChannel] = []
    if config.email_enabled:
        channels.append(
            AlertChannel(
                id=None,
                name="E-mail SMTP",
                provider="email",
                enabled=True,
                min_severity="LOW",
                config={
                    "smtp_host": config.smtp_host,
                    "smtp_port": config.smtp_port,
                    "smtp_user": config.smtp_user,
                    "smtp_password": config.smtp_password,
                    "smtp_from": config.smtp_from,
                    "alert_email_to": config.alert_email_to,
                    "use_tls": config.smtp_use_tls,
                },
            )
        )

    if config.webhook_enabled and config.webhook_provider.lower() == "discord":
        channels.append(
            AlertChannel(
                id=None,
                name="Discord Webhook",
                provider="discord",
                enabled=True,
                min_severity="LOW",
                config={"webhook_url": config.discord_webhook_url},
            )
        )

    if config.webhook_enabled and config.webhook_provider.lower() == "telegram":
        channels.append(
            AlertChannel(
                id=None,
                name="Telegram Bot",
                provider="telegram",
                enabled=True,
                min_severity="LOW",
                config={
                    "bot_token": config.telegram_bot_token,
                    "chat_id": config.telegram_chat_id,
                    "parse_mode": config.telegram_parse_mode,
                },
            )
        )

    return channels


class WebhookSender:
    def __init__(self, config: AlertConfig):
        self.config = config

    def send(self, notification: AlertNotification) -> None:
        provider = self.config.webhook_provider.lower()
        if provider == "discord":
            self._send_discord(notification)
            return
        if provider == "telegram":
            self._send_telegram(notification)
            return
        if provider == "slack":
            self._send_slack(notification)
            return
        if provider == "msteams":
            self._send_msteams(notification)
            return
        if provider == "google_chat":
            self._send_google_chat(notification)
            return
        if provider == "mattermost":
            self._send_mattermost(notification)
            return
        if provider == "rocketchat":
            self._send_rocketchat(notification)
            return
        if provider == "pushover":
            self._send_pushover(notification)
            return
        if provider == "webhook":
            self._send_generic_webhook(notification)
            return
        allowed = ", ".join(sorted(ALERT_CHANNEL_PROVIDERS - {"email"}))
        raise RuntimeError(f"WEBHOOK_PROVIDER must be one of {allowed}")

    def _post_json(self, url: str, payload: dict[str, Any], headers: Optional[dict[str, str]] = None) -> None:
        if not url:
            raise RuntimeError("Webhook URL is not configured")
        data = json.dumps(payload).encode("utf-8")
        request_headers = {
            "Content-Type": "application/json",
            "User-Agent": "NetGuard-AlertService/1.0",
        }
        request_headers.update(headers or {})
        request = Request(
            url,
            data=data,
            headers=request_headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Webhook returned HTTP {response.status}")
        except HTTPError as exc:
            detail = ""
            try:
                error_payload = json.loads(exc.read().decode("utf-8") or "{}")
                retry_after = error_payload.get("parameters", {}).get("retry_after")
                if retry_after is not None:
                    detail = f"; retry_after={retry_after}s"
            except Exception:
                detail = ""
            raise RuntimeError(f"Webhook returned HTTP {exc.code}{detail}") from exc
        except URLError as exc:
            raise RuntimeError(str(exc.reason)) from exc

    def _post_form(self, url: str, payload: dict[str, Any]) -> None:
        data = urlencode(payload).encode("utf-8")
        request = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "NetGuard-AlertService/1.0",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Webhook returned HTTP {response.status}")
        except HTTPError as exc:
            detail = ""
            try:
                error_payload = json.loads(exc.read().decode("utf-8") or "{}")
                retry_after = error_payload.get("parameters", {}).get("retry_after")
                if retry_after is not None:
                    detail = f"; retry_after={retry_after}s"
            except Exception:
                detail = ""
            raise RuntimeError(f"Webhook returned HTTP {exc.code}{detail}") from exc
        except URLError as exc:
            raise RuntimeError(str(exc.reason)) from exc

    def _message_text(self, notification: AlertNotification) -> str:
        return f"{notification.title}\n\n{notification.body}"

    def _severity_color(self, severity: str) -> str:
        return {
            "LOW": "439FE0",
            "MEDIUM": "FFB020",
            "HIGH": "FF7A00",
            "CRITICAL": "E81123",
        }.get(normalize_severity(severity), "439FE0")

    def _notification_facts(self, notification: AlertNotification) -> list[dict[str, str]]:
        problem = notification.problem
        return [
            {"title": "Dispositivo", "value": problem.device_name},
            {"title": "IP", "value": problem.device_ip},
            {"title": "Problema", "value": problem.problem_type},
            {"title": "Severidade", "value": problem.severity},
            {"title": "Status", "value": notification.status},
            {"title": "Data/Hora", "value": notification.timestamp.isoformat()},
        ]

    def _send_discord(self, notification: AlertNotification) -> None:
        content = f"**{notification.title}**\n{notification.body}"
        self._post_json(self.config.discord_webhook_url, {"content": content})

    def _send_telegram(self, notification: AlertNotification) -> None:
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be configured")
        token = quote(self.config.telegram_bot_token, safe=":")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        parse_mode = self.config.telegram_parse_mode or "HTML"
        if str(parse_mode or "").strip().lower() == "html":
            text = build_telegram_alert_html(notification)
        else:
            text = telegram_text_for_parse_mode(f"{notification.title}\n\n{notification.body}", parse_mode)
        self._post_json(
            url,
            {
                "chat_id": self.config.telegram_chat_id,
                "text": text,
                **({"parse_mode": parse_mode} if parse_mode else {}),
                "disable_web_page_preview": True,
            },
        )

    def _send_slack(self, notification: AlertNotification) -> None:
        payload = {
            "text": self._message_text(notification),
            "attachments": [
                {
                    "color": f"#{self._severity_color(notification.problem.severity)}",
                    "fields": [
                        {"title": item["title"], "value": item["value"], "short": True}
                        for item in self._notification_facts(notification)
                    ],
                }
            ],
        }
        self._post_json(self.config.slack_webhook_url, payload)

    def _send_msteams(self, notification: AlertNotification) -> None:
        facts = [{"title": item["title"], "value": item["value"]} for item in self._notification_facts(notification)]
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": notification.title,
                                "weight": "Bolder",
                                "size": "Medium",
                                "wrap": True,
                            },
                            {"type": "FactSet", "facts": facts},
                            {"type": "TextBlock", "text": notification.problem.description, "wrap": True},
                        ],
                    },
                }
            ],
        }
        self._post_json(self.config.msteams_webhook_url, payload)

    def _send_google_chat(self, notification: AlertNotification) -> None:
        self._post_json(self.config.google_chat_webhook_url, {"text": self._message_text(notification)})

    def _send_mattermost(self, notification: AlertNotification) -> None:
        self._post_json(self.config.mattermost_webhook_url, {"username": self.config.mattermost_username or "NetGuard", "text": self._message_text(notification)})

    def _send_rocketchat(self, notification: AlertNotification) -> None:
        self._post_json(self.config.rocketchat_webhook_url, {"alias": self.config.rocketchat_alias or "NetGuard", "text": self._message_text(notification)})

    def _send_pushover(self, notification: AlertNotification) -> None:
        if not self.config.pushover_app_token or not self.config.pushover_user_key:
            raise RuntimeError("Pushover app_token and user_key must be configured")
        payload = {
            "token": self.config.pushover_app_token,
            "user": self.config.pushover_user_key,
            "title": notification.title,
            "message": notification.body,
            "priority": str(self.config.pushover_priority),
        }
        if self.config.pushover_device:
            payload["device"] = self.config.pushover_device
        if self.config.pushover_sound:
            payload["sound"] = self.config.pushover_sound
        self._post_form(
            "https://api.pushover.net/1/messages.json",
            payload,
        )

    def _send_generic_webhook(self, notification: AlertNotification) -> None:
        self._post_json(
            self.config.generic_webhook_url,
            {
                "title": notification.title,
                "body": notification.body,
                "status": notification.status,
                "severity": notification.problem.severity,
                "device_name": notification.problem.device_name,
                "device_ip": notification.problem.device_ip,
                "problem_type": notification.problem.problem_type,
                "description": notification.problem.description,
                "timestamp": notification.timestamp.isoformat(),
                "incident_id": notification.incident_id,
                "recovery": notification.recovery,
                "context": notification.context,
            },
            headers=self.config.generic_webhook_headers,
        )


class PostgresIncidentRepository:
    def __init__(self, cur, assets_table: str = "assets"):
        self.cur = cur
        self.assets_table = safe_identifier(assets_table, "assets")

    def _row_to_dict(self, row) -> Optional[dict[str, Any]]:
        if row is None:
            return None
        if isinstance(row, dict):
            return dict(row)
        columns = []
        for desc in self.cur.description or []:
            columns.append(getattr(desc, "name", None) or desc[0])
        return {column: row[index] for index, column in enumerate(columns)}

    def _incident_select(self) -> str:
        return """
            SELECT
              id,
              opened_at,
              last_seen_at,
              status,
              hostname,
              src_ip::text AS src_ip,
              incident_type,
              key,
              severity,
              title,
              details,
              asset_id,
              device_name,
              device_ip::text AS device_ip,
              problem_type,
              description,
              first_detected_at,
              last_detected_at,
              resolved_at,
              notification_sent,
              COALESCE(opening_notification_sent, notification_sent, false) AS opening_notification_sent,
              opening_notified_at,
              COALESCE(recovery_notification_sent, false) AS recovery_notification_sent,
              recovery_notified_at,
              last_notification_at,
              notification_fingerprint,
              created_at,
              updated_at
            FROM incidents
        """

    def find_asset_id(self, problem: AlertProblem) -> Optional[int]:
        self.cur.execute(
            f"""
            SELECT id
            FROM {self.assets_table}
            WHERE {ip_text_sql('ip')} = %s
               OR LOWER(name) = LOWER(%s)
            ORDER BY
              CASE WHEN {ip_text_sql('ip')} = %s THEN 0 ELSE 1 END,
              CASE WHEN LOWER(name) = LOWER(%s) THEN 0 ELSE 1 END,
              id
            LIMIT 1
            """,
            (problem.device_ip, problem.device_name, problem.device_ip, problem.device_name),
        )
        row = self.cur.fetchone()
        return int(row[0]) if row else None

    def find_open_incident(self, problem: AlertProblem) -> Optional[dict[str, Any]]:
        fingerprint = build_notification_fingerprint(problem)
        fingerprint_specific = notification_fingerprint_has_specific_context(fingerprint)
        self.cur.execute(
            self._incident_select()
            + f"""
            WHERE {active_status_sql()}
              AND (
                {ip_text_sql('device_ip')} = %s
                OR (device_ip IS NULL AND {ip_text_sql('src_ip')} = %s)
              )
              AND (
                (
                  %s <> ''
                  AND (
                    LOWER(COALESCE(notification_fingerprint, '')) = %s
                    OR LOWER(COALESCE(details->>'notification_fingerprint', '')) = %s
                    OR LOWER(COALESCE(details->>'incident_fingerprint', '')) = %s
                    OR LOWER(COALESCE(details->>'loop_fingerprint', '')) = %s
                    OR LOWER(COALESCE(details->>'fingerprint', '')) = %s
                  )
                )
                OR (
                  (
                    %s = false
                    OR LOWER(COALESCE(
                      notification_fingerprint,
                      details->>'notification_fingerprint',
                      details->>'incident_fingerprint',
                      details->>'loop_fingerprint',
                      details->>'fingerprint',
                      ''
                    )) = ''
                  )
                  AND (
                    UPPER(problem_type) = %s
                    OR (problem_type IS NULL AND LOWER(incident_type) = LOWER(%s))
                  )
                )
              )
            ORDER BY
              CASE
                WHEN %s <> ''
                 AND (
                   LOWER(COALESCE(notification_fingerprint, '')) = %s
                   OR LOWER(COALESCE(details->>'notification_fingerprint', '')) = %s
                   OR LOWER(COALESCE(details->>'incident_fingerprint', '')) = %s
                   OR LOWER(COALESCE(details->>'loop_fingerprint', '')) = %s
                   OR LOWER(COALESCE(details->>'fingerprint', '')) = %s
                 )
                THEN 0
                ELSE 1
              END,
              COALESCE(last_detected_at, last_seen_at, opened_at) DESC,
              id DESC
            LIMIT 1
            """,
            (
                problem.device_ip,
                problem.device_ip,
                fingerprint,
                fingerprint,
                fingerprint,
                fingerprint,
                fingerprint,
                fingerprint,
                fingerprint_specific,
                problem.problem_type,
                problem.problem_type,
                fingerprint,
                fingerprint,
                fingerprint,
                fingerprint,
                fingerprint,
                fingerprint,
            ),
        )
        return self._row_to_dict(self.cur.fetchone())

    def get_incident(self, incident_id: int) -> Optional[dict[str, Any]]:
        self.cur.execute(self._incident_select() + " WHERE id = %s", (incident_id,))
        return self._row_to_dict(self.cur.fetchone())

    def find_recent_notification(self, incident_id: int, since: datetime) -> Optional[dict[str, Any]]:
        self.cur.execute(
            """
            SELECT id, incident_id, channel, provider, delivery_status, error, sent_at
            FROM incident_notifications
            WHERE incident_id = %s
              AND sent_at >= %s
            ORDER BY sent_at DESC, id DESC
            LIMIT 1
            """,
            (incident_id, since),
        )
        return self._row_to_dict(self.cur.fetchone())

    def find_recent_equivalent_notification(self, problem: AlertProblem, since: datetime) -> Optional[dict[str, Any]]:
        fingerprint = build_notification_fingerprint(problem)
        self.cur.execute(
            f"""
            SELECT n.id, n.incident_id, n.channel, n.provider, n.delivery_status, n.error, n.sent_at
            FROM incident_notifications n
            JOIN incidents i ON i.id = n.incident_id
            WHERE n.sent_at >= %s
              AND LOWER(COALESCE(n.delivery_status, '')) = 'success'
              AND LOWER(COALESCE(n.provider, '')) <> 'anti_spam'
              AND (
                LOWER(COALESCE(i.notification_fingerprint, '')) = %s
                OR LOWER(COALESCE(i.details->>'notification_fingerprint', '')) = %s
                OR LOWER(COALESCE(i.details->>'loop_fingerprint', '')) = %s
                OR (
                  (
                    {ip_text_sql('i.device_ip')} = %s
                    OR (i.device_ip IS NULL AND {ip_text_sql('i.src_ip')} = %s)
                  )
                  AND (
                    UPPER(i.problem_type) = %s
                    OR (i.problem_type IS NULL AND LOWER(i.incident_type) = LOWER(%s))
                  )
                )
              )
            ORDER BY n.sent_at DESC, n.id DESC
            LIMIT 1
            """,
            (
                since,
                fingerprint,
                fingerprint,
                fingerprint,
                problem.device_ip,
                problem.device_ip,
                problem.problem_type,
                problem.problem_type,
            ),
        )
        return self._row_to_dict(self.cur.fetchone())

    def has_successful_notification(self, incident_id: int) -> bool:
        self.cur.execute(
            """
            SELECT EXISTS (
              SELECT 1
              FROM incident_notifications
              WHERE incident_id = %s
                AND delivery_status = 'success'
                AND LOWER(COALESCE(provider, '')) <> 'anti_spam'
            )
            """,
            (incident_id,),
        )
        row = self.cur.fetchone()
        return bool(row and row[0])

    def has_recovery_notification_sent(self, incident_id: int) -> bool:
        self.cur.execute(
            """
            SELECT COALESCE(recovery_notification_sent, false)
            FROM incidents
            WHERE id = %s
            """,
            (incident_id,),
        )
        row = self.cur.fetchone()
        return bool(row and row[0])

    def list_active_channels(self) -> list[AlertChannel]:
        if not self.has_alert_channels_table():
            return []

        self.cur.execute(
            """
            SELECT id, name, provider, enabled, min_severity, config
            FROM alert_channels
            WHERE enabled = true
            ORDER BY name, id
            """
        )
        channels: list[AlertChannel] = []
        for row in self.cur.fetchall():
            channel = self._row_to_dict(row) or {}
            try:
                channels.append(
                    AlertChannel(
                        id=channel.get("id"),
                        name=channel.get("name") or channel.get("provider") or "Canal",
                        provider=channel.get("provider") or "",
                        enabled=bool(channel.get("enabled")),
                        min_severity=channel.get("min_severity") or "LOW",
                        config=channel.get("config") or {},
                    ).normalized()
                )
            except ValueError:
                continue
        return channels

    def has_configured_channels(self) -> bool:
        if not self.has_alert_channels_table():
            return False

        self.cur.execute("SELECT EXISTS (SELECT 1 FROM alert_channels)")
        row = self.cur.fetchone()
        return bool(row and row[0])

    def has_alert_channels_table(self) -> bool:
        self.cur.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = 'alert_channels'
            )
            """
        )
        row = self.cur.fetchone()
        return bool(row and row[0])

    def create_incident(self, problem: AlertProblem, detected_at: datetime) -> dict[str, Any]:
        details = incident_details(problem, "OPEN", notification_sent=False, timestamp=detected_at)
        asset_id = self.find_asset_id(problem)
        self.cur.execute(
            self._incident_insert_sql(),
            (
                detected_at,
                detected_at,
                storage_status("OPEN"),
                problem.device_name,
                problem.device_ip,
                problem.problem_type.lower(),
                build_incident_key(problem.device_ip, problem.problem_type),
                problem.severity.lower(),
                ALERT_TITLE,
                json.dumps(details, ensure_ascii=False),
                asset_id,
                problem.device_name,
                problem.device_ip,
                problem.problem_type,
                problem.description,
                detected_at,
                detected_at,
                False,
                False,
                False,
                build_notification_fingerprint(problem),
                detected_at,
                detected_at,
            ),
        )
        return self._row_to_dict(self.cur.fetchone()) or {}

    def _incident_insert_sql(self) -> str:
        return (
            """
            INSERT INTO incidents (
              opened_at,
              last_seen_at,
              status,
              hostname,
              src_ip,
              incident_type,
              key,
              severity,
              title,
              details,
              asset_id,
              device_name,
              device_ip,
              problem_type,
              description,
              first_detected_at,
              last_detected_at,
              notification_sent,
              opening_notification_sent,
              recovery_notification_sent,
              notification_fingerprint,
              created_at,
              updated_at
            )
            VALUES (
              %s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,
              %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
            )
            ON CONFLICT (key) WHERE status = 'open'
            DO UPDATE SET
              last_seen_at = EXCLUDED.last_seen_at,
              last_detected_at = EXCLUDED.last_detected_at,
              updated_at = EXCLUDED.updated_at,
              device_name = EXCLUDED.device_name,
              device_ip = EXCLUDED.device_ip,
              problem_type = EXCLUDED.problem_type,
              description = EXCLUDED.description,
              severity = EXCLUDED.severity,
              title = EXCLUDED.title,
              notification_fingerprint = COALESCE(incidents.notification_fingerprint, EXCLUDED.notification_fingerprint),
              details = incidents.details || (EXCLUDED.details - 'notification_sent' - 'opening_notification_sent')
            RETURNING
              id,
              opened_at,
              last_seen_at,
              status,
              hostname,
              src_ip::text AS src_ip,
              incident_type,
              key,
              severity,
              title,
              details,
              asset_id,
              device_name,
              device_ip::text AS device_ip,
              problem_type,
              description,
              first_detected_at,
              last_detected_at,
              resolved_at,
              notification_sent,
              COALESCE(opening_notification_sent, notification_sent, false) AS opening_notification_sent,
              opening_notified_at,
              COALESCE(recovery_notification_sent, false) AS recovery_notification_sent,
              recovery_notified_at,
              last_notification_at,
              notification_fingerprint,
              created_at,
              updated_at
            """
        )

    def touch_incident_detection(self, incident_id: int, detected_at: datetime) -> dict[str, Any]:
        self.cur.execute(
            self._incident_update_returning(
                """
                UPDATE incidents
                SET
                  last_seen_at = %s,
                  last_detected_at = %s,
                  updated_at = %s
                WHERE id = %s
                """
            ),
            (detected_at, detected_at, detected_at, incident_id),
        )
        return self._row_to_dict(self.cur.fetchone()) or {}

    def update_incident_for_notification(
        self,
        incident_id: int,
        problem: AlertProblem,
        detected_at: datetime,
    ) -> dict[str, Any]:
        details = incident_details(problem, "OPEN", notification_sent=False, timestamp=detected_at)
        self.cur.execute(
            self._incident_update_returning(
                """
                UPDATE incidents
                SET
                  last_seen_at = %s,
                  last_detected_at = %s,
                  updated_at = %s,
                  device_name = %s,
                  device_ip = %s,
                  hostname = %s,
                  src_ip = %s,
                  problem_type = %s,
                  incident_type = %s,
                  description = %s,
                  severity = %s,
                  title = %s,
                  notification_fingerprint = COALESCE(notification_fingerprint, %s),
                  details = details || (%s::jsonb - 'notification_sent' - 'opening_notification_sent')
                WHERE id = %s
                """
            ),
            (
                detected_at,
                detected_at,
                detected_at,
                problem.device_name,
                problem.device_ip,
                problem.device_name,
                problem.device_ip,
                problem.problem_type,
                problem.problem_type.lower(),
                problem.description,
                problem.severity.lower(),
                ALERT_TITLE,
                build_notification_fingerprint(problem),
                json.dumps(details, ensure_ascii=False),
                incident_id,
            ),
        )
        return self._row_to_dict(self.cur.fetchone()) or {}

    def mark_notification_sent(self, incident_id: int, sent: bool, sent_at: datetime) -> dict[str, Any]:
        details = {
            "last_opening_notification_attempt_at": sent_at.isoformat(),
        }
        if sent:
            details.update(
                {
                    "notification_sent": True,
                    "opening_notification_sent": True,
                    "last_notification_at": sent_at.isoformat(),
                }
            )
        self.cur.execute(
            self._incident_update_returning(
                """
                UPDATE incidents
                SET
                  notification_sent = notification_sent OR %s,
                  opening_notification_sent = opening_notification_sent OR %s,
                  opening_notified_at = CASE
                    WHEN %s AND opening_notified_at IS NULL THEN %s
                    ELSE opening_notified_at
                  END,
                  last_notification_at = CASE
                    WHEN %s THEN %s
                    ELSE last_notification_at
                  END,
                  updated_at = %s,
                  details = details || %s::jsonb
                WHERE id = %s
                """
            ),
            (
                bool(sent),
                bool(sent),
                bool(sent),
                sent_at,
                bool(sent),
                sent_at,
                sent_at,
                json.dumps(details, ensure_ascii=False),
                incident_id,
            ),
        )
        return self._row_to_dict(self.cur.fetchone()) or {}

    def mark_recovery_notification_sent(self, incident_id: int, sent_at: datetime) -> dict[str, Any]:
        details = {
            "recovery_notification_sent": True,
            "recovery_notified_at": sent_at.isoformat(),
            "last_notification_at": sent_at.isoformat(),
        }
        self.cur.execute(
            self._incident_update_returning(
                """
                UPDATE incidents
                SET
                  recovery_notification_sent = true,
                  recovery_notified_at = COALESCE(recovery_notified_at, %s),
                  last_notification_at = %s,
                  updated_at = %s,
                  details = details || %s::jsonb
                WHERE id = %s
                """
            ),
            (sent_at, sent_at, sent_at, json.dumps(details, ensure_ascii=False), incident_id),
        )
        return self._row_to_dict(self.cur.fetchone()) or {}

    def mark_recovery_notification_suppressed(self, incident_id: int, suppressed_at: datetime, reason: str) -> dict[str, Any]:
        details = {
            "recovery_notification_suppressed": True,
            "recovery_notification_suppressed_at": suppressed_at.isoformat(),
            "recovery_notification_suppression_reason": reason,
        }
        self.cur.execute(
            self._incident_update_returning(
                """
                UPDATE incidents
                SET
                  updated_at = %s,
                  details = details || %s::jsonb
                WHERE id = %s
                """
            ),
            (suppressed_at, json.dumps(details, ensure_ascii=False), incident_id),
        )
        return self._row_to_dict(self.cur.fetchone()) or {}

    def resolve_incident(self, incident_id: int, resolved_at: datetime) -> Optional[dict[str, Any]]:
        details = {"status": "RESOLVED", "resolved_at": resolved_at.isoformat()}
        self.cur.execute(
            self._incident_update_returning(
                """
                UPDATE incidents
                SET
                  status = 'resolved',
                  resolved_at = %s,
                  last_seen_at = %s,
                  updated_at = %s,
                  details = details || %s::jsonb
                WHERE id = %s
                  AND LOWER(status) <> 'resolved'
                """
            ),
            (resolved_at, resolved_at, resolved_at, json.dumps(details, ensure_ascii=False), incident_id),
        )
        updated = self._row_to_dict(self.cur.fetchone())
        if updated is not None:
            return updated
        return self.get_incident(incident_id)

    def _incident_update_returning(self, update_sql: str) -> str:
        return (
            update_sql
            + """
            RETURNING
              id,
              opened_at,
              last_seen_at,
              status,
              hostname,
              src_ip::text AS src_ip,
              incident_type,
              key,
              severity,
              title,
              details,
              asset_id,
              device_name,
              device_ip::text AS device_ip,
              problem_type,
              description,
              first_detected_at,
              last_detected_at,
              resolved_at,
              notification_sent,
              COALESCE(opening_notification_sent, notification_sent, false) AS opening_notification_sent,
              opening_notified_at,
              COALESCE(recovery_notification_sent, false) AS recovery_notification_sent,
              recovery_notified_at,
              last_notification_at,
              notification_fingerprint,
              created_at,
              updated_at
            """
        )

    def record_notification_result(self, incident_id: Optional[int], result: NotificationResult, sent_at: datetime) -> None:
        self.cur.execute(
            """
            INSERT INTO incident_notifications (
              incident_id,
              channel,
              provider,
              delivery_status,
              error,
              sent_at
            )
            VALUES (%s,%s,%s,%s,%s,%s)
            """,
            (incident_id, result.channel, result.provider, result.status, result.error, sent_at),
        )


def incident_details(
    problem: AlertProblem,
    status: str,
    *,
    notification_sent: bool,
    timestamp: datetime,
) -> dict[str, Any]:
    extra_details = dict(problem.details or {})
    base_details = {
        "source": "alert_service",
        "device_name": problem.device_name,
        "device_ip": problem.device_ip,
        "problem_type": problem.problem_type,
        "notification_fingerprint": build_notification_fingerprint(problem),
        "description": problem.description,
        "severity": problem.severity,
        "status": output_status(status),
        "notification_sent": bool(notification_sent),
        "opening_notification_sent": bool(notification_sent),
        "detected_at": timestamp.isoformat(),
        "recommendation": problem.description,
    }
    return {**base_details, **extra_details}


def parse_datetime_value(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def incident_details_dict(incident: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not incident:
        return {}
    details = incident.get("details")
    return details if isinstance(details, dict) else {}


def opening_notification_was_sent(incident: Optional[dict[str, Any]]) -> bool:
    details = incident_details_dict(incident)
    return bool(
        incident
        and (
            incident.get("opening_notification_sent")
            or incident.get("notification_sent")
            or details.get("opening_notification_sent")
            or details.get("notification_sent")
        )
    )


def recovery_notification_was_sent(incident: Optional[dict[str, Any]]) -> bool:
    details = incident_details_dict(incident)
    return bool(incident and (incident.get("recovery_notification_sent") or details.get("recovery_notification_sent")))


def recovery_notification_was_suppressed(incident: Optional[dict[str, Any]]) -> bool:
    details = incident_details_dict(incident)
    return bool(incident and details.get("recovery_notification_suppressed"))


def netguard_incident_url(incident_id: Optional[int]) -> str:
    base_url = os.getenv("NETGUARD_PUBLIC_URL", DEFAULT_NETGUARD_PUBLIC_URL).strip().rstrip("/")
    if not base_url:
        return "-"
    if incident_id:
        return f"{base_url}/monitoring/alerts?incident_id={incident_id}"
    return f"{base_url}/monitoring/alerts"


def notification_problem_name(problem: AlertProblem, incident: Optional[dict[str, Any]] = None) -> str:
    details = incident_details_dict(incident)
    for value in (
        details.get("problem_name"),
        details.get("trigger"),
        incident.get("title") if incident else None,
        problem.problem_type,
    ):
        text = str(value or "").strip()
        if text and not text.lower().startswith("[netguard]"):
            return human_problem_name(text)
    return human_problem_name(problem.problem_type)


def human_problem_name(value: Any) -> str:
    raw = str(value or "").strip()
    normalized = raw.upper()
    labels = {
        "HOST_DOWN": "Host indisponível",
        "SNMP_COLLECTION_SILENCE": "Sem telemetria SNMP recente",
        "ICMP_COLLECTION_SILENCE": "Sem telemetria ICMP recente",
        "SYSLOG_COLLECTION_SILENCE": "Sem eventos syslog recentes",
        "LOOP_RISK": "Risco de loop L2",
        "BROADCAST_STORM": "Broadcast storm",
        "MAC_FLAPPING": "MAC flapping",
        "INTERFACE_FLAP": "Interface oscilando",
        "TEST_NOTIFICATION": "Teste de notificação",
    }
    labels.update(
        {
            "HOST_DOWN": "Host indisponivel",
            "INTERFACE_FLAP": "Oscilacao de interface",
            "TEST_NOTIFICATION": "Teste de notificacao",
        }
    )
    if normalized in labels:
        return labels[normalized]
    return raw.replace("_", " ").strip().title() or "Incidente"


def notification_item(problem: AlertProblem, incident: Optional[dict[str, Any]] = None) -> str:
    details = incident_details_dict(incident)
    for value in (
        details.get("item"),
        details.get("ifName"),
        details.get("metric"),
        details.get("key"),
        problem.problem_type,
    ):
        text = str(value or "").strip()
        if text:
            return text
    return problem.problem_type


def first_text(*values: Any, default: str = "-") -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return default


def compact_items(values: Any, *, limit: int = 4) -> str:
    if not isinstance(values, (list, tuple)):
        return ""

    items: list[str] = []
    for value in values:
        if isinstance(value, dict):
            label = first_text(value.get("label"), value.get("signal"), value.get("metric"), default="")
            focus = first_text(value.get("focus"), value.get("key"), value.get("ifName"), default="")
            count = value.get("count")
            score = value.get("score_pct")
            text = label
            if focus and focus != "host":
                text = f"{text} em {focus}" if text else focus
            if score is not None:
                text = f"{text} ({score}%)"
            elif count and int(count or 0) > 1:
                text = f"{text} x{count}"
        else:
            text = str(value or "").strip()

        if text and text not in items:
            items.append(text)

    if not items:
        return ""

    visible = items[:limit]
    suffix = f"; +{len(items) - limit} sinais" if len(items) > limit else ""
    return "; ".join(visible) + suffix


def infer_affected_context(problem: AlertProblem, details: dict[str, Any]) -> str:
    return first_text(
        details.get("affected_context"),
        compact_items(details.get("affected_contexts"), limit=3),
        details.get("interface_pair"),
        details.get("ifName"),
        details.get("iface"),
        details.get("key"),
        notification_item(problem, {"details": details}),
        default="Host",
    )


def infer_evidence_summary(details: dict[str, Any]) -> str:
    return first_text(
        details.get("evidence_summary"),
        compact_items(details.get("signal_contexts"), limit=4),
        compact_items(details.get("top_predictions"), limit=4),
        compact_items(details.get("evidences"), limit=4),
        compact_items(details.get("snmp_hints"), limit=4),
        details.get("raw"),
        default="Sem evidência adicional registrada.",
    )


def infer_impact(problem: AlertProblem, details: dict[str, Any]) -> str:
    problem_type = str(problem.problem_type or "").upper()
    source = str(details.get("source") or "").lower()
    metric = str(details.get("metric") or details.get("item") or "").lower()

    if "LOOP_RISK" in problem_type:
        return "Pode causar instabilidade no segmento, broadcast storm, perda de pacotes e queda intermitente de portas."
    if "BROADCAST_STORM" in problem_type:
        return "Pode degradar a VLAN ou o domínio L2, aumentando latência, perda e uso de CPU nos switches."
    if "MAC_FLAPPING" in problem_type:
        return "Indica MAC alternando entre portas; pode ser loop físico, redundância indevida ou agregação incorreta."
    if "INTERFACE_FLAP" in problem_type or "LINEPROTO" in problem_type:
        return "A porta está oscilando e pode afetar conectividade do dispositivo ou do enlace conectado."
    if source == "prediction_signal" or "PREDICT" in problem_type:
        return "Há tendência anômala em métricas de interface; ainda é preditivo, mas merece verificação antes de virar incidente maior."
    if "errors" in metric or "discards" in metric:
        return "Pode indicar cabo, SFP, duplex, fila, saturação ou descarte por congestionamento."
    return first_text(details.get("impact"), default="Evento relevante para investigação operacional.")


def infer_action(problem: AlertProblem, details: dict[str, Any]) -> str:
    problem_type = str(problem.problem_type or "").upper()
    source = str(details.get("source") or "").lower()
    metric = str(details.get("metric") or details.get("item") or "").lower()

    if "LOOP_RISK" in problem_type:
        return "Verifique STP/Loop Guard, isole uma das portas suspeitas e confirme se storm, MAC flapping e flap cessam."
    if "BROADCAST_STORM" in problem_type:
        return "Identifique a porta/VLAN de origem, valide STP e storm-control, e isole a porta se o tráfego continuar subindo."
    if "MAC_FLAPPING" in problem_type:
        return "Confira as portas envolvidas, agregação, redundância física e possibilidade de loop entre switches."
    if "INTERFACE_FLAP" in problem_type or "LINEPROTO" in problem_type:
        return "Verifique cabo/SFP, speed/duplex, energia do equipamento remoto e histórico de link up/down."
    if source == "prediction_signal" or "PREDICT" in problem_type:
        return "Abra o host no NetGuard, compare as interfaces do resumo e priorize as de maior score antes de atuar fisicamente."
    if "errors" in metric or "discards" in metric:
        return "Cheque contadores da interface, cabo/SFP, velocidade/duplex, fila e saturação."
    return first_text(details.get("action"), details.get("recommendation"), default="Verifique o host no NetGuard e correlacione com eventos recentes.")


def default_recovery_value(problem: AlertProblem, details: dict[str, Any]) -> str:
    explicit = details.get("recovery_value")
    if explicit:
        return clean_text(explicit)

    problem_type = str(problem.problem_type or "").upper()
    source = str(details.get("source") or "").lower()
    if source == "syslog_signal" or problem_type.startswith("SYSLOG_"):
        return "Evento syslog encerrado"
    if "LOOP_RISK" in problem_type or "LOOP" in problem_type:
        return "Sinal de loop normalizado"
    return "Up (1)"


def build_template_context(
    problem: AlertProblem,
    timestamp: datetime,
    status: str,
    *,
    incident: Optional[dict[str, Any]] = None,
    recovery: bool = False,
) -> dict[str, Any]:
    details = incident_details_dict(incident)
    started_at = (
        parse_datetime_value(incident.get("first_detected_at")) if incident else None
    ) or (
        parse_datetime_value(incident.get("opened_at")) if incident else None
    ) or problem.detected_at or timestamp
    resolved_at = (
        parse_datetime_value(incident.get("resolved_at")) if incident else None
    ) or (timestamp if recovery else None)
    group_name = (
        details.get("group_name")
        or details.get("group")
        or incident.get("group_name") if incident else None
    )
    problem_name = notification_problem_name(problem, incident)
    value = details.get("value") or details.get("opdata") or ("Up (1)" if recovery else "Down (0)")
    summary = first_text(
        details.get("summary"),
        details.get("opening_reason"),
        details.get("recommendation"),
        problem.description,
        problem_name,
    )
    affected_context = infer_affected_context(problem, details)
    base_context = {
        "incident_id": incident.get("id") if incident else "",
        "device_name": problem.device_name,
        "device_ip": problem.device_ip,
        "host": problem.device_name,
        "ip": problem.device_ip,
        "group_name": clean_text(group_name, "Sem grupo"),
        "problem_type": problem.problem_type,
        "problem_name": problem_name,
        "description": problem.description,
        "summary": clean_text(summary),
        "item": notification_item(problem, incident),
        "trigger": problem.problem_type,
        "severity": problem.severity,
        "severity_label": severity_label(problem.severity),
        "status": output_status(status),
        "value": clean_text(value),
        "impact": clean_text(infer_impact(problem, details)),
        "action": clean_text(infer_action(problem, details)),
        "evidence_summary": clean_text(infer_evidence_summary(details)),
        "affected_context": clean_text(affected_context),
        "recovery_value": default_recovery_value(problem, details),
        "started_at": format_alert_datetime(started_at),
        "started_at_short": format_alert_short_datetime(started_at),
        "resolved_at": format_alert_datetime(resolved_at),
        "timestamp": format_alert_datetime(timestamp),
        "timestamp_short": format_alert_short_datetime(timestamp),
        "duration": format_duration(started_at, resolved_at or timestamp),
        "incident_url": netguard_incident_url(incident.get("id") if incident else None),
    }
    operational = ai_operational_sections(problem, details, recovery=recovery, context=base_context)
    if operational is None:
        operational = fallback_operational_sections(problem, details, recovery=recovery, context=base_context)
    base_context.update(
        {
            "friendly_summary": clean_text(operational.get("summary"), base_context["summary"]),
            "friendly_impact": clean_text(operational.get("impact"), base_context["impact"]),
            "friendly_action": clean_text(operational.get("action"), base_context["action"]),
            "friendly_evidence": clean_text(operational.get("evidence"), base_context["evidence_summary"]),
            "friendly_commands": clean_text(
                operational.get("commands"),
                "Abra o host no NetGuard para ver mais detalhes.",
            ),
            "text_source": clean_text(operational.get("source"), "fallback"),
            "text_model": clean_text(operational.get("model"), "-"),
        }
    )
    return base_context

class TemplateContext(dict):
    def __missing__(self, key):
        return ""


def render_alert_template(template: str, context: dict[str, Any]) -> str:
    values = TemplateContext({key: clean_text(value, "") for key, value in context.items()})
    return str(template or "").format_map(values).strip()


def build_alert_title(
    problem: AlertProblem,
    timestamp: datetime,
    status: str,
    *,
    incident: Optional[dict[str, Any]] = None,
    recovery: bool = False,
) -> str:
    context = build_template_context(problem, timestamp, status, incident=incident, recovery=recovery)
    if recovery:
        return f"[NetGuard] Recuperado: {context['problem_name']}"
    return f"[NetGuard] {context['severity_label']}: {context['problem_name']}"


def build_alert_body(
    problem: AlertProblem,
    timestamp: datetime,
    status: str,
    *,
    incident: Optional[dict[str, Any]] = None,
    recovery: bool = False,
) -> str:
    context = build_template_context(problem, timestamp, status, incident=incident, recovery=recovery)
    template = DEFAULT_RECOVERY_TEMPLATE if recovery else DEFAULT_PROBLEM_TEMPLATE
    return render_alert_template(template, context)


def notification_with_channel_template(channel: AlertChannel, notification: AlertNotification) -> AlertNotification:
    config = dict(channel.config or {})
    body_template = config.get("recovery_template") if notification.recovery else config.get("problem_template")
    title_template = config.get("recovery_title_template") if notification.recovery else config.get("problem_title_template")
    context = dict(notification.context or {})
    if not context:
        context = build_template_context(
            notification.problem,
            notification.timestamp,
            notification.status,
            recovery=notification.recovery,
        )
    return AlertNotification(
        title=render_alert_template(title_template, context) if title_template else notification.title,
        body=render_alert_template(body_template, context) if body_template else notification.body,
        problem=notification.problem,
        incident_id=notification.incident_id,
        status=notification.status,
        timestamp=notification.timestamp,
        recovery=notification.recovery,
        context=context,
    )


def notification_problem_from_incident(incident: dict[str, Any]) -> AlertProblem:
    severity = str(incident.get("severity") or "LOW").upper()
    legacy_severity_map = {
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "NOTICE": "LOW",
        "INFO": "LOW",
        "ERROR": "HIGH",
        "ERR": "HIGH",
        "FATAL": "CRITICAL",
    }
    severity = legacy_severity_map.get(severity, severity)
    if severity not in ALERT_SEVERITIES:
        severity = "LOW"
    return AlertProblem(
        device_name=str(incident.get("device_name") or incident.get("hostname") or "unknown"),
        device_ip=ip_without_cidr(incident.get("device_ip") or incident.get("src_ip") or "0.0.0.0"),
        problem_type=str(incident.get("problem_type") or incident.get("incident_type") or "INCIDENT"),
        description=str(incident.get("description") or incident.get("title") or "Incidente resolvido"),
        severity=severity,
    ).normalized()


class AlertService:
    def __init__(
        self,
        repository,
        config: Optional[AlertConfig] = None,
        email_sender: Optional[Any] = None,
        webhook_sender: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ):
        self.repository = repository
        self.config = config or load_alert_config()
        self.email_sender = email_sender or SmtpEmailSender(self.config)
        self.webhook_sender = webhook_sender or WebhookSender(self.config)
        self.logger = logger or logging.getLogger("netguard.alerts")
        self.clock = clock or utc_now

    def handle_problem(self, problem: AlertProblem) -> AlertResult:
        normalized = problem.normalized()
        detected_at = ensure_aware_utc(normalized.detected_at or self.clock())
        existing = self.repository.find_open_incident(normalized)
        interval = timedelta(minutes=self.config.anti_spam_minutes)

        if existing:
            last_detected = ensure_aware_utc(
                existing.get("last_detected_at")
                or existing.get("last_seen_at")
                or existing.get("opened_at")
                or detected_at
            )
            severity_escalated = severity_rank_value(normalized.severity) > severity_rank_value(existing.get("severity"))
            opening_already_notified = opening_notification_was_sent(existing)
            if (opening_already_notified or detected_at - last_detected < interval) and not severity_escalated:
                incident = self.repository.touch_incident_detection(existing["id"], detected_at)
                suppression_reason = (
                    "Opening alert already sent for this active incident"
                    if opening_already_notified
                    else f"Repeated alert inside {self.config.anti_spam_minutes} minutes"
                )
                suppression_result = NotificationResult(
                    channel="alert",
                    provider="anti_spam",
                    status="suppressed",
                    error=suppression_reason,
                )
                self.repository.record_notification_result(incident["id"], suppression_result, detected_at)
                self.logger.info(
                    "Alerta suprimido por anti-spam: incident_id=%s device_ip=%s problem_type=%s",
                    incident.get("id"),
                    normalized.device_ip,
                    normalized.problem_type,
                )
                return AlertResult(
                    incident=incident,
                    created=False,
                    updated=True,
                    notification_sent=False,
                    notification_suppressed=True,
                    notification_results=[suppression_result],
                )

            incident = self.repository.update_incident_for_notification(existing["id"], normalized, detected_at)
            created = False
            updated = True
        else:
            incident = self.repository.create_incident(normalized, detected_at)
            created = True
            updated = False
            equivalent_finder = getattr(self.repository, "find_recent_equivalent_notification", None)
            recent_equivalent = equivalent_finder(normalized, detected_at - interval) if callable(equivalent_finder) else None
            if recent_equivalent:
                suppression_result = NotificationResult(
                    channel="alert",
                    provider="anti_spam",
                    status="suppressed",
                    error=f"Equivalent alert already notified inside {self.config.anti_spam_minutes} minutes",
                )
                self.repository.record_notification_result(incident["id"], suppression_result, detected_at)
                self.logger.info(
                    "Alerta equivalente suprimido por anti-spam: incident_id=%s device_ip=%s problem_type=%s previous_incident_id=%s",
                    incident.get("id"),
                    normalized.device_ip,
                    normalized.problem_type,
                    recent_equivalent.get("incident_id"),
                )
                return AlertResult(
                    incident=incident,
                    created=True,
                    updated=False,
                    notification_sent=False,
                    notification_suppressed=True,
                    notification_results=[suppression_result],
                )

        notification = AlertNotification(
            title=build_alert_title(normalized, detected_at, "OPEN", incident=incident),
            body=build_alert_body(normalized, detected_at, "OPEN", incident=incident),
            problem=normalized,
            incident_id=incident.get("id"),
            status="OPEN",
            timestamp=detected_at,
            context=build_template_context(normalized, detected_at, "OPEN", incident=incident),
        )
        results = self._send_notifications(notification)
        notification_sent = any(item.status == "success" for item in results)
        incident = self.repository.mark_notification_sent(incident["id"], notification_sent, detected_at)
        for result in results:
            self.repository.record_notification_result(incident["id"], result, detected_at)

        return AlertResult(
            incident=incident,
            created=created,
            updated=updated,
            notification_sent=notification_sent,
            notification_suppressed=False,
            notification_results=results,
        )

    def notify_incident(self, incident_id: int, *, force: bool = False) -> Optional[AlertResult]:
        timestamp = ensure_aware_utc(self.clock())
        incident = self.repository.get_incident(incident_id)
        if incident is None:
            return None

        if str(incident.get("status") or "").strip().lower() not in ACTIVE_STATUS_VALUES:
            return AlertResult(
                incident=incident,
                created=False,
                updated=False,
                notification_sent=False,
                notification_suppressed=False,
                notification_results=[],
            )

        if not force:
            if opening_notification_was_sent(incident):
                suppression_result = NotificationResult(
                    channel="alert",
                    provider="anti_spam",
                    status="suppressed",
                    error="Opening alert already sent for this active incident",
                )
                self.repository.record_notification_result(incident_id, suppression_result, timestamp)
                self.logger.info(
                    "Notificacao de abertura ja enviada para incidente ativo: incident_id=%s",
                    incident_id,
                )
                return AlertResult(
                    incident=incident,
                    created=False,
                    updated=True,
                    notification_sent=False,
                    notification_suppressed=True,
                    notification_results=[suppression_result],
                )

            recent = self._find_recent_notification(incident_id, timestamp)
            if recent:
                suppression_result = NotificationResult(
                    channel="alert",
                    provider="anti_spam",
                    status="suppressed",
                    error=f"Repeated incident notification inside {self.config.anti_spam_minutes} minutes",
                )
                if str(recent.get("provider") or "").lower() != "anti_spam":
                    self.repository.record_notification_result(incident_id, suppression_result, timestamp)
                self.logger.info(
                    "Notificacao de incidente suprimida por anti-spam: incident_id=%s",
                    incident_id,
                )
                return AlertResult(
                    incident=incident,
                    created=False,
                    updated=True,
                    notification_sent=False,
                    notification_suppressed=True,
                    notification_results=[suppression_result],
                )

        problem = notification_problem_from_incident(incident)
        status = output_status(incident.get("status"))
        notification = AlertNotification(
            title=build_alert_title(problem, timestamp, status, incident=incident),
            body=build_alert_body(problem, timestamp, status, incident=incident),
            problem=problem,
            incident_id=incident_id,
            status=status,
            timestamp=timestamp,
            context=build_template_context(problem, timestamp, status, incident=incident),
        )
        results = self._send_notifications(notification)
        notification_sent = any(item.status == "success" for item in results)
        incident = self.repository.mark_notification_sent(incident_id, notification_sent, timestamp)
        for result in results:
            self.repository.record_notification_result(incident_id, result, timestamp)

        return AlertResult(
            incident=incident,
            created=False,
            updated=True,
            notification_sent=notification_sent,
            notification_suppressed=False,
            notification_results=results,
        )

    def _find_recent_notification(self, incident_id: int, timestamp: datetime) -> Optional[dict[str, Any]]:
        finder = getattr(self.repository, "find_recent_notification", None)
        if not callable(finder):
            return None
        since = timestamp - timedelta(minutes=self.config.anti_spam_minutes)
        return finder(incident_id, since)

    def resolve_incident(self, incident_id: int, *, send_recovery_notification: bool = False) -> Optional[AlertResult]:
        resolved_at = ensure_aware_utc(self.clock())
        incident = self.repository.resolve_incident(incident_id, resolved_at)
        if incident is None:
            return None

        results: list[NotificationResult] = []
        notification_sent = False
        if not send_recovery_notification:
            suppressor = getattr(self.repository, "mark_recovery_notification_suppressed", None)
            if callable(suppressor):
                incident = suppressor(
                    incident["id"],
                    resolved_at,
                    "Recovery notification disabled for this resolution request",
                )
            return AlertResult(
                incident=incident,
                created=False,
                updated=True,
                notification_sent=False,
                notification_suppressed=True,
                notification_results=[],
            )

        if recovery_notification_was_sent(incident):
            return AlertResult(
                incident=incident,
                created=False,
                updated=True,
                notification_sent=False,
                notification_suppressed=True,
                notification_results=[],
            )

        if recovery_notification_was_suppressed(incident):
            return AlertResult(
                incident=incident,
                created=False,
                updated=True,
                notification_sent=False,
                notification_suppressed=True,
                notification_results=[],
            )

        opening_sent = opening_notification_was_sent(incident)
        if not opening_sent:
            success_checker = getattr(self.repository, "has_successful_notification", None)
            opening_sent = bool(callable(success_checker) and success_checker(incident["id"]))

        if not opening_sent:
            suppression_result = NotificationResult(
                channel="alert",
                provider="anti_spam",
                status="suppressed",
                error="Recovery notification suppressed because the opening alert was not sent",
            )
            self.repository.record_notification_result(incident["id"], suppression_result, resolved_at)
            return AlertResult(
                incident=incident,
                created=False,
                updated=True,
                notification_sent=False,
                notification_suppressed=True,
                notification_results=[suppression_result],
            )

        problem = notification_problem_from_incident(incident)
        notification = AlertNotification(
            title=build_alert_title(problem, resolved_at, "RESOLVED", incident=incident, recovery=True),
            body=build_alert_body(problem, resolved_at, "RESOLVED", incident=incident, recovery=True),
            problem=problem,
            incident_id=incident.get("id"),
            status="RESOLVED",
            timestamp=resolved_at,
            recovery=True,
            context=build_template_context(problem, resolved_at, "RESOLVED", incident=incident, recovery=True),
        )
        results = self._send_notifications(notification)
        notification_sent = any(item.status == "success" for item in results)
        for result in results:
            self.repository.record_notification_result(incident["id"], result, resolved_at)
        if notification_sent:
            marker = getattr(self.repository, "mark_recovery_notification_sent", None)
            if callable(marker):
                incident = marker(incident["id"], resolved_at)

        return AlertResult(
            incident=incident,
            created=False,
            updated=True,
            notification_sent=notification_sent,
            notification_suppressed=False,
            notification_results=results,
        )

    def test_channel(self, channel: AlertChannel) -> NotificationResult:
        normalized = channel.normalized()
        timestamp = ensure_aware_utc(self.clock())
        problem = AlertProblem(
            device_name="NetGuard-Test",
            device_ip="127.0.0.1",
            problem_type="TEST_NOTIFICATION",
            description=f"Teste manual do canal {normalized.name}",
            severity="CRITICAL",
            detected_at=timestamp,
        ).normalized()
        notification = AlertNotification(
            title=build_alert_title(problem, timestamp, "OPEN"),
            body=build_alert_body(problem, timestamp, "OPEN"),
            problem=problem,
            incident_id=None,
            status="OPEN",
            timestamp=timestamp,
            context=build_template_context(problem, timestamp, "OPEN"),
        )
        return self._send_configured_channel(normalized, notification)

    def _send_notifications(self, notification: AlertNotification) -> list[NotificationResult]:
        results: list[NotificationResult] = []
        channels = self._active_channels()

        for channel in channels:
            if not channel.enabled:
                continue
            if not severity_allows(notification.problem.severity, channel.min_severity):
                continue
            results.append(self._send_configured_channel(channel, notification))

        if not results:
            self.logger.info(
                "Nenhum canal de alerta habilitado para incident_id=%s",
                notification.incident_id,
            )

        return results

    def _active_channels(self) -> list[AlertChannel]:
        loader = getattr(self.repository, "list_active_channels", None)
        configured = loader() if callable(loader) else []
        if configured:
            return [channel.normalized() for channel in configured if channel.enabled]
        has_configured_channels = getattr(self.repository, "has_configured_channels", None)
        if callable(has_configured_channels) and has_configured_channels():
            return []
        return [channel.normalized() for channel in env_alert_channels(self.config) if channel.enabled]

    def _send_configured_channel(self, channel: AlertChannel, notification: AlertNotification) -> NotificationResult:
        resolved = channel.normalized()
        prepared = notification_with_channel_template(resolved, notification)
        if resolved.id is None and resolved.provider == "email":
            return self._send_channel(resolved.name, "email", self.email_sender, prepared)
        if resolved.id is None and resolved.provider in {"discord", "telegram"}:
            return self._send_channel(resolved.name, resolved.provider, self.webhook_sender, prepared)

        channel_config = channel_alert_config(resolved)

        if resolved.provider == "email":
            return self._send_channel(resolved.name, "email", SmtpEmailSender(channel_config), prepared)

        return self._send_channel(resolved.name, resolved.provider, WebhookSender(channel_config), prepared)

    def _send_channel(
        self,
        channel: str,
        provider: str,
        sender: Any,
        notification: AlertNotification,
    ) -> NotificationResult:
        cooldown_key = (str(provider or "").lower(), str(channel or "").lower())
        now_ts = time.time()
        cooldown_until = CHANNEL_FAILURE_COOLDOWNS.get(cooldown_key, 0)
        if cooldown_until > now_ts:
            wait_seconds = int(max(1, cooldown_until - now_ts))
            error = f"Canal em cooldown por falha externa recente; nova tentativa em {wait_seconds}s"
            self.logger.warning(
                "Alerta nao enviado por cooldown: channel=%s provider=%s incident_id=%s wait=%ss",
                channel,
                provider,
                notification.incident_id,
                wait_seconds,
            )
            return NotificationResult(channel=channel, provider=provider, status="failed", error=error)

        try:
            sender.send(notification)
            CHANNEL_FAILURE_COOLDOWNS.pop(cooldown_key, None)
            self.logger.info(
                "Alerta enviado com sucesso: channel=%s provider=%s incident_id=%s",
                channel,
                provider,
                notification.incident_id,
            )
            return NotificationResult(channel=channel, provider=provider, status="success")
        except Exception as exc:  # pragma: no cover - exact network failures vary
            error_text = notification_error_text(exc)
            self.logger.warning(
                "Falha ao enviar alerta: channel=%s provider=%s incident_id=%s error=%s",
                channel,
                provider,
                notification.incident_id,
                error_text,
            )
            cooldown_seconds = notification_retry_after_seconds(exc) or channel_cooldown_seconds()
            CHANNEL_FAILURE_COOLDOWNS[cooldown_key] = time.time() + cooldown_seconds
            return NotificationResult(channel=channel, provider=provider, status="failed", error=error_text)
