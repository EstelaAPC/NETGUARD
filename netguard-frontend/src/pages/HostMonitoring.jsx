import React, { useEffect, useEffectEvent, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import AIInsightCard from "../components/AIInsightCard";
import Breadcrumbs from "../components/Breadcrumbs";
import GrafanaDashboardCard from "../components/GrafanaDashboardCard";
import Sidebar from "../components/Sidebar";
import {
  generateHostRecommendation,
  generateHostSummary,
  listAIInsights,
} from "../services/ai";
import { getHostDashboards } from "../services/dashboards";
import {
  collectHostNow,
  getHost,
  getHostCorrelations,
  getHostInterfaces,
  getHostIncidents,
  getHostLoopRiskEvidence,
  getHostMetrics,
  getHostMonitoringItems,
  getHostProfiles,
  getHostPredictions,
  getHostSyslog,
  toggleMonitoringItem,
  updateMonitoringItem,
} from "../services/monitoring";
import { TIME_RANGE_OPTIONS, resolveTimeRange } from "../monitoringUi";

const TABS = [
  { id: "summary", label: "Resumo", description: "Contexto e prioridade" },
  { id: "insights", label: "Insights", description: "IA sob demanda" },
  { id: "visualization", label: "Visualização", description: "Grafana nativo" },
  { id: "monitoring", label: "Monitoramento", description: "Templates e itens" },
  { id: "snmp", label: "SNMP", description: "Telemetria e interfaces" },
  { id: "syslog", label: "Syslog", description: "Eventos recentes" },
  { id: "incidents", label: "Incidentes", description: "Fila operacional" },
  { id: "predictions", label: "Previsões", description: "Anomalias e loop_risk" },
];

const LOOP_SYSLOG_TERMS = [
  "STP_TOPOLOGY_CHANGE",
  "MAC_FLAPPING",
  "INTERFACE_FLAP",
  "BROADCAST_STORM",
  "loop_risk",
  "loop risk",
];

const SEVERITY_CLASSES = {
  critical: "bg-red-500/20 text-red-200 border-red-500/30",
  high: "bg-orange-500/20 text-orange-200 border-orange-500/30",
  warning: "bg-amber-500/20 text-amber-200 border-amber-500/30",
  medium: "bg-yellow-500/20 text-yellow-200 border-yellow-500/30",
  low: "bg-sky-500/20 text-sky-200 border-sky-500/30",
  info: "bg-sky-500/20 text-sky-200 border-sky-500/30",
  notice: "bg-sky-500/20 text-sky-200 border-sky-500/30",
};

const STATUS_CLASSES = {
  open: "bg-red-500/20 text-red-200 border-red-500/30",
  closed: "bg-emerald-500/20 text-emerald-200 border-emerald-500/30",
};

const SYSLOG_PROCESS_PATTERN = /^%?([A-Za-z][A-Za-z0-9_]*)(?:-([0-7])-([A-Za-z0-9_]+))?$/;
const SYSLOG_LEVEL_TO_SEVERITY = {
  0: "critical",
  1: "critical",
  2: "high",
  3: "high",
  4: "warning",
  5: "notice",
  6: "info",
  7: "info",
};
const SYSLOG_SUBSYSTEM_LABELS = {
  link: "Link",
  lineproto: "Line protocol",
  spantree: "STP",
  stormctrl: "Storm control",
  sw_matm: "MAC table",
  loop: "Loop",
  pm: "Port manager",
  counters: "Contadores",
  manual: "Manual",
  system: "Sistema",
};
const SYSLOG_CATEGORY_LABELS = {
  link: "Link / Flap",
  loop: "Loop / STP",
  mac: "MAC / Storm",
  manual: "Manual / Sistema",
  other: "Outros",
};
const SNMP_FAMILY_FILTERS = [
  { value: "all", label: "Todos" },
  { value: "status", label: "Status" },
  { value: "traffic", label: "Tráfego" },
  { value: "errors", label: "Erros" },
  { value: "discards", label: "Descartes" },
  { value: "system", label: "Sistema" },
  { value: "interfaces", label: "Interfaces" },
  { value: "anomalies", label: "Anomalias" },
];

const SNMP_PRESET_FILTERS = [
  { value: "relevant", label: "Mostrar apenas relevantes" },
  { value: "all", label: "Mostrar todas as interfaces" },
  { value: "anomalies", label: "Somente anômalos" },
  { value: "active", label: "Somente interfaces ativas" },
  { value: "traffic", label: "Somente tráfego" },
  { value: "errors", label: "Somente erros/descartes" },
  { value: "status", label: "Somente status" },
];

const MONITORING_SECTIONS = [
  { id: "items", label: "Itens monitorados" },
  { id: "interfaces", label: "Inventário SNMP" },
  { id: "correlations", label: "Correlação" },
  { id: "policy", label: "Política" },
];
const SYSLOG_QUICK_FILTERS = [
  { value: "all", label: "Todos" },
  { value: "precursor", label: "Precursores" },
  { value: "link", label: "Link / Flap" },
  { value: "loop", label: "Loop / STP" },
  { value: "mac", label: "MAC / Storm" },
  { value: "manual", label: "Manual / Sistema" },
];

function formatDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("pt-BR");
}

function formatNumber(value, digits = 2) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "-";
  }

  return Number(value).toLocaleString("pt-BR", {
    minimumFractionDigits: 0,
    maximumFractionDigits: digits,
  });
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** power).toFixed(power === 0 ? 0 : 2)} ${units[power]}`;
}

function formatDurationSeconds(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return "-";
  if (numeric < 60) return `${numeric}s`;
  if (numeric < 3600) {
    const minutes = Math.floor(numeric / 60);
    const seconds = numeric % 60;
    return seconds ? `${minutes}min ${seconds}s` : `${minutes}min`;
  }

  const hours = Math.floor(numeric / 3600);
  const minutes = Math.floor((numeric % 3600) / 60);
  return minutes ? `${hours}h ${minutes}min` : `${hours}h`;
}

function formatCollectionPolicySummary(policy) {
  if (!policy || typeof policy !== "object") {
    return "Política de coleta global";
  }

  const icmp = formatDurationSeconds(policy.icmp_interval_sec);
  const snmp = formatDurationSeconds(policy.snmp_interval_sec);
  const tcp = formatDurationSeconds(policy.tcp_interval_sec);
  const timeout = formatDurationSeconds(policy.timeout_sec);
  const retries = Number(policy.retries || 0);

  return `ICMP ${icmp} | SNMP ${snmp} | TCP ${tcp} | timeout ${timeout} | ${retries} tentativa(s)`;
}

function formatCollectionPolicyHeadline(policy) {
  if (!policy || typeof policy !== "object") {
    return "Política de coleta global";
  }

  const icmp = formatDurationSeconds(policy.icmp_interval_sec);
  const snmp = formatDurationSeconds(policy.snmp_interval_sec);
  const tcp = formatDurationSeconds(policy.tcp_interval_sec);
  const timeout = formatDurationSeconds(policy.timeout_sec);
  const retries = Number(policy.retries || 0);

  return `ICMP ${icmp} • SNMP ${snmp} • TCP ${tcp} • timeout ${timeout} • ${retries} tentativa(s)`;
}

function formatRetentionSummary(policy) {
  if (!policy || typeof policy !== "object") {
    return "Retenção herdada da política global";
  }

  const history = policy.history_retention_days || "-";
  const trends = policy.trend_retention_days || "-";
  const logs = policy.log_retention_days || "-";
  const incidents = policy.incident_retention_days || "-";

  return `Histórico ${history}d • Trends ${trends}d • Syslog ${logs}d • Incidentes ${incidents}d`;
}

function formatPolicyCountLabel(count) {
  const total = Number(count || 0);
  if (total <= 0) return "Nenhuma política";
  if (total === 1) return "1 política";
  return `${total} políticas`;
}

function formatLoopRiskIncidentTitle(incident) {
  const type = String(incident?.incident_type || "").toLowerCase();
  const rawTitle = String(incident?.details?.problem_name || incident?.title || "").trim();
  const normalizedTitle = rawTitle.toLowerCase();

  if (
    (normalizedTitle.includes("predi") && normalizedTitle.includes("loop")) ||
    normalizedTitle.includes("alerta de risco de loop")
  ) {
    return "Risco de loop L2";
  }

  if (type === "loop_risk") {
    return rawTitle || "Risco de loop L2";
  }

  return rawTitle || "Incidente relacionado a risco de loop";
}

function wait(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function metricBaseName(metric) {
  return String(metric || "").split("|")[0];
}

function formatMetricName(metric) {
  const base = metricBaseName(metric);

  const labels = {
    "host.alive": "Host ativo",
    "icmp.rtt_ms": "RTT ICMP",
    "icmp.loss_pct": "Perda ICMP",
    "snmp.if.in_octets": "Octetos de entrada",
    "snmp.if.out_octets": "Octetos de saída",
    "snmp.if.in_errors": "Erros de entrada",
    "snmp.if.out_errors": "Erros de saída",
    "snmp.if.in_discards": "Descartes de entrada",
    "snmp.if.out_discards": "Descartes de saída",
    "snmp.if.oper_status": "Estado operacional",
    "snmp.if.admin_status": "Estado administrativo",
    "snmp.if.in_errors.delta": "Anomalia de erros de entrada",
    "snmp.if.out_errors.delta": "Anomalia de erros de saída",
    "snmp.if.in_discards.delta": "Anomalia de descartes de entrada",
    "snmp.if.out_discards.delta": "Anomalia de descartes de saída",
    "snmp.if.in_octets.delta": "Anomalia de tráfego de entrada",
    "snmp.if.out_octets.delta": "Anomalia de tráfego de saída",
    loop_risk: "Risco de loop",
  };

  return labels[base] || base;
}

function formatSeverityLabel(value) {
  const key = String(value || "").toLowerCase();

  const labels = {
    critical: "Crítica",
    high: "Alta",
    warning: "Atenção",
    medium: "Média",
    low: "Baixa",
    info: "Informativa",
    notice: "Aviso",
  };

  return labels[key] || (value ? String(value) : "Sem severidade");
}

function severityRank(value) {
  const ranks = {
    critical: 6,
    high: 5,
    warning: 4,
    medium: 3,
    low: 2,
    info: 1,
    notice: 1,
  };

  return ranks[String(value || "").toLowerCase()] || 0;
}

function formatStatusLabel(value) {
  const key = String(value || "").toLowerCase();

  const labels = {
    open: "Aberto",
    acknowledged: "Reconhecido",
    resolved: "Resolvido",
    closed: "Fechado",
  };

  return labels[key] || (value ? String(value) : "Sem status");
}

function formatIncidentType(value) {
  const key = String(value || "").toLowerCase();

  const labels = {
    loop_risk: "Risco de loop",
    early_warning: "Alerta antecipado",
    host_down: "Host indisponível",
    snmp_collection_silence: "Sem telemetria SNMP recente",
    icmp_collection_silence: "Sem telemetria ICMP recente",
    interface_down: "Interface indisponível",
    link_flap: "Oscilação de link",
    mac_flapping: "MAC flapping",
    broadcast_storm: "Broadcast storm",
  };

  if (labels[key]) return labels[key];
  if (key.startsWith("syslog_loop_")) return `Evento de loop ${String(value).replace(/^syslog_loop_/i, "").replaceAll("_", "/")}`;
  if (key.startsWith("syslog_interface_flap_")) {
    return `Oscilação de interface ${String(value).replace(/^syslog_interface_flap_/i, "").replaceAll("_", "/")}`;
  }
  return value
    ? String(value)
        .replaceAll("_", " ")
        .replace(/\s+/g, " ")
        .replace(/\b\w/g, (letter) => letter.toUpperCase())
    : "Incidente";
}

function extractInterfaceName(item) {
  if (item?.labels?.ifName) return item.labels.ifName;
  if (item?.details?.ifName) return item.details.ifName;

  const source = `${item?.metric || ""}|${item?.key || ""}`;
  const match = source.match(/ifIndex=(\d+)/i);

  return match ? `ifIndex ${match[1]}` : "-";
}

function normalizeInterfaceName(value) {
  const text = String(value || "").trim();
  if (!text) return "";

  const cleaned = text.replace(/^[<>\[(]+/, "").replace(/[>\]),.;:]+$/, "");
  const replacements = [
    ["TenGigabitEthernet", "Te"],
    ["GigabitEthernet", "Gi"],
    ["FastEthernet", "Fa"],
    ["Port-channel", "Po"],
    ["Ethernet", "Eth"],
    ["Loopback", "Lo"],
    ["Vlan", "Vlan"],
  ];

  const lowered = cleaned.toLowerCase();
  const matched = replacements.find(([prefix]) => lowered.startsWith(prefix.toLowerCase()));
  return matched ? `${matched[1]}${cleaned.slice(matched[0].length)}` : cleaned;
}

function extractInterfacePair(...parts) {
  const token = String.raw`(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Port-channel|Ethernet|Loopback|Vlan|Te|Gi|Fa|Po|Eth|Lo)\d+(?:\/\d+)*(?:\.\d+)?`;
  const pairRegex = new RegExp(`(${token})\\s*<->\\s*(${token})`, "i");

  for (const part of parts) {
    const text = String(part || "");
    if (!text) continue;
    const match = text.match(pairRegex);
    if (!match) continue;
    const left = normalizeInterfaceName(match[1]);
    const right = normalizeInterfaceName(match[2]);
    if (left && right) {
      return `${left}<->${right}`;
    }
  }

  return "";
}

function extractInterfaceTokens(...parts) {
  const token = String.raw`(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Port-channel|Ethernet|Loopback|Vlan|Te|Gi|Fa|Po|Eth|Lo)\d+(?:\/\d+)*(?:\.\d+)?`;
  const regex = new RegExp(token, "gi");
  const seen = new Set();
  const interfaces = [];

  for (const part of parts) {
    const text = String(part || "");
    if (!text) continue;
    const matches = text.match(regex) || [];
    for (const item of matches) {
      const normalized = normalizeInterfaceName(item);
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      interfaces.push(normalized);
    }
  }

  return interfaces;
}

function metricCategory(metric, item = null) {
  const base = metricBaseName(metric).toLowerCase();
  const text = `${base} ${item?.label || ""} ${item?.metric || ""}`.toLowerCase();

  if (base === "host.alive" || base.includes(".oper_status") || base.includes(".admin_status")) return "status";
  if (base.includes(".in_octets") || base.includes(".out_octets") || base.includes("traffic") || base.includes("throughput")) return "traffic";
  if (base.includes(".in_errors") || base.includes(".out_errors") || base.includes("crc") || base.includes("error")) return "errors";
  if (base.includes(".in_discards") || base.includes(".out_discards") || base.includes("discard")) return "discards";
  if (base.includes(".delta") || base.includes("loop_risk") || text.includes("anomalia")) return "anomalies";
  if (
    base.startsWith("snmp.system.") ||
    base.startsWith("system.") ||
    base.includes("cpu") ||
    base.includes("memory") ||
    base.includes("temp") ||
    base.includes("fan") ||
    base.includes("power") ||
    base.includes("uptime")
  ) {
    return "system";
  }
  if (base.startsWith("snmp.if.") || base.includes("interface")) return "interfaces";
  return "other";
}

function formatMetricCategory(value) {
  const labels = {
    all: "Todas",
    traffic: "Tráfego",
    errors: "Erros",
    discards: "Descartes",
    status: "Status",
    system: "Sistema",
    interfaces: "Interfaces",
    anomalies: "Anomalias",
    other: "Outras",
  };

  return labels[value] || "Outras";
}

function formatSnmpStatusValue(metric, value) {
  const base = metricBaseName(metric).toLowerCase();
  const normalized = String(value ?? "").trim().toLowerCase();

  if (base.includes("oper_status") || base.includes("admin_status")) {
    if (normalized === "1" || normalized === "up" || normalized === "ok") return "up";
    if (normalized === "2" || normalized === "down") return "down";
    if (!normalized) return "-";
    return normalized;
  }

  if (base.includes("octets") || base.includes("traffic")) {
    return formatBytes(value);
  }

  return value === null || value === undefined || value === "" ? "-" : formatNumber(value);
}

function isStatusMetric(metric) {
  return metricCategory(metric) === "status";
}

function isTrafficMetric(metric) {
  return metricCategory(metric) === "traffic";
}

function isErrorMetric(metric) {
  return metricCategory(metric) === "errors" || metricCategory(metric) === "discards";
}

function isAnomalyMetric(metric) {
  return metricCategory(metric) === "anomalies";
}

function normalizeInterfaceStatus(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return "";
  if (normalized === "1" || normalized === "up" || normalized === "ok" || normalized === "enabled") {
    return "up";
  }
  if (normalized === "2" || normalized === "down" || normalized === "disabled" || normalized === "err-disabled") {
    return "down";
  }
  return normalized;
}

function interfaceDisplayName(iface) {
  return (
    iface?.if_name ||
    iface?.ifdescr ||
    iface?.if_descr ||
    iface?.if_alias ||
    iface?.ifAlias ||
    iface?.name ||
    (iface?.ifindex ? `ifIndex ${iface.ifindex}` : "")
  );
}

function interfaceSummary(iface) {
  return (
    iface?.if_alias ||
    iface?.ifAlias ||
    iface?.ifdescr ||
    iface?.if_descr ||
    iface?.name ||
    ""
  );
}

function interfaceKeyFromRecord(iface) {
  return normalizeInterfaceName(interfaceDisplayName(iface));
}

function isInterfaceActiveForDisplay(iface) {
  const oper = normalizeInterfaceStatus(iface?.oper_status);
  const admin = normalizeInterfaceStatus(iface?.admin_status);
  return oper === "up" || admin === "up";
}

function isInterfaceRelevantForDisplay(iface) {
  const errors =
    Number(iface?.last_in_errors || 0) +
    Number(iface?.last_out_errors || 0) +
    Number(iface?.last_in_discards || 0) +
    Number(iface?.last_out_discards || 0);
  const traffic = Number(iface?.last_in_bps || 0) + Number(iface?.last_out_bps || 0);
  return isInterfaceActiveForDisplay(iface) || errors > 0 || traffic > 0;
}

function normalizeSyslogSubsystem(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  const cleaned = text.replace(/^%/, "").replace(/:$/, "");
  const match = cleaned.match(SYSLOG_PROCESS_PATTERN);
  const base = match?.[1] || cleaned;
  return base.toLowerCase().replace(/\s+/g, "_");
}

function formatSyslogSubsystem(value) {
  const key = normalizeSyslogSubsystem(value);
  if (!key) return "Sem subsistema";
  return (
    SYSLOG_SUBSYSTEM_LABELS[key] ||
    key
      .split("_")
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ")
  );
}

function inferSyslogSeverity(event) {
  const explicit = String(event?.severity || "").trim().toLowerCase();
  const upperText = `${event?.process || ""} ${event?.message || ""} ${event?.raw || ""}`.toUpperCase();
  if (explicit) {
    if (/^\d+$/.test(explicit)) {
      return SYSLOG_LEVEL_TO_SEVERITY[Number(explicit)] || "";
    }
    return explicit;
  }

  if (upperText.includes("CHANGED STATE TO UP")) {
    return "notice";
  }
  if (upperText.includes("CHANGED STATE TO DOWN")) {
    return "warning";
  }

  const processText = String(event?.process || "").trim().replace(/:$/, "");
  const processMatch = processText.match(SYSLOG_PROCESS_PATTERN);
  if (processMatch?.[2]) {
    return SYSLOG_LEVEL_TO_SEVERITY[Number(processMatch[2])] || "";
  }

  if (["UNPROTECTED", "ERR_DISABLE", "LOOP DETECTADO"].some((token) => upperText.includes(token))) {
    return "high";
  }
  if (
    [
      "LOOPGUARD_BLOCK",
      "BROADCAST STORM",
      "STORMCTRL",
      "MACFLAP",
      "MAC FLAP",
      "BURST DE ERROS",
      "CHANGED STATE TO DOWN",
    ].some((token) => upperText.includes(token))
  ) {
    return "warning";
  }
  if (["TOPOTRAP", "DESABILITADO", "CHANGED STATE TO UP"].some((token) => upperText.includes(token))) {
    return "notice";
  }
  if (["TESTE DE SYSLOG MANUAL", "INICIADO", "CONFIGURAÇÃO SALVA", "PORTAS:"].some((token) => upperText.includes(token))) {
    return "info";
  }
  return "";
}

function inferSyslogSubsystem(event) {
  const explicit = normalizeSyslogSubsystem(event?.subsystem);
  if (explicit) return explicit;

  const processText = String(event?.process || "").trim().replace(/^%/, "").replace(/:$/, "");
  const processMatch = processText.match(SYSLOG_PROCESS_PATTERN);
  if (processMatch?.[1]) {
    return normalizeSyslogSubsystem(processMatch[1]);
  }

  const upperText = `${event?.process || ""} ${event?.message || ""} ${event?.raw || ""}`.toUpperCase();
  const rules = [
    ["LOOPGUARD", "spantree"],
    ["SPANTREE", "spantree"],
    ["TOPOLOGY CHANGE", "spantree"],
    ["TCN", "spantree"],
    ["MACFLAP", "sw_matm"],
    ["MAC FLAP", "sw_matm"],
    ["MAC FLAPPING", "sw_matm"],
    ["SW_MATM", "sw_matm"],
    ["STORMCTRL", "stormctrl"],
    ["BROADCAST STORM", "stormctrl"],
    ["STORM CONTROL", "stormctrl"],
    ["LINE PROTOCOL ON INTERFACE", "lineproto"],
    ["CHANGED STATE TO", "link"],
    ["ERR_DISABLE", "pm"],
    ["ERR-RECOVER", "pm"],
    ["BURST DE ERROS", "counters"],
    ["DISCARD", "counters"],
    ["COUNTERS", "counters"],
    ["TESTE DE SYSLOG MANUAL", "manual"],
    ["CONFIGURAÇÃO SALVA", "system"],
    ["CONFIG:", "system"],
    ["INICIADO", "system"],
    ["PORTAS:", "system"],
    ["LOOP", "loop"],
  ];

  const found = rules.find(([token]) => upperText.includes(token));
  return found?.[1] || "";
}

function inferSyslogIface(event) {
  const pair = extractInterfacePair(event?.iface, event?.message, event?.raw);
  if (pair) return pair;

  const direct = normalizeInterfaceName(event?.iface);
  if (direct) return direct;

  const interfaces = extractInterfaceTokens(event?.iface, event?.message, event?.raw);
  return interfaces.length === 1 ? interfaces[0] : "";
}

function inferSyslogCategory(event) {
  const subsystem = inferSyslogSubsystem(event);
  const upperText = `${event?.message || ""} ${event?.raw || ""}`.toUpperCase();

  if (
    subsystem === "spantree" ||
    subsystem === "loop" ||
    ["LOOP", "SPANTREE", "TOPOLOGY CHANGE", "TCN"].some((token) => upperText.includes(token))
  ) {
    return "loop";
  }
  if (
    subsystem === "stormctrl" ||
    subsystem === "sw_matm" ||
    ["MACFLAP", "MAC FLAP", "MAC FLAPPING", "STORMCTRL", "BROADCAST STORM"].some((token) =>
      upperText.includes(token)
    )
  ) {
    return "mac";
  }
  if (
    subsystem === "link" ||
    subsystem === "lineproto" ||
    ["CHANGED STATE TO", "UPDOWN", "LINE PROTOCOL ON INTERFACE"].some((token) => upperText.includes(token))
  ) {
    return "link";
  }
  if (subsystem === "manual" || subsystem === "system") {
    return "manual";
  }
  return "other";
}

function enrichSyslogEvent(event) {
  const severity = inferSyslogSeverity(event);
  const subsystem = inferSyslogSubsystem(event);
  const iface = inferSyslogIface(event);
  const category = inferSyslogCategory({ ...event, severity, subsystem, iface });
  const searchable = [
    event?.message,
    event?.raw,
    event?.process,
    severity,
    subsystem,
    formatSyslogSubsystem(subsystem),
    iface,
    SYSLOG_CATEGORY_LABELS[category],
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return {
    ...event,
    severity,
    subsystem,
    iface,
    category,
    subsystemLabel: formatSyslogSubsystem(subsystem),
    categoryLabel: SYSLOG_CATEGORY_LABELS[category] || "Outros",
    searchable,
  };
}

function isLoopSignal(event) {
  const text = `${event?.message || ""} ${event?.raw || ""}`.toUpperCase();
  return LOOP_SYSLOG_TERMS.some((term) => text.includes(term.toUpperCase()));
}

function getHealthStatus(host, latestAliveMetric) {
  if (!host?.enabled) {
    return {
      label: "Cadastro inativo",
      className: "bg-slate-500/20 text-slate-200 border-slate-500/30",
    };
  }

  const backendStatus = String(host?.health_status || "").toLowerCase();
  const backendStates = {
    degraded: {
      label: "Degradado",
      className: "bg-amber-500/20 text-amber-200 border-amber-500/30",
    },
    critical: {
      label: "Crítico",
      className: "bg-red-500/20 text-red-200 border-red-500/30",
    },
    unavailable: {
      label: "Indisponível",
      className: "bg-red-500/20 text-red-200 border-red-500/30",
    },
  };
  if (backendStates[backendStatus]) {
    return backendStates[backendStatus];
  }

  if (!latestAliveMetric) {
    return {
      label: "Sem telemetria recente",
      className: "bg-slate-500/20 text-slate-200 border-slate-500/30",
    };
  }

  if (Number(latestAliveMetric.value) >= 1) {
    return {
      label: "Saudável",
      className: "bg-emerald-500/20 text-emerald-200 border-emerald-500/30",
    };
  }

  return {
    label: "Indisponível",
    className: "bg-red-500/20 text-red-200 border-red-500/30",
  };
}

function getScoreClass(score) {
  if (score >= 0.8) return "bg-red-500/20 text-red-200 border-red-500/30";
  if (score >= 0.5) return "bg-amber-500/20 text-amber-200 border-amber-500/30";
  return "bg-sky-500/20 text-sky-200 border-sky-500/30";
}

function getIncidentEvidence(incident) {
  const details = incident?.details || {};

  if (Array.isArray(details.evidences)) return details.evidences;
  if (Array.isArray(details.evidence)) return details.evidence;

  return [];
}

function formatEvidencePreview(evidences, limit = 5) {
  const values = Array.isArray(evidences) ? evidences.filter(Boolean) : [];
  return {
    visible: values.slice(0, limit),
    hiddenCount: Math.max(values.length - limit, 0),
  };
}

function buildTimelineItems({ latestAliveMetric, precursorSyslog, loopRiskIncidents, anomalyScores }) {
  const items = [];

  if (latestAliveMetric?.ts) {
    items.push({
      id: `alive-${latestAliveMetric.ts}`,
      ts: latestAliveMetric.ts,
      title: Number(latestAliveMetric.value) >= 1 ? "Host acessível" : "Host indisponível",
      detail:
        Number(latestAliveMetric.value) >= 1
          ? "A última coleta ICMP indica disponibilidade."
          : "A última coleta ICMP indica perda de conectividade.",
      tone: Number(latestAliveMetric.value) >= 1 ? "emerald" : "red",
      badge: "Telemetria",
    });
  }

  precursorSyslog.slice(0, 5).forEach((event) => {
    items.push({
      id: `syslog-${event.id}`,
      ts: event.ts,
      title: event.message || "Evento de syslog",
      detail: `${event.subsystemLabel || formatSyslogSubsystem(event.subsystem) || "Subsistema não informado"}${
        event.iface ? ` • ${event.iface}` : ""
      }`,
      tone: "amber",
      badge: "Syslog",
      severity: event.severity,
    });
  });

  loopRiskIncidents.slice(0, 3).forEach((incident) => {
    items.push({
      id: `incident-${incident.id}`,
      ts: incident.last_seen_at || incident.opened_at,
      title: incident.title,
      detail: incident?.details?.recommendation || "Incidente ativo associado ao host.",
      tone: "red",
      badge: "Incidente",
      severity: incident.severity,
    });
  });

  anomalyScores
    .filter((item) => Number(item.score || 0) >= 0.2)
    .slice(0, 4)
    .forEach((item, index) => {
      items.push({
        id: `prediction-${item.ts}-${item.metric}-${index}`,
        ts: item.ts,
        title: formatMetricName(item.metric),
        detail: `Score ${Math.round(Number(item.score || 0) * 100)}% • ${extractInterfaceName(item)}`,
        tone: Number(item.score || 0) >= 0.8 ? "red" : Number(item.score || 0) >= 0.5 ? "amber" : "sky",
        badge: "Previsão",
      });
    });

  return items
    .sort((a, b) => new Date(b.ts) - new Date(a.ts))
    .slice(0, 8);
}

function InfoCard({ title, value, subtitle, tone = "slate", valueClassName = "" }) {
  const tones = {
    slate: "border-white/10 bg-slate-900/60",
    emerald: "border-emerald-500/20 bg-emerald-500/10",
    amber: "border-amber-500/20 bg-amber-500/10",
    red: "border-red-500/20 bg-red-500/10",
    sky: "border-sky-500/20 bg-sky-500/10",
  };

  return (
    <div className={`h-fit self-start overflow-hidden rounded-xl border p-4 ${tones[tone] || tones.slate}`}>
      <div className="text-xs uppercase tracking-wide text-slate-400">{title}</div>
      <div className={`mt-2 break-words font-semibold text-white ${valueClassName || "text-2xl"}`}>{value}</div>
      {subtitle && <div className="mt-1 line-clamp-2 break-words text-sm text-slate-300">{subtitle}</div>}
    </div>
  );
}

function EmptyState({ title, subtitle }) {
  return (
    <div className="rounded-xl border border-dashed border-white/10 bg-slate-900/30 px-4 py-10 text-center">
      <div className="text-base font-medium text-white">{title}</div>
      <div className="mt-2 text-sm text-slate-400">{subtitle}</div>
    </div>
  );
}

function Pill({ children, className = "" }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${className}`}
    >
      {children}
    </span>
  );
}

function KeyValueItem({ label, value, accent = false }) {
  return (
    <div className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
      <div className="text-[11px] uppercase tracking-[0.14em] text-slate-500">{label}</div>
      <div className={`mt-2 line-clamp-3 break-words text-sm font-medium ${accent ? "text-white" : "text-slate-200"}`}>{value}</div>
    </div>
  );
}

export default function HostMonitoring() {
  const { hostId } = useParams();
  const me = useMemo(() => JSON.parse(localStorage.getItem("ng_user") || "{}"), []);

  const [activeTab, setActiveTab] = useState("summary");
  const [host, setHost] = useState(null);
  const [hostLoadState, setHostLoadState] = useState("loading");
  const [profiles, setProfiles] = useState([]);
  const [metrics, setMetrics] = useState([]);
  const [syslog, setSyslog] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [predictions, setPredictions] = useState(null);
  const [monitoringItems, setMonitoringItems] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [loopEvidence, setLoopEvidence] = useState(null);
  const [dashboards, setDashboards] = useState([]);
  const [hostInsights, setHostInsights] = useState({
    host_summary: null,
    operational_recommendation: null,
  });
  const [insightsLoading, setInsightsLoading] = useState(false);
  const [insightsError, setInsightsError] = useState("");
  const [generatingInsightType, setGeneratingInsightType] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [collectingNow, setCollectingNow] = useState(false);
  const [collectNowNotice, setCollectNowNotice] = useState("");
  const [error, setError] = useState("");
  const [snmpQuery, setSnmpQuery] = useState("");
  const [snmpMetricType, setSnmpMetricType] = useState("all");
  const [snmpInterfaceFilter, setSnmpInterfaceFilter] = useState("all");
  const [snmpPresetFilter, setSnmpPresetFilter] = useState("relevant");
  const [snmpTimeFilter, setSnmpTimeFilter] = useState("current");
  const [snmpLimit, setSnmpLimit] = useState("60");
  const [monitoringSection, setMonitoringSection] = useState("items");
  const [monitoringQuery, setMonitoringQuery] = useState("");
  const [monitoringStatusFilter, setMonitoringStatusFilter] = useState("all");
  const [monitoringProtocolFilter, setMonitoringProtocolFilter] = useState("all");
  const [monitoringPage, setMonitoringPage] = useState(1);
  const [monitoringPageSize, setMonitoringPageSize] = useState("10");
  const [interfaceQuery, setInterfaceQuery] = useState("");
  const [interfaceStatusFilter, setInterfaceStatusFilter] = useState("all");
  const [interfacePage, setInterfacePage] = useState(1);
  const [interfacePageSize, setInterfacePageSize] = useState("10");
  const [correlationQuery, setCorrelationQuery] = useState("");
  const [correlationFilter, setCorrelationFilter] = useState("relevant");
  const [syslogQuery, setSyslogQuery] = useState("");
  const [syslogType, setSyslogType] = useState("all");
  const [syslogSeverityFilter, setSyslogSeverityFilter] = useState("all");
  const [syslogSubsystemFilter, setSyslogSubsystemFilter] = useState("all");
  const [syslogInterfaceFilter, setSyslogInterfaceFilter] = useState("all");
  const [syslogLimit, setSyslogLimit] = useState("20");
  const [incidentStatusFilter, setIncidentStatusFilter] = useState("all");
  const [predictionSort, setPredictionSort] = useState("score_desc");
  const [timeWindow, setTimeWindow] = useState("24h");
  const [savingItemId, setSavingItemId] = useState("");

  async function loadData(requestedHostId = hostId, mode = "initial") {
    try {
      const currentTimeRange = resolveTimeRange(timeWindow);

      if (mode === "initial") {
        setLoading(true);
        setHostLoadState("loading");
      } else {
        setRefreshing(true);
      }

      setError("");
      if (mode === "initial") {
        setCollectNowNotice("");
      }

      let hostData;
      try {
        hostData = await getHost(requestedHostId);
      } catch (hostError) {
        if (hostError?.status === 404 || String(hostError?.message || "").includes("Host n?o encontrado") || String(hostError?.message || "").includes("Host nao encontrado")) {
          setHostLoadState("not_found");
          setHost(null);
          setProfiles([]);
          setMetrics([]);
          setSyslog([]);
          setIncidents([]);
          setPredictions(null);
          setMonitoringItems([]);
          setInterfaces([]);
          setCorrelations([]);
          setLoopEvidence(null);
          setDashboards([]);
          return null;
        }

        throw hostError;
      }

      setHost(hostData);
      setHostLoadState("ready");
      setLoading(false);

      const [profilesResult, metricsResult, syslogResult, incidentsResult, predictionsResult, dashboardResult, monitoringItemResult, interfaceResult, correlationResult, loopEvidenceResult] =
        await Promise.allSettled([
          getHostProfiles(requestedHostId),
          getHostMetrics(requestedHostId, {
            limit: 250,
            from: currentTimeRange.from,
            to: currentTimeRange.to,
          }),
          getHostSyslog(requestedHostId, {
            limit: 100,
            from: currentTimeRange.from,
            to: currentTimeRange.to,
          }),
          getHostIncidents(requestedHostId, {
            limit: 200,
            from: currentTimeRange.from,
            to: currentTimeRange.to,
          }),
          getHostPredictions(requestedHostId, {
            limit: 100,
            from: currentTimeRange.from,
            to: currentTimeRange.to,
          }),
          getHostDashboards(requestedHostId, {
            from: currentTimeRange.from,
            to: currentTimeRange.to,
          }),
          getHostMonitoringItems(requestedHostId),
          getHostInterfaces(requestedHostId),
          getHostCorrelations(requestedHostId, { limit: 120 }),
          getHostLoopRiskEvidence(requestedHostId, { minutes: 5 }),
        ]);

      const profileData = profilesResult.status === "fulfilled" ? profilesResult.value : [];
      const metricData = metricsResult.status === "fulfilled" ? metricsResult.value : [];
      const syslogData = syslogResult.status === "fulfilled" ? syslogResult.value : [];
      const incidentData = incidentsResult.status === "fulfilled" ? incidentsResult.value : [];
      const predictionData = predictionsResult.status === "fulfilled" ? predictionsResult.value : null;
      const dashboardData = dashboardResult.status === "fulfilled" ? dashboardResult.value : [];
      const monitoringItemData = monitoringItemResult.status === "fulfilled" ? monitoringItemResult.value : [];
      const interfaceData = interfaceResult.status === "fulfilled" ? interfaceResult.value : [];
      const correlationData = correlationResult.status === "fulfilled" ? correlationResult.value : [];
      const loopEvidenceData = loopEvidenceResult.status === "fulfilled" ? loopEvidenceResult.value : null;

      setProfiles(Array.isArray(profileData) ? profileData : []);
      setMetrics(Array.isArray(metricData) ? metricData : []);
      setSyslog(Array.isArray(syslogData) ? syslogData : []);
      setIncidents(Array.isArray(incidentData) ? incidentData : []);
      setPredictions(predictionData || null);
      setMonitoringItems(Array.isArray(monitoringItemData) ? monitoringItemData : []);
      setInterfaces(Array.isArray(interfaceData) ? interfaceData : []);
      setCorrelations(Array.isArray(correlationData) ? correlationData : []);
      setLoopEvidence(loopEvidenceData || null);
      setDashboards(Array.isArray(dashboardData) ? dashboardData : []);

      return {
        hostData,
        profileData,
        metricData,
        syslogData,
        incidentData,
        predictionData,
        dashboardData,
        monitoringItemData,
        interfaceData,
        correlationData,
        loopEvidenceData,
      };
    } catch (err) {
      if (err?.status === 404 || String(err?.message || "").includes("Host n?o encontrado") || String(err?.message || "").includes("Host nao encontrado")) {
        setHostLoadState("not_found");
        setError("");
      } else {
        setHostLoadState("error");
        setError(err?.message || "Falha ao carregar monitoramento do host");
      }
      setHost(null);
      setProfiles([]);
      setMetrics([]);
      setSyslog([]);
      setIncidents([]);
      setPredictions(null);
      setMonitoringItems([]);
      setInterfaces([]);
      setCorrelations([]);
      setLoopEvidence(null);
      setDashboards([]);
      return null;
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void loadData(hostId, "initial");
  }, [hostId, timeWindow]);

  async function loadInsights(requestedHostId = hostId) {
    try {
      setInsightsLoading(true);
      setInsightsError("");
      const items = await listAIInsights({
        targetType: "host",
        targetId: requestedHostId,
        limit: 10,
      }).catch(() => []);

      const nextInsights = {
        host_summary: null,
        operational_recommendation: null,
      };

      (Array.isArray(items) ? items : []).forEach((item) => {
        if (item?.insight_type === "host_summary" && !nextInsights.host_summary) {
          nextInsights.host_summary = item;
        }
        if (item?.insight_type === "operational_recommendation" && !nextInsights.operational_recommendation) {
          nextInsights.operational_recommendation = item;
        }
      });

      setHostInsights(nextInsights);
    } catch (insightLoadError) {
      setInsightsError(insightLoadError?.message || "Falha ao carregar insights do host");
      setHostInsights({
        host_summary: null,
        operational_recommendation: null,
      });
    } finally {
      setInsightsLoading(false);
    }
  }

  useEffect(() => {
    void loadInsights(hostId);
  }, [hostId]);

  async function handleRefresh() {
    await Promise.all([loadData(hostId, "refresh"), loadInsights(hostId)]);
  }

  async function waitForCollectionAdvance(previousState) {
    for (let attempt = 0; attempt < 6; attempt += 1) {
      await wait(2500);

      const nextSnapshot = await loadData(hostId, "refresh");
      const nextHost = nextSnapshot?.hostData;
      if (!nextHost) {
        continue;
      }

      const icmpChanged =
        String(nextHost.last_icmp_collection_at || "") !== String(previousState.lastIcmp || "");
      const snmpChanged =
        String(nextHost.last_snmp_collection_at || "") !== String(previousState.lastSnmp || "");

      if (icmpChanged || snmpChanged) {
        return true;
      }
    }

    return false;
  }

  async function handleCollectNow() {
    try {
      const previousState = {
        lastIcmp: host?.last_icmp_collection_at,
        lastSnmp: host?.last_snmp_collection_at,
      };
      setCollectingNow(true);
      setError("");
      const result = await collectHostNow(hostId, "all");
      setCollectNowNotice(
        result?.message || "Solicitação de coleta registrada. Os pollers vão processar o pedido no próximo ciclo disponível."
      );
      await handleRefresh();
      const advanced = await waitForCollectionAdvance(previousState);
      await loadInsights(hostId);

      if (advanced) {
        setCollectNowNotice("Nova telemetria recebida para o host. A tela foi atualizada com a coleta mais recente.");
      }
    } catch (collectError) {
      setCollectNowNotice("");
      setError(collectError?.message || "Falha ao solicitar uma nova coleta para o host.");
    } finally {
      setCollectingNow(false);
    }
  }

  async function handleToggleMonitoringItem(item) {
    try {
      setSavingItemId(`toggle-${item.id}`);
      setError("");
      const updated = await toggleMonitoringItem(item.id, !item.enabled);
      setMonitoringItems((current) => current.map((entry) => (entry.id === item.id ? updated : entry)));
    } catch (itemError) {
      setError(itemError?.message || "Falha ao alternar item monitorado.");
    } finally {
      setSavingItemId("");
    }
  }

  async function handleMonitoringItemNumberChange(item, field, value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return;
    try {
      setSavingItemId(`${field}-${item.id}`);
      setError("");
      const updated = await updateMonitoringItem(item.id, { [field]: numeric });
      setMonitoringItems((current) => current.map((entry) => (entry.id === item.id ? updated : entry)));
    } catch (itemError) {
      setError(itemError?.message || "Falha ao salvar item monitorado.");
    } finally {
      setSavingItemId("");
    }
  }

  const latestByMetric = useMemo(() => {
    const map = {};

    metrics.forEach((item) => {
      if (!map[item.metric]) {
        map[item.metric] = item;
      }
    });

    return map;
  }, [metrics]);

  const latestAliveMetric = latestByMetric["host.alive"];
  const latestRttMetric = latestByMetric["icmp.rtt_ms"];
  const latestLossMetric = latestByMetric["icmp.loss_pct"];

  const health = useMemo(
    () => getHealthStatus(host, latestAliveMetric),
    [host, latestAliveMetric]
  );

  const snmpMetrics = useMemo(
    () => metrics.filter((item) => String(item.metric || "").startsWith("snmp.")),
    [metrics]
  );

  const snmpInterfaceOptions = useMemo(() => {
    const options = snmpMetrics
      .map((item) => extractInterfaceName(item))
      .filter((value) => value && value !== "-")
      .filter((value, index, array) => array.indexOf(value) === index)
      .sort((a, b) => a.localeCompare(b, "pt-BR", { numeric: true }));

    return options;
  }, [snmpMetrics]);

  const observedInterfaces = useMemo(() => {
    const keys = new Set();

    snmpMetrics.forEach((item) => {
      const iface = extractInterfaceName(item);
      if (iface && iface !== "-") keys.add(iface);
    });

    return keys.size;
  }, [snmpMetrics]);

  const relevantInterfaceSet = useMemo(() => {
    const set = new Set();
    const add = (value) => {
      const key = normalizeInterfaceName(value);
      if (key) set.add(key);
    };

    interfaces.forEach((iface) => {
      const key = interfaceKeyFromRecord(iface);
      if (!key) return;

      if (isInterfaceRelevantForDisplay(iface) || isInterfaceActiveForDisplay(iface)) {
        add(key);
      }
    });

    syslog.forEach((event) => {
      add(inferSyslogIface(event));
    });

    correlations.forEach((item) => {
      add(item.normalized_iface || item.if_name || item.ifdescr || item.if_alias);
    });

    incidents.forEach((incident) => {
      const evidenceText = [
        incident?.title,
        incident?.description,
        incident?.details?.evidence_summary,
        Array.isArray(getIncidentEvidence(incident)) ? getIncidentEvidence(incident).join(" ") : "",
      ]
        .filter(Boolean)
        .join(" ");

      extractInterfaceTokens(evidenceText).forEach(add);
    });

    return set;
  }, [correlations, incidents, interfaces, syslog]);

  const filteredSnmpMetrics = useMemo(() => {
    const normalized = snmpQuery.trim().toLowerCase();
    const timeWindowMs =
      snmpTimeFilter === "6h"
        ? 6 * 60 * 60 * 1000
        : snmpTimeFilter === "12h"
        ? 12 * 60 * 60 * 1000
        : snmpTimeFilter === "24h"
        ? 24 * 60 * 60 * 1000
        : snmpTimeFilter === "48h"
        ? 48 * 60 * 60 * 1000
        : snmpTimeFilter === "7d"
        ? 7 * 24 * 60 * 60 * 1000
        : 0;
    const cutoff = timeWindowMs ? Date.now() - timeWindowMs : 0;

    const result = snmpMetrics.filter((item) => {
      const iface = normalizeInterfaceName(extractInterfaceName(item));
      const category = metricCategory(item.metric, item);
      const valueText = formatSnmpStatusValue(item.metric, item.value).toLowerCase();
      const isRelevantInterface = iface && relevantInterfaceSet.has(iface);
      const isVisibleByPreset =
        snmpPresetFilter === "all"
          ? true
          : snmpPresetFilter === "relevant"
          ? category === "anomalies" ||
            category === "system" ||
            (iface && isRelevantInterface) ||
            category === "traffic" ||
            category === "errors" ||
            category === "discards"
          : snmpPresetFilter === "anomalies"
          ? category === "anomalies"
          : snmpPresetFilter === "active"
          ? iface && isRelevantInterface
          : snmpPresetFilter === "traffic"
          ? category === "traffic"
          : snmpPresetFilter === "errors"
          ? category === "errors" || category === "discards"
          : snmpPresetFilter === "status"
          ? category === "status"
          : true;

      if (snmpMetricType !== "all" && category !== snmpMetricType) return false;
      if (snmpInterfaceFilter !== "all" && iface !== snmpInterfaceFilter) return false;
      if (!isVisibleByPreset) return false;
      if (cutoff && item.ts && new Date(item.ts).getTime() < cutoff) return false;
      if (!normalized) return true;

      return (
        String(item.metric || "").toLowerCase().includes(normalized) ||
        String(formatMetricName(item.metric) || "").toLowerCase().includes(normalized) ||
        String(iface || "").toLowerCase().includes(normalized) ||
        String(valueText || "").toLowerCase().includes(normalized)
      );
    });

    return result.slice(0, Number(snmpLimit));
  }, [
    relevantInterfaceSet,
    snmpInterfaceFilter,
    snmpLimit,
    snmpMetricType,
    snmpMetrics,
    snmpPresetFilter,
    snmpQuery,
    snmpTimeFilter,
  ]);

  const snmpFamilyCounts = useMemo(() => {
    const counts = {
      all: snmpMetrics.length,
      status: 0,
      traffic: 0,
      errors: 0,
      discards: 0,
      system: 0,
      interfaces: 0,
      anomalies: 0,
      other: 0,
    };

    snmpMetrics.forEach((item) => {
      const category = metricCategory(item.metric, item);
      counts[category] = (counts[category] || 0) + 1;
    });

    return counts;
  }, [snmpMetrics]);

  const snmpLimitOptions = useMemo(() => {
    return [
      { value: "10", label: "10" },
      { value: "15", label: "15" },
      { value: "20", label: "20" },
      { value: "40", label: "40" },
      { value: "60", label: "60" },
    ];
  }, []);

  const enrichedSyslog = useMemo(() => syslog.map((item) => enrichSyslogEvent(item)), [syslog]);

  const loopRiskIncidents = useMemo(() => {
    const fromPredictions = Array.isArray(predictions?.loop_risk_incidents)
      ? predictions.loop_risk_incidents
      : [];

    if (fromPredictions.length) return fromPredictions;

    return incidents.filter(
      (item) => String(item.incident_type || "").toLowerCase() === "loop_risk"
    );
  }, [incidents, predictions]);

  const openLoopRiskIncidents = useMemo(
    () =>
      loopRiskIncidents.filter((item) => {
        const status = String(item.status || "").toLowerCase();
        return status === "open" || status === "acknowledged";
      }),
    [loopRiskIncidents]
  );

  const resolvedLoopRiskIncidents = useMemo(
    () =>
      loopRiskIncidents.filter((item) => {
        const status = String(item.status || "").toLowerCase();
        return status === "resolved" || status === "closed";
      }),
    [loopRiskIncidents]
  );

  const precursorSyslog = useMemo(
    () => enrichedSyslog.filter((item) => item.category === "loop" || item.category === "mac" || isLoopSignal(item)),
    [enrichedSyslog]
  );

  const openIncidents = useMemo(
    () => incidents.filter((item) => String(item.status || "").toLowerCase() === "open"),
    [incidents]
  );

  const closedIncidents = useMemo(
    () => incidents.filter((item) => String(item.status || "").toLowerCase() === "closed"),
    [incidents]
  );

  const anomalyScores = useMemo(
    () => (Array.isArray(predictions?.anomaly_scores) ? predictions.anomaly_scores : []),
    [predictions]
  );

  const latestLoopRiskScore = useMemo(
    () =>
      anomalyScores.find(
        (item) => String(item.metric || "").toLowerCase() === "loop_risk"
      ) || null,
    [anomalyScores]
  );

  const syslogTypeOptions = useMemo(
    () => [
      { value: "precursor", label: "Precursores de loop" },
      { value: "link", label: "Link / Flap" },
      { value: "loop", label: "Loop / STP" },
      { value: "mac", label: "MAC / Storm" },
      { value: "manual", label: "Manual / Sistema" },
      { value: "other", label: "Outros" },
    ],
    []
  );

  const syslogSubsystemOptions = useMemo(() => {
    const options = enrichedSyslog
      .map((item) => item.subsystem)
      .filter(Boolean)
      .filter((value, index, array) => array.indexOf(value) === index)
      .sort((a, b) => formatSyslogSubsystem(a).localeCompare(formatSyslogSubsystem(b), "pt-BR"));

    return options;
  }, [enrichedSyslog]);

  const syslogInterfaceOptions = useMemo(() => {
    const options = enrichedSyslog
      .map((item) => item.iface)
      .filter(Boolean)
      .filter((value, index, array) => array.indexOf(value) === index)
      .sort((a, b) => a.localeCompare(b, "pt-BR", { numeric: true }));

    return options;
  }, [enrichedSyslog]);

  const syslogSeverityOptions = useMemo(() => {
    const options = enrichedSyslog
      .map((item) => item.severity)
      .filter(Boolean)
      .filter((value, index, array) => array.indexOf(value) === index)
      .sort((a, b) => severityRank(b) - severityRank(a));

    return options;
  }, [enrichedSyslog]);

  const syslogTypeCounts = useMemo(() => {
    const counts = {
      all: enrichedSyslog.length,
      precursor: 0,
      link: 0,
      loop: 0,
      mac: 0,
      manual: 0,
      other: 0,
    };

    enrichedSyslog.forEach((item) => {
      counts[item.category] = (counts[item.category] || 0) + 1;
      if (item.category === "loop" || item.category === "mac" || isLoopSignal(item)) {
        counts.precursor += 1;
      }
    });

    return counts;
  }, [enrichedSyslog]);

  const filteredSyslog = useMemo(() => {
    const normalized = syslogQuery.trim().toLowerCase();

    const result = enrichedSyslog.filter((item) => {
      if (
        syslogType === "precursor" &&
        item.category !== "loop" &&
        item.category !== "mac" &&
        !isLoopSignal(item)
      ) {
        return false;
      }
      if (syslogType !== "all" && syslogType !== "precursor" && item.category !== syslogType) {
        return false;
      }
      if (syslogSeverityFilter !== "all" && item.severity !== syslogSeverityFilter) {
        return false;
      }
      if (syslogSubsystemFilter !== "all" && item.subsystem !== syslogSubsystemFilter) {
        return false;
      }
      if (syslogInterfaceFilter !== "all" && item.iface !== syslogInterfaceFilter) {
        return false;
      }

      if (!normalized) return true;

      return String(item.searchable || "").includes(normalized);
    });

    return result.slice(0, Number(syslogLimit));
  }, [
    enrichedSyslog,
    syslogInterfaceFilter,
    syslogLimit,
    syslogQuery,
    syslogSeverityFilter,
    syslogSubsystemFilter,
    syslogType,
  ]);

  const filteredIncidents = useMemo(() => {
    if (incidentStatusFilter === "all") return incidents;

    return incidents.filter(
      (item) => String(item.status || "").toLowerCase() === incidentStatusFilter
    );
  }, [incidentStatusFilter, incidents]);

  const monitoringProtocolOptions = useMemo(() => {
    const options = Array.from(
      new Set(
        monitoringItems
          .map((item) => String(item.protocol || "").toUpperCase())
          .filter(Boolean)
      )
    ).sort((a, b) => a.localeCompare(b, "pt-BR"));

    return options;
  }, [monitoringItems]);

  const filteredMonitoringItems = useMemo(() => {
    const normalized = monitoringQuery.trim().toLowerCase();

    const items = monitoringItems.filter((item) => {
      const protocol = String(item.protocol || "").toUpperCase();
      const status = item.enabled === false ? "inactive" : "active";
      if (monitoringProtocolFilter !== "all" && protocol !== monitoringProtocolFilter) return false;
      if (monitoringStatusFilter !== "all" && status !== monitoringStatusFilter) return false;
      if (!normalized) return true;

      return [
        item.display_name,
        item.item_key,
        item.protocol,
        item.oid,
        item.last_error,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalized);
    });

    items.sort((a, b) => {
      const enabledDiff = Number(Boolean(b.enabled)) - Number(Boolean(a.enabled));
      if (enabledDiff !== 0) return enabledDiff;
      return String(a.display_name || a.item_key || "").localeCompare(
        String(b.display_name || b.item_key || ""),
        "pt-BR",
        { numeric: true }
      );
    });

    return items;
  }, [monitoringItems, monitoringProtocolFilter, monitoringQuery, monitoringStatusFilter]);

  const monitoringPageSizeValue = Math.max(5, Number(monitoringPageSize) || 10);
  const monitoringPageCount = Math.max(1, Math.ceil(filteredMonitoringItems.length / monitoringPageSizeValue));
  const visibleMonitoringItems = filteredMonitoringItems.slice(
    (Math.min(monitoringPage, monitoringPageCount) - 1) * monitoringPageSizeValue,
    Math.min(monitoringPage, monitoringPageCount) * monitoringPageSizeValue
  );

  const filteredInterfaces = useMemo(() => {
    const normalized = interfaceQuery.trim().toLowerCase();

    const items = interfaces.filter((iface) => {
      const status = isInterfaceActiveForDisplay(iface) ? "active" : "down";
      const attention = !isInterfaceActiveForDisplay(iface) || isInterfaceRelevantForDisplay(iface);
      if (interfaceStatusFilter === "active" && status !== "active") return false;
      if (interfaceStatusFilter === "down" && status !== "down") return false;
      if (interfaceStatusFilter === "attention" && !attention) return false;
      if (!normalized) return true;

      return [
        interfaceDisplayName(iface),
        interfaceSummary(iface),
        iface.ifindex,
        iface.admin_status,
        iface.oper_status,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalized);
    });

    items.sort((a, b) => {
      const aScore = Number(Boolean(isInterfaceActiveForDisplay(a))) + Number(Boolean(isInterfaceRelevantForDisplay(a)));
      const bScore = Number(Boolean(isInterfaceActiveForDisplay(b))) + Number(Boolean(isInterfaceRelevantForDisplay(b)));
      if (aScore !== bScore) return bScore - aScore;
      return String(interfaceDisplayName(a)).localeCompare(String(interfaceDisplayName(b)), "pt-BR", {
        numeric: true,
      });
    });

    return items;
  }, [interfaceQuery, interfaceStatusFilter, interfaces]);

  const interfacePageSizeValue = Math.max(5, Number(interfacePageSize) || 10);
  const interfacePageCount = Math.max(1, Math.ceil(filteredInterfaces.length / interfacePageSizeValue));
  const visibleInterfaces = filteredInterfaces.slice(
    (Math.min(interfacePage, interfacePageCount) - 1) * interfacePageSizeValue,
    Math.min(interfacePage, interfacePageCount) * interfacePageSizeValue
  );

  const filteredCorrelations = useMemo(() => {
    const normalized = correlationQuery.trim().toLowerCase();

    const items = correlations.filter((item) => {
      const iface = normalizeInterfaceName(item.normalized_iface || item.if_name || item.ifdescr || item.if_alias);
      const metric = String(item.metric_name || item.metric || "").toLowerCase();
      const message = String(item.event_message || item.syslog_message || "").toLowerCase();
      const confidence = Number(item.confidence || 0);
      const relevant = confidence >= 0.2 || iface || message || metric;

      if (correlationFilter === "relevant" && !relevant) return false;
      if (correlationFilter === "all") return true;

      if (!normalized) return true;

      return [iface, metric, message, item.event_subsystem, item.iface, item.event_ifname, item.event_ifalias]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalized);
    });

    items.sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));

    return items;
  }, [correlationFilter, correlationQuery, correlations]);

  useEffect(() => {
    setMonitoringPage(1);
  }, [monitoringProtocolFilter, monitoringQuery, monitoringStatusFilter, monitoringItems.length]);

  useEffect(() => {
    setInterfacePage(1);
  }, [interfaceQuery, interfaceStatusFilter, interfaces.length]);

  const sortedPredictions = useMemo(() => {
    const items = [...anomalyScores];

    if (predictionSort === "score_asc") {
      items.sort((a, b) => Number(a.score || 0) - Number(b.score || 0));
      return items;
    }

    if (predictionSort === "recent") {
      items.sort((a, b) => new Date(b.ts) - new Date(a.ts));
      return items;
    }

    items.sort((a, b) => Number(b.score || 0) - Number(a.score || 0));
    return items;
  }, [anomalyScores, predictionSort]);

  const latestCollectionTime =
    latestAliveMetric?.ts || latestRttMetric?.ts || latestLossMetric?.ts || metrics[0]?.ts || null;

  const lastRelevantIncident = useMemo(
    () => openIncidents[0] || incidents[0] || null,
    [incidents, openIncidents]
  );

  const hostMissing = hostLoadState === "not_found";
  const hostLoadError = hostLoadState === "error";
  const hostDisplayName =
    host?.name ||
    (hostMissing ? "Host nao encontrado" : hostLoadError ? "Erro ao carregar host" : `Host ${hostId}`);

  const groupDisplay = host?.group_path || host?.group_name || "Sem grupo legado";
  const templateDisplay = host?.template_name || "Sem template legado";
  const templateMeta = [host?.template_vendor, host?.template_family, host?.template_asset_type]
    .filter(Boolean)
    .join(" / ");
  const resolvedCollectionPolicy = host?.collection_policy_resolved || {};
  const collectionSourceLabels = host?.collection_policy_source_labels || {};
  const collectionPolicyLabel = formatCollectionPolicySummary(resolvedCollectionPolicy);
  const collectionPolicyHeadline = formatCollectionPolicyHeadline(resolvedCollectionPolicy);
  const collectionRetentionSummary = formatRetentionSummary(resolvedCollectionPolicy);
  const collectionPolicySourceLabel = (() => {
    const entries = Object.entries(collectionSourceLabels);
    if (!entries.length) return "Politica global";

    const templateCount = entries.filter(([, label]) => String(label || "").toLowerCase().includes("template")).length;
    const globalCount = entries.length - templateCount;

    if (templateCount && globalCount) {
      return `${templateCount} template(s) | ${globalCount} global(is)`;
    }

    if (templateCount) {
      return `${templateCount} template(s)`;
    }

    return `${globalCount} global(is)`;
  })();

  const nextCollectionEstimate = useMemo(() => {
    const candidates = [host?.next_icmp_collection_at, host?.next_snmp_collection_at]
      .filter(Boolean)
      .map((value) => new Date(value))
      .filter((value) => !Number.isNaN(value.getTime()))
      .sort((a, b) => a - b);
    return candidates[0]?.toISOString() || null;
  }, [host?.next_icmp_collection_at, host?.next_snmp_collection_at]);

  const profileNames = useMemo(
    () =>
      profiles
        .map((profile) => profile.display_name || profile.name)
        .filter(Boolean),
    [profiles]
  );

  const activeProfileCount = useMemo(
    () => profiles.filter((profile) => profile.enabled !== false).length,
    [profiles]
  );

  const tabCounts = useMemo(
    () => ({
      summary: null,
      insights: Object.values(hostInsights).filter(Boolean).length,
      visualization: dashboards.length,
      monitoring: monitoringItems.length,
      snmp: snmpMetrics.length,
      syslog: syslog.length,
      incidents: incidents.length,
      predictions: anomalyScores.length,
    }),
    [
      anomalyScores.length,
      dashboards.length,
      hostInsights,
      incidents.length,
      monitoringItems.length,
      snmpMetrics.length,
      syslog.length,
    ]
  );

  const timelineItems = useMemo(
    () =>
      buildTimelineItems({
        latestAliveMetric,
        precursorSyslog,
        loopRiskIncidents,
        anomalyScores,
      }),
    [anomalyScores, latestAliveMetric, loopRiskIncidents, precursorSyslog]
  );

  const summaryCards = (
    <section className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <InfoCard
        title="Saúde"
        value={health.label}
        subtitle="Baseado na última telemetria"
        tone={
          health.label === "Saudável"
            ? "emerald"
            : health.label === "Indisponível"
            ? "red"
            : "slate"
        }
      />
      <InfoCard
        title="Grupo"
        value={groupDisplay}
        subtitle={
          host?.group_id
            ? "Grupo principal do cadastro"
            : "Host legado sem grupo persistido"
        }
        tone={host?.group_id ? "slate" : "amber"}
        valueClassName="text-base leading-6"
      />
      <InfoCard
        title="Template de monitoramento"
        value={templateDisplay}
        subtitle={templateMeta || (host?.template_id ? "Template principal do host" : "Host legado sem template persistido")}
        tone={host?.template_id ? "sky" : "amber"}
        valueClassName="text-base leading-6"
      />
      <InfoCard
        title="Políticas de coleta"
        value={formatPolicyCountLabel(activeProfileCount)}
        subtitle={
          activeProfileCount
            ? `${profileNames.slice(0, 2).join(" / ")}${
                activeProfileCount > 2 ? ` +${activeProfileCount - 2}` : ""
              }`
            : "Nenhuma política aplicada"
        }
        tone={activeProfileCount ? "sky" : "slate"}
        valueClassName="text-base leading-6"
      />
      <InfoCard
        title="Última coleta"
        value={latestCollectionTime ? formatDateTime(latestCollectionTime) : "-"}
        subtitle={
          latestCollectionTime
            ? "Última telemetria recebida"
            : "Sem telemetria recente"
        }
        tone={latestCollectionTime ? "sky" : "slate"}
        valueClassName="text-base leading-6"
      />
      <InfoCard
        title="Intervalo atual"
        value={collectionPolicyHeadline}
        subtitle={collectionRetentionSummary}
        tone="sky"
        valueClassName="text-sm leading-6"
      />
      <InfoCard
        title="Próxima coleta estimada"
        value={nextCollectionEstimate ? formatDateTime(nextCollectionEstimate) : "-"}
        subtitle={nextCollectionEstimate ? "Menor janela entre ICMP e SNMP" : "Aguardando primeira coleta para estimar"}
        tone={nextCollectionEstimate ? "sky" : "slate"}
        valueClassName="text-base leading-6"
      />
      <InfoCard
        title="Último incidente"
        value={
          lastRelevantIncident
            ? formatIncidentType(lastRelevantIncident.incident_type)
            : "Sem incidentes"
        }
        subtitle={
          lastRelevantIncident
            ? `${formatStatusLabel(lastRelevantIncident.status)} | ${formatDateTime(
                lastRelevantIncident.last_seen_at || lastRelevantIncident.opened_at
              )}`
            : "Nenhum incidente relevante para o host"
        }
        tone={
          lastRelevantIncident
            ? String(lastRelevantIncident.status || "").toLowerCase() === "open"
              ? "red"
              : "slate"
            : "slate"
        }
        valueClassName="text-base leading-6"
      />
      <InfoCard
        title="Risco de loop"
        value={
          openLoopRiskIncidents.length
            ? `${openLoopRiskIncidents.length} incidente(s) aberto(s)`
            : latestLoopRiskScore
            ? `${Math.round(Number(latestLoopRiskScore.score || 0) * 100)}%`
            : resolvedLoopRiskIncidents.length
            ? "Sem incidente aberto"
            : "Sem alerta"
        }
        subtitle={
          openLoopRiskIncidents.length
            ? "Incidente ativo de risco de loop no host"
            : latestLoopRiskScore
            ? "Índice recente calculado por correlação"
            : resolvedLoopRiskIncidents.length
            ? "Há histórico recente, mas sem incidente ativo"
            : "Nenhum risco de loop associado"
        }
        tone={openLoopRiskIncidents.length || latestLoopRiskScore ? "amber" : "sky"}
      />
    </section>
  );

  function renderSummaryLegacy() {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-semibold text-white">Identificação do host</h2>
              {host?.tags?.demo_primary ? (
                <Pill className="bg-sky-500/20 text-sky-100 border-sky-400/30">
                  Ativo principal da demonstração
                </Pill>
              ) : null}
            </div>
            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-slate-400">Nome</div>
                <div className="mt-1 text-white font-medium">{host?.name || "-"}</div>
              </div>
              <div>
                <div className="text-slate-400">IP</div>
                <div className="mt-1 text-white font-medium">{host?.ip || "-"}</div>
              </div>
              <div>
                <div className="text-slate-400">Status do cadastro</div>
                <div className="mt-1">
                  <Pill
                    className={
                      host?.enabled
                        ? "bg-emerald-500/20 text-emerald-200 border-emerald-500/30"
                        : "bg-slate-500/20 text-slate-200 border-slate-500/30"
                    }
                  >
                    {host?.enabled ? "Ativo" : "Inativo"}
                  </Pill>
                </div>
              </div>
              <div>
                <div className="text-slate-400">Saúde atual</div>
                <div className="mt-1">
                  <Pill className={health.className}>{health.label}</Pill>
                </div>
              </div>
              <div>
                <div className="text-slate-400">Versão SNMP</div>
                <div className="mt-1 text-white font-medium">
                  {host?.snmp_profile?.version || "-"}
                </div>
              </div>
              <div>
                <div className="text-slate-400">Community SNMP</div>
                <div className="mt-1 text-white font-medium">
                  {host?.snmp_profile?.community ? "Configurada" : "-"}
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <h2 className="text-lg font-semibold text-white">Panorama operacional</h2>
            <div className="mt-4 grid grid-cols-1 items-start md:grid-cols-2 gap-4">
              <InfoCard
                title="RTT ICMP"
                value={latestRttMetric ? `${formatNumber(latestRttMetric.value)} ms` : "-"}
                subtitle={latestRttMetric ? formatDateTime(latestRttMetric.ts) : "Sem coleta recente"}
                tone="sky"
              />
              <InfoCard
                title="Perda ICMP"
                value={latestLossMetric ? `${formatNumber(latestLossMetric.value)} %` : "-"}
                subtitle={latestLossMetric ? formatDateTime(latestLossMetric.ts) : "Sem coleta recente"}
                tone="sky"
              />
              <InfoCard
                title="Métricas SNMP"
                value={snmpMetrics.length}
                subtitle={`${observedInterfaces} interface(s) observada(s)`}
              />
              <InfoCard
                title="Syslogs recentes"
                value={syslog.length}
                subtitle={`${precursorSyslog.length} sinal(is) precursor(es) de loop`}
                tone={precursorSyslog.length ? "amber" : "slate"}
              />
            </div>

            <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/40 p-4">
              <div className="text-sm font-medium text-white">Leitura para a banca</div>
              <div className="mt-2 text-sm text-slate-300">
                O NetGuard acompanha a disponibilidade do ativo, correlaciona sinais precursores
                recebidos por syslog, cruza esse contexto com telemetria SNMP e destaca incidentes
                e previsões operacionais no mesmo fluxo.
              </div>
            </div>
          </section>
        </div>

        {loopRiskIncidents.length > 0 ? (
          <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5">
            <div className="flex flex-wrap items-center gap-3">
              <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/40">
                Destaque para banca
              </Pill>
              <h2 className="text-lg font-semibold text-white">
                Host com sinalização de risco de loop
              </h2>
            </div>

            <div className="mt-4 space-y-3">
              {loopRiskIncidents.map((incident) => (
                <div
                  key={incident.id}
                  className="rounded-lg border border-amber-500/20 bg-slate-950/40 p-4"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/30">
                      {formatIncidentType(incident.incident_type)}
                    </Pill>
                    <Pill
                      className={
                        STATUS_CLASSES[String(incident.status || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatStatusLabel(incident.status)}
                    </Pill>
                    <Pill
                      className={
                        SEVERITY_CLASSES[String(incident.severity || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatSeverityLabel(incident.severity)}
                    </Pill>
                  </div>

                  <div className="mt-3 text-white font-medium">{incident.title}</div>

                  <div className="mt-2 text-sm text-slate-300">
                    Aberto em {formatDateTime(incident.opened_at)}
                  </div>

                  {Array.isArray(getIncidentEvidence(incident)) &&
                  getIncidentEvidence(incident).length ? (
                    (() => {
                      const evidencePreview = formatEvidencePreview(getIncidentEvidence(incident), 4);
                      return (
                        <div className="mt-3 space-y-2">
                          <div className="flex flex-wrap gap-2">
                            {evidencePreview.visible.map((evidence, index) => (
                              <Pill
                                key={`${incident.id}-${index}`}
                                className="bg-slate-900/70 text-slate-100 border-white/10"
                              >
                                {evidence}
                              </Pill>
                            ))}
                          </div>
                          {evidencePreview.hiddenCount ? (
                            <div className="text-xs text-slate-500">
                              +{evidencePreview.hiddenCount} evidência(s) menos relevante(s) ocultada(s) para manter a leitura limpa.
                            </div>
                          ) : null}
                        </div>
                      );
                    })()
                  ) : null}

                  {incident?.details?.recommendation ? (
                    <div className="mt-3 text-sm text-slate-200">
                      {incident.details.recommendation}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </section>
        ) : null}

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Timeline operacional do host</h2>
              <p className="mt-1 text-sm text-slate-400">
                Sequência recente de telemetria, syslog, previsões e incidentes.
              </p>
            </div>
            <Pill className="bg-slate-800 text-slate-100 border-white/10">
              {timelineItems.length} evento(s)
            </Pill>
          </div>

          <div className="mt-5 space-y-4">
            {timelineItems.length ? (
              timelineItems.map((item) => (
                <div
                  key={item.id}
                  className="relative rounded-xl border border-white/10 bg-slate-950/40 p-4 pl-6"
                >
                  <span
                    className={`absolute left-0 top-0 h-full w-1 rounded-l-xl ${
                      item.tone === "red"
                        ? "bg-red-400"
                        : item.tone === "amber"
                        ? "bg-amber-400"
                        : item.tone === "emerald"
                        ? "bg-emerald-400"
                        : "bg-sky-400"
                    }`}
                  />

                  <div className="flex flex-wrap items-center gap-2">
                    <Pill className="bg-slate-800 text-slate-100 border-white/10">
                      {item.badge}
                    </Pill>
                    {item.severity ? (
                      <Pill
                        className={
                          SEVERITY_CLASSES[String(item.severity || "").toLowerCase()] ||
                          "bg-slate-500/20 text-slate-200 border-slate-500/30"
                        }
                      >
                        {formatSeverityLabel(item.severity)}
                      </Pill>
                    ) : null}
                    <span className="text-xs text-slate-400">{formatDateTime(item.ts)}</span>
                  </div>

                  <div className="mt-3 text-base font-medium text-white">{item.title}</div>
                  <div className="mt-1 text-sm text-slate-300">{item.detail}</div>
                </div>
              ))
            ) : (
              <EmptyState
                title="Sem eventos suficientes para a linha do tempo"
                subtitle="A timeline será preenchida conforme chegarem telemetria, syslog, previsões e incidentes."
              />
            )}
          </div>
        </section>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <h2 className="text-lg font-semibold text-white">Sinais recentes de syslog</h2>

            <div className="mt-4 space-y-3">
              {precursorSyslog.length ? (
                precursorSyslog.slice(0, 5).map((event) => (
                  <div
                    key={event.id}
                    className="rounded-lg border border-amber-500/20 bg-slate-950/40 p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/30">
                        Possível precursor
                      </Pill>
                      {event.severity ? (
                        <Pill
                          className={
                            SEVERITY_CLASSES[String(event.severity || "").toLowerCase()] ||
                            "bg-slate-500/20 text-slate-200 border-slate-500/30"
                          }
                        >
                          {formatSeverityLabel(event.severity)}
                        </Pill>
                      ) : null}
                      <span className="text-xs text-slate-400">
                        {formatDateTime(event.ts)}
                      </span>
                    </div>
                    <div className="mt-2 text-white font-medium">{event.message}</div>
                    <div className="mt-2 text-sm text-slate-400">
                      {event.subsystem || "-"} {event.iface ? ` | ${event.iface}` : ""}
                    </div>
                  </div>
                ))
              ) : (
                <EmptyState
                  title="Sem sinais precursores recentes"
                  subtitle="Os eventos de syslog relacionados a loop aparecerão aqui."
                />
              )}
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <h2 className="text-lg font-semibold text-white">Incidentes do host</h2>

            <div className="mt-4 space-y-3">
              {incidents.length ? (
                incidents.slice(0, 5).map((incident) => (
                  <div
                    key={incident.id}
                    className="rounded-lg border border-white/10 bg-slate-950/40 p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill
                        className={
                          STATUS_CLASSES[String(incident.status || "").toLowerCase()] ||
                          "bg-slate-500/20 text-slate-200 border-slate-500/30"
                        }
                      >
                        {formatStatusLabel(incident.status)}
                      </Pill>
                      <Pill
                        className={
                          SEVERITY_CLASSES[String(incident.severity || "").toLowerCase()] ||
                          "bg-slate-500/20 text-slate-200 border-slate-500/30"
                        }
                      >
                        {formatSeverityLabel(incident.severity)}
                      </Pill>
                      <Pill className="bg-slate-800 text-slate-100 border-white/10">
                        {formatIncidentType(incident.incident_type)}
                      </Pill>
                    </div>
                    <div className="mt-2 text-white font-medium">{incident.title}</div>
                    <div className="mt-2 text-sm text-slate-400">
                      Aberto em {formatDateTime(incident.opened_at)}
                    </div>
                  </div>
                ))
              ) : (
                <EmptyState
                  title="Nenhum incidente associado"
                  subtitle="Incidentes abertos e fechados deste host aparecerão aqui."
                />
              )}
            </div>
          </section>
        </div>
      </div>
    );
  }

  void renderSummaryLegacy;

  function renderSummary() {
    return (
      <div className="space-y-6">
        {!host?.group_id ? (
          <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/30">
                Cadastro legado
              </Pill>
              <div className="text-sm text-amber-100">
                Este host ainda está sem grupo persistido. A regularização deve ser feita em
                Coleta de dados &gt; Hosts antes de novas alterações de cadastro.
              </div>
            </div>
          </section>
        ) : null}

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.35fr),minmax(340px,0.95fr)]">
          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-white">Contexto do host</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Cadastro, grupo e cobertura de monitoramento consolidados em um único bloco.
                </p>
              </div>
              <Pill className={health.className}>{health.label}</Pill>
            </div>

            <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2">
              <KeyValueItem label="Nome" value={host?.name || "-"} accent />
              <KeyValueItem label="IP" value={host?.ip || "-"} accent />
              <KeyValueItem label="Grupo" value={groupDisplay} />
              <KeyValueItem label="Template" value={templateDisplay} />
              <KeyValueItem
                label="Políticas aplicadas"
                value={
                  activeProfileCount
                    ? formatPolicyCountLabel(activeProfileCount)
                    : "Nenhuma política aplicada"
                }
              />
              <KeyValueItem
                label="Última coleta"
                value={latestCollectionTime ? formatDateTime(latestCollectionTime) : "-"}
              />
              <KeyValueItem label="Política de coleta e retenção" value={collectionPolicyLabel} />
              <KeyValueItem label="Origem da política" value={collectionPolicySourceLabel} />
              <KeyValueItem
                label="Última coleta ICMP"
                value={host?.last_icmp_collection_at ? formatDateTime(host.last_icmp_collection_at) : "-"}
              />
              <KeyValueItem
                label="Última coleta SNMP"
                value={host?.last_snmp_collection_at ? formatDateTime(host.last_snmp_collection_at) : "-"}
              />
              <KeyValueItem
                label="Próximo ICMP estimado"
                value={host?.next_icmp_collection_at ? formatDateTime(host.next_icmp_collection_at) : "-"}
              />
              <KeyValueItem
                label="Próximo SNMP estimado"
                value={host?.next_snmp_collection_at ? formatDateTime(host.next_snmp_collection_at) : "-"}
              />
              <KeyValueItem
                label="Último incidente"
                value={
                  lastRelevantIncident
                    ? lastRelevantIncident.title
                    : "Nenhum incidente relevante"
                }
              />
              <KeyValueItem
                label="SNMP"
                value={
                  host?.snmp_profile?.community
                    ? `${String(host?.snmp_profile?.version || "v2c").toUpperCase()} | porta ${
                        host?.snmp_profile?.port || 161
                      }`
                    : "Configuração pendente"
                }
              />
              <KeyValueItem
                label="Cobertura de interfaces"
                value={`${observedInterfaces} interface(s) observada(s)`}
              />
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div>
              <h2 className="text-lg font-semibold text-white">Prioridades operacionais</h2>
              <p className="mt-1 text-sm text-slate-400">
                Indicadores rápidos para triagem e leitura do estado atual do host.
              </p>
            </div>

            <div className="mt-4 grid grid-cols-1 items-start gap-4 md:grid-cols-2">
              <InfoCard
                title="RTT ICMP"
                value={latestRttMetric ? `${formatNumber(latestRttMetric.value)} ms` : "-"}
                subtitle={
                  latestRttMetric ? formatDateTime(latestRttMetric.ts) : "Sem coleta recente"
                }
                tone="sky"
                valueClassName="text-xl"
              />
              <InfoCard
                title="Perda ICMP"
                value={latestLossMetric ? `${formatNumber(latestLossMetric.value)} %` : "-"}
                subtitle={
                  latestLossMetric ? formatDateTime(latestLossMetric.ts) : "Sem coleta recente"
                }
                tone="sky"
                valueClassName="text-xl"
              />
              <InfoCard
                title="Syslog precursor"
                value={precursorSyslog.length}
                subtitle="Eventos relacionados a sinais de loop"
                tone={precursorSyslog.length ? "amber" : "slate"}
              />
              <InfoCard
                title="Incidentes abertos"
                value={openIncidents.length}
                subtitle="Fila operacional atual do host"
                tone={openIncidents.length ? "red" : "emerald"}
              />
            </div>

            <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/40 p-4">
              <div className="text-xs uppercase tracking-[0.14em] text-slate-500">
                Leitura rápida
              </div>
              <div className="mt-2 text-sm font-medium text-white">
                {lastRelevantIncident
                  ? lastRelevantIncident.title
                  : "Nenhum incidente relevante para destacar agora."}
              </div>
              <div className="mt-2 text-sm text-slate-400">
                {lastRelevantIncident
                  ? `${formatIncidentType(lastRelevantIncident.incident_type)} | ${formatStatusLabel(
                    lastRelevantIncident.status
                    )} | ${formatDateTime(
                      lastRelevantIncident.last_seen_at || lastRelevantIncident.opened_at
                    )}`
                  : "Use as abas abaixo para aprofundar telemetria, syslog, incidentes e previsões do host."}
              </div>
            </div>
          </section>
        </div>

        {loopRiskIncidents.length > 0 ? (
          <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5">
            <div className="flex flex-wrap items-center gap-3">
              <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/40">
                Atenção prioritária
              </Pill>
              <div>
                <h2 className="text-lg font-semibold text-white">
                  Risco de loop em acompanhamento
                </h2>
                <p className="mt-1 text-sm text-amber-100/90">
                  Incidentes de risco de loop priorizados para acompanhamento operacional.
                </p>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              {loopRiskIncidents.map((incident) => (
                <div
                  key={incident.id}
                  className="rounded-lg border border-amber-500/20 bg-slate-950/40 p-4"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/30">
                      {formatIncidentType(incident.incident_type)}
                    </Pill>
                    <Pill
                      className={
                        STATUS_CLASSES[String(incident.status || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatStatusLabel(incident.status)}
                    </Pill>
                    <Pill
                      className={
                        SEVERITY_CLASSES[String(incident.severity || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatSeverityLabel(incident.severity)}
                    </Pill>
                  </div>

                  <div className="mt-3 text-white font-medium">{incident.title}</div>

                  <div className="mt-2 text-sm text-slate-300">
                    Aberto em {formatDateTime(incident.opened_at)}
                  </div>

                  {Array.isArray(getIncidentEvidence(incident)) &&
                  getIncidentEvidence(incident).length ? (
                    (() => {
                      const evidencePreview = formatEvidencePreview(getIncidentEvidence(incident), 4);
                      return (
                        <div className="mt-3 space-y-2">
                          <div className="flex flex-wrap gap-2">
                            {evidencePreview.visible.map((evidence, index) => (
                              <Pill
                                key={`${incident.id}-${index}`}
                                className="bg-slate-900/70 text-slate-100 border-white/10"
                              >
                                {evidence}
                              </Pill>
                            ))}
                          </div>
                          {evidencePreview.hiddenCount ? (
                            <div className="text-xs text-slate-500">
                              +{evidencePreview.hiddenCount} evidência(s) menos relevante(s) ocultada(s) para manter a leitura limpa.
                            </div>
                          ) : null}
                        </div>
                      );
                    })()
                  ) : null}

                  {incident?.details?.recommendation ? (
                    <div className="mt-3 text-sm text-slate-200">
                      {incident.details.recommendation}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </section>
        ) : null}

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Linha do tempo operacional</h2>
              <p className="mt-1 text-sm text-slate-400">
                Sequência recente de telemetria, syslog, previsões e incidentes do host.
              </p>
            </div>
            <Pill className="bg-slate-800 text-slate-100 border-white/10">
              {timelineItems.length} evento(s)
            </Pill>
          </div>

          <div className="mt-5 space-y-4">
            {timelineItems.length ? (
              timelineItems.map((item) => (
                <div
                  key={item.id}
                  className="relative rounded-xl border border-white/10 bg-slate-950/40 p-4 pl-6"
                >
                  <span
                    className={`absolute left-0 top-0 h-full w-1 rounded-l-xl ${
                      item.tone === "red"
                        ? "bg-red-400"
                        : item.tone === "amber"
                        ? "bg-amber-400"
                        : item.tone === "emerald"
                        ? "bg-emerald-400"
                        : "bg-sky-400"
                    }`}
                  />

                  <div className="flex flex-wrap items-center gap-2">
                    <Pill className="bg-slate-800 text-slate-100 border-white/10">
                      {item.badge}
                    </Pill>
                    {item.severity ? (
                      <Pill
                        className={
                          SEVERITY_CLASSES[String(item.severity || "").toLowerCase()] ||
                          "bg-slate-500/20 text-slate-200 border-slate-500/30"
                        }
                      >
                        {formatSeverityLabel(item.severity)}
                      </Pill>
                    ) : null}
                    <span className="text-xs text-slate-400">{formatDateTime(item.ts)}</span>
                  </div>

                  <div className="mt-3 text-base font-medium text-white">{item.title}</div>
                  <div className="mt-1 text-sm text-slate-300">{item.detail}</div>
                </div>
              ))
            ) : (
              <EmptyState
                title="Sem eventos suficientes para a linha do tempo"
                subtitle="A linha do tempo será preenchida conforme chegarem telemetria, syslog, previsões e incidentes."
              />
            )}
          </div>
        </section>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-white">Sinais recentes de syslog</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Eventos com maior relevância operacional para este host.
                </p>
              </div>
              <Pill className="bg-slate-800 text-slate-100 border-white/10">
                {precursorSyslog.length}
              </Pill>
            </div>

            <div className="mt-4 space-y-3">
              {precursorSyslog.length ? (
                precursorSyslog.slice(0, 5).map((event) => (
                  <div
                    key={event.id}
                    className="rounded-lg border border-amber-500/20 bg-slate-950/40 p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/30">
                        Possível precursor
                      </Pill>
                      {event.severity ? (
                        <Pill
                          className={
                            SEVERITY_CLASSES[String(event.severity || "").toLowerCase()] ||
                            "bg-slate-500/20 text-slate-200 border-slate-500/30"
                          }
                        >
                          {formatSeverityLabel(event.severity)}
                        </Pill>
                      ) : null}
                      <span className="text-xs text-slate-400">
                        {formatDateTime(event.ts)}
                      </span>
                    </div>
                    <div className="mt-2 text-white font-medium">{event.message}</div>
                    <div className="mt-2 text-sm text-slate-400">
                      {event.subsystem || "-"} {event.iface ? ` | ${event.iface}` : ""}
                    </div>
                  </div>
                ))
              ) : (
                <EmptyState
                  title="Sem sinais precursores recentes"
                  subtitle="Os eventos de syslog relacionados a loop aparecerão aqui."
                />
              )}
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-white">Fila recente de incidentes</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Incidentes mais recentes para ação ou acompanhamento.
                </p>
              </div>
              <Pill className="bg-slate-800 text-slate-100 border-white/10">
                {incidents.length}
              </Pill>
            </div>

            <div className="mt-4 space-y-3">
              {incidents.length ? (
                incidents.slice(0, 5).map((incident) => (
                  <div
                    key={incident.id}
                    className="rounded-lg border border-white/10 bg-slate-950/40 p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill
                        className={
                          STATUS_CLASSES[String(incident.status || "").toLowerCase()] ||
                          "bg-slate-500/20 text-slate-200 border-slate-500/30"
                        }
                      >
                        {formatStatusLabel(incident.status)}
                      </Pill>
                      <Pill
                        className={
                          SEVERITY_CLASSES[String(incident.severity || "").toLowerCase()] ||
                          "bg-slate-500/20 text-slate-200 border-slate-500/30"
                        }
                      >
                        {formatSeverityLabel(incident.severity)}
                      </Pill>
                      <Pill className="bg-slate-800 text-slate-100 border-white/10">
                        {formatIncidentType(incident.incident_type)}
                      </Pill>
                    </div>

                    <div className="mt-3 text-white font-medium">{incident.title}</div>

                    <div className="mt-2 text-sm text-slate-300">
                      Aberto em {formatDateTime(incident.opened_at)} - Último sinal em{" "}
                      {formatDateTime(incident.last_seen_at)}
                    </div>

                    {incident.details?.recommendation ? (
                      <div className="mt-3 text-sm text-slate-300">
                        {incident.details.recommendation}
                      </div>
                    ) : null}
                  </div>
                ))
              ) : (
                <EmptyState
                  title="Sem incidentes para este host"
                  subtitle="Os incidentes associados ao host aparecerão aqui."
                />
              )}
            </div>
          </section>
        </div>
      </div>
    );
  }

  function renderMonitoring() {
    const protocols = Array.from(
      new Set(monitoringItems.filter((item) => item.enabled).map((item) => String(item.protocol || "").toUpperCase()))
    ).filter(Boolean);
    const loopLabel = loopEvidence?.label || "Sem evidência";
    const loopTone =
      loopEvidence?.state === "loop_detectado"
        ? "red"
        : loopEvidence?.state === "risco_alto"
      ? "amber"
      : loopEvidence?.state === "possivel_risco"
      ? "sky"
      : "slate";

    const currentMonitoringPage = Math.min(monitoringPage, monitoringPageCount);
    const currentInterfacePage = Math.min(interfacePage, interfacePageCount);
    const protocolSummary = protocols.length ? protocols.slice(0, 4).join(", ") : "-";

    return (
      <div className="space-y-6">
        <section className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-4">
          <InfoCard
            title="Protocolos ativos"
            value={protocolSummary}
            subtitle="Itens habilitados no host"
            tone="sky"
            valueClassName="text-base leading-6"
          />
          <InfoCard
            title="Itens monitorados"
            value={monitoringItems.length}
            subtitle={`${monitoringItems.filter((item) => item.enabled).length} ativo(s)`}
            tone="slate"
          />
          <InfoCard
            title="Interfaces relevantes"
            value={relevantInterfaceSet.size}
            subtitle="Ativas, com erro ou associadas a incidente"
            tone="emerald"
          />
          <InfoCard title="Risco de loop" value={loopLabel} subtitle="Janela de 5 minutos" tone={loopTone} />
        </section>

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Monitoramento do host</h2>
              <p className="mt-1 text-sm text-slate-400">
                Selecione uma subaba para ver apenas itens monitorados, inventário SNMP, correlações ou a política aplicada.
              </p>
            </div>
            <Pill className="border-white/10 bg-slate-950/40 text-slate-200">
              {MONITORING_SECTIONS.find((section) => section.id === monitoringSection)?.label || "Monitoramento"}
            </Pill>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            {MONITORING_SECTIONS.map((section) => {
              const active = monitoringSection === section.id;
              return (
                <button
                  key={section.id}
                  type="button"
                  onClick={() => setMonitoringSection(section.id)}
                  className={`rounded-full border px-3 py-1.5 text-xs transition ${
                    active
                      ? "border-sky-400/40 bg-sky-500/20 text-sky-100"
                      : "border-white/10 bg-slate-950/30 text-slate-300 hover:border-slate-500 hover:bg-slate-800/60"
                  }`}
                >
                  {section.label}
                </button>
              );
            })}
          </div>
        </section>

        {monitoringSection === "items" ? (
          <section className="rounded-xl border border-white/10 bg-slate-900/60">
            <div className="border-b border-white/10 p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">Itens monitorados do host</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Filtro por item, protocolo e status. A lista mostra só a página atual.
                  </p>
                </div>
                <Pill className="border-white/10 bg-slate-950/40 text-slate-200">
                  {visibleMonitoringItems.length} / {filteredMonitoringItems.length}
                </Pill>
              </div>

              <div className="mt-4 flex flex-wrap items-end gap-4">
                <div className="min-w-[240px] flex-1">
                  <label className="text-xs text-slate-400">Buscar</label>
                  <input
                    value={monitoringQuery}
                    onChange={(e) => setMonitoringQuery(e.target.value)}
                    placeholder="Item, protocolo, OID, erro..."
                    className="mt-1 w-full rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">Protocolo</label>
                  <select
                    value={monitoringProtocolFilter}
                    onChange={(e) => setMonitoringProtocolFilter(e.target.value)}
                    className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  >
                    <option value="all">Todos</option>
                    {monitoringProtocolOptions.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Status</label>
                  <select
                    value={monitoringStatusFilter}
                    onChange={(e) => setMonitoringStatusFilter(e.target.value)}
                    className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  >
                    <option value="all">Todos</option>
                    <option value="active">Ativos</option>
                    <option value="inactive">Inativos</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Itens por página</label>
                  <select
                    value={monitoringPageSize}
                    onChange={(e) => setMonitoringPageSize(e.target.value)}
                    className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  >
                    <option value="10">10</option>
                    <option value="15">15</option>
                    <option value="20">20</option>
                  </select>
                </div>
                <div>
                  <button
                    type="button"
                    onClick={() => {
                      setMonitoringQuery("");
                      setMonitoringProtocolFilter("all");
                      setMonitoringStatusFilter("all");
                      setMonitoringPage(1);
                    }}
                    className="rounded-md bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700"
                  >
                    Limpar
                  </button>
                </div>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Suporte</th>
                    <th className="px-4 py-3">Protocolo</th>
                    <th className="px-4 py-3">Item</th>
                    <th className="px-4 py-3">OID</th>
                    <th className="px-4 py-3">Intervalo</th>
                    <th className="px-4 py-3">Retenção</th>
                    <th className="px-4 py-3">Última coleta</th>
                    <th className="px-4 py-3">Último erro</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-slate-200">
                  {visibleMonitoringItems.length ? (
                    visibleMonitoringItems.map((item) => (
                      <tr key={item.id} className={item.enabled ? "" : "opacity-60"}>
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            onClick={() => handleToggleMonitoringItem(item)}
                            disabled={savingItemId === `toggle-${item.id}`}
                            className={`rounded-full border px-3 py-1 text-xs font-medium ${
                              item.enabled
                                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                                : "border-slate-500/30 bg-slate-500/10 text-slate-300"
                            }`}
                          >
                            {item.enabled ? "Ativo" : "Inativo"}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${
                              item.supported === false
                                ? "border-slate-500/30 bg-slate-500/10 text-slate-300"
                                : "border-sky-500/30 bg-sky-500/10 text-sky-100"
                            }`}
                          >
                            {item.supported === false ? "Não suportado" : "Suportado quando disponível"}
                          </span>
                        </td>
                        <td className="px-4 py-3 uppercase text-slate-300">{item.protocol}</td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-white">{item.display_name}</div>
                          <div className="text-xs text-slate-500">{item.item_key}</div>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-400">{item.oid || "-"}</td>
                        <td className="px-4 py-3">
                          <input
                            type="number"
                            min="5"
                            max="3600"
                            defaultValue={item.poll_interval_seconds}
                            onBlur={(event) =>
                              handleMonitoringItemNumberChange(item, "poll_interval_seconds", event.target.value)
                            }
                            className="w-20 rounded-md border border-white/10 bg-slate-950 px-2 py-1 text-sm text-white"
                          />
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">
                          Hist {item.history_retention_days}d | Trends {item.trend_retention_days}d | Logs {item.log_retention_days}d
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">{formatDateTime(item.last_collected_at)}</td>
                        <td className="px-4 py-3 text-slate-400">{item.last_error || "-"}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="9" className="px-4 py-10 text-center text-slate-500">
                        Nenhum item monitorado encontrado para este filtro.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/10 px-5 py-4 text-sm text-slate-400">
              <div>
                Página {currentMonitoringPage} de {monitoringPageCount}
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setMonitoringPage((value) => Math.max(1, value - 1))}
                  disabled={currentMonitoringPage <= 1}
                  className="rounded-md border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Anterior
                </button>
                <button
                  type="button"
                  onClick={() => setMonitoringPage((value) => Math.min(monitoringPageCount, value + 1))}
                  disabled={currentMonitoringPage >= monitoringPageCount}
                  className="rounded-md border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Próxima
                </button>
              </div>
            </div>
          </section>
        ) : null}

        {monitoringSection === "interfaces" ? (
          <section className="rounded-xl border border-white/10 bg-slate-900/60">
            <div className="border-b border-white/10 p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">Inventário de interfaces SNMP</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Interface, admin, oper, tráfego, erros, descartes e última atualização.
                  </p>
                </div>
                <Pill className="border-white/10 bg-slate-950/40 text-slate-200">
                  {visibleInterfaces.length} / {filteredInterfaces.length}
                </Pill>
              </div>

              <div className="mt-4 flex flex-wrap items-end gap-4">
                <div className="min-w-[240px] flex-1">
                  <label className="text-xs text-slate-400">Buscar interface</label>
                  <input
                    value={interfaceQuery}
                    onChange={(e) => setInterfaceQuery(e.target.value)}
                    placeholder="Fa0/3, Gi0/1, uplink, alias..."
                    className="mt-1 w-full rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">Status</label>
                  <select
                    value={interfaceStatusFilter}
                    onChange={(e) => setInterfaceStatusFilter(e.target.value)}
                    className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  >
                    <option value="all">Todos</option>
                    <option value="active">Ativas</option>
                    <option value="attention">Com atenção</option>
                    <option value="down">Inativas</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Itens por página</label>
                  <select
                    value={interfacePageSize}
                    onChange={(e) => setInterfacePageSize(e.target.value)}
                    className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  >
                    <option value="10">10</option>
                    <option value="15">15</option>
                    <option value="20">20</option>
                  </select>
                </div>
                <div>
                  <button
                    type="button"
                    onClick={() => {
                      setInterfaceQuery("");
                      setInterfaceStatusFilter("all");
                      setInterfacePage(1);
                    }}
                    className="rounded-md bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700"
                  >
                    Limpar
                  </button>
                </div>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Interface</th>
                    <th className="px-4 py-3">Admin</th>
                    <th className="px-4 py-3">Oper</th>
                    <th className="px-4 py-3">Tráfego</th>
                    <th className="px-4 py-3">Erros / descartes</th>
                    <th className="px-4 py-3">Última atualização</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-slate-200">
                  {visibleInterfaces.length ? (
                    visibleInterfaces.map((iface) => {
                      const ifaceName = interfaceDisplayName(iface);
                      const ifaceSummaryText = interfaceSummary(iface);
                      const active = isInterfaceActiveForDisplay(iface);
                      const attention = isInterfaceRelevantForDisplay(iface);
                      const trafficIn = Number(iface.last_in_bps || 0);
                      const trafficOut = Number(iface.last_out_bps || 0);
                      const errors =
                        Number(iface.last_in_errors || 0) + Number(iface.last_out_errors || 0);
                      const discards =
                        Number(iface.last_in_discards || 0) + Number(iface.last_out_discards || 0);

                      return (
                        <tr key={iface.id} className={attention ? "bg-sky-500/5" : ""}>
                          <td className="px-4 py-3">
                            <div className="font-medium text-white">{ifaceName || "-"}</div>
                            <div className="text-xs text-slate-500">{ifaceSummaryText || "-"}</div>
                          </td>
                          <td className="px-4 py-3">
                            <Pill
                              className={
                                normalizeInterfaceStatus(iface.admin_status) === "up"
                                  ? "border-emerald-400/30 bg-emerald-500/15 text-emerald-100"
                                  : "border-slate-500/30 bg-slate-500/10 text-slate-300"
                              }
                            >
                              {formatSnmpStatusValue("snmp.if.admin_status", iface.admin_status)}
                            </Pill>
                          </td>
                          <td className="px-4 py-3">
                            <Pill
                              className={
                                normalizeInterfaceStatus(iface.oper_status) === "up"
                                  ? "border-emerald-400/30 bg-emerald-500/15 text-emerald-100"
                                  : "border-red-400/30 bg-red-500/15 text-red-100"
                              }
                            >
                              {formatSnmpStatusValue("snmp.if.oper_status", iface.oper_status)}
                            </Pill>
                          </td>
                          <td className="px-4 py-3 text-xs text-slate-300">
                            In {formatBytes(trafficIn)}
                            <br />
                            Out {formatBytes(trafficOut)}
                          </td>
                          <td className="px-4 py-3 text-xs text-slate-300">
                            E {formatNumber(errors, 0)}
                            <br />
                            D {formatNumber(discards, 0)}
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            <div>{formatDateTime(iface.last_seen_at)}</div>
                            <div className="mt-1 text-xs text-slate-500">
                              {active ? "Interface ativa" : attention ? "Com atenção" : "Sem atividade recente"}
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan="6" className="px-4 py-10 text-center text-slate-500">
                        Nenhuma interface com erro no período selecionado.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/10 px-5 py-4 text-sm text-slate-400">
              <div>
                Página {currentInterfacePage} de {interfacePageCount}
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setInterfacePage((value) => Math.max(1, value - 1))}
                  disabled={currentInterfacePage <= 1}
                  className="rounded-md border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Anterior
                </button>
                <button
                  type="button"
                  onClick={() => setInterfacePage((value) => Math.min(interfacePageCount, value + 1))}
                  disabled={currentInterfacePage >= interfacePageCount}
                  className="rounded-md border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Próxima
                </button>
              </div>
            </div>
          </section>
        ) : null}

        {monitoringSection === "correlations" ? (
          <section className="rounded-xl border border-white/10 bg-slate-900/60">
            <div className="border-b border-white/10 p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">Correlação Syslog + SNMP</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Só as associações mais úteis para operação, com interface, confiança e métrica relacionada.
                  </p>
                </div>
                <Pill className="border-white/10 bg-slate-950/40 text-slate-200">
                  {filteredCorrelations.length} correlação(ões)
                </Pill>
              </div>

              <div className="mt-4 flex flex-wrap items-end gap-4">
                <div className="min-w-[240px] flex-1">
                  <label className="text-xs text-slate-400">Buscar</label>
                  <input
                    value={correlationQuery}
                    onChange={(e) => setCorrelationQuery(e.target.value)}
                    placeholder="Fa0/3, STP, MAC flap, syslog, métrica..."
                    className="mt-1 w-full rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">Escopo</label>
                  <select
                    value={correlationFilter}
                    onChange={(e) => setCorrelationFilter(e.target.value)}
                    className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                  >
                    <option value="relevant">Só relevantes</option>
                    <option value="all">Todas</option>
                  </select>
                </div>
                <div>
                  <button
                    type="button"
                    onClick={() => {
                      setCorrelationQuery("");
                      setCorrelationFilter("relevant");
                    }}
                    className="rounded-md bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700"
                  >
                    Limpar
                  </button>
                </div>
              </div>
            </div>

            <div className="grid gap-4 p-5 md:grid-cols-3">
              <InfoCard title="Correlação exibida" value={filteredCorrelations.length} subtitle="Filtro atual" tone="sky" />
              <InfoCard
                title="Alta confiança"
                value={filteredCorrelations.filter((item) => Number(item.confidence || 0) >= 0.7).length}
                subtitle=">= 70%"
                tone="emerald"
              />
              <InfoCard
                title="Com interface"
                value={filteredCorrelations.filter((item) => normalizeInterfaceName(item.normalized_iface || item.if_name || item.ifdescr)).length}
                subtitle="Associação direta"
                tone="amber"
              />
            </div>

            <div className="divide-y divide-white/10">
              {filteredCorrelations.length ? (
                filteredCorrelations.slice(0, 12).map((item) => {
                  const iface = normalizeInterfaceName(item.normalized_iface || item.if_name || item.ifdescr || item.if_alias);
                  const metricLabel = item.metric_name || item.metric || item.event_metric || "Métrica relacionada";
                  const confidence = Math.round(Number(item.confidence || 0) * 100);

                  return (
                    <div key={item.id} className="p-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <Pill className="border-sky-400/30 bg-sky-500/15 text-sky-100">
                          {iface || "Sem interface"}
                        </Pill>
                        <Pill className="border-white/10 bg-slate-800 text-slate-100">
                          confiança {confidence}%
                        </Pill>
                        <Pill className="border-white/10 bg-slate-800 text-slate-100">{metricLabel}</Pill>
                      </div>
                      <div className="mt-2 text-sm text-white">{item.event_message || item.syslog_message || "-"}</div>
                      <div className="mt-1 text-xs text-slate-500">
                        {formatDateTime(item.event_ts || item.ts)} | {item.event_subsystem || "-"}
                        {item.ifindex ? ` | ifIndex ${item.ifindex}` : ""}
                      </div>
                    </div>
                  );
                })
              ) : (
                <EmptyState
                  title="Nenhuma correlação recente encontrada."
                  subtitle="Ajuste o escopo ou aguarde novos syslogs e amostras SNMP para cruzar os eventos."
                />
              )}
            </div>
          </section>
        ) : null}

        {monitoringSection === "policy" ? (
          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-white">Política de coleta e retenção</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Resumo operacional da política aplicada ao host e dos limites persistidos.
                </p>
              </div>
              <Pill className="border-white/10 bg-slate-950/40 text-slate-200">
                {collectionPolicyLabel}
              </Pill>
            </div>

            <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              <KeyValueItem label="ICMP" value={formatDurationSeconds(resolvedCollectionPolicy.icmp_interval_sec)} accent />
              <KeyValueItem label="SNMP" value={formatDurationSeconds(resolvedCollectionPolicy.snmp_interval_sec)} accent />
              <KeyValueItem label="TCP" value={formatDurationSeconds(resolvedCollectionPolicy.tcp_interval_sec)} accent />
              <KeyValueItem label="Timeout" value={formatDurationSeconds(resolvedCollectionPolicy.timeout_sec)} />
              <KeyValueItem label="Tentativas" value={`${resolvedCollectionPolicy.retries || "-"} tentativa(s)`} />
              <KeyValueItem label="Histórico" value={`${resolvedCollectionPolicy.history_retention_days || "-"} dia(s)`} />
              <KeyValueItem label="Trends" value={`${resolvedCollectionPolicy.trend_retention_days || "-"} dia(s)`} />
              <KeyValueItem label="Syslog" value={`${resolvedCollectionPolicy.log_retention_days || "-"} dia(s)`} />
              <KeyValueItem label="Incidentes" value={`${resolvedCollectionPolicy.incident_retention_days || "-"} dia(s)`} />
              <KeyValueItem label="Notificações" value={`${resolvedCollectionPolicy.notification_retention_days || "-"} dia(s)`} />
              <KeyValueItem label="Auditoria" value={`${resolvedCollectionPolicy.audit_retention_days || "-"} dia(s)`} />
              <KeyValueItem label="Origem da política" value={collectionPolicySourceLabel} accent />
            </div>
          </section>
        ) : null}
      </div>
    );

    return (
      <div className="space-y-6">
        <section className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-4">
          <InfoCard
            title="Protocolos ativos"
            value={protocols.length ? protocols.join(", ") : "-"}
            subtitle="Derivado dos itens habilitados"
            tone="sky"
          />
          <InfoCard
            title="Itens monitorados"
            value={monitoringItems.length}
            subtitle={`${monitoringItems.filter((item) => item.enabled).length} ativo(s)`}
            tone="slate"
          />
          <InfoCard
            title="Interfaces no inventário"
            value={interfaces.length}
            subtitle="Atualizado pela coleta SNMP"
            tone="emerald"
          />
          <InfoCard
            title="Risco de loop"
            value={loopLabel}
            subtitle="Janela de 5 minutos"
            tone={loopTone}
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-slate-900/60">
          <div className="border-b border-white/10 p-5">
              <h2 className="text-lg font-semibold text-white">Itens monitorados do host</h2>
              <p className="mt-1 text-sm text-slate-400">
              Alterações de intervalo, timeout, tentativas e habilitação são persistidas no backend e usadas pelos pollers quando suportado.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Suporte</th>
                    <th className="px-4 py-3">Protocolo</th>
                    <th className="px-4 py-3">Item</th>
                    <th className="px-4 py-3">OID</th>
                    <th className="px-4 py-3">Intervalo</th>
                    <th className="px-4 py-3">Timeout</th>
                  <th className="px-4 py-3">Tent.</th>
                  <th className="px-4 py-3">Retenção</th>
                  <th className="px-4 py-3">Última coleta</th>
                  <th className="px-4 py-3">Último erro</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10 text-slate-200">
                  {monitoringItems.length ? (
                    monitoringItems.map((item) => (
                      <tr key={item.id} className={item.enabled ? "" : "opacity-60"}>
                        <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => handleToggleMonitoringItem(item)}
                          disabled={savingItemId === `toggle-${item.id}`}
                          className={`rounded-full border px-3 py-1 text-xs font-medium ${
                            item.enabled
                              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                              : "border-slate-500/30 bg-slate-500/10 text-slate-300"
                          }`}
                        >
                          {item.enabled ? "Ativo" : "Inativo"}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${
                            item.supported === false
                              ? "border-slate-500/30 bg-slate-500/10 text-slate-300"
                              : "border-sky-500/30 bg-sky-500/10 text-sky-100"
                          }`}
                        >
                          {item.supported === false ? "Não suportado" : "Suportado quando disponível"}
                        </span>
                      </td>
                      <td className="px-4 py-3 uppercase text-slate-300">{item.protocol}</td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-white">{item.display_name}</div>
                        <div className="text-xs text-slate-500">{item.item_key}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-400">{item.oid || "-"}</td>
                      <td className="px-4 py-3">
                        <input
                          type="number"
                          min="5"
                          max="3600"
                          defaultValue={item.poll_interval_seconds}
                          onBlur={(event) =>
                            handleMonitoringItemNumberChange(item, "poll_interval_seconds", event.target.value)
                          }
                          className="w-20 rounded-md border border-white/10 bg-slate-950 px-2 py-1 text-sm text-white"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <input
                          type="number"
                          min="1"
                          max="30"
                          defaultValue={item.timeout_seconds}
                          onBlur={(event) =>
                            handleMonitoringItemNumberChange(item, "timeout_seconds", event.target.value)
                          }
                          className="w-16 rounded-md border border-white/10 bg-slate-950 px-2 py-1 text-sm text-white"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <input
                          type="number"
                          min="0"
                          max="10"
                          defaultValue={item.retries}
                          onBlur={(event) => handleMonitoringItemNumberChange(item, "retries", event.target.value)}
                          className="w-16 rounded-md border border-white/10 bg-slate-950 px-2 py-1 text-sm text-white"
                        />
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        Historico {item.history_retention_days}d | Trends {item.trend_retention_days}d | Syslog {item.log_retention_days}d
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">{formatDateTime(item.last_collected_at)}</td>
                      <td className="px-4 py-3 text-slate-400">{item.last_error || "-"}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="11" className="px-4 py-10 text-center text-slate-500">
                      Nenhum item de monitoramento encontrado para este host/template.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-2">
          <div className="rounded-xl border border-white/10 bg-slate-900/60">
            <div className="border-b border-white/10 p-5">
              <h2 className="text-lg font-semibold text-white">Inventário de interfaces SNMP</h2>
              <p className="mt-1 text-sm text-slate-400">
                ifDescr, ifName, ifAlias, status, velocidade e últimos contadores persistidos.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Índice</th>
                    <th className="px-4 py-3">Interface</th>
                    <th className="px-4 py-3">Admin</th>
                    <th className="px-4 py-3">Oper</th>
                    <th className="px-4 py-3">Tráfego</th>
                    <th className="px-4 py-3">Erros/Desc.</th>
                    <th className="px-4 py-3">Última</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-slate-200">
                  {interfaces.length ? (
                    interfaces.slice(0, 40).map((iface) => (
                      <tr key={iface.id}>
                        <td className="px-4 py-3">{iface.ifindex}</td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-white">{iface.if_name || iface.ifdescr}</div>
                          <div className="text-xs text-slate-500">{iface.if_alias || iface.ifdescr}</div>
                        </td>
                        <td className="px-4 py-3">{iface.admin_status || "-"}</td>
                        <td className="px-4 py-3">{iface.oper_status || "-"}</td>
                        <td className="px-4 py-3 text-xs text-slate-400">
                          In {formatNumber(iface.last_in_bps || 0)} b/s
                          <br />
                          Out {formatNumber(iface.last_out_bps || 0)} b/s
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">
                          E {formatNumber((iface.last_in_errors || 0) + (iface.last_out_errors || 0), 0)}
                          <br />
                          D {formatNumber((iface.last_in_discards || 0) + (iface.last_out_discards || 0), 0)}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">{formatDateTime(iface.last_seen_at)}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="7" className="px-4 py-10 text-center text-slate-500">
                        Nenhuma interface inventariada ainda. Execute discovery de interfaces ou aguarde o SNMP poller.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-900/60">
            <div className="border-b border-white/10 p-5">
              <h2 className="text-lg font-semibold text-white">Correlação Syslog + SNMP</h2>
              <p className="mt-1 text-sm text-slate-400">
                Eventos Cisco/Aruba associados a ifDescr, ifName ou ifAlias normalizados.
              </p>
            </div>
            <div className="divide-y divide-white/10">
              {correlations.length ? (
                correlations.slice(0, 20).map((item) => (
                  <div key={item.id} className="p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill className="bg-sky-500/20 text-sky-100 border-sky-400/30">
                        {item.normalized_iface || item.if_name || item.ifdescr || "-"}
                      </Pill>
                      <Pill className="bg-slate-800 text-slate-100 border-white/10">
                        confiança {Math.round(Number(item.confidence || 0) * 100)}%
                      </Pill>
                    </div>
                    <div className="mt-2 text-sm text-white">{item.event_message || "-"}</div>
                    <div className="mt-1 text-xs text-slate-500">
                      {formatDateTime(item.event_ts)} | {item.event_subsystem || "-"} | ifIndex {item.ifindex || "-"}
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-sm text-slate-500">
                  Ainda não há correlação gravada entre syslog e interface SNMP para este host.
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
          <div className="flex flex-wrap items-center gap-2">
            <Pill
              className={
                loopEvidence?.state === "loop_detectado"
                  ? "bg-red-500/20 text-red-100 border-red-400/30"
                  : loopEvidence?.state === "risco_alto"
                  ? "bg-amber-500/20 text-amber-100 border-amber-400/30"
                  : "bg-slate-800 text-slate-100 border-white/10"
              }
            >
              {loopLabel}
            </Pill>
            <h2 className="text-lg font-semibold text-white">Evidências de risco de loop</h2>
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <InfoCard
              title="Score recente"
              value={
                loopEvidence?.latest_score !== undefined
                  ? `${Math.round(Number(loopEvidence.latest_score || 0) * 100)}%`
                  : "-"
              }
              subtitle="Índice recente de risco de loop"
              tone={loopTone}
            />
            <InfoCard
              title="Eventos correlacionados"
              value={loopEvidence?.correlations?.length || 0}
              subtitle="janela de 5 minutos"
              tone="slate"
            />
            <InfoCard
              title="Incidentes relacionados"
              value={loopEvidence?.incidents?.length || 0}
              subtitle="abertos/reconhecidos"
              tone="amber"
            />
          </div>
        </section>
      </div>
    );
  }

  function renderSnmp() {
    const hasSnmpFilters =
      snmpQuery.trim() ||
      snmpMetricType !== "all" ||
      snmpInterfaceFilter !== "all" ||
      snmpPresetFilter !== "relevant" ||
      snmpTimeFilter !== "current";

    const activeInterfaceCount = interfaces.filter((iface) => isInterfaceActiveForDisplay(iface)).length;
    const relevantInterfaceCount = relevantInterfaceSet.size;
    const anomalyMetricCount = filteredSnmpMetrics.filter((item) => isAnomalyMetric(item.metric)).length;

    return (
      <div className="space-y-6">
        <section className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-4">
          <InfoCard
            title="Amostras SNMP"
            value={snmpMetrics.length}
            subtitle="Registros recebidos no período"
          />
          <InfoCard
            title="Interfaces ativas"
            value={activeInterfaceCount}
            subtitle="Admin ou oper em up"
            tone="emerald"
          />
          <InfoCard
            title="Interfaces relevantes"
            value={relevantInterfaceCount}
            subtitle="Ativas, com erro, incidente ou alteração recente"
            tone="sky"
          />
          <InfoCard
            title="Anomalias filtradas"
            value={anomalyMetricCount}
            subtitle="Métricas de desvio e loop"
            tone={anomalyMetricCount ? "amber" : "slate"}
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-end gap-4">
            <div className="min-w-[240px] flex-1">
              <label className="text-xs text-slate-400">Buscar</label>
              <input
                value={snmpQuery}
                onChange={(e) => setSnmpQuery(e.target.value)}
                placeholder="Métrica, interface, valor ou status..."
                className="mt-1 w-full rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
              />
            </div>

            <div>
              <label className="text-xs text-slate-400">Categoria</label>
              <select
                value={snmpMetricType}
                onChange={(e) => setSnmpMetricType(e.target.value)}
                className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
              >
                {SNMP_FAMILY_FILTERS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Interface</label>
              <select
                value={snmpInterfaceFilter}
                onChange={(e) => setSnmpInterfaceFilter(e.target.value)}
                className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="all">Todas</option>
                {snmpInterfaceOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Valor / status</label>
              <select
                value={snmpPresetFilter}
                onChange={(e) => setSnmpPresetFilter(e.target.value)}
                className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
              >
                {SNMP_PRESET_FILTERS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Data / hora</label>
              <select
                value={snmpTimeFilter}
                onChange={(e) => setSnmpTimeFilter(e.target.value)}
                className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="current">Janela atual</option>
                <option value="6h">Últimas 6h</option>
                <option value="12h">Últimas 12h</option>
                <option value="24h">Últimas 24h</option>
                <option value="48h">Últimas 48h</option>
                <option value="7d">Últimos 7 dias</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Limite</label>
              <select
                value={snmpLimit}
                onChange={(e) => setSnmpLimit(e.target.value)}
                className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
              >
                {snmpLimitOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <button
                onClick={() => {
                  setSnmpQuery("");
                  setSnmpMetricType("all");
                  setSnmpInterfaceFilter("all");
                  setSnmpPresetFilter("relevant");
                  setSnmpTimeFilter("current");
                  setSnmpLimit("60");
                }}
                className="rounded-md bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700"
              >
                Limpar
              </button>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            {SNMP_PRESET_FILTERS.map((option) => {
              const active = snmpPresetFilter === option.value;
              return (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setSnmpPresetFilter(option.value)}
                  className={`rounded-full border px-3 py-1.5 text-xs transition ${
                    active
                      ? "border-sky-400/40 bg-sky-500/20 text-sky-100"
                      : "border-white/10 bg-slate-950/30 text-slate-300 hover:border-slate-500 hover:bg-slate-800/60"
                  }`}
                >
                  {option.label}
                </button>
              );
            })}
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            {SNMP_FAMILY_FILTERS.map((option) => {
              const active = snmpMetricType === option.value;
              const count = snmpFamilyCounts[option.value] || 0;
              return (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setSnmpMetricType(option.value)}
                  className={`rounded-full border px-3 py-1.5 text-xs transition ${
                    active
                      ? "border-emerald-400/40 bg-emerald-500/15 text-emerald-100"
                      : "border-white/10 bg-slate-950/30 text-slate-300 hover:border-slate-500 hover:bg-slate-800/60"
                  }`}
                >
                  {option.label} <span className="text-slate-400">{count}</span>
                </button>
              );
            })}
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <Pill className="border-white/10 bg-slate-950/40 text-slate-200">
              {filteredSnmpMetrics.length} de {snmpMetrics.length} amostras
            </Pill>
            {hasSnmpFilters ? (
              <span>A tela mostra primeiro interfaces ativas, com evento relevante e métricas úteis.</span>
            ) : (
              <span>Use os filtros para focar em status, tráfego, erros, descartes, sistema, interfaces e anomalias.</span>
            )}
          </div>
        </section>

        {snmpMetrics.length && filteredSnmpMetrics.length ? (
          <section className="rounded-xl border border-white/10 bg-slate-900/60">
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Data/Hora</th>
                    <th className="px-4 py-3">Categoria</th>
                    <th className="px-4 py-3">Métrica</th>
                    <th className="px-4 py-3">Interface</th>
                    <th className="px-4 py-3">Valor / status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-slate-200">
                  {filteredSnmpMetrics.map((item, index) => {
                    const iface = normalizeInterfaceName(extractInterfaceName(item));
                    const category = metricCategory(item.metric, item);
                    const valueText = formatSnmpStatusValue(item.metric, item.value);
                    const highlight = isAnomalyMetric(item.metric) || (iface && relevantInterfaceSet.has(iface));

                    return (
                      <tr key={`${item.ts}-${item.metric}-${index}`} className={highlight ? "bg-sky-500/5" : ""}>
                        <td className="whitespace-nowrap px-4 py-3">{formatDateTime(item.ts)}</td>
                        <td className="px-4 py-3">
                          <Pill className="border-white/10 bg-slate-800 text-slate-100">
                            {formatMetricCategory(category)}
                          </Pill>
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-white">{formatMetricName(item.metric)}</div>
                          <div className="mt-1 text-xs text-slate-500">{item.metric}</div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-slate-100">{iface || "-"}</div>
                          {iface && relevantInterfaceSet.has(iface) ? (
                            <div className="mt-1 text-xs text-emerald-300">Interface relevante</div>
                          ) : null}
                        </td>
                        <td className="px-4 py-3">
                          {isStatusMetric(item.metric) ? (
                            <Pill
                              className={
                                String(valueText).toLowerCase() === "up"
                                  ? "border-emerald-400/30 bg-emerald-500/15 text-emerald-100"
                                  : String(valueText).toLowerCase() === "down"
                                  ? "border-red-400/30 bg-red-500/15 text-red-100"
                                  : "border-slate-500/30 bg-slate-500/10 text-slate-200"
                              }
                            >
                              {valueText}
                            </Pill>
                          ) : (
                            <div className="font-medium text-white">{valueText}</div>
                          )}
                          {!isStatusMetric(item.metric) ? (
                            <div className="mt-1 text-xs text-slate-500">Valor bruto: {formatNumber(item.value, 3)}</div>
                          ) : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        ) : !snmpMetrics.length ? (
          <EmptyState
            title="Sem métricas SNMP"
            subtitle="Quando o poller coletar dados SNMP deste host, eles aparecerão aqui."
          />
        ) : (
          <EmptyState
            title="Nenhuma métrica SNMP encontrada para este filtro"
            subtitle="Ajuste categoria, interface, janela ou relevância para ver apenas o que importa."
          />
        )}
      </div>
    );
  }

  function renderSyslog() {
    const hasSyslogFilters =
      syslogQuery.trim() ||
      syslogType !== "all" ||
      syslogSeverityFilter !== "all" ||
      syslogSubsystemFilter !== "all" ||
      syslogInterfaceFilter !== "all";

    return (
      <div className="space-y-6">
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <InfoCard
            title="Eventos recentes"
            value={enrichedSyslog.length}
            subtitle="Registros do syslog_events"
          />
          <InfoCard
            title="Sinais precursores"
            value={precursorSyslog.length}
            subtitle="Eventos relacionados a possível loop"
            tone={precursorSyslog.length ? "amber" : "slate"}
          />
          <InfoCard
            title="Último syslog"
            value={enrichedSyslog[0]?.ts ? formatDateTime(enrichedSyslog[0].ts) : "-"}
            subtitle="Evento mais recente associado ao host"
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-end gap-4">
            <div className="flex-1 min-w-[240px]">
              <label className="text-xs text-slate-400">Texto</label>
              <input
                value={syslogQuery}
                onChange={(e) => setSyslogQuery(e.target.value)}
                placeholder="Buscar em mensagem, interface ou subsistema..."
                className="mt-1 w-full rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              />
            </div>

            <div>
              <label className="text-xs text-slate-400">Categoria</label>
              <select
                value={syslogType}
                onChange={(e) => setSyslogType(e.target.value)}
                className="mt-1 rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="all">Todos</option>
                {syslogTypeOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Severidade</label>
              <select
                value={syslogSeverityFilter}
                onChange={(e) => setSyslogSeverityFilter(e.target.value)}
                className="mt-1 rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="all">Todas</option>
                {syslogSeverityOptions.map((option) => (
                  <option key={option} value={option}>
                    {formatSeverityLabel(option)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Subsistema</label>
              <select
                value={syslogSubsystemFilter}
                onChange={(e) => setSyslogSubsystemFilter(e.target.value)}
                className="mt-1 rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="all">Todos</option>
                {syslogSubsystemOptions.map((option) => (
                  <option key={option} value={option}>
                    {formatSyslogSubsystem(option)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Interface</label>
              <select
                value={syslogInterfaceFilter}
                onChange={(e) => setSyslogInterfaceFilter(e.target.value)}
                className="mt-1 rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="all">Todas</option>
                {syslogInterfaceOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Limite</label>
              <select
                value={syslogLimit}
                onChange={(e) => setSyslogLimit(e.target.value)}
                className="mt-1 rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="10">10</option>
                <option value="20">20</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
            </div>

            <div>
              <button
                onClick={() => {
                  setSyslogQuery("");
                  setSyslogType("all");
                  setSyslogSeverityFilter("all");
                  setSyslogSubsystemFilter("all");
                  setSyslogInterfaceFilter("all");
                  setSyslogLimit("20");
                }}
                className="rounded-md bg-slate-800 hover:bg-slate-700 px-3 py-2 text-sm"
              >
                Limpar
              </button>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            {SYSLOG_QUICK_FILTERS.map((option) => {
              const active = syslogType === option.value;
              const count = syslogTypeCounts[option.value] || 0;
              return (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setSyslogType(option.value)}
                  className={`rounded-full border px-3 py-1.5 text-xs transition ${
                    active
                      ? "border-sky-400/40 bg-sky-500/20 text-sky-100"
                      : "border-white/10 bg-slate-950/30 text-slate-300 hover:border-slate-500 hover:bg-slate-800/60"
                  }`}
                >
                  {option.label} <span className="text-slate-400">{count}</span>
                </button>
              );
            })}
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <Pill className="border-white/10 bg-slate-950/40 text-slate-200">
              {filteredSyslog.length} de {enrichedSyslog.length} eventos
            </Pill>
            {hasSyslogFilters ? (
              <span>Use categoria, severidade, subsistema e interface para isolar o contexto certo.</span>
            ) : (
              <span>Os campos vazios antigos agora são enriquecidos automaticamente a partir do processo, da mensagem e da interface detectada.</span>
            )}
          </div>
        </section>

        {enrichedSyslog.length && filteredSyslog.length ? (
          <section className="rounded-xl border border-white/10 bg-white/5 overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="bg-white/5">
                <tr className="text-left text-slate-300">
                  <th className="px-4 py-3">Data/Hora</th>
                  <th className="px-4 py-3">Severidade</th>
                  <th className="px-4 py-3">Subsistema</th>
                  <th className="px-4 py-3">Interface</th>
                  <th className="px-4 py-3">Mensagem</th>
                </tr>
              </thead>
              <tbody>
                {filteredSyslog.map((event) => {
                  const highlighted = event.category === "loop" || event.category === "mac" || isLoopSignal(event);

                  return (
                    <tr
                      key={event.id}
                      className={`border-t border-white/10 ${highlighted ? "bg-amber-500/5" : ""}`}
                    >
                      <td className="px-4 py-3 whitespace-nowrap">{formatDateTime(event.ts)}</td>
                      <td className="px-4 py-3">
                        {event.severity ? (
                          <Pill
                            className={
                              SEVERITY_CLASSES[String(event.severity || "").toLowerCase()] ||
                              "bg-slate-800 text-slate-100 border-white/10"
                            }
                          >
                            {formatSeverityLabel(event.severity)}
                          </Pill>
                        ) : (
                          "-"
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-white">{event.subsystemLabel || "-"}</div>
                        <div className="mt-1 text-xs text-slate-500">{event.categoryLabel}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-200">{event.iface || "-"}</td>
                      <td className="px-4 py-3">
                        <div className="text-white">{event.message}</div>
                        {event.process ? (
                          <div className="mt-1 text-xs text-slate-500">Origem: {event.process}</div>
                        ) : null}
                        {highlighted ? (
                          <div className="mt-1 text-xs text-amber-200">
                            Evento destacado como possível sinal precursor de loop.
                          </div>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>
        ) : !syslog.length ? (
          <EmptyState
            title="Sem syslogs associados ao host"
            subtitle="Os eventos recebidos em syslog_events aparecerão aqui."
          />
        ) : null}

        {enrichedSyslog.length && !filteredSyslog.length ? (
          <EmptyState
            title="Nenhum syslog corresponde aos filtros"
            subtitle={
              hasSyslogFilters
                ? "Ajuste texto, categoria, severidade, subsistema, interface ou limite para encontrar eventos."
                : "Não há syslogs para exibir com os filtros atuais."
            }
          />
        ) : null}
      </div>
    );
  }

  function renderIncidents() {
    return (
      <div className="space-y-6">
        <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <InfoCard title="Incidentes totais" value={incidents.length} subtitle="Abertos e fechados" />
          <InfoCard title="Abertos" value={openIncidents.length} subtitle="Status aberto" tone="red" />
          <InfoCard title="Fechados" value={closedIncidents.length} subtitle="Status fechado" tone="emerald" />
          <InfoCard
            title="Risco de loop"
            value={loopRiskIncidents.length}
            subtitle="Registros desse tipo para o host"
            tone={loopRiskIncidents.length ? "amber" : "slate"}
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-end gap-4">
            <div>
              <label className="text-xs text-slate-400">Status</label>
              <select
                value={incidentStatusFilter}
                onChange={(e) => setIncidentStatusFilter(e.target.value)}
                className="mt-1 rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="all">Todos</option>
                <option value="open">Abertos</option>
                <option value="closed">Fechados</option>
              </select>
            </div>

            <div>
              <button
                onClick={() => setIncidentStatusFilter("all")}
                className="rounded-md bg-slate-800 hover:bg-slate-700 px-3 py-2 text-sm"
              >
                Limpar
              </button>
            </div>
          </div>
        </section>

        {filteredIncidents.length ? (
          <div className="space-y-4">
            {filteredIncidents.map((incident) => {
              const isLoopRisk =
                String(incident.incident_type || "").toLowerCase() === "loop_risk";

              return (
                <section
                  key={incident.id}
                  className={`rounded-xl border p-5 ${
                    isLoopRisk
                      ? "border-amber-500/30 bg-amber-500/10"
                      : "border-white/10 bg-slate-900/60"
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Pill
                      className={
                        STATUS_CLASSES[String(incident.status || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatStatusLabel(incident.status)}
                    </Pill>
                    <Pill
                      className={
                        SEVERITY_CLASSES[String(incident.severity || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatSeverityLabel(incident.severity)}
                    </Pill>
                    <Pill
                      className={
                        isLoopRisk
                          ? "bg-amber-500/20 text-amber-100 border-amber-400/30"
                          : "bg-slate-800 text-slate-100 border-white/10"
                      }
                    >
                      {formatIncidentType(incident.incident_type)}
                    </Pill>
                  </div>

                  <div className="mt-4 text-lg font-semibold text-white">{incident.title}</div>

                  <div className="mt-2 text-sm text-slate-300">
                    Aberto em {formatDateTime(incident.opened_at)} - Último sinal em{" "}
                    {formatDateTime(incident.last_seen_at)}
                  </div>

                  {incident.details?.recommendation ? (
                    <div className="mt-4 rounded-lg border border-white/10 bg-slate-950/40 p-4 text-sm text-slate-200">
                      {incident.details.recommendation}
                    </div>
                  ) : null}

                  {getIncidentEvidence(incident).length ? (
                    (() => {
                      const evidencePreview = formatEvidencePreview(getIncidentEvidence(incident), 4);
                      return (
                        <div className="mt-4 space-y-2">
                          <div className="flex flex-wrap gap-2">
                            {evidencePreview.visible.map((evidence, index) => (
                              <Pill
                                key={`${incident.id}-evidence-${index}`}
                                className="bg-slate-900/70 text-slate-100 border-white/10"
                              >
                                {evidence}
                              </Pill>
                            ))}
                          </div>
                          {evidencePreview.hiddenCount ? (
                            <div className="text-xs text-slate-500">
                              +{evidencePreview.hiddenCount} evidência(s) menos relevante(s) ocultada(s) para manter a leitura limpa.
                            </div>
                          ) : null}
                        </div>
                      );
                    })()
                  ) : null}
                </section>
              );
            })}
          </div>
        ) : incidents.length ? (
          <EmptyState
            title="Nenhum incidente corresponde ao filtro"
            subtitle="Troque o status selecionado para visualizar outros registros."
          />
        ) : (
          <EmptyState
            title="Nenhum incidente encontrado"
            subtitle="Incidentes abertos e fechados associados ao host aparecerão aqui."
          />
        )}
      </div>
    );
  }

  function renderVisualization() {
    const recentSyslog = enrichedSyslog.slice(0, 3);
    const recentIncidents = incidents.slice(0, 3);
    const criticalInterfaces = interfaces
      .filter((iface) => {
        const oper = String(iface.oper_status || "").toLowerCase();
        const isDown = oper && !["1", "up", "ok"].includes(oper);
        const errors = Number(iface.last_in_errors || 0) + Number(iface.last_out_errors || 0);
        const discards = Number(iface.last_in_discards || 0) + Number(iface.last_out_discards || 0);
        return isDown || errors > 0 || discards > 0;
      })
      .slice(0, 4);
    const evidenceItems = [
      latestLoopRiskScore ? `Loop risk ${Math.round(Number(latestLoopRiskScore.score || 0) * 100)}%` : "",
      precursorSyslog.length ? `${precursorSyslog.length} syslog(s) precursor(es)` : "",
      openIncidents.length ? `${openIncidents.length} incidente(s) aberto(s)` : "",
      criticalInterfaces.length ? `${criticalInterfaces.length} interface(s) com atenção` : "",
    ].filter(Boolean);

    return (
      <div className="space-y-6">
        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Visão por host</h2>
              <p className="mt-1 text-sm text-slate-400">
                Dashboards Grafana, contexto do template e leitura visual do ativo em uma mesma área.
              </p>
            </div>
            <Pill className="bg-slate-800 text-slate-100 border-white/10">
              {dashboards.length} dashboard(s)
            </Pill>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <InfoCard
            title="Saúde atual"
            value={health.label}
            subtitle={host?.health_reason || "Baseado na telemetria e nos incidentes atuais"}
            tone={
              health.label === "Saudável"
                ? "emerald"
                : health.label === "Degradado"
                ? "amber"
                : health.label === "Indisponível" || health.label === "Crítico"
                ? "red"
                : "slate"
            }
          />
          <InfoCard
            title="RTT ICMP"
            value={latestRttMetric ? `${formatNumber(latestRttMetric.value)} ms` : "Sem dados recentes"}
            subtitle={latestRttMetric ? formatDateTime(latestRttMetric.ts) : "Aguardando coleta ICMP"}
            tone="sky"
          />
          <InfoCard
            title="Perda de pacotes"
            value={latestLossMetric ? `${formatNumber(latestLossMetric.value)} %` : "Sem dados recentes"}
            subtitle={latestLossMetric ? formatDateTime(latestLossMetric.ts) : "Aguardando coleta ICMP"}
            tone={latestLossMetric && Number(latestLossMetric.value || 0) > 0 ? "amber" : "sky"}
          />
          <InfoCard
            title="Status SNMP"
            value={host?.last_snmp_collection_at ? "Com telemetria" : "Sem dados recentes"}
            subtitle={host?.last_snmp_collection_at ? formatDateTime(host.last_snmp_collection_at) : "Aguardando amostra SNMP"}
            tone={host?.last_snmp_collection_at ? "emerald" : "amber"}
          />
        </section>

        <section className="grid gap-4 xl:grid-cols-[1fr,1fr,1fr]">
          <div className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">Últimos syslogs</h3>
              <Pill className="bg-slate-800 text-slate-100 border-white/10">{enrichedSyslog.length}</Pill>
            </div>
            <div className="mt-4 space-y-3">
              {recentSyslog.length ? (
                recentSyslog.map((event, index) => (
                  <div key={`${event.ts}-${index}`} className="rounded-lg border border-white/10 bg-slate-950/40 p-3">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span>{formatDateTime(event.ts)}</span>
                      <span>|</span>
                      <span>{event.subsystemLabel || event.subsystem || "Syslog"}</span>
                      {event.iface ? <span>| {event.iface}</span> : null}
                    </div>
                    <div className="mt-2 line-clamp-2 text-sm text-slate-200">{event.message || event.raw || "Evento syslog recebido."}</div>
                  </div>
                ))
              ) : (
                <EmptyState title="Nenhum evento syslog recente" subtitle="Eventos recebidos para este host aparecerão aqui." />
              )}
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">Incidentes recentes</h3>
              <Pill className="bg-slate-800 text-slate-100 border-white/10">{incidents.length}</Pill>
            </div>
            <div className="mt-4 space-y-3">
              {recentIncidents.length ? (
                recentIncidents.map((incident) => (
                  <div key={incident.id} className="rounded-lg border border-white/10 bg-slate-950/40 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill className={STATUS_CLASSES[String(incident.status || "").toLowerCase()] || "bg-slate-800 text-slate-100 border-white/10"}>
                        {formatStatusLabel(incident.status)}
                      </Pill>
                      <Pill className={SEVERITY_CLASSES[String(incident.severity || "").toLowerCase()] || "bg-slate-800 text-slate-100 border-white/10"}>
                        {formatSeverityLabel(incident.severity)}
                      </Pill>
                    </div>
                    <div className="mt-2 line-clamp-2 text-sm text-slate-200">{incident.title || formatIncidentType(incident.incident_type)}</div>
                    <div className="mt-1 text-xs text-slate-500">{formatDateTime(incident.last_seen_at || incident.opened_at)}</div>
                  </div>
                ))
              ) : (
                <EmptyState title="Nenhum incidente aberto" subtitle="Incidentes associados ao host aparecerão aqui." />
              )}
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">Evidências principais</h3>
              <Pill className="bg-slate-800 text-slate-100 border-white/10">{evidenceItems.length}</Pill>
            </div>
            <div className="mt-4 space-y-3">
              {evidenceItems.length ? (
                evidenceItems.map((item) => (
                  <div key={item} className="rounded-lg border border-white/10 bg-slate-950/40 p-3 text-sm text-slate-200">
                    {item}
                  </div>
                ))
              ) : (
                <EmptyState title="Sem evidências recentes" subtitle="Riscos, incidentes e interfaces críticas aparecerão aqui quando houver sinais." />
              )}
              {criticalInterfaces.length ? (
                <div className="pt-2">
                  <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Interfaces críticas</div>
                  <div className="flex flex-wrap gap-2">
                    {criticalInterfaces.map((iface) => (
                      <Pill key={iface.id || iface.ifindex} className="bg-amber-500/20 text-amber-100 border-amber-400/30">
                        {iface.if_name || iface.ifdescr || `ifIndex ${iface.ifindex}`}
                      </Pill>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </section>

        {dashboards.length ? (
          dashboards.map((dashboard) => (
            <GrafanaDashboardCard
              key={`${dashboard.owner_type}-${dashboard.dashboard_key}`}
              dashboard={dashboard}
              title={`Dashboard de ${host?.name || "host"}`}
              description={
                host?.template_name
                  ? `Visualização Grafana alinhada ao template ${host.template_name} dentro do contexto operacional deste host.`
                  : dashboard.description
              }
            />
          ))
        ) : (
          <EmptyState
            title="Nenhum dashboard disponível para este host"
            subtitle="O Grafana ainda não foi provisionado para este ativo ou o endpoint /dashboards/host/{id} está sem resposta."
          />
        )}
      </div>
    );
  }

  async function handleGenerateInsight(kind, refresh = false) {
    try {
      setGeneratingInsightType(kind);
      setInsightsError("");

      const generated =
        kind === "host_summary"
          ? await generateHostSummary(hostId, { refresh })
          : await generateHostRecommendation(hostId, { refresh });

      setHostInsights((current) => ({
        ...current,
        [kind]: generated,
      }));
    } catch (insightError) {
      setInsightsError(insightError?.message || "Falha ao gerar insight do host");
    } finally {
      setGeneratingInsightType("");
    }
  }

  function renderInsights() {
    return (
      <div className="space-y-6">
        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Insights operacionais do host</h2>
              <p className="mt-1 text-sm text-slate-400">
                Gera análises sob demanda com contexto do NetGuard, cache simples e evidências estruturadas. Use a área IA / Insights para abrir uma conversa operacional mais ampla.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Pill className="bg-slate-800 text-slate-100 border-white/10">
                {host?.template_name || "Sem template legado"}
              </Pill>
              <Link
                to={`/insights?host_id=${hostId}`}
                className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-900"
              >
                Abrir assistente
              </Link>
            </div>
          </div>
        </section>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <AIInsightCard
            title="Resumo do host"
            description="Leitura técnica do estado atual do host, ancorada em grupo, template, incidentes, risco de loop, telemetria, syslog e previsões recentes."
            insight={hostInsights.host_summary}
            loading={insightsLoading || generatingInsightType === "host_summary"}
            error={insightsError}
            primaryActionLabel="Gerar resumo do host"
            onGenerate={() => handleGenerateInsight("host_summary")}
            onRefresh={() => handleGenerateInsight("host_summary", true)}
            emptyTitle="Resumo do host ainda não gerado"
            emptySubtitle="Use esse insight para obter uma leitura objetiva do estado atual do ativo."
          />

          <AIInsightCard
            title="Recomendação operacional"
            description="Sugestão objetiva de acompanhamento ou ação manual, alinhada ao template do host e aos sinais recentes do ambiente."
            insight={hostInsights.operational_recommendation}
            loading={insightsLoading || generatingInsightType === "operational_recommendation"}
            error={insightsError}
            primaryActionLabel="Gerar recomendação"
            onGenerate={() => handleGenerateInsight("operational_recommendation")}
            onRefresh={() => handleGenerateInsight("operational_recommendation", true)}
            emptyTitle="Recomendação operacional ainda não gerada"
            emptySubtitle="Gere a recomendação quando precisar priorizar a próxima ação manual para este host."
          />
        </div>
      </div>
    );
  }

  function renderPredictions() {
    const maxScorePct =
      predictions?.summary?.max_score !== null &&
      predictions?.summary?.max_score !== undefined
        ? Math.round(Number(predictions.summary.max_score) * 100)
        : null;

    return (
      <div className="space-y-6">
        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <InfoCard
            title="Anomalias detectadas"
            value={predictions?.summary?.anomaly_count || anomalyScores.length}
            subtitle="Ocorrências registradas para o host"
          />
          <InfoCard
            title="Maior índice"
            value={maxScorePct != null ? `${maxScorePct}%` : "-"}
            subtitle="Maior índice recente calculado para o host"
            tone={maxScorePct && maxScorePct >= 50 ? "amber" : "sky"}
          />
          <InfoCard
            title="Risco de loop aberto"
            value={predictions?.summary?.loop_risk_open || 0}
            subtitle="Incidentes de risco de loop com status aberto"
            tone={(predictions?.summary?.loop_risk_open || 0) > 0 ? "amber" : "slate"}
          />
          <InfoCard
            title="Última previsão"
            value={predictions?.summary?.latest_ts ? formatDateTime(predictions.summary.latest_ts) : "-"}
            subtitle="Última anomalia registrada para o host"
          />
        </section>

        {loopRiskIncidents.length ? (
          <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5">
            <div className="flex flex-wrap items-center gap-2">
              <Pill className="bg-amber-500/20 text-amber-100 border-amber-400/30">
                {openLoopRiskIncidents.length ? "Incidente ativo" : "Histórico recente"}
              </Pill>
              <h2 className="text-lg font-semibold text-white">
                {openLoopRiskIncidents.length
                  ? "Incidentes de risco de loop em destaque"
                  : "Histórico recente de risco de loop"}
              </h2>
            </div>

            <div className="mt-4 space-y-3">
              {loopRiskIncidents.map((incident) => (
                <div
                  key={`prediction-loop-${incident.id}`}
                  className="rounded-lg border border-amber-500/20 bg-slate-950/40 p-4"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Pill
                      className={
                        STATUS_CLASSES[String(incident.status || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatStatusLabel(incident.status)}
                    </Pill>
                    <Pill
                      className={
                        SEVERITY_CLASSES[String(incident.severity || "").toLowerCase()] ||
                        "bg-slate-500/20 text-slate-200 border-slate-500/30"
                      }
                    >
                      {formatSeverityLabel(incident.severity)}
                    </Pill>
                  </div>

                  <div className="mt-3 text-white font-medium">{formatLoopRiskIncidentTitle(incident)}</div>
                  <div className="mt-2 text-sm text-slate-300">
                    {String(incident.status || "").toLowerCase() === "resolved" ||
                    String(incident.status || "").toLowerCase() === "closed"
                      ? `Resolvido em ${formatDateTime(incident.resolved_at || incident.updated_at || incident.last_seen_at)}`
                      : `Aberto em ${formatDateTime(incident.opened_at)}`}
                  </div>

                  {getIncidentEvidence(incident).length ? (
                    (() => {
                      const evidencePreview = formatEvidencePreview(getIncidentEvidence(incident), 4);
                      return (
                        <div className="mt-3 space-y-2">
                          <div className="flex flex-wrap gap-2">
                            {evidencePreview.visible.map((evidence, index) => (
                              <Pill
                                key={`${incident.id}-prediction-evidence-${index}`}
                                className="bg-slate-900/70 text-slate-100 border-white/10"
                              >
                                {evidence}
                              </Pill>
                            ))}
                          </div>
                          {evidencePreview.hiddenCount ? (
                            <div className="text-xs text-slate-500">
                              +{evidencePreview.hiddenCount} evidência(s) complementar(es) ocultada(s) para manter a leitura objetiva.
                            </div>
                          ) : null}
                        </div>
                      );
                    })()
                  ) : null}
                </div>
              ))}
            </div>
          </section>
        ) : (
          <section className="rounded-xl border border-sky-500/20 bg-sky-500/10 p-5">
            <h2 className="text-lg font-semibold text-white">Sem risco de loop registrado</h2>
            <p className="mt-2 text-sm text-slate-200">
              Os scores de anomalia continuam visíveis abaixo e servem como base
              para previsão e correlação temporal.
            </p>
          </section>
        )}

        <section className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-end gap-4">
            <div>
              <label className="text-xs text-slate-400">Ordenação</label>
              <select
                value={predictionSort}
                onChange={(e) => setPredictionSort(e.target.value)}
                className="mt-1 rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
              >
                <option value="score_desc">Maior score</option>
                <option value="score_asc">Menor score</option>
                <option value="recent">Mais recentes</option>
              </select>
            </div>
          </div>
        </section>

        {sortedPredictions.length ? (
          <section className="rounded-xl border border-white/10 bg-white/5 overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="bg-white/5">
                <tr className="text-left text-slate-300">
                  <th className="px-4 py-3">Data/Hora</th>
                  <th className="px-4 py-3">Métrica</th>
                  <th className="px-4 py-3">Chave</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Z-score</th>
                  <th className="px-4 py-3">Valor</th>
                  <th className="px-4 py-3">Baseline</th>
                </tr>
              </thead>
              <tbody>
                {sortedPredictions.map((item, index) => {
                  const scorePct = Math.round(Number(item.score || 0) * 100);

                  return (
                    <tr key={`${item.ts}-${item.metric}-${index}`} className="border-t border-white/10">
                      <td className="px-4 py-3 whitespace-nowrap">{formatDateTime(item.ts)}</td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-white">{formatMetricName(item.metric)}</div>
                        <div className="text-xs text-slate-400">{item.metric}</div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-white">{item.key}</div>
                        <div className="text-xs text-slate-400">{extractInterfaceName(item)}</div>
                      </td>
                      <td className="px-4 py-3">
                        <Pill className={getScoreClass(Number(item.score || 0))}>
                          {scorePct}%
                        </Pill>
                      </td>
                      <td className="px-4 py-3">{formatNumber(item.z)}</td>
                      <td className="px-4 py-3">{formatNumber(item.value)}</td>
                      <td className="px-4 py-3">
                        <div className="text-white">
                          média {formatNumber(item.baseline_mean)}
                        </div>
                        <div className="text-xs text-slate-400">
                          desvio {formatNumber(item.baseline_std)}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>
        ) : (
          <EmptyState
            title="Sem previsões ou anomalias recentes"
            subtitle="Os registros de anomaly_scores deste host aparecerão aqui."
          />
        )}
      </div>
    );
  }

  return (
    <>
      <Sidebar />

      <div className="ng-shell bg-slate-950 text-white">
        <header className="sticky top-0 z-10 border-b border-white/10 bg-slate-900/60 backdrop-blur">
          <div className="max-w-[1600px] mx-auto px-6 py-4 flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <Breadcrumbs
                items={[
                  { label: "Monitoramento", to: "/monitoring/overview" },
                  { label: "Hosts monitorados", to: "/monitoring/hosts" },
                  { label: hostDisplayName },
                ]}
              />
              <h1 className="mt-2 text-2xl font-semibold">
                {hostDisplayName}
              </h1>
              <p className="mt-1 text-sm text-slate-400">
                Visão operacional consolidada com telemetria, eventos, incidentes e previsões.
              </p>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <Pill className={health.className}>{health.label}</Pill>
                <Pill
                  className={
                    host?.group_id
                      ? "bg-slate-800 text-slate-100 border-white/10"
                      : "bg-amber-500/20 text-amber-100 border-amber-400/30"
                  }
                >
                  {groupDisplay}
                </Pill>
                <Pill
                  className={
                    host?.template_id
                      ? "bg-slate-800 text-slate-100 border-white/10"
                      : "bg-amber-500/20 text-amber-100 border-amber-400/30"
                  }
                >
                  {templateDisplay}
                </Pill>
                <Pill className="bg-slate-800 text-slate-100 border-white/10">
                  {formatPolicyCountLabel(activeProfileCount)}
                </Pill>
                <Pill className="bg-slate-800 text-slate-100 border-white/10">
                  {TIME_RANGE_OPTIONS.find((option) => option.id === timeWindow)?.label || "Últimas 24h"}
                </Pill>
                <Pill className="bg-slate-800 text-slate-100 border-white/10">
                  {latestCollectionTime
                    ? `Última coleta ${formatDateTime(latestCollectionTime)}`
                    : "Sem coleta recente"}
                </Pill>
                <Pill className="bg-slate-800 text-slate-100 border-white/10">
                  {`Coleta ${formatDurationSeconds(resolvedCollectionPolicy.icmp_interval_sec)} / ${formatDurationSeconds(
                    resolvedCollectionPolicy.snmp_interval_sec
                  )}`}
                </Pill>
                <Pill className="bg-slate-800 text-slate-100 border-white/10">
                  {nextCollectionEstimate
                    ? `Próxima coleta ${formatDateTime(nextCollectionEstimate)}`
                    : "Próxima coleta ainda não estimada"}
                </Pill>
                {lastRelevantIncident ? (
                  <Pill
                    className={
                      String(lastRelevantIncident.status || "").toLowerCase() === "open"
                        ? "bg-red-500/20 text-red-200 border-red-500/30"
                        : "bg-slate-800 text-slate-100 border-white/10"
                    }
                  >
                    {formatIncidentType(lastRelevantIncident.incident_type)}
                  </Pill>
                ) : null}
              </div>
            </div>

            <div className="flex flex-col items-start gap-3">
              <div className="flex flex-wrap items-center gap-3">
                <div>
                  <label className="mb-1 block text-[11px] uppercase tracking-[0.14em] text-slate-500">
                    Janela
                  </label>
                  <select
                    value={timeWindow}
                    onChange={(event) => setTimeWindow(event.target.value)}
                    className="rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-400"
                  >
                    {TIME_RANGE_OPTIONS.map((option) => (
                      <option key={option.id} value={option.id}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </div>
                <Link
                  to="/monitoring/hosts"
                  className="rounded-md bg-slate-800 hover:bg-slate-700 px-4 py-2 text-sm"
                >
                  Voltar para hosts monitorados
                </Link>
                <Link
                  to={`/data-collection/hosts/${hostId}/edit`}
                  className="rounded-md bg-slate-800 hover:bg-slate-700 px-4 py-2 text-sm"
                >
                  Editar host
                </Link>
                <Link
                  to="/data-collection/hosts"
                  className="rounded-md bg-slate-800 hover:bg-slate-700 px-4 py-2 text-sm"
                >
                  Coleta de dados
                </Link>
                <button
                  onClick={handleRefresh}
                  className="rounded-md bg-sky-600 hover:bg-sky-500 px-4 py-2 text-sm disabled:opacity-70"
                  disabled={loading || refreshing || collectingNow}
                >
                  {refreshing ? "Recarregando..." : "Recarregar"}
                </button>
                <button
                  onClick={handleCollectNow}
                  className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-100 hover:bg-emerald-500/20 disabled:opacity-70"
                  disabled={loading || refreshing || collectingNow}
                >
                  {collectingNow ? "Solicitando coleta..." : "Coletar agora"}
                </button>
                <div className="text-sm text-slate-400">
                  {me?.name} {me?.role ? `(${me.role})` : ""}
                </div>
              </div>
              <div className="max-w-xl text-xs leading-6 text-slate-400">
                <span className="font-medium text-slate-300">Recarregar</span> atualiza a tela com os dados já persistidos.
                {" "}
                <span className="font-medium text-slate-300">Coletar agora</span> registra uma solicitação explícita de nova coleta
                ICMP e SNMP, processada pelos pollers no próximo ciclo disponível.
              </div>
            </div>
          </div>
        </header>

        <main className="max-w-[1600px] mx-auto px-6 py-8 space-y-6">
          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-200">
              {error}
            </div>
          )}
          {collectNowNotice ? (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-emerald-100">
              {collectNowNotice}
            </div>
          ) : null}

          {hostLoadState === "loading" ? (
            <div className="rounded-xl border border-white/10 bg-slate-900/60 p-10 text-center text-slate-400">
              Carregando cadastro do host...
            </div>
          ) : hostMissing ? (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-6 text-amber-100">
              <div className="text-lg font-semibold text-white">Host nao encontrado</div>
              <div className="mt-2 text-sm text-amber-100/90">
                O identificador informado n?o corresponde a um host cadastrado.
              </div>
            </div>
          ) : hostLoadError && !host ? (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-red-100">
              <div className="text-lg font-semibold text-white">Erro ao carregar host</div>
              <div className="mt-2 text-sm text-red-100/90">
                {error || "Falha ao carregar monitoramento do host"}
              </div>
            </div>
          ) : (
            <>
              {summaryCards}

              <section className="rounded-xl border border-white/10 bg-slate-900/60 p-3">
                <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-8">
                  {TABS.map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`rounded-xl border px-4 py-3 text-left transition ${
                        activeTab === tab.id
                          ? "border-sky-400/40 bg-sky-500/10 text-white"
                          : "border-white/10 bg-slate-950/40 text-slate-300 hover:bg-slate-900"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-sm font-medium">{tab.label}</span>
                        {tabCounts[tab.id] !== null ? (
                          <span
                            className={`rounded-full px-2.5 py-1 text-xs ${
                              activeTab === tab.id
                                ? "bg-sky-500/20 text-sky-100"
                                : "bg-slate-800 text-slate-300"
                            }`}
                          >
                            {tabCounts[tab.id]}
                          </span>
                        ) : null}
                      </div>
                      <div
                        className={`mt-1 text-xs ${
                          activeTab === tab.id ? "text-sky-100/80" : "text-slate-500"
                        }`}
                      >
                        {tab.description}
                      </div>
                    </button>
                  ))}
                </div>
              </section>

              {activeTab === "summary" && renderSummary()}
              {activeTab === "insights" && renderInsights()}
              {activeTab === "visualization" && renderVisualization()}
              {activeTab === "monitoring" && renderMonitoring()}
              {activeTab === "snmp" && renderSnmp()}
              {activeTab === "syslog" && renderSyslog()}
              {activeTab === "incidents" && renderIncidents()}
              {activeTab === "predictions" && renderPredictions()}
            </>
          )}
        </main>
      </div>
    </>
  );
}

