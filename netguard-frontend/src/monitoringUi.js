export const TIME_RANGE_OPTIONS = [
  { id: "1h", label: "Última 1h", hours: 1 },
  { id: "6h", label: "Últimas 6h", hours: 6 },
  { id: "24h", label: "Últimas 24h", hours: 24 },
  { id: "7d", label: "Últimos 7 dias", hours: 24 * 7 },
  { id: "30d", label: "Últimos 30 dias", hours: 24 * 30 },
];

export const SEVERITY_META = {
  critical: {
    label: "Crítica",
    className: "border-red-500/30 bg-red-500/15 text-red-100",
  },
  high: {
    label: "Alta",
    className: "border-orange-500/30 bg-orange-500/15 text-orange-100",
  },
  warning: {
    label: "Atenção",
    className: "border-amber-500/30 bg-amber-500/15 text-amber-100",
  },
  medium: {
    label: "Média",
    className: "border-yellow-500/30 bg-yellow-500/15 text-yellow-100",
  },
  low: {
    label: "Baixa",
    className: "border-sky-500/30 bg-sky-500/15 text-sky-100",
  },
  info: {
    label: "Informativa",
    className: "border-slate-500/30 bg-slate-500/15 text-slate-100",
  },
  notice: {
    label: "Informativa",
    className: "border-slate-500/30 bg-slate-500/15 text-slate-100",
  },
};

export const STATUS_META = {
  open: {
    label: "Aberto",
    className: "border-red-500/30 bg-red-500/15 text-red-100",
  },
  acknowledged: {
    label: "Reconhecido",
    className: "border-amber-500/30 bg-amber-500/15 text-amber-100",
  },
  resolved: {
    label: "Resolvido",
    className: "border-emerald-500/30 bg-emerald-500/15 text-emerald-100",
  },
  closed: {
    label: "Fechado",
    className: "border-emerald-500/30 bg-emerald-500/15 text-emerald-100",
  },
};

export const HEALTH_META = {
  healthy: {
    label: "Saudável",
    className: "border-emerald-500/30 bg-emerald-500/15 text-emerald-100",
  },
  degraded: {
    label: "Degradado",
    className: "border-amber-500/30 bg-amber-500/15 text-amber-100",
  },
  critical: {
    label: "Crítico",
    className: "border-red-500/30 bg-red-500/15 text-red-100",
  },
  unavailable: {
    label: "Indisponível",
    className: "border-red-500/30 bg-red-500/15 text-red-100",
  },
  down: {
    label: "Indisponível",
    className: "border-red-500/30 bg-red-500/15 text-red-100",
  },
  no_data: {
    label: "Sem telemetria",
    className: "border-slate-500/30 bg-slate-500/15 text-slate-100",
  },
  inactive: {
    label: "Cadastro inativo",
    className: "border-slate-500/30 bg-slate-500/15 text-slate-100",
  },
};

export function formatDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("pt-BR");
}

export function formatRelativeWindowLabel(windowId) {
  return TIME_RANGE_OPTIONS.find((option) => option.id === windowId)?.label || "Período";
}

export function resolveTimeRange(windowId) {
  const option = TIME_RANGE_OPTIONS.find((item) => item.id === windowId) || TIME_RANGE_OPTIONS[2];
  const now = new Date();
  const from = new Date(now.getTime() - option.hours * 60 * 60 * 1000);

  return {
    from: from.toISOString(),
    to: now.toISOString(),
  };
}

export function severityLabel(value) {
  return SEVERITY_META[String(value || "").toLowerCase()]?.label || "Sem severidade";
}

export function severityClassName(value) {
  return (
    SEVERITY_META[String(value || "").toLowerCase()]?.className ||
    "border-slate-500/30 bg-slate-500/15 text-slate-100"
  );
}

export function statusLabel(value) {
  return STATUS_META[String(value || "").toLowerCase()]?.label || "Sem status";
}

export function statusClassName(value) {
  return (
    STATUS_META[String(value || "").toLowerCase()]?.className ||
    "border-slate-500/30 bg-slate-500/15 text-slate-100"
  );
}

export function healthLabel(value) {
  return HEALTH_META[String(value || "").toLowerCase()]?.label || "Sem estado";
}

export function healthClassName(value) {
  return (
    HEALTH_META[String(value || "").toLowerCase()]?.className ||
    "border-slate-500/30 bg-slate-500/15 text-slate-100"
  );
}

export function incidentTypeLabel(value) {
  const labels = {
    loop_risk: "Risco de loop",
    early_warning: "Alerta antecipado",
  };

  return labels[String(value || "").toLowerCase()] || (value ? String(value).replaceAll("_", " ") : "Incidente");
}

export function sourceLabel(value) {
  const labels = {
    syslog: "Syslog",
    incident: "Incidente",
    prediction: "Previsão",
  };

  return labels[String(value || "").toLowerCase()] || "Sinal";
}

