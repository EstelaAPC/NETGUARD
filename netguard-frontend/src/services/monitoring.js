import { API_BASE_URL, jsonHeaders } from "./config";

const API = API_BASE_URL;

function defaultHeaders() {
  return jsonHeaders();
}

function getOptions() {
  return {
    headers: {
      ...defaultHeaders(),
      "Cache-Control": "no-cache, no-store, max-age=0",
      Pragma: "no-cache",
    },
    cache: "no-store",
  };
}

function withBust(path, params) {
  const search = params instanceof URLSearchParams ? params : new URLSearchParams(params || {});
  search.set("_ts", String(Date.now()));
  const qs = search.toString();
  return `${path}${qs ? `?${qs}` : ""}`;
}

async function handle(res, fallback = "Falha ao carregar dados") {
  if (!res.ok) {
    let msg = fallback;

    try {
      const data = await res.json();
      msg = typeof data === "object" ? JSON.stringify(data) : String(data);
    } catch {
      try {
        msg = await res.text();
      } catch {}
    }

    const error = new Error(msg || fallback);
    error.status = res.status;
    throw error;
  }

  try {
    return await res.json();
  } catch {
    return null;
  }
}

export async function getHost(hostId) {
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}`)}`, getOptions());

  return handle(res, "Falha ao buscar host");
}

export async function collectHostNow(hostId, protocol = "all") {
  const res = await fetch(`${API}/hosts/${hostId}/collect-now`, {
    method: "POST",
    headers: defaultHeaders(),
    body: JSON.stringify({ protocol }),
  });

  return handle(res, "Falha ao solicitar coleta do host");
}

export async function getHostProfiles(hostId) {
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/profiles`)}`, getOptions());

  return handle(res, "Falha ao buscar profiles do host");
}

export async function getHostMonitoringItems(hostId) {
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/monitoring-items`)}`, getOptions());

  return handle(res, "Falha ao buscar itens monitorados do host");
}

export async function getHostInterfaces(hostId) {
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/interfaces`)}`, getOptions());

  return handle(res, "Falha ao buscar interfaces do host");
}

export async function updateMonitoringItem(itemId, payload) {
  const res = await fetch(`${API}/monitoring/items/${itemId}`, {
    method: "PUT",
    headers: defaultHeaders(),
    body: JSON.stringify(payload),
  });

  return handle(res, "Falha ao atualizar item monitorado");
}

export async function toggleMonitoringItem(itemId, enabled) {
  const res = await fetch(`${API}/monitoring/items/${itemId}/enabled`, {
    method: "PATCH",
    headers: defaultHeaders(),
    body: JSON.stringify({ enabled }),
  });

  return handle(res, "Falha ao alternar item monitorado");
}

export async function getHostMetrics(
  hostId,
  { metric, metricPrefix, from, to, limit = 200 } = {}
) {
  const params = new URLSearchParams();

  if (metric) params.append("metric", metric);
  if (metricPrefix) params.append("metric_prefix", metricPrefix);
  if (from) params.append("from", from);
  if (to) params.append("to", to);
  params.append("limit", String(limit));

  const res = await fetch(`${API}${withBust(`/metrics/by-asset/${hostId}`, params)}`, getOptions());

  return handle(res, "Falha ao buscar metricas do host");
}

export async function getHostSyslog(hostId, { severity, subsystem, q, from, to, limit = 100 } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (severity) params.append("severity", severity);
  if (subsystem) params.append("subsystem", subsystem);
  if (q) params.append("q", q);
  if (from) params.append("from", from);
  if (to) params.append("to", to);
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/syslog`, params)}`, getOptions());

  return handle(res, "Falha ao buscar syslog do host");
}

export async function getHostIncidents(hostId, { status, severity, incidentType, from, to, limit = 200 } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (status) params.append("status", status);
  if (severity) params.append("severity", severity);
  if (incidentType) params.append("incident_type", incidentType);
  if (from) params.append("from", from);
  if (to) params.append("to", to);

  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/incidents`, params)}`, getOptions());

  return handle(res, "Falha ao buscar incidentes do host");
}

export async function getHostPredictions(hostId, { metric, from, to, limit = 100 } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (metric) params.append("metric", metric);
  if (from) params.append("from", from);
  if (to) params.append("to", to);
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/predictions`, params)}`, getOptions());

  return handle(res, "Falha ao buscar previsoes do host");
}

export async function getHostCorrelations(hostId, { limit = 100 } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/correlations`, params)}`, getOptions());

  return handle(res, "Falha ao buscar correlacoes do host");
}

export async function getHostLoopRiskEvidence(hostId, { minutes = 5 } = {}) {
  const params = new URLSearchParams({ minutes: String(minutes) });
  const res = await fetch(`${API}${withBust(`/hosts/${hostId}/loop-risk/evidence`, params)}`, getOptions());

  return handle(res, "Falha ao buscar evidencias de loop risk");
}

export async function listRecentSignals({
  assetId,
  groupId,
  templateId,
  source,
  type,
  severity,
  q,
  from,
  to,
  limit = 120,
} = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (assetId) params.append("asset_id", String(assetId));
  if (groupId) params.append("group_id", String(groupId));
  if (templateId) params.append("template_id", String(templateId));
  if (source) params.append("source", source);
  if (type) params.append("type", type);
  if (severity) params.append("severity", severity);
  if (q) params.append("q", q);
  if (from) params.append("from", from);
  if (to) params.append("to", to);

  const res = await fetch(`${API}${withBust("/signals/recent", params)}`, getOptions());

  return handle(res, "Falha ao buscar sinais recentes");
}
