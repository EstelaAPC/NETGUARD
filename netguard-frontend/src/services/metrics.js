import { API_BASE_URL, jsonHeaders } from "./config";

const API_URL = API_BASE_URL;

async function apiFetch(path) {
  const res = await fetch(`${API_URL}${path}`, {
    headers: jsonHeaders(),
  });

  if (!res.ok) {
    throw new Error(`Erro ao carregar ${path}`);
  }

  return res.json();
}

export async function getMetricsOverview() {
  return apiFetch("/metrics/overview");
}

export async function getMetricsTimeseries({ assetId, metric, limit = 100 } = {}) {
  const params = new URLSearchParams();

  if (assetId) params.append("asset_id", assetId);
  if (metric) params.append("metric", metric);
  params.append("limit", String(limit));

  return apiFetch(`/metrics/timeseries?${params.toString()}`);
}

export async function getCapacityEstimate() {
  return apiFetch("/capacity/estimate");
}
