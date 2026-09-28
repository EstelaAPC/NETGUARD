import { API_BASE_URL, jsonHeaders } from "./config";

const API_URL = API_BASE_URL;

export async function listIncidents(options = {}) {
  const params = new URLSearchParams();

  if (options.assetId) params.append("asset_id", String(options.assetId));
  if (options.groupId) params.append("group_id", String(options.groupId));
  if (options.templateId) params.append("template_id", String(options.templateId));
  if (options.status) params.append("status", String(options.status));
  if (options.severity) params.append("severity", String(options.severity));
  if (options.incidentType) params.append("incident_type", String(options.incidentType));
  if (options.q) params.append("q", String(options.q));
  if (options.from) params.append("from", String(options.from));
  if (options.to) params.append("to", String(options.to));
  if (options.limit) params.append("limit", String(options.limit));

  const res = await fetch(`${API_URL}/incidents${params.toString() ? `?${params.toString()}` : ""}`, {
    headers: jsonHeaders(),
  });

  if (!res.ok) {
    throw new Error("Erro ao carregar incidentes");
  }

  return res.json();
}
