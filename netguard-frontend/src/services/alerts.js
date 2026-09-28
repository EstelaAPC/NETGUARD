import { API_BASE_URL, jsonHeaders } from "./config";

function defaultHeaders() {
  return jsonHeaders();
}

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      ...defaultHeaders(),
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Erro ao consultar alertas");
  }

  if (res.status === 204) return null;
  return res.json();
}

function queryString(options = {}) {
  const params = new URLSearchParams();
  Object.entries(options).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      params.append(key, String(value));
    }
  });
  return params.toString() ? `?${params.toString()}` : "";
}

export function getAlertSummary() {
  return request("/alerts/summary");
}

export function listAlertIncidents(options = {}) {
  return request(`/alerts/incidents${queryString(options)}`);
}

export function listAlertNotifications(options = {}) {
  return request(`/alerts/notifications${queryString(options)}`);
}

export function resolveAlertIncident(incidentId, options = {}) {
  return request(`/incidents/${incidentId}/resolve`, {
    method: "POST",
    body: JSON.stringify({
      send_recovery_notification: options.sendRecoveryNotification !== false,
      manual_reason: options.manualReason || "",
      resolution_source: options.resolutionSource || "manual",
    }),
  });
}

export function acknowledgeAlertIncident(incidentId, options = {}) {
  return request(`/alerts/incidents/${incidentId}/acknowledge`, {
    method: "POST",
    body: JSON.stringify({
      note: options.note || "",
    }),
  });
}

export function notifyAlertIncident(incidentId, options = {}) {
  return request(`/alerts/incidents/${incidentId}/notify`, {
    method: "POST",
    body: JSON.stringify({
      force: options.force !== false,
    }),
  });
}

export function listAlertChannels() {
  return request("/alerts/channels");
}

export function createAlertChannel(payload) {
  return request("/alerts/channels", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateAlertChannel(channelId, payload) {
  return request(`/alerts/channels/${channelId}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function toggleAlertChannel(channelId, enabled) {
  return request(`/alerts/channels/${channelId}/toggle`, {
    method: "PATCH",
    body: JSON.stringify({ enabled }),
  });
}

export function deleteAlertChannel(channelId) {
  return request(`/alerts/channels/${channelId}`, {
    method: "DELETE",
  });
}

export function testAlertChannel(channelId) {
  return request(`/alerts/channels/${channelId}/test`, {
    method: "POST",
  });
}
