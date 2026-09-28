import { API_BASE_URL, jsonHeaders } from "./config";

const API = API_BASE_URL;
const AI_REQUEST_TIMEOUT_MS = 190000;

function defaultHeaders() {
  return jsonHeaders();
}

async function handle(res, fallback = "Falha ao processar a solicitação de IA") {
  if (!res.ok) {
    let msg = fallback;

    try {
      const data = await res.json();
      msg = typeof data === "object" ? data.detail || JSON.stringify(data) : String(data);
    } catch {
      try {
        msg = await res.text();
      } catch {}
    }

    throw new Error(msg || fallback);
  }

  try {
    return await res.json();
  } catch {
    return null;
  }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = AI_REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error("A IA demorou além do esperado para responder. Tente novamente em instantes.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

export async function listAIInsights({
  targetType,
  targetId,
  insightType,
  includeExpired,
  limit = 20,
} = {}) {
  const params = new URLSearchParams();
  if (targetType) params.append("target_type", targetType);
  if (targetId !== undefined && targetId !== null && targetId !== "") {
    params.append("target_id", String(targetId));
  }
  if (insightType) params.append("insight_type", insightType);
  if (includeExpired) params.append("include_expired", "true");
  params.append("limit", String(limit));

  const res = await fetchWithTimeout(`${API}/ai/insights?${params.toString()}`, {
    headers: defaultHeaders(),
  });

  return handle(res, "Falha ao carregar insights");
}

async function postInsight(path, payload = {}, fallback) {
  const res = await fetchWithTimeout(`${API}${path}`, {
    method: "POST",
    headers: defaultHeaders(),
    body: JSON.stringify(payload),
  });

  return handle(res, fallback);
}

export function generateHostSummary(hostId, { refresh = false } = {}) {
  return postInsight(`/ai/hosts/${hostId}/summary`, { refresh }, "Falha ao gerar resumo do host");
}

export function generateHostRecommendation(hostId, { refresh = false } = {}) {
  return postInsight(
    `/ai/hosts/${hostId}/recommendation`,
    { refresh },
    "Falha ao gerar recomendação operacional"
  );
}

export function explainIncident(incidentId, { refresh = false } = {}) {
  return postInsight(`/ai/incidents/${incidentId}/explain`, { refresh }, "Falha ao explicar o incidente");
}

export function generateTechnicalSummary({ hostId, incidentId, refresh = false } = {}) {
  return postInsight(
    "/ai/reports/technical-summary",
    {
      host_id: hostId ?? null,
      incident_id: incidentId ?? null,
      refresh,
    },
    "Falha ao gerar resumo técnico"
  );
}

export function chatWithAI({ message, hostId, incidentId, hours = 24, history = [] }) {
  return postInsight(
    "/ai/chat",
    {
      message,
      host_id: hostId ?? null,
      incident_id: incidentId ?? null,
      hours,
      history: history.map((item) => ({
        role: item.role,
        content: item.content,
      })),
    },
    "Falha ao consultar o assistente operacional"
  );
}
