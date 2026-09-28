import { API_BASE_URL, jsonHeaders } from "./config";

const API = API_BASE_URL;

function defaultHeaders() {
  return jsonHeaders({
    "Cache-Control": "no-cache, no-store, max-age=0",
    Pragma: "no-cache",
  });
}

async function handle(res, fallback = "Falha ao carregar relatórios") {
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
    return [];
  }
}

function buildQuery(options = {}) {
  const params = new URLSearchParams();
  if (options.q) params.append("q", String(options.q));
  if (options.severity && options.severity !== "all") params.append("severity", String(options.severity));
  if (options.source && options.source !== "all") params.append("source", String(options.source));
  if (options.from) params.append("from", String(options.from));
  if (options.to) params.append("to", String(options.to));
  params.append("limit", String(options.limit || 500));
  params.set("_ts", String(Date.now()));
  return params.toString() ? `?${params.toString()}` : "";
}

export async function listReportEvents(options = {}) {
  const res = await fetch(`${API}/reports/events${buildQuery(options)}`, {
    headers: defaultHeaders(),
    cache: "no-store",
  });

  return handle(res, "Falha ao carregar eventos consolidados");
}
