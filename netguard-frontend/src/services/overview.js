import { API_BASE_URL, jsonHeaders } from "./config";

const API = API_BASE_URL;

async function handle(res, fallback = "Erro na requisição") {
  if (!res.ok) {
    let msg = fallback;
    try {
      const data = await res.json();
      msg = typeof data === "object" ? JSON.stringify(data) : String(data);
    } catch {
      try { msg = await res.text(); } catch {}
    }
    throw new Error(msg || fallback);
  }
  try { return await res.json(); } catch { return null; }
}

export async function getOverview() {
  const res = await fetch(`${API}/metrics/overview`, { headers: jsonHeaders() });
  return handle(res, "Falha ao carregar overview");
}

