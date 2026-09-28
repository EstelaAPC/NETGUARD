import { API_BASE_URL, jsonHeaders as buildJsonHeaders } from "./config";

const API = API_BASE_URL;

function jsonHeaders() {
  return buildJsonHeaders();
}

export async function listAssets() {
  const r = await fetch(`${API}/assets`, { headers: jsonHeaders() });
  if (!r.ok) throw new Error(await r.text().catch(() => "Falha ao listar"));
  return r.json();
}

export async function createAsset(payload) {
  const r = await fetch(`${API}/assets`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(await r.text().catch(() => "Falha ao criar"));
  return r.json();
}
