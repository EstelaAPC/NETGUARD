import { API_BASE_URL, jsonHeaders } from "./config";

const API = API_BASE_URL;

async function handle(res, fallback = "Falha ao carregar dashboards") {
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

    throw new Error(msg || fallback);
  }

  try {
    return await res.json();
  } catch {
    return null;
  }
}

function getOptions() {
  return {
    cache: "no-store",
    headers: jsonHeaders({
      "Cache-Control": "no-cache, no-store, max-age=0",
      Pragma: "no-cache",
    }),
  };
}

function buildQuery(options = {}) {
  const params = new URLSearchParams();
  if (options.from) params.append("from", String(options.from));
  if (options.to) params.append("to", String(options.to));
  params.set("_ts", String(Date.now()));
  return params.toString() ? `?${params.toString()}` : "";
}

export async function getOpsDashboards(options = {}) {
  const res = await fetch(`${API}/dashboards/ops${buildQuery(options)}`, getOptions());
  return handle(res, "Falha ao carregar dashboard operacional");
}

export async function getHostDashboards(hostId, options = {}) {
  const res = await fetch(`${API}/dashboards/host/${hostId}${buildQuery(options)}`, getOptions());
  return handle(res, "Falha ao carregar dashboards do host");
}

export async function getGroupDashboards(groupId, options = {}) {
  const res = await fetch(`${API}/dashboards/group/${groupId}${buildQuery(options)}`, getOptions());
  return handle(res, "Falha ao carregar dashboards do grupo");
}

export async function getTemplateDashboards(templateId, options = {}) {
  const res = await fetch(`${API}/dashboards/template/${templateId}${buildQuery(options)}`, getOptions());
  return handle(res, "Falha ao carregar dashboards do template");
}
