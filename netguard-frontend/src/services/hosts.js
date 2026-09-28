import { API_BASE_URL, jsonHeaders as buildJsonHeaders } from "./config";

// src/services/hosts.js

const API = API_BASE_URL;

function jsonHeaders() {
  return buildJsonHeaders();
}

function authOptions(options = {}) {
  return {
    ...options,
    headers: {
      ...jsonHeaders(),
      ...(options.headers || {}),
    },
  };
}

async function handle(res, fallback = "Erro na requisição") {
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

export async function listHosts(options = {}) {
  const params = options || {};
  const qs = new URLSearchParams();

  if (params.groupId) {
    qs.append("group_id", String(params.groupId));
  }
  if (params.templateId) {
    qs.append("template_id", String(params.templateId));
  }
  if (params.q) {
    qs.append("q", String(params.q));
  }
  if (params.enabled !== undefined && params.enabled !== null && params.enabled !== "") {
    qs.append("enabled", String(params.enabled));
  }
  if (params.health) {
    qs.append("health", String(params.health));
  }
  if (params.severity) {
    qs.append("severity", String(params.severity));
  }
  if (params.from) {
    qs.append("from", String(params.from));
  }
  if (params.to) {
    qs.append("to", String(params.to));
  }
  if (params.limit) {
    qs.append("limit", String(params.limit));
  }

  const res = await fetch(`${API}/hosts${qs.toString() ? `?${qs.toString()}` : ""}`, authOptions());
  return handle(res, "Falha ao listar hosts");
}

export async function listHostGroups() {
  const res = await fetch(`${API}/host-groups`, authOptions());
  return handle(res, "Falha ao listar grupos de hosts");
}

export async function listHostGroupsTree() {
  const res = await fetch(`${API}/host-groups/tree`, authOptions());
  return handle(res, "Falha ao listar árvore de grupos de hosts");
}

export async function listTemplates() {
  const res = await fetch(`${API}/templates`, authOptions());
  return handle(res, "Falha ao listar templates");
}

export async function getTemplate(id) {
  const res = await fetch(`${API}/templates/${id}`, authOptions());
  return handle(res, "Falha ao buscar template");
}

export async function getTemplatePreview(id) {
  const res = await fetch(`${API}/templates/${id}/preview`, authOptions());
  return handle(res, "Falha ao buscar preview do template");
}

export async function updateTemplateCollectionPolicy(id, payload) {
  const res = await fetch(`${API}/templates/${id}/collection-policy`, {
    method: "PUT",
    headers: jsonHeaders(),
    body: JSON.stringify({
      icmp_interval_sec: Number(payload.icmp_interval_sec),
      snmp_interval_sec: Number(payload.snmp_interval_sec),
      tcp_interval_sec: Number(payload.tcp_interval_sec || 60),
      timeout_sec: Number(payload.timeout_sec),
      retries: Number(payload.retries),
      history_retention_days: Number(payload.history_retention_days || 30),
      trend_retention_days: Number(payload.trend_retention_days || 90),
      log_retention_days: Number(payload.log_retention_days || 14),
      incident_retention_days: Number(payload.incident_retention_days || 180),
      notification_retention_days: Number(payload.notification_retention_days || 90),
      audit_retention_days: Number(payload.audit_retention_days || 365),
    }),
  });

  return handle(res, "Falha ao salvar política de coleta do template");
}

export async function listTemplateItems(id) {
  const res = await fetch(`${API}/templates/${id}/items`, authOptions());
  return handle(res, "Falha ao listar itens do template");
}

export async function listHostMonitoringItems(hostId) {
  const res = await fetch(`${API}/hosts/${hostId}/monitoring-items`, authOptions());
  return handle(res, "Falha ao listar itens monitorados do host");
}

export async function applyHostTemplate(hostId, payload) {
  const res = await fetch(`${API}/hosts/${hostId}/template`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      template_id: Number(payload.template_id),
      copy_items_to_host: payload.copy_items_to_host !== false,
      replace_profiles: payload.replace_profiles !== false,
    }),
  });

  return handle(res, "Falha ao aplicar template ao host");
}

export async function updateMonitoringItem(itemId, payload) {
  const res = await fetch(`${API}/monitoring/items/${itemId}`, {
    method: "PUT",
    headers: jsonHeaders(),
    body: JSON.stringify(payload),
  });

  return handle(res, "Falha ao atualizar item monitorado");
}

export async function toggleMonitoringItem(itemId, enabled) {
  const res = await fetch(`${API}/monitoring/items/${itemId}/enabled`, {
    method: "PATCH",
    headers: jsonHeaders(),
    body: JSON.stringify({ enabled }),
  });

  return handle(res, "Falha ao alternar item monitorado");
}

export async function createHostGroup(payload) {
  const res = await fetch(`${API}/host-groups`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      name: payload.name,
      parent_id:
        payload.parent_id === "" || payload.parent_id === undefined || payload.parent_id === null
          ? null
          : Number(payload.parent_id),
      tags: payload.tags || {},
      enabled: payload.enabled !== false,
    }),
  });

  return handle(res, "Falha ao criar grupo de hosts");
}

export async function getHost(id) {
  const res = await fetch(`${API}/hosts/${id}`, authOptions());
  return handle(res, "Falha ao buscar host");
}

export async function createHost(payload) {
  const res = await fetch(`${API}/hosts`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      name: payload.name,
      ip: payload.ip,
      enabled: !!payload.enabled,
      snmp_profile: payload.snmp_profile || {},
      tags: payload.tags || {},
      group_id:
        payload.group_id === "" || payload.group_id === undefined || payload.group_id === null
          ? null
          : Number(payload.group_id),
      template_id:
        payload.template_id === "" || payload.template_id === undefined || payload.template_id === null
          ? null
          : Number(payload.template_id),
      collection_policy_override: payload.collection_policy_override || {},
    }),
  });

  return handle(res, "Falha ao criar host");
}

export async function updateHost(id, payload) {
  const res = await fetch(`${API}/hosts/${id}`, {
    method: "PUT",
    headers: jsonHeaders(),
    body: JSON.stringify({
      name: payload.name,
      ip: payload.ip,
      enabled: !!payload.enabled,
      snmp_profile: payload.snmp_profile || {},
      tags: payload.tags || {},
      group_id:
        payload.group_id === "" || payload.group_id === undefined || payload.group_id === null
          ? null
          : Number(payload.group_id),
      template_id:
        payload.template_id === "" || payload.template_id === undefined || payload.template_id === null
          ? null
          : Number(payload.template_id),
      collection_policy_override: payload.collection_policy_override || {},
    }),
  });

  return handle(res, "Falha ao atualizar host");
}

export async function deleteHost(id) {
  const res = await fetch(`${API}/hosts/${id}`, authOptions({ method: "DELETE" }));
  return handle(res, "Falha ao remover host");
}

export async function listProfiles() {
  const res = await fetch(`${API}/profiles`, authOptions());
  return handle(res, "Falha ao listar profiles");
}

export async function getHostProfiles(hostId) {
  const res = await fetch(`${API}/hosts/${hostId}/profiles`, authOptions());
  return handle(res, "Falha ao buscar profiles do host");
}

export async function updateHostProfiles(hostId, profiles) {
  const res = await fetch(`${API}/hosts/${hostId}/profiles`, {
    method: "PUT",
    headers: jsonHeaders(),
    body: JSON.stringify({
      profiles: profiles.map((p) => ({
        profile_id: p.profile_id,
        params: p.params || {},
        enabled: p.enabled !== false,
      })),
    }),
  });

  return handle(res, "Falha ao salvar profiles do host");
}

export async function discoverHostInterfaces(hostId) {
  const res = await fetch(`${API}/hosts/${hostId}/discover-interfaces`, {
    method: "POST",
    headers: jsonHeaders(),
  });
  return handle(res, "Falha ao descobrir interfaces do host");
}

export async function listHostInterfaces(hostId) {
  const res = await fetch(`${API}/hosts/${hostId}/interfaces`, authOptions());
  return handle(res, "Falha ao listar interfaces do host");
}

export async function updateHostInterface(hostId, interfaceId, payload) {
  const res = await fetch(`${API}/hosts/${hostId}/interfaces/${interfaceId}`, {
    method: "PUT",
    headers: jsonHeaders(),
    body: JSON.stringify(payload),
  });

  return handle(res, "Falha ao atualizar interface do host");
}

export async function scanNetworkDiscovery(payload) {
  const res = await fetch(`${API}/discovery/scan`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      cidr: payload.cidr,
      timeout_seconds: Number(payload.timeout_seconds || 1),
      retries: Number(payload.retries || 1),
      use_icmp: payload.use_icmp !== false,
      use_snmp: payload.use_snmp !== false,
      snmp_community: payload.snmp_community || "public",
      requested_by: payload.requested_by || undefined,
    }),
  });

  return handle(res, "Falha ao executar descoberta de rede");
}

export async function listDiscoveryRuns(limit = 20) {
  const res = await fetch(`${API}/discovery/runs?limit=${Number(limit) || 20}`, authOptions());
  return handle(res, "Falha ao listar execucoes de descoberta");
}

export async function listDiscoveryResults(runId) {
  const res = await fetch(`${API}/discovery/runs/${runId}/results`, authOptions());
  return handle(res, "Falha ao listar resultados de descoberta");
}

export async function importDiscoveryResults(payload) {
  const res = await fetch(`${API}/discovery/import`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      result_ids: payload.result_ids || [],
      group_id:
        payload.group_id === "" || payload.group_id === undefined || payload.group_id === null
          ? null
          : Number(payload.group_id),
      enable_hosts: payload.enable_hosts !== false,
      snmp_community: payload.snmp_community || undefined,
    }),
  });

  return handle(res, "Falha ao importar hosts descobertos");
}

export async function promoteDiscoveryResult(resultId, payload = {}) {
  const res = await fetch(`${API}/discovery/results/${resultId}/promote`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      result_ids: [Number(resultId)],
      group_id:
        payload.group_id === "" || payload.group_id === undefined || payload.group_id === null
          ? null
          : Number(payload.group_id),
      enable_hosts: payload.enable_hosts !== false,
      snmp_community: payload.snmp_community || undefined,
    }),
  });

  return handle(res, "Falha ao importar host descoberto");
}

