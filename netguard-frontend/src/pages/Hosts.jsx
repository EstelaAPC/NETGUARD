import React, { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import AppShell from "../components/AppShell";
import { deleteHost, listHostGroups, listHosts, listTemplates } from "../services/hosts";

function statusBadge(enabled) {
  return enabled
    ? "bg-emerald-500/20 text-emerald-200 border-emerald-500/30"
    : "bg-slate-500/20 text-slate-200 border-slate-500/30";
}

function formatDurationSeconds(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return "-";
  if (numeric < 60) return `${numeric}s`;
  if (numeric < 3600) {
    const minutes = Math.floor(numeric / 60);
    const seconds = numeric % 60;
    return seconds ? `${minutes}min ${seconds}s` : `${minutes}min`;
  }

  const hours = Math.floor(numeric / 3600);
  const minutes = Math.floor((numeric % 3600) / 60);
  return minutes ? `${hours}h ${minutes}min` : `${hours}h`;
}

function formatCollectionPolicySummary(policy) {
  if (!policy || typeof policy !== "object") {
    return "Fallback global";
  }

  return `ICMP ${formatDurationSeconds(policy.icmp_interval_sec)} • SNMP ${formatDurationSeconds(
    policy.snmp_interval_sec
  )}`;
}

export default function Hosts() {
  const navigate = useNavigate();
  const location = useLocation();
  const [items, setItems] = useState([]);
  const [groups, setGroups] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(location.state?.success || "");
  const [query, setQuery] = useState("");
  const [groupFilter, setGroupFilter] = useState("");
  const [templateFilter, setTemplateFilter] = useState(
    () => new URLSearchParams(location.search).get("template_id") || ""
  );
  const [statusFilter, setStatusFilter] = useState("all");

  useEffect(() => {
    if (location.state?.success) {
      navigate({ pathname: location.pathname, search: location.search }, { replace: true, state: null });
    }
  }, [location.pathname, location.search, location.state, navigate]);

  useEffect(() => {
    setTemplateFilter(new URLSearchParams(location.search).get("template_id") || "");
  }, [location.search]);

  async function loadData() {
    try {
      setLoading(true);
      setError("");
      const [hostData, groupData, templateData] = await Promise.all([
        listHosts({ groupId: groupFilter || undefined, templateId: templateFilter || undefined }),
        listHostGroups().catch(() => []),
        listTemplates().catch(() => []),
      ]);
      setItems(Array.isArray(hostData) ? hostData : []);
      setGroups(Array.isArray(groupData) ? groupData : []);
      setTemplates(Array.isArray(templateData) ? templateData : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar hosts");
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [groupFilter, templateFilter]);

  const filteredItems = useMemo(() => {
    const normalized = query.trim().toLowerCase();

    return items.filter((host) => {
      if (statusFilter === "active" && !host.enabled) return false;
      if (statusFilter === "inactive" && host.enabled) return false;
      if (!normalized) return true;

      return (
        String(host.name || "").toLowerCase().includes(normalized) ||
        String(host.ip || "").toLowerCase().includes(normalized) ||
        String(host.group_name || host.group_path || "").toLowerCase().includes(normalized) ||
        String(
          `${host.template_name || ""} ${host.template_family || ""} ${host.template_vendor || ""}`
        )
          .toLowerCase()
          .includes(normalized)
      );
    });
  }, [items, query, statusFilter]);

  async function handleDelete(host) {
    if (!confirm(`Remover o host "${host.name}"?`)) {
      return;
    }

    try {
      setError("");
      setSuccess("");
      await deleteHost(host.id);
      await loadData();
      setSuccess("Host removido com sucesso.");
    } catch (deleteError) {
      setError(deleteError?.message || "Falha ao remover host");
    }
  }

  return (
    <AppShell
      title="Hosts"
      description="Área de Coleta de dados para cadastro, organização e manutenção dos hosts monitorados pelo NetGuard, com grupo e template como base do cadastro."
      actions={
        <>
          <Link
            to="/monitoring/hosts"
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Ver hosts monitorados
          </Link>
          <Link
            to="/data-collection/hosts/new"
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600"
          >
            Criar host
          </Link>
        </>
      }
    >
      {error ? (
        <div className="mb-6 rounded-lg border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      ) : null}

      {success ? (
        <div className="mb-6 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {success}
        </div>
      ) : null}

      <section className="rounded-2xl border border-white/10 bg-slate-900/70 p-4">
        <div className="flex flex-wrap items-end gap-4">
          <div className="min-w-[240px] flex-1">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Buscar</label>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Nome, IP, grupo ou template..."
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
          </div>

          <div className="min-w-[220px]">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Grupo</label>
            <select
              value={groupFilter}
              onChange={(event) => setGroupFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todos os grupos</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.path || group.name}
                </option>
              ))}
            </select>
          </div>

          <div className="min-w-[220px]">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Template</label>
            <select
              value={templateFilter}
              onChange={(event) => setTemplateFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todos os templates</option>
              {templates.map((template) => (
                <option key={template.id} value={template.id}>
                  {template.name}
                </option>
              ))}
            </select>
          </div>

          <div className="min-w-[200px]">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Status</label>
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="all">Todos</option>
              <option value="active">Ativos</option>
              <option value="inactive">Inativos</option>
            </select>
          </div>
        </div>
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70">
        <div className="flex items-center justify-between gap-4 border-b border-white/10 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Cadastro de hosts</h2>
            <p className="mt-1 text-sm text-slate-400">
              Esta lista pertence à Coleta de dados e concentra cadastro, grupo principal, template e manutenção dos ativos.
            </p>
          </div>
          <div className="rounded-full border border-white/10 bg-slate-950 px-3 py-1 text-xs uppercase tracking-wide text-slate-400">
            {filteredItems.length} host(s)
          </div>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
            <div className="px-6 py-12 text-center text-sm text-slate-400">Carregando hosts...</div>
          ) : filteredItems.length ? (
            <table className="min-w-full text-sm">
              <thead className="bg-slate-950/70 text-left text-slate-300">
                <tr>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">IP</th>
                  <th className="px-4 py-3">Grupo</th>
                  <th className="px-4 py-3">Template</th>
                  <th className="px-4 py-3">Coleta</th>
                  <th className="px-4 py-3">SNMP</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Ações</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((host) => (
                  <tr key={host.id} className="border-t border-white/10 bg-slate-950/20">
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{host.name}</div>
                      <div className="text-xs text-slate-500">Host ID {host.id}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{host.ip}</td>
                    <td className="px-4 py-3">
                      {host.group_name ? (
                        <span className="inline-flex rounded-full border border-sky-500/30 bg-sky-500/20 px-2.5 py-1 text-xs font-medium text-sky-100">
                          {host.group_path || host.group_name}
                        </span>
                      ) : (
                        <span className="inline-flex rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-300">
                          Sem grupo
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {host.template_name ? (
                        <div className="space-y-1">
                          <span className="inline-flex rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-100">
                            {host.template_name}
                          </span>
                          <div className="text-xs text-slate-500">
                            {[host.template_vendor, host.template_family, host.template_asset_type]
                              .filter(Boolean)
                              .join(" / ") || "Template base"}
                          </div>
                        </div>
                      ) : (
                        <span className="inline-flex rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-300">
                          Sem template
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-sm text-slate-200">
                        {formatCollectionPolicySummary(host.collection_policy_resolved)}
                      </div>
                      <div className="text-xs text-slate-500">
                        {host.collection_policy_source === "host"
                          ? "Override por host"
                          : host.collection_policy_source === "mixed"
                          ? "Template + override"
                          : host.collection_policy_source === "template"
                          ? "Padrão do template"
                          : "Fallback global"}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {host?.snmp_profile?.community ? "Configurado" : "Não configurado"}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${statusBadge(host.enabled)}`}>
                        {host.enabled ? "Ativo" : "Inativo"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <Link
                          to={`/monitoring/hosts/${host.id}`}
                          className="rounded-md border border-white/10 bg-slate-950 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800"
                        >
                          Monitorar
                        </Link>
                        <Link
                          to={`/data-collection/hosts/${host.id}/edit`}
                          className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs text-sky-100 hover:bg-sky-500/20"
                        >
                          Editar
                        </Link>
                        <button
                          type="button"
                          onClick={() => handleDelete(host)}
                          className="rounded-md border border-rose-500/20 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-100 hover:bg-rose-500/20"
                        >
                          Remover
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-6 py-12 text-center text-sm text-slate-400">
              Nenhum host encontrado com os filtros atuais.
            </div>
          )}
        </div>
      </section>
    </AppShell>
  );
}


