import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppShell from "../components/AppShell";
import { listHostGroups, listHosts, listTemplates } from "../services/hosts";
import { listRecentSignals } from "../services/monitoring";
import {
  TIME_RANGE_OPTIONS,
  formatDateTime,
  resolveTimeRange,
  severityClassName,
  severityLabel,
  sourceLabel,
  statusClassName,
  statusLabel,
} from "../monitoringUi";

function StatCard({ label, value, subtitle, tone = "slate" }) {
  const tones = {
    slate: "border-white/10 bg-slate-900/70",
    sky: "border-sky-500/20 bg-sky-500/10",
    amber: "border-amber-500/20 bg-amber-500/10",
    red: "border-red-500/20 bg-red-500/10",
  };

  return (
    <div className={`rounded-2xl border p-5 ${tones[tone] || tones.slate}`}>
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-3 text-3xl font-semibold text-white">{value}</div>
      {subtitle ? <div className="mt-2 text-sm text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function contextText(signal) {
  const parts = [signal.subsystem, signal.iface].filter(Boolean);
  return parts.length ? parts.join(" / ") : "Sem contexto adicional";
}

export default function Metrics() {
  const [rows, setRows] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [groups, setGroups] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [groupFilter, setGroupFilter] = useState("");
  const [templateFilter, setTemplateFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [windowFilter, setWindowFilter] = useState("24h");

  const range = useMemo(() => resolveTimeRange(windowFilter), [windowFilter]);

  async function loadData(mode = "initial") {
    try {
      if (mode === "initial") {
        setLoading(true);
      } else {
        setRefreshing(true);
      }

      setError("");
      const [signalData, hostData, groupData, templateData] = await Promise.all([
        listRecentSignals({
          assetId: hostFilter || undefined,
          groupId: groupFilter || undefined,
          templateId: templateFilter || undefined,
          source: sourceFilter || undefined,
          type: typeFilter || undefined,
          severity: severityFilter || undefined,
          q: query || undefined,
          from: range.from,
          to: range.to,
          limit: 250,
        }),
        listHosts({ limit: 500 }).catch(() => []),
        listHostGroups().catch(() => []),
        listTemplates().catch(() => []),
      ]);

      setRows(Array.isArray(signalData) ? signalData : []);
      setHosts(Array.isArray(hostData) ? hostData : []);
      setGroups(Array.isArray(groupData) ? groupData : []);
      setTemplates(Array.isArray(templateData) ? templateData : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar sinais recentes");
      setRows([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadData("initial");
  }, [groupFilter, hostFilter, query, range.from, range.to, severityFilter, sourceFilter, templateFilter, typeFilter]);

  const typeOptions = useMemo(() => {
    return [...new Set(rows.map((row) => row.signal_type).filter(Boolean))].sort((a, b) =>
      String(a).localeCompare(String(b), "pt-BR")
    );
  }, [rows]);

  useEffect(() => {
    if (typeFilter && rows.length > 0 && !typeOptions.includes(typeFilter)) {
      setTypeFilter("");
    }
  }, [rows.length, typeFilter, typeOptions]);

  const filteredRows = useMemo(() => {
    if (!typeFilter) return rows;
    return rows.filter((row) => row.signal_type === typeFilter);
  }, [rows, typeFilter]);

  const stats = useMemo(() => {
    return {
      total: filteredRows.length,
      syslog: filteredRows.filter((row) => row.source === "syslog").length,
      incidents: filteredRows.filter((row) => row.source === "incident").length,
      predictions: filteredRows.filter((row) => row.source === "prediction").length,
    };
  }, [filteredRows]);

  return (
    <AppShell
      title="Sinais recentes"
      description="Tela operacional para observar syslogs recentes, sinais precursores, anomalias e eventos relevantes com contexto de host, grupo, template e interface."
      actions={
        <button
          type="button"
          onClick={() => loadData("refresh")}
          disabled={loading || refreshing}
          className="inline-flex whitespace-nowrap rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
        >
          {refreshing ? "Atualizando..." : "Atualizar"}
        </button>
      }
    >
      {error ? (
        <div className="mb-6 rounded-lg border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      ) : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Sinais visíveis" value={stats.total} subtitle="Eventos relevantes na janela selecionada." tone="sky" />
        <StatCard label="Syslog" value={stats.syslog} subtitle="Eventos recentes de syslog." tone="slate" />
        <StatCard label="Incidentes" value={stats.incidents} subtitle="Sinais já promovidos à fila operacional." tone="red" />
        <StatCard label="Previsões" value={stats.predictions} subtitle="Anomalias e correlações recentes." tone="amber" />
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70 p-4">
        <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-[minmax(280px,1.2fr),220px,220px,220px,220px]">
          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Buscar</label>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Host, texto, subsystem, interface..."
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
          </div>

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Host</label>
            <select
              value={hostFilter}
              onChange={(event) => setHostFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todos os hosts</option>
              {hosts.map((host) => (
                <option key={host.id} value={host.id}>
                  {host.name}
                </option>
              ))}
            </select>
          </div>

          <div>
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

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Template</label>
            <select
              value={templateFilter}
              onChange={(event) => setTemplateFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todos os templates</option>
              {templates.filter((template) => template.enabled !== false).map((template) => (
                <option key={template.id} value={template.id}>
                  {template.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Janela</label>
            <select
              value={windowFilter}
              onChange={(event) => setWindowFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              {TIME_RANGE_OPTIONS.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-[220px,220px,220px,auto]">
          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Fonte</label>
            <select
              value={sourceFilter}
              onChange={(event) => setSourceFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todas</option>
              <option value="syslog">Syslog</option>
              <option value="incident">Incidente</option>
              <option value="prediction">Previsão</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Severidade</label>
            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todas</option>
              <option value="critical">Crítica</option>
              <option value="high">Alta</option>
              <option value="warning">Atenção</option>
              <option value="medium">Média</option>
              <option value="low">Baixa</option>
              <option value="info">Informativa</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Tipo</label>
            <select
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todos</option>
              {typeOptions.map((typeOption) => (
                <option key={typeOption} value={typeOption}>
                  {typeOption}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="button"
              onClick={() => {
                setQuery("");
                setHostFilter("");
                setGroupFilter("");
                setTemplateFilter("");
                setSourceFilter("");
                setSeverityFilter("");
                setTypeFilter("");
                setWindowFilter("24h");
              }}
              className="inline-flex whitespace-nowrap rounded-md border border-white/10 bg-slate-950 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-900"
            >
              Limpar filtros
            </button>
          </div>
        </div>
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70">
        <div className="flex items-center justify-between gap-4 border-b border-white/10 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Fluxo recente de sinais</h2>
            <p className="mt-1 text-sm text-slate-400">
              Eventos, precursores e anomalias consolidados para leitura operacional rápida.
            </p>
          </div>
          <div className="rounded-full border border-white/10 bg-slate-950 px-3 py-1 text-xs uppercase tracking-wide text-slate-400">
            {filteredRows.length} sinal(is)
          </div>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
            <div className="px-6 py-12 text-center text-sm text-slate-400">
              Carregando sinais recentes...
            </div>
          ) : filteredRows.length ? (
            <table className="min-w-[1280px] text-sm xl:min-w-full">
              <thead className="bg-slate-950/70 text-left text-slate-300">
                <tr>
                  <th className="px-4 py-3">Hora</th>
                  <th className="px-4 py-3">Fonte</th>
                  <th className="px-4 py-3">Sinal</th>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">Grupo</th>
                  <th className="px-4 py-3">Contexto</th>
                  <th className="px-4 py-3">Severidade / Status</th>
                  <th className="px-4 py-3 min-w-[420px]">Mensagem</th>
                  <th className="w-[120px] px-4 py-3 text-right">Ação</th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((row) => (
                  <tr key={row.id} className="border-t border-white/10 bg-slate-950/20">
                    <td className="px-4 py-3 text-slate-300">{formatDateTime(row.ts)}</td>
                    <td className="px-4 py-3">
                      <span className="inline-flex rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-200">
                        {sourceLabel(row.source)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-200">{row.title}</td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{row.hostname}</div>
                      <div className="text-xs text-slate-500">{row.src_ip || "-"}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{row.group_path || row.group_name || "Sem grupo"}</td>
                    <td className="px-4 py-3 text-slate-300">{contextText(row)}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        {row.severity ? (
                          <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${severityClassName(row.severity)}`}>
                            {severityLabel(row.severity)}
                          </span>
                        ) : null}
                        {row.status ? (
                          <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${statusClassName(row.status)}`}>
                            {statusLabel(row.status)}
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{row.message}</td>
                    <td className="px-4 py-3 text-right">
                      {row.asset_id ? (
                        <Link
                          to={`/monitoring/hosts/${row.asset_id}`}
                          className="inline-flex min-w-[88px] justify-center whitespace-nowrap rounded-md bg-sky-500 px-3 py-2 text-xs font-medium text-white hover:bg-sky-600"
                        >
                          Abrir host
                        </Link>
                      ) : (
                        <span className="text-xs text-slate-500">Sem vínculo</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-6 py-12 text-center text-sm text-slate-400">
              Nenhum sinal recente encontrado para os filtros atuais.
            </div>
          )}
        </div>
      </section>
    </AppShell>
  );
}


