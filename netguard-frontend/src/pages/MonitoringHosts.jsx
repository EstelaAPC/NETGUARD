import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppShell from "../components/AppShell";
import { listHostGroups, listHosts, listTemplates } from "../services/hosts";
import {
  TIME_RANGE_OPTIONS,
  formatDateTime,
  healthClassName,
  healthLabel,
  severityClassName,
  severityLabel,
  resolveTimeRange,
} from "../monitoringUi";

function StatCard({ label, value, subtitle, tone = "slate" }) {
  const tones = {
    slate: "border-white/10 bg-slate-900/70",
    sky: "border-sky-500/20 bg-sky-500/10",
    emerald: "border-emerald-500/20 bg-emerald-500/10",
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

function severityWeight(value) {
  const weights = {
    critical: 6,
    high: 5,
    warning: 4,
    medium: 3,
    low: 2,
    info: 1,
    notice: 1,
  };

  return weights[String(value || "").toLowerCase()] || 0;
}

function loopRiskLabel(score) {
  if (score === null || score === undefined) return "Sem alerta";
  const pct = Math.round(Number(score) * 100);
  if (pct >= 90) return `${pct}% crítico`;
  if (pct >= 75) return `${pct}% alto`;
  if (pct >= 50) return `${pct}% atenção`;
  return `${pct}% informativo`;
}

function loopRiskClass(score) {
  if (score === null || score === undefined) {
    return "border-white/10 bg-slate-900 text-slate-300";
  }
  if (score >= 0.9) return "border-red-500/30 bg-red-500/15 text-red-100";
  if (score >= 0.75) return "border-orange-500/30 bg-orange-500/15 text-orange-100";
  if (score >= 0.5) return "border-amber-500/30 bg-amber-500/15 text-amber-100";
  return "border-sky-500/30 bg-sky-500/15 text-sky-100";
}

export default function MonitoringHosts() {
  const [rows, setRows] = useState([]);
  const [groups, setGroups] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [groupFilter, setGroupFilter] = useState("");
  const [templateFilter, setTemplateFilter] = useState("");
  const [healthFilter, setHealthFilter] = useState("");
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
      const [hostData, groupData, templateData] = await Promise.all([
        listHosts({
          q: query || undefined,
          groupId: groupFilter || undefined,
          templateId: templateFilter || undefined,
          health: healthFilter || undefined,
          severity: severityFilter || undefined,
          from: range.from,
          to: range.to,
          limit: 300,
        }),
        listHostGroups().catch(() => []),
        listTemplates().catch(() => []),
      ]);

      setRows(Array.isArray(hostData) ? hostData : []);
      setGroups(Array.isArray(groupData) ? groupData : []);
      setTemplates(Array.isArray(templateData) ? templateData : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar hosts monitorados");
      setRows([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadData("initial");
  }, [groupFilter, healthFilter, query, range.from, range.to, severityFilter, templateFilter]);

  const orderedRows = useMemo(() => {
    return [...rows].sort((a, b) => {
      const aDemo = a?.name === "lab-linux-01" || a?.ip === "172.30.10.10";
      const bDemo = b?.name === "lab-linux-01" || b?.ip === "172.30.10.10";
      if (aDemo && !bDemo) return -1;
      if (!aDemo && bDemo) return 1;

      const severityDiff = severityWeight(b.max_incident_severity) - severityWeight(a.max_incident_severity);
      if (severityDiff !== 0) return severityDiff;

      const openDiff = Number(b.open_incidents || 0) - Number(a.open_incidents || 0);
      if (openDiff !== 0) return openDiff;

      return String(b.last_activity_at || "").localeCompare(String(a.last_activity_at || ""));
    });
  }, [rows]);

  const stats = useMemo(() => {
    const openIncidentTotal = orderedRows.reduce(
      (total, row) => total + Number(row.open_incidents || 0),
      0
    );

    return {
      total: orderedRows.length,
      down: orderedRows.filter((row) => row.health_status === "down").length,
      atRisk: orderedRows.filter((row) => Number(row.loop_risk_score || 0) >= 0.5).length,
      openIncidentTotal,
      severeHosts: orderedRows.filter(
        (row) => severityWeight(row.max_incident_severity) >= 5
      ).length,
    };
  }, [orderedRows]);

  return (
    <AppShell
      title="Hosts monitorados"
      description="Grade operacional de hosts com saúde, severidade, incidentes abertos, risco de loop, última atividade e acesso direto ao drill-down por host."
      actions={
        <>
          <Link
            to="/data-collection/hosts"
            className="inline-flex whitespace-nowrap rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Ir para coleta de dados
          </Link>
          <button
            type="button"
            onClick={() => loadData("refresh")}
            disabled={loading || refreshing}
            className="inline-flex whitespace-nowrap rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
          >
            {refreshing ? "Atualizando..." : "Atualizar"}
          </button>
        </>
      }
    >
      {error ? (
        <div className="mb-6 rounded-lg border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      ) : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <StatCard label="Hosts visíveis" value={stats.total} subtitle="Após filtros operacionais." tone="sky" />
        <StatCard label="Indisponíveis" value={stats.down} subtitle="Host.alive recente abaixo do esperado." tone="red" />
        <StatCard label="Com risco de loop" value={stats.atRisk} subtitle="Score igual ou acima de 50%." tone="amber" />
        <StatCard label="Incidentes abertos" value={stats.openIncidentTotal} subtitle="Fila aberta somada nesta visão." tone="red" />
        <StatCard label="Alta criticidade" value={stats.severeHosts} subtitle="Hosts com severidade alta ou crítica." tone="amber" />
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70 p-4">
        <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-[minmax(280px,1.5fr),220px,220px,220px,220px]">
          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Buscar</label>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Host, IP, grupo ou template..."
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
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
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Saúde</label>
            <select
              value={healthFilter}
              onChange={(event) => setHealthFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todas</option>
              <option value="healthy">Saudável</option>
              <option value="down">Indisponível</option>
              <option value="no_data">Sem telemetria</option>
              <option value="inactive">Cadastro inativo</option>
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
              <option value="none">Sem incidente</option>
            </select>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-end gap-4">
          <div className="w-[220px]">
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

          <button
            type="button"
            onClick={() => {
              setQuery("");
              setGroupFilter("");
              setTemplateFilter("");
              setHealthFilter("");
              setSeverityFilter("");
              setWindowFilter("24h");
            }}
            className="inline-flex whitespace-nowrap rounded-md border border-white/10 bg-slate-950 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-900"
          >
            Limpar filtros
          </button>
        </div>
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70">
        <div className="flex items-center justify-between gap-4 border-b border-white/10 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Grade operacional</h2>
            <p className="mt-1 text-sm text-slate-400">
              Saúde, gravidade, atividade recente e contexto do host em uma única visão.
            </p>
          </div>
          <div className="rounded-full border border-white/10 bg-slate-950 px-3 py-1 text-xs uppercase tracking-wide text-slate-400">
            {orderedRows.length} host(s)
          </div>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
            <div className="px-6 py-12 text-center text-sm text-slate-400">
              Carregando grade operacional...
            </div>
          ) : orderedRows.length ? (
            <table className="min-w-[1180px] text-sm xl:min-w-full">
              <thead className="bg-slate-950/70 text-left text-slate-300">
                <tr>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">Grupo</th>
                  <th className="px-4 py-3">Template</th>
                  <th className="px-4 py-3">Saúde</th>
                  <th className="px-4 py-3">Severidade</th>
                  <th className="px-4 py-3">Incidentes abertos</th>
                  <th className="px-4 py-3">Risco de loop</th>
                  <th className="px-4 py-3">Última atividade</th>
                  <th className="px-4 py-3">Última coleta</th>
                  <th className="w-[120px] px-4 py-3 text-right">Ação</th>
                </tr>
              </thead>
              <tbody>
                {orderedRows.map((row) => (
                  <tr key={row.id} className="border-t border-white/10 bg-slate-950/20">
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{row.name}</div>
                      <div className="text-xs text-slate-500">{row.ip}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{row.group_path || row.group_name || "Sem grupo legado"}</td>
                    <td className="px-4 py-3 text-slate-300">{row.template_name || "Sem template legado"}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${healthClassName(row.health_status)}`}>
                        {healthLabel(row.health_status)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {row.max_incident_severity ? (
                        <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${severityClassName(row.max_incident_severity)}`}>
                          {severityLabel(row.max_incident_severity)}
                        </span>
                      ) : (
                        <span className="inline-flex rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-300">
                          Sem incidente
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-200">{row.open_incidents || 0}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${loopRiskClass(row.loop_risk_score)}`}>
                        {loopRiskLabel(row.loop_risk_score)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{formatDateTime(row.last_activity_at)}</td>
                    <td className="px-4 py-3 text-slate-300">{formatDateTime(row.last_collection_at)}</td>
                    <td className="px-4 py-3 text-right">
                      <Link
                        to={`/monitoring/hosts/${row.id}`}
                        className="inline-flex min-w-[88px] justify-center whitespace-nowrap rounded-md bg-sky-500 px-3 py-2 text-xs font-medium text-white hover:bg-sky-600"
                      >
                        Abrir host
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-6 py-12 text-center text-sm text-slate-400">
              Nenhum host monitorado encontrado para os filtros atuais.
            </div>
          )}
        </div>
      </section>
    </AppShell>
  );
}

