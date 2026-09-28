import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AIInsightCard from "../components/AIInsightCard";
import AppShell from "../components/AppShell";
import { explainIncident } from "../services/ai";
import { listHostGroups, listHosts, listTemplates } from "../services/hosts";
import { listIncidents } from "../services/incidents";
import {
  TIME_RANGE_OPTIONS,
  formatDateTime,
  incidentTypeLabel,
  resolveTimeRange,
  severityClassName,
  severityLabel,
  statusClassName,
  statusLabel,
} from "../monitoringUi";

function StatCard({ label, value, subtitle, tone = "slate" }) {
  const tones = {
    slate: "border-white/10 bg-slate-900/70",
    red: "border-red-500/20 bg-red-500/10",
    amber: "border-amber-500/20 bg-amber-500/10",
    sky: "border-sky-500/20 bg-sky-500/10",
  };

  return (
    <div className={`rounded-2xl border p-5 ${tones[tone] || tones.slate}`}>
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-3 text-3xl font-semibold text-white">{value}</div>
      {subtitle ? <div className="mt-2 text-sm text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function recommendationPreview(incident) {
  const recommendation = incident?.details?.recommendation;
  if (recommendation) return recommendation;
  return incident?.title || "-";
}

const SIGNAL_META = {
  BROADCAST_STORM: {
    label: "Broadcast storm",
    className: "border-red-500/20 bg-red-500/10 text-red-100",
  },
  MAC_FLAPPING: {
    label: "MAC flapping",
    className: "border-amber-500/20 bg-amber-500/10 text-amber-100",
  },
  INTERFACE_FLAP: {
    label: "Interface flap",
    className: "border-sky-500/20 bg-sky-500/10 text-sky-100",
  },
  STP_TOPOLOGY_CHANGE: {
    label: "Topology change",
    className: "border-violet-500/20 bg-violet-500/10 text-violet-100",
  },
};

function uniqueStrings(values = []) {
  return [...new Set((Array.isArray(values) ? values : []).map((item) => String(item || "").trim()).filter(Boolean))];
}

function signalLabel(signal, fallbackLabel = "") {
  return SIGNAL_META[String(signal || "").toUpperCase()]?.label || fallbackLabel || String(signal || "").replaceAll("_", " ");
}

function signalClassName(signal) {
  return (
    SIGNAL_META[String(signal || "").toUpperCase()]?.className ||
    "border-white/10 bg-slate-950/50 text-slate-200"
  );
}

function contextLabel(value) {
  const text = String(value || "").trim();
  if (!text || text.toLowerCase() === "host" || text.toLowerCase() === "unknown") {
    return "Contexto não identificado";
  }
  return text;
}

function buildIncidentSignalContexts(incident) {
  const details = incident?.details || {};
  const structured = Array.isArray(details.signal_contexts) ? details.signal_contexts : [];
  if (structured.length) {
    const buckets = new Map();
    structured.forEach((rawItem) => {
      const item = rawItem || {};
      const signal = String(item.signal || "");
      const focus = String(item.focus || "host");
      const bucketKey = `${signal}|${focus}`;
      const current = buckets.get(bucketKey) || {
        signal,
        label: signalLabel(signal, item.label),
        count: 0,
        focus,
        interfaces: [],
        className: signalClassName(signal),
      };
      current.count += Math.max(1, Number(item.count || 0));
      current.interfaces = uniqueStrings([...current.interfaces, ...(Array.isArray(item.interfaces) ? item.interfaces : [])]);
      buckets.set(bucketKey, current);
    });
    return [...buckets.values()].sort((left, right) => right.count - left.count);
  }

  const buckets = new Map();
  const evidences = Array.isArray(details.evidences) ? details.evidences : [];
  evidences.forEach((value) => {
    const text = String(value || "").trim();
    if (!text || text.startsWith("SNMP_DEGRADATION:")) return;
    const [signal, ...rest] = text.split(":");
    const focus = rest.join(":") || "host";
    const bucketKey = `${signal}|${focus}`;
    const current = buckets.get(bucketKey) || {
      signal,
      label: signalLabel(signal),
      count: 0,
      focus,
      interfaces: [],
      className: signalClassName(signal),
    };
    current.count += 1;
    if (focus && focus !== "host" && focus !== "unknown") {
      current.interfaces = uniqueStrings([
        ...current.interfaces,
        ...String(focus).split("<->"),
      ]);
    }
    buckets.set(bucketKey, current);
  });

  return [...buckets.values()].sort((left, right) => right.count - left.count);
}

function buildAffectedContexts(incident, signalContexts) {
  const details = incident?.details || {};
  const explicit = uniqueStrings(details.affected_contexts);
  if (explicit.length) return explicit;
  return uniqueStrings(signalContexts.map((item) => item.focus).filter((value) => value && value !== "host" && value !== "unknown"));
}

function buildOpeningReason(incident, signalContexts) {
  const explicit = String(incident?.details?.opening_reason || "").trim();
  if (explicit) return explicit;

  const loopContext = signalContexts.find((item) => item.signal === "BROADCAST_STORM");
  const macContext = signalContexts.find((item) => item.signal === "MAC_FLAPPING");
  const flapContext = signalContexts.find((item) => item.signal === "INTERFACE_FLAP");

  const parts = [];
  if (loopContext && macContext && loopContext.focus === macContext.focus) {
    parts.push(`Correlação entre storm e MAC flapping em ${contextLabel(loopContext.focus)}`);
  } else if (loopContext) {
    parts.push(`Broadcast storm em ${contextLabel(loopContext.focus)}`);
  } else if (macContext) {
    parts.push(`MAC flapping em ${contextLabel(macContext.focus)}`);
  }

  if (flapContext && flapContext.focus !== loopContext?.focus) {
    parts.push(`flap recorrente adicional em ${contextLabel(flapContext.focus)}`);
  }

  return parts.length
    ? `${parts.join("; ")} na mesma janela de correlação operacional.`
    : recommendationPreview(incident);
}

function compactContextList(values, limit = 3) {
  const items = uniqueStrings(values);
  if (items.length <= limit) return items.join(" • ");
  return `${items.slice(0, limit).join(" • ")} +${items.length - limit}`;
}

function contextPreview(incident, signalContexts) {
  const openingReason = buildOpeningReason(incident, signalContexts);
  const contexts = buildAffectedContexts(incident, signalContexts);
  if (contexts.length) {
    return `${openingReason} Contextos: ${contexts.join(" • ")}`;
  }
  return openingReason;
}

function DetailCard({ label, value, subtitle = "" }) {
  return (
    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-2 text-sm font-semibold text-white">{value || "-"}</div>
      {subtitle ? <div className="mt-1 text-xs text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function SignalSummaryCard({ item }) {
  return (
    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-white">{item.label}</div>
          <div className="mt-1 text-sm text-slate-300">{contextLabel(item.focus)}</div>
        </div>
        <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${item.className}`}>
          {item.count} ocorrência(s)
        </span>
      </div>
      {item.interfaces.length ? (
        <div className="mt-3 text-xs text-slate-400">
          Interfaces envolvidas: {item.interfaces.join(" • ")}
        </div>
      ) : null}
    </div>
  );
}

export default function Incidents() {
  const [rows, setRows] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [groups, setGroups] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [incidentInsight, setIncidentInsight] = useState(null);
  const [incidentInsightLoading, setIncidentInsightLoading] = useState(false);
  const [incidentInsightError, setIncidentInsightError] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [groupFilter, setGroupFilter] = useState("");
  const [templateFilter, setTemplateFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("open");
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
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
      const [incidentData, hostData, groupData, templateData] = await Promise.all([
        listIncidents({
          assetId: hostFilter || undefined,
          groupId: groupFilter || undefined,
          templateId: templateFilter || undefined,
          status: statusFilter || undefined,
          severity: severityFilter || undefined,
          incidentType: typeFilter || undefined,
          q: query || undefined,
          from: range.from,
          to: range.to,
          limit: 300,
        }),
        listHosts({ limit: 500 }).catch(() => []),
        listHostGroups().catch(() => []),
        listTemplates().catch(() => []),
      ]);

      setRows(Array.isArray(incidentData) ? incidentData : []);
      setHosts(Array.isArray(hostData) ? hostData : []);
      setGroups(Array.isArray(groupData) ? groupData : []);
      setTemplates(Array.isArray(templateData) ? templateData : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar fila de incidentes");
      setRows([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadData("initial");
  }, [groupFilter, hostFilter, query, range.from, range.to, severityFilter, statusFilter, templateFilter, typeFilter]);

  const stats = useMemo(() => {
    return {
      total: rows.length,
      open: rows.filter((row) => row.status === "open").length,
      highPriority: rows.filter((row) => ["critical", "high"].includes(row.severity)).length,
      loopRisk: rows.filter((row) => row.incident_type === "loop_risk").length,
    };
  }, [rows]);

  useEffect(() => {
    if (!rows.length) {
      setSelectedIncident(null);
      setIncidentInsight(null);
      setIncidentInsightError("");
      return;
    }

    setSelectedIncident((current) => {
      if (current) {
        const nextSelected = rows.find((row) => row.id === current.id);
        if (nextSelected) return nextSelected;
      }
      return rows[0];
    });
  }, [rows]);

  useEffect(() => {
    setIncidentInsight(null);
    setIncidentInsightError("");
  }, [selectedIncident?.id]);

  const selectedSignalContexts = useMemo(
    () => buildIncidentSignalContexts(selectedIncident),
    [selectedIncident],
  );
  const selectedAffectedContexts = useMemo(
    () => buildAffectedContexts(selectedIncident, selectedSignalContexts),
    [selectedIncident, selectedSignalContexts],
  );
  const selectedOpeningReason = useMemo(
    () => buildOpeningReason(selectedIncident, selectedSignalContexts),
    [selectedIncident, selectedSignalContexts],
  );

  function handleSelectIncident(row) {
    setSelectedIncident(row);
  }

  async function handleExplainIncident(row, refresh = false) {
    try {
      setSelectedIncident(row);
      setIncidentInsightLoading(true);
      setIncidentInsightError("");
      const generated = await explainIncident(row.id, { refresh });
      setIncidentInsight(generated);
    } catch (insightError) {
      setIncidentInsightError(insightError?.message || "Falha ao explicar incidente");
      setIncidentInsight(null);
    } finally {
      setIncidentInsightLoading(false);
    }
  }

  return (
    <AppShell
      title="Incidentes"
      description="Fila operacional de incidentes com filtros server-side, contexto de host, grupo, template, severidade e acesso direto ao drill-down operacional."
      actions={
        <button
          type="button"
          onClick={() => loadData("refresh")}
          disabled={loading || refreshing}
          className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
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
        <StatCard label="Incidentes visíveis" value={stats.total} subtitle="Após filtros operacionais." tone="sky" />
        <StatCard label="Abertos" value={stats.open} subtitle="Demandam triagem ou acompanhamento." tone="red" />
        <StatCard label="Alta prioridade" value={stats.highPriority} subtitle="Alta ou crítica na janela selecionada." tone="amber" />
        <StatCard label="Risco de loop" value={stats.loopRisk} subtitle="Correlação ativa de loop_risk." tone="amber" />
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70 p-4">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr),240px,220px,220px,220px]">
          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Buscar</label>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Host, IP, tipo ou recomendação..."
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

        <div className="mt-4 grid gap-4 xl:grid-cols-[220px,220px,220px,auto]">
          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Status</label>
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Todos</option>
              <option value="open">Aberto</option>
              <option value="closed">Fechado</option>
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
              <option value="loop_risk">Risco de loop</option>
              <option value="early_warning">Alerta antecipado</option>
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
                setStatusFilter("open");
                setSeverityFilter("");
                setTypeFilter("");
                setWindowFilter("24h");
              }}
              className="rounded-md border border-white/10 bg-slate-950 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-900"
            >
              Limpar filtros
            </button>
          </div>
        </div>
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70">
        {selectedIncident ? (
          <div className="border-b border-white/10 px-6 py-6">
            <div className="flex flex-col gap-6">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-xl font-semibold text-white">{selectedIncident.title}</h2>
                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${severityClassName(selectedIncident.severity)}`}>
                      {severityLabel(selectedIncident.severity)}
                    </span>
                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${statusClassName(selectedIncident.status)}`}>
                      {statusLabel(selectedIncident.status)}
                    </span>
                    <span className="inline-flex rounded-full border border-white/10 bg-slate-950/70 px-2.5 py-1 text-xs font-medium text-slate-200">
                      {incidentTypeLabel(selectedIncident.incident_type)}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-slate-400">
                    {selectedIncident.hostname}
                    {selectedIncident.src_ip ? ` • ${selectedIncident.src_ip}` : ""}
                    {selectedIncident.group_path || selectedIncident.group_name ? ` • ${selectedIncident.group_path || selectedIncident.group_name}` : ""}
                    {selectedIncident.template_name ? ` • ${selectedIncident.template_name}` : ""}
                  </p>
                </div>

                <div className="flex flex-wrap gap-2">
                  {selectedIncident.asset_id ? (
                    <Link
                      to={`/monitoring/hosts/${selectedIncident.asset_id}`}
                      className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-900"
                    >
                      Abrir host
                    </Link>
                  ) : null}
                  <Link
                    to={`/insights?incident_id=${selectedIncident.id}${selectedIncident.asset_id ? `&host_id=${selectedIncident.asset_id}` : ""}`}
                    className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-900"
                  >
                    Abrir assistente
                  </Link>
                </div>
              </div>

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr),minmax(360px,1fr)]">
                <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-5">
                  <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Por que este incidente foi aberto
                  </div>
                  <p className="mt-3 text-sm leading-7 text-slate-200">{selectedOpeningReason}</p>
                  {selectedAffectedContexts.length ? (
                    <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-sm text-slate-300">
                      <span className="font-medium text-white">Contexto afetado:</span>{" "}
                      {compactContextList(selectedAffectedContexts.map(contextLabel), 4)}
                    </div>
                  ) : null}
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <DetailCard
                    label="Severidade"
                    value={severityLabel(selectedIncident.severity)}
                    subtitle={selectedIncident?.details?.score_pct ? `Score ${selectedIncident.details.score_pct}%` : ""}
                  />
                  <DetailCard label="Status" value={statusLabel(selectedIncident.status)} />
                  <DetailCard
                    label="Abertura"
                    value={formatDateTime(selectedIncident.opened_at)}
                    subtitle={selectedIncident?.details?.window_sec ? `Janela de correlação ${selectedIncident.details.window_sec}s` : ""}
                  />
                  <DetailCard
                    label="Último sinal"
                    value={formatDateTime(selectedIncident.last_seen_at)}
                    subtitle="Atualização mais recente do incidente"
                  />
                  <DetailCard label="Tipo do incidente" value={incidentTypeLabel(selectedIncident.incident_type)} />
                  <DetailCard
                    label="Contexto afetado"
                    value={selectedAffectedContexts.length ? compactContextList(selectedAffectedContexts.map(contextLabel), 4) : "Contexto não identificado"}
                    subtitle="Agrupado por contexto operacional"
                  />
                </div>
              </div>

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr),minmax(320px,1fr)]">
                <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-5">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <h3 className="text-sm font-semibold text-white">Evidências resumidas</h3>
                      <p className="mt-1 text-xs text-slate-400">
                        Agrupadas por tipo de sinal e interface ou contexto operacional.
                      </p>
                    </div>
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      {selectedSignalContexts.length} grupo(s)
                    </div>
                  </div>
                  {selectedSignalContexts.length ? (
                    <div className="mt-4 grid gap-3 md:grid-cols-2">
                      {selectedSignalContexts.map((item) => (
                        <SignalSummaryCard key={`${item.signal}-${item.focus}`} item={item} />
                      ))}
                    </div>
                  ) : (
                    <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-sm text-slate-400">
                      Nenhuma evidência estruturada disponível para este incidente.
                    </div>
                  )}
                </div>

                <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-5">
                  <h3 className="text-sm font-semibold text-white">Recomendação operacional</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-300">
                    {selectedIncident?.details?.recommendation || "Sem recomendação operacional estruturada para este incidente."}
                  </p>
                </div>
              </div>

              <AIInsightCard
                title="Explicação do incidente"
                description={`Leitura técnica do incidente ${selectedIncident.title}, com foco em severidade, status, evidências, host e relação com loop_risk quando aplicável.`}
                insight={incidentInsight}
                loading={incidentInsightLoading}
                error={incidentInsightError}
                primaryActionLabel="Gerar explicação"
                onGenerate={() => handleExplainIncident(selectedIncident)}
                onRefresh={() => handleExplainIncident(selectedIncident, true)}
                emptyTitle="Explicação do incidente ainda não gerada"
                emptySubtitle="Gere o insight para apoiar triagem e comunicação técnica deste incidente."
              />
            </div>
          </div>
        ) : null}

        <div className="flex items-center justify-between gap-4 border-b border-white/10 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Fila operacional</h2>
            <p className="mt-1 text-sm text-slate-400">
              Incidentes ordenados por gravidade e recência, com contexto suficiente para agir.
            </p>
          </div>
          <div className="rounded-full border border-white/10 bg-slate-950 px-3 py-1 text-xs uppercase tracking-wide text-slate-400">
            {rows.length} incidente(s)
          </div>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
            <div className="px-6 py-12 text-center text-sm text-slate-400">
              Carregando fila operacional...
            </div>
          ) : rows.length ? (
            <table className="min-w-full text-sm">
              <thead className="bg-slate-950/70 text-left text-slate-300">
                <tr>
                  <th className="px-4 py-3">Severidade</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">Grupo</th>
                  <th className="px-4 py-3">Tipo</th>
                  <th className="px-4 py-3">Abertura</th>
                  <th className="px-4 py-3">Última ocorrência</th>
                  <th className="px-4 py-3 min-w-[420px]">Contexto</th>
                  <th className="px-4 py-3 text-right">Ação</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const rowSignalContexts = buildIncidentSignalContexts(row);
                  const rowAffectedContexts = buildAffectedContexts(row, rowSignalContexts);
                  const selected = selectedIncident?.id === row.id;
                  return (
                  <tr
                    key={row.id}
                    onClick={() => handleSelectIncident(row)}
                    className={`border-t border-white/10 transition cursor-pointer ${
                      selected ? "bg-sky-500/10" : "bg-slate-950/20 hover:bg-slate-900/50"
                    }`}
                  >
                    <td className="px-4 py-3 align-top">
                      <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${severityClassName(row.severity)}`}>
                        {severityLabel(row.severity)}
                      </span>
                    </td>
                    <td className="px-4 py-3 align-top">
                      <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${statusClassName(row.status)}`}>
                        {statusLabel(row.status)}
                      </span>
                    </td>
                    <td className="px-4 py-3 align-top">
                      <div className="font-medium text-white">{row.hostname}</div>
                      <div className="text-xs text-slate-500">{row.src_ip}</div>
                    </td>
                    <td className="px-4 py-3 align-top text-slate-300">{row.group_path || row.group_name || "Sem grupo"}</td>
                    <td className="px-4 py-3 align-top text-slate-300">{incidentTypeLabel(row.incident_type)}</td>
                    <td className="px-4 py-3 align-top text-slate-300">{formatDateTime(row.opened_at)}</td>
                    <td className="px-4 py-3 align-top text-slate-300">{formatDateTime(row.last_seen_at)}</td>
                    <td className="px-4 py-3 align-top text-slate-300">
                      <div className="max-w-[480px]">
                        <div className="font-medium text-slate-100">
                          {buildOpeningReason(row, rowSignalContexts)}
                        </div>
                        {rowAffectedContexts.length ? (
                          <div className="mt-1 text-xs text-slate-500">
                            Contextos: {compactContextList(rowAffectedContexts.map(contextLabel), 3)}
                          </div>
                        ) : null}
                        {rowSignalContexts.length ? (
                          <div className="mt-2 text-xs text-slate-400">
                            {rowSignalContexts.slice(0, 3).map((item) => `${item.label}: ${item.count}`).join(" • ")}
                          </div>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-4 py-3 align-top text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={(event) => {
                            event.stopPropagation();
                            handleExplainIncident(row);
                          }}
                          className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-900"
                        >
                          Explicar
                        </button>
                        {row.asset_id ? (
                          <Link
                            to={`/monitoring/hosts/${row.asset_id}`}
                            onClick={(event) => event.stopPropagation()}
                            className="rounded-md bg-sky-500 px-3 py-2 text-xs font-medium text-white hover:bg-sky-600"
                          >
                            Abrir host
                          </Link>
                        ) : (
                          <span className="text-xs text-slate-500">Host legado</span>
                        )}
                      </div>
                    </td>
                  </tr>
                )})}
              </tbody>
            </table>
          ) : (
            <div className="px-6 py-12 text-center text-sm text-slate-400">
              Nenhum incidente encontrado para este filtro.
            </div>
          )}
        </div>
      </section>
    </AppShell>
  );
}

