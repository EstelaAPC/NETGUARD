import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppShell from "../components/AppShell";
import GrafanaDashboardCard from "../components/GrafanaDashboardCard";
import { getAlertSummary, listAlertIncidents, listAlertNotifications } from "../services/alerts";
import { getOpsDashboards } from "../services/dashboards";
import { getCapacityEstimate } from "../services/metrics";
import { getOverview } from "../services/overview";
import { listHosts } from "../services/hosts";
import { TIME_RANGE_OPTIONS, resolveTimeRange } from "../monitoringUi";

function StatCard({ title, value, subtitle, tone = "slate" }) {
  const tones = {
    slate: "border-white/10 bg-slate-900/70",
    sky: "border-sky-500/20 bg-sky-500/10",
    emerald: "border-emerald-500/20 bg-emerald-500/10",
    amber: "border-amber-500/20 bg-amber-500/10",
    orange: "border-orange-500/20 bg-orange-500/10",
    red: "border-red-500/20 bg-red-500/10",
  };

  return (
    <div className={`overflow-hidden rounded-2xl border p-5 ${tones[tone] || tones.slate}`}>
      <div className="h-1 w-16 rounded-full bg-white/20" />
      <div className="mt-4 text-xs font-medium uppercase tracking-wide text-slate-500">{title}</div>
      <div className="mt-2 text-3xl font-semibold text-white">{value}</div>
      {subtitle ? <div className="mt-2 text-sm text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function SectionCard({ eyebrow, title, description, actions, children }) {
  return (
    <section className="overflow-hidden rounded-2xl border border-white/10 bg-slate-900/60">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/10 px-5 py-4">
        <div>
          {eyebrow ? (
            <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{eyebrow}</div>
          ) : null}
          <h2 className="mt-1 text-lg font-semibold text-white">{title}</h2>
          {description ? <p className="mt-1 text-sm text-slate-400">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

function EmptyPanel({ title, subtitle }) {
  return (
    <div className="rounded-xl border border-dashed border-white/10 bg-slate-950/30 px-5 py-8 text-center">
      <div className="text-base font-medium text-white">{title}</div>
      {subtitle ? <p className="mt-2 text-sm text-slate-400">{subtitle}</p> : null}
    </div>
  );
}

function MiniRow({ label, value, tone = "slate" }) {
  const tones = {
    slate: "text-slate-100",
    emerald: "text-emerald-100",
    amber: "text-amber-100",
    orange: "text-orange-100",
    red: "text-red-100",
    sky: "text-sky-100",
  };

  return (
    <div className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
      <div className="text-[11px] uppercase tracking-[0.14em] text-slate-500">{label}</div>
      <div className={`mt-1 text-sm font-semibold ${tones[tone] || tones.slate}`}>{value}</div>
    </div>
  );
}

function formatHostState(value) {
  const state = String(value || "").toLowerCase();
  if (state === "healthy") return "Saudável";
  if (state === "degraded") return "Degradado";
  if (state === "critical") return "Crítico";
  if (state === "unavailable" || state === "down") return "Indisponível";
  if (state === "inactive") return "Inativo";
  if (state === "no_data") return "Sem telemetria";
  return "Sem estado";
}

function healthPriority(value) {
  const state = String(value || "").toLowerCase();
  if (state === "critical" || state === "down") return 3;
  if (state === "degraded") return 2;
  if (state === "healthy") return 1;
  return 0;
}

function formatTime(value) {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString("pt-BR");
  } catch {
    return "-";
  }
}

function normalizeStatus(value) {
  return String(value || "").trim().toLowerCase();
}

function isOpenStatus(value) {
  const status = normalizeStatus(value);
  return status === "open" || status === "acknowledged";
}

function formatStatus(value) {
  const status = normalizeStatus(value);
  if (status === "open") return "Aberto";
  if (status === "acknowledged") return "Reconhecido";
  if (status === "resolved") return "Resolvido";
  if (status === "closed") return "Fechado";
  return value ? String(value) : "Sem status";
}

function formatSeverity(value) {
  const severity = String(value || "").trim().toLowerCase();
  if (severity === "critical") return "Crítica";
  if (severity === "high") return "Alta";
  if (severity === "medium") return "Média";
  if (severity === "low") return "Baixa";
  if (severity === "info" || severity === "informational") return "Informativa";
  return value ? String(value) : "Sem severidade";
}

function formatDuration(start, end) {
  if (!start) return "Duração não informada";
  const startedAt = new Date(start).getTime();
  const endedAt = end ? new Date(end).getTime() : Date.now();
  if (!Number.isFinite(startedAt) || !Number.isFinite(endedAt) || endedAt < startedAt) {
    return "Duração não informada";
  }
  const totalSeconds = Math.floor((endedAt - startedAt) / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes < 60) return `${minutes}min`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes ? `${hours}h ${remainingMinutes}min` : `${hours}h`;
}

function problemLabel(value) {
  const raw = String(value || "Incidente").trim();
  const normalized = raw.toLowerCase();
  const labels = {
    host_down: "Host indisponível",
    icmp_collection_silence: "Sem telemetria ICMP recente",
    snmp_collection_silence: "Sem telemetria SNMP recente",
    loop_risk: "Risco de loop L2",
    interface_down: "Interface indisponível",
    link_flap: "Oscilação de link",
    mac_flapping: "MAC flapping",
    broadcast_storm: "Broadcast storm",
  };
  if (labels[normalized]) return labels[normalized];
  if (normalized.startsWith("syslog_loop_")) return `Evento de loop ${raw.replace(/^syslog_loop_/i, "").replaceAll("_", "/")}`;
  if (normalized.startsWith("syslog_interface_flap_")) {
    return `Oscilação de interface ${raw.replace(/^syslog_interface_flap_/i, "").replaceAll("_", "/")}`;
  }
  return raw
    .replaceAll("_", " ")
    .replace(/\s+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function notificationStatusLabel(value) {
  const status = String(value || "").trim().toLowerCase();
  if (status === "success" || status === "sent" || status === "enviado") return "Enviado";
  if (status === "suppressed" || status === "suprimido") return "Suprimido";
  if (status === "failed" || status === "error" || status === "erro") return "Falha";
  if (status === "pending") return "Pendente";
  return value ? String(value) : "Status não informado";
}

export default function Dashboard() {
  const [overview, setOverview] = useState(null);
  const [alertSummary, setAlertSummary] = useState(null);
  const [dashboards, setDashboards] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [capacity, setCapacity] = useState(null);
  const [windowFilter, setWindowFilter] = useState("24h");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const range = useMemo(() => resolveTimeRange(windowFilter), [windowFilter]);

  async function loadData(mode = "initial") {
    try {
      if (mode === "initial") {
        setLoading(true);
      } else {
        setRefreshing(true);
      }

      setError("");
      const [overviewData, dashboardData, alertData, hostData, incidentData, notificationData, capacityData] = await Promise.all([
        getOverview().catch(() => null),
        getOpsDashboards({ from: range.from, to: range.to }).catch(() => []),
        getAlertSummary().catch(() => null),
        listHosts({ limit: 20 }).catch(() => []),
        listAlertIncidents({ limit: 10 }).catch(() => []),
        listAlertNotifications({ limit: 6 }).catch(() => []),
        getCapacityEstimate().catch(() => null),
      ]);

      setOverview(overviewData);
      setDashboards(Array.isArray(dashboardData) ? dashboardData : []);
      setAlertSummary(alertData);
      setHosts(Array.isArray(hostData) ? hostData : []);
      setIncidents(Array.isArray(incidentData) ? incidentData : []);
      setNotifications(Array.isArray(notificationData) ? notificationData : []);
      setCapacity(capacityData);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar a visão geral");
      setDashboards([]);
      setAlertSummary(null);
      setOverview(null);
      setHosts([]);
      setIncidents([]);
      setNotifications([]);
      setCapacity(null);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadData("initial");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range.from, range.to]);

  const avgRtt = useMemo(() => {
    const values = (overview?.hosts || [])
      .map((host) => Number(host.last_rtt_ms))
      .filter((value) => !Number.isNaN(value));

    if (!values.length) return "-";
    return `${(values.reduce((total, value) => total + value, 0) / values.length).toFixed(2)} ms`;
  }, [overview]);

  const avgLoss = useMemo(() => {
    const values = (overview?.hosts || [])
      .map((host) => Number(host.last_loss_pct))
      .filter((value) => !Number.isNaN(value));

    if (!values.length) return "-";
    return `${(values.reduce((total, value) => total + value, 0) / values.length).toFixed(2)} %`;
  }, [overview]);

  const formatBytes = (value) => {
    const bytes = Number(value || 0);
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / 1024 ** power).toFixed(power === 0 ? 0 : 2)} ${units[power]}`;
  };

  const hostRows = useMemo(() => {
    const rows = Array.isArray(hosts) ? hosts : [];
    return rows
      .slice()
      .sort((a, b) => {
        const scoreDiff = healthPriority(b.health_status) - healthPriority(a.health_status);
        if (scoreDiff !== 0) return scoreDiff;
        return Number(b.open_incidents || 0) - Number(a.open_incidents || 0);
      });
  }, [hosts]);

  const healthCounts = useMemo(() => {
    const counts = {
      healthy: 0,
      degraded: 0,
      critical: 0,
      unavailable: 0,
      inactive: 0,
    };

    hostRows.forEach((host) => {
      const state = String(host?.health_status || "").toLowerCase();
      if (state === "healthy") counts.healthy += 1;
      else if (state === "degraded") counts.degraded += 1;
      else if (state === "critical") counts.critical += 1;
      else if (state === "unavailable" || state === "down") counts.unavailable += 1;
      else if (!host?.enabled) counts.inactive += 1;
    });

    return counts;
  }, [hostRows]);

  const topProblemRows = useMemo(() => {
    const buckets = new Map();
    (Array.isArray(incidents) ? incidents : []).forEach((incident) => {
      const label = incident.problem_type || incident.incident_type || incident.title || "Incidente";
      const key = String(label).toLowerCase();
      const current =
        buckets.get(key) ||
        {
          label,
          count: 0,
          severity: incident.severity || null,
          updatedAt: incident.updated_at || incident.last_detected_at || null,
        };
      current.count += 1;
      if (!current.severity && incident.severity) current.severity = incident.severity;
      if (!current.updatedAt || (incident.updated_at && incident.updated_at > current.updatedAt)) {
        current.updatedAt = incident.updated_at || incident.last_detected_at;
      }
      buckets.set(key, current);
    });

    return Array.from(buckets.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [incidents]);

  const spotlightHost = hostRows[0] || null;
  const recentEvent = alertSummary?.last_alert || incidents[0] || null;
  const openedIncidents = Array.isArray(incidents)
    ? incidents.filter((incident) => isOpenStatus(incident?.status))
    : [];
  const criticalOpenIncidents = openedIncidents.filter((incident) =>
    String(incident?.severity || "").toLowerCase() === "critical"
  );
  const loopRiskIncidents = openedIncidents.filter((incident) => {
    const text = `${incident?.problem_type || ""} ${incident?.incident_type || ""} ${incident?.title || ""}`.toLowerCase();
    return text.includes("loop");
  });
  const snmpFailureIncidents = openedIncidents.filter((incident) => {
    const text = `${incident?.problem_type || ""} ${incident?.incident_type || ""} ${incident?.title || ""}`.toLowerCase();
    return text.includes("snmp") && (text.includes("silence") || text.includes("falha") || text.includes("collection"));
  });
  const riskyLoopHosts = hostRows.filter((host) => Number(host?.loop_risk_score || 0) >= 0.5);
  const loopRiskCount = Math.max(loopRiskIncidents.length, riskyLoopHosts.length);
  const recentNotifications = Array.isArray(notifications) ? notifications.slice(0, 4) : [];
  const capacityScenarios = Array.isArray(capacity?.scenarios) ? capacity.scenarios : [];
  const capacityComponents = capacity?.estimated_components || {};
  const hasCapacityEstimate = Boolean(
    capacity &&
      (capacity.total_hosts ||
        capacity.total_items ||
        capacity.estimated_storage_per_day_bytes ||
        capacity.estimated_storage_per_month_bytes ||
        capacity.estimated_storage_for_retention_bytes ||
        capacityScenarios.length)
  );
  const activeProtocols = Array.from(
    new Set(
      hostRows.flatMap((host) => {
        const protocols = host?.protocols_enabled || host?.protocols || [];
        if (Array.isArray(protocols)) return protocols;
        if (protocols && typeof protocols === "object") {
          return Object.entries(protocols)
            .filter(([, enabled]) => Boolean(enabled))
            .map(([protocol]) => protocol);
        }
        return [];
      })
    )
  )
    .map((protocol) => String(protocol).toUpperCase())
    .sort();

  return (
    <AppShell
      title="Visão geral"
      description="Painel operacional principal do NetGuard com Grafana integrado ao fluxo de monitoramento."
      actions={
        <>
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-[0.14em] text-slate-500">Janela</label>
            <select
              value={windowFilter}
              onChange={(event) => setWindowFilter(event.target.value)}
              className="rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-400"
            >
              {TIME_RANGE_OPTIONS.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          <Link
            to="/monitoring/hosts"
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Hosts monitorados
          </Link>
          <Link
            to="/monitoring/incidents"
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Incidentes
          </Link>
          <Link
            to="/monitoring/alerts"
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Alertas
          </Link>
          <button
            type="button"
            onClick={() => loadData("refresh")}
            disabled={loading || refreshing}
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
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

      <section className="overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950">
        <div className="grid gap-6 px-6 py-6 xl:grid-cols-[1.2fr,0.8fr] xl:items-stretch">
          <div className="flex h-full flex-col justify-between">
            <div>
              <div className="text-[11px] uppercase tracking-[0.22em] text-sky-300/80">Visão NOC</div>
              <h2 className="mt-2 text-2xl font-semibold text-white">Leitura operacional do ambiente em tempo real</h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
                Saúde geral, incidentes, risco de loop, notificações e host em foco em um único painel de abertura.
              </p>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              <Link
                to="/monitoring/hosts"
                className="rounded-md border border-white/10 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 hover:bg-slate-900"
              >
                Ver hosts
              </Link>
              <Link
                to="/monitoring/incidents"
                className="rounded-md border border-white/10 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 hover:bg-slate-900"
              >
                Ver incidentes
              </Link>
              <Link
                to="/monitoring/alerts"
                className="rounded-md border border-white/10 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 hover:bg-slate-900"
              >
                Ver alertas
              </Link>
            </div>

            <div className="mt-6 grid gap-3 md:grid-cols-3">
              <MiniRow
                label="Saúde"
                value={`${healthCounts.healthy} saudáveis | ${healthCounts.degraded} degradados | ${healthCounts.critical} críticos`}
                tone="emerald"
              />
              <MiniRow
                label="Incidentes"
                value={`${alertSummary?.open_alerts ?? openedIncidents.length} abertos`}
                tone="orange"
              />
              <MiniRow
                label="Sinal dominante"
                value={loopRiskCount ? "Risco de loop sob atenção" : "Sem risco de loop no recorte atual"}
                tone={loopRiskCount ? "red" : "sky"}
              />
            </div>
          </div>

          <div className="grid gap-3">
            <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-4">
              <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">Host em foco</div>
              <div className="mt-2 text-lg font-semibold text-white">{spotlightHost?.name || "Sem host em destaque"}</div>
              <div className="mt-1 text-sm text-slate-400">{spotlightHost?.ip || "Aguardando dados operacionais"}</div>
              <div className="mt-3 flex flex-wrap gap-2">
                <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs text-slate-200">
                  {spotlightHost ? formatHostState(spotlightHost.health_status) : "Sem estado"}
                </span>
                <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs text-slate-200">
                  {spotlightHost ? `${Number(spotlightHost.open_incidents || 0)} incidente(s)` : "Sem incidentes"}
                </span>
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <MiniRow
                label="Último evento"
                value={
                  recentEvent
                    ? problemLabel(recentEvent.problem_type || recentEvent.incident_type || recentEvent.title || recentEvent.device_name)
                    : "Sem eventos recentes"
                }
                tone="sky"
              />
              <MiniRow
                label="Última notificação"
                value={recentNotifications.length ? notificationStatusLabel(recentNotifications[0].delivery_status) : "Sem histórico recente"}
                tone="amber"
              />
            </div>

            <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-4">
              <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">Host prioritário</div>
              <div className="mt-2 text-sm text-slate-300">
                {spotlightHost?.health_reason || "Nenhuma justificativa detalhada exposta para este recorte."}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <StatCard title="Hosts totais" value={overview?.total_hosts ?? hostRows.length} subtitle="Inventário operacional atual." tone="sky" />
        <StatCard title="Saudáveis" value={healthCounts.healthy} subtitle="Hosts com telemetria em ordem." tone="emerald" />
        <StatCard title="Degradados" value={healthCounts.degraded} subtitle="Hosts que merecem atenção." tone="amber" />
        <StatCard title="Críticos" value={healthCounts.critical} subtitle="Hosts com risco operacional alto." tone="red" />
        <StatCard title="Indisponíveis" value={healthCounts.unavailable} subtitle="Hosts sem disponibilidade recente." tone="red" />
      </section>

      <div className="mt-5 text-[11px] uppercase tracking-[0.18em] text-slate-500">Sinais operacionais</div>
      <section className="mt-3 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <StatCard
          title="Incidentes abertos"
          value={alertSummary?.open_alerts ?? openedIncidents.length}
          subtitle={`${alertSummary?.critical_open_alerts ?? criticalOpenIncidents.length} críticos | ${alertSummary?.notifications_suppressed_today ?? 0} anti-spam`}
          tone="orange"
        />
        <StatCard
          title="Risco de loop"
          value={loopRiskCount}
          subtitle={loopRiskCount ? "Hosts ou incidentes com risco de loop." : "Sem risco ativo nos dados atuais."}
          tone={loopRiskCount ? "red" : "emerald"}
        />
        <StatCard
          title="SNMP com falha"
          value={snmpFailureIncidents.length}
          subtitle={snmpFailureIncidents.length ? "Incidentes SNMP ativos." : "Sem incidente SNMP ativo."}
          tone={snmpFailureIncidents.length ? "amber" : "emerald"}
        />
        <StatCard
          title="Syslog recebido"
          value={alertSummary?.syslog_events_today ?? "-"}
          subtitle="Contagem diária quando a API expõe esse dado."
        />
        <StatCard
          title="Notificações"
          value={alertSummary?.notifications_sent_today ?? 0}
          subtitle={`${alertSummary?.active_channels ?? 0} canal(is) ativo(s)`}
          tone="sky"
        />
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-2">
        <SectionCard
          eyebrow="Visão NOC"
          title="Saúde operacional e problemas mais quentes"
          description="Resumo compacto para leitura de sala NOC e abertura da apresentação."
          actions={
            <>
              <Link
                to="/monitoring/hosts"
                className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
              >
                Ver hosts
              </Link>
              <Link
                to="/monitoring/incidents"
                className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
              >
                Ver incidentes
              </Link>
            </>
          }
        >
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <MiniRow label="Incidentes críticos" value={alertSummary?.critical_open_alerts ?? criticalOpenIncidents.length} tone="red" />
            <MiniRow label="Risco de loop" value={loopRiskCount || "Sem alerta"} tone={loopRiskCount ? "red" : "emerald"} />
            <MiniRow label="SNMP com falha" value={snmpFailureIncidents.length || "Sem alerta"} tone={snmpFailureIncidents.length ? "amber" : "emerald"} />
            <MiniRow
              label="Último evento"
              value={
                recentEvent
                  ? problemLabel(recentEvent.problem_type || recentEvent.incident_type || recentEvent.title || recentEvent.device_name)
                  : "Sem eventos recentes"
              }
              tone="sky"
            />
          </div>

          <div className="mt-5 grid gap-4 xl:grid-cols-[1.1fr,0.9fr,0.9fr]">
            <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
              <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Top problemas</div>
              <div className="mt-3 space-y-3">
                {topProblemRows.length ? (
                  topProblemRows.map((problem) => (
                    <div key={problem.label} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-slate-950/40 px-3 py-2">
                      <div>
                        <div className="text-sm font-medium text-white">{problemLabel(problem.label)}</div>
                        <div className="text-xs text-slate-400">
                          {problem.severity ? `Severidade ${formatSeverity(problem.severity)}` : "Sem severidade"}
                          {problem.updatedAt ? ` • atualizado em ${formatTime(problem.updatedAt)}` : ""}
                        </div>
                      </div>
                      <div className="rounded-full border border-white/10 bg-slate-900 px-3 py-1 text-sm font-semibold text-slate-100">
                        {problem.count}
                      </div>
                    </div>
                  ))
                ) : (
                  <EmptyPanel
                    title="Sem problemas consolidados"
                    subtitle="Os principais problemas aparecerão aqui quando houver incidentes ou eventos relevantes."
                  />
                )}
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
              <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Últimos eventos</div>
              <div className="mt-3 space-y-3">
                {recentEvent ? (
                  <div className="rounded-lg border border-white/10 bg-slate-950/40 px-3 py-3">
                    <div className="text-sm font-medium text-white">
                      {recentEvent.device_name || recentEvent.hostname || recentEvent.title || "Evento recente"}
                    </div>
                    <div className="mt-1 text-xs text-slate-400">
                      {problemLabel(recentEvent.problem_type || recentEvent.incident_type || recentEvent.source || "Sinal")}
                      {recentEvent.updated_at || recentEvent.last_detected_at ? ` • ${formatTime(recentEvent.updated_at || recentEvent.last_detected_at)}` : ""}
                    </div>
                    <div className="mt-2 text-sm text-slate-300">
                      {recentEvent.summary || recentEvent.message || recentEvent.title || "Sem descrição adicional."}
                    </div>
                  </div>
                ) : (
                  <EmptyPanel
                    title="Sem eventos recentes"
                    subtitle="A linha do tempo ficará preenchida conforme chegarem alertas, incidentes e notificações."
                  />
                )}
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
              <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Últimas notificações</div>
              <div className="mt-3 space-y-3">
                {recentNotifications.length ? (
                  recentNotifications.map((notification) => (
                    <div key={notification.id || `${notification.created_at}-${notification.channel}`} className="rounded-lg border border-white/10 bg-slate-950/40 px-3 py-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="text-sm font-medium text-white">
                          {notification.channel || notification.provider || "Canal"}
                        </div>
                        <span className="rounded-full border border-white/10 bg-slate-900 px-2 py-0.5 text-[11px] uppercase tracking-wide text-slate-300">
                          {notificationStatusLabel(notification.delivery_status)}
                        </span>
                      </div>
                      <div className="mt-1 text-xs text-slate-400">
                        {formatTime(notification.created_at || notification.sent_at || notification.updated_at)}
                      </div>
                      <div className="mt-2 line-clamp-2 text-sm text-slate-300">
                        {notification.error_message || notification.subject || notification.message || "Notificação registrada."}
                      </div>
                    </div>
                  ))
                ) : (
                  <EmptyPanel
                    title="Nenhuma notificação recente"
                    subtitle="Envios e falhas aparecerão aqui quando houver histórico disponível."
                  />
                )}
              </div>
            </div>
          </div>
        </SectionCard>

        <SectionCard
          eyebrow="Visão por host"
          title="Host em foco"
          description="Resumo visual do ativo mais relevante no momento, com saúde, telemetria e incidentes."
          actions={
            <Link
              to="/monitoring/hosts"
              className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
            >
              Abrir lista
            </Link>
          }
        >
          {spotlightHost ? (
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <MiniRow label="Host" value={spotlightHost.name || "-"} tone="sky" />
                <MiniRow label="IP" value={spotlightHost.ip || "-"} />
                <MiniRow
                  label="Saúde"
                  value={formatHostState(spotlightHost.health_status)}
                  tone={
                    String(spotlightHost.health_status || "").toLowerCase() === "healthy"
                      ? "emerald"
                      : String(spotlightHost.health_status || "").toLowerCase() === "degraded"
                        ? "amber"
                        : "red"
                  }
                />
                <MiniRow label="Incidentes" value={Number(spotlightHost.open_incidents || 0)} tone="orange" />
                <MiniRow label="Última coleta" value={spotlightHost.last_collection_at ? formatTime(spotlightHost.last_collection_at) : "-"} />
                <MiniRow
                  label="Loop risk"
                  value={
                    spotlightHost.loop_risk_score !== null && spotlightHost.loop_risk_score !== undefined
                      ? `${Math.round(Number(spotlightHost.loop_risk_score) * 100)}%`
                      : "Sem score"
                  }
                  tone="amber"
                />
              </div>
              <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Contexto do host</div>
                <div className="mt-2 text-sm text-slate-300">
                  {spotlightHost.health_reason || "Sem justificativa adicional exposta nesta visão."}
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Link
                    to={`/monitoring/hosts/${spotlightHost.id}`}
                    className="rounded-md bg-sky-500 px-3 py-2 text-sm font-medium text-white hover:bg-sky-600"
                  >
                    Ver detalhe
                  </Link>
                  <Link
                    to={`/monitoring/hosts/${spotlightHost.id}?tab=visualization`}
                    className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
                  >
                    Visualização
                  </Link>
                </div>
              </div>
            </div>
          ) : (
            <EmptyPanel
              title="Sem host em destaque"
              subtitle="Quando houver ativos carregados, este bloco passa a mostrar saúde, telemetria e incidentes do host mais relevante."
            />
          )}
        </SectionCard>

        <SectionCard
          eyebrow="Visão de incidentes"
          title="Linha do tempo e recuperação"
          description="Incidentes abertos, último evento e progresso de notificação em leitura rápida."
          actions={
            <Link
              to="/monitoring/incidents"
              className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
            >
              Abrir incidentes
            </Link>
          }
        >
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <MiniRow label="Incidentes abertos" value={alertSummary?.open_alerts ?? openedIncidents.length} tone="orange" />
            <MiniRow label="Críticos abertos" value={alertSummary?.critical_open_alerts ?? criticalOpenIncidents.length} tone="red" />
            <MiniRow label="Notificações enviadas hoje" value={alertSummary?.notifications_sent_today ?? 0} tone="emerald" />
            <MiniRow
              label="Recuperação"
              value={
                Array.isArray(incidents) &&
                incidents.some((incident) => {
                  const status = String(incident?.status || "").toLowerCase();
                  return status === "resolved" || status === "closed";
                })
                  ? "Há incidentes recuperados"
                  : "Sem recuperação recente"
              }
            />
          </div>

          <div className="mt-5 space-y-3">
            {openedIncidents.length ? (
              openedIncidents.slice(0, 4).map((incident) => (
                <div key={incident.id} className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-100">
                          {incident.device_name || incident.hostname || incident.host_name || "Host não identificado"}
                        </span>
                        <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-100">
                          {problemLabel(incident.problem_type || incident.incident_type)}
                        </span>
                        <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-100">
                          {formatSeverity(incident.severity)}
                        </span>
                        <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-100">
                          {formatStatus(incident.status)}
                        </span>
                      </div>
                      <div className="mt-2 text-sm text-slate-300">
                        {incident.title || incident.summary || "Incidente em andamento."}
                      </div>
                      <div className="mt-2 text-xs text-slate-500">
                        Duração: {formatDuration(incident.opened_at || incident.first_detected_at, incident.resolved_at)}
                        {" | "}
                        Recuperação: {incident.resolved_at ? formatTime(incident.resolved_at) : "não registrada"}
                      </div>
                    </div>
                    <Link
                      to={`/monitoring/alerts?incident_id=${incident.id}`}
                      className="shrink-0 rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800"
                    >
                      Abrir detalhe
                    </Link>
                  </div>
                </div>
              ))
            ) : (
              <EmptyPanel
                title="Sem incidentes abertos"
                subtitle="Quando houver problemas ativos, a timeline operacional aparece aqui com a recuperação mais recente."
              />
            )}
          </div>
        </SectionCard>

        <SectionCard
          eyebrow="Visão de capacidade"
          title="Cobertura e volume operacional"
          description="Leitura de porte do ambiente usando inventário, telemetria, retenção e cálculo estimado de disco."
          actions={
            <Link
              to="/monitoring/hosts"
              className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
            >
              Ver inventário
            </Link>
          }
        >
          {hasCapacityEstimate ? (
            <>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <MiniRow label="Hosts monitorados" value={capacity?.total_hosts ?? overview?.total_hosts ?? "-"} tone="sky" />
                <MiniRow label="Itens monitorados" value={capacity?.total_items ?? 0} tone="emerald" />
                <MiniRow label="Protocolos ativos" value={activeProtocols.length ? activeProtocols.join(", ") : "Sem dados recentes"} />
                <MiniRow label="Intervalo médio" value={capacity?.avg_collection_interval_sec ? `${Number(capacity.avg_collection_interval_sec).toFixed(0)} s` : "Sem dados recentes"} tone="amber" />
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <MiniRow label="Estimativa por dia" value={formatBytes(capacity?.estimated_storage_per_day_bytes)} tone="sky" />
                <MiniRow label="Estimativa por mês" value={formatBytes(capacity?.estimated_storage_per_month_bytes)} tone="emerald" />
                <MiniRow label="Retenção estimada" value={formatBytes(capacity?.estimated_storage_for_retention_bytes)} tone="orange" />
                <MiniRow label="Disco recomendado" value={formatBytes(capacity?.recommended_disk_bytes)} tone="red" />
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <MiniRow label="Retenção de métricas" value={`${capacity?.avg_history_retention_days || 30} dias`} />
                <MiniRow label="Trend / logs" value={`${capacity?.avg_trend_retention_days || 90}d | ${capacity?.avg_log_retention_days || 14}d`} />
                <MiniRow
                  label="Incidentes / notificações / auditoria"
                  value={`${capacity?.avg_incident_retention_days || 180}d | ${capacity?.avg_notification_retention_days || 90}d | ${capacity?.avg_audit_retention_days || 365}d`}
                />
              </div>
              <div className="mt-4 grid gap-4 xl:grid-cols-[1.1fr,0.9fr]">
                <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                  <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Fórmula da estimativa</div>
                  <div className="mt-3 text-sm leading-6 text-slate-300">
                    {capacity?.formula || "Estimativa indisponível."}
                  </div>
                  <div className="mt-3 text-xs text-slate-500">
                    Esta seção mostra apenas uma estimativa técnica. O NetGuard não executa expurgo automático destrutivo nesta etapa.
                  </div>
                </div>

                <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                  <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Premissas adotadas</div>
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <MiniRow label="Bytes por amostra" value={`${capacity?.avg_sample_bytes || 256} B`} />
                    <MiniRow label="Fator de trends" value={String(capacity?.assumptions?.trend_ratio || 0.12)} />
                    <MiniRow label="Syslog por host/dia" value={`${capacity?.assumptions?.syslog_events_per_host_per_day || 0}`} />
                    <MiniRow label="Segurança de disco" value={`${capacity?.assumptions?.safety_factor || 1.25}x`} />
                  </div>
                </div>
              </div>
              <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/30 p-4">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Componentes estimados por dia</div>
                <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                  <MiniRow label="Métricas brutas" value={formatBytes(capacityComponents.raw_metrics_per_day_bytes)} tone="sky" />
                  <MiniRow label="Trends / agregados" value={formatBytes(capacityComponents.trend_metrics_per_day_bytes)} tone="emerald" />
                  <MiniRow label="Syslog / logs" value={formatBytes(capacityComponents.syslog_per_day_bytes)} tone="amber" />
                  <MiniRow label="Incidentes" value={formatBytes(capacityComponents.incidents_per_day_bytes)} tone="orange" />
                  <MiniRow label="Notificações" value={formatBytes(capacityComponents.notifications_per_day_bytes)} tone="sky" />
                  <MiniRow label="Auditoria" value={formatBytes(capacityComponents.audit_per_day_bytes)} tone="red" />
                </div>
              </div>
              {capacityScenarios.length ? (
                <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/30 p-4">
                  <div className="text-xs uppercase tracking-[0.16em] text-slate-500">Faixas de referência</div>
                  <div className="mt-3 grid gap-3 xl:grid-cols-4">
                    {capacityScenarios.map((scenario) => (
                      <div key={scenario.hosts} className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                        <div className="text-sm font-semibold text-white">{scenario.hosts} hosts</div>
                        <div className="mt-1 text-xs text-slate-400">{scenario.label || "Estimativa de porte"}</div>
                        <div className="mt-3 space-y-2 text-sm text-slate-300">
                          <div>Itens estimados: {scenario.estimated_items}</div>
                          <div>CPU mínima: {scenario.recommended_vcpu} vCPU</div>
                          <div>RAM mínima: {scenario.recommended_ram_gb} GB</div>
                          <div>Disco recomendado: {formatBytes(scenario.recommended_disk_bytes)}</div>
                          <div>Retenção estimada: {formatBytes(scenario.estimated_storage_for_retention_bytes)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          ) : (
            <EmptyPanel
              title="Dados insuficientes para estimativa"
              subtitle="A estimativa de capacidade aparecerá quando a API consolidar hosts, itens monitorados, intervalos e retenção."
            />
          )}
        </SectionCard>
      </section>

      <section className="mt-6 space-y-6">
        {loading ? (
          <div className="rounded-2xl border border-white/10 bg-slate-900/70 px-6 py-14 text-center text-sm text-slate-400">
            Carregando dashboards operacionais...
          </div>
        ) : dashboards.length ? (
          dashboards.map((dashboard) => (
            <GrafanaDashboardCard
              key={`${dashboard.owner_type}-${dashboard.dashboard_key}`}
              dashboard={dashboard}
            />
          ))
        ) : (
          <div className="rounded-2xl border border-dashed border-white/10 bg-slate-900/60 px-6 py-14 text-center">
            <div className="text-lg font-medium text-white">Nenhum dashboard operacional disponível</div>
            <p className="mt-2 text-sm text-slate-400">
              Verifique se o Grafana foi provisionado e se o endpoint `/dashboards/ops` está respondendo.
            </p>
          </div>
        )}
      </section>
    </AppShell>
  );
}
