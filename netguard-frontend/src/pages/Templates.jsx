import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppShell from "../components/AppShell";
import { getTemplateDashboards } from "../services/dashboards";
import { listHosts, listTemplates, updateTemplateCollectionPolicy } from "../services/hosts";
import { formatDateTime } from "../monitoringUi";

const CAPABILITY_LABELS = {
  icmp: "ICMP",
  snmp: "SNMP",
  discovery: "Discovery",
  syslog: "Syslog",
  correlation: "Correlação",
  loop_risk: "loop_risk",
};

const DEVICE_MONITORING_MATRIX = {
  switch: {
    title: "Switches Cisco / Aruba / Dell / HPE",
    items: [
      "CPU",
      "Memória",
      "Temperatura",
      "Fan",
      "Fonte de alimentação",
      "Falha PoE",
      "Interface down",
      "Link flap",
      "CRC/erros",
      "Descartes",
      "Broadcast storm",
      "MAC flapping",
      "STP topology change",
      "Risco de loop",
    ],
  },
  linux: {
    title: "Linux Host",
    items: ["CPU", "Memória", "Disco", "Uso de filesystem", "Serviço TCP", "Latência", "Perda de pacotes"],
  },
};

function TemplateStatCard({ label, value, tone = "slate", subtitle }) {
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

function capabilityEntries(template) {
  const capabilities = template?.capabilities || {};
  return Object.entries(CAPABILITY_LABELS).filter(([key]) => capabilities[key]);
}

function previewItems(template, key) {
  const value = template?.preview?.[key];
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function metadataLabel(template) {
  return [template?.vendor, template?.family, template?.asset_type].filter(Boolean).join(" / ");
}

function monitoringMatrixForTemplate(template) {
  const assetType = String(template?.asset_type || "").toLowerCase();
  const family = String(template?.family || "").toLowerCase();
  const vendor = String(template?.vendor || "").toLowerCase();

  if (assetType.includes("switch") || family.includes("switch") || /cisco|aruba|dell|hpe/.test(vendor)) {
    return DEVICE_MONITORING_MATRIX.switch;
  }

  if (assetType.includes("linux") || family.includes("linux")) {
    return DEVICE_MONITORING_MATRIX.linux;
  }

  return null;
}

function statusBadge(template) {
  return template?.enabled
    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
    : "border-amber-500/30 bg-amber-500/10 text-amber-100";
}

function normalizeCollectionPolicy(policy) {
  return {
    icmp_interval_sec: String(policy?.icmp_interval_sec ?? 30),
    snmp_interval_sec: String(policy?.snmp_interval_sec ?? 30),
    tcp_interval_sec: String(policy?.tcp_interval_sec ?? 60),
    timeout_sec: String(policy?.timeout_sec ?? 1),
    retries: String(policy?.retries ?? 1),
    history_retention_days: String(policy?.history_retention_days ?? 30),
    trend_retention_days: String(policy?.trend_retention_days ?? 90),
    log_retention_days: String(policy?.log_retention_days ?? 14),
    incident_retention_days: String(policy?.incident_retention_days ?? 180),
    notification_retention_days: String(policy?.notification_retention_days ?? 90),
    audit_retention_days: String(policy?.audit_retention_days ?? 365),
  };
}

function collectionPolicySummary(policy) {
  return `ICMP ${policy?.icmp_interval_sec || "-"}s | SNMP ${policy?.snmp_interval_sec || "-"}s | timeout ${
    policy?.timeout_sec || "-"
  }s | tentativas ${policy?.retries || "-"} | historico ${policy?.history_retention_days || "-"}d | trends ${
    policy?.trend_retention_days || "-"
  }d | syslog ${policy?.log_retention_days || "-"}d | incidentes ${policy?.incident_retention_days || "-"}d | notificacoes ${
    policy?.notification_retention_days || "-"
  }d | auditoria ${policy?.audit_retention_days || "-"}d`;
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

function buildTemplateUsage(hosts) {
  return hosts.reduce((acc, host) => {
    if (!host.template_id) return acc;

    const key = String(host.template_id);
    const current = acc[key] || {
      total: 0,
      enabled: 0,
      openIncidents: 0,
      criticalHosts: 0,
      lastActivityAt: "",
      hosts: [],
    };

    current.total += 1;
    current.enabled += host.enabled !== false ? 1 : 0;
    current.openIncidents += Number(host.open_incidents || 0);
    current.criticalHosts += severityWeight(host.max_incident_severity) >= 5 ? 1 : 0;
    current.hosts.push(host);

    if (host.last_activity_at && String(host.last_activity_at) > String(current.lastActivityAt || "")) {
      current.lastActivityAt = host.last_activity_at;
    }

    acc[key] = current;
    return acc;
  }, {});
}

function PreviewBlock({ title, items, emptyLabel }) {
  return (
    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{title}</div>
      <div className="mt-3 space-y-2">
        {items.length ? (
          items.map((item) => (
            <div key={`${title}-${item}`} className="text-sm leading-6 text-slate-200">
              {item}
            </div>
          ))
        ) : (
          <div className="text-sm text-slate-400">{emptyLabel}</div>
        )}
      </div>
    </div>
  );
}

export default function Templates() {
  const [templates, setTemplates] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [query, setQuery] = useState("");
  const [templateFilter, setTemplateFilter] = useState("all");
  const [templateDashboards, setTemplateDashboards] = useState({});
  const [policyDrafts, setPolicyDrafts] = useState({});
  const [savingTemplateId, setSavingTemplateId] = useState(null);

  useEffect(() => {
    let mounted = true;

    async function load() {
      try {
        setLoading(true);
        setError("");
        setSuccess("");
        const [data, hostData] = await Promise.all([
          listTemplates(),
          listHosts({ limit: 1000 }).catch(() => []),
        ]);
        if (!mounted) return;
        setTemplates(Array.isArray(data) ? data : []);
        setHosts(Array.isArray(hostData) ? hostData : []);
        setPolicyDrafts(
          Object.fromEntries(
            (Array.isArray(data) ? data : []).map((template) => [
              template.id,
              normalizeCollectionPolicy(template.collection_policy),
            ])
          )
        );
      } catch (loadError) {
        if (!mounted) return;
        setError(loadError?.message || "Falha ao carregar templates");
        setTemplates([]);
        setHosts([]);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    load();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!templates.length) {
      setTemplateDashboards({});
      return;
    }

    let mounted = true;

    async function loadDashboardSuggestions() {
      const entries = await Promise.all(
        templates.map(async (template) => {
          try {
            const dashboards = await getTemplateDashboards(template.id);
            return [template.id, Array.isArray(dashboards) ? dashboards : []];
          } catch {
            return [template.id, []];
          }
        })
      );

      if (!mounted) return;
      setTemplateDashboards(Object.fromEntries(entries));
    }

    loadDashboardSuggestions();
    return () => {
      mounted = false;
    };
  }, [templates]);

  const usageByTemplate = useMemo(() => buildTemplateUsage(hosts), [hosts]);

  const filteredTemplates = useMemo(() => {
    const normalized = query.trim().toLowerCase();

    return templates.filter((template) => {
      const usage = usageByTemplate[String(template.id)] || {};
      const inUse = Number(usage.total || 0) > 0;

      if (templateFilter === "active" && template.enabled === false) return false;
      if (templateFilter === "planned" && template.enabled !== false) return false;
      if (templateFilter === "in_use" && !inUse) return false;
      if (templateFilter === "unused" && inUse) return false;
      if (templateFilter === "discovery" && !template?.capabilities?.discovery) return false;
      if (!normalized) return true;

      const haystack = [
        template.name,
        template.asset_type,
        template.vendor,
        template.family,
        template.summary,
        ...(previewItems(template, "monitors") || []),
        ...(previewItems(template, "signals") || []),
        ...(usage.hosts || []).map((host) => host.name),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(normalized);
    });
  }, [query, templateFilter, templates, usageByTemplate]);

  const activeCount = useMemo(
    () => templates.filter((template) => template.enabled !== false).length,
    [templates]
  );

  const plannedCount = useMemo(
    () => templates.filter((template) => template.enabled === false).length,
    [templates]
  );

  const templatesInUse = useMemo(
    () => templates.filter((template) => Number(usageByTemplate[String(template.id)]?.total || 0) > 0).length,
    [templates, usageByTemplate]
  );

  const hostsWithoutTemplate = useMemo(
    () => hosts.filter((host) => !host.template_id).length,
    [hosts]
  );

  async function handlePolicySave(templateId) {
    try {
      setSavingTemplateId(templateId);
      setError("");
      setSuccess("");

      const updated = await updateTemplateCollectionPolicy(templateId, policyDrafts[templateId]);

      setTemplates((current) =>
        current.map((template) => (template.id === templateId ? updated : template))
      );
      setPolicyDrafts((current) => ({
        ...current,
        [templateId]: normalizeCollectionPolicy(updated.collection_policy),
      }));
      setSuccess(`Política de coleta atualizada para ${updated.name}.`);
    } catch (saveError) {
      setError(saveError?.message || "Falha ao salvar política de coleta do template");
    } finally {
      setSavingTemplateId(null);
    }
  }

  return (
    <AppShell
      title="Templates"
      description="Catálogo de templates de monitoramento na área de Coleta de dados. Os templates simplificam o cadastro do host e também sugerem o dashboard operacional mais coerente."
      actions={
        <>
          <Link
            to="/data-collection/hosts"
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Ver hosts
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
        <div className="mb-6 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100">
          {success}
        </div>
      ) : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <TemplateStatCard
          label="Templates no catálogo"
          value={templates.length}
          tone="sky"
          subtitle="Camada de produto acima das políticas de coleta e retenção."
        />
        <TemplateStatCard
          label="Disponíveis agora"
          value={activeCount}
          tone="emerald"
          subtitle="Prontos para uso no editor de hosts."
        />
        <TemplateStatCard
          label="Em preparação"
          value={plannedCount}
          tone="amber"
          subtitle="Visíveis no catálogo, mas ainda não ativos."
        />
        <TemplateStatCard
          label="Templates em uso"
          value={templatesInUse}
          tone="emerald"
          subtitle="Já vinculados a hosts cadastrados."
        />
        <TemplateStatCard
          label="Hosts sem template"
          value={hostsWithoutTemplate}
          tone={hostsWithoutTemplate ? "red" : "slate"}
          subtitle="Pendências de padronização do cadastro."
        />
      </section>

      <section className="mt-6 rounded-2xl border border-white/10 bg-slate-900/70 p-4">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr),260px,auto]">
          <div className="min-w-[280px] flex-1">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Buscar template
            </label>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Nome, tipo, vendor, familia ou capacidade..."
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
          </div>

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Visão
            </label>
            <select
              value={templateFilter}
              onChange={(event) => setTemplateFilter(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="all">Todos</option>
              <option value="active">Disponíveis</option>
              <option value="planned">Planejados</option>
              <option value="in_use">Em uso</option>
              <option value="unused">Sem hosts</option>
              <option value="discovery">Com discovery</option>
            </select>
          </div>

          <div className="flex items-end">
            <div className="rounded-full border border-white/10 bg-slate-950 px-3 py-2 text-xs uppercase tracking-wide text-slate-400">
              {filteredTemplates.length} template(s)
            </div>
          </div>
        </div>
      </section>

      <section className="mt-6">
        {loading ? (
          <div className="rounded-2xl border border-white/10 bg-slate-900/70 px-6 py-14 text-center text-sm text-slate-400">
            Carregando catálogo de templates...
          </div>
        ) : filteredTemplates.length ? (
          <div className="grid gap-6 xl:grid-cols-2">
            {filteredTemplates.map((template) => {
              const capabilities = capabilityEntries(template);
              const monitorItems = previewItems(template, "monitors");
              const discoveryItems = previewItems(template, "discovery");
              const signalItems = previewItems(template, "signals");
              const correlationItems = previewItems(template, "correlation");
              const suggestedDashboards = templateDashboards[template.id] || [];
              const policyDraft = policyDrafts[template.id] || normalizeCollectionPolicy(template.collection_policy);
              const usage = usageByTemplate[String(template.id)] || {};

              return (
                <article
                  key={template.id}
                  className="rounded-2xl border border-white/10 bg-slate-900/70 p-6"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="text-xl font-semibold text-white">{template.name}</h2>
                        <span
                          className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${statusBadge(
                            template
                          )}`}
                        >
                          {template.enabled !== false ? "Disponível" : "Planejado"}
                        </span>
                      </div>
                      <div className="mt-2 text-sm text-slate-400">
                        {metadataLabel(template) || "Template sem metadata complementar"}
                      </div>
                    </div>

                    <div className="rounded-lg border border-white/10 bg-slate-950/60 px-3 py-2 text-xs uppercase tracking-wide text-slate-400">
                      {template.profiles?.length || 0} profile(s)
                    </div>
                  </div>

                  <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Hosts usando</div>
                      <div className="mt-2 text-xl font-semibold text-white">{usage.total || 0}</div>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Ativos</div>
                      <div className="mt-2 text-xl font-semibold text-white">{usage.enabled || 0}</div>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Incidentes</div>
                      <div className="mt-2 text-xl font-semibold text-white">{usage.openIncidents || 0}</div>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Última atividade</div>
                      <div className="mt-2 text-sm font-medium text-white">
                        {usage.lastActivityAt ? formatDateTime(usage.lastActivityAt) : "-"}
                      </div>
                    </div>
                  </div>

                  <p className="mt-4 text-sm leading-7 text-slate-300">
                    {template.summary || template.preview?.summary || "Sem resumo disponível."}
                  </p>

                  <div className="mt-4 flex flex-wrap gap-2">
                    {capabilities.length ? (
                      capabilities.map(([key, label]) => (
                        <span
                          key={`${template.id}-${key}`}
                          className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-100"
                        >
                          {label}
                        </span>
                      ))
                    ) : (
                      <span className="rounded-full border border-white/10 bg-slate-950 px-2.5 py-1 text-xs font-medium text-slate-300">
                        Sem capacidades declaradas
                      </span>
                    )}
                  </div>

                  <div className="mt-5 grid gap-4 xl:grid-cols-2">
                    <PreviewBlock
                      title="Monitora"
                      items={monitorItems}
                      emptyLabel="Sem itens de preview definidos."
                    />
                    <PreviewBlock
                      title="Descoberta e sinais"
                      items={[...discoveryItems, ...signalItems.slice(0, 3), ...correlationItems]}
                      emptyLabel="Sem descoberta ou sinais adicionais disponíveis."
                    />
                  </div>

                  <div className="mt-5 rounded-xl border border-white/10 bg-slate-950/40 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="text-xs uppercase tracking-wide text-slate-500">
                          Aplicação operacional
                        </div>
                        <div className="mt-2 text-sm text-slate-300">
                          Padroniza template de monitoramento, política de coleta e dashboard sugerido para novos hosts.
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Link
                          to={`/data-collection/hosts/new?template_id=${template.id}`}
                          className="rounded-md bg-sky-500 px-3 py-2 text-xs font-medium text-white hover:bg-sky-600"
                        >
                          Criar host
                        </Link>
                        <Link
                          to={`/data-collection/hosts?template_id=${template.id}`}
                          className="rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800"
                        >
                          Ver hosts
                        </Link>
                      </div>
                    </div>
                  </div>

                  <div className="mt-5 rounded-xl border border-white/10 bg-slate-950/40 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Dashboard sugerido
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {suggestedDashboards.length ? (
                        suggestedDashboards.map((dashboard) => (
                          <a
                            key={`${template.id}-${dashboard.dashboard_key}`}
                            href={dashboard.view_url}
                            target="_blank"
                            rel="noreferrer"
                            className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-100 hover:bg-sky-500/15"
                          >
                            {dashboard.title}
                          </a>
                        ))
                      ) : (
                        <span className="text-sm text-slate-400">
                          O template ainda não possui dashboard sugerido.
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="mt-5 rounded-xl border border-white/10 bg-slate-950/40 p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="text-xs uppercase tracking-wide text-slate-500">
                          Política de coleta e retenção
                        </div>
                        <div className="mt-2 text-sm text-slate-300">
                          {collectionPolicySummary(template.collection_policy)}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => handlePolicySave(template.id)}
                        disabled={savingTemplateId === template.id}
                        className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-sm text-sky-100 hover:bg-sky-500/20 disabled:opacity-60"
                      >
                        {savingTemplateId === template.id ? "Salvando..." : "Salvar política"}
                      </button>
                    </div>

                      <div className="mt-4 grid gap-4 md:grid-cols-2">
                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Intervalo ICMP (segundos)
                        </label>
                        <input
                          type="number"
                          min="5"
                          step="1"
                          value={policyDraft.icmp_interval_sec}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                icmp_interval_sec: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Intervalo SNMP (segundos)
                        </label>
                        <input
                          type="number"
                          min="5"
                          step="1"
                          value={policyDraft.snmp_interval_sec}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                snmp_interval_sec: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Timeout (segundos)
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.timeout_sec}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                timeout_sec: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Tentativas
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.retries}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                retries: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Retenção de históricos (dias)
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.history_retention_days}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                history_retention_days: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Retenção de trends (dias)
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.trend_retention_days}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                trend_retention_days: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Retenção de syslog (dias)
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.log_retention_days}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                log_retention_days: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Retenção de incidentes (dias)
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.incident_retention_days}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                incident_retention_days: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Retenção de notificações (dias)
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.notification_retention_days}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                notification_retention_days: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Retenção de auditoria (dias)
                        </label>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={policyDraft.audit_retention_days}
                          onChange={(event) =>
                            setPolicyDrafts((current) => ({
                              ...current,
                              [template.id]: {
                                ...policyDraft,
                                audit_retention_days: event.target.value,
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="mt-5 rounded-xl border border-white/10 bg-slate-950/40 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Profiles de coleta vinculados
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {template.profiles?.length ? (
                        template.profiles.map((profile) => (
                          <span
                            key={`${template.id}-${profile.profile_id}`}
                            className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-200"
                          >
                            {profile.display_name || profile.name}
                          </span>
                        ))
                      ) : (
                        <span className="text-sm text-slate-400">Nenhum profile associado.</span>
                      )}
                    </div>
                  </div>

                  {monitoringMatrixForTemplate(template) ? (
                    <div className="mt-5 rounded-xl border border-white/10 bg-slate-950/40 p-4">
                      <div className="text-xs uppercase tracking-wide text-slate-500">
                        Itens monitoráveis
                      </div>
                      <div className="mt-2 text-sm font-medium text-white">
                        {monitoringMatrixForTemplate(template).title}
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {monitoringMatrixForTemplate(template).items.map((item) => (
                          <span
                            key={`${template.id}-${item}`}
                            className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-100"
                          >
                            {item}
                          </span>
                        ))}
                      </div>
                      <div className="mt-3 text-xs text-slate-500">
                        Suportado quando disponível no equipamento e na MIB do fabricante.
                      </div>
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        ) : (
          <div className="rounded-2xl border border-dashed border-white/10 bg-slate-900/60 px-6 py-14 text-center">
            <div className="text-lg font-medium text-white">Nenhum template encontrado</div>
            <p className="mt-2 text-sm text-slate-400">
              Ajuste a busca ou confirme se o endpoint `/templates` está retornando o catálogo esperado.
            </p>
          </div>
        )}
      </section>
    </AppShell>
  );
}

