import React, { useEffect, useMemo, useState } from "react";
import AIInsightCard from "../components/AIInsightCard";
import Breadcrumbs from "../components/Breadcrumbs";
import Sidebar from "../components/Sidebar";
import { generateTechnicalSummary, listAIInsights } from "../services/ai";
import { listReportEvents } from "../services/reports";

const SEVERITY_META = {
  critical: {
    label: "Crítica",
    className: "bg-red-500/20 text-red-200 border border-red-500/30",
    rank: 6,
  },
  high: {
    label: "Alta",
    className: "bg-orange-500/20 text-orange-200 border border-orange-500/30",
    rank: 5,
  },
  warning: {
    label: "Atenção",
    className: "bg-amber-500/20 text-amber-200 border border-amber-500/30",
    rank: 4,
  },
  medium: {
    label: "Média",
    className: "bg-yellow-500/20 text-yellow-200 border border-yellow-500/30",
    rank: 3,
  },
  low: {
    label: "Baixa",
    className: "bg-sky-500/20 text-sky-200 border border-sky-500/30",
    rank: 2,
  },
  notice: {
    label: "Aviso",
    className: "bg-slate-500/20 text-slate-200 border border-slate-500/30",
    rank: 1,
  },
  info: {
    label: "Informativa",
    className: "bg-sky-500/20 text-sky-200 border border-sky-500/30",
    rank: 0,
  },
};

const SOURCE_META = {
  incident: { label: "Incidente", className: "bg-red-500/10 text-red-100", rank: 0 },
  prediction: { label: "Previsão", className: "bg-sky-500/10 text-sky-100", rank: 1 },
  syslog: { label: "Syslog", className: "bg-amber-500/10 text-amber-100", rank: 2 },
};

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];
const SORT_OPTIONS = [
  { value: "ts:desc", label: "Data/Hora (mais recentes)" },
  { value: "ts:asc", label: "Data/Hora (mais antigos)" },
  { value: "severity:desc", label: "Severidade (mais alta)" },
  { value: "severity:asc", label: "Severidade (mais baixa)" },
  { value: "source:asc", label: "Origem (A-Z)" },
  { value: "source:desc", label: "Origem (Z-A)" },
];

const PREDICTION_GROUP_WINDOW_MS = 5 * 60 * 1000;

function formatDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("pt-BR");
}

function formatDateInputValue(date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
}

function severityMeta(value) {
  return (
    SEVERITY_META[String(value || "").toLowerCase()] || {
      label: value ? String(value) : "Sem severidade",
      className: "bg-slate-500/20 text-slate-200 border border-slate-500/30",
      rank: -1,
    }
  );
}

function sourceMeta(value, fallbackLabel) {
  return (
    SOURCE_META[String(value || "").toLowerCase()] || {
      label: fallbackLabel || value || "Evento",
      className: "bg-slate-500/10 text-slate-200",
      rank: 99,
    }
  );
}

function formatPredictionWindow(firstTs, lastTs) {
  if (!firstTs || !lastTs || firstTs === lastTs) {
    return `em ${formatDateTime(lastTs || firstTs)}`;
  }

  return `entre ${formatDateTime(firstTs)} e ${formatDateTime(lastTs)}`;
}

function normalizeText(value) {
  return String(value || "").trim().toLowerCase();
}

const PREDICTION_METRIC_LABELS = {
  "snmp.if.in_errors.delta": "Erros de entrada",
  "snmp.if.out_errors.delta": "Erros de saída",
  "snmp.if.in_discards.delta": "Descartes de entrada",
  "snmp.if.out_discards.delta": "Descartes de saída",
  "snmp.if.in_octets.delta": "Tráfego de entrada",
  "snmp.if.out_octets.delta": "Tráfego de saída",
};

function predictionMetricLabel(metric) {
  const key = String(metric || "").trim();
  return PREDICTION_METRIC_LABELS[key] || key || "Métrica não informada";
}

function predictionMetricUnit(metric) {
  const key = String(metric || "").toLowerCase();
  if (key.includes("octets")) return "octetos no intervalo";
  if (key.includes("errors")) return "erros no intervalo";
  if (key.includes("discards")) return "descartes no intervalo";
  return "unidades no intervalo";
}

function normalizeReportDetails(value) {
  return String(value || "")
    .replace(/â€¢/g, "•")
    .replace(/\s+/g, " ")
    .trim();
}

function formatInterfaceContext(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (/^ifIndex=/i.test(text)) return text.replace(/^ifIndex=/i, "ifIndex ");
  if (/^\d+$/.test(text)) return `ifIndex ${text}`;
  return text;
}

function extractPredictionSamples(details) {
  const text = normalizeReportDetails(details);
  const samples = [];
  const regex = /Score\s+(\d+)%((?:\s*•\s*(?!Score\b)[^•]+){0,2})/gi;
  let match;

  while ((match = regex.exec(text)) !== null) {
    const chunks = String(match[2] || "")
      .split("•")
      .map((chunk) => chunk.trim())
      .filter(Boolean);
    const rawValue = chunks.find((chunk) => /^valor\s+/i.test(chunk));
    const rawContext = chunks.find((chunk) => !/^valor\s+/i.test(chunk));

    samples.push({
      scorePct: match[1],
      context: formatInterfaceContext(rawContext),
      value: rawValue ? rawValue.replace(/^valor\s+/i, "").trim() : "",
    });
  }

  return samples;
}

function formatObservedValue(value, metric) {
  const raw = String(value || "").trim();
  if (!raw) return "";

  const normalized = Number(raw.replace(",", "."));
  const displayed = Number.isFinite(normalized)
    ? normalized.toLocaleString("pt-BR", { maximumFractionDigits: 2 })
    : raw;
  return `${displayed} ${predictionMetricUnit(metric)}`;
}

function predictionContextFromRow(row, samples = []) {
  const sampleContext = samples.find((sample) => sample.context)?.context;
  if (sampleContext) return sampleContext;

  const context = String(row.context_name || "").split("•").pop()?.trim();
  if (context && context !== row.host_name) return formatInterfaceContext(context);

  const titleMatch = String(row.title || "").match(/Anomalia em\s+(.+)$/i);
  return titleMatch ? formatInterfaceContext(titleMatch[1]) : "";
}

function formatPredictionTitle(row) {
  const samples = extractPredictionSamples(row.details);
  const metric = predictionMetricLabel(row.signal_type);
  const context = predictionContextFromRow(row, samples);
  return context ? `Anomalia: ${metric} em ${context}` : `Anomalia: ${metric}`;
}

function formatPredictionDetails(row) {
  const samples = extractPredictionSamples(row.details);
  if (!samples.length) return row.details || "";

  const metric = `Métrica: ${predictionMetricLabel(row.signal_type)}`;
  const prefix =
    row.grouped && row.occurrenceCount > 1
      ? `${row.occurrenceCount} ocorrências semelhantes ${formatPredictionWindow(row.firstTs, row.lastTs)}`
      : "";

  if (samples.length === 1) {
    const sample = samples[0];
    return [
      prefix,
      `Índice de anomalia: ${sample.scorePct}%`,
      metric,
      sample.context ? `Interface: ${sample.context}` : "",
      sample.value ? `Valor observado: ${formatObservedValue(sample.value, row.signal_type)}` : "",
    ]
      .filter(Boolean)
      .join(" | ");
  }

  const sampleText = samples
    .map((sample) =>
      [
        `Índice ${sample.scorePct}%`,
        sample.context ? `interface ${sample.context}` : "",
        sample.value ? `valor ${formatObservedValue(sample.value, row.signal_type)}` : "",
      ]
        .filter(Boolean)
        .join(", ")
    )
    .join("; ");

  return [prefix, metric, `Amostras: ${sampleText}`].filter(Boolean).join(" | ");
}

function formatReportTitle(row) {
  return String(row.source) === "prediction" ? formatPredictionTitle(row) : row.title || "";
}

function formatReportDetails(row) {
  return String(row.source) === "prediction" ? formatPredictionDetails(row) : row.details || "";
}

function buildPredictionGroupKey(row) {
  const bucket = Math.floor(new Date(row.ts).getTime() / PREDICTION_GROUP_WINDOW_MS);
  return [
    row.source,
    row.asset_id || row.host_name || "",
    normalizeText(row.context_name),
    normalizeText(row.title),
    normalizeText(row.signal_type),
    bucket,
  ].join("|");
}

function consolidateRows(rows) {
  const groupedPredictions = new Map();
  const passthrough = [];

  for (const row of rows) {
    if (String(row.source) !== "prediction") {
      passthrough.push({
        ...row,
        occurrenceCount: 1,
        firstTs: row.ts,
        lastTs: row.ts,
        grouped: false,
      });
      continue;
    }

    const key = buildPredictionGroupKey(row);
    const existing = groupedPredictions.get(key);

    if (!existing) {
      groupedPredictions.set(key, {
        ...row,
        occurrenceCount: 1,
        firstTs: row.ts,
        lastTs: row.ts,
        grouped: false,
        detailsSamples: row.details ? [String(row.details)] : [],
      });
      continue;
    }

    existing.occurrenceCount += 1;
    existing.grouped = true;
    if (new Date(row.ts).getTime() > new Date(existing.lastTs).getTime()) {
      existing.lastTs = row.ts;
      existing.ts = row.ts;
    }
    if (new Date(row.ts).getTime() < new Date(existing.firstTs).getTime()) {
      existing.firstTs = row.ts;
    }
    if (row.details && !existing.detailsSamples.includes(String(row.details)) && existing.detailsSamples.length < 3) {
      existing.detailsSamples.push(String(row.details));
    }
  }

  const consolidatedPredictions = Array.from(groupedPredictions.values()).map((row) => {
    if (row.occurrenceCount <= 1) {
      return {
        ...row,
        details: row.detailsSamples[0] || row.details || "",
      };
    }

    const summary = `${row.occurrenceCount} ocorrências semelhantes ${formatPredictionWindow(row.firstTs, row.lastTs)}.`;
    const detailSuffix = row.detailsSamples.filter(Boolean).join(" • ");

    return {
      ...row,
      title: `${row.title} (${row.occurrenceCount} ocorrências)`,
      details: detailSuffix ? `${summary} ${detailSuffix}` : summary,
    };
  });

  return [...passthrough, ...consolidatedPredictions];
}

function sortRows(rows, sortValue) {
  const [field, direction] = String(sortValue || "ts:desc").split(":");
  const multiplier = direction === "asc" ? 1 : -1;

  return [...rows].sort((left, right) => {
    if (field === "severity") {
      return (severityMeta(left.severity).rank - severityMeta(right.severity).rank) * multiplier;
    }

    if (field === "source") {
      const sourceCompare = sourceMeta(left.source, left.source_label).label.localeCompare(
        sourceMeta(right.source, right.source_label).label,
        "pt-BR"
      );
      if (sourceCompare !== 0) {
        return sourceCompare * multiplier;
      }
      return (new Date(left.ts).getTime() - new Date(right.ts).getTime()) * -1;
    }

    return (new Date(left.ts).getTime() - new Date(right.ts).getTime()) * multiplier;
  });
}

function buildPageWindow(currentPage, totalPages) {
  const pages = new Set([1, totalPages, currentPage - 1, currentPage, currentPage + 1]);
  return Array.from(pages)
    .filter((value) => value >= 1 && value <= totalPages)
    .sort((left, right) => left - right);
}

function StatCard({ title, value, subtitle }) {
  return (
    <div className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{title}</div>
      <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
      {subtitle ? <div className="mt-1 text-sm text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function EmptyState({ title, subtitle }) {
  return (
    <div className="rounded-xl border border-dashed border-white/10 bg-slate-900/40 px-6 py-14 text-center">
      <div className="text-base font-medium text-white">{title}</div>
      <div className="mt-2 text-sm text-slate-400">{subtitle}</div>
    </div>
  );
}

export default function Relatorios() {
  const me = useMemo(() => JSON.parse(localStorage.getItem("ng_user") || "{}"), []);
  const initialTo = useMemo(() => new Date(), []);
  const initialFrom = useMemo(() => new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), []);

  const [rows, setRows] = useState([]);
  const [totalInPeriod, setTotalInPeriod] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [src, setSrc] = useState("all");
  const [from, setFrom] = useState(formatDateInputValue(initialFrom));
  const [to, setTo] = useState(formatDateInputValue(initialTo));
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [sortBy, setSortBy] = useState("ts:desc");
  const [technicalSummary, setTechnicalSummary] = useState(null);
  const [technicalSummaryLoading, setTechnicalSummaryLoading] = useState(false);
  const [technicalSummaryError, setTechnicalSummaryError] = useState("");

  useEffect(() => {
    void loadCachedTechnicalSummary();
  }, []);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadRows();
    }, 250);

    return () => window.clearTimeout(timeoutId);
  }, [q, sev, src, from, to]);

  useEffect(() => {
    setPage(1);
  }, [q, sev, src, from, to, pageSize, sortBy]);

  async function loadRows() {
    try {
      setLoading(true);
      setError("");

      const [baseItems, filteredItems] = await Promise.all([
        listReportEvents({ from, to, limit: 1000 }),
        listReportEvents({
          q,
          severity: sev,
          source: src,
          from,
          to,
          limit: 1000,
        }),
      ]);

      setTotalInPeriod(Array.isArray(baseItems) ? baseItems.length : 0);
      setRows(Array.isArray(filteredItems) ? filteredItems : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar eventos consolidados");
      setRows([]);
      setTotalInPeriod(0);
    } finally {
      setLoading(false);
    }
  }

  async function loadCachedTechnicalSummary() {
    try {
      const items = await listAIInsights({
        targetType: "report",
        insightType: "technical_summary",
        limit: 1,
      }).catch(() => []);

      setTechnicalSummary(Array.isArray(items) && items.length ? items[0] : null);
    } catch (loadError) {
      setTechnicalSummaryError(loadError?.message || "Falha ao carregar resumo técnico");
      setTechnicalSummary(null);
    }
  }

  async function handleGenerateTechnicalSummary(refresh = false) {
    try {
      setTechnicalSummaryLoading(true);
      setTechnicalSummaryError("");
      const generated = await generateTechnicalSummary({ refresh });
      setTechnicalSummary(generated);
    } catch (generationError) {
      setTechnicalSummaryError(generationError?.message || "Falha ao gerar resumo técnico");
    } finally {
      setTechnicalSummaryLoading(false);
    }
  }

  const consolidatedRows = useMemo(() => consolidateRows(rows), [rows]);
  const sortedRows = useMemo(() => sortRows(consolidatedRows, sortBy), [consolidatedRows, sortBy]);
  const totalPages = Math.max(1, Math.ceil(sortedRows.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageRows = useMemo(
    () => sortedRows.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [sortedRows, currentPage, pageSize]
  );
  const pageWindow = useMemo(() => buildPageWindow(currentPage, totalPages), [currentPage, totalPages]);

  const totalCritical = rows.filter((row) => row.severity === "critical").length;
  const totalWarnings = rows.filter((row) => ["high", "warning"].includes(String(row.severity || "").toLowerCase())).length;
  const totalInformational = rows.filter((row) =>
    ["medium", "low", "info", "notice"].includes(String(row.severity || "").toLowerCase())
  ).length;
  const distinctSources = new Set(rows.map((row) => row.source).filter(Boolean)).size;

  function handleExportCSV() {
    const headers = [
      "Data/Hora",
      "Primeira ocorrência",
      "Última ocorrência",
      "Ocorrências",
      "Severidade",
      "Origem",
      "Host",
      "Contexto",
      "Grupo",
      "Template",
      "Título",
      "Detalhes",
    ];

    const escapeCsv = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const lines = sortedRows.map((row) =>
      [
        row.ts,
        row.firstTs || row.ts,
        row.lastTs || row.ts,
        row.occurrenceCount || 1,
        severityMeta(row.severity).label,
        row.source_label || sourceMeta(row.source).label,
        row.host_name || "",
        row.context_name || "",
        row.group_name || "",
        row.template_name || "",
        formatReportTitle(row),
        formatReportDetails(row),
      ].map(escapeCsv)
    );

    const csv = "\uFEFF" + [headers.map(escapeCsv), ...lines].map((line) => line.join(";")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `netguard-relatorios-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <Sidebar />
      <div className="ng-shell bg-slate-950 text-white">
        <header className="sticky top-0 z-10 border-b border-white/10 bg-slate-900/50 backdrop-blur">
          <div className="max-w-[1400px] mx-auto px-6 py-3 flex items-center justify-between">
            <div>
              <Breadcrumbs />
              <h1 className="mt-2 text-2xl font-semibold">Relatórios</h1>
              <p className="mt-2 text-sm text-slate-400">
                Histórico consolidado de eventos operacionais do ambiente, com filtros reais, consolidação visual e exportação CSV.
              </p>
            </div>
            <div className="text-sm text-slate-400">
              {me?.name} {me?.role ? `(${me.role})` : ""}
            </div>
          </div>
        </header>

        <main className="max-w-[1400px] mx-auto px-6 py-8 space-y-6">
          <AIInsightCard
            title="Resumo técnico"
            description="Texto formal e objetivo, reaproveitável em relatório técnico, histórico operacional ou apresentação do ambiente."
            insight={technicalSummary}
            loading={technicalSummaryLoading}
            error={technicalSummaryError}
            primaryActionLabel="Gerar resumo técnico"
            onGenerate={() => handleGenerateTechnicalSummary()}
            onRefresh={() => handleGenerateTechnicalSummary(true)}
            emptyTitle="Resumo técnico ainda não gerado"
            emptySubtitle="Gere este insight para produzir um texto curto, ancorado nos dados reais consolidados do NetGuard."
          />

          <section className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
            <div className="flex flex-wrap items-end gap-4">
              <div className="min-w-[240px] flex-1">
                <label className="text-xs text-slate-400">Busca</label>
                <input
                  value={q}
                  onChange={(event) => setQ(event.target.value)}
                  placeholder="Título, detalhes, host, grupo ou contexto..."
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400">Severidade</label>
                <select
                  value={sev}
                  onChange={(event) => setSev(event.target.value)}
                  className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                >
                  <option value="all">Todas</option>
                  <option value="critical">Crítica</option>
                  <option value="high">Alta</option>
                  <option value="warning">Atenção</option>
                  <option value="medium">Média</option>
                  <option value="low">Baixa</option>
                  <option value="info">Informativa</option>
                  <option value="notice">Aviso</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400">Origem</label>
                <select
                  value={src}
                  onChange={(event) => setSrc(event.target.value)}
                  className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                >
                  <option value="all">Todas</option>
                  <option value="incident">Incidente</option>
                  <option value="syslog">Syslog</option>
                  <option value="prediction">Previsão</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400">Data inicial</label>
                <input
                  type="date"
                  value={from}
                  onChange={(event) => setFrom(event.target.value)}
                  className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400">Data final</label>
                <input
                  type="date"
                  value={to}
                  onChange={(event) => setTo(event.target.value)}
                  className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400">Ordenação</label>
                <select
                  value={sortBy}
                  onChange={(event) => setSortBy(event.target.value)}
                  className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                >
                  {SORT_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400">Itens por página</label>
                <select
                  value={pageSize}
                  onChange={(event) => setPageSize(Number(event.target.value))}
                  className="mt-1 rounded-md border border-white/10 bg-slate-800/60 px-3 py-2 outline-none focus:border-sky-400"
                >
                  {PAGE_SIZE_OPTIONS.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>

              <div className="ml-auto flex items-center gap-2">
                <button
                  onClick={() => {
                    setQ("");
                    setSev("all");
                    setSrc("all");
                    setSortBy("ts:desc");
                    setPageSize(25);
                    setFrom(formatDateInputValue(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)));
                    setTo(formatDateInputValue(new Date()));
                  }}
                  className="rounded-md bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700"
                >
                  Restaurar filtros
                </button>
                <button
                  onClick={handleExportCSV}
                  className="rounded-md bg-sky-600 px-3 py-2 text-sm hover:bg-sky-500 disabled:opacity-50"
                  disabled={!sortedRows.length}
                >
                  Exportar CSV
                </button>
              </div>
            </div>
          </section>

          <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <StatCard title="Total no período" value={totalInPeriod} subtitle="Eventos reais encontrados na janela selecionada" />
            <StatCard title="Filtrados" value={rows.length} subtitle={`${distinctSources} origem(ns) • ${totalCritical} críticos`} />
            <StatCard title="Linhas consolidadas" value={sortedRows.length} subtitle="Repetições curtas de previsão agrupadas visualmente" />
            <StatCard title="Exibidos na página" value={pageRows.length} subtitle={`${totalWarnings} alertas • ${totalInformational} informativos`} />
          </section>

          {error ? (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-200">{error}</div>
          ) : null}

          <section className="rounded-xl border border-white/10 bg-white/5 overflow-x-auto">
            {loading ? (
              <div className="px-6 py-16 text-center text-slate-400">Carregando eventos operacionais consolidados...</div>
            ) : pageRows.length ? (
              <table className="min-w-full text-sm">
                <thead className="bg-white/5 text-left text-slate-300">
                  <tr>
                    <th className="px-4 py-3 whitespace-nowrap">Data/Hora</th>
                    <th className="px-4 py-3 whitespace-nowrap">Severidade</th>
                    <th className="px-4 py-3 whitespace-nowrap">Origem</th>
                    <th className="px-4 py-3">Host / Contexto</th>
                    <th className="px-4 py-3">Título</th>
                    <th className="px-4 py-3">Detalhes</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((row) => {
                    const severity = severityMeta(row.severity);
                    const source = sourceMeta(row.source, row.source_label);

                    return (
                      <tr key={row.id} className="border-t border-white/10 align-top">
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div>{formatDateTime(row.ts)}</div>
                          {row.grouped ? (
                            <div className="mt-1 text-xs text-slate-400">
                              Janela agrupada: {formatPredictionWindow(row.firstTs, row.lastTs)}
                            </div>
                          ) : null}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ${severity.className}`}>
                            {severity.label}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ${source.className}`}>
                            {row.source_label || source.label}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-white">{row.host_name || "Sem host associado"}</div>
                          <div className="mt-1 text-xs text-slate-400">
                            {row.context_name || row.group_name || row.template_name || "Sem contexto adicional"}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-white">{formatReportTitle(row)}</div>
                          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                            <span>{row.template_name || "Sem template"}</span>
                            {row.group_name ? <span>• {row.group_name}</span> : null}
                            {row.occurrenceCount > 1 ? (
                              <span className="inline-flex rounded-full bg-sky-500/10 px-2 py-0.5 text-sky-200">
                                {row.occurrenceCount} ocorrências
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-slate-300">{formatReportDetails(row)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="p-6">
                <EmptyState
                  title="Nenhum evento operacional encontrado"
                  subtitle="Ajuste o período, a severidade, a origem ou a busca textual para consultar o histórico consolidado."
                />
              </div>
            )}
          </section>

          <section className="flex flex-col gap-3 rounded-xl border border-white/10 bg-slate-900/40 px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
            <div className="text-sm text-slate-300">
              Página <span className="font-semibold text-white">{currentPage}</span> de{" "}
              <span className="font-semibold text-white">{totalPages}</span>
              <span className="mx-2 text-slate-500">•</span>
              {totalInPeriod} no período
              <span className="mx-2 text-slate-500">•</span>
              {rows.length} filtrados
              <span className="mx-2 text-slate-500">•</span>
              {sortedRows.length} linhas consolidadas
              <span className="mx-2 text-slate-500">•</span>
              {pageRows.length} exibidos nesta página
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                className="rounded-md bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700 disabled:opacity-40"
                onClick={() => setPage((value) => Math.max(1, value - 1))}
                disabled={currentPage === 1}
              >
                Anterior
              </button>

              {pageWindow.map((value, index) => {
                const prev = pageWindow[index - 1];
                const showGap = prev && value - prev > 1;

                return (
                  <React.Fragment key={value}>
                    {showGap ? <span className="px-1 text-slate-500">...</span> : null}
                    <button
                      className={`rounded-md px-3 py-1.5 text-sm ${
                        value === currentPage ? "bg-sky-600 text-white" : "bg-slate-800 hover:bg-slate-700"
                      }`}
                      onClick={() => setPage(value)}
                    >
                      {value}
                    </button>
                  </React.Fragment>
                );
              })}

              <button
                className="rounded-md bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700 disabled:opacity-40"
                onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                disabled={currentPage === totalPages}
              >
                Próxima
              </button>
            </div>
          </section>
        </main>
      </div>
    </>
  );
}
