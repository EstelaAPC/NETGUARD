import React from "react";
import SafeMarkdown from "./SafeMarkdown";

function formatDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("pt-BR");
}

function MetaPill({ children, tone = "slate" }) {
  const tones = {
    slate: "border-white/10 bg-slate-950 text-slate-300",
    sky: "border-sky-500/20 bg-sky-500/10 text-sky-100",
    emerald: "border-emerald-500/20 bg-emerald-500/10 text-emerald-100",
    amber: "border-amber-500/20 bg-amber-500/10 text-amber-100",
    rose: "border-rose-500/20 bg-rose-500/10 text-rose-100",
  };

  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${tones[tone] || tones.slate}`}>
      {children}
    </span>
  );
}

export default function AIInsightCard({
  title,
  description,
  insight,
  loading = false,
  error = "",
  emptyTitle = "Nenhum insight gerado",
  emptySubtitle = "Gere o insight sob demanda para ver a análise contextual.",
  primaryActionLabel = "Gerar insight",
  onGenerate,
  onRefresh,
}) {
  return (
    <section className="h-full min-h-0 rounded-2xl border border-white/10 bg-slate-900/70 p-5">
      <div className="flex h-full min-h-0 flex-col">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">{title}</h3>
            {description ? <p className="mt-1 text-sm text-slate-400">{description}</p> : null}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {onGenerate ? (
              <button
                type="button"
                onClick={onGenerate}
                disabled={loading}
                className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
              >
                {loading ? "Gerando..." : primaryActionLabel}
              </button>
            ) : null}

            {onRefresh && insight ? (
              <button
                type="button"
                onClick={onRefresh}
                disabled={loading}
                className="rounded-md border border-white/10 bg-slate-950 px-4 py-2 text-sm text-slate-200 hover:bg-slate-900 disabled:opacity-70"
              >
                Regenerar
              </button>
            ) : null}
          </div>
        </div>

        {error ? (
          <div className="mt-4 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
            {error}
          </div>
        ) : null}

        {loading ? (
          <div className="mt-4 rounded-xl border border-white/10 bg-slate-950/50 px-4 py-10 text-center text-sm text-slate-400">
            Gerando resposta...
          </div>
        ) : null}

        {!loading && !insight ? (
          <div className="mt-4 rounded-xl border border-dashed border-white/10 bg-slate-950/40 px-4 py-10 text-center">
            <div className="text-base font-medium text-white">{emptyTitle}</div>
            <div className="mt-2 text-sm text-slate-400">{emptySubtitle}</div>
          </div>
        ) : null}

        {!loading && insight ? (
          <div className="mt-4 flex min-h-0 flex-1 flex-col space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <MetaPill tone={insight.cached ? "emerald" : "sky"}>
                {insight.cached ? "Cache reutilizado" : "Gerado nesta solicitação"}
              </MetaPill>
              <MetaPill>{insight.model || "Modelo não informado"}</MetaPill>
              <MetaPill>Gerado em {formatDateTime(insight.created_at)}</MetaPill>
              {insight.expires_at ? <MetaPill tone="amber">Expira em {formatDateTime(insight.expires_at)}</MetaPill> : null}
            </div>

            <div className="min-h-0 flex-1 rounded-xl border border-white/10 bg-slate-950/40 p-5">
              <div className="max-h-[34rem] overflow-y-auto overscroll-contain pr-2 pb-4">
                <SafeMarkdown content={insight.content_md} />
              </div>
            </div>

            <details className="rounded-xl border border-white/10 bg-slate-950/30">
              <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-200">
                Evidências e contexto enviados ao modelo
              </summary>
              <div className="border-t border-white/10 px-4 py-4">
                <pre className="overflow-x-auto whitespace-pre-wrap text-xs leading-6 text-slate-300">
                  {JSON.stringify(insight.evidence_json || {}, null, 2)}
                </pre>
              </div>
            </details>
          </div>
        ) : null}
      </div>
    </section>
  );
}

