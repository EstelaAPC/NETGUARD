import React from "react";

export default function GrafanaDashboardCard({
  dashboard,
  title,
  description,
  height,
  extraActions = null,
}) {
  if (!dashboard) {
    return null;
  }

  const resolvedTitle = title || dashboard.title || "Dashboard";
  const resolvedDescription = description || dashboard.description;
  const resolvedHeight = height || dashboard.height || 760;
  const tags = Array.isArray(dashboard.tags) ? dashboard.tags.filter(Boolean) : [];

  return (
    <section className="overflow-hidden rounded-2xl border border-white/10 bg-slate-900/70 shadow-[0_0_0_1px_rgba(15,23,42,0.18)]">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/10 px-6 py-5">
        <div>
          <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Grafana integrado</div>
          <h2 className="mt-1 text-lg font-semibold text-white">{resolvedTitle}</h2>
          {resolvedDescription ? (
            <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-400">{resolvedDescription}</p>
          ) : null}
          {tags.length ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {tags.map((tag) => (
                <span
                  key={`${dashboard.dashboard_key}-${tag}`}
                  className="rounded-full border border-white/10 bg-slate-950 px-2.5 py-1 text-xs font-medium text-slate-300"
                >
                  {tag}
                </span>
              ))}
            </div>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {extraActions}
          {dashboard.edit_url ? (
            <a
              href={dashboard.edit_url}
              target="_blank"
              rel="noreferrer"
              className="rounded-md border border-white/10 bg-slate-950 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
              title="Abre o dashboard no Grafana para ajuste manual. Requer login com permissões de edição."
            >
              Abrir para editar
            </a>
          ) : null}
          <a
            href={dashboard.view_url}
            target="_blank"
            rel="noreferrer"
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600"
          >
            Abrir no Grafana
          </a>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-6 py-3 text-xs text-slate-400">
        <span>Edição avançada continua no Grafana. A visualização abaixo usa o mesmo contexto de host, grupo, template e período selecionado no NetGuard.</span>
        <span className="rounded-full border border-white/10 bg-slate-950/50 px-2.5 py-1 text-[11px] uppercase tracking-wide text-slate-300">
          Visualização embutida
        </span>
      </div>

      <div className="bg-slate-950/40 p-4">
        <div className="overflow-hidden rounded-xl border border-white/10 bg-slate-950/70">
          {dashboard.embed_url ? (
            <iframe
              src={dashboard.embed_url}
              title={resolvedTitle}
              width="100%"
              height={resolvedHeight}
              frameBorder="0"
              loading="lazy"
              className="block w-full bg-slate-950"
            />
          ) : (
            <div className="flex min-h-[420px] items-center justify-center px-6 py-16 text-center">
              <div>
                <div className="text-base font-medium text-white">Visualização do Grafana indisponível</div>
                <p className="mt-2 text-sm text-slate-400">
                  O painel ainda não forneceu embed_url para este dashboard.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

