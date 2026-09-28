import React from "react";

function InfoCard({ title, body }) {
  return (
    <div className="rounded-xl border border-white/10 bg-slate-900/70 p-5">
      <h2 className="text-base font-semibold text-white">{title}</h2>
      <p className="mt-2 text-sm leading-6 text-slate-400">{body}</p>
    </div>
  );
}

export default function FeaturePlaceholder({
  heroTitle,
  heroBody,
  statusLabel,
  highlights = [],
  nextSteps = [],
}) {
  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-sky-500/20 bg-sky-500/10 p-6">
        <div className="inline-flex rounded-full border border-sky-400/30 bg-sky-500/20 px-2.5 py-1 text-xs font-medium uppercase tracking-wide text-sky-100">
          {statusLabel}
        </div>
        <h2 className="mt-4 text-xl font-semibold text-white">{heroTitle}</h2>
        <p className="mt-3 max-w-4xl text-sm leading-7 text-slate-200">{heroBody}</p>
      </section>

      {highlights.length ? (
        <section className="grid gap-4 xl:grid-cols-3">
          {highlights.map((item) => (
            <InfoCard key={item.title} title={item.title} body={item.body} />
          ))}
        </section>
      ) : null}

      {nextSteps.length ? (
        <section className="rounded-2xl border border-white/10 bg-slate-900/70 p-6">
          <h2 className="text-base font-semibold text-white">Próximos passos previstos</h2>
          <div className="mt-4 space-y-3">
            {nextSteps.map((step, index) => (
              <div key={`${step}-${index}`} className="flex gap-3 rounded-lg border border-white/10 bg-slate-950/40 px-4 py-3">
                <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-sky-500/20 text-xs font-semibold text-sky-100">
                  {index + 1}
                </div>
                <p className="text-sm leading-6 text-slate-300">{step}</p>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}

