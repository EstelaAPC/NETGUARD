import React from "react";
import { Link } from "react-router-dom";
import AppShell from "../components/AppShell";

const PRODUCT_AREAS = [
  {
    title: "Monitoramento",
    body: "Área operacional do produto. Reúne visão geral, incidentes, hosts monitorados, sinais recentes e o drill-down principal por host.",
  },
  {
    title: "Coleta de dados",
    body: "Área de cadastro e configuração. Centraliza hosts, grupos, templates e descoberta, mantendo separado o que é operação do que é configuração.",
  },
  {
    title: "Relatórios",
    body: "Área para consolidação técnica, apoio à banca e geração de resumos formais reaproveitáveis no TCC.",
  },
  {
    title: "IA / Insights",
    body: "Camada assistida por Ollama para resumo do host, explicação de incidente, recomendação operacional e chat contextual ao NetGuard.",
  },
];

const MONITORING_ITEMS = [
  "Disponibilidade por ICMP, telemetria e métricas operacionais.",
  "SNMP básico de host e interfaces, com foco em RTT, perda e leituras de rede.",
  "Syslog recente com contexto de subsistema, interface e sinais precursores.",
  "Incidentes operacionais com severidade, status e vínculo com host.",
  "Previsões e anomalias, incluindo o pipeline de loop_risk.",
  "Dashboards Grafana embutidos por ambiente, host e grupo.",
];

const DEMO_FLOW = [
  "Abrir Monitoramento > Visão geral para mostrar o estado consolidado do ambiente.",
  "Entrar em Monitoramento > Hosts monitorados e selecionar o lab-linux-01.",
  "Usar as abas do host para navegar entre SNMP, Syslog, Incidentes, Previsões, Visualização e Insights.",
  "Mostrar a relação entre o dashboard do host, os incidentes e o loop_risk.",
  "Abrir Relatórios para gerar ou revisar o resumo técnico da demonstração.",
];

const INTERPRETATION_GUIDE = [
  {
    title: "Dashboards",
    body: "Mostram o panorama visual do host ou do ambiente. Use-os para complementar a leitura operacional, não como fonte isolada de decisão.",
  },
  {
    title: "Incidentes",
    body: "São a fila de trabalho operacional. Reúnem severidade, status, evidências e vínculo com o host para triagem e acompanhamento.",
  },
  {
    title: "Previsões",
    body: "Destacam sinais anômalos e risco de loop. Servem para antecipar atenção antes de uma falha explícita.",
  },
  {
    title: "Syslog",
    body: "Fornece contexto textual e temporal do que o ativo reportou. É útil para explicar incidentes e correlações.",
  },
  {
    title: "Insights de IA",
    body: "Geram resumo, explicação e recomendação com base nos dados do próprio produto. Devem ser lidos junto das evidências e do contexto operacional.",
  },
];

const FAQ_ITEMS = [
  {
    q: "O que é o NetGuard neste projeto?",
    a: "É uma plataforma de monitoramento com foco em simplicidade operacional, visão por host, incidentes, correlação e apoio por IA.",
  },
  {
    q: "Qual é o host principal do laboratório?",
    a: "O lab-linux-01 é o ativo principal da demonstração e concentra o fluxo completo de monitoramento do ambiente controlado.",
  },
  {
    q: "O que o produto monitora hoje?",
    a: "Hoje o produto cobre disponibilidade, SNMP básico, syslog, incidentes, previsões/anomalias, loop_risk e dashboards operacionais.",
  },
  {
    q: "Como interpretar a diferença entre dashboards, incidentes e insights?",
    a: "Dashboards ajudam a visualizar, incidentes organizam a fila operacional e insights ajudam a explicar o que já foi coletado.",
  },
];

function SectionCard({ title, body }) {
  return (
    <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-5">
      <h2 className="text-lg font-semibold text-white">{title}</h2>
      <p className="mt-3 text-sm leading-7 text-slate-300">{body}</p>
    </article>
  );
}

export default function Help() {
  return (
    <AppShell
      title="Ajuda"
      description="Guia curto e contextual do NetGuard para navegação, demonstração e leitura técnica do ambiente."
      actions={
        <>
          <Link
            to="/monitoring/hosts"
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Ver hosts monitorados
          </Link>
          <Link
            to="/insights"
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600"
          >
            Abrir IA / Insights
          </Link>
        </>
      }
    >
      <section className="rounded-2xl border border-sky-500/20 bg-sky-500/10 p-6">
        <div className="max-w-5xl">
          <h2 className="text-2xl font-semibold text-white">O que é o NetGuard</h2>
          <p className="mt-3 text-sm leading-7 text-slate-100">
            O NetGuard é uma plataforma de monitoramento construída para unir cadastro, operação,
            correlação e apoio por IA em um fluxo mais simples de entender do que ferramentas mais densas.
            Nesta demonstração, o foco está no host <strong>lab-linux-01</strong>, na visão por host, nos
            incidentes, no syslog, nas previsões e no pipeline de <strong>loop_risk</strong>.
          </p>
        </div>
      </section>

      <section className="mt-6 grid gap-4 xl:grid-cols-4">
        {PRODUCT_AREAS.map((item) => (
          <SectionCard key={item.title} title={item.title} body={item.body} />
        ))}
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-[1.2fr,1fr]">
        <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-6">
          <h2 className="text-xl font-semibold text-white">O que o NetGuard monitora hoje</h2>
          <div className="mt-4 space-y-3">
            {MONITORING_ITEMS.map((item) => (
              <div key={item} className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3 text-sm text-slate-200">
                {item}
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-6">
          <h2 className="text-xl font-semibold text-white">Fluxo recomendado de uso</h2>
          <div className="mt-4 space-y-3">
            {DEMO_FLOW.map((item, index) => (
              <div key={item} className="flex gap-3 rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
                <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-sky-500/20 text-xs font-semibold text-sky-100">
                  {index + 1}
                </div>
                <div className="text-sm leading-6 text-slate-200">{item}</div>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="mt-6 grid gap-4 xl:grid-cols-2">
        {INTERPRETATION_GUIDE.map((item) => (
          <SectionCard key={item.title} title={item.title} body={item.body} />
        ))}
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-[1.1fr,1fr]">
        <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-6">
          <h2 className="text-xl font-semibold text-white">Como validar o ambiente de demonstração</h2>
          <div className="mt-4 space-y-3 text-sm text-slate-200">
            <div className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
              Confirme que o <strong>lab-linux-01</strong> aparece em Hosts monitorados e possui grupo, template e dashboard.
            </div>
            <div className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
              Verifique se a visão geral e o dashboard do host estão carregando com dados do ambiente.
            </div>
            <div className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
              Navegue por Syslog, Incidentes e Previsões para mostrar como o NetGuard correlaciona sinais.
            </div>
            <div className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
              Gere um insight de IA ou use o assistente para explicar o host em linguagem técnica.
            </div>
          </div>
        </article>

        <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-6">
          <h2 className="text-xl font-semibold text-white">Perguntas frequentes</h2>
          <div className="mt-4 space-y-3">
            {FAQ_ITEMS.map((item) => (
              <div key={item.q} className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                <div className="text-sm font-medium text-white">{item.q}</div>
                <div className="mt-2 text-sm leading-6 text-slate-300">{item.a}</div>
              </div>
            ))}
          </div>
        </article>
      </section>
    </AppShell>
  );
}
