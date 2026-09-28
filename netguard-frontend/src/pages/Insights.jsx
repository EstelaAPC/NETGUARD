import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import AppShell from "../components/AppShell";
import SafeMarkdown from "../components/SafeMarkdown";
import { chatWithAI, listAIInsights } from "../services/ai";
import { listHosts } from "../services/hosts";
import { listIncidents } from "../services/incidents";

const CHAT_WINDOWS = [
  { id: "6", label: "Últimas 6h" },
  { id: "24", label: "Últimas 24h" },
  { id: "72", label: "Últimas 72h" },
];

function formatDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("pt-BR");
}

function MessageBubble({ message }) {
  const isUser = message.role === "user";

  return (
    <article
      className={`rounded-2xl border p-4 ${
        isUser
          ? "ml-auto max-w-3xl border-sky-500/20 bg-sky-500/10"
          : "mr-auto max-w-4xl border-white/10 bg-slate-900/80"
      }`}
    >
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-slate-400">
        <span className="font-medium text-slate-200">{isUser ? "Você" : "Assistente operacional"}</span>
        <span>{formatDateTime(message.ts)}</span>
        {!isUser && message.model ? (
          <span className="rounded-full border border-white/10 bg-slate-950 px-2 py-0.5 text-[11px] text-slate-300">
            {message.model}
          </span>
        ) : null}
      </div>

      {isUser ? (
        <p className="whitespace-pre-wrap text-sm leading-6 text-slate-100">{message.content}</p>
      ) : (
        <div className="text-sm leading-6 text-slate-100">
          <SafeMarkdown content={message.content} />
        </div>
      )}

      {!isUser && message.evidence ? (
        <details className="mt-4 rounded-xl border border-white/10 bg-slate-950/40">
          <summary className="cursor-pointer px-3 py-2 text-xs font-medium uppercase tracking-wide text-slate-400">
            Ver evidências e contexto usados
          </summary>
          <div className="border-t border-white/10 px-3 py-3">
            <pre className="overflow-x-auto whitespace-pre-wrap text-xs leading-6 text-slate-300">
              {JSON.stringify(message.evidence, null, 2)}
            </pre>
          </div>
        </details>
      ) : null}
    </article>
  );
}

function RecentInsightItem({ item }) {
  const label = item?.title || item?.insight_type || "Insight";

  return (
    <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
      <div className="text-sm font-medium text-white">{label}</div>
      <div className="mt-1 text-xs text-slate-400">
        {item?.target_type || "escopo"} #{item?.target_id ?? "-"} • {formatDateTime(item?.created_at)}
      </div>
      <div className="mt-2 line-clamp-3 text-xs leading-5 text-slate-300">{item?.content_md || "Sem conteúdo disponível."}</div>
    </div>
  );
}

export default function Insights() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [hosts, setHosts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [recentInsights, setRecentInsights] = useState([]);
  const [loadingData, setLoadingData] = useState(true);
  const [refreshingData, setRefreshingData] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [error, setError] = useState("");
  const [placeholderIndex, setPlaceholderIndex] = useState(0);

  const [selectedHostId, setSelectedHostId] = useState(searchParams.get("host_id") || "");
  const [selectedIncidentId, setSelectedIncidentId] = useState(searchParams.get("incident_id") || "");
  const [windowHours, setWindowHours] = useState(searchParams.get("hours") || "24");

  const selectedHost = useMemo(
    () => hosts.find((host) => String(host.id) === String(selectedHostId)) || null,
    [hosts, selectedHostId]
  );
  const selectedIncident = useMemo(
    () => incidents.find((incident) => String(incident.id) === String(selectedIncidentId)) || null,
    [incidents, selectedIncidentId]
  );
  const demoHost = useMemo(
    () => hosts.find((host) => host.name === "lab-linux-01" || host.ip === "172.30.10.10") || null,
    [hosts]
  );

  async function loadContext(mode = "initial") {
    try {
      if (mode === "initial") {
        setLoadingData(true);
      } else {
        setRefreshingData(true);
      }

      setError("");
      const [hostData, incidentData, insightData] = await Promise.all([
        listHosts({ limit: 200 }).catch(() => []),
        listIncidents({ status: "open", limit: 40 }).catch(() => []),
        listAIInsights({ limit: 8 }).catch(() => []),
      ]);

      setHosts(Array.isArray(hostData) ? hostData : []);
      setIncidents(Array.isArray(incidentData) ? incidentData : []);
      setRecentInsights(Array.isArray(insightData) ? insightData : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar o contexto de IA.");
    } finally {
      setLoadingData(false);
      setRefreshingData(false);
    }
  }

  useEffect(() => {
    loadContext("initial");
  }, []);

  useEffect(() => {
    const nextParams = new URLSearchParams();
    if (selectedHostId) nextParams.set("host_id", String(selectedHostId));
    if (selectedIncidentId) nextParams.set("incident_id", String(selectedIncidentId));
    if (windowHours) nextParams.set("hours", String(windowHours));
    setSearchParams(nextParams, { replace: true });
  }, [selectedHostId, selectedIncidentId, setSearchParams, windowHours]);

  const suggestions = useMemo(() => {
    const focusHost = selectedHost || demoHost;
    const prompts = [
      "Explicar incidente",
      "Sugerir causa raiz",
      "O que fazer agora?",
      "Gerar resumo para gestor",
      "Gerar evidências para TCC",
      "Gerar comandos Cisco",
      "Gerar comandos Linux",
    ];

    if (focusHost) {
      prompts.push(`Explicar o host ${focusHost.name}`);
      prompts.push(`O que está acontecendo com o host ${focusHost.name}?`);
      prompts.push(`O que devo verificar primeiro no host ${focusHost.name}?`);
      prompts.push(`Gerar resumo técnico do host ${focusHost.name}`);
    }

    if (selectedIncident) {
      prompts.push("Quais evidências sustentam esse incidente?");
      prompts.push("Quais comandos eu uso para validar esse incidente?");
    }

    return prompts;
  }, [demoHost, selectedHost, selectedIncident]);

  const placeholderExamples = useMemo(() => {
    const focusHost = selectedHost || demoHost;
    const examples = [
      "Ex.: Explicar incidente",
      "Ex.: Sugerir causa raiz",
      "Ex.: O que fazer agora?",
    ];

    if (focusHost) {
      examples.push(`Ex.: O que está acontecendo com o host ${focusHost.name}?`);
    }

    return examples;
  }, [demoHost, selectedHost]);

  useEffect(() => {
    setPlaceholderIndex(0);
  }, [placeholderExamples]);

  useEffect(() => {
    if (placeholderExamples.length <= 1) return undefined;

    const timer = window.setInterval(() => {
      setPlaceholderIndex((current) => (current + 1) % placeholderExamples.length);
    }, 3500);

    return () => window.clearInterval(timer);
  }, [placeholderExamples]);

  async function sendMessage(promptText) {
    const question = String(promptText || "").trim();
    if (!question || chatLoading) return;

    const userMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: question,
      ts: new Date().toISOString(),
    };

    const history = messages.slice(-8).map((item) => ({
      role: item.role,
      content: item.content,
    }));

    setMessages((current) => [...current, userMessage]);
    setInput("");
    setChatLoading(true);
    setError("");

    try {
      const response = await chatWithAI({
        message: question,
        hostId: selectedHostId || undefined,
        incidentId: selectedIncidentId || undefined,
        hours: Number(windowHours || 24),
        history,
      });

      setMessages((current) => [
        ...current,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: response?.reply_md || "Sem resposta útil do assistente.",
          ts: response?.generated_at || new Date().toISOString(),
          model: response?.model || "",
          evidence: response?.evidence_json || {},
          contextScope: response?.context_scope || {},
        },
      ]);

      loadContext("refresh");
    } catch (chatError) {
      setError(chatError?.message || "Falha ao consultar o assistente operacional.");
    } finally {
      setChatLoading(false);
    }
  }

  function handleSubmit(event) {
    event.preventDefault();
    sendMessage(input);
  }

  function handleInputKeyDown(event) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      if (!chatLoading && input.trim()) {
        sendMessage(input);
      }
    }
  }

  function clearConversation() {
    setMessages([]);
    setInput("");
    setError("");
  }

  return (
    <AppShell
      title="IA / Insights"
      description="Assistente contextual do NetGuard para operação, redes e artigo/TCC. Use perguntas objetivas sobre hosts, incidentes, syslog, SNMP, dashboards, métricas, Zabbix/SolarWinds e conceitos de rede."
      maxWidth="max-w-[1750px]"
      actions={
        <>
          <button
            type="button"
            onClick={() => loadContext("refresh")}
            disabled={loadingData || refreshingData || chatLoading}
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-70"
          >
            {refreshingData ? "Atualizando..." : "Atualizar contexto"}
          </button>
          <button
            type="button"
            onClick={clearConversation}
            disabled={chatLoading || messages.length === 0}
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
          >
            Limpar conversa
          </button>
        </>
      }
    >
      {error ? (
        <div className="mb-6 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      ) : null}

      <section className="rounded-2xl border border-white/10 bg-slate-900/70 p-5">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr),minmax(0,1fr),220px]">
          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Host em foco</label>
            <select
              value={selectedHostId}
              onChange={(event) => setSelectedHostId(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Ambiente geral</option>
              {hosts.map((host) => (
                <option key={host.id} value={host.id}>
                  {host.name} ({host.ip})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Incidente em foco</label>
            <select
              value={selectedIncidentId}
              onChange={(event) => setSelectedIncidentId(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="">Nenhum incidente específico</option>
              {incidents.map((incident) => (
                <option key={incident.id} value={incident.id}>
                  #{incident.id} • {incident.title}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Janela</label>
            <select
              value={windowHours}
              onChange={(event) => setWindowHours(event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              {CHAT_WINDOWS.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {suggestions.map((prompt) => (
            <button
              key={prompt}
              type="button"
              onClick={() => sendMessage(prompt)}
              disabled={chatLoading}
              className="rounded-full border border-white/10 bg-slate-950 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-900 disabled:opacity-70"
            >
              {prompt}
            </button>
          ))}
        </div>
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.7fr),420px]">
        <div className="rounded-2xl border border-white/10 bg-slate-900/70">
          <div className="border-b border-white/10 px-5 py-4">
            <h2 className="text-lg font-semibold text-white">Assistente operacional</h2>
            <p className="mt-1 text-sm text-slate-400">
              Responde sobre NetGuard, redes corporativas e artigo/TCC; usa evidências do ambiente quando a pergunta for sobre o estado real da rede.
            </p>
          </div>

          <div className="space-y-4 px-5 py-5">
            {messages.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-white/10 bg-slate-950/40 px-5 py-12 text-center">
                <div className="text-lg font-medium text-white">Nenhuma pergunta enviada ainda</div>
                <p className="mt-2 text-sm text-slate-400">
                  Use uma sugestão rápida ou faça uma pergunta técnica sobre host, incidentes, syslog, SNMP, previsões ou dashboards.
                </p>
              </div>
            ) : (
              messages.map((message) => <MessageBubble key={message.id} message={message} />)
            )}

            {chatLoading ? (
              <div className="rounded-2xl border border-white/10 bg-slate-950/40 px-4 py-5 text-sm text-slate-400">
                Gerando resposta...
              </div>
            ) : null}
          </div>

          <form onSubmit={handleSubmit} className="border-t border-white/10 px-5 py-4">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Pergunta</label>
            <div className="mt-2 flex flex-col gap-3 xl:flex-row">
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={handleInputKeyDown}
                rows={3}
                placeholder={placeholderExamples[placeholderIndex] || "Ex.: O que o NetGuard faz hoje?"}
                className="min-h-[96px] flex-1 rounded-xl border border-white/10 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-sky-400"
              />
              <button
                type="submit"
                disabled={chatLoading || !input.trim()}
                className="rounded-xl bg-sky-500 px-5 py-3 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70 xl:self-end"
              >
                {chatLoading ? "Enviando..." : "Perguntar"}
              </button>
            </div>
            <p className="mt-2 text-xs text-slate-500">
              Você pode perguntar sobre o produto, o ambiente ou um host em foco. <strong>Enter</strong> envia e <strong>Shift+Enter</strong> quebra linha.
            </p>
          </form>
        </div>

        <aside className="space-y-6">
          <section className="rounded-2xl border border-white/10 bg-slate-900/70 p-5">
            <h2 className="text-lg font-semibold text-white">Contexto atual</h2>
            <div className="mt-4 space-y-3 text-sm text-slate-300">
              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Escopo principal</div>
                <div className="mt-1 text-white">{selectedHost ? selectedHost.name : "Ambiente geral"}</div>
              </div>

              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Grupo</div>
                <div className="mt-1">{selectedHost?.group_path || selectedHost?.group_name || "Sem grupo em foco"}</div>
              </div>

              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Template</div>
                <div className="mt-1">{selectedHost?.template_name || "Sem template específico"}</div>
              </div>

              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Incidente</div>
                <div className="mt-1">{selectedIncident?.title || "Nenhum incidente selecionado"}</div>
              </div>

              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Janela</div>
                <div className="mt-1">
                  {CHAT_WINDOWS.find((option) => option.id === windowHours)?.label || "Últimas 24h"}
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-2xl border border-white/10 bg-slate-900/70 p-5">
            <h2 className="text-lg font-semibold text-white">Insights recentes em cache</h2>
            <p className="mt-1 text-sm text-slate-400">
              Gerações recentes de resumo, explicação e recomendação já armazenadas no produto.
            </p>

            <div className="mt-4 space-y-3">
              {loadingData ? (
                <div className="rounded-xl border border-white/10 bg-slate-950/40 px-4 py-5 text-sm text-slate-400">
                  Carregando histórico recente de insights...
                </div>
              ) : recentInsights.length ? (
                recentInsights.map((item) => <RecentInsightItem key={item.id} item={item} />)
              ) : (
                <div className="rounded-xl border border-dashed border-white/10 bg-slate-950/40 px-4 py-5 text-sm text-slate-400">
                  Nenhum insight recente para este contexto.
                </div>
              )}
            </div>
          </section>
        </aside>
      </section>
    </AppShell>
  );
}

