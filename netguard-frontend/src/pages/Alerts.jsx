import React, { useEffect, useMemo, useState } from "react";
import AppShell from "../components/AppShell";
import {
  acknowledgeAlertIncident,
  createAlertChannel,
  deleteAlertChannel,
  listAlertChannels,
  listAlertIncidents,
  listAlertNotifications,
  notifyAlertIncident,
  resolveAlertIncident,
  testAlertChannel,
  toggleAlertChannel,
  updateAlertChannel,
} from "../services/alerts";
import { formatDateTime, severityClassName, severityLabel, statusClassName, statusLabel } from "../monitoringUi";

const EMPTY_FORM = {
  name: "",
  provider: "email",
  enabled: true,
  min_severity: "LOW",
  config: {
    smtp_host: "",
    smtp_port: 587,
    smtp_user: "",
    smtp_password: "",
    smtp_from: "",
    alert_email_to: "",
    use_tls: true,
  },
};

const FILTER_DEFAULTS = {
  q: "",
  severity: "",
  status: "",
  device: "",
  problem: "",
};

const TAB_DEFINITIONS = [
  { id: "open", label: "Alertas abertos" },
  { id: "history", label: "Histórico de alertas" },
  { id: "channels", label: "Canais de notificação" },
  { id: "templates", label: "Templates/Regras" },
];

const PROVIDER_LABELS = {
  email: "E-mail",
  discord: "Discord",
  telegram: "Telegram",
  slack: "Slack",
  msteams: "Microsoft Teams",
  google_chat: "Google Chat",
  mattermost: "Mattermost",
  rocketchat: "Rocket.Chat",
  pushover: "Pushover",
  webhook: "Webhook genérico",
};

const PROVIDER_DESCRIPTIONS = {
  email: "SMTP com destinatário dedicado",
  discord: "Webhook Discord",
  telegram: "Bot API do Telegram",
  slack: "Incoming Webhook Slack",
  msteams: "Incoming Webhook Teams",
  google_chat: "Webhook Google Chat",
  mattermost: "Webhook Mattermost",
  rocketchat: "Webhook Rocket.Chat",
  pushover: "Pushover Messages API",
  webhook: "POST JSON genérico",
};

const WEBHOOK_PROVIDERS = ["discord", "slack", "msteams", "google_chat", "mattermost", "rocketchat", "webhook"];
const PROVIDER_OPTIONS = Object.entries(PROVIDER_LABELS).map(([value, label]) => ({
  value,
  label,
  description: PROVIDER_DESCRIPTIONS[value],
}));
const MESSAGE_TEMPLATE_CONFIG = {
  problem_template: "",
  recovery_template: "",
};

const DELIVERY_LABELS = {
  success: "Enviado",
  failed: "Erro",
  suppressed: "Suprimido",
};

const DELIVERY_CLASS_NAMES = {
  success: "border-emerald-500/30 bg-emerald-500/10 text-emerald-100",
  failed: "border-rose-500/30 bg-rose-500/10 text-rose-100",
  suppressed: "border-amber-500/30 bg-amber-500/10 text-amber-100",
};

const SEVERITY_RANK = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const ACTIVE_STATUSES = new Set(["open", "acknowledged"]);
const PAGE_SIZE_OPTIONS = [10, 15, 25];

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalizeText(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeUpper(value) {
  return String(value || "").trim().toUpperCase();
}

function withMessageTemplates(config) {
  return { ...config, ...MESSAGE_TEMPLATE_CONFIG };
}

function providerDefaultConfig(provider) {
  if (WEBHOOK_PROVIDERS.includes(provider)) {
    if (provider === "mattermost") return withMessageTemplates({ webhook_url: "", username: "NetGuard" });
    if (provider === "rocketchat") return withMessageTemplates({ webhook_url: "", alias: "NetGuard" });
    if (provider === "webhook") return withMessageTemplates({ webhook_url: "", headers: {}, headers_json: "{}" });
    return withMessageTemplates({ webhook_url: "" });
  }
  if (provider === "telegram") return withMessageTemplates({ bot_token: "", chat_id: "", parse_mode: "" });
  if (provider === "pushover") return withMessageTemplates({ app_token: "", user_key: "", device: "", priority: 0, sound: "" });
  return withMessageTemplates(clone(EMPTY_FORM.config));
}

function notificationLabel(notification) {
  if (!notification) return "Sem envio";
  const channel = notification.provider === "anti_spam" ? "Anti-spam" : notification.channel || notification.provider || "Canal";
  const status = DELIVERY_LABELS[normalizeText(notification.delivery_status)] || notification.delivery_status || "-";
  return `${channel}: ${status}`;
}

function isActiveStatus(status) {
  return ACTIVE_STATUSES.has(normalizeText(status));
}

function incidentTimestamp(incident) {
  const value = incident?.last_detected_at || incident?.updated_at || incident?.first_detected_at || incident?.resolved_at;
  const parsed = value ? new Date(value).getTime() : 0;
  return Number.isFinite(parsed) ? parsed : 0;
}

function sortAlertsForView(items, tab) {
  return [...items].sort((a, b) => {
    if (tab === "open") {
      const severityDelta = (SEVERITY_RANK[normalizeUpper(b.severity)] || 0) - (SEVERITY_RANK[normalizeUpper(a.severity)] || 0);
      if (severityDelta !== 0) return severityDelta;
    }
    return incidentTimestamp(b) - incidentTimestamp(a);
  });
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b, "pt-BR"));
}

function deliveryClassName(value) {
  return DELIVERY_CLASS_NAMES[normalizeText(value)] || "border-slate-500/30 bg-slate-500/10 text-slate-200";
}

function hasCustomTemplates(channel) {
  const config = channel?.config || {};
  return Boolean(config.problem_template || config.recovery_template || config.problem_title_template || config.recovery_title_template);
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

function TextInput(props) {
  return (
    <input
      {...props}
      className="w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
    />
  );
}

function TextArea(props) {
  return (
    <textarea
      {...props}
      className="min-h-24 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
    />
  );
}

function SelectInput(props) {
  return (
    <select
      {...props}
      className="w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
    />
  );
}

function MetricCard({ title, value, subtitle, tone = "slate" }) {
  const toneClasses = {
    red: "border-red-500/20 bg-red-500/10",
    orange: "border-orange-500/20 bg-orange-500/10",
    emerald: "border-emerald-500/20 bg-emerald-500/10",
    sky: "border-sky-500/20 bg-sky-500/10",
    slate: "border-white/10 bg-slate-900/70",
  };
  return (
    <div className={`rounded-lg border p-4 ${toneClasses[tone] || toneClasses.slate}`}>
      <div className="text-xs uppercase tracking-wide text-slate-500">{title}</div>
      <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
      {subtitle ? <div className="mt-1 min-h-5 text-xs text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function Pager({ page, totalPages, pageSize, totalItems, onPageChange, onPageSizeChange }) {
  return (
    <div className="flex flex-col gap-3 border-t border-white/10 px-4 py-3 text-sm text-slate-400 sm:flex-row sm:items-center sm:justify-between">
      <div>
        {totalItems} registro{totalItems === 1 ? "" : "s"} • página {Math.min(page, totalPages)} de {totalPages}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <SelectInput value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>
          {PAGE_SIZE_OPTIONS.map((value) => (
            <option key={value} value={value}>{value} por página</option>
          ))}
        </SelectInput>
        <button
          type="button"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page <= 1}
          className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-900 disabled:opacity-50"
        >
          Anterior
        </button>
        <button
          type="button"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page >= totalPages}
          className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-900 disabled:opacity-50"
        >
          Próxima
        </button>
      </div>
    </div>
  );
}

function AlertFilters({ filters, tab, devices, problems, onChange, onClear }) {
  const statusOptions = tab === "open"
    ? [
        { value: "", label: "Abertos e reconhecidos" },
        { value: "OPEN", label: "Somente abertos" },
        { value: "ACKNOWLEDGED", label: "Somente reconhecidos" },
      ]
    : [
        { value: "", label: "Resolvidos e fechados" },
        { value: "RESOLVED", label: "Somente resolvidos" },
        { value: "CLOSED", label: "Somente fechados" },
      ];

  return (
    <div className="grid gap-3 border-b border-white/10 bg-slate-950/30 p-4 lg:grid-cols-[1.4fr,0.8fr,0.8fr,1fr,1fr,auto]">
      <Field label="Busca">
        <TextInput
          value={filters.q}
          onChange={(event) => onChange("q", event.target.value)}
          placeholder="Dispositivo, IP, problema ou descrição"
        />
      </Field>
      <Field label="Severidade">
        <SelectInput value={filters.severity} onChange={(event) => onChange("severity", event.target.value)}>
          <option value="">Todas</option>
          <option value="CRITICAL">Crítica</option>
          <option value="HIGH">Alta</option>
          <option value="MEDIUM">Média</option>
          <option value="LOW">Baixa</option>
        </SelectInput>
      </Field>
      <Field label="Status">
        <SelectInput value={filters.status} onChange={(event) => onChange("status", event.target.value)}>
          {statusOptions.map((option) => (
            <option key={option.value || "all"} value={option.value}>{option.label}</option>
          ))}
        </SelectInput>
      </Field>
      <Field label="Dispositivo">
        <SelectInput value={filters.device} onChange={(event) => onChange("device", event.target.value)}>
          <option value="">Todos</option>
          {devices.map((device) => (
            <option key={device} value={device}>{device}</option>
          ))}
        </SelectInput>
      </Field>
      <Field label="Tipo de problema">
        <SelectInput value={filters.problem} onChange={(event) => onChange("problem", event.target.value)}>
          <option value="">Todos</option>
          {problems.map((problem) => (
            <option key={problem} value={problem}>{problem}</option>
          ))}
        </SelectInput>
      </Field>
      <div className="flex items-end">
        <button
          type="button"
          onClick={onClear}
          className="h-[42px] rounded-md border border-white/10 bg-slate-950 px-3 text-xs font-medium text-slate-200 hover:bg-slate-900"
        >
          Limpar
        </button>
      </div>
    </div>
  );
}

function AlertTable({ items, loading, tab, onNotify, notifyingId, onAcknowledge, acknowledgingId, onResolve }) {
  const emptyLabel = tab === "open" ? "Nenhum alerta aberto encontrado." : "Nenhum alerta no histórico para os filtros selecionados.";

  return (
    <>
      <div className="hidden lg:block">
        <table className="w-full table-fixed text-sm">
          <thead className="bg-slate-950/70 text-left text-slate-300">
            <tr>
              <th className="w-[125px] px-4 py-3">Severidade</th>
              <th className="w-[130px] px-4 py-3">Status</th>
              <th className="w-[190px] px-4 py-3">Dispositivo</th>
              <th className="px-4 py-3">Problema</th>
              <th className="w-[175px] px-4 py-3">Última detecção</th>
              <th className="w-[190px] px-4 py-3">Notificação</th>
              <th className="w-[165px] px-4 py-3 text-right">Ações</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-slate-400">Carregando alertas...</td></tr>
            ) : items.length ? (
              items.map((incident) => (
                <tr key={incident.id} className="border-t border-white/10 bg-slate-950/20 align-top">
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${severityClassName(incident.severity)}`}>
                      {severityLabel(incident.severity)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${statusClassName(incident.status)}`}>
                      {statusLabel(incident.status)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="truncate font-medium text-white" title={incident.device_name}>{incident.device_name || "-"}</div>
                    <div className="truncate text-xs text-slate-500" title={incident.device_ip}>{incident.device_ip || "-"}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="truncate font-medium text-slate-100" title={incident.problem_type}>{incident.problem_type || "-"}</div>
                    <div className="mt-1 line-clamp-2 text-xs leading-5 text-slate-500" title={incident.description}>{incident.description || "-"}</div>
                  </td>
                  <td className="px-4 py-3 text-slate-300">{formatDateTime(incident.last_detected_at || incident.updated_at)}</td>
                  <td className="px-4 py-3 text-slate-300">
                    <div className="line-clamp-2 text-xs leading-5">{notificationLabel(incident.latest_notification)}</div>
                    {!isActiveStatus(incident.status) && incident.resolution_source ? (
                      <div className="mt-1 text-xs text-slate-500">
                        Resolucao: {incident.resolution_source === "automatic" ? "Automatica" : "Manual"}
                      </div>
                    ) : null}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {isActiveStatus(incident.status) ? (
                      <div className="flex flex-wrap justify-end gap-2">
                        {!incident.notification_sent ? (
                          <button
                            type="button"
                            onClick={() => onNotify(incident)}
                            disabled={notifyingId === incident.id}
                            className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-xs font-medium text-sky-100 hover:bg-sky-500/20 disabled:opacity-70"
                          >
                            {notifyingId === incident.id ? "Enviando..." : "Enviar"}
                          </button>
                        ) : null}
                        {normalizeText(incident.status) === "open" ? (
                          <button
                            type="button"
                            onClick={() => onAcknowledge(incident)}
                            disabled={acknowledgingId === incident.id}
                            className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-100 hover:bg-amber-500/20 disabled:opacity-70"
                          >
                            {acknowledgingId === incident.id ? "Reconhecendo..." : "Reconhecer"}
                          </button>
                        ) : null}
                        <button
                          type="button"
                          onClick={() => onResolve(incident)}
                          className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-100 hover:bg-emerald-500/20"
                        >
                          Resolver manualmente
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-500">Sem ação</span>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-slate-400">{emptyLabel}</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="grid gap-3 p-4 lg:hidden">
        {loading ? <div className="rounded-lg border border-white/10 bg-slate-950/40 p-6 text-center text-sm text-slate-400">Carregando alertas...</div> : null}
        {!loading && !items.length ? <div className="rounded-lg border border-white/10 bg-slate-950/40 p-6 text-center text-sm text-slate-400">{emptyLabel}</div> : null}
        {!loading && items.map((incident) => (
          <div key={incident.id} className="rounded-lg border border-white/10 bg-slate-950/40 p-4">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <div className="font-semibold text-white">{incident.device_name || "-"}</div>
                <div className="text-xs text-slate-500">{incident.device_ip || "-"}</div>
              </div>
              <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${severityClassName(incident.severity)}`}>
                {severityLabel(incident.severity)}
              </span>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${statusClassName(incident.status)}`}>
                {statusLabel(incident.status)}
              </span>
              <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs text-slate-300">{incident.problem_type || "-"}</span>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-300">{incident.description || "-"}</p>
            <div className="mt-3 grid gap-1 text-xs text-slate-500">
              <span>Última detecção: {formatDateTime(incident.last_detected_at || incident.updated_at)}</span>
              <span>{notificationLabel(incident.latest_notification)}</span>
              {!isActiveStatus(incident.status) && incident.resolution_source ? (
                <span>Resolucao: {incident.resolution_source === "automatic" ? "Automatica" : "Manual"}</span>
              ) : null}
            </div>
            {isActiveStatus(incident.status) ? (
              <div className="mt-4 flex flex-wrap gap-2">
                {!incident.notification_sent ? (
                  <button type="button" onClick={() => onNotify(incident)} disabled={notifyingId === incident.id} className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-xs font-medium text-sky-100 disabled:opacity-70">
                    {notifyingId === incident.id ? "Enviando..." : "Enviar"}
                  </button>
                ) : null}
                {normalizeText(incident.status) === "open" ? (
                  <button type="button" onClick={() => onAcknowledge(incident)} disabled={acknowledgingId === incident.id} className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-100 disabled:opacity-70">
                    {acknowledgingId === incident.id ? "Reconhecendo..." : "Reconhecer"}
                  </button>
                ) : null}
                <button type="button" onClick={() => onResolve(incident)} className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-100">
                  Resolver manualmente
                </button>
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </>
  );
}

function ChannelFormModal({
  open,
  form,
  editingId,
  saving,
  onClose,
  onSubmit,
  onFormChange,
  onProviderChange,
  onConfigChange,
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex bg-slate-950/75 backdrop-blur-sm">
      <button type="button" className="absolute inset-0 cursor-default" aria-label="Fechar formulário" onClick={onClose} />
      <form
        onSubmit={onSubmit}
        className="relative ml-auto flex h-full w-full max-w-2xl flex-col border-l border-white/10 bg-slate-900 shadow-2xl"
      >
        <div className="border-b border-white/10 px-5 py-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">{editingId ? "Editar canal" : "Novo canal"}</h2>
              <p className="mt-1 text-sm text-slate-400">
                Configure somente campos do provedor selecionado. Segredos salvos permanecem mascarados na edição.
              </p>
            </div>
            <button type="button" onClick={onClose} className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800">
              Fechar
            </button>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
          <div className="grid gap-4">
            <Field label="Nome do canal">
              <TextInput value={form.name} onChange={(event) => onFormChange({ ...form, name: event.target.value })} placeholder="Telegram NOC" required />
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Tipo">
                <SelectInput value={form.provider} onChange={(event) => onProviderChange(event.target.value)}>
                  {PROVIDER_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </SelectInput>
                <div className="mt-1 text-xs text-slate-500">{PROVIDER_DESCRIPTIONS[form.provider]}</div>
              </Field>
              <Field label="Severidade mínima">
                <SelectInput value={form.min_severity} onChange={(event) => onFormChange({ ...form, min_severity: event.target.value })}>
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </SelectInput>
              </Field>
            </div>

            <label className="flex items-center gap-2 text-sm text-slate-200">
              <input type="checkbox" checked={form.enabled} onChange={(event) => onFormChange({ ...form, enabled: event.target.checked })} />
              Ativo
            </label>

            {form.provider === "email" ? (
              <div className="grid gap-4 rounded-lg border border-white/10 bg-slate-950/40 p-4">
                <div className="text-sm font-semibold text-white">Configuração SMTP</div>
                <Field label="SMTP Host"><TextInput value={form.config.smtp_host || ""} onChange={(event) => onConfigChange("smtp_host", event.target.value)} /></Field>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="SMTP Port"><TextInput type="number" value={form.config.smtp_port || 587} onChange={(event) => onConfigChange("smtp_port", Number(event.target.value))} /></Field>
                  <Field label="SMTP User"><TextInput value={form.config.smtp_user || ""} onChange={(event) => onConfigChange("smtp_user", event.target.value)} /></Field>
                </div>
                <Field label="SMTP Password"><TextInput type="password" value={form.config.smtp_password || ""} onChange={(event) => onConfigChange("smtp_password", event.target.value)} /></Field>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="SMTP From"><TextInput value={form.config.smtp_from || ""} onChange={(event) => onConfigChange("smtp_from", event.target.value)} /></Field>
                  <Field label="Destinatário"><TextInput value={form.config.alert_email_to || ""} onChange={(event) => onConfigChange("alert_email_to", event.target.value)} /></Field>
                </div>
                <label className="flex items-center gap-2 text-sm text-slate-200">
                  <input type="checkbox" checked={form.config.use_tls !== false} onChange={(event) => onConfigChange("use_tls", event.target.checked)} />
                  Usar TLS
                </label>
              </div>
            ) : null}

            {WEBHOOK_PROVIDERS.includes(form.provider) ? (
              <div className="grid gap-4 rounded-lg border border-white/10 bg-slate-950/40 p-4">
                <div className="text-sm font-semibold text-white">Webhook</div>
                <Field label="Webhook URL">
                  <TextInput type="password" value={form.config.webhook_url || ""} onChange={(event) => onConfigChange("webhook_url", event.target.value)} />
                </Field>
                {form.provider === "mattermost" ? (
                  <Field label="Username">
                    <TextInput value={form.config.username || "NetGuard"} onChange={(event) => onConfigChange("username", event.target.value)} />
                  </Field>
                ) : null}
                {form.provider === "rocketchat" ? (
                  <Field label="Alias">
                    <TextInput value={form.config.alias || "NetGuard"} onChange={(event) => onConfigChange("alias", event.target.value)} />
                  </Field>
                ) : null}
                {form.provider === "webhook" ? (
                  <Field label="Headers JSON">
                    <TextArea value={form.config.headers_json || "{}"} onChange={(event) => onConfigChange("headers_json", event.target.value)} spellCheck={false} />
                  </Field>
                ) : null}
              </div>
            ) : null}

            {form.provider === "telegram" ? (
              <div className="grid gap-4 rounded-lg border border-white/10 bg-slate-950/40 p-4">
                <div className="text-sm font-semibold text-white">Telegram Bot API</div>
                <Field label="Bot Token">
                  <TextInput type="password" value={form.config.bot_token || ""} onChange={(event) => onConfigChange("bot_token", event.target.value)} />
                </Field>
                <Field label="Chat ID">
                  <TextInput value={form.config.chat_id || ""} onChange={(event) => onConfigChange("chat_id", event.target.value)} />
                </Field>
                <Field label="Parse mode">
                  <SelectInput value={form.config.parse_mode || ""} onChange={(event) => onConfigChange("parse_mode", event.target.value)}>
                    <option value="">Texto simples</option>
                    <option value="Markdown">Markdown</option>
                    <option value="HTML">HTML</option>
                    <option value="MarkdownV2">MarkdownV2</option>
                  </SelectInput>
                </Field>
              </div>
            ) : null}

            {form.provider === "pushover" ? (
              <div className="grid gap-4 rounded-lg border border-white/10 bg-slate-950/40 p-4">
                <div className="text-sm font-semibold text-white">Pushover</div>
                <Field label="App Token">
                  <TextInput type="password" value={form.config.app_token || ""} onChange={(event) => onConfigChange("app_token", event.target.value)} />
                </Field>
                <Field label="User Key">
                  <TextInput type="password" value={form.config.user_key || ""} onChange={(event) => onConfigChange("user_key", event.target.value)} />
                </Field>
                <div className="grid gap-4 sm:grid-cols-3">
                  <Field label="Device">
                    <TextInput value={form.config.device || ""} onChange={(event) => onConfigChange("device", event.target.value)} />
                  </Field>
                  <Field label="Priority">
                    <TextInput type="number" value={form.config.priority ?? 0} onChange={(event) => onConfigChange("priority", Number(event.target.value))} />
                  </Field>
                  <Field label="Sound">
                    <TextInput value={form.config.sound || ""} onChange={(event) => onConfigChange("sound", event.target.value)} />
                  </Field>
                </div>
              </div>
            ) : null}

            <div className="grid gap-4 rounded-lg border border-white/10 bg-slate-950/40 p-4">
              <div>
                <div className="text-sm font-semibold text-white">Template da mensagem</div>
                <p className="mt-1 text-xs leading-5 text-slate-400">
                  Vazio usa o padrão do NetGuard. Placeholders: {"{device_name}"}, {"{device_ip}"}, {"{group_name}"}, {"{problem_name}"}, {"{problem_type}"}, {"{item}"}, {"{value}"}, {"{severity_label}"}, {"{started_at}"}, {"{resolved_at}"}, {"{duration}"}, {"{incident_url}"}.
                </p>
              </div>
              <Field label="Template de problema">
                <TextArea
                  value={form.config.problem_template || ""}
                  onChange={(event) => onConfigChange("problem_template", event.target.value)}
                  placeholder="🚨 Problema detectado: {problem_name}"
                  spellCheck={false}
                />
              </Field>
              <Field label="Template de recuperação">
                <TextArea
                  value={form.config.recovery_template || ""}
                  onChange={(event) => onConfigChange("recovery_template", event.target.value)}
                  placeholder="✅ Problema resolvido após {duration}"
                  spellCheck={false}
                />
              </Field>
            </div>
          </div>
        </div>

        <div className="border-t border-white/10 px-5 py-4">
          <button type="submit" disabled={saving} className="w-full rounded-md bg-sky-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70">
            {saving ? "Salvando..." : editingId ? "Salvar alterações" : "Criar canal"}
          </button>
        </div>
      </form>
    </div>
  );
}

export default function Alerts() {
  const [incidents, setIncidents] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [channels, setChannels] = useState([]);
  const [form, setForm] = useState(() => clone(EMPTY_FORM));
  const [editingId, setEditingId] = useState(null);
  const [activeTab, setActiveTab] = useState("open");
  const [filters, setFilters] = useState(() => ({ ...FILTER_DEFAULTS }));
  const [page, setPage] = useState({ open: 1, history: 1 });
  const [pageSize, setPageSize] = useState(10);
  const [channelModalOpen, setChannelModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState(null);
  const [notifyingId, setNotifyingId] = useState(null);
  const [acknowledgingId, setAcknowledgingId] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const openIncidents = useMemo(() => incidents.filter((item) => isActiveStatus(item.status)), [incidents]);
  const historyIncidents = useMemo(() => incidents.filter((item) => !isActiveStatus(item.status)), [incidents]);

  const deviceOptions = useMemo(() => uniqueSorted(incidents.map((item) => item.device_name || item.device_ip)), [incidents]);
  const problemOptions = useMemo(() => uniqueSorted(incidents.map((item) => item.problem_type)), [incidents]);

  const filteredAlerts = useMemo(() => {
    const base = activeTab === "history" ? historyIncidents : openIncidents;
    const query = normalizeText(filters.q);
    const status = normalizeUpper(filters.status);
    const severity = normalizeUpper(filters.severity);
    const device = filters.device;
    const problem = filters.problem;

    return sortAlertsForView(
      base.filter((incident) => {
        if (severity && normalizeUpper(incident.severity) !== severity) return false;
        if (status && normalizeUpper(incident.status) !== status) return false;
        if (device && (incident.device_name || incident.device_ip) !== device) return false;
        if (problem && incident.problem_type !== problem) return false;
        if (!query) return true;
        const haystack = [
          incident.device_name,
          incident.device_ip,
          incident.problem_type,
          incident.description,
          incident.status,
          incident.severity,
        ].map(normalizeText).join(" ");
        return haystack.includes(query);
      }),
      activeTab
    );
  }, [activeTab, filters, historyIncidents, openIncidents]);

  const currentPage = page[activeTab] || 1;
  const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const paginatedAlerts = filteredAlerts.slice((safePage - 1) * pageSize, safePage * pageSize);

  const stats = useMemo(() => {
    const sentOrFailed = notifications.filter((item) => ["success", "failed"].includes(normalizeText(item.delivery_status)));
    const lastNotification = sentOrFailed[0];
    return {
      open: openIncidents.length,
      critical: openIncidents.filter((item) => normalizeUpper(item.severity) === "CRITICAL").length,
      activeChannels: channels.filter((item) => item.enabled).length,
      sentOrFailed: sentOrFailed.length,
      lastNotification,
    };
  }, [channels, notifications, openIncidents]);

  async function loadData() {
    try {
      setLoading(true);
      setError("");
      const [incidentData, notificationData, channelData] = await Promise.all([
        listAlertIncidents({ limit: 500 }),
        listAlertNotifications({ limit: 120 }),
        listAlertChannels(),
      ]);
      setIncidents(Array.isArray(incidentData) ? incidentData : []);
      setNotifications(Array.isArray(notificationData) ? notificationData : []);
      setChannels(Array.isArray(channelData) ? channelData : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar alertas");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  function setTab(tabId) {
    setActiveTab(tabId);
    setMessage("");
    setError("");
  }

  function setFilterValue(key, value) {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage((current) => ({ ...current, [activeTab]: 1 }));
  }

  function clearFilters() {
    setFilters({ ...FILTER_DEFAULTS });
    setPage((current) => ({ ...current, [activeTab]: 1 }));
  }

  function changePage(nextPage) {
    setPage((current) => ({ ...current, [activeTab]: nextPage }));
  }

  function changePageSize(nextPageSize) {
    setPageSize(nextPageSize);
    setPage((current) => ({ ...current, [activeTab]: 1 }));
  }

  function openNewChannel() {
    setEditingId(null);
    setForm(clone(EMPTY_FORM));
    setMessage("");
    setError("");
    setChannelModalOpen(true);
  }

  function closeChannelModal() {
    setChannelModalOpen(false);
    setEditingId(null);
    setForm(clone(EMPTY_FORM));
  }

  function editChannel(channel) {
    const provider = channel.provider || "email";
    const config = {
      ...providerDefaultConfig(provider),
      ...(channel.config || {}),
    };
    if (provider === "webhook") {
      config.headers_json = JSON.stringify(config.headers || {}, null, 2);
    }
    setEditingId(channel.id);
    setForm({
      name: channel.name || "",
      provider,
      enabled: channel.enabled !== false,
      min_severity: channel.min_severity || "LOW",
      config,
    });
    setMessage("");
    setError("");
    setChannelModalOpen(true);
  }

  function setProvider(provider) {
    setForm((current) => ({
      ...current,
      provider,
      config: providerDefaultConfig(provider),
    }));
  }

  function setConfigValue(key, value) {
    setForm((current) => ({
      ...current,
      config: {
        ...current.config,
        [key]: value,
      },
    }));
  }

  async function saveChannel(event) {
    event.preventDefault();
    try {
      setSaving(true);
      setError("");
      setMessage("");
      const config = { ...form.config };
      if (form.provider === "webhook" && typeof config.headers_json === "string") {
        try {
          config.headers = config.headers_json.trim() ? JSON.parse(config.headers_json) : {};
        } catch {
          throw new Error("Headers do webhook genérico devem estar em JSON válido.");
        }
        delete config.headers_json;
      }
      const payload = {
        ...form,
        config,
        name: form.name.trim(),
        min_severity: normalizeUpper(form.min_severity || "LOW"),
      };
      if (editingId) {
        await updateAlertChannel(editingId, payload);
        setMessage("Canal atualizado.");
      } else {
        await createAlertChannel(payload);
        setMessage("Canal criado.");
      }
      closeChannelModal();
      await loadData();
      setActiveTab("channels");
    } catch (saveError) {
      setError(saveError?.message || "Falha ao salvar canal");
    } finally {
      setSaving(false);
    }
  }

  async function toggleChannel(channel) {
    try {
      setError("");
      await toggleAlertChannel(channel.id, !channel.enabled);
      await loadData();
    } catch (toggleError) {
      setError(toggleError?.message || "Falha ao alterar canal");
    }
  }

  async function removeChannel(channel) {
    if (!window.confirm(`Excluir o canal "${channel.name}"?`)) return;
    try {
      setError("");
      await deleteAlertChannel(channel.id);
      if (editingId === channel.id) closeChannelModal();
      await loadData();
      setMessage("Canal excluído.");
    } catch (deleteError) {
      setError(deleteError?.message || "Falha ao excluir canal");
    }
  }

  async function testChannel(channel) {
    try {
      setTestingId(channel.id);
      setError("");
      const result = await testAlertChannel(channel.id);
      setMessage(`Teste ${DELIVERY_LABELS[normalizeText(result.delivery_status)] || result.delivery_status}.`);
      await loadData();
    } catch (testError) {
      setError(testError?.message || "Falha ao testar canal");
    } finally {
      setTestingId(null);
    }
  }

  async function resolveIncident(incident) {
    const manualReason = window.prompt("Justificativa da resolucao manual:", "Resolvido manualmente pelo operador apos validacao.");
    if (manualReason === null) return;
    try {
      setError("");
      await resolveAlertIncident(incident.id, {
        sendRecoveryNotification: true,
        manualReason: manualReason.trim(),
        resolutionSource: "manual",
      });
      await loadData();
      setMessage(`Alerta ${incident.id} resolvido manualmente.`);
    } catch (resolveError) {
      setError(resolveError?.message || "Falha ao resolver incidente");
    }
  }

  async function acknowledgeIncident(incident) {
    try {
      setAcknowledgingId(incident.id);
      setError("");
      setMessage("");
      await acknowledgeAlertIncident(incident.id, { note: "Reconhecido pela fila operacional." });
      await loadData();
      setMessage(`Alerta ${incident.id} reconhecido. Ele continua aberto ate recuperacao automatica ou resolucao manual.`);
    } catch (ackError) {
      setError(ackError?.message || "Falha ao reconhecer incidente");
    } finally {
      setAcknowledgingId(null);
    }
  }

  async function sendIncidentNotification(incident) {
    try {
      setNotifyingId(incident.id);
      setError("");
      setMessage("");
      const result = await notifyAlertIncident(incident.id, { force: true });
      await loadData();
      setMessage(
        result?.notification_sent
          ? `Notificação enviada para ${incident.device_name}.`
          : `Tentativa de notificação registrada para ${incident.device_name}.`
      );
    } catch (notifyError) {
      setError(notifyError?.message || "Falha ao enviar notificação do incidente");
    } finally {
      setNotifyingId(null);
    }
  }

  return (
    <AppShell
      title="Alertas"
      description="Incidentes, histórico e canais de comunicação organizados por fluxo operacional."
      actions={
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={loadData}
            disabled={loading}
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-100 hover:bg-slate-800 disabled:opacity-70"
          >
            Atualizar
          </button>
          <button
            type="button"
            onClick={openNewChannel}
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600"
          >
            + Novo canal
          </button>
        </div>
      }
    >
      {error ? <div className="mb-6 rounded-lg border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</div> : null}
      {message ? <div className="mb-6 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">{message}</div> : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard title="Alertas abertos" value={stats.open} subtitle="OPEN + ACKNOWLEDGED" tone="red" />
        <MetricCard title="Críticos abertos" value={stats.critical} subtitle="Severidade CRITICAL ativa" tone="orange" />
        <MetricCard title="Canais ativos" value={stats.activeChannels} subtitle={`${channels.length} canal(is) cadastrado(s)`} tone="sky" />
        <MetricCard
          title="Notificações recentes"
          value={stats.sentOrFailed}
          subtitle={stats.lastNotification ? notificationLabel(stats.lastNotification) : "Sem envio ou falha recente"}
          tone="emerald"
        />
      </section>

      <section className="mt-6 rounded-lg border border-white/10 bg-slate-900/70">
        <div className="flex gap-2 overflow-x-auto border-b border-white/10 px-3 py-3">
          {TAB_DEFINITIONS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setTab(tab.id)}
              className={`whitespace-nowrap rounded-md px-3 py-2 text-sm font-medium transition ${
                activeTab === tab.id
                  ? "bg-sky-500 text-white"
                  : "bg-slate-950 text-slate-300 hover:bg-slate-800"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === "open" || activeTab === "history" ? (
          <>
            <AlertFilters
              filters={filters}
              tab={activeTab}
              devices={deviceOptions}
              problems={problemOptions}
              onChange={setFilterValue}
              onClear={clearFilters}
            />
            <div className="border-b border-white/10 px-5 py-4">
              <h2 className="text-lg font-semibold text-white">
                {activeTab === "open" ? "Alertas abertos" : "Histórico de alertas"}
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                {activeTab === "open"
                  ? "Visualização principal mostra somente incidentes ativos, ordenados por severidade e última detecção."
                  : "Alertas resolvidos e fechados ficam separados da fila operacional principal."}
              </p>
            </div>
            <AlertTable
              items={paginatedAlerts}
              loading={loading}
              tab={activeTab}
              onNotify={sendIncidentNotification}
              notifyingId={notifyingId}
              onAcknowledge={acknowledgeIncident}
              acknowledgingId={acknowledgingId}
              onResolve={resolveIncident}
            />
            <Pager
              page={safePage}
              totalPages={totalPages}
              pageSize={pageSize}
              totalItems={filteredAlerts.length}
              onPageChange={changePage}
              onPageSizeChange={changePageSize}
            />
          </>
        ) : null}

        {activeTab === "channels" ? (
          <div>
            <div className="flex flex-col gap-3 border-b border-white/10 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Canais de notificação</h2>
                <p className="mt-1 text-sm text-slate-400">Somente provedores com adapter real no backend ficam disponíveis para cadastro.</p>
              </div>
              <button type="button" onClick={openNewChannel} className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600">
                + Novo canal
              </button>
            </div>
            <div className="grid gap-4 p-5 md:grid-cols-2 xl:grid-cols-3">
              {channels.map((channel) => (
                <div key={channel.id} className="rounded-lg border border-white/10 bg-slate-950/40 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate font-semibold text-white" title={channel.name}>{channel.name}</div>
                      <div className="mt-1 text-sm text-slate-400">{PROVIDER_LABELS[channel.provider] || channel.provider} • {channel.min_severity}</div>
                    </div>
                    <span className={`shrink-0 rounded-full border px-2.5 py-1 text-xs ${channel.enabled ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100" : "border-slate-500/30 bg-slate-500/10 text-slate-300"}`}>
                      {channel.enabled ? "Ativo" : "Inativo"}
                    </span>
                  </div>
                  <div className="mt-4 grid gap-1 text-xs text-slate-400">
                    <span>Último teste: {channel.last_test_status || "-"}</span>
                    <span>{channel.last_test_at ? formatDateTime(channel.last_test_at) : "Ainda não testado"}</span>
                  </div>
                  {channel.last_test_error ? <div className="mt-2 line-clamp-2 text-xs text-rose-300" title={channel.last_test_error}>{channel.last_test_error}</div> : null}
                  <div className="mt-4 flex flex-wrap gap-2">
                    <button type="button" onClick={() => editChannel(channel)} className="rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">Editar</button>
                    <button type="button" onClick={() => toggleChannel(channel)} className="rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">
                      {channel.enabled ? "Desativar" : "Ativar"}
                    </button>
                    <button type="button" onClick={() => testChannel(channel)} disabled={testingId === channel.id} className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-xs text-sky-100 hover:bg-sky-500/20 disabled:opacity-60">
                      {testingId === channel.id ? "Testando..." : "Testar"}
                    </button>
                    <button type="button" onClick={() => removeChannel(channel)} className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-100 hover:bg-rose-500/20">Excluir</button>
                  </div>
                </div>
              ))}
              {!channels.length ? <div className="rounded-lg border border-white/10 bg-slate-950/40 p-6 text-sm text-slate-400">Nenhum canal configurado.</div> : null}
            </div>
          </div>
        ) : null}

        {activeTab === "templates" ? (
          <div>
            <div className="border-b border-white/10 px-5 py-4">
              <h2 className="text-lg font-semibold text-white">Templates/Regras de notificação</h2>
              <p className="mt-1 text-sm text-slate-400">
                O backend atual usa regras por canal: severidade mínima, ativo/inativo e templates opcionais de problema/recuperação.
              </p>
            </div>
            <div className="grid gap-4 p-5 lg:grid-cols-2">
              {channels.map((channel) => (
                <div key={channel.id} className="rounded-lg border border-white/10 bg-slate-950/40 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="font-semibold text-white">{channel.name}</div>
                      <div className="mt-1 text-sm text-slate-400">{PROVIDER_LABELS[channel.provider] || channel.provider}</div>
                    </div>
                    <span className={`rounded-full border px-2.5 py-1 text-xs ${hasCustomTemplates(channel) ? "border-sky-500/30 bg-sky-500/10 text-sky-100" : "border-slate-500/30 bg-slate-500/10 text-slate-300"}`}>
                      {hasCustomTemplates(channel) ? "Template customizado" : "Template padrão"}
                    </span>
                  </div>
                  <div className="mt-4 grid gap-2 text-sm text-slate-300">
                    <div>Regra de envio: severidade mínima <span className="font-semibold text-white">{channel.min_severity}</span></div>
                    <div>Status do canal: <span className={channel.enabled ? "text-emerald-200" : "text-slate-400"}>{channel.enabled ? "ativo" : "inativo"}</span></div>
                    <div className="text-xs text-slate-500">Templates ficam armazenados no `config` do canal e são usados pelo AlertService.</div>
                  </div>
                  <button type="button" onClick={() => editChannel(channel)} className="mt-4 rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">
                    Editar regra/template
                  </button>
                </div>
              ))}
              {!channels.length ? <div className="rounded-lg border border-white/10 bg-slate-950/40 p-6 text-sm text-slate-400">Crie um canal para configurar templates e regras.</div> : null}
            </div>
          </div>
        ) : null}
      </section>

      <ChannelFormModal
        open={channelModalOpen}
        form={form}
        editingId={editingId}
        saving={saving}
        onClose={closeChannelModal}
        onSubmit={saveChannel}
        onFormChange={setForm}
        onProviderChange={setProvider}
        onConfigChange={setConfigValue}
      />
    </AppShell>
  );
}
