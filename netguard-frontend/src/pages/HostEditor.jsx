import React, { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import AppShell from "../components/AppShell";
import {
  createHost,
  createHostGroup,
  discoverHostInterfaces,
  getHost,
  getHostProfiles,
  getTemplatePreview,
  listHostGroups,
  listHostInterfaces,
  listProfiles,
  listTemplates,
  updateHost,
  updateHostInterface,
  updateHostProfiles,
} from "../services/hosts";

const DEFAULT_SNMP = {
  version: "v2c",
  port: 161,
  retries: 1,
  timeout: 1,
  community: "public",
};

const COLLECTION_POLICY_FIELDS = [
  "icmp_interval_sec",
  "snmp_interval_sec",
  "tcp_interval_sec",
  "timeout_sec",
  "retries",
  "history_retention_days",
  "trend_retention_days",
  "log_retention_days",
  "incident_retention_days",
  "notification_retention_days",
  "audit_retention_days",
];

const EMPTY_COLLECTION_POLICY_OVERRIDE = {
  icmp_interval_sec: "",
  snmp_interval_sec: "",
  tcp_interval_sec: "",
  timeout_sec: "",
  retries: "",
  history_retention_days: "",
  trend_retention_days: "",
  log_retention_days: "",
  incident_retention_days: "",
  notification_retention_days: "",
  audit_retention_days: "",
};

function normalizeCollectionPolicyOverride(policy) {
  return COLLECTION_POLICY_FIELDS.reduce((acc, field) => {
    acc[field] =
      policy?.[field] === null || policy?.[field] === undefined || policy?.[field] === ""
        ? ""
        : String(policy[field]);
    return acc;
  }, {});
}

function hasCollectionPolicyOverride(policy) {
  return COLLECTION_POLICY_FIELDS.some((field) => String(policy?.[field] ?? "").trim() !== "");
}

function buildCollectionPolicyOverridePayload(policy, enabled) {
  if (!enabled) return {};

  return COLLECTION_POLICY_FIELDS.reduce((acc, field) => {
    const raw = String(policy?.[field] ?? "").trim();
    if (!raw) return acc;
    acc[field] = Number(raw);
    return acc;
  }, {});
}

function collectionPolicySummary(policy) {
  if (!policy) return "Política de coleta global";

  return `ICMP ${policy.icmp_interval_sec || "-"}s | SNMP ${policy.snmp_interval_sec || "-"}s | timeout ${
    policy.timeout_sec || "-"
  }s | tentativas ${policy.retries || "-"} | historico ${policy.history_retention_days || "-"}d | trends ${
    policy.trend_retention_days || "-"
  }d | syslog ${policy.log_retention_days || "-"}d | incidentes ${policy.incident_retention_days || "-"}d | notificacoes ${
    policy.notification_retention_days || "-"
  }d | auditoria ${policy.audit_retention_days || "-"}d`;
}

const DEFAULT_GROUP_FORM = { name: "", parent_id: "" };

const TABS = [
  { id: "general", label: "Host / Geral" },
  { id: "group", label: "Grupo" },
  { id: "snmp", label: "SNMP" },
  { id: "profiles", label: "Templates de monitoramento" },
  { id: "interfaces", label: "Interfaces" },
  { id: "metadata", label: "Metadados / Parâmetros" },
  { id: "monitoring", label: "Monitoramento / Descoberta" },
];

function makeRowId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeForm(host) {
  const normalizedOverride = normalizeCollectionPolicyOverride(host?.collection_policy_override);

  return {
    name: host?.name || "",
    ip: host?.ip || "",
    group_id: host?.group_id ?? "",
    template_id: host?.template_id ?? "",
    enabled: host?.enabled !== false,
    snmp_profile: {
      ...DEFAULT_SNMP,
      ...(host?.snmp_profile || {}),
    },
    collection_policy_override: normalizedOverride,
    collection_policy_override_enabled: hasCollectionPolicyOverride(normalizedOverride),
    collection_policy_resolved: host?.collection_policy_resolved || {},
    collection_policy_source_labels: host?.collection_policy_source_labels || {},
  };
}

function tagsToRows(tags) {
  const entries = Object.entries(tags || {});
  return entries.length
    ? entries.map(([key, value]) => ({
        id: makeRowId(),
        key,
        value: typeof value === "string" ? value : JSON.stringify(value),
      }))
    : [{ id: makeRowId(), key: "", value: "" }];
}

function parseTagValue(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (raw === "null") return null;
  if (!Number.isNaN(Number(raw))) return Number(raw);

  if (
    (raw.startsWith("{") && raw.endsWith("}")) ||
    (raw.startsWith("[") && raw.endsWith("]")) ||
    (raw.startsWith('"') && raw.endsWith('"'))
  ) {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  return raw;
}

function rowsToTags(rows) {
  return rows.reduce((acc, row) => {
    const key = String(row.key || "").trim();
    if (!key) return acc;
    acc[key] = parseTagValue(row.value);
    return acc;
  }, {});
}

function groupLabel(groups, groupId) {
  const group = groups.find((item) => String(item.id) === String(groupId));
  return group ? group.path || group.name : "Sem grupo";
}

function templateLabel(templates, templateId) {
  const template = templates.find((item) => String(item.id) === String(templateId));
  return template ? template.name : "Sem template";
}

function templateCapabilities(templatePreview) {
  const capabilities = templatePreview?.capabilities || {};
  const labels = {
    icmp: "ICMP",
    snmp: "SNMP",
    discovery: "Discovery",
    syslog: "Syslog",
    correlation: "Correlação",
    loop_risk: "loop_risk",
  };

  return Object.entries(labels).filter(([key]) => capabilities[key]);
}

function mapTemplateProfiles(templatePreview) {
  return Array.isArray(templatePreview?.profiles)
    ? templatePreview.profiles.map((profile) => ({
        profile_id: profile.profile_id,
        name: profile.name,
        display_name: profile.display_name,
        description: profile.description,
        kind: profile.kind,
        params: profile.params || {},
        enabled: profile.enabled !== false,
        config: profile.config || {},
      }))
    : [];
}

function TabBar({ tabs, activeTab, onChange }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-white/10 bg-slate-900/70">
      <div className="inline-flex min-w-full border-b border-white/10">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => onChange(tab.id)}
            className={`whitespace-nowrap border-b-2 px-4 py-3 text-sm font-medium transition ${
              activeTab === tab.id
                ? "border-sky-400 bg-slate-900 text-white"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function Card({ title, subtitle, children }) {
  return (
    <section className="rounded-2xl border border-white/10 bg-slate-900/70">
      <div className="border-b border-white/10 px-6 py-5">
        <h2 className="text-lg font-semibold text-white">{title}</h2>
        {subtitle ? <p className="mt-2 text-sm leading-6 text-slate-400">{subtitle}</p> : null}
      </div>
      <div className="px-6 py-5">{children}</div>
    </section>
  );
}

function PlaceholderCard({ title, body, note }) {
  return (
    <Card title={title} subtitle={body}>
      <div className="rounded-xl border border-dashed border-white/10 bg-slate-950/40 px-6 py-10 text-center">
        <p className="mx-auto max-w-3xl text-sm leading-7 text-slate-300">{body}</p>
        {note ? <p className="mt-4 text-xs uppercase tracking-[0.14em] text-slate-500">{note}</p> : null}
      </div>
    </Card>
  );
}

export default function HostEditor() {
  const navigate = useNavigate();
  const location = useLocation();
  const { hostId } = useParams();
  const isEdit = Boolean(hostId);

  const [activeTab, setActiveTab] = useState("general");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(location.state?.success || "");

  const [form, setForm] = useState(() => normalizeForm(null));
  const [groups, setGroups] = useState([]);
  const [groupForm, setGroupForm] = useState(DEFAULT_GROUP_FORM);
  const [groupCreateOpen, setGroupCreateOpen] = useState(false);
  const [groupSaving, setGroupSaving] = useState(false);

  const [templates, setTemplates] = useState([]);
  const [templatePreview, setTemplatePreview] = useState(null);
  const [templateLoading, setTemplateLoading] = useState(false);
  const [templateSelectionDirty, setTemplateSelectionDirty] = useState(false);

  const [profiles, setProfiles] = useState([]);
  const [selectedProfiles, setSelectedProfiles] = useState([]);
  const [profileQuery, setProfileQuery] = useState("");

  const [tagRows, setTagRows] = useState(tagsToRows({}));

  const [interfaces, setInterfaces] = useState([]);
  const [interfacesLoading, setInterfacesLoading] = useState(false);
  const [discovering, setDiscovering] = useState(false);

  useEffect(() => {
    if (location.state?.success) {
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [location.pathname, location.state, navigate]);

  useEffect(() => {
    let mounted = true;

    async function loadEditor() {
      try {
        setLoading(true);
        setError("");

        const [groupData, profileData, templateData] = await Promise.all([
          listHostGroups(),
          listProfiles(),
          listTemplates().catch(() => []),
        ]);
        if (!mounted) return;

        setGroups(Array.isArray(groupData) ? groupData : []);
        setProfiles(Array.isArray(profileData) ? profileData : []);
        setTemplates(Array.isArray(templateData) ? templateData : []);

        if (!isEdit) {
          const requestedTemplateId = new URLSearchParams(location.search).get("template_id") || "";
          const templateExists = (Array.isArray(templateData) ? templateData : []).some(
            (template) => String(template.id) === String(requestedTemplateId)
          );

          setForm({
            ...normalizeForm(null),
            template_id: templateExists ? requestedTemplateId : "",
          });
          setSelectedProfiles([]);
          setTagRows(tagsToRows({}));
          setInterfaces([]);
          setTemplatePreview(null);
          setTemplateSelectionDirty(false);
          return;
        }

        const [hostData, hostProfiles, hostInterfaces] = await Promise.all([
          getHost(hostId),
          getHostProfiles(hostId),
          listHostInterfaces(hostId).catch(() => []),
        ]);

        if (!mounted) return;

        setForm(normalizeForm(hostData));
        setSelectedProfiles(Array.isArray(hostProfiles) ? hostProfiles : []);
        setTagRows(tagsToRows(hostData?.tags || {}));
        setInterfaces(Array.isArray(hostInterfaces) ? hostInterfaces : []);
        setTemplatePreview(null);
        setTemplateSelectionDirty(false);
      } catch (loadError) {
        if (!mounted) return;
        setError(loadError?.message || "Falha ao carregar editor do host");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadEditor();
    return () => {
      mounted = false;
    };
  }, [hostId, isEdit, location.search]);

  const selectedGroup = useMemo(() => groupLabel(groups, form.group_id), [form.group_id, groups]);
  const hasPersistableGroup = Boolean(form.group_id);
  const isLegacyWithoutGroup = isEdit && !hasPersistableGroup;
  const selectedTemplate = useMemo(
    () => templateLabel(templates, form.template_id),
    [form.template_id, templates]
  );
  const hasPersistableTemplate = Boolean(form.template_id);
  const isLegacyWithoutTemplate = isEdit && !hasPersistableTemplate;
  const activeTemplates = useMemo(
    () =>
      templates.filter(
        (template) => template.enabled !== false || String(template.id) === String(form.template_id)
      ),
    [form.template_id, templates]
  );

  const selectedProfileIds = useMemo(
    () => new Set(selectedProfiles.map((profile) => Number(profile.profile_id))),
    [selectedProfiles]
  );

  const availableProfiles = useMemo(() => {
    const query = profileQuery.trim().toLowerCase();

    return profiles
      .filter((profile) => !selectedProfileIds.has(Number(profile.id)))
      .filter((profile) => {
        if (!query) return true;
        const haystack = `${profile.display_name || profile.name} ${profile.kind || ""} ${profile.description || ""}`.toLowerCase();
        return haystack.includes(query);
      });
  }, [profileQuery, profiles, selectedProfileIds]);

  useEffect(() => {
    let active = true;

    async function loadTemplateDetails() {
      if (!form.template_id) {
        setTemplatePreview(null);
        setTemplateSelectionDirty(false);
        return;
      }

      try {
        setTemplateLoading(true);
        const preview = await getTemplatePreview(form.template_id);
        if (!active) return;

        setTemplatePreview(preview);
        if (templateSelectionDirty || !isEdit || selectedProfiles.length === 0) {
          setSelectedProfiles(mapTemplateProfiles(preview));
        }
        setTemplateSelectionDirty(false);
      } catch (templateError) {
        if (!active) return;
        setTemplatePreview(null);
        setError(templateError?.message || "Falha ao carregar preview do template");
      } finally {
        if (active) setTemplateLoading(false);
      }
    }

    loadTemplateDetails();

    return () => {
      active = false;
    };
  }, [form.template_id, isEdit, templateSelectionDirty]);

  function setField(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  function setSnmp(field, value) {
    setForm((current) => ({
      ...current,
      snmp_profile: {
        ...current.snmp_profile,
        [field]: value,
      },
    }));
  }

  function setCollectionOverrideEnabled(enabled) {
    setForm((current) => {
      const shouldEnable = Boolean(enabled);
      if (!shouldEnable) {
        return {
          ...current,
          collection_policy_override_enabled: false,
          collection_policy_override: { ...EMPTY_COLLECTION_POLICY_OVERRIDE },
        };
      }

      const nextOverride = hasCollectionPolicyOverride(current.collection_policy_override)
        ? current.collection_policy_override
        : normalizeCollectionPolicyOverride(
            templatePreview?.collection_policy || current.collection_policy_resolved || {}
          );

      return {
        ...current,
        collection_policy_override_enabled: true,
        collection_policy_override: nextOverride,
      };
    });
  }

  function setCollectionOverrideField(field, value) {
    setForm((current) => ({
      ...current,
      collection_policy_override: {
        ...current.collection_policy_override,
        [field]: value,
      },
    }));
  }

  function addTagRow() {
    setTagRows((current) => [...current, { id: makeRowId(), key: "", value: "" }]);
  }

  function updateTagRow(rowId, field, value) {
    setTagRows((current) => current.map((row) => (row.id === rowId ? { ...row, [field]: value } : row)));
  }

  function removeTagRow(rowId) {
    setTagRows((current) => {
      const next = current.filter((row) => row.id !== rowId);
      return next.length ? next : [{ id: makeRowId(), key: "", value: "" }];
    });
  }

  async function reloadGroups() {
    const groupData = await listHostGroups();
    setGroups(Array.isArray(groupData) ? groupData : []);
  }

  async function handleGroupCreate(event) {
    event.preventDefault();

    try {
      setGroupSaving(true);
      setError("");
      const created = await createHostGroup(groupForm);
      await reloadGroups();
      setField("group_id", String(created.id));
      setGroupForm(DEFAULT_GROUP_FORM);
      setGroupCreateOpen(false);
      setSuccess(`Grupo "${created.name}" criado e selecionado.`);
    } catch (groupError) {
      setError(groupError?.message || "Falha ao criar grupo");
    } finally {
      setGroupSaving(false);
    }
  }

  function addProfile(profile) {
    setSelectedProfiles((current) => [
      ...current,
      {
        profile_id: profile.id,
        name: profile.name,
        display_name: profile.display_name,
        description: profile.description,
        kind: profile.kind,
        params: {},
        enabled: true,
      },
    ]);
  }

  function removeProfile(profileId) {
    setSelectedProfiles((current) =>
      current.filter((profile) => Number(profile.profile_id) !== Number(profileId))
    );
  }

  async function refreshInterfaces() {
    if (!hostId) return;

    try {
      setInterfacesLoading(true);
      const hostInterfaces = await listHostInterfaces(hostId);
      setInterfaces(Array.isArray(hostInterfaces) ? hostInterfaces : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar interfaces");
    } finally {
      setInterfacesLoading(false);
    }
  }

  async function handleDiscoverInterfaces() {
    if (!hostId) return;

    try {
      setDiscovering(true);
      setError("");
      await discoverHostInterfaces(hostId);
      await refreshInterfaces();
      setSuccess("Interfaces descobertas com sucesso.");
    } catch (discoverError) {
      setError(discoverError?.message || "Falha ao executar discovery");
    } finally {
      setDiscovering(false);
    }
  }

  async function toggleInterface(row) {
    if (!hostId) return;

    try {
      const updated = await updateHostInterface(hostId, row.id, { selected: !row.selected });
      setInterfaces((current) => current.map((item) => (item.id === updated.id ? updated : item)));
    } catch (toggleError) {
      setError(toggleError?.message || "Falha ao atualizar interface");
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();

    if (!hasPersistableGroup) {
      setError(
        isEdit
          ? "Este host legado ainda está sem grupo. Selecione um grupo antes de salvar."
          : "Selecione um grupo antes de salvar o host."
      );
      setSuccess("");
      setActiveTab("group");
      return;
    }

    if (!hasPersistableTemplate) {
      setError(
        isEdit
          ? "Este host legado ainda está sem template. Selecione um template antes de salvar."
          : "Selecione um template antes de salvar o host."
      );
      setSuccess("");
      setActiveTab("profiles");
      return;
    }

    try {
      setSaving(true);
      setError("");
      setSuccess("");

      const payload = {
        ...form,
        tags: rowsToTags(tagRows),
        collection_policy_override: buildCollectionPolicyOverridePayload(
          form.collection_policy_override,
          form.collection_policy_override_enabled
        ),
      };

      if (isEdit) {
        await updateHost(hostId, payload);
        await updateHostProfiles(hostId, selectedProfiles);
        setSuccess("Host atualizado com sucesso.");
      } else {
        const created = await createHost(payload);
        await updateHostProfiles(created.id, selectedProfiles);
        navigate(`/data-collection/hosts/${created.id}/edit`, {
          replace: true,
          state: { success: "Host criado com sucesso." },
        });
        return;
      }
    } catch (submitError) {
      setError(submitError?.message || "Falha ao salvar host");
    } finally {
      setSaving(false);
    }
  }

  function renderGeneral() {
    return (
      <Card
        title="Identidade do host"
        subtitle="Primeira etapa do cadastro: nome, IP e estado principal do ativo."
      >
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr),360px]">
          <div className="space-y-5">
            {!hasPersistableGroup ? (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-4 text-sm text-amber-100">
                {isLegacyWithoutGroup
                  ? "Host legado sem grupo definido. Este cadastro precisa ser associado a um grupo antes de qualquer salvamento."
                  : "Grupo obrigatório. Escolha um grupo na aba Grupo antes de concluir o cadastro."}
              </div>
            ) : null}
            {!hasPersistableTemplate ? (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-4 text-sm text-amber-100">
                {isLegacyWithoutTemplate
                  ? "Host legado sem template definido. Selecione um template para normalizar este cadastro."
                  : "Template obrigatório. Escolha um template na aba Templates de monitoramento antes de concluir o cadastro."}
              </div>
            ) : null}
            <div>
              <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Nome do host</label>
              <input
                value={form.name}
                onChange={(event) => setField("name", event.target.value)}
                className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                placeholder="Ex.: lab-linux-01"
                required
              />
            </div>
            <div>
              <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Endereço IP</label>
              <input
                value={form.ip}
                onChange={(event) => setField("ip", event.target.value)}
                className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                placeholder="172.30.10.10"
                required
              />
            </div>
            <label className="inline-flex items-center gap-3 rounded-md border border-white/10 bg-slate-950 px-3 py-3">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(event) => setField("enabled", event.target.checked)}
              />
              <span className="text-sm text-slate-200">{form.enabled ? "Host ativo" : "Host inativo"}</span>
            </label>
          </div>

          <div className="space-y-4 rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500">Grupo atual</div>
              <div className="mt-1 text-sm font-medium text-white">
                {hasPersistableGroup ? selectedGroup : isLegacyWithoutGroup ? "Sem grupo legado" : "Obrigatório"}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500">SNMP</div>
              <div className="mt-1 text-sm font-medium text-white">
                {String(form.snmp_profile?.version || "v2c").toUpperCase()}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500">Profiles</div>
              <div className="mt-1 text-sm font-medium text-white">{selectedProfiles.length} vinculados</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500">Template</div>
              <div className="mt-1 text-sm font-medium text-white">
                {hasPersistableTemplate
                  ? selectedTemplate
                  : isLegacyWithoutTemplate
                  ? "Sem template legado"
                  : "Obrigatório"}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500">Interfaces</div>
              <div className="mt-1 text-sm font-medium text-white">
                {isEdit ? `${interfaces.length} descobertas` : "Disponível após salvar"}
              </div>
            </div>
          </div>
        </div>
      </Card>
    );
  }

  function renderGroup() {
    return (
      <Card
        title="Grupo"
        subtitle="Grupo é obrigatório. Selecione um grupo existente ou use a criação rápida inline para cadastrar um novo grupo."
      >
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr),380px]">
          <div className="space-y-5">
            {!hasPersistableGroup ? (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-4 text-sm text-amber-100">
                {isLegacyWithoutGroup
                  ? "Host legado detectado sem grupo. Selecione um grupo existente ou crie um novo grupo para regularizar este cadastro."
                  : "Selecione um grupo para habilitar o salvamento do host."}
              </div>
            ) : null}
            <div>
              <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Grupo principal *</label>
              <select
                value={form.group_id}
                onChange={(event) => setField("group_id", event.target.value)}
                className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                required
              >
                <option value="" disabled>
                  Selecione um grupo
                </option>
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.path || group.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-medium text-white">Criação rápida</div>
                  <p className="mt-1 text-sm text-slate-400">Crie grupos sem sair do fluxo de edição.</p>
                </div>
                <button
                  type="button"
                  onClick={() => setGroupCreateOpen((current) => !current)}
                  className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-sm text-sky-100 hover:bg-sky-500/20"
                >
                  {groupCreateOpen ? "Fechar" : "Criar grupo"}
                </button>
              </div>

              {groupCreateOpen ? (
                <form onSubmit={handleGroupCreate} className="mt-4 grid gap-4 lg:grid-cols-2">
                  <div>
                    <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Nome</label>
                    <input
                      value={groupForm.name}
                      onChange={(event) =>
                        setGroupForm((current) => ({ ...current, name: event.target.value }))
                      }
                      className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                      required
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Grupo pai</label>
                    <select
                      value={groupForm.parent_id}
                      onChange={(event) =>
                        setGroupForm((current) => ({ ...current, parent_id: event.target.value }))
                      }
                      className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                    >
                      <option value="">Sem grupo pai</option>
                      {groups.map((group) => (
                        <option key={group.id} value={group.id}>
                          {group.path || group.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="lg:col-span-2 flex justify-end">
                    <button
                      type="submit"
                      disabled={groupSaving}
                      className="rounded-md bg-sky-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
                    >
                      {groupSaving ? "Criando grupo..." : "Criar e selecionar grupo"}
                    </button>
                  </div>
                </form>
              ) : null}
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <div className="text-sm font-medium text-white">Grupos disponíveis</div>
            <div className="mt-3 max-h-[380px] space-y-2 overflow-y-auto">
              {groups.map((group) => {
                const selected = String(group.id) === String(form.group_id);
                return (
                  <button
                    type="button"
                    key={group.id}
                    onClick={() => setField("group_id", String(group.id))}
                    className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm ${
                      selected
                        ? "border-sky-400/40 bg-sky-500/10 text-sky-100"
                        : "border-white/10 bg-slate-900 text-slate-200 hover:bg-slate-800"
                    }`}
                  >
                    <span>{group.path || group.name}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </Card>
    );
  }

  function renderSnmp() {
    return (
      <Card title="SNMP" subtitle="Configuração de acesso SNMP organizada em blocos mais compactos e legíveis.">
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Versão</label>
            <select
              value={form.snmp_profile.version || "v2c"}
              onChange={(event) => setSnmp("version", event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            >
              <option value="v1">SNMP v1</option>
              <option value="v2c">SNMP v2c</option>
            </select>
          </div>
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Community</label>
            <input
              value={form.snmp_profile.community || ""}
              onChange={(event) => setSnmp("community", event.target.value)}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
          </div>
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Porta</label>
            <input
              type="number"
              value={form.snmp_profile.port ?? 161}
              onChange={(event) => setSnmp("port", parseInt(event.target.value || "161", 10))}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
          </div>
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Retries</label>
            <input
              type="number"
              value={form.snmp_profile.retries ?? 1}
              onChange={(event) => setSnmp("retries", parseInt(event.target.value || "1", 10))}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
          </div>
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4 xl:col-span-2">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Timeout</label>
            <input
              type="number"
              value={form.snmp_profile.timeout ?? 1}
              onChange={(event) => setSnmp("timeout", parseInt(event.target.value || "1", 10))}
              className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
          </div>
        </div>
      </Card>
    );
  }

  function renderProfilesLegacy() {
    return (
      <Card
        title="Templates de monitoramento"
        subtitle="Profiles organizados em um fluxo compacto: vinculados à esquerda e catálogo filtrável à direita."
      >
        <div className="grid gap-6 xl:grid-cols-2">
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <div className="flex items-center justify-between gap-3">
            <div className="text-sm font-medium text-white">Profiles vinculados</div>
              <div className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs text-slate-300">
                {selectedProfiles.length}
              </div>
            </div>
            <div className="mt-4 overflow-hidden rounded-lg border border-white/10">
              {selectedProfiles.length ? (
                <table className="min-w-full text-sm">
                  <thead className="bg-slate-900 text-left text-slate-300">
                    <tr>
                      <th className="px-3 py-2">Profile</th>
                      <th className="px-3 py-2">Tipo</th>
                      <th className="px-3 py-2 text-right">Ação</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedProfiles.map((profile) => (
                      <tr key={profile.profile_id} className="border-t border-white/10 bg-slate-950/40">
                        <td className="px-3 py-2">
                          <div className="font-medium text-white">{profile.display_name || profile.name}</div>
                          {profile.description ? <div className="text-xs text-slate-500">{profile.description}</div> : null}
                        </td>
                        <td className="px-3 py-2 text-slate-300">{profile.kind || "-"}</td>
                        <td className="px-3 py-2 text-right">
                          <button
                            type="button"
                            onClick={() => removeProfile(profile.profile_id)}
                            className="rounded-md border border-white/10 bg-slate-900 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-800"
                          >
                            Remover
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="px-4 py-8 text-center text-sm text-slate-400">Nenhum profile vinculado ainda.</div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <div className="text-sm font-medium text-white">Catálogo disponível</div>
            <input
              value={profileQuery}
              onChange={(event) => setProfileQuery(event.target.value)}
              placeholder="Buscar por nome, tipo ou descrição..."
              className="mt-4 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
            />
            <div className="mt-4 max-h-[420px] space-y-2 overflow-y-auto pr-1">
              {availableProfiles.length ? (
                availableProfiles.map((profile) => (
                  <div key={profile.id} className="rounded-lg border border-white/10 bg-slate-900/80 p-3">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="font-medium text-white">{profile.display_name || profile.name}</div>
                        <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">{profile.kind || "profile"}</div>
                        {profile.description ? <div className="mt-2 text-sm text-slate-400">{profile.description}</div> : null}
                      </div>
                      <button
                        type="button"
                        onClick={() => addProfile(profile)}
                        className="rounded-md bg-sky-500 px-3 py-2 text-xs font-medium text-white hover:bg-sky-600"
                      >
                        Adicionar
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div className="rounded-lg border border-dashed border-white/10 px-4 py-8 text-center text-sm text-slate-400">
                  Nenhum profile disponível para este filtro.
                </div>
              )}
            </div>
          </div>
        </div>
      </Card>
    );
  }

  void renderProfilesLegacy;

  function renderProfiles() {
    const capabilityItems = templateCapabilities(templatePreview);
    const derivedTemplateProfiles = mapTemplateProfiles(templatePreview);
    const monitorItems = Array.isArray(templatePreview?.preview?.monitors)
      ? templatePreview.preview.monitors
      : [];
    const signalItems = Array.isArray(templatePreview?.preview?.signals)
      ? templatePreview.preview.signals
      : [];
    const discoveryItems = Array.isArray(templatePreview?.preview?.discovery)
      ? templatePreview.preview.discovery
      : [];

    return (
      <Card
        title="Templates de monitoramento"
        subtitle="Escolha primeiro o template principal do host. Os profiles ficam subordinados ao template e aparecem abaixo como camada técnica."
      >
        <div className="space-y-6">
          <div className="grid gap-6 xl:grid-cols-[minmax(0,1.1fr),minmax(360px,0.9fr)]">
            <div className="space-y-5 rounded-xl border border-white/10 bg-slate-950/40 p-5">
              {!hasPersistableTemplate ? (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-4 text-sm text-amber-100">
                  {isLegacyWithoutTemplate
                    ? "Host legado sem template. Escolha um template para regularizar o cadastro antes de salvar."
                    : "Template obrigatório. Escolha um template principal para definir o pacote padrão de monitoramento."}
                </div>
              ) : null}

              <div>
                <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Template principal *
                </label>
                <select
                  value={form.template_id}
                  onChange={(event) => {
                    setTemplateSelectionDirty(true);
                    setField("template_id", event.target.value);
                  }}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                  required
                >
                  <option value="" disabled>
                    Selecione um template
                  </option>
                  {activeTemplates.map((template) => (
                    <option key={template.id} value={template.id}>
                      {template.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-900/70 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-medium text-white">Lógica de produto</div>
                    <p className="mt-1 text-sm text-slate-400">
                      O usuário escolhe grupo e template primeiro; detalhes técnicos ficam abaixo.
                    </p>
                  </div>
                  <Link
                    to="/data-collection/templates"
                    className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-sm text-sky-100 hover:bg-sky-500/20"
                  >
                    Abrir catálogo
                  </Link>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-medium text-white">Preview do template</div>
                  <p className="mt-1 text-sm text-slate-400">
                    Resumo simples do que o host vai monitorar.
                  </p>
                </div>
                {templatePreview?.enabled === false ? (
                  <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-100">
                    Planejado
                  </span>
                ) : null}
              </div>

              {templateLoading ? (
                <div className="mt-4 rounded-xl border border-white/10 bg-slate-900/70 px-4 py-10 text-center text-sm text-slate-400">
                  Carregando preview do template...
                </div>
              ) : templatePreview ? (
                <div className="mt-4 space-y-4">
                  <div>
                    <div className="text-base font-semibold text-white">{templatePreview.name}</div>
                    <div className="mt-1 text-sm text-slate-400">
                      {[templatePreview.vendor, templatePreview.family, templatePreview.asset_type]
                        .filter(Boolean)
                        .join(" / ")}
                    </div>
                    <p className="mt-3 text-sm leading-6 text-slate-300">
                      {templatePreview.summary || templatePreview.preview?.summary || "Sem resumo disponível."}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {capabilityItems.length ? (
                      capabilityItems.map(([key, label]) => (
                        <span
                          key={key}
                          className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-100"
                        >
                          {label}
                        </span>
                      ))
                    ) : (
                      <span className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-300">
                        Sem capacidades declaradas
                      </span>
                    )}
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="rounded-xl border border-white/10 bg-slate-900/70 p-4">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Monitora</div>
                      <div className="mt-3 space-y-2">
                        {monitorItems.length ? (
                          monitorItems.map((item) => (
                            <div key={item} className="text-sm text-slate-200">
                              {item}
                            </div>
                          ))
                        ) : (
                          <div className="text-sm text-slate-400">Sem itens de preview.</div>
                        )}
                      </div>
                    </div>

                    <div className="rounded-xl border border-white/10 bg-slate-900/70 p-4">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Capacidade derivada</div>
                      <div className="mt-3 space-y-2">
                        <div className="text-sm text-slate-200">
                          {derivedTemplateProfiles.length} profile(s) derivados do template
                        </div>
                        <div className="text-sm text-slate-200">
                          {discoveryItems.length
                            ? discoveryItems.join(" / ")
                            : "Sem descoberta específica disponível"}
                        </div>
                        <div className="text-sm text-slate-200">
                          {signalItems.length
                            ? signalItems.slice(0, 3).join(" / ")
                            : "Sem sinais destacados"}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="mt-4 rounded-xl border border-dashed border-white/10 bg-slate-900/70 px-4 py-10 text-center text-sm text-slate-400">
                  Selecione um template para visualizar o preview do monitoramento.
                </div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-950/30 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-white">Profiles vinculados e ajustes avançados</div>
                <p className="mt-1 text-sm text-slate-400">
                  O template define o conjunto padrão. Os profiles abaixo mostram o que está efetivamente vinculado ao host.
                </p>
              </div>
              <div className="rounded-full border border-white/10 bg-slate-900 px-2.5 py-1 text-xs text-slate-300">
                {selectedProfiles.length} profile(s)
              </div>
            </div>

            <div className="mt-5 grid gap-6 xl:grid-cols-2">
              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                <div className="text-sm font-medium text-white">Profiles aplicados ao host</div>
                <div className="mt-4 overflow-hidden rounded-lg border border-white/10">
                  {selectedProfiles.length ? (
                    <table className="min-w-full text-sm">
                      <thead className="bg-slate-900 text-left text-slate-300">
                        <tr>
                          <th className="px-3 py-2">Profile</th>
                          <th className="px-3 py-2">Tipo</th>
                          <th className="px-3 py-2 text-right">Ação</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedProfiles.map((profile) => (
                          <tr key={profile.profile_id} className="border-t border-white/10 bg-slate-950/40">
                            <td className="px-3 py-2">
                              <div className="font-medium text-white">{profile.display_name || profile.name}</div>
                              {profile.description ? (
                                <div className="text-xs text-slate-500">{profile.description}</div>
                              ) : null}
                            </td>
                            <td className="px-3 py-2 text-slate-300">{profile.kind || "-"}</td>
                            <td className="px-3 py-2 text-right">
                              <button
                                type="button"
                                onClick={() => removeProfile(profile.profile_id)}
                                className="rounded-md border border-white/10 bg-slate-900 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-800"
                              >
                                Remover
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="px-4 py-8 text-center text-sm text-slate-400">
                      Nenhum profile derivado ainda.
                    </div>
                  )}
                </div>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
                <div className="text-sm font-medium text-white">Catálogo técnico</div>
                <input
                  value={profileQuery}
                  onChange={(event) => setProfileQuery(event.target.value)}
                  placeholder="Buscar por nome, tipo ou descrição..."
                  className="mt-4 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                />
                <div className="mt-4 max-h-[360px] space-y-2 overflow-y-auto pr-1">
                  {availableProfiles.length ? (
                    availableProfiles.map((profile) => (
                      <div key={profile.id} className="rounded-lg border border-white/10 bg-slate-900/80 p-3">
                        <div className="flex items-start justify-between gap-4">
                          <div className="min-w-0">
                            <div className="font-medium text-white">{profile.display_name || profile.name}</div>
                            <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">
                              {profile.kind || "profile"}
                            </div>
                            {profile.description ? (
                              <div className="mt-2 text-sm text-slate-400">{profile.description}</div>
                            ) : null}
                          </div>
                          <button
                            type="button"
                            onClick={() => addProfile(profile)}
                            className="rounded-md bg-sky-500 px-3 py-2 text-xs font-medium text-white hover:bg-sky-600"
                          >
                            Adicionar
                          </button>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="rounded-lg border border-dashed border-white/10 px-4 py-8 text-center text-sm text-slate-400">
                      Nenhum profile disponível para este filtro.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </Card>
    );
  }

  function renderInterfaces() {
    if (!isEdit) {
      return (
        <PlaceholderCard
          title="Interfaces"
          body="Salve o host primeiro para liberar a descoberta de interfaces. Essa etapa fica isolada em uma aba própria para não pesar o fluxo principal de criação."
          note="Discovery por host disponível após o primeiro salvamento"
        />
      );
    }

    return (
      <Card
        title="Interfaces"
        subtitle="Discovery e seleção de interfaces ficam em uma aba isolada, mantendo o restante da edição mais leve."
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-sm text-slate-400">
            {interfaces.length} interface(s) carregada(s) para este host.
          </div>
          <button
            type="button"
            onClick={handleDiscoverInterfaces}
            disabled={discovering}
            className="rounded-md bg-sky-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
          >
            {discovering ? "Executando discovery..." : "Executar discovery"}
          </button>
        </div>

        <div className="mt-5 overflow-hidden rounded-xl border border-white/10">
          {interfacesLoading ? (
            <div className="px-4 py-10 text-center text-sm text-slate-400">Carregando interfaces...</div>
          ) : interfaces.length ? (
            <table className="min-w-full text-sm">
              <thead className="bg-slate-900 text-left text-slate-300">
                <tr>
                  <th className="px-3 py-2">Monitorar</th>
                  <th className="px-3 py-2">ifIndex</th>
                  <th className="px-3 py-2">Interface</th>
                  <th className="px-3 py-2">Admin</th>
                  <th className="px-3 py-2">Oper</th>
                </tr>
              </thead>
              <tbody>
                {interfaces.map((row) => (
                  <tr key={row.id} className="border-t border-white/10 bg-slate-950/30">
                    <td className="px-3 py-2">
                      <input type="checkbox" checked={!!row.selected} onChange={() => toggleInterface(row)} />
                    </td>
                    <td className="px-3 py-2 text-slate-300">{row.ifindex}</td>
                    <td className="px-3 py-2 text-white">{row.ifdescr}</td>
                    <td className="px-3 py-2 text-slate-300">{row.admin_status === 1 ? "up" : row.admin_status === 2 ? "down" : "-"}</td>
                    <td className="px-3 py-2 text-slate-300">{row.oper_status === 1 ? "up" : row.oper_status === 2 ? "down" : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-4 py-10 text-center text-sm text-slate-400">Nenhuma interface descoberta ainda.</div>
          )}
        </div>
      </Card>
    );
  }

  function renderMetadata() {
    const preview = rowsToTags(tagRows);

    return (
      <Card
        title="Metadados / Parâmetros"
        subtitle="Base atual para tags e parâmetros compatíveis com o backend existente."
      >
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr),360px]">
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="text-sm font-medium text-white">Tags do host</div>
              <button
                type="button"
                onClick={addTagRow}
                className="rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
              >
                Adicionar linha
              </button>
            </div>
            <div className="mt-4 space-y-3">
              {tagRows.map((row) => (
                <div key={row.id} className="grid gap-3 lg:grid-cols-[minmax(0,1fr),minmax(0,1fr),auto]">
                  <input
                    value={row.key}
                    onChange={(event) => updateTagRow(row.id, "key", event.target.value)}
                    className="rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                    placeholder="Chave"
                  />
                  <input
                    value={row.value}
                    onChange={(event) => updateTagRow(row.id, "value", event.target.value)}
                    className="rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                    placeholder='Valor (ex.: "core", "true", "42")'
                  />
                  <button
                    type="button"
                    onClick={() => removeTagRow(row.id)}
                    className="rounded-md border border-white/10 bg-slate-900 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
                  >
                    Remover
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
            <div className="text-sm font-medium text-white">Preview</div>
            <pre className="mt-3 overflow-auto rounded-lg border border-white/10 bg-slate-900 p-3 text-xs leading-6 text-slate-300">
              {JSON.stringify(preview, null, 2)}
            </pre>
          </div>
        </div>
      </Card>
    );
  }

  function renderMonitoring() {
    const templateCollectionPolicy = templatePreview?.collection_policy || form.collection_policy_resolved || {};
    const usingOverride = Boolean(form.collection_policy_override_enabled);
    const effectiveCollectionPolicy = usingOverride
      ? {
          ...templateCollectionPolicy,
          ...buildCollectionPolicyOverridePayload(form.collection_policy_override, true),
        }
      : templateCollectionPolicy;

    const readiness = [
      { label: "Cadastro salvo", value: isEdit ? "Sim" : "Ainda não" },
      { label: "Grupo", value: form.group_id ? "Definido" : "Obrigatório" },
      { label: "Template", value: form.template_id ? selectedTemplate : "Obrigatório" },
      { label: "SNMP", value: form.snmp_profile?.community ? "Configurado" : "Pendente" },
      { label: "Profiles", value: selectedProfiles.length ? `${selectedProfiles.length} vinculados` : "Nenhum" },
      { label: "Interfaces", value: isEdit ? `${interfaces.length} carregadas` : "Aguardando salvamento" },
      { label: "Coleta", value: usingOverride ? "Override por host" : "Padrão do template" },
    ];

    return (
      <Card
        title="Monitoramento / Descoberta"
        subtitle="Painel de prontidão para o host entrar no fluxo operacional do NetGuard."
      >
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
          {readiness.map((item) => (
            <div key={item.label} className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-500">{item.label}</div>
              <div className="mt-2 text-sm font-medium text-white">{item.value}</div>
            </div>
          ))}
        </div>

        <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.2fr),minmax(340px,0.8fr)]">
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-white">Política de coleta e retenção</div>
                <p className="mt-1 text-sm text-slate-400">
                  O template define o intervalo padrão. O host pode aplicar um override apenas quando precisar de uma coleta diferente.
                </p>
              </div>
              <label className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-slate-900 px-3 py-2 text-sm text-slate-200">
                <input
                  type="checkbox"
                  checked={usingOverride}
                  onChange={(event) => setCollectionOverrideEnabled(event.target.checked)}
                />
                Aplicar override por host
              </label>
            </div>

            <div className="mt-5 grid gap-4 md:grid-cols-2">
              <div>
                <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Intervalo ICMP (segundos)
                </label>
                <input
                  type="number"
                  min="5"
                  step="1"
                  value={form.collection_policy_override.icmp_interval_sec}
                  onChange={(event) => setCollectionOverrideField("icmp_interval_sec", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.icmp_interval_sec || 30)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
                />
              </div>

              <div>
                <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Intervalo TCP (segundos)
                </label>
                <input
                  type="number"
                  min="5"
                  step="1"
                  value={form.collection_policy_override.tcp_interval_sec}
                  onChange={(event) => setCollectionOverrideField("tcp_interval_sec", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.tcp_interval_sec || 60)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.snmp_interval_sec}
                  onChange={(event) => setCollectionOverrideField("snmp_interval_sec", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.snmp_interval_sec || 30)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
                />
              </div>

              <div>
                <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Timeout da coleta (segundos)
                </label>
                <input
                  type="number"
                  min="1"
                  step="1"
                  value={form.collection_policy_override.timeout_sec}
                  onChange={(event) => setCollectionOverrideField("timeout_sec", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.timeout_sec || 1)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.retries}
                  onChange={(event) => setCollectionOverrideField("retries", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.retries || 1)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.history_retention_days}
                  onChange={(event) => setCollectionOverrideField("history_retention_days", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.history_retention_days || 30)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.trend_retention_days}
                  onChange={(event) => setCollectionOverrideField("trend_retention_days", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.trend_retention_days || 90)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.log_retention_days}
                  onChange={(event) => setCollectionOverrideField("log_retention_days", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.log_retention_days || 14)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.incident_retention_days}
                  onChange={(event) => setCollectionOverrideField("incident_retention_days", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.incident_retention_days || 180)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.notification_retention_days}
                  onChange={(event) => setCollectionOverrideField("notification_retention_days", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.notification_retention_days || 90)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
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
                  value={form.collection_policy_override.audit_retention_days}
                  onChange={(event) => setCollectionOverrideField("audit_retention_days", event.target.value)}
                  disabled={!usingOverride}
                  placeholder={String(templateCollectionPolicy.audit_retention_days || 365)}
                  className="mt-1 w-full rounded-md border border-white/10 bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400 disabled:opacity-60"
                />
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-dashed border-white/10 bg-slate-900/50 px-4 py-3 text-sm text-slate-300">
              {usingOverride
                ? "O host vai salvar uma política própria de coleta. Se o override for removido, ele volta a seguir o padrão definido no template."
                : "Sem override: o host segue o padrão de coleta do template. Os pollers usam fallback global apenas quando o template não define política própria."}
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-5">
            <div className="text-sm font-medium text-white">Resumo da política aplicada</div>
            <div className="mt-4 space-y-3">
              <div className="rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Template</div>
                <div className="mt-2 text-sm font-medium text-white">
                  {collectionPolicySummary(templateCollectionPolicy)}
                </div>
              </div>
              <div className="rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Host</div>
                <div className="mt-2 text-sm font-medium text-white">
                  {usingOverride
                    ? collectionPolicySummary(
                        buildCollectionPolicyOverridePayload(form.collection_policy_override, true)
                      )
                    : "Sem override salvo"}
                </div>
              </div>
              <div className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-3">
                <div className="text-xs uppercase tracking-wide text-sky-200/70">Efetivo</div>
                <div className="mt-2 text-sm font-medium text-white">
                  {collectionPolicySummary(effectiveCollectionPolicy)}
                </div>
              </div>
            </div>
          </div>
        </div>

        {isEdit ? (
          <div className="mt-5 flex justify-end">
            <Link
              to={`/monitoring/hosts/${hostId}`}
              className="rounded-md bg-sky-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-sky-600"
            >
              Abrir monitoramento do host
            </Link>
          </div>
        ) : null}
      </Card>
    );
  }

  function renderActiveTab() {
    switch (activeTab) {
      case "general":
        return renderGeneral();
      case "group":
        return renderGroup();
      case "snmp":
        return renderSnmp();
      case "profiles":
        return renderProfiles();
      case "interfaces":
        return renderInterfaces();
      case "metadata":
        return renderMetadata();
      case "monitoring":
        return renderMonitoring();
      case "dashboards":
        return (
          <PlaceholderCard
            title="Dashboards"
            body="Dashboards por host e visualizações integradas ao fluxo de configuração."
          />
        );
      case "insights":
        return (
          <PlaceholderCard
            title="IA / Insights"
            body="Resumo automático do host, explicações operacionais e recomendações."
          />
        );
      default:
        return renderGeneral();
    }
  }

  return (
    <>
      <AppShell
        title={isEdit ? "Editar host" : "Novo host"}
        description="Editor de host em Coleta de dados, com grupo e template como base do cadastro."
        maxWidth="max-w-[1680px]"
        contentClassName="pb-32"
        actions={
          <>
            {isEdit ? (
              <Link
                to={`/monitoring/hosts/${hostId}`}
                className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
              >
                Abrir monitoramento
              </Link>
            ) : null}
            <Link
              to="/data-collection/hosts"
              className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
            >
              Voltar à lista
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
          <div className="mb-6 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
            {success}
          </div>
        ) : null}

        <form id="host-editor-form" onSubmit={handleSubmit} className="space-y-6">
          <TabBar tabs={TABS} activeTab={activeTab} onChange={setActiveTab} />
          {loading ? (
            <div className="rounded-2xl border border-white/10 bg-slate-900/70 px-6 py-12 text-center text-sm text-slate-400">
              Carregando editor de host...
            </div>
          ) : (
            renderActiveTab()
          )}
        </form>
      </AppShell>

      <div className="fixed bottom-0 ng-sidebar-offset-left right-0 z-20 border-t border-white/10 bg-slate-950/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1680px] items-center justify-between gap-4 px-6 py-4">
          <div className="text-sm text-slate-400">
            {isEdit ? `Editando host #${hostId}` : "Novo host"} | Aba atual:{" "}
            <span className="text-slate-200">
              {TABS.find((tab) => tab.id === activeTab)?.label || "Host / Geral"}
            </span>
            {!hasPersistableGroup ? (
              <div className="mt-1 text-xs text-amber-200">
                Selecione um grupo para habilitar o salvamento.
              </div>
            ) : null}
            {hasPersistableGroup && !hasPersistableTemplate ? (
              <div className="mt-1 text-xs text-amber-200">
                Selecione um template para habilitar o salvamento.
              </div>
            ) : null}
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => navigate("/data-collection/hosts")}
              className="rounded-md border border-white/10 bg-slate-900 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-800"
            >
              Cancelar
            </button>
            <button
              type="submit"
              form="host-editor-form"
              disabled={saving || loading || !hasPersistableGroup || !hasPersistableTemplate}
              className="rounded-md bg-sky-500 px-5 py-2.5 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
            >
              {saving ? "Salvando..." : isEdit ? "Salvar alterações" : "Salvar host"}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}


