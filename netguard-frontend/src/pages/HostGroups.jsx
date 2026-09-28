import React, { useEffect, useMemo, useState } from "react";
import AppShell from "../components/AppShell";
import GrafanaDashboardCard from "../components/GrafanaDashboardCard";
import { getGroupDashboards } from "../services/dashboards";
import { createHostGroup, listHostGroups, listHostGroupsTree } from "../services/hosts";

const INITIAL_FORM = {
  name: "",
  parent_id: "",
};

function normalizeGroup(raw) {
  if (!raw || typeof raw !== "object") return null;

  const id = Number(raw.id);
  if (!Number.isFinite(id)) return null;

  return {
    id,
    name: String(raw.name || `Grupo ${id}`),
    slug: String(raw.slug || ""),
    parent_id:
      raw.parent_id === null || raw.parent_id === undefined || raw.parent_id === ""
        ? null
        : Number(raw.parent_id),
    path: String(raw.path || raw.name || `group-${id}`),
    tags: raw.tags && typeof raw.tags === "object" ? raw.tags : {},
    enabled: raw.enabled !== false,
    children: Array.isArray(raw.children) ? raw.children : [],
  };
}

function flattenGroupTree(nodes, acc = []) {
  if (!Array.isArray(nodes)) return acc;

  nodes.forEach((node) => {
    const normalized = normalizeGroup(node);
    if (!normalized) return;
    acc.push(normalized);
    if (Array.isArray(node.children) && node.children.length) {
      flattenGroupTree(node.children, acc);
    }
  });

  return acc;
}

function mergeGroups(flatData, treeData) {
  const byId = new Map();

  const addMany = (items) => {
    items.forEach((item) => {
      const normalized = normalizeGroup(item);
      if (!normalized) return;
      byId.set(normalized.id, normalized);
    });
  };

  addMany(Array.isArray(flatData) ? flatData : []);
  addMany(flattenGroupTree(treeData, []));

  return Array.from(byId.values()).sort((a, b) => String(a.path).localeCompare(String(b.path), "pt-BR"));
}

export default function HostGroups() {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [form, setForm] = useState(INITIAL_FORM);
  const [selectedGroupId, setSelectedGroupId] = useState(null);
  const [groupDashboards, setGroupDashboards] = useState([]);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState("");

  useEffect(() => {
    let mounted = true;

    async function load() {
      try {
        setLoading(true);
        setError("");

        const [flatResult, treeResult] = await Promise.allSettled([
          listHostGroups(),
          listHostGroupsTree(),
        ]);

        const flatData = flatResult.status === "fulfilled" ? flatResult.value : [];
        const treeData = treeResult.status === "fulfilled" ? treeResult.value : [];
        const merged = mergeGroups(flatData, treeData);

        if (!mounted) return;

        if (!merged.length && flatResult.status === "rejected" && treeResult.status === "rejected") {
          throw flatResult.reason || treeResult.reason || new Error("Falha ao carregar grupos de hosts.");
        }

        setGroups(merged);
      } catch (loadError) {
        if (!mounted) return;
        setError(loadError?.message || "Falha ao carregar grupos de hosts.");
        setGroups([]);
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
    if (!groups.length) {
      setSelectedGroupId(null);
      setGroupDashboards([]);
      return;
    }

    setSelectedGroupId((current) => {
      const normalizedCurrent = Number(current);
      if (Number.isFinite(normalizedCurrent) && groups.some((group) => group.id === normalizedCurrent)) {
        return normalizedCurrent;
      }

      const labGroup = groups.find((group) => String(group.name || "").trim().toLowerCase() === "lab");
      return labGroup?.id || groups[0].id;
    });
  }, [groups]);

  useEffect(() => {
    if (!selectedGroupId) {
      setGroupDashboards([]);
      setDashboardError("");
      return;
    }

    let mounted = true;

    async function loadDashboards() {
      try {
        setDashboardLoading(true);
        setDashboardError("");
        const data = await getGroupDashboards(selectedGroupId);
        if (!mounted) return;
        setGroupDashboards(Array.isArray(data) ? data : []);
      } catch (loadError) {
        if (!mounted) return;
        setDashboardError(loadError?.message || "Falha ao carregar o dashboard do grupo.");
        setGroupDashboards([]);
      } finally {
        if (mounted) setDashboardLoading(false);
      }
    }

    loadDashboards();
    return () => {
      mounted = false;
    };
  }, [selectedGroupId]);

  const parentLabels = useMemo(() => {
    const map = new Map();
    groups.forEach((group) => {
      map.set(group.id, group.path || group.name);
    });
    return map;
  }, [groups]);

  const selectedGroup = useMemo(
    () => groups.find((group) => group.id === selectedGroupId) || null,
    [groups, selectedGroupId]
  );

  async function reloadGroups() {
    setLoading(true);
    setError("");
    try {
      const [flatData, treeData] = await Promise.all([
        listHostGroups().catch(() => []),
        listHostGroupsTree().catch(() => []),
      ]);
      setGroups(mergeGroups(flatData, treeData));
    } catch (loadError) {
      setError(loadError?.message || "Falha ao atualizar os grupos de hosts.");
      setGroups([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();

    try {
      setSaving(true);
      setError("");
      setSuccess("");

      await createHostGroup(form);
      await reloadGroups();
      setForm(INITIAL_FORM);
      setSuccess("Grupo criado com sucesso.");
    } catch (submitError) {
      setError(submitError?.message || "Falha ao criar grupo.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <AppShell
      title="Grupos de hosts"
      description="Área de configuração para organizar hosts em grupos e subgrupos simples. A listagem abaixo já alimenta os filtros operacionais e o dashboard por grupo."
      actions={
        <button
          type="button"
          onClick={reloadGroups}
          disabled={loading || saving}
          className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-70"
        >
          {loading ? "Atualizando..." : "Atualizar grupos"}
        </button>
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

      <div className="grid gap-6 xl:grid-cols-[420px,minmax(0,1fr)]">
        <section className="rounded-2xl border border-white/10 bg-slate-900/70 p-6">
          <h2 className="text-lg font-semibold text-white">Criar grupo</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Use grupos para organizar o cadastro de hosts, aplicar filtros operacionais e abrir dashboards
            segmentados por contexto.
          </p>

          <form onSubmit={handleSubmit} className="mt-6 space-y-4">
            <div>
              <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Nome</label>
              <input
                value={form.name}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
                placeholder="Ex.: Campus / Core"
                required
              />
            </div>

            <div>
              <label className="text-xs font-medium uppercase tracking-wide text-slate-500">Grupo pai</label>
              <select
                value={form.parent_id}
                onChange={(event) => setForm((current) => ({ ...current, parent_id: event.target.value }))}
                className="mt-1 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-sky-400"
              >
                <option value="">Sem grupo pai</option>
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.path || group.name}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="submit"
              disabled={saving}
              className="w-full rounded-md bg-sky-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
            >
              {saving ? "Salvando grupo..." : "Salvar grupo"}
            </button>
          </form>
        </section>

        <section className="rounded-2xl border border-white/10 bg-slate-900/70 p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Lista de grupos</h2>
              <p className="mt-2 text-sm text-slate-400">
                Estrutura atual de grupos disponível para cadastro, filtros e visualização operacional.
              </p>
            </div>
            <div className="rounded-full border border-white/10 bg-slate-950 px-3 py-1 text-xs uppercase tracking-wide text-slate-400">
              {groups.length} grupo(s)
            </div>
          </div>

          <div className="mt-6 overflow-hidden rounded-xl border border-white/10">
            {loading ? (
              <div className="px-4 py-10 text-center text-sm text-slate-400">Carregando grupos de hosts...</div>
            ) : groups.length ? (
              <table className="min-w-full text-sm">
                <thead className="bg-slate-950/80 text-left text-slate-300">
                  <tr>
                    <th className="px-4 py-3">Nome</th>
                    <th className="px-4 py-3">Caminho</th>
                    <th className="px-4 py-3">Grupo pai</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3 text-right">Visualização</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((group) => (
                    <tr
                      key={group.id}
                      className={`border-t border-white/10 ${
                        selectedGroupId === group.id ? "bg-sky-500/10" : "bg-slate-950/30"
                      }`}
                    >
                      <td className="px-4 py-3 text-white">{group.name}</td>
                      <td className="px-4 py-3 text-slate-300">{group.path || "-"}</td>
                      <td className="px-4 py-3 text-slate-300">
                        {group.parent_id ? parentLabels.get(group.parent_id) || "-" : "Raiz"}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ${
                            group.enabled
                              ? "bg-emerald-500/20 text-emerald-200"
                              : "bg-slate-500/20 text-slate-200"
                          }`}
                        >
                          {group.enabled ? "Ativo" : "Inativo"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => setSelectedGroupId(group.id)}
                          className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-900"
                        >
                          Ver dashboard
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="px-4 py-10 text-center text-sm text-slate-400">
                Nenhum grupo cadastrado ainda. Crie o primeiro grupo para organizar os hosts do ambiente.
              </div>
            )}
          </div>
        </section>
      </div>

      <section className="mt-6">
        {dashboardError ? (
          <div className="mb-4 rounded-lg border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {dashboardError}
          </div>
        ) : null}

        {dashboardLoading ? (
          <div className="rounded-2xl border border-white/10 bg-slate-900/70 px-6 py-14 text-center text-sm text-slate-400">
            Carregando dashboard do grupo...
          </div>
        ) : groupDashboards.length ? (
          groupDashboards.map((dashboard) => (
            <GrafanaDashboardCard
              key={`group-${dashboard.owner_id}-${dashboard.dashboard_key}`}
              dashboard={dashboard}
              title={selectedGroup ? `Dashboard do grupo ${selectedGroup.name}` : dashboard.title}
              description={
                selectedGroup
                  ? `Visualização operacional do grupo ${selectedGroup.path || selectedGroup.name} dentro do fluxo de Coleta de dados.`
                  : dashboard.description
              }
            />
          ))
        ) : selectedGroup ? (
          <div className="rounded-2xl border border-dashed border-white/10 bg-slate-900/60 px-6 py-14 text-center">
            <div className="text-lg font-medium text-white">Nenhum dashboard de grupo disponível</div>
            <p className="mt-2 text-sm text-slate-400">
              O grupo selecionado já pode ser usado em filtros e cadastro, mas ainda não recebeu uma visualização
              específica no Grafana.
            </p>
          </div>
        ) : (
          <div className="rounded-2xl border border-dashed border-white/10 bg-slate-900/60 px-6 py-14 text-center">
            <div className="text-lg font-medium text-white">Selecione um grupo para visualizar</div>
            <p className="mt-2 text-sm text-slate-400">
              Escolha um grupo na lista acima para abrir o dashboard filtrado por contexto.
            </p>
          </div>
        )}
      </section>
    </AppShell>
  );
}
