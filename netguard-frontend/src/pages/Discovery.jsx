import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppShell from "../components/AppShell";
import {
  discoverHostInterfaces,
  importDiscoveryResults,
  listDiscoveryRuns,
  listHostGroups,
  listHosts,
  listTemplates,
  promoteDiscoveryResult,
  scanNetworkDiscovery,
} from "../services/hosts";
import { collectHostNow } from "../services/monitoring";
import { formatDateTime, healthClassName, healthLabel } from "../monitoringUi";

const INITIAL_FORM = {
  cidr: "192.168.56.0/24",
  timeout_seconds: 1,
  retries: 1,
  use_icmp: true,
  use_snmp: true,
  snmp_community: "public",
};

function StatCard({ label, value, subtitle, tone = "slate" }) {
  const tones = {
    slate: "border-white/10 bg-slate-900/70",
    sky: "border-sky-500/20 bg-sky-500/10",
    emerald: "border-emerald-500/20 bg-emerald-500/10",
    amber: "border-amber-500/20 bg-amber-500/10",
    red: "border-red-500/20 bg-red-500/10",
  };

  return (
    <div className={`rounded-lg border p-5 ${tones[tone] || tones.slate}`}>
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-3 text-3xl font-semibold text-white">{value}</div>
      {subtitle ? <div className="mt-2 text-sm text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function Badge({ children, className = "border-white/10 bg-slate-800 text-slate-200" }) {
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${className}`}>
      {children}
    </span>
  );
}

function truncate(value, size = 96) {
  const text = String(value || "");
  if (text.length <= size) return text;
  return `${text.slice(0, size - 1)}...`;
}

function isImportable(result) {
  return (
    result &&
    !result.already_registered &&
    !result.existing_host_id &&
    !result.imported_host_id &&
    (result.icmp_status === "up" || result.snmp_status === "up")
  );
}

function hostNeedsAction(host) {
  return !host.template_id || !host.group_id || host.health_status !== "healthy";
}

export default function Discovery() {
  const [form, setForm] = useState(INITIAL_FORM);
  const [hosts, setHosts] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [groups, setGroups] = useState([]);
  const [runs, setRuns] = useState([]);
  const [currentRun, setCurrentRun] = useState(null);
  const [selectedIds, setSelectedIds] = useState([]);
  const [targetGroupId, setTargetGroupId] = useState("");
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [importing, setImporting] = useState(false);
  const [runningAction, setRunningAction] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function loadBaseData() {
    try {
      setLoading(true);
      setError("");
      const [hostData, templateData, groupData, runData] = await Promise.all([
        listHosts({ limit: 1000 }),
        listTemplates().catch(() => []),
        listHostGroups().catch(() => []),
        listDiscoveryRuns(10).catch(() => []),
      ]);
      setHosts(Array.isArray(hostData) ? hostData : []);
      setTemplates(Array.isArray(templateData) ? templateData : []);
      setGroups(Array.isArray(groupData) ? groupData : []);
      setRuns(Array.isArray(runData) ? runData : []);
    } catch (loadError) {
      setError(loadError?.message || "Falha ao carregar descoberta de rede");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadBaseData();
  }, []);

  const results = currentRun?.results || [];
  const importableResults = useMemo(() => results.filter(isImportable), [results]);
  const selectedImportableIds = selectedIds.filter((id) => importableResults.some((item) => item.id === id));
  const templatesById = useMemo(
    () => Object.fromEntries(templates.map((template) => [String(template.id), template])),
    [templates]
  );

  const stats = useMemo(() => {
    return {
      totalHosts: hosts.length,
      actionHosts: hosts.filter(hostNeedsAction).length,
      lastRuns: runs.length,
      found: results.filter((item) => item.icmp_status === "up" || item.snmp_status === "up").length,
      snmp: results.filter((item) => item.snmp_status === "up").length,
      importable: importableResults.length,
    };
  }, [hosts, importableResults.length, results, runs.length]);

  function updateForm(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  function toggleSelected(id, checked) {
    setSelectedIds((current) => {
      if (checked) return Array.from(new Set([...current, id]));
      return current.filter((item) => item !== id);
    });
  }

  async function handleScan(event) {
    event.preventDefault();
    try {
      setScanning(true);
      setError("");
      setSuccess("");
      setSelectedIds([]);
      const run = await scanNetworkDiscovery(form);
      setCurrentRun(run);
      setRuns((current) => [run, ...current.filter((item) => item.id !== run.id)].slice(0, 10));
      setSuccess(`Descoberta concluída: ${run.active_hosts} ativo(s), ${run.snmp_hosts} com SNMP.`);
    } catch (scanError) {
      setError(scanError?.message || "Falha ao executar descoberta");
    } finally {
      setScanning(false);
    }
  }

  async function handleImportSelected() {
    if (!selectedImportableIds.length) return;
    try {
      setImporting(true);
      setError("");
      setSuccess("");
      const result = await importDiscoveryResults({
        result_ids: selectedImportableIds,
        group_id: targetGroupId,
        enable_hosts: true,
        snmp_community: form.snmp_community,
      });
      setSuccess(`${result?.imported_host_ids?.length || 0} host(s) importado(s).`);
      setSelectedIds([]);
      await loadBaseData();
    } catch (importError) {
      setError(importError?.message || "Falha ao importar hosts descobertos");
    } finally {
      setImporting(false);
    }
  }

  async function handleImportOne(result) {
    try {
      setImporting(true);
      setError("");
      setSuccess("");
      await promoteDiscoveryResult(result.id, {
        group_id: targetGroupId,
        enable_hosts: true,
        snmp_community: form.snmp_community,
      });
      setSuccess(`Host ${result.sys_name || result.ip} importado.`);
      await loadBaseData();
    } catch (importError) {
      setError(importError?.message || "Falha ao importar host");
    } finally {
      setImporting(false);
    }
  }

  async function runHostAction(host, action) {
    const key = `${action}-${host.id}`;
    try {
      setRunningAction(key);
      setError("");
      setSuccess("");
      if (action === "collect") {
        await collectHostNow(host.id, "all");
        setSuccess(`Coleta solicitada para ${host.name}.`);
      } else {
        await discoverHostInterfaces(host.id);
        setSuccess(`Inventário SNMP atualizado para ${host.name}.`);
      }
      await loadBaseData();
    } catch (actionError) {
      setError(actionError?.message || "Falha ao executar ação no host");
    } finally {
      setRunningAction("");
    }
  }

  return (
    <AppShell
      title="Descoberta de rede"
      description="Localize dispositivos por CIDR usando ICMP/SNMP e importe ativos para Hosts monitorados com template sugerido."
      actions={
        <>
          <Link
            to="/monitoring/hosts"
            className="rounded-md border border-white/10 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800"
          >
            Hosts monitorados
          </Link>
          <button
            type="button"
            onClick={loadBaseData}
            disabled={loading || scanning}
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-70"
          >
            Atualizar
          </button>
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

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <StatCard label="Hosts cadastrados" value={stats.totalHosts} subtitle="Base atual" tone="sky" />
        <StatCard label="Requer ação" value={stats.actionHosts} subtitle="Sem template, grupo ou saudável" tone="amber" />
        <StatCard label="Execuções" value={stats.lastRuns} subtitle="Histórico recente" tone="slate" />
        <StatCard label="Encontrados" value={stats.found} subtitle="ICMP ou SNMP up" tone="emerald" />
        <StatCard label="SNMP" value={stats.snmp} subtitle="Responderam UDP/161" tone="emerald" />
        <StatCard label="Importáveis" value={stats.importable} subtitle="Ainda não cadastrados" tone="sky" />
      </section>

      <section className="mt-6 rounded-lg border border-white/10 bg-slate-900/60 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Nova descoberta por range</h2>
            <p className="mt-1 text-sm text-slate-400">
              O MVP bloqueia ranges maiores que /24 e só importa dispositivos após ação explícita.
            </p>
          </div>
          <Badge className="border-sky-500/30 bg-sky-500/10 text-sky-100">ICMP + SNMP v2c</Badge>
        </div>

        <form onSubmit={handleScan} className="mt-5 grid gap-4 lg:grid-cols-6">
          <label className="lg:col-span-2">
            <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Range CIDR</span>
            <input
              value={form.cidr}
              onChange={(event) => updateForm("cidr", event.target.value)}
              className="mt-2 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-sky-400"
              placeholder="192.168.56.0/24"
              required
            />
          </label>
          <label>
            <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Timeout</span>
            <input
              type="number"
              min="1"
              max="5"
              value={form.timeout_seconds}
              onChange={(event) => updateForm("timeout_seconds", event.target.value)}
              className="mt-2 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-sky-400"
            />
          </label>
          <label>
            <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Tentativas</span>
            <input
              type="number"
              min="0"
              max="3"
              value={form.retries}
              onChange={(event) => updateForm("retries", event.target.value)}
              className="mt-2 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-sky-400"
            />
          </label>
          <label className="lg:col-span-2">
            <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Community SNMP v2c</span>
            <input
              value={form.snmp_community}
              onChange={(event) => updateForm("snmp_community", event.target.value)}
              className="mt-2 w-full rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-sky-400"
              placeholder="public"
            />
          </label>

          <div className="lg:col-span-4 flex flex-wrap items-center gap-4">
            <label className="inline-flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={form.use_icmp}
                onChange={(event) => updateForm("use_icmp", event.target.checked)}
              />
              Usar ICMP
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={form.use_snmp}
                onChange={(event) => updateForm("use_snmp", event.target.checked)}
              />
              Usar SNMP
            </label>
          </div>
          <div className="lg:col-span-2 flex justify-end">
            <button
              type="submit"
              disabled={scanning}
              className="w-full rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-600 disabled:opacity-70 lg:w-auto"
            >
              {scanning ? "Executando..." : "Iniciar descoberta"}
            </button>
          </div>
        </form>
      </section>

      <section className="mt-6 rounded-lg border border-white/10 bg-slate-900/60">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-5">
          <div>
            <h2 className="text-lg font-semibold text-white">Resultados</h2>
            <p className="mt-1 text-sm text-slate-400">
              Templates são sugeridos por sysDescr/sysObjectID quando SNMP responde.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <select
              value={targetGroupId}
              onChange={(event) => setTargetGroupId(event.target.value)}
              className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none focus:border-sky-400"
            >
              <option value="">Grupo discovery padrão</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.path || group.name}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => setSelectedIds(importableResults.map((item) => item.id))}
              disabled={!importableResults.length}
              className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50"
            >
              Selecionar importáveis
            </button>
            <button
              type="button"
              onClick={handleImportSelected}
              disabled={!selectedImportableIds.length || importing}
              className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-600 disabled:opacity-60"
            >
              {importing ? "Importando..." : `Importar selecionados (${selectedImportableIds.length})`}
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3">Sel.</th>
                <th className="px-4 py-3">IP</th>
                <th className="px-4 py-3">ICMP</th>
                <th className="px-4 py-3">SNMP</th>
                <th className="px-4 py-3">sysName</th>
                <th className="px-4 py-3">sysDescr</th>
                <th className="px-4 py-3">Vendor</th>
                <th className="px-4 py-3">Template sugerido</th>
                <th className="px-4 py-3">Cadastro</th>
                <th className="px-4 py-3 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10 text-slate-200">
              {results.length ? (
                results.map((result) => {
                  const importable = isImportable(result);
                  const checked = selectedIds.includes(result.id);
                  return (
                    <tr key={result.id} className="hover:bg-slate-950/40">
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={!importable}
                          onChange={(event) => toggleSelected(result.id, event.target.checked)}
                        />
                      </td>
                      <td className="px-4 py-3 font-medium text-white">{result.ip}</td>
                      <td className="px-4 py-3">
                        <Badge
                          className={
                            result.icmp_status === "up"
                              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                              : "border-slate-500/30 bg-slate-500/10 text-slate-300"
                          }
                        >
                          {result.icmp_status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        <Badge
                          className={
                            result.snmp_status === "up"
                              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                              : "border-slate-500/30 bg-slate-500/10 text-slate-300"
                          }
                        >
                          {result.snmp_status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">{result.sys_name || "-"}</td>
                      <td className="px-4 py-3 text-slate-400">{truncate(result.sys_descr)}</td>
                      <td className="px-4 py-3">{result.detected_vendor || "-"}</td>
                      <td className="px-4 py-3">
                        {result.suggested_template_name || result.suggested_template_slug || "-"}
                      </td>
                      <td className="px-4 py-3">
                        {result.already_registered || result.existing_host_id ? (
                          <Badge className="border-amber-500/30 bg-amber-500/10 text-amber-100">
                            Já cadastrado
                          </Badge>
                        ) : result.imported_host_id ? (
                          <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-100">
                            Importado
                          </Badge>
                        ) : (
                          <Badge>Não cadastrado</Badge>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => handleImportOne(result)}
                          disabled={!importable || importing}
                          className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                        >
                          Importar
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="10" className="px-4 py-10 text-center text-slate-500">
                    Execute uma descoberta para listar dispositivos ativos.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_360px]">
        <div className="rounded-lg border border-white/10 bg-slate-900/60">
          <div className="border-b border-white/10 p-5">
            <h2 className="text-lg font-semibold text-white">Hosts já cadastrados</h2>
            <p className="mt-1 text-sm text-slate-400">
              Fluxo preservado para coleta sob demanda e inventário de interfaces SNMP.
            </p>
          </div>
          <div className="divide-y divide-white/10">
            {(loading ? [] : hosts.slice(0, 8)).map((host) => {
              const template = templatesById[String(host.template_id)];
              return (
                <div key={host.id} className="flex flex-wrap items-center justify-between gap-4 p-4">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link to={`/monitoring/hosts/${host.id}`} className="font-medium text-white hover:text-sky-200">
                        {host.name}
                      </Link>
                      <Badge className={healthClassName(host.health_status)}>
                        {healthLabel(host.health_status)}
                      </Badge>
                    </div>
                    <div className="mt-1 text-sm text-slate-400">
                      {host.ip} | {template?.name || host.template_name || "Sem template"} |{" "}
                      {host.group_path || host.group_name || "Sem grupo"}
                    </div>
                    {host.health_reason ? (
                      <div className="mt-1 text-xs text-slate-500">{host.health_reason}</div>
                    ) : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => runHostAction(host, "interfaces")}
                      disabled={runningAction === `interfaces-${host.id}`}
                      className="rounded-md border border-white/10 bg-slate-950 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-60"
                    >
                      {runningAction === `interfaces-${host.id}` ? "Atualizando..." : "Inventário SNMP"}
                    </button>
                    <button
                      type="button"
                      onClick={() => runHostAction(host, "collect")}
                      disabled={runningAction === `collect-${host.id}`}
                      className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-100 hover:bg-emerald-500/20 disabled:opacity-60"
                    >
                      {runningAction === `collect-${host.id}` ? "Solicitando..." : "Coletar agora"}
                    </button>
                  </div>
                </div>
              );
            })}
            {!loading && !hosts.length ? (
              <div className="p-8 text-center text-sm text-slate-500">Nenhum host cadastrado.</div>
            ) : null}
          </div>
        </div>

        <div className="rounded-lg border border-white/10 bg-slate-900/60 p-5">
          <h2 className="text-lg font-semibold text-white">Execuções recentes</h2>
          <div className="mt-4 space-y-3">
            {runs.length ? (
              runs.map((run) => (
                <button
                  key={run.id}
                  type="button"
                  onClick={() => setCurrentRun(run)}
                  className="w-full rounded-lg border border-white/10 bg-slate-950/50 p-3 text-left hover:bg-slate-950"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-medium text-white">{run.cidr}</span>
                    <Badge
                      className={
                        run.status === "completed"
                          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                          : run.status === "failed"
                          ? "border-rose-500/30 bg-rose-500/10 text-rose-100"
                          : "border-sky-500/30 bg-sky-500/10 text-sky-100"
                      }
                    >
                      {run.status}
                    </Badge>
                  </div>
                  <div className="mt-2 text-xs text-slate-500">
                    {formatDateTime(run.started_at)} | ativos {run.active_hosts} | SNMP {run.snmp_hosts}
                  </div>
                </button>
              ))
            ) : (
              <p className="text-sm text-slate-500">Nenhuma execução registrada ainda.</p>
            )}
          </div>
        </div>
      </section>
    </AppShell>
  );
}
