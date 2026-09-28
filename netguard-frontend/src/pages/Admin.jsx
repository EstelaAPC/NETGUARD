import React, { useEffect, useMemo, useState } from "react";
import Breadcrumbs from "../components/Breadcrumbs";
import Sidebar from "../components/Sidebar";
import {
  listUsers,
  updateRole,
  updateUser,
  setActive,
  resetPassword,
  createUser,
  deleteUser,
  listAuditLogs,
} from "../services/users";
import { roleLabel } from "../authz";

const EMPTY_FORM = {
  name: "",
  email: "",
  role: "viewer",
  active: true,
};

function errorMessage(error, fallback) {
  return error?.response?.data?.detail || error?.message || fallback;
}

export default function Admin() {
  const me = useMemo(
    () => JSON.parse(localStorage.getItem("ng_user") || "{}"),
    []
  );

  const isAdmin = me?.role === "admin";

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);

  const [open, setOpen] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [credentialNotice, setCredentialNotice] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);

  function resetFormAndClose() {
    setOpen(false);
    setEditingUser(null);
    setForm(EMPTY_FORM);
    setErr(null);
  }

  async function refresh() {
    try {
      setErr(null);
      setLoading(true);
      const data = await listUsers();
      setUsers(Array.isArray(data) ? data : []);
      setAuditLoading(true);
      const logs = await listAuditLogs(80);
      setAuditLogs(Array.isArray(logs) ? logs : []);
    } catch (e) {
      setErr(errorMessage(e, "Falha ao buscar usuários"));
      setUsers([]);
    } finally {
      setLoading(false);
      setAuditLoading(false);
    }
  }

  useEffect(() => {
    if (!isAdmin) {
      setLoading(false);
      return;
    }
    refresh();
  }, [isAdmin]);

  function ensureAdmin() {
    if (!isAdmin) {
      throw new Error("Apenas administradores podem executar esta ação.");
    }
  }

  function onOpenCreate() {
    try {
      ensureAdmin();
      setEditingUser(null);
      setForm(EMPTY_FORM);
      setErr(null);
      setOpen(true);
    } catch (e) {
      setErr(errorMessage(e, "Acesso negado"));
    }
  }

  function onOpenEdit(user) {
    try {
      ensureAdmin();
      setEditingUser(user);
      setForm({
        name: user.name || "",
        email: user.email || "",
        role: user.role || "viewer",
        active: !!user.active,
      });
      setErr(null);
      setOpen(true);
    } catch (e) {
      setErr(errorMessage(e, "Acesso negado"));
    }
  }

  async function onChangeRole(id, role) {
    try {
      ensureAdmin();
      setErr(null);

      if (me?.id === id) {
        throw new Error("Você não pode alterar seu próprio papel.");
      }

      await updateRole(id, role);
      setUsers((prev) =>
        prev.map((u) => (u.id === id ? { ...u, role } : u))
      );
    } catch (e) {
      setErr(errorMessage(e, "Falha ao alterar papel"));
    }
  }

  async function onToggleActive(id, active) {
    try {
      ensureAdmin();
      setErr(null);

      if (me?.id === id) {
        throw new Error("Você não pode alterar seu próprio status.");
      }

      await setActive(id, active);
      setUsers((prev) =>
        prev.map((u) => (u.id === id ? { ...u, active } : u))
      );
    } catch (e) {
      setErr(errorMessage(e, "Falha ao alterar status"));
    }
  }

async function onResetPassword(id) {
  try {
    ensureAdmin();
    setErr(null);
    const target = users.find((u) => u.id === id);
    if (!target) throw new Error("Usuário não encontrado.");
    if (me?.id === id) {
      throw new Error("Use troca de senha da sessão para alterar sua própria senha.");
    }

    const ok = window.confirm(
      `Gerar uma senha temporária para ${target.name}? O usuário terá que definir uma nova senha no próximo login.`
    );
    if (!ok) return;

    const result = await resetPassword(id);
    if (result?.user) {
      setUsers((prev) =>
        prev.map((u) => (u.id === id ? { ...u, ...result.user } : u))
      );
    }
    setCredentialNotice({
      title: "Senha temporária gerada",
      name: result?.user?.name || target.name,
      email: result?.user?.email || target.email,
      temporaryPassword: result?.temporary_password,
      mode: "reset",
    });
  } catch (e) {
    setErr(errorMessage(e, "Falha ao resetar senha"));
  }
}
  async function onDeleteUser(user) {
    try {
      ensureAdmin();
      setErr(null);

      if (me?.id === user.id) {
        throw new Error("Você não pode excluir seu próprio usuário.");
      }

      const ok = window.confirm(
        `Excluir definitivamente o usuário ${user.name}? Esta ação remove o cadastro de acesso.`
      );
      if (!ok) return;

      await deleteUser(user.id, me?.id);
      setUsers((prev) => prev.filter((u) => u.id !== user.id));
      setCredentialNotice(null);
    } catch (e) {
      setErr(errorMessage(e, "Falha ao excluir usuário"));
    }
  }

  async function onSubmitUser(e) {
    e.preventDefault();

    try {
      ensureAdmin();
      setErr(null);

      const name = form.name.trim();
      const email = form.email.trim().toLowerCase();

      if (!name) throw new Error("Nome é obrigatório.");
      if (!email) throw new Error("E-mail é obrigatório.");

      if (editingUser) {
        if (me?.id === editingUser.id) {
          if (form.role !== editingUser.role) {
            throw new Error("Você não pode alterar seu próprio papel.");
          }
          if (form.active !== editingUser.active) {
            throw new Error("Você não pode alterar seu próprio status.");
          }
        }

        await updateUser(editingUser.id, {
          name,
          email,
          role: form.role,
          active: !!form.active,
        });

        alert("Usuário atualizado com sucesso!");
      } else {
        const result = await createUser({
          name,
          email,
          role: form.role,
          active: !!form.active,
        });

        setCredentialNotice({
          title: "Usuário criado com senha temporária",
          name: result?.user?.name || name,
          email: result?.user?.email || email,
          temporaryPassword: result?.temporary_password,
          mode: "create",
        });
      }

      await refresh();
      resetFormAndClose();
    } catch (e) {
      setErr(errorMessage(e, "Falha ao salvar usuário"));
    }
  }

  if (!isAdmin) {
    return (
      <>
        <Sidebar />
        <div className="ng-shell bg-slate-950 text-white">
          <header className="sticky top-0 z-10 border-b border-white/10 bg-slate-900/50 backdrop-blur">
            <div className="max-w-[1400px] mx-auto px-6 py-3 flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div>
                  <Breadcrumbs />
                  <h1 className="mt-2 font-semibold text-2xl">Administração</h1>
                </div>
                <span className="text-[11px] rounded-full px-2 py-0.5 bg-red-500/10 text-red-300 border border-red-500/30">
                  acesso negado
                </span>
              </div>

              <div className="text-sm text-slate-400">
                {me?.name} ({me?.role})
              </div>
            </div>
          </header>

          <main className="max-w-[1400px] mx-auto px-6 py-8">
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300">
              Apenas administradores podem acessar esta área.
            </div>
          </main>
        </div>
      </>
    );
  }

  return (
    <>
      <Sidebar />

      <div className="ng-shell bg-slate-950 text-white">
        <header className="sticky top-0 z-10 border-b border-white/10 bg-slate-900/50 backdrop-blur">
          <div className="max-w-[1400px] mx-auto px-6 py-3 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div>
                <Breadcrumbs />
                <h1 className="mt-2 font-semibold text-2xl">Administração</h1>
              </div>
              <span className="text-[11px] rounded-full px-2 py-0.5 bg-amber-500/10 text-amber-300 border border-amber-500/30">
                restrito
              </span>
            </div>

            <div className="text-sm text-slate-400">
              {me?.name} ({me?.role})
            </div>
          </div>
        </header>

        <main className="max-w-[1400px] mx-auto px-6 py-8 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-slate-400 text-sm">
              Gerencie usuários da plataforma.
            </p>

            <button
              onClick={onOpenCreate}
              className="whitespace-nowrap px-4 py-2 rounded-md bg-sky-500 hover:bg-sky-600 transition font-medium"
            >
              + Novo usuário
            </button>
          </div>

          {err && (
            <div className="mb-4 rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
              {err}
            </div>
          )}

          {credentialNotice && (
            <div className="mb-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-100">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <h2 className="font-semibold text-white">
                    {credentialNotice.title}
                  </h2>
                  <p className="mt-1 text-emerald-100/80">
                    Entregue esta senha temporária para o usuário. No próximo
                    login ele será obrigado a definir uma nova senha.
                  </p>
                  <div className="mt-3 grid gap-2 md:grid-cols-3">
                    <div>
                      <span className="block text-xs uppercase tracking-wide text-emerald-200/70">
                        Usuário
                      </span>
                      <span className="font-medium">{credentialNotice.name}</span>
                    </div>
                    <div>
                      <span className="block text-xs uppercase tracking-wide text-emerald-200/70">
                        E-mail
                      </span>
                      <span className="font-medium">{credentialNotice.email}</span>
                    </div>
                    <div>
                      <span className="block text-xs uppercase tracking-wide text-emerald-200/70">
                        Senha temporária
                      </span>
                      <code className="rounded bg-slate-950/70 px-2 py-1 font-mono text-white">
                        {credentialNotice.temporaryPassword}
                      </code>
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setCredentialNotice(null)}
                  className="rounded-md border border-white/10 bg-slate-950/50 px-3 py-2 text-xs text-white hover:bg-slate-900"
                >
                  Ocultar
                </button>
              </div>
            </div>
          )}

          <div className="overflow-x-auto rounded-xl border border-white/10 bg-white/5">
            <table className="min-w-[1120px] text-sm xl:min-w-full">
              <thead className="bg-white/5">
                <tr className="text-left">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Nome</th>
                  <th className="px-4 py-3">E-mail</th>
                  <th className="px-4 py-3">Papel</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Ações</th>
                </tr>
              </thead>

              <tbody>
                {loading ? (
                  <tr>
                    <td
                      colSpan="6"
                      className="px-4 py-10 text-center text-slate-400"
                    >
                      Carregando...
                    </td>
                  </tr>
                ) : users.length ? (
                  users.map((u) => {
                    const isMe = me?.id === u.id;

                    return (
                      <tr key={u.id} className="border-t border-white/10">
                        <td className="px-4 py-3">{u.id}</td>
                        <td className="px-4 py-3">{u.name}</td>
                        <td className="px-4 py-3">{u.email}</td>

                        <td className="px-4 py-3">
                          <select
                            value={u.role}
                            disabled={isMe}
                            onChange={(e) =>
                              onChangeRole(u.id, e.target.value)
                            }
                            className="min-w-[11rem] rounded-md bg-slate-800/60 border border-white/10 px-2 py-1 text-sm outline-none focus:border-sky-400 disabled:opacity-50"
                          >
                            <option value="admin">admin</option>
                            <option value="operator">operator / Analista NOC</option>
                            <option value="viewer">viewer / Leitura</option>
                            <option value="auditor">auditor / Professor</option>
                          </select>
                        </td>

                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-2">
                            <span
                              className={`px-2 py-1 rounded text-xs ${
                                u.active
                                  ? "bg-emerald-500/20 text-emerald-300"
                                  : "bg-red-500/20 text-red-300"
                              }`}
                            >
                              {u.active ? "Ativo" : "Inativo"}
                            </span>
                            {u.must_change_password && (
                              <span className="px-2 py-1 rounded text-xs bg-amber-500/20 text-amber-200">
                                Troca pendente
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-2">
                            <button
                              onClick={() => onOpenEdit(u)}
                              className="whitespace-nowrap rounded-md bg-amber-600 hover:bg-amber-500 px-3 py-1 text-white"
                            >
                              Editar
                            </button>

                            <button
                              onClick={() => onToggleActive(u.id, !u.active)}
                              disabled={isMe}
                              className="whitespace-nowrap rounded-md bg-slate-800 hover:bg-slate-700 px-3 py-1 disabled:opacity-50"
                            >
                              {u.active ? "Desativar" : "Ativar"}
                            </button>

                            <button
                              onClick={() => onResetPassword(u.id)}
                              disabled={isMe}
                              className="whitespace-nowrap rounded-md bg-indigo-600 hover:bg-indigo-500 px-3 py-1 text-white disabled:opacity-50"
                            >
                              Resetar senha
                            </button>

                            <button
                              onClick={() => onDeleteUser(u)}
                              disabled={isMe}
                              className="whitespace-nowrap rounded-md bg-red-600/90 hover:bg-red-500 px-3 py-1 text-white disabled:opacity-50"
                            >
                              Excluir
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td
                      colSpan="6"
                      className="px-4 py-10 text-center text-slate-400"
                    >
                      Nenhum usuário encontrado.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <section className="rounded-xl border border-white/10 bg-white/5">
            <div className="border-b border-white/10 px-4 py-3">
              <h2 className="text-lg font-semibold">Auditoria recente</h2>
              <p className="text-sm text-slate-400">
                Ações administrativas, autenticação, discovery, canais e incidentes.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-[900px] text-sm xl:min-w-full">
                <thead className="bg-white/5 text-left">
                  <tr>
                    <th className="px-4 py-3">Quando</th>
                    <th className="px-4 py-3">Ator</th>
                    <th className="px-4 py-3">Perfil</th>
                    <th className="px-4 py-3">Ação</th>
                    <th className="px-4 py-3">Alvo</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLoading ? (
                    <tr>
                      <td colSpan="5" className="px-4 py-8 text-center text-slate-400">Carregando auditoria...</td>
                    </tr>
                  ) : auditLogs.length ? (
                    auditLogs.map((item) => (
                      <tr key={item.id} className="border-t border-white/10">
                        <td className="px-4 py-3 text-slate-300">{item.created_at ? new Date(item.created_at).toLocaleString() : "-"}</td>
                        <td className="px-4 py-3">
                          <div className="font-medium">{item.actor || item.actor_email || "sistema"}</div>
                          {item.actor_email && <div className="text-xs text-slate-500">{item.actor_email}</div>}
                        </td>
                        <td className="px-4 py-3">{roleLabel(item.actor_role)}</td>
                        <td className="px-4 py-3 font-mono text-xs text-sky-200">{item.action}</td>
                        <td className="px-4 py-3 text-slate-300">{item.target_type || "-"} {item.target_id || ""}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="5" className="px-4 py-8 text-center text-slate-400">Nenhum evento de auditoria encontrado.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>

      {open && (
        <div className="fixed inset-0 z-20 bg-black/60 flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-xl border border-white/10 bg-slate-900 p-6 text-white shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">
                {editingUser ? "Editar usuário" : "Novo usuário"}
              </h2>

              <button
                onClick={resetFormAndClose}
                className="px-2 py-1 rounded-md bg-slate-800 hover:bg-slate-700"
              >
                Fechar
              </button>
            </div>

            <form onSubmit={onSubmitUser} className="space-y-4">
              <div>
                <label className="text-sm">Nome</label>
                <input
                  className="mt-1 w-full rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
                  value={form.name}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, name: e.target.value }))
                  }
                  required
                />
              </div>

              <div>
                <label className="text-sm">E-mail</label>
                <input
                  type="email"
                  className="mt-1 w-full rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
                  value={form.email}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, email: e.target.value }))
                  }
                  required
                />
              </div>

              <div>
                <label className="text-sm">Papel</label>
                <select
                  className="mt-1 w-full rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400 disabled:opacity-50"
                  value={form.role}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, role: e.target.value }))
                  }
                  disabled={me?.id === editingUser?.id}
                >
                  <option value="admin">admin</option>
                  <option value="operator">operator / Analista NOC</option>
                  <option value="viewer">viewer / Leitura</option>
                  <option value="auditor">auditor / Professor</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <input
                  id="active"
                  type="checkbox"
                  checked={form.active}
                  disabled={me?.id === editingUser?.id}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, active: e.target.checked }))
                  }
                />
                <label htmlFor="active" className="text-sm">
                  Ativo
                </label>
              </div>

              {!editingUser && (
                <div className="rounded-md border border-sky-500/20 bg-sky-500/10 p-3 text-sm text-sky-200">
                  O usuário será criado com uma senha temporária única e
                  precisará definir uma nova senha no primeiro login.
                </div>
              )}

              <button
                type="submit"
                className="w-full rounded-md bg-sky-500 hover:bg-sky-600 py-2 font-medium transition"
              >
                {editingUser ? "Salvar alterações" : "Criar usuário"}
              </button>
            </form>
          </div>
        </div>
      )}

    </>
  );
}
