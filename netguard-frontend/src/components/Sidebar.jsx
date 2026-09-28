import React, { useEffect, useMemo, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { changePassword, logoutRemote } from "../services/auth";
import { can, roleLabel } from "../authz";
import { isNavEntryActive, isSectionActive, navigationSections } from "../navigation";

function NavIcon({ name }) {
  const common = "h-4 w-4";

  switch (name) {
    case "monitoring":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M3 12h4l2.5-5 4 10 2.5-5H21" />
        </svg>
      );
    case "database":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <ellipse cx="12" cy="6" rx="7" ry="3" />
          <path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6" />
          <path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
        </svg>
      );
    case "reports":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M4 19h16" />
          <path d="M7 16V9" />
          <path d="M12 16V5" />
          <path d="M17 16v-3" />
        </svg>
      );
    case "administration":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M12 15.5A3.5 3.5 0 1 0 12 8.5a3.5 3.5 0 0 0 0 7Z" />
          <path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 0 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 0 1-4 0v-.2a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 0 1 0-4h.2a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3h.1a1.6 1.6 0 0 0 1-1.5V3a2 2 0 0 1 4 0v.2a1.6 1.6 0 0 0 1 1.5h.1a1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8v.1a1.6 1.6 0 0 0 1.5 1H21a2 2 0 0 1 0 4h-.2a1.6 1.6 0 0 0-1.5 1Z" />
        </svg>
      );
    case "insights":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M9 18h6" />
          <path d="M10 22h4" />
          <path d="M12 2a7 7 0 0 0-4 12.7c.6.4 1 1 1.1 1.7h5.8c.1-.7.5-1.3 1.1-1.7A7 7 0 0 0 12 2Z" />
        </svg>
      );
    case "help":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M9.1 9a3 3 0 1 1 5.8 1c-.5 1-1.5 1.4-2.2 1.9-.8.5-1.2 1-1.2 2.1" />
          <path d="M12 17h.01" />
          <circle cx="12" cy="12" r="9" />
        </svg>
      );
    default:
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M5 12h14" />
          <path d="M12 5v14" />
        </svg>
      );
  }
}
const leafBase =
  "group flex w-full items-center gap-3 rounded-md border-l-2 px-3 py-2 text-sm transition";
const leafInactive =
  "border-transparent text-slate-300 hover:border-slate-700 hover:bg-slate-800/70 hover:text-white";
const leafActive = "border-sky-400 bg-slate-800 text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]";

function ToggleIcon({ collapsed }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4">
      {collapsed ? <path d="m9 6 6 6-6 6" /> : <path d="m15 6-6 6 6 6" />}
    </svg>
  );
}

function LogoutIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-4 w-4">
      <path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4" />
      <path d="M14 16l4-4-4-4" />
      <path d="M8 12h10" />
    </svg>
  );
}

export default function Sidebar({ collapsed: controlledCollapsed, onToggle } = {}) {
  const nav = useNavigate();
  const location = useLocation();
  const user = useMemo(() => JSON.parse(localStorage.getItem("ng_user") || "{}"), []);
  const [internalCollapsed, setInternalCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem("ng_sidebar_collapsed") === "1";
  });
  const [openSections, setOpenSections] = useState({});
  const [sessionPanelOpen, setSessionPanelOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [passwordError, setPasswordError] = useState(null);
  const collapsed = typeof controlledCollapsed === "boolean" ? controlledCollapsed : internalCollapsed;

  useEffect(() => {
    localStorage.setItem("ng_sidebar_collapsed", collapsed ? "1" : "0");
    document.documentElement.dataset.sidebarCollapsed = collapsed ? "1" : "0";
  }, [collapsed]);

  useEffect(() => {
    setOpenSections((current) => {
      const nextState = { ...current };

      navigationSections.forEach((section) => {
        if (section.items?.length && isSectionActive(section, location.pathname) && nextState[section.key] === undefined) {
          nextState[section.key] = true;
        }
      });

      return nextState;
    });
  }, [location.pathname]);

  const onLogout = async () => {
    await logoutRemote();
    nav("/login");
  };

  async function onChangePassword(e) {
    e.preventDefault();
    setPasswordError(null);
    if (newPassword.length < 6) {
      setPasswordError("A nova senha deve ter ao menos 6 caracteres.");
      return;
    }
    try {
      await changePassword(user.id, newPassword);
      setNewPassword("");
      setPasswordOpen(false);
      setSessionPanelOpen(false);
    } catch (error) {
      setPasswordError(error?.response?.data?.detail || error?.message || "Falha ao alterar senha.");
    }
  }

  function canSeeSection(section) {
    if (section.key === "administration") return can(user, "manageUsers");
    if (section.key === "data-collection") return can(user, "manageHosts") || can(user, "manageTemplates") || can(user, "runDiscovery");
    if (section.key === "insights") return can(user, "useAi");
    return true;
  }

  function toggleSection(sectionKey) {
    setOpenSections((current) => ({
      ...current,
      [sectionKey]: !current[sectionKey],
    }));
  }

  function handleSidebarToggle() {
    if (typeof controlledCollapsed === "boolean") {
      onToggle?.();
      return;
    }
    setInternalCollapsed((current) => !current);
  }

  return (
    <aside
      className={`fixed left-0 top-0 z-30 flex h-screen flex-col border-r border-white/10 bg-[#0f1722] text-white shadow-[12px_0_30px_rgba(2,6,23,0.35)] transition-[width] duration-200 ${
        collapsed ? "w-20" : "w-72"
      }`}
    >
      <div className={`border-b border-white/10 ${collapsed ? "px-3 py-4" : "px-5 py-5"}`}>
        <div className={`flex items-center ${collapsed ? "flex-col justify-center gap-3" : "justify-between gap-3"}`}>
          <div className={`flex min-w-0 items-center gap-3 ${collapsed ? "justify-center" : ""}`}>
            <img src="/logo.png" alt="NetGuard" className="h-8 w-8 shrink-0 rounded" />
            {!collapsed ? (
              <div className="min-w-0">
                <div className="truncate text-lg font-semibold tracking-wide text-sky-300">NetGuard</div>
                <div className="truncate text-xs uppercase tracking-[0.16em] text-slate-500">Monitoramento</div>
              </div>
            ) : null}
          </div>
          <button
            type="button"
            onClick={handleSidebarToggle}
            title={collapsed ? "Exibir menu lateral" : "Ocultar menu lateral"}
            aria-label={collapsed ? "Exibir menu lateral" : "Ocultar menu lateral"}
            className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-slate-900/80 text-slate-300 transition hover:border-sky-500/40 hover:text-white"
          >
            <ToggleIcon collapsed={collapsed} />
          </button>
        </div>

        {!collapsed ? (
          <button
            type="button"
            onClick={() => setSessionPanelOpen((open) => !open)}
            className="mt-4 w-full rounded-lg border border-white/10 bg-slate-900/80 px-3 py-2 text-left transition hover:border-sky-500/40"
          >
            <div className="text-xs uppercase tracking-[0.14em] text-slate-500">Sessão</div>
            <div className="mt-1 truncate text-sm font-medium text-slate-100">{user?.name || "Usuário"}</div>
            <div className="truncate text-xs text-slate-400">{roleLabel(user?.role)}</div>
          </button>
        ) : null}

        {!collapsed && sessionPanelOpen && (
          <div className="mt-2 rounded-lg border border-white/10 bg-slate-950/80 p-3 text-xs text-slate-300">
            <div className="space-y-1">
              <div className="font-medium text-slate-100">{user?.email}</div>
              <div>Perfil: {roleLabel(user?.role)}</div>
            </div>
            <div className="mt-3 grid gap-2">
              <button
                type="button"
                onClick={() => setPasswordOpen((open) => !open)}
                className="rounded-md border border-white/10 px-2 py-1.5 text-left hover:bg-slate-800"
              >
                Alterar senha
              </button>
              <button
                type="button"
                onClick={onLogout}
                className="rounded-md border border-red-500/20 bg-red-500/10 px-2 py-1.5 text-left text-red-100 hover:bg-red-500/20"
              >
                Sair
              </button>
            </div>
            {passwordOpen && (
              <form onSubmit={onChangePassword} className="mt-3 space-y-2">
                <input
                  type="password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  placeholder="Nova senha"
                  className="w-full rounded-md border border-white/10 bg-slate-900 px-2 py-1.5 text-sm outline-none focus:border-sky-400"
                />
                {passwordError && <div className="text-red-300">{passwordError}</div>}
                <button type="submit" className="w-full rounded-md bg-sky-500 px-2 py-1.5 font-medium text-white hover:bg-sky-600">
                  Salvar senha
                </button>
              </form>
            )}
          </div>
        )}
      </div>

      <nav className={`flex-1 space-y-4 overflow-y-auto py-4 ${collapsed ? "px-2" : "px-3"}`}>
        {navigationSections.filter(canSeeSection).map((section) => {
          const sectionActive = isSectionActive(section, location.pathname);

          if (section.items?.length) {
            const isOpen = openSections[section.key] ?? sectionActive;

            if (collapsed) {
              return (
                <NavLink
                  key={section.key}
                  to={section.items[0]?.to || "/monitoring/overview"}
                  title={section.label}
                  aria-label={section.label}
                  className={`flex h-11 w-full items-center justify-center rounded-lg transition ${
                    sectionActive ? "bg-slate-800/80 text-white" : "text-slate-300 hover:bg-slate-800/60 hover:text-white"
                  }`}
                >
                  <NavIcon name={section.icon} />
                </NavLink>
              );
            }

            return (
              <section key={section.key}>
                <button
                  type="button"
                  onClick={() => toggleSection(section.key)}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left transition ${
                    sectionActive ? "bg-slate-800/80 text-white" : "text-slate-300 hover:bg-slate-800/60 hover:text-white"
                  }`}
                >
                  <span className="flex items-center gap-3 text-sm font-medium">
                    <NavIcon name={section.icon} />
                    {section.label}
                  </span>
                  <span className={`text-xs transition-transform ${isOpen ? "rotate-90" : ""}`}>&gt;</span>
                </button>

                {isOpen ? (
                  <div className="mt-2 space-y-1 border-l border-white/10 pl-3 ml-4">
                    {section.items.map((item) => {
                      const active = isNavEntryActive(item, location.pathname);

                      return (
                        <NavLink
                          key={item.key}
                          to={item.to}
                          className={`${leafBase} ${active ? leafActive : leafInactive}`}
                        >
                          <span className="truncate">{item.label}</span>
                        </NavLink>
                      );
                    })}
                  </div>
                ) : null}
              </section>
            );
          }

          const active = isNavEntryActive(section, location.pathname);

          return (
            <NavLink
              key={section.key}
              to={section.to}
              title={collapsed ? section.label : undefined}
              aria-label={collapsed ? section.label : undefined}
              className={
                collapsed
                  ? `flex h-11 w-full items-center justify-center rounded-lg transition ${
                      active ? "bg-slate-800/80 text-white" : "text-slate-300 hover:bg-slate-800/60 hover:text-white"
                    }`
                  : `${leafBase} ${active ? leafActive : leafInactive}`
              }
            >
              <NavIcon name={section.icon} />
              {!collapsed ? <span className="truncate">{section.label}</span> : null}
            </NavLink>
          );
        })}
      </nav>

      <div className={`border-t border-white/10 ${collapsed ? "p-3" : "p-4"}`}>
        <button
          onClick={onLogout}
          title={collapsed ? "Desconectar" : undefined}
          aria-label={collapsed ? "Desconectar" : undefined}
          className={`inline-flex w-full items-center justify-center rounded-md border border-red-500/20 bg-red-500/10 text-sm font-medium text-red-100 transition hover:bg-red-500/20 ${
            collapsed ? "h-11 px-0" : "py-2.5"
          }`}
        >
          {collapsed ? <LogoutIcon /> : "Desconectar"}
        </button>
      </div>
    </aside>
  );
}
