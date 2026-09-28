import React, { useEffect, useState } from "react";
import Sidebar from "./Sidebar";
import Breadcrumbs from "./Breadcrumbs";

export default function AppShell({
  title,
  description,
  actions = null,
  breadcrumbs = null,
  children,
  maxWidth = "max-w-[1600px]",
  contentClassName = "",
}) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem("ng_sidebar_collapsed") === "1";
  });

  useEffect(() => {
    localStorage.setItem("ng_sidebar_collapsed", sidebarCollapsed ? "1" : "0");
  }, [sidebarCollapsed]);

  return (
    <>
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((current) => !current)}
      />
      <div
        className={`min-h-screen min-w-0 bg-slate-950 text-white transition-[padding] duration-200 ${
          sidebarCollapsed ? "pl-20" : "pl-72"
        }`}
        style={{ "--ng-sidebar-width": sidebarCollapsed ? "5rem" : "18rem" }}
      >
        <header className="sticky top-0 z-10 border-b border-white/10 bg-slate-900/75 backdrop-blur">
          <div className={`mx-auto ${maxWidth} min-w-0 px-4 py-4 sm:px-6`}>
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div className="min-w-0">
                <Breadcrumbs items={breadcrumbs} />
                <h1 className="mt-2 text-2xl font-semibold text-white">{title}</h1>
                {description ? <p className="mt-2 max-w-4xl text-sm text-slate-400">{description}</p> : null}
              </div>
              {actions ? (
                <div className="flex shrink-0 flex-wrap items-center gap-3 xl:justify-end">{actions}</div>
              ) : null}
            </div>
          </div>
        </header>

        <main className={`mx-auto ${maxWidth} min-w-0 px-4 py-8 sm:px-6 ${contentClassName}`}>
          {children}
        </main>
      </div>
    </>
  );
}
