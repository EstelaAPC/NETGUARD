function normalizePath(pathname = "/") {
  return pathname === "/" ? pathname : pathname.replace(/\/+$/, "");
}

function startsWithSegment(pathname, prefix) {
  const current = normalizePath(pathname);
  const base = normalizePath(prefix);
  return current === base || current.startsWith(`${base}/`);
}

export const navigationSections = [
  {
    key: "monitoring",
    label: "Monitoramento",
    icon: "monitoring",
    items: [
      {
        key: "overview",
        label: "Visão geral",
        to: "/monitoring/overview",
        aliases: ["/dashboard"],
        activePrefixes: ["/monitoring/overview", "/dashboard"],
      },
      {
        key: "incidents",
        label: "Incidentes",
        to: "/monitoring/incidents",
        aliases: ["/incidents"],
        activePrefixes: ["/monitoring/incidents", "/incidents"],
      },
      {
        key: "alerts",
        label: "Alertas",
        to: "/monitoring/alerts",
        aliases: ["/alerts"],
        activePrefixes: ["/monitoring/alerts", "/alerts"],
      },
      {
        key: "hosts-monitored",
        label: "Hosts monitorados",
        to: "/monitoring/hosts",
        activePrefixes: ["/monitoring/hosts"],
      },
      {
        key: "signals",
        label: "Sinais recentes",
        to: "/monitoring/signals",
        aliases: ["/metrics"],
        activePrefixes: ["/monitoring/signals", "/metrics"],
      },
    ],
  },
  {
    key: "data-collection",
    label: "Coleta de dados",
    icon: "database",
    items: [
      {
        key: "hosts-config",
        label: "Hosts",
        to: "/data-collection/hosts",
        aliases: ["/hosts"],
        activePrefixes: ["/data-collection/hosts", "/hosts"],
      },
      {
        key: "host-groups",
        label: "Grupos de hosts",
        to: "/data-collection/host-groups",
        activePrefixes: ["/data-collection/host-groups"],
      },
      {
        key: "templates",
        label: "Templates",
        to: "/data-collection/templates",
        activePrefixes: ["/data-collection/templates"],
      },
      {
        key: "discovery",
        label: "Descoberta",
        to: "/data-collection/discovery",
        activePrefixes: ["/data-collection/discovery"],
      },
    ],
  },
  {
    key: "reports",
    label: "Relatórios",
    icon: "reports",
    to: "/reports",
    aliases: ["/relatorios"],
    activePrefixes: ["/reports", "/relatorios"],
  },
  {
    key: "administration",
    label: "Administração",
    icon: "administration",
    to: "/administration",
    aliases: ["/admin"],
    activePrefixes: ["/administration", "/admin"],
  },
  {
    key: "insights",
    label: "IA / Insights",
    icon: "insights",
    to: "/insights",
    activePrefixes: ["/insights"],
  },
  {
    key: "help",
    label: "Ajuda",
    icon: "help",
    to: "/help",
    activePrefixes: ["/help"],
  },
];

export function isNavEntryActive(entry, pathname) {
  const prefixes = entry.activePrefixes || [];
  return prefixes.some((prefix) => startsWithSegment(pathname, prefix));
}

export function isSectionActive(section, pathname) {
  if (section.items?.length) {
    return section.items.some((item) => isNavEntryActive(item, pathname));
  }

  return isNavEntryActive(section, pathname);
}

function crumb(label, to = null) {
  return { label, to };
}

export function getBreadcrumbs(pathname) {
  const path = normalizePath(pathname);

  if (path === "/monitoring/overview" || path === "/dashboard") {
    return [crumb("Monitoramento"), crumb("Visão geral")];
  }

  if (path === "/monitoring/incidents" || path === "/incidents") {
    return [crumb("Monitoramento"), crumb("Incidentes")];
  }

  if (path === "/monitoring/alerts" || path === "/alerts") {
    return [crumb("Monitoramento"), crumb("Alertas")];
  }

  if (path === "/monitoring/signals" || path === "/metrics") {
    return [crumb("Monitoramento"), crumb("Sinais recentes")];
  }

  if (path === "/monitoring/hosts") {
    return [crumb("Monitoramento"), crumb("Hosts monitorados")];
  }

  if (/^\/monitoring\/hosts\/[^/]+$/.test(path) || /^\/hosts\/[^/]+\/monitoring$/.test(path)) {
    return [
      crumb("Monitoramento", "/monitoring/overview"),
      crumb("Hosts monitorados", "/monitoring/hosts"),
      crumb("Detalhe do host"),
    ];
  }

  if (path === "/data-collection/hosts" || path === "/hosts") {
    return [crumb("Coleta de dados"), crumb("Hosts")];
  }

  if (path === "/data-collection/hosts/new") {
    return [
      crumb("Coleta de dados", "/data-collection/hosts"),
      crumb("Hosts", "/data-collection/hosts"),
      crumb("Novo host"),
    ];
  }

  if (/^\/data-collection\/hosts\/[^/]+\/edit$/.test(path)) {
    return [
      crumb("Coleta de dados", "/data-collection/hosts"),
      crumb("Hosts", "/data-collection/hosts"),
      crumb("Editar host"),
    ];
  }

  if (path === "/data-collection/host-groups") {
    return [crumb("Coleta de dados"), crumb("Grupos de hosts")];
  }

  if (path === "/data-collection/templates") {
    return [crumb("Coleta de dados"), crumb("Templates")];
  }

  if (path === "/data-collection/discovery") {
    return [crumb("Coleta de dados"), crumb("Descoberta")];
  }

  if (path === "/reports" || path === "/relatorios") {
    return [crumb("Relatórios")];
  }

  if (path === "/administration" || path === "/admin") {
    return [crumb("Administração")];
  }

  if (path === "/insights") {
    return [crumb("IA / Insights")];
  }

  if (path === "/help") {
    return [crumb("Ajuda")];
  }

  return [];
}

