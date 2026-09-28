const ROLE_LABELS = {
  admin: "Admin",
  operator: "Operador / NOC",
  viewer: "Viewer / Leitura",
  auditor: "Auditor / Professor",
};

const ROLE_PERMISSIONS = {
  admin: [
    "manageUsers",
    "manageHosts",
    "manageTemplates",
    "runDiscovery",
    "configureAlerts",
    "resolveIncidents",
    "useAi",
    "viewReports",
  ],
  operator: ["resolveIncidents", "useAi", "viewReports"],
  viewer: ["viewReports"],
  auditor: ["viewReports"],
};

export function normalizeRole(role) {
  return String(role || "viewer").trim().toLowerCase();
}

export function roleLabel(role) {
  return ROLE_LABELS[normalizeRole(role)] || ROLE_LABELS.viewer;
}

export function hasRole(user, roles) {
  const allowed = Array.isArray(roles) ? roles : [roles];
  return allowed.map(normalizeRole).includes(normalizeRole(user?.role));
}

export function can(user, permission) {
  const role = normalizeRole(user?.role);
  return (ROLE_PERMISSIONS[role] || []).includes(permission);
}

