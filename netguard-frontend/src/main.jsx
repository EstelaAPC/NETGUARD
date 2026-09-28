import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes, useParams } from "react-router-dom";
import "./index.css";

import Admin from "./pages/Admin.jsx";
import Alerts from "./pages/Alerts.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Discovery from "./pages/Discovery.jsx";
import Help from "./pages/Help.jsx";
import HostEditor from "./pages/HostEditor.jsx";
import HostGroups from "./pages/HostGroups.jsx";
import HostMonitoring from "./pages/HostMonitoring.jsx";
import Hosts from "./pages/Hosts.jsx";
import Incidents from "./pages/Incidents.jsx";
import Insights from "./pages/Insights.jsx";
import Login from "./pages/Login.jsx";
import Metrics from "./pages/Metrics.jsx";
import MonitoringHosts from "./pages/MonitoringHosts.jsx";
import Relatorios from "./pages/Relatorios.jsx";
import Templates from "./pages/Templates.jsx";
import { hasRole, roleLabel } from "./authz";

function getSessionUser() {
  try {
    return JSON.parse(localStorage.getItem("ng_user") || "{}");
  } catch {
    return {};
  }
}

function sessionIsExpired() {
  const expiresAt = localStorage.getItem("ng_token_expires_at");
  if (!expiresAt) return false;
  return new Date(expiresAt).getTime() <= Date.now();
}

function clearExpiredSession() {
  localStorage.removeItem("ng_user");
  localStorage.removeItem("ng_token");
  localStorage.removeItem("ng_token_expires_at");
  localStorage.removeItem("ng_session");
  sessionStorage.removeItem("ng_token");
  sessionStorage.removeItem("ng_session");
}

function PrivateRoute({ children }) {
  const token = localStorage.getItem("ng_token") || sessionStorage.getItem("ng_token");
  const user = getSessionUser();
  if (token && sessionIsExpired()) {
    clearExpiredSession();
    return <Navigate to="/login" replace />;
  }
  if (token && user?.must_change_password) return <Navigate to="/login" replace />;
  return token ? children : <Navigate to="/login" replace />;
}

function RoleRoute({ roles, children }) {
  const token = localStorage.getItem("ng_token") || sessionStorage.getItem("ng_token");
  const user = getSessionUser();

  if (!token) return <Navigate to="/login" replace />;
  if (sessionIsExpired()) {
    clearExpiredSession();
    return <Navigate to="/login" replace />;
  }
  if (user?.must_change_password) return <Navigate to="/login" replace />;
  if (!hasRole(user, roles)) {
    return (
      <div className="min-h-screen bg-slate-950 px-6 py-10 text-slate-100">
        <div className="mx-auto max-w-2xl rounded-xl border border-red-500/30 bg-red-500/10 p-5">
          <h1 className="text-xl font-semibold">Acesso negado</h1>
          <p className="mt-2 text-sm text-red-100/90">
            Você não tem permissão para executar esta ação. Perfil atual: {roleLabel(user?.role)}.
          </p>
        </div>
      </div>
    );
  }
  return children;
}

function RedirectHostMonitoringAlias() {
  const { hostId } = useParams();
  return <Navigate to={`/monitoring/hosts/${hostId}`} replace />;
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />

        <Route
          path="/monitoring/overview"
          element={
            <PrivateRoute>
              <Dashboard />
            </PrivateRoute>
          }
        />

        <Route
          path="/monitoring/incidents"
          element={
            <PrivateRoute>
              <Incidents />
            </PrivateRoute>
          }
        />

        <Route
          path="/monitoring/alerts"
          element={
            <PrivateRoute>
              <Alerts />
            </PrivateRoute>
          }
        />

        <Route
          path="/monitoring/hosts"
          element={
            <PrivateRoute>
              <MonitoringHosts />
            </PrivateRoute>
          }
        />

        <Route
          path="/monitoring/hosts/:hostId"
          element={
            <PrivateRoute>
              <HostMonitoring />
            </PrivateRoute>
          }
        />

        <Route
          path="/monitoring/signals"
          element={
            <PrivateRoute>
              <Metrics />
            </PrivateRoute>
          }
        />

        <Route
          path="/data-collection/hosts"
          element={
            <RoleRoute roles={["admin"]}>
              <Hosts />
            </RoleRoute>
          }
        />

        <Route
          path="/data-collection/hosts/new"
          element={
            <RoleRoute roles={["admin"]}>
              <HostEditor />
            </RoleRoute>
          }
        />

        <Route
          path="/data-collection/hosts/:hostId/edit"
          element={
            <RoleRoute roles={["admin"]}>
              <HostEditor />
            </RoleRoute>
          }
        />

        <Route
          path="/data-collection/host-groups"
          element={
            <RoleRoute roles={["admin"]}>
              <HostGroups />
            </RoleRoute>
          }
        />

        <Route
          path="/data-collection/templates"
          element={
            <RoleRoute roles={["admin"]}>
              <Templates />
            </RoleRoute>
          }
        />

        <Route
          path="/data-collection/discovery"
          element={
            <RoleRoute roles={["admin"]}>
              <Discovery />
            </RoleRoute>
          }
        />

        <Route
          path="/reports"
          element={
            <PrivateRoute>
              <Relatorios />
            </PrivateRoute>
          }
        />

        <Route
          path="/administration"
          element={
            <RoleRoute roles={["admin"]}>
              <Admin />
            </RoleRoute>
          }
        />

        <Route
          path="/insights"
          element={
            <RoleRoute roles={["admin", "operator"]}>
              <Insights />
            </RoleRoute>
          }
        />

        <Route
          path="/help"
          element={
            <PrivateRoute>
              <Help />
            </PrivateRoute>
          }
        />

        <Route path="/dashboard" element={<Navigate to="/monitoring/overview" replace />} />
        <Route path="/incidents" element={<Navigate to="/monitoring/incidents" replace />} />
        <Route path="/alerts" element={<Navigate to="/monitoring/alerts" replace />} />
        <Route path="/metrics" element={<Navigate to="/monitoring/signals" replace />} />
        <Route path="/hosts" element={<Navigate to="/data-collection/hosts" replace />} />
        <Route path="/hosts/:hostId/monitoring" element={<RedirectHostMonitoringAlias />} />
        <Route path="/relatorios" element={<Navigate to="/reports" replace />} />
        <Route path="/admin" element={<Navigate to="/administration" replace />} />

        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
