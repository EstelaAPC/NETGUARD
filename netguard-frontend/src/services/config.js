export function getApiBaseUrl() {
  const envUrl = import.meta.env?.VITE_API_URL;
  if (envUrl) return envUrl.replace(/\/+$/, "");

  if (typeof window !== "undefined" && window.location?.hostname) {
    return "/api";
  }

  return "/api";
}

export const API_BASE_URL = getApiBaseUrl();

export function getToken() {
  const token = localStorage.getItem("ng_token") || sessionStorage.getItem("ng_token");
  if (!token || token === "null" || token === "undefined") return "";
  return token;
}

export function jsonHeaders(extraHeaders = {}) {
  const token = getToken();

  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extraHeaders,
  };
}
