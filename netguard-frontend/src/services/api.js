import axios from "axios";
import { API_BASE_URL } from "./config";

const api = axios.create({
  baseURL: API_BASE_URL,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("ng_token") || sessionStorage.getItem("ng_token");
  if (token && token !== "fake-token") {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401 && window.location.pathname !== "/login") {
      localStorage.removeItem("ng_user");
      localStorage.removeItem("ng_token");
      sessionStorage.removeItem("ng_token");
      localStorage.removeItem("ng_session");
      sessionStorage.removeItem("ng_session");
      window.location.assign("/login");
    }
    return Promise.reject(error);
  }
);

export default api;
