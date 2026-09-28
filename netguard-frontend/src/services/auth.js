import api from "./api";

const KEY = "ng_user";

export async function login(email, password) {
  const { data } = await api.post("/auth/login", {
    email: email.trim().toLowerCase(),
    password,
  });

  const user = data?.user || data;
  const token = data?.access_token;

  localStorage.setItem(KEY, JSON.stringify(user));
  if (token) localStorage.setItem("ng_token", token);
  if (data?.expires_at) localStorage.setItem("ng_token_expires_at", data.expires_at);
  localStorage.setItem("ng_session", "ok");

  return { ...data, user };
}

export async function changePassword(userId, newPassword) {
  const { data } = await api.post("/auth/change-password", {
    user_id: userId,
    new_password: newPassword,
  });
  return data;
}

export async function getMe() {
  const { data } = await api.get("/auth/me");
  if (data?.user) {
    localStorage.setItem(KEY, JSON.stringify(data.user));
  }
  return data?.user || data;
}

export async function logoutRemote() {
  try {
    await api.post("/auth/logout");
  } catch {
    // Logout local ainda deve limpar a sessao mesmo se o token ja expirou.
  }
  logout();
}

export function logout() {
  localStorage.removeItem(KEY);
  localStorage.removeItem("ng_token");
  localStorage.removeItem("ng_token_expires_at");
  sessionStorage.removeItem("ng_token");
  localStorage.removeItem("ng_session");
  sessionStorage.removeItem("ng_session");
}

export function getCurrentUser() {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "{}");
  } catch {
    return {};
  }
}

export function setCurrentUser(user) {
  localStorage.setItem(KEY, JSON.stringify(user));
}
