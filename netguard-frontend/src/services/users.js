import api from "./api";

export async function listUsers() {
  const { data } = await api.get("/users");
  return data;
}

export async function createUser(user) {
  const { data } = await api.post("/users", user);
  return data;
}

export async function updateUser(id, user) {
  const { data } = await api.put(`/users/${id}`, user);
  return data;
}

export async function setActive(id, active) {
  const { data } = await api.patch(`/users/${id}/status`, { active });
  return data;
}
export async function resetPassword(id) {
  const { data } = await api.patch(`/users/${id}/password`);
  return data;
}

export async function deleteUser(id, actorUserId) {
  const params = actorUserId ? { actor_user_id: actorUserId } : {};
  const { data } = await api.delete(`/users/${id}`, { params });
  return data;
}

export async function updateRole(id, role) {
  const user = await api.get("/users");
  const current = user.data.find((u) => u.id === id);

  if (!current) {
    throw new Error("Usuário não encontrado.");
  }

  const { data } = await api.put(`/users/${id}`, {
    name: current.name,
    email: current.email,
    role,
    active: current.active,
  });

  return data;
}

export async function listAuditLogs(limit = 100) {
  const { data } = await api.get("/audit-logs", { params: { limit } });
  return data;
}
