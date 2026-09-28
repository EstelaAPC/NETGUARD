import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  login as authLogin,
  changePassword,
  setCurrentUser,
} from "../services/auth";

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [mustChangeOpen, setMustChangeOpen] = useState(false);
  const [loggedUser, setLoggedUser] = useState(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);

  useEffect(() => {
    try {
      const storedUser = JSON.parse(localStorage.getItem("ng_user") || "{}");
      const token = localStorage.getItem("ng_token") || sessionStorage.getItem("ng_token");
      if (token && storedUser?.must_change_password) {
        setLoggedUser(storedUser);
        setMustChangeOpen(true);
      }
    } catch {
      // Ignore invalid local session state; normal login will rebuild it.
    }
  }, []);

  const validate = () => {
    if (!email.trim()) return "Informe seu e-mail.";
    const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!ok) return "E-mail inválido.";
    if (!password) return "Digite sua senha.";
    if (password.length < 6) return "A senha deve ter ao menos 6 caracteres.";
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    const v = validate();
    if (v) return setError(v);

    try {
      setLoading(true);

      const result = await authLogin(email, password);
      const user = result?.user ?? result;

      if (remember) {
        localStorage.setItem("ng_session", "ok");
      } else {
        sessionStorage.setItem("ng_session", "ok");
      }

      if (user?.must_change_password) {
        setLoggedUser(user);
        setMustChangeOpen(true);
        return;
      }

      if (user?.role === "admin") navigate("/administration");
      else navigate("/monitoring/overview");
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Credenciais inválidas ou servidor indisponível."
      );
    } finally {
      setLoading(false);
    }
  };

  async function handleChangePassword(e) {
    e.preventDefault();
    setError(null);

    if (!newPassword) return setError("Digite a nova senha.");
    if (newPassword.length < 6) {
      return setError("A nova senha deve ter ao menos 6 caracteres.");
    }
    if (newPassword !== confirmPassword) {
      return setError("As senhas não coincidem.");
    }

    try {
      setChangingPassword(true);

      const result = await changePassword(loggedUser.id, newPassword);

      const updatedUser = {
        ...loggedUser,
        ...(result?.user || {}),
        must_change_password: false,
      };

      setCurrentUser(updatedUser);
      setMustChangeOpen(false);
      setLoggedUser(updatedUser);
      setNewPassword("");
      setConfirmPassword("");

      if (updatedUser.role === "admin") navigate("/administration");
      else navigate("/monitoring/overview");
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Falha ao alterar a senha."
      );
    } finally {
      setChangingPassword(false);
    }
  }

  return (
    <div className="min-h-screen w-full bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-200 flex items-center justify-center p-6">
      <div aria-hidden className="pointer-events-none fixed inset-0">
        <div
          className="absolute -top-24 -left-24 h-72 w-72 rounded-full blur-3xl opacity-30"
          style={{
            background:
              "radial-gradient(40% 40% at 50% 50%, rgba(56,189,248,0.5) 0%, rgba(56,189,248,0.05) 100%)",
          }}
        />
        <div
          className="absolute -bottom-28 -right-28 h-96 w-96 rounded-full blur-3xl opacity-30"
          style={{
            background:
              "radial-gradient(40% 40% at 50% 50%, rgba(192,132,252,0.5) 0%, rgba(192,132,252,0.05) 100%)",
          }}
        />
      </div>

      <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-2 gap-8 relative">
        <div className="hidden lg:flex flex-col justify-center">
          <div className="relative hidden lg:flex flex-col justify-center">
            <img
              src="/logo.png"
              alt="NetGuard Logo"
              className="absolute inset-0 m-auto w-[28rem] h-[28rem] opacity-10 object-contain select-none pointer-events-none"
            />

            <div className="relative">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 px-3 py-1 text-xs text-slate-300/80 w-fit">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                Ambiente seguro • NetGuard
              </div>

              <h1 className="mt-6 text-4xl font-bold tracking-tight">
                Bem-vindo ao{" "}
                <span className="bg-gradient-to-r from-sky-400 to-violet-400 bg-clip-text text-transparent">
                  NetGuard
                </span>
              </h1>

              <p className="mt-4 max-w-md text-slate-300/80">
                Monitore sua rede com confiabilidade e estilo. Entre para acessar
                dashboards, alertas e configurações.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-center">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-white/5 backdrop-blur p-6 shadow-xl">
            <div className="mb-5">
              <h2 className="text-2xl font-semibold">Entrar</h2>
              <p className="text-sm text-slate-300/80">
                Use suas credenciais cadastradas.
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="space-y-2">
                <label htmlFor="email" className="text-sm">
                  E-mail
                </label>
                <input
                  id="email"
                  type="email"
                  autoComplete="username"
                  placeholder="admin@netguard.local"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-3 pr-3 py-2 rounded-md bg-slate-800/60 border border-white/10 outline-none focus:border-sky-400 transition"
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="password" className="text-sm">
                  Senha
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-3 pr-16 py-2 rounded-md bg-slate-800/60 border border-white/10 outline-none focus:border-sky-400 transition"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((s) => !s)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md px-2 py-1 text-slate-300/80 hover:text-white"
                  >
                    {showPassword ? "Ocultar" : "Mostrar"}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between text-sm">
                <label className="inline-flex items-center gap-2 select-none">
                  <input
                    type="checkbox"
                    className="h-4 w-4 cursor-pointer rounded border-white/20"
                    checked={remember}
                    onChange={(e) => setRemember(e.target.checked)}
                  />
                  Lembrar de mim
                </label>
              </div>

              {error && (
                <div
                  role="alert"
                  className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
                >
                  {error}
                </div>
              )}

              <button
                type="submit"
                className={`w-full inline-flex items-center justify-center rounded-md bg-sky-500 hover:bg-sky-600 disabled:opacity-70 py-2 font-medium transition ${loading ? "pointer-events-none" : ""
                  }`}
                disabled={loading}
              >
                {loading ? "Entrando..." : "Entrar"}
              </button>
            </form>

            <p className="mt-6 text-center text-xs text-slate-300/70">
              Ao entrar, você concorda com os termos de uso e política de
              privacidade.
            </p>
          </div>
        </div>
      </div>

      {mustChangeOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-2xl font-semibold mb-2">
              Troca obrigatória de senha
            </h2>
            <p className="text-slate-300/80 text-sm mb-5">
              Sua senha foi redefinida ou é temporária. Defina uma nova senha
              para continuar.
            </p>

            <form onSubmit={handleChangePassword} className="space-y-4">
              <div>
                <label className="block text-sm mb-2">Nova senha</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
                  required
                />
              </div>

              <div>
                <label className="block text-sm mb-2">
                  Confirmar nova senha
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full rounded-md bg-slate-800/60 border border-white/10 px-3 py-2 outline-none focus:border-sky-400"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={changingPassword}
                className="w-full rounded-md bg-sky-500 hover:bg-sky-600 py-2 font-medium disabled:opacity-70"
              >
                {changingPassword ? "Salvando..." : "Salvar nova senha"}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

