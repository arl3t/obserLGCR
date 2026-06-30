import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Eye, EyeOff, Loader2, Lock, Mail, Radar } from "lucide-react";
import { useLocalAuth } from "@/auth/LocalAuthProvider";
import { PLATFORM_AUTH_ENABLED } from "@/auth/auth-config";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const localAuth = useLocalAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const returnTo = (() => {
    const from = (location.state as { from?: { pathname?: string } } | null)?.from;
    return from?.pathname ?? "/noc";
  })();

  if (!PLATFORM_AUTH_ENABLED) {
    return <Navigate to="/noc" replace />;
  }

  if (localAuth?.isLoading) {
    return (
      <div className="obser-shell flex min-h-dvh items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (localAuth?.isAuthenticated) {
    return <Navigate to={returnTo} replace />;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!localAuth) return;
    setSubmitting(true);
    setError(null);
    try {
      await localAuth.login(email.trim(), password);
      navigate(returnTo, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al iniciar sesión");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="obser-shell relative flex min-h-dvh items-center justify-center overflow-hidden p-4">
      {/* Glow decorativo */}
      <div
        className="pointer-events-none absolute inset-0"
        aria-hidden
      >
        <div className="absolute left-1/2 top-0 h-[420px] w-[720px] -translate-x-1/2 rounded-full bg-primary/10 blur-3xl" />
        <div className="absolute bottom-0 right-0 h-64 w-64 rounded-full bg-primary/5 blur-2xl" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: "easeOut" }}
        className="relative w-full max-w-[420px]"
      >
        {/* Card principal */}
        <div className="ut-card overflow-hidden p-0">
          <div className="border-b border-border px-8 pb-6 pt-8 text-center">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-[5px] bg-[var(--ut-bg-elevated)] ring-1 ring-border">
              <Radar className="h-7 w-7 text-primary" aria-hidden />
            </div>
            <h1 className="ut-header__title text-xl">
              obser<span className="text-primary">LGCR</span>
            </h1>
            <p className="ut-header__subtitle mt-1 text-xs uppercase tracking-[0.2em]">
              Network Operations Center
            </p>
          </div>

          {/* Formulario */}
          <form onSubmit={handleSubmit} className="space-y-5 px-8 py-7">
            <div className="text-center">
              <h2 className="text-sm font-semibold text-foreground">Iniciar sesión</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Accede al centro de operaciones con tus credenciales
              </p>
            </div>

            {error && (
              <div
                role="alert"
                className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400"
              >
                {error}
              </div>
            )}

            <div className="space-y-2">
              <label htmlFor="email" className="text-xs text-muted-foreground">
                Correo electrónico
              </label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  placeholder="admin@obserlgcr.local"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="ut-input pl-9"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="password" className="text-xs text-muted-foreground">
                Contraseña
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="ut-input pl-9 pr-9"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  aria-label={showPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <Button type="submit" disabled={submitting} className="ut-btn w-full" style={{ marginTop: 0 }}>
              {submitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Verificando…
                </>
              ) : (
                "Entrar al NOC"
              )}
            </Button>
          </form>

          {/* Footer */}
          <div className="border-t border-border/60 bg-muted/20 px-8 py-4">
            <p className="text-center text-[10px] leading-relaxed text-muted-foreground">
              Credenciales gestionadas en PostgreSQL.
              <br />
              Lab: <span className="obser-mono text-primary">admin@obserlgcr.local</span>
            </p>
          </div>
        </div>

        <p className="mt-4 text-center text-[10px] text-muted-foreground/60">
          obserLGCR · Monitoreo de infraestructura y operaciones SOC
        </p>
      </motion.div>
    </div>
  );
}
