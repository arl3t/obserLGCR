/**
 * LoginCallback — página de callback OIDC para Authorization Code Flow + PKCE.
 *
 * Esta página se renderiza en /auth/callback después de que Keycloak
 * redirige de vuelta al dashboard con el código de autorización.
 *
 * react-oidc-context procesa automáticamente el código cuando se renderiza
 * cualquier componente que use useAuth(). Esta página solo gestiona los estados
 * de carga, error y redirección post-login.
 *
 * Flujo:
 *   1. Keycloak → /auth/callback?code=xxx&state=yyy
 *   2. oidc-client-ts intercepta, intercambia code por tokens
 *   3. Este componente detecta auth.isAuthenticated=true → navega al destino
 */

import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/auth/useAuth";
import { defaultHomeForTier, rolesToTier } from "@/auth/useSocTier";

/** Borra todas las claves de sessionStorage relacionadas con el flujo OIDC */
function clearOidcSessionStorage() {
  const keysToRemove: string[] = [];
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (key && (key.startsWith("oidc.") || key === "auth_return_to")) {
      keysToRemove.push(key);
    }
  }
  keysToRemove.forEach((k) => sessionStorage.removeItem(k));
}

export function LoginCallback() {
  const navigate = useNavigate();
  const { isAuthenticated, isLoading, error, login, roles } = useAuth();
  const retried = useRef(false);

  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      const returnTo = sessionStorage.getItem("auth_return_to");
      sessionStorage.removeItem("auth_return_to");
      // C2.3 — Redirect inteligente: si el usuario aterrizó desde la raíz
      // (sin return path explícito o "/"), lo mandamos a su vista según tier.
      // Si venía con un deep-link real (e.g. /gestion?investigate=…), lo
      // respetamos. Esto evita que un manager caiga en OverviewCharts cuando
      // hace login fresco.
      const isGenericLanding = !returnTo || returnTo === "/" || returnTo === "";
      const dest = isGenericLanding
        ? defaultHomeForTier(rolesToTier(roles))
        : returnTo;
      navigate(dest, { replace: true });
    }
  }, [isLoading, isAuthenticated, navigate, roles]);

  // "No matching state" → limpiar sessionStorage y reintentar login una vez
  useEffect(() => {
    if (error && !retried.current && error.message.includes("No matching state")) {
      retried.current = true;
      clearOidcSessionStorage();
      void login();
    }
  }, [error, login]);

  if (error && !(error.message.includes("No matching state") && !retried.current)) {
    return (
      <div className="flex min-h-dvh flex-col items-center justify-center gap-4 p-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <p className="text-lg font-semibold text-destructive">Error de autenticación</p>
          <p className="max-w-sm text-sm text-muted-foreground">{error.message}</p>
          <button
            onClick={() => { clearOidcSessionStorage(); void login(); }}
            className="mt-4 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-dvh flex-col items-center justify-center gap-3">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      <p className="text-sm text-muted-foreground">Completando inicio de sesión...</p>
    </div>
  );
}
