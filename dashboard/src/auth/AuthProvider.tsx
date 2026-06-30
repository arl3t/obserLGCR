/**
 * AuthProvider — envuelve la aplicación con el contexto OIDC de Keycloak.
 *
 * Si VITE_OIDC_AUTHORITY está vacío (modo lab / sin Keycloak), el provider
 * se renderiza como pass-through y no inicia ningún flujo de autenticación.
 *
 * Flujo de autenticación:
 *   1. Usuario accede al dashboard sin sesión → ProtectedRoute llama signinRedirect()
 *   2. Navegador → Keycloak login page (Authorization Code + PKCE)
 *   3. Keycloak → redirect a /auth/callback con code + state
 *   4. LoginCallback procesa el código → obtiene access_token + refresh_token
 *   5. TokenSyncInner actualiza tokenStore → todas las peticiones Axios incluyen el token
 *   6. automaticSilentRenew renueva el token antes de que expire (sin interacción del usuario)
 *
 * Variables de entorno Vite (legacyhunt-dashboard/.env):
 *   VITE_OIDC_AUTHORITY  URL del realm KC accesible desde el navegador
 *                        Ej: http://localhost:8180/realms/legacyhunt-soc
 *   VITE_OIDC_CLIENT_ID  Client ID del dashboard en Keycloak (default: legacyhunt-dashboard)
 */

import { type ReactNode, useEffect } from "react";
import { AuthProvider as OidcAuthProvider, useAuth as useOidcAuth } from "react-oidc-context";
import { tokenStore } from "./token-store";

// ── Configuración OIDC ────────────────────────────────────────────────────────

const OIDC_AUTHORITY = (import.meta.env.VITE_OIDC_AUTHORITY ?? "").trim();
const OIDC_CLIENT_ID = (import.meta.env.VITE_OIDC_CLIENT_ID ?? "legacyhunt-dashboard").trim();

// ── Sincronización token → tokenStore ────────────────────────────────────────
// Este componente debe renderizarse DENTRO de OidcAuthProvider para poder
// usar el hook useAuth de react-oidc-context.

function TokenSyncInner() {
  const auth = useOidcAuth();

  useEffect(() => {
    const token = auth.user?.access_token ?? null;
    tokenStore.set(token);

    // Limpieza cuando el componente desmonta o el usuario hace logout
    return () => {
      tokenStore.clear();
    };
  }, [auth.user?.access_token]);

  return null;
}

// ── AuthProvider público ──────────────────────────────────────────────────────

interface AuthProviderProps {
  children: ReactNode;
}

/**
 * AuthProvider
 * Envuelve la aplicación con el contexto OIDC. Si VITE_OIDC_AUTHORITY no está
 * configurado (modo lab), actúa como pass-through sin autenticación.
 */
export function AuthProvider({ children }: AuthProviderProps) {
  // Modo lab: sin Keycloak configurado → pasar sin auth
  if (!OIDC_AUTHORITY) {
    return <>{children}</>;
  }

  return (
    <OidcAuthProvider
      authority={OIDC_AUTHORITY}
      client_id={OIDC_CLIENT_ID}
      redirect_uri={`${window.location.origin}/auth/callback`}
      post_logout_redirect_uri={`${window.location.origin}/`}
      response_type="code"
      scope="openid profile email roles"
      automaticSilentRenew={true}
      loadUserInfo={true}
      // Limpiar code/state de la URL sin tocar sessionStorage.
      // LoginCallback.tsx lee auth_return_to y hace la navegación React Router.
      onSigninCallback={() => {
        window.history.replaceState({}, document.title, window.location.pathname);
      }}
    >
      <TokenSyncInner />
      {children}
    </OidcAuthProvider>
  );
}
