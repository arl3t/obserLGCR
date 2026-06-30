/**
 * useAuth — hook de autenticación con helpers específicos del SOC LegacyHunt.
 *
 * Envuelve react-oidc-context y añade:
 *   - Extracción de roles SOC desde realm_access.roles del JWT
 *   - hasRole(role): comprueba si el usuario tiene exactamente ese rol
 *   - hasMinRole(minRole): comprueba si el usuario tiene ese rol o uno superior
 *   - login() / logout(): aliases semánticos de signinRedirect / signoutRedirect
 *   - Compatibilidad con modo lab (VITE_OIDC_AUTHORITY vacío → usuario virtual sin auth)
 *
 * Jerarquía de roles (de menor a mayor privilegio):
 *   analyst → hunter → manager → admin
 *
 * Ejemplo de uso:
 *   const { isAuthenticated, hasMinRole, preferredUsername, logout } = useAuth();
 *   if (!hasMinRole("hunter")) return <AccessDenied />;
 */

import { useAuth as useOidcAuth } from "react-oidc-context";
import { tokenStore } from "./token-store";

// Decodifica el payload de un JWT (base64url) sin validar la firma.
// Sólo se usa para leer claims localmente (realm_access.roles).
function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    const part = token.split(".")[1];
    const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(base64)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

// Jerarquía SOC (debe coincidir con auth.middleware.mjs del API)
const ROLE_HIERARCHY = ["analyst", "hunter", "manager", "admin"] as const;
type SocRole = (typeof ROLE_HIERARCHY)[number];

const OIDC_AUTHORITY = (import.meta.env.VITE_OIDC_AUTHORITY ?? "").trim();
const OIDC_CLIENT_ID = (import.meta.env.VITE_OIDC_CLIENT_ID ?? "legacyhunt-dashboard").trim();

// ── Tipo de retorno ───────────────────────────────────────────────────────────

export interface SocAuthState {
  // Estado OIDC base (de react-oidc-context)
  isAuthenticated: boolean;
  isLoading: boolean;
  error: Error | undefined;
  user: ReturnType<typeof useOidcAuth>["user"];

  // Helpers SOC
  roles: string[];
  preferredUsername: string | null;
  email: string | null;
  displayName: string | null;

  hasRole: (role: string) => boolean;
  hasMinRole: (minRole: SocRole | string) => boolean;

  login: () => Promise<void>;
  logout: () => void;

  // Modo lab (sin Keycloak configurado)
  isLabMode: boolean;
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useAuth(): SocAuthState {
  // En modo lab (VITE_OIDC_AUTHORITY vacío) AuthProvider es pass-through y NO hay
  // contexto OIDC, así que useOidcAuth() devuelve undefined. El early-return de
  // lab DEBE ir antes de tocar `auth`, o `auth.user` revienta con
  // "Cannot read properties of undefined (reading 'user')".
  const auth = useOidcAuth();

  // Modo lab: si VITE_OIDC_AUTHORITY no está configurado, comportarse como si hubiera
  // un usuario admin autenticado (compatibilidad total con el stack actual)
  const isLabMode = !OIDC_AUTHORITY;
  if (isLabMode) {
    return {
      isAuthenticated: true,
      isLoading:       false,
      error:           undefined,
      user:            null,
      roles:           ["admin"],
      preferredUsername: "lab-user",
      email:           null,
      displayName:     "Lab User",
      hasRole:         () => true,
      hasMinRole:      () => true,
      login:           async () => {},
      logout:          async () => {},
      isLabMode:       true,
    };
  }

  // Extraer roles SOC del token JWT.
  // Keycloak incluye realm_access en el access_token (scope "roles"), pero NO
  // en el ID token ni en el userinfo endpoint por defecto → profile.realm_access
  // suele estar vacío. Se lee primero desde profile y, si falla, se decodifica
  // el access_token directamente (sin validar firma, sólo para claims locales).
  const rawRoles: string[] = (() => {
    const fromProfile = (
      auth.user?.profile?.realm_access as { roles?: string[] } | undefined
    )?.roles;
    if (fromProfile?.length) return fromProfile;
    if (auth.user?.access_token) {
      const payload = decodeJwtPayload(auth.user.access_token);
      return (payload.realm_access as { roles?: string[] } | undefined)?.roles ?? [];
    }
    return [];
  })();
  const socRoles = rawRoles.filter((r) => ROLE_HIERARCHY.includes(r as SocRole));

  return {
    isAuthenticated:  auth.isAuthenticated,
    isLoading:        auth.isLoading,
    error:            auth.error,
    user:             auth.user,

    roles:            socRoles,
    preferredUsername: auth.user?.profile?.preferred_username ?? null,
    email:            auth.user?.profile?.email ?? null,
    displayName:
      auth.user?.profile?.name ??
      auth.user?.profile?.preferred_username ??
      null,

    /**
     * hasRole — comprueba si el usuario tiene exactamente este rol.
     * Para hierarchy, usa hasMinRole.
     */
    hasRole: (role: string) => socRoles.includes(role),

    /**
     * hasMinRole — comprueba si el usuario tiene este rol o uno de mayor privilegio.
     * Funciona porque los roles son composite en Keycloak:
     *   admin tiene ["analyst","hunter","manager","admin"] en el token.
     * Así que roles.includes(minRole) ya implementa la jerarquía.
     */
    hasMinRole: (minRole: SocRole | string) => socRoles.includes(minRole as string),

    login: () => auth.signinRedirect(),
    logout: () => {
      const idToken = auth.user?.id_token ?? null;
      // Limpiar estado OIDC de sessionStorage de forma SÍNCRONA.
      // NO usar auth.removeUser() (async): su Promise.then() corre como microtask,
      // React re-renderiza ProtectedRoute que llama signinRedirect(), y ese
      // window.location.href al login de KC sobrescribe el href de logout antes
      // de que el browser navegue — la sesión de KC nunca se cierra.
      // Borrar directamente la clave oidc-client-ts evita el re-render.
      for (let i = sessionStorage.length - 1; i >= 0; i--) {
        const key = sessionStorage.key(i);
        if (key?.startsWith("oidc.user:")) sessionStorage.removeItem(key);
      }
      tokenStore.clear();
      const logoutUrl = new URL(`${OIDC_AUTHORITY}/protocol/openid-connect/logout`);
      logoutUrl.searchParams.set("client_id", OIDC_CLIENT_ID);
      logoutUrl.searchParams.set("post_logout_redirect_uri", `${window.location.origin}/`);
      if (idToken) logoutUrl.searchParams.set("id_token_hint", idToken);
      window.location.href = logoutUrl.toString();
    },

    isLabMode: false,
  };
}
