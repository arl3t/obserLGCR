/** Configuración de autenticación del dashboard (compile-time). */

export const OIDC_AUTHORITY = (import.meta.env.VITE_OIDC_AUTHORITY ?? "").trim();
export const OIDC_CLIENT_ID = (import.meta.env.VITE_OIDC_CLIENT_ID ?? "legacyhunt-dashboard").trim();

/** Auth local contra PostgreSQL (POST /api/auth/login). Default: activo si no hay OIDC. */
export const PLATFORM_AUTH_ENABLED =
  !OIDC_AUTHORITY && import.meta.env.VITE_PLATFORM_AUTH !== "false";

/** Sin OIDC ni platform auth → modo lab (usuario admin sintético). */
export const isLabMode = !OIDC_AUTHORITY && !PLATFORM_AUTH_ENABLED;

export const SESSION_STORAGE_KEY = "obserlgcr_platform_token";
export const SESSION_USER_KEY = "obserlgcr_platform_user";
