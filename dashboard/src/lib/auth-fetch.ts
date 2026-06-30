/**
 * authFetch — wrapper de `fetch` con paridad de credenciales al interceptor
 * de Axios en `api/client.ts`. Necesario porque tras `requireAuth("manager")`
 * en el gate /api/surveillance/*, las llamadas `fetch()` raw fallaban con
 * 401 "Autenticación requerida" cuando el OIDC JWT no estaba presente o no
 * verificaba (Axios sí seguía funcionando porque incluye `X-Api-Key` como
 * fallback cuando `OIDC_ALLOW_API_KEY_FALLBACK=true` en el backend).
 *
 * Headers que adjunta (en este orden de prioridad):
 *   1. Authorization: Bearer <token>   tokenStore.get() ?? localStorage("lh_auth_token")
 *   2. X-Api-Key: <VITE_TRINO_PROXY_API_KEY>   si está definida
 *
 * No pisa headers preexistentes; si el caller ya puso Authorization/X-Api-Key
 * por su cuenta, se respetan.
 */

import { tokenStore } from "@/auth/token-store";

const TRINO_PROXY_API_KEY = (import.meta.env.VITE_TRINO_PROXY_API_KEY ?? "").trim();

export function authFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const token = tokenStore.get() ?? (typeof localStorage !== "undefined" ? localStorage.getItem("lh_auth_token") : null);
  const headers = new Headers(init.headers ?? {});

  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (TRINO_PROXY_API_KEY && !headers.has("X-Api-Key")) {
    headers.set("X-Api-Key", TRINO_PROXY_API_KEY);
  }

  // Si no hay credenciales y no hay headers que añadir, evitar copiar init innecesariamente.
  if (!token && !TRINO_PROXY_API_KEY && [...headers.keys()].length === 0) {
    return fetch(input, init);
  }
  return fetch(input, { ...init, headers });
}
