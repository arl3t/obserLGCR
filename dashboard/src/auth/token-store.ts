/**
 * token-store — almacén módulo-nivel del access token OIDC.
 *
 * Necesario porque el interceptor Axios (client.ts) es un módulo puro y no puede
 * acceder al contexto React. AuthProvider actualiza este store cuando cambia el token.
 *
 * Ciclo de vida:
 *   1. AuthProvider monta → TokenSyncInner subscrive al auth context
 *   2. Usuario hace login → react-oidc-context emite user con access_token
 *   3. TokenSyncInner llama tokenStore.set(token)
 *   4. El interceptor Axios llama tokenStore.get() en cada request
 *   5. Usuario hace logout o el token expira → tokenStore.set(null)
 */

let _token: string | null = null;

export const tokenStore = {
  get(): string | null {
    return _token;
  },
  set(token: string | null): void {
    _token = token;
  },
  clear(): void {
    _token = null;
  },
};
