/**
 * Origen del API para axios desde el navegador.
 *
 * - `VITE_API_BASE_URL` definido → URL absoluta (requiere CORS en el backend).
 * - Vacío → rutas relativas `/api/*` (nginx Docker :8080, proxy Vite :5173).
 * - Fallback runtime → `:8787` en el mismo host (lab/LAN) si el proxy falla.
 */

const PROXY_PORTS = new Set(["80", "443", "8080", "8443", "5173", "5174", "4173", "4174"]);

function isLabHostname(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "127.0.0.1") return true;
  if (h.endsWith(".local") || h.endsWith(".lan")) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

/** API directo en :8787 (mismo host que el dashboard). CORS habilitado en modo demo. */
export function getDirectLabApiBase(): string {
  if (typeof window === "undefined") return "";
  const { hostname, protocol } = window.location;
  if (!isLabHostname(hostname)) return "";
  const proto = protocol === "https:" ? "https:" : "http:";
  return `${proto}//${hostname}:8787`.replace(/\/$/, "");
}

function effectivePort(): string {
  if (typeof window === "undefined") return "";
  const { port, protocol } = window.location;
  return port || (protocol === "https:" ? "443" : "80");
}

let runtimeFallback = "";

export function setRuntimeApiFallback(base: string): void {
  runtimeFallback = base.replace(/\/$/, "");
}

export function getLegacyHuntApiBase(): string {
  const env = (import.meta.env.VITE_API_BASE_URL ?? "").trim().replace(/\/$/, "");
  if (env) return env;
  if (runtimeFallback) return runtimeFallback;
  if (import.meta.env.DEV) return "";

  if (typeof window !== "undefined") {
    const port = effectivePort();
    if (PROXY_PORTS.has(port)) return "";
    const direct = getDirectLabApiBase();
    if (direct) return direct;
  }

  return "";
}

export function shouldRetryApiOnNetworkError(config: { baseURL?: string; __apiRetried?: boolean } | undefined): boolean {
    if (!config || config.__apiRetried) return false;
  const env = (import.meta.env.VITE_API_BASE_URL ?? "").trim();
  if (env) return false;
  const current = (config.baseURL ?? "").replace(/\/$/, "");
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  // Reintentar con :8787 si falló vía proxy/same-origin
  if (current && origin && current !== origin) return false;
  return Boolean(getDirectLabApiBase());
}
