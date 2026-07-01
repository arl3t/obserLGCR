/**
 * Resolución de origen del API para axios desde el navegador.
 *
 * IPAM (`/api/v1/ipam/*`) siempre va al mismo origen (nginx :8080 o Vite :5173).
 * El API Node y nginx reenvían al microservicio ipam — nunca llamar :8790 desde el browser.
 */

export function isIpamApiPath(url: string): boolean {
  return url.startsWith("/api/v1/ipam");
}

function isLabHostname(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "127.0.0.1") return true;
  if (h.endsWith(".local") || h.endsWith(".lan")) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

function labDirectBase(port: number): string {
  if (typeof window === "undefined") return "";
  const { hostname, protocol } = window.location;
  if (!isLabHostname(hostname)) return "";
  const proto = protocol === "https:" ? "https:" : "http:";
  return `${proto}//${hostname}:${port}`.replace(/\/$/, "");
}

export function getDirectLabApiBase(): string {
  return labDirectBase(8787);
}

const PROXY_PORTS = new Set(["80", "443", "8080", "8443", "5173", "5174", "4173", "4174"]);

function effectivePort(): string {
  if (typeof window === "undefined") return "";
  const { port, protocol } = window.location;
  return port || (protocol === "https:" ? "443" : "80");
}

export function getLegacyHuntApiBase(url = ""): string {
  if (isIpamApiPath(url)) return "";

  const env = (import.meta.env.VITE_API_BASE_URL ?? "").trim().replace(/\/$/, "");
  if (env) return env;
  if (import.meta.env.DEV) return "";

  if (typeof window !== "undefined") {
    const port = effectivePort();
    if (PROXY_PORTS.has(port)) return "";
    const direct = getDirectLabApiBase();
    if (direct) return direct;
  }

  return "";
}

/** Mismo origen — IPAM nunca usa puerto directo :8790 en el browser. */
export function resolveRequestBaseUrl(url: string): string | undefined {
  if (typeof window === "undefined") return undefined;
  if (isIpamApiPath(url)) return window.location.origin;
  const b = getLegacyHuntApiBase(url);
  return b || window.location.origin;
}

export function shouldRetryMainApiOnNetworkError(
  config: { baseURL?: string; url?: string; __apiRetried?: boolean } | undefined,
): boolean {
  if (!config || config.__apiRetried) return false;
  if (isIpamApiPath(config.url ?? "")) return false;
  const env = (import.meta.env.VITE_API_BASE_URL ?? "").trim();
  if (env) return false;
  const current = (config.baseURL ?? "").replace(/\/$/, "");
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  if (current && origin && current !== origin) return false;
  return Boolean(getDirectLabApiBase());
}
