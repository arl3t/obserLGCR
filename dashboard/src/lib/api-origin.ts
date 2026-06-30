/**
 * Origen del API para axios desde el navegador.
 *
 * - `VITE_API_BASE_URL` definido → URL absoluta del API.
 * - Dev (`import.meta.env.DEV`) → "" (Vite proxea /api a :8787).
 * - Prod con VITE_API_BASE_URL vacío → "" (rutas relativas /api/*).
 *   Docker/nginx y reverse proxies en el mismo host reenvían /api al backend.
 * - Excepción: `vite preview` / serve estático en puertos de dev sin proxy
 *   (5173, 4173…) → API directo en :8787 del mismo host.
 */
function isLikelyLabHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "127.0.0.1") return true;
  const lower = hostname.toLowerCase();
  if (lower.endsWith(".local") || lower.endsWith(".lan")) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname)) return true;
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(hostname)) return true;
  return false;
}

/** Puertos donde el front se sirve SIN proxy /api integrado (preview Vite, serve estático). */
const DIRECT_API_PREVIEW_PORTS = new Set(["4173", "5173", "5174", "4174", "3000", "5000", "5500"]);

/** Puertos donde /api suele ir por reverse proxy en el mismo origen (Docker nginx, prod). */
const PROXY_API_PORTS = new Set(["80", "443", "8080", "8443"]);

export function getLegacyHuntApiBase(): string {
  const env = (import.meta.env.VITE_API_BASE_URL ?? "").trim().replace(/\/$/, "");
  if (env) return env;
  if (import.meta.env.DEV) return "";

  if (typeof window !== "undefined") {
    const h = window.location.hostname;
    const rawPort = window.location.port;
    const effectivePort =
      rawPort || (window.location.protocol === "https:" ? "443" : "80");

    // Docker (:8080) y nginx (:80/:443): usar /api relativo en el mismo host.
    if (PROXY_API_PORTS.has(effectivePort) || PROXY_API_PORTS.has(rawPort)) {
      return "";
    }

    // Preview estático sin proxy: API directo en :8787 (mismo host lab).
    if (
      h &&
      isLikelyLabHostname(h) &&
      (DIRECT_API_PREVIEW_PORTS.has(effectivePort) ||
        DIRECT_API_PREVIEW_PORTS.has(rawPort))
    ) {
      const proto = window.location.protocol === "https:" ? "https:" : "http:";
      return `${proto}//${h}:8787`.replace(/\/$/, "");
    }
  }

  return "";
}
