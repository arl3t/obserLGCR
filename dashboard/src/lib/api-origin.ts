/**
 * Origen del legacyhunt-api para axios desde el navegador.
 * - `VITE_API_BASE_URL` (sin barra final) si está definido — p. ej. build detrás de nginx u otro host.
 * - Dev (`import.meta.env.DEV`): cadena vacía → `/api/*` al origen del dev server; Vite proxea a :8787.
 * - Prod sin env y host de lab (localhost, 127.0.0.1, RFC1918): asume API en el mismo host puerto **8787**.
 *   Así `vite preview`, `npx serve dist` u otro estático no devuelven index.html en `/api/*` (error “HTML en lugar de JSON”).
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

/** Puertos típicos de preview/serve del front (API suele seguir en :8787). */
function isStaticPreviewPort(port: string): boolean {
  return new Set(["4173", "5173", "5174", "4174", "3000", "5000", "8080", "5500"]).has(port);
}

export function getLegacyHuntApiBase(): string {
  const env = (import.meta.env.VITE_API_BASE_URL ?? "").trim().replace(/\/$/, "");
  if (env) return env;
  if (import.meta.env.DEV) return "";

  if (typeof window !== "undefined") {
    const h = window.location.hostname;
    const rawPort = window.location.port;
    const effectivePort =
      rawPort || (window.location.protocol === "https:" ? "443" : "80");
    const proto = window.location.protocol === "https:" ? "https:" : "http:";

    if (
      h &&
      (isLikelyLabHostname(h) ||
        isStaticPreviewPort(effectivePort) ||
        isStaticPreviewPort(rawPort))
    ) {
      return `${proto}//${h}:8787`.replace(/\/$/, "");
    }
  }
  return "";
}
