import { isAxiosError } from "axios";
import { api } from "@/api/client";
import type { ThcReverseDnsResponse } from "@/types/thc-rdns";

function htmlHelp(): string {
  return (
    "No se obtuvo JSON del API (legacyhunt-api). " +
    "Pruebe: curl -sS http://127.0.0.1:8787/api/health/live · " +
    "docker compose up -d legacyhunt-api · " +
    "npm run dev (proxy /api) o VITE_API_BASE_URL=http://127.0.0.1:8787 y rebuild. " +
    "Si usaba PWA: borrar datos del sitio / service worker."
  );
}

function isHtmlBody(s: string): boolean {
  const t = (s ?? "").trimStart();
  return t.startsWith("<!") || t.startsWith("<html") || t.startsWith("<HTML");
}

function parseThcJson(body: string, status: number): ThcReverseDnsResponse {
  let parsed: ThcReverseDnsResponse;
  try {
    parsed = JSON.parse(body) as ThcReverseDnsResponse;
  } catch {
    throw new Error(`HTTP ${status}: cuerpo no JSON (${body.slice(0, 120)}…)`);
  }
  if (status >= 400) {
    const msg =
      parsed && typeof parsed === "object" && "error" in parsed
        ? String((parsed as { error?: string }).error ?? "")
        : "";
    throw new Error(msg || `HTTP ${status}`);
  }
  if (!parsed || typeof parsed !== "object" || !("ok" in parsed)) {
    throw new Error("Respuesta inválida del API");
  }
  if (!parsed.ok) {
    throw new Error((parsed as { error?: string }).error ?? "Error reverse DNS");
  }
  return parsed;
}

/** Orígenes directos al Node en :8787 (evitan index.html del SPA cuando /api no está proxeado). */
function direct8787Bases(): string[] {
  if (typeof window === "undefined") return [];
  const h = window.location.hostname;
  const out: string[] = ["http://127.0.0.1:8787"];
  if (h && h !== "127.0.0.1") {
    out.push(`http://${h}:8787`);
  }
  if (window.location.protocol === "https:") {
    out.push(`https://127.0.0.1:8787`);
    if (h && h !== "127.0.0.1") {
      out.push(`https://${h}:8787`);
    }
  }
  return [...new Set(out)];
}

async function fetchThcViaGet(url: string): Promise<{ status: number; body: string }> {
  const r = await fetch(url, {
    credentials: "omit",
    headers: { Accept: "application/json" },
  });
  const body = await r.text();
  return { status: r.status, body };
}

/**
 * GET reverse DNS THC: Axios (respeta VITE_API_BASE_URL / proxy) y, si llega HTML, reintenta en :8787.
 */
export async function fetchThcReverseDnsWithFallback(
  ip: string,
  opts: { live?: boolean } = {},
): Promise<ThcReverseDnsResponse> {
  const params = new URLSearchParams({ ip });
  if (opts.live) params.set("live", "1");

  try {
    const { data: raw, status } = await api.get<string>("/api/intel/thc-reverse-dns", {
      params: { ip, ...(opts.live ? { live: "1" } : {}) },
      responseType: "text",
      transformResponse: (r) => r,
      validateStatus: () => true,
    });
    const body = raw ?? "";
    if (!isHtmlBody(body)) {
      return parseThcJson(body, status);
    }
  } catch (e) {
    if (isAxiosError(e)) {
      const d = e.response?.data;
      if (typeof d === "string" && isHtmlBody(d)) {
        /* continuar a :8787 */
      } else if (e.response == null) {
        /* sin respuesta (red, etc.) — probar :8787 */
      } else {
        throw e;
      }
    } else {
      throw e;
    }
  }

  for (const base of direct8787Bases()) {
    const url = `${base.replace(/\/$/, "")}/api/intel/thc-reverse-dns?${params.toString()}`;
    try {
      const { status, body } = await fetchThcViaGet(url);
      if (!isHtmlBody(body)) {
        return parseThcJson(body, status);
      }
    } catch {
      /* siguiente base */
    }
  }

  throw new Error(htmlHelp());
}
