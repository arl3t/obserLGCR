import type { IntelligenceSourcesSummary } from "@/types/intelligence-sources";
import { getLegacyHuntApiBase } from "@/lib/api-origin";

const INTEL_PATH = "/api/intelligence-sources";

/**
 * URLs a probar en orden. Prioriza mismo origen + proxy Vite/nginx para evitar
 * recibir index.html (HTML) cuando /api no está proxeado o :8787 no es el API.
 */
function intelligenceSourcesCandidateUrls(): string[] {
  const explicit = (import.meta.env.VITE_API_BASE_URL ?? "").trim().replace(/\/$/, "");
  const out: string[] = [];

  if (explicit) {
    if (explicit.endsWith("/api")) {
      out.push(`${explicit}/intelligence-sources`);
    } else {
      out.push(`${explicit}${INTEL_PATH}`);
    }
  }

  const inferred = getLegacyHuntApiBase();
  if (inferred) {
    out.push(`${inferred}${INTEL_PATH}`);
  }

  out.push(INTEL_PATH);

  if (import.meta.env.DEV && typeof window !== "undefined") {
    let h = window.location.hostname;
    if (h.includes(":") && !h.startsWith("[")) h = `[${h}]`;
    out.push(`http://${h}:8787${INTEL_PATH}`);
  }

  return [...new Set(out)];
}

function looksLikeHtml(body: string): boolean {
  const t = body.trimStart().slice(0, 64).toLowerCase();
  return t.startsWith("<!") || t.startsWith("<html") || t.startsWith("<head");
}

function intelUrlToHealthUrl(intelUrl: string): string {
  if (intelUrl.endsWith(INTEL_PATH)) {
    const base = intelUrl.slice(0, -INTEL_PATH.length);
    return `${base}/api/health`;
  }
  return intelUrl.replace(INTEL_PATH, "/api/health");
}

/** Ayuda a distinguir API real vs SPA (Vite/nginx) en :8787. */
async function diagnoseHealth(intelCandidates: string[]): Promise<string[]> {
  const lines: string[] = [];
  const healthUrls = [...new Set(intelCandidates.map(intelUrlToHealthUrl))];
  for (const hu of healthUrls) {
    try {
      const r = await fetch(hu, { cache: "no-store" });
      const text = await r.text();
      const trimmed = text.trimStart();
      if (looksLikeHtml(text)) {
        lines.push(
          `Diagnóstico ${hu}: HTTP ${r.status} HTML → ese origen no es legacyhunt-api (suele ser Vite u otro front en el mismo puerto, o 404 antiguo de Express sin la ruta nueva).`,
        );
        continue;
      }
      if (!trimmed.startsWith("{")) {
        lines.push(`Diagnóstico ${hu}: HTTP ${r.status}, cuerpo no JSON.`);
        continue;
      }
      try {
        const j = JSON.parse(text) as { service?: string; ok?: boolean };
        if (j.service === "legacyhunt-api" && j.ok) {
          lines.push(
            `Diagnóstico ${hu}: legacyhunt-api OK — si /api/intelligence-sources sigue en HTML, reinicie el contenedor tras git pull: docker compose up -d legacyhunt-api`,
          );
        } else {
          lines.push(`Diagnóstico ${hu}: JSON inesperado (service=${String(j.service)}).`);
        }
      } catch {
        lines.push(`Diagnóstico ${hu}: JSON inválido.`);
      }
    } catch (e) {
      lines.push(
        `Diagnóstico ${hu}: ${e instanceof Error ? e.message : String(e)} (¿nada escuchando o firewall?)`,
      );
    }
  }
  return lines;
}

/** Intenta una URL; null = reintentar otra (p. ej. cuerpo HTML). */
async function tryFetchOne(
  url: string,
): Promise<
  | { ok: true; data: IntelligenceSourcesSummary }
  | { ok: false; retry: boolean; detail: string }
> {
  let r: Response;
  try {
    r = await fetch(url, { cache: "no-store" });
  } catch (e) {
    return {
      ok: false,
      retry: true,
      detail: `${url}: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  const text = await r.text();
  if (looksLikeHtml(text)) {
    const hint404 =
      r.status === 404 && /cannot get/i.test(text)
        ? " (404 Express: ruta inexistente → API sin GET /api/intelligence-sources; actualice y reinicie legacyhunt-api)"
        : "";
    return {
      ok: false,
      retry: true,
      detail: `${url}: HTTP ${r.status} HTML${hint404}`,
    };
  }

  let j: unknown;
  try {
    j = JSON.parse(text);
  } catch {
    return {
      ok: false,
      retry: true,
      detail: `${url}: no es JSON (${text.slice(0, 80).replace(/\s+/g, " ")}…)`,
    };
  }

  const o = j as {
    ok?: boolean;
    error?: string;
    snapshotAt?: string;
    sources?: IntelligenceSourcesSummary["sources"];
  };

  if (!r.ok) {
    return {
      ok: false,
      retry: false,
      detail: o.error ?? `HTTP ${r.status}`,
    };
  }
  if (!o.ok) {
    return {
      ok: false,
      retry: false,
      detail: o.error ?? "API devolvió ok: false",
    };
  }
  if (!Array.isArray(o.sources) || typeof o.snapshotAt !== "string") {
    return {
      ok: false,
      retry: false,
      detail: "Formato inválido (faltan sources o snapshotAt)",
    };
  }

  return {
    ok: true,
    data: { snapshotAt: o.snapshotAt, sources: o.sources },
  };
}

/** Datos reales: Trino + lake (MinIO) vía legacyhunt-api. */
export async function fetchIntelligenceSourcesLive(): Promise<IntelligenceSourcesSummary> {
  const candidates = intelligenceSourcesCandidateUrls();
  const failures: string[] = [];

  for (const url of candidates) {
    const hit = await tryFetchOne(url);
    if (hit.ok) return hit.data;
    failures.push(hit.detail);
    if (!hit.retry) {
      throw new Error(hit.detail);
    }
  }

  const diag = await diagnoseHealth(candidates);
  throw new Error(
    [
      `No se pudo obtener JSON de ${INTEL_PATH}.`,
      "",
      "Intentos:",
      ...failures.map((f) => `• ${f}`),
      "",
      ...diag,
      "",
      "Acciones: `docker compose --profile core --profile lakehouse up -d` (servicio legacyhunt-api en :8787). Compruebe `curl -sS http://127.0.0.1:8787/api/health`. En dev, Vite proxea `/api` a ese puerto.",
    ].join("\n"),
  );
}

