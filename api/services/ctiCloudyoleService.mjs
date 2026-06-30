/**
 * ctiCloudyoleService.mjs — Cliente para la API CTI Cloud & Olé (Kaduu).
 *
 * Endpoints reales (descubiertos vía OpenAPI con Basic Auth):
 *   POST /api/monitor/leaks/domain   body {"domain":"x"}     → leaks asociados a un dominio
 *   POST /api/monitor/leaks/email    body {"email":"x"}      → leaks asociados a un email
 *   GET  /api/me                                              → perfil de la cuenta (ping)
 *
 * Auth: header `X-API-Key`. La doc (`/docs`, `/openapi.json`) está detrás de un
 * Basic Auth de nginx independiente — sólo necesario para inspeccionar el spec,
 * no para usar el API.
 *
 * Variables de entorno:
 *   CTI_CLOUDYOLE_BASE_URL   default https://cti.cloudyole.es
 *   CTI_CLOUDYOLE_API_KEY    requerido
 *
 * Modo manual: cada búsqueda exitosa puede persistir el JSON crudo en S3
 * (ver `saveCtiResultToS3`). El uso esperado es desde rutas server.mjs, que
 * inyectan el `S3Client` y el bucket/prefix configurados.
 */

import { PutObjectCommand } from "@aws-sdk/client-s3";
import { randomUUID } from "node:crypto";
import { getResolvedKeySync } from "./apiKeysService.mjs";

// ── Config ─────────────────────────────────────────────────────────────────────

function getCtiConfig() {
  return {
    baseUrl: (process.env.CTI_CLOUDYOLE_BASE_URL ?? "").trim().replace(/\/+$/, ""),
    apiKey: (getResolvedKeySync("CTI_CLOUDYOLE_API_KEY") ?? "").trim(),   // DB (Ajustes) → .env
    timeoutMs: 15_000,
  };
}

export function ctiConfigured() {
  const { baseUrl, apiKey } = getCtiConfig();
  return Boolean(baseUrl && apiKey);
}

// ── Transporte ────────────────────────────────────────────────────────────────

async function ctiFetch(path, opts = {}) {
  const { baseUrl, apiKey, timeoutMs } = getCtiConfig();
  if (!baseUrl || !apiKey) {
    throw new Error("CTI Cloud & Olé no configurado (CTI_CLOUDYOLE_BASE_URL / CTI_CLOUDYOLE_API_KEY)");
  }
  const res = await fetch(`${baseUrl}${path}`, {
    ...opts,
    headers: {
      "X-API-Key": apiKey,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
    signal: AbortSignal.timeout(timeoutMs),
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }

  if (!res.ok) {
    const err = new Error(
      `CTI Cloud & Olé HTTP ${res.status} — ${opts.method ?? "GET"} ${path}`,
    );
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

/**
 * Aplana la respuesta `{ data: [[hit, hit, ...]] }` que devuelve la API a un
 * array simple. La API a veces devuelve `data` como array-de-arrays (paginado
 * por shard) y otras como array plano; este helper cubre ambas formas.
 */
export function flattenLeakResponse(data) {
  if (!data || typeof data !== "object") return [];
  const inner = data.data;
  if (!Array.isArray(inner)) return [];
  if (inner.length === 0) return [];
  if (Array.isArray(inner[0])) return inner.flat();
  return inner;
}

// ── API pública ───────────────────────────────────────────────────────────────

/** GET /api/me — verifica que las credenciales estén bien y la API esté arriba. */
export async function ping() {
  try {
    const data = await ctiFetch("/api/me");
    return { ok: true, detail: data?.email ?? data?.username ?? "connected" };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * Busca leaks asociados a un dominio.
 * @param {string} domain
 * @returns {Promise<{configured:boolean, count:number, hits:object[], raw?:object, error?:string}>}
 */
export async function searchDomainLeaks(domain) {
  if (!ctiConfigured()) return { configured: false, count: 0, hits: [] };
  try {
    const raw = await ctiFetch("/api/monitor/leaks/domain", {
      method: "POST",
      body: JSON.stringify({ domain }),
    });
    const hits = flattenLeakResponse(raw);
    return { configured: true, count: hits.length, hits, raw };
  } catch (e) {
    return { configured: true, count: 0, hits: [], error: e.message };
  }
}

/**
 * Busca leaks asociados a un email.
 * @param {string} email
 */
export async function searchEmailLeaks(email) {
  if (!ctiConfigured()) return { configured: false, count: 0, hits: [] };
  try {
    const raw = await ctiFetch("/api/monitor/leaks/email", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
    const hits = flattenLeakResponse(raw);
    return { configured: true, count: hits.length, hits, raw };
  } catch (e) {
    return { configured: true, count: 0, hits: [], error: e.message };
  }
}

// ── Persistencia S3 ───────────────────────────────────────────────────────────

/**
 * Persiste el resultado crudo en S3 al prefijo del lake.
 * Path:
 *   <prefix>/source=cti/year=YYYY/month=MM/day=DD/kind=<kind>/<slug>_<ts>_<id>.json
 *
 * @param {object} args
 * @param {import('@aws-sdk/client-s3').S3Client} args.s3Client
 * @param {string} args.bucket
 * @param {string} args.prefix - p.ej. "leak_intel/raw" (sin barra final)
 * @param {'domain'|'email'} args.kind
 * @param {string} args.query - dominio o email consultado
 * @param {object} args.raw - JSON crudo recibido de la API
 * @param {object} [args.summary] - opcional: { count }
 * @returns {Promise<{bucket:string,key:string,size:number}>}
 */
export async function saveCtiResultToS3({ s3Client, bucket, prefix, kind, query, raw, summary }) {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  const ts = now.toISOString().replace(/[:-]/g, "").replace(/\.\d{3}Z$/, "Z");
  const slug =
    String(query)
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 80) || "unknown";
  const id = randomUUID().slice(0, 8);
  const key = `${prefix}/source=cti/year=${y}/month=${m}/day=${d}/kind=${kind}/${slug}_${ts}_${id}.json`;

  const body = JSON.stringify(
    {
      source: "cti-cloudyole",
      kind,
      query,
      queriedAt: now.toISOString(),
      summary: summary ?? null,
      raw,
    },
    null,
    2,
  );

  await s3Client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: body,
      ContentType: "application/json",
      Metadata: {
        source: "cti-cloudyole",
        kind,
        // S3 metadata sólo acepta ASCII y limita tamaño; recortamos.
        query: String(query).replace(/[^\x20-\x7e]/g, "_").slice(0, 200),
      },
    }),
  );

  return { bucket, key, size: Buffer.byteLength(body, "utf8") };
}
