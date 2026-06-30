/**
 * nvdEnrichment.mjs — B1 audit Casos 2026-05-21
 *
 * Cache + fetcher de metadata oficial NVD (National Vulnerability Database)
 * para los CVEs detectados en /api/cases/:id/cves.
 *
 * Por qué un cache PG y no cada request directo:
 *   · Rate limit NVD: 50/30s con API key, 5/30s sin clave. Un panel de caso
 *     fácilmente lista 5–20 CVEs; sin cache hubiéramos saturado en minutos.
 *   · Latencia NVD: 1–4s p50, hasta 10s con load. Inline rompería el SLA
 *     del endpoint del caso.
 *   · Estabilidad: CVSS/CWE/descripción cambian poco — TTL 30d es seguro,
 *     y los CVEs en `AWAITING_ANALYSIS` (sin CVSS asignado) se reintentan
 *     a las 24h por si NVD los completó.
 *
 * Flujo del endpoint:
 *   1. `getEnrichmentBatch(cveIds)` → devuelve filas válidas de cve_cache.
 *   2. Para los CVEs faltantes/expirados, devuelve placeholder (status:'pending')
 *      y **encola fetch background** (no bloquea la respuesta).
 *   3. El worker async hace requests serializados a NVD (1 req cada 700ms,
 *      muy debajo del límite 50/30s) y persiste en cve_cache.
 *
 * El frontend muestra "—" para los que todavía no tienen enrichment y refetch
 * en 30-60s revela los datos.
 *
 * Tests: tests/nvdEnrichment.test.mjs (parser snapshot, sin red).
 */

import { pgQuery } from "../db/postgres.mjs";
import { config } from "../config.mjs";
import { logger } from "../logger.mjs";
import { getResolvedKey } from "./apiKeysService.mjs";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
// EPSS (FIRST.org) — keyless, batchable, sin rate-limit documentado. Se recalcula
// a diario, así que un TTL de 24h mantiene el dato fresco sin sobre-consultar.
const EPSS_URL = "https://api.first.org/data/v1/epss";
const EPSS_TTL_MS = 24 * 3600 * 1000;
const EPSS_BATCH = 80;   // CVEs por request (acota el largo del query string)

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const TTL_OK_MS         = 30 * 24 * 3600 * 1000;     // 30 días
const TTL_AWAITING_MS   = 24 * 3600 * 1000;          // 1 día (NVD aún sin analizar)
const TTL_NOT_FOUND_MS  = 7 * 24 * 3600 * 1000;      // 7 días (CVE inválido)
const FETCH_TIMEOUT_MS  = 12_000;
const FETCH_INTERVAL_MS = 700;                        // ~1.4 req/s, debajo de 50/30s

// ── DDL idempotente ─────────────────────────────────────────────────────────
export async function ensureCveCacheTable() {
  await pgQuery(`CREATE SCHEMA IF NOT EXISTS legacyhunt_soc`);
  await pgQuery(`
    CREATE TABLE IF NOT EXISTS legacyhunt_soc.cve_cache (
      cve_id              VARCHAR(32)  PRIMARY KEY,
      cvss_v3_score       NUMERIC(3,1),
      cvss_v3_severity    VARCHAR(16),
      cvss_v3_vector      VARCHAR(64),
      cvss_v2_score       NUMERIC(3,1),
      cwe_ids             TEXT[],
      description         TEXT,
      reference_urls      TEXT[],
      published_at        TIMESTAMPTZ,
      last_modified       TIMESTAMPTZ,
      vuln_status         VARCHAR(32),
      fetched_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
      ttl_until           TIMESTAMPTZ  NOT NULL DEFAULT now() + INTERVAL '30 days'
    )
  `);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_cve_cache_ttl_until   ON legacyhunt_soc.cve_cache (ttl_until)`);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_cve_cache_vuln_status ON legacyhunt_soc.cve_cache (vuln_status)`);
  // EPSS (I1 audit 2026-06-05): probabilidad de explotación en 30 días (FIRST.org).
  // Independiente del TTL de NVD — EPSS se recalcula a diario, por eso su propia
  // marca de fetch. ALTER idempotente: se auto-aplica al boot aunque la tabla
  // ya exista (migración 075 replica esto para el deploy).
  await pgQuery(`ALTER TABLE legacyhunt_soc.cve_cache ADD COLUMN IF NOT EXISTS epss_score      NUMERIC(8,6)`);
  await pgQuery(`ALTER TABLE legacyhunt_soc.cve_cache ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(8,6)`);
  await pgQuery(`ALTER TABLE legacyhunt_soc.cve_cache ADD COLUMN IF NOT EXISTS epss_fetched_at TIMESTAMPTZ`);
}

// ── Parser puro (testeable sin red) ─────────────────────────────────────────

/**
 * Convierte un item del array `vulnerabilities` de NVD 2.0 a la fila del
 * cache. Retorna `null` si el shape no es reconocible. Exportado para tests.
 */
export function parseNvdVulnerability(item) {
  const cve = item?.cve;
  if (!cve?.id || !CVE_RE.test(cve.id)) return null;

  const metrics = cve.metrics ?? {};
  // NVD devuelve cvssMetricV31, cvssMetricV30 y cvssMetricV2 como arrays
  // (uno por "fuente" — primary, secondary). Tomamos el primary si existe,
  // si no el primero.
  function pickPrimary(arr) {
    if (!Array.isArray(arr) || !arr.length) return null;
    return arr.find((m) => m?.type === "Primary") ?? arr[0];
  }
  const v31 = pickPrimary(metrics.cvssMetricV31);
  const v30 = pickPrimary(metrics.cvssMetricV30);
  const v2  = pickPrimary(metrics.cvssMetricV2);
  const v3  = v31 ?? v30;

  const v3Score    = Number(v3?.cvssData?.baseScore);
  const v3Severity = v3?.cvssData?.baseSeverity ?? null;
  const v3Vector   = v3?.cvssData?.vectorString ?? null;
  const v2Score    = Number(v2?.cvssData?.baseScore);

  // CWEs: weaknesses[].description[].value === "CWE-XXX"
  const cwes = new Set();
  for (const w of cve.weaknesses ?? []) {
    for (const d of w?.description ?? []) {
      if (typeof d?.value === "string" && /^CWE-\d+$/.test(d.value)) {
        cwes.add(d.value);
      }
    }
  }

  // Descripción english
  const en = (cve.descriptions ?? []).find((d) => d?.lang === "en");

  // Top 10 referencias URL
  const refs = [];
  for (const r of cve.references ?? []) {
    if (typeof r?.url === "string" && refs.length < 10) refs.push(r.url);
  }

  return {
    cve_id:           cve.id,
    cvss_v3_score:    Number.isFinite(v3Score) ? v3Score : null,
    cvss_v3_severity: v3Severity,
    cvss_v3_vector:   v3Vector,
    cvss_v2_score:    Number.isFinite(v2Score) ? v2Score : null,
    cwe_ids:          [...cwes],
    description:      en?.value ?? null,
    reference_urls:   refs,
    published_at:     cve.published ? new Date(cve.published) : null,
    last_modified:    cve.lastModified ? new Date(cve.lastModified) : null,
    vuln_status:      cve.vulnStatus ?? null,
  };
}

/** Calcula el TTL adecuado para una fila parseada. Exportado para tests. */
export function ttlForRow(row) {
  if (!row) return TTL_NOT_FOUND_MS;
  if (row.vuln_status && /awaiting/i.test(row.vuln_status)) return TTL_AWAITING_MS;
  return TTL_OK_MS;
}

// ── Fetcher con rate limit interno ──────────────────────────────────────────

let _lastFetchAt = 0;
const _queue = new Map(); // cve_id → Promise<row | null>

async function fetchOneFromNvd(cveId) {
  // Throttle simple: respeta FETCH_INTERVAL_MS entre llamadas serializadas.
  const wait = Math.max(0, _lastFetchAt + FETCH_INTERVAL_MS - Date.now());
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  _lastFetchAt = Date.now();

  const url = `${NVD_URL}?cveId=${encodeURIComponent(cveId)}`;
  const headers = {};
  const nvdKey = (await getResolvedKey("NVD_API_KEY")) || config.NVD_API_KEY;
  if (nvdKey) headers.apiKey = nvdKey;

  let res;
  try {
    res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    logger.warn("nvd: fetch network error", { cveId, error: err?.message });
    return null;
  }

  if (res.status === 404 || res.status === 400) {
    // NVD devuelve 404 para CVE inexistente; lo cacheamos como "not_found"
    // con TTL corto para no martillarlo en cada refresh del panel.
    return { cve_id: cveId, vuln_status: "NOT_FOUND" };
  }
  if (!res.ok) {
    logger.warn("nvd: fetch non-2xx", { cveId, status: res.status });
    return null;
  }

  let data;
  try {
    data = await res.json();
  } catch {
    logger.warn("nvd: invalid json", { cveId });
    return null;
  }
  const items = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  if (!items.length) {
    return { cve_id: cveId, vuln_status: "NOT_FOUND" };
  }
  return parseNvdVulnerability(items[0]);
}

async function upsertRow(row) {
  if (!row?.cve_id) return;
  const ttlMs = ttlForRow(row);
  await pgQuery(
    `
    INSERT INTO legacyhunt_soc.cve_cache
      (cve_id, cvss_v3_score, cvss_v3_severity, cvss_v3_vector, cvss_v2_score,
       cwe_ids, description, reference_urls, published_at, last_modified,
       vuln_status, fetched_at, ttl_until)
    VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(),
       now() + ($12 || ' milliseconds')::interval)
    ON CONFLICT (cve_id) DO UPDATE SET
      cvss_v3_score    = EXCLUDED.cvss_v3_score,
      cvss_v3_severity = EXCLUDED.cvss_v3_severity,
      cvss_v3_vector   = EXCLUDED.cvss_v3_vector,
      cvss_v2_score    = EXCLUDED.cvss_v2_score,
      cwe_ids          = EXCLUDED.cwe_ids,
      description      = EXCLUDED.description,
      reference_urls   = EXCLUDED.reference_urls,
      published_at     = EXCLUDED.published_at,
      last_modified    = EXCLUDED.last_modified,
      vuln_status      = EXCLUDED.vuln_status,
      fetched_at       = now(),
      ttl_until        = now() + (${ttlMs} || ' milliseconds')::interval
    `,
    [
      row.cve_id,
      row.cvss_v3_score    ?? null,
      row.cvss_v3_severity ?? null,
      row.cvss_v3_vector   ?? null,
      row.cvss_v2_score    ?? null,
      row.cwe_ids          ?? null,
      row.description      ?? null,
      row.reference_urls   ?? null,
      row.published_at     ?? null,
      row.last_modified    ?? null,
      row.vuln_status      ?? null,
      String(ttlMs),
    ],
  );
}

async function fetchAndCache(cveId) {
  if (_queue.has(cveId)) return _queue.get(cveId);
  const p = (async () => {
    try {
      const row = await fetchOneFromNvd(cveId);
      if (row) await upsertRow(row);
      return row;
    } catch (err) {
      logger.warn("nvd: fetchAndCache failed", { cveId, error: err?.message });
      return null;
    } finally {
      _queue.delete(cveId);
    }
  })();
  _queue.set(cveId, p);
  return p;
}

// ── EPSS (FIRST.org) ─────────────────────────────────────────────────────────

/**
 * Upsert batch de EPSS sobre cve_cache. Si la fila no existe (NVD aún no
 * fetcheado), la inserta con `ttl_until = now()` para que el NVD siga
 * pendiente; si existe, sólo toca las columnas epss_* (no pisa el TTL de NVD).
 */
async function upsertEpssBatch(items) {
  const rows = (Array.isArray(items) ? items : []).filter((it) => it?.cve && CVE_RE.test(it.cve));
  if (!rows.length) return;
  const tuples = [];
  const params = [];
  let i = 1;
  for (const it of rows) {
    const score = Number(it.epss);
    const pct   = Number(it.percentile);
    tuples.push(`($${i++}, $${i++}, $${i++}, now(), now())`);
    params.push(it.cve, Number.isFinite(score) ? score : null, Number.isFinite(pct) ? pct : null);
  }
  await pgQuery(
    `INSERT INTO legacyhunt_soc.cve_cache
       (cve_id, epss_score, epss_percentile, epss_fetched_at, ttl_until)
     VALUES ${tuples.join(", ")}
     ON CONFLICT (cve_id) DO UPDATE SET
       epss_score      = EXCLUDED.epss_score,
       epss_percentile = EXCLUDED.epss_percentile,
       epss_fetched_at = now()`,
    params,
  );
}

/**
 * Fetch EPSS para una lista de CVEs (chunked) y persiste. Best-effort:
 * fallos de red se loggean y se saltan. Sin rate-limit, pero chunkeamos para
 * no exceder el largo del query string.
 */
async function fetchEpssBatchAndCache(cveIds) {
  const valid = [...new Set((cveIds ?? []).filter((c) => typeof c === "string" && CVE_RE.test(c)))];
  for (let off = 0; off < valid.length; off += EPSS_BATCH) {
    const chunk = valid.slice(off, off + EPSS_BATCH);
    let data;
    try {
      const res = await fetch(`${EPSS_URL}?cve=${chunk.join(",")}`, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) { logger.warn("epss: fetch non-2xx", { status: res.status }); continue; }
      data = await res.json();
    } catch (err) {
      logger.warn("epss: fetch error", { error: err?.message });
      continue;
    }
    try {
      await upsertEpssBatch(data?.data);
    } catch (err) {
      logger.warn("epss: upsert error", { error: err?.message });
    }
  }
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Lee del cache las filas válidas (no expiradas) para los CVEs pedidos y
 * encola fetch en background para los que faltan o expiraron.
 *
 * Devuelve un Map<cve_id, row> con las que ya tenemos cacheadas; el resto
 * tendrá NVD data en el próximo refresh (el cliente puede mostrar skeleton
 * y refrescar en 30-60s).
 *
 * @param {string[]} cveIds
 * @returns {Promise<Map<string, object>>}
 */
export async function getEnrichmentBatch(cveIds) {
  const out = new Map();
  if (!Array.isArray(cveIds) || !cveIds.length) return out;

  const valid = [...new Set(cveIds.filter((c) => typeof c === "string" && CVE_RE.test(c)))];
  if (!valid.length) return out;

  const rows = await pgQuery(
    `SELECT cve_id, cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
            cvss_v2_score, cwe_ids, description, reference_urls,
            published_at, last_modified, vuln_status, fetched_at, ttl_until,
            epss_score, epss_percentile, epss_fetched_at
       FROM legacyhunt_soc.cve_cache
      WHERE cve_id = ANY($1::text[])`,
    [valid],
  );
  const now = Date.now();
  const rowByCve = new Map();
  for (const r of rows) {
    rowByCve.set(r.cve_id, r);
    if (new Date(r.ttl_until).getTime() > now) {
      out.set(r.cve_id, r);
    }
  }

  // Background fetch NVD para los que faltan o están expirados.
  const missing = valid.filter((c) => !out.has(c));
  if (missing.length) {
    // No await — fire-and-forget; los errores van al logger del worker.
    Promise.all(missing.map((c) => fetchAndCache(c))).catch(() => { /* swallowed */ });
  }

  // Background fetch EPSS para los que no tienen score o lo tienen vencido
  // (>24h). Independiente del TTL de NVD: un CVE con NVD fresco igual puede
  // tener EPSS stale. Un solo request batch FIRST.org cubre toda la lista.
  const epssStale = valid.filter((c) => {
    const r = rowByCve.get(c);
    if (!r || !r.epss_fetched_at) return true;
    return now - new Date(r.epss_fetched_at).getTime() > EPSS_TTL_MS;
  });
  if (epssStale.length) {
    fetchEpssBatchAndCache(epssStale).catch(() => { /* swallowed */ });
  }
  return out;
}

/**
 * Versión sync-await: fetch + cache de un único CVE. Usado por scripts/CLIs
 * y para warm-up. NO usar en el path crítico del endpoint del caso.
 */
export async function fetchAndCacheCve(cveId) {
  if (!CVE_RE.test(cveId ?? "")) return null;
  return fetchAndCache(cveId);
}
