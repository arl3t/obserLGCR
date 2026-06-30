/**
 * kevCatalog.mjs — B1 audit Casos 2026-05-21
 *
 * Mantenedor del catálogo CISA Known Exploited Vulnerabilities (KEV).
 *
 *   · CISA publica un JSON único con TODAS las KEV (~1200 al 2026-05).
 *   · No hay paginación ni rate limit: un GET trae el bulk completo (~600 kB).
 *   · CISA actualiza ~semanal; refrescamos cada 24h por seguridad.
 *
 * Uso desde el endpoint /api/cases/:id/cves:
 *   const kevMap = await getKevByIds(cveIds);  // Map<cve_id, kevRow>
 *   // → si hay match, badge "🚨 KEV — explotación activa" en el panel
 *
 * El primer pull se dispara al boot (lazy) si la tabla está vacía o más
 * vieja de 7 días. Un refresh manual está expuesto vía
 * `refreshKevCatalog()` para que un endpoint admin pueda forzarlo.
 *
 * Decisión: NO marcamos `expires_at` por CVE — una CVE que estuvo en KEV
 * y luego CISA la quitó debe desaparecer del catálogo. El refresh hace
 * TRUNCATE+INSERT (transacción) para mantener consistencia con CISA.
 */

import { pgQuery, withPgClient } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const REFRESH_AFTER_MS = 7 * 24 * 3600 * 1000;     // 7 días
const FETCH_TIMEOUT_MS = 30_000;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

// ── DDL idempotente ─────────────────────────────────────────────────────────
export async function ensureKevTable() {
  await pgQuery(`CREATE SCHEMA IF NOT EXISTS legacyhunt_soc`);
  await pgQuery(`
    CREATE TABLE IF NOT EXISTS legacyhunt_soc.cve_kev (
      cve_id                 VARCHAR(32)  PRIMARY KEY,
      vendor_project         VARCHAR(128),
      product                VARCHAR(256),
      vulnerability_name     TEXT,
      date_added             DATE,
      short_description      TEXT,
      required_action        TEXT,
      due_date               DATE,
      known_ransomware_use   BOOLEAN      NOT NULL DEFAULT false,
      notes                  TEXT,
      cwes                   TEXT[],
      refreshed_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
    )
  `);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_cve_kev_date_added ON legacyhunt_soc.cve_kev (date_added DESC)`);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_cve_kev_ransomware ON legacyhunt_soc.cve_kev (known_ransomware_use)`);
}

// ── Parser (testeable sin red) ──────────────────────────────────────────────

/**
 * Convierte un item del array `vulnerabilities` del feed CISA a un row tabular.
 * Retorna `null` si el cveID no matchea el formato.
 *
 * Shape esperado (snake_case en CISA — preservamos los nombres camelCase
 * estándar de su feed):
 *   { cveID, vendorProject, product, vulnerabilityName, dateAdded,
 *     shortDescription, requiredAction, dueDate,
 *     knownRansomwareCampaignUse, notes, cwes }
 */
export function parseKevItem(item) {
  if (!item || typeof item !== "object") return null;
  const id = String(item.cveID ?? "").trim();
  if (!CVE_RE.test(id)) return null;

  const ransom = String(item.knownRansomwareCampaignUse ?? "").toLowerCase();
  return {
    cve_id:               id,
    vendor_project:       item.vendorProject ?? null,
    product:              item.product ?? null,
    vulnerability_name:   item.vulnerabilityName ?? null,
    date_added:           item.dateAdded || null,
    short_description:    item.shortDescription ?? null,
    required_action:      item.requiredAction ?? null,
    due_date:             item.dueDate || null,
    known_ransomware_use: ransom === "known",
    notes:                item.notes ?? null,
    cwes:                 Array.isArray(item.cwes) ? item.cwes.filter(Boolean) : [],
  };
}

// ── Fetch + refresh ─────────────────────────────────────────────────────────

async function fetchCatalog() {
  const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`KEV fetch failed: HTTP ${res.status}`);
  const json = await res.json();
  const items = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
  return items.map(parseKevItem).filter(Boolean);
}

/**
 * Vacía la tabla y reinserta el catálogo completo en una transacción.
 * Llamar desde admin/cron — operación pesada (~1200 filas, ~500ms).
 */
export async function refreshKevCatalog() {
  const t0 = Date.now();
  const rows = await fetchCatalog();
  if (!rows.length) {
    logger.warn("kev: refresh devolvió 0 filas — no toco la tabla");
    return { ok: false, count: 0, reason: "empty-feed" };
  }
  await withPgClient(async (client) => {
    await client.query("BEGIN");
    try {
      await client.query(`TRUNCATE TABLE legacyhunt_soc.cve_kev`);
      // Insert en chunks para no saturar parámetros (PG: 65535 max).
      const CHUNK = 200;
      for (let i = 0; i < rows.length; i += CHUNK) {
        const slice = rows.slice(i, i + CHUNK);
        const params = [];
        const tuples = [];
        for (const r of slice) {
          const base = params.length;
          tuples.push(
            `($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},` +
              `$${base + 6},$${base + 7},$${base + 8},$${base + 9},$${base + 10},$${base + 11})`,
          );
          params.push(
            r.cve_id,
            r.vendor_project,
            r.product,
            r.vulnerability_name,
            r.date_added,
            r.short_description,
            r.required_action,
            r.due_date,
            r.known_ransomware_use,
            r.notes,
            r.cwes,
          );
        }
        await client.query(
          `INSERT INTO legacyhunt_soc.cve_kev
             (cve_id, vendor_project, product, vulnerability_name, date_added,
              short_description, required_action, due_date, known_ransomware_use,
              notes, cwes)
           VALUES ${tuples.join(",")}
           ON CONFLICT (cve_id) DO NOTHING`,
          params,
        );
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    }
  });
  const ms = Date.now() - t0;
  logger.info("kev: refresh ok", { count: rows.length, ms });
  return { ok: true, count: rows.length, ms };
}

/** ¿La tabla está fresca? (< REFRESH_AFTER_MS de antigüedad) */
async function isFresh() {
  const rows = await pgQuery(
    `SELECT MAX(refreshed_at) AS max_at FROM legacyhunt_soc.cve_kev`,
  );
  const max = rows[0]?.max_at ? new Date(rows[0].max_at).getTime() : 0;
  return max && Date.now() - max < REFRESH_AFTER_MS;
}

/**
 * Refresh sólo si está stale o vacío. Usado al boot — no falla si no hay
 * red; el catálogo se hidrata en el próximo refresh exitoso.
 */
export async function ensureKevFresh() {
  try {
    if (await isFresh()) return { ok: true, skipped: true };
    return await refreshKevCatalog();
  } catch (err) {
    logger.warn("kev: ensureKevFresh failed", { error: err?.message });
    return { ok: false, error: err?.message };
  }
}

// ── Public API para consumers ───────────────────────────────────────────────

/**
 * Devuelve un Map<cve_id, row> para los CVEs pedidos.
 * Sólo retorna las que SÍ están en el catálogo (los CVEs no-KEV no aparecen).
 *
 * @param {string[]} cveIds
 */
export async function getKevByIds(cveIds) {
  const out = new Map();
  if (!Array.isArray(cveIds) || !cveIds.length) return out;
  const valid = [...new Set(cveIds.filter((c) => typeof c === "string" && CVE_RE.test(c)))];
  if (!valid.length) return out;
  const rows = await pgQuery(
    `SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
            short_description, required_action, due_date, known_ransomware_use,
            notes, cwes
       FROM legacyhunt_soc.cve_kev
      WHERE cve_id = ANY($1::text[])`,
    [valid],
  );
  for (const r of rows) out.set(r.cve_id, r);
  return out;
}

/** Indicador para health-check / admin UI: cuántas KEV tenemos y desde cuándo. */
export async function getKevStats() {
  const rows = await pgQuery(
    `SELECT COUNT(*) AS total,
            COUNT(*) FILTER (WHERE known_ransomware_use) AS ransomware,
            MAX(refreshed_at) AS refreshed_at
       FROM legacyhunt_soc.cve_kev`,
  );
  const r = rows[0] ?? {};
  return {
    total:        Number(r.total ?? 0),
    ransomware:   Number(r.ransomware ?? 0),
    refreshedAt:  r.refreshed_at ?? null,
  };
}
