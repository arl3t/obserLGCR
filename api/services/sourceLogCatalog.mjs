/**
 * sourceLogCatalog.mjs — Frente A (audit Scoring 2026-05-21)
 *
 * Cache + getters sync para el catálogo `legacyhunt_soc.source_log_catalog`.
 * Reemplaza el mapping duplicado en routes/incidents.mjs (resolveNetworkZone,
 * labelOrigenSistema) por un lookup centralizado.
 *
 * NO migra `services/dedupKey.mjs#sourceCategoryOf` — ese mapping es
 * byte-sensitive (forma el hash dedup_key) y tiene contraparte Python en
 * data/airflow/plugins/dedup_key_canon.py que debe permanecer alineada.
 * Migrar dedup requiere actualizar ambos lados + backfill — fuera de scope.
 *
 * Patrón espejo de `services/socThresholds.mjs`:
 *   - `primeCatalogCache()`  → llamar al boot del API.
 *   - `getCachedCatalog()`   → snapshot sync; refresh pasivo si TTL vencido.
 *   - `lookupSourceLog(s)`   → fila completa o defaults para source_log unknown.
 *   - getters específicos: `getNetworkZone`, `getSensorLabel`, `getSensorFamily`,
 *     `getSourceCategory`, `getIcebergTable`.
 *   - `invalidateCatalogCache()` → forzar re-read.
 */

import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const TTL_MS = 5 * 60 * 1000;

/**
 * Defaults aplicados cuando un `source_log` no está en la tabla. Mantienen
 * compatibilidad bit-a-bit con el comportamiento anterior de
 * `resolveNetworkZone` (caía a 'internal') y `labelOrigenSistema` (caía al
 * propio source_log o 'Desconocido').
 */
const DEFAULT_FALLBACK = Object.freeze({
  sensor_family:   "unknown",
  source_category: "other",
  network_zone:    "internal",
  iceberg_table:   null,
  enabled:         true,
});

let _cache = new Map();   // Map<source_log, row>
let _cachedAt = 0;
let _refreshInflight = null;

function _rowToObj(r) {
  return {
    source_log:      r.source_log,
    sensor_name:     r.sensor_name,
    sensor_family:   r.sensor_family,
    source_category: r.source_category,
    network_zone:    r.network_zone,
    iceberg_table:   r.iceberg_table ?? null,
    enabled:         r.enabled !== false,
    notes:           r.notes ?? null,
  };
}

/** Lee la tabla y actualiza el cache. Devuelve el Map. */
export async function refreshCatalog() {
  try {
    // Cargamos TODAS las filas (no sólo enabled=true): el flag `enabled` por
    // fila es ahora autoritativo para gatear la alimentación de casos
    // (isSourceEnabled / getDisabledSourceLogs). Si filtrásemos enabled=true,
    // una fuente deshabilitada caería al DEFAULT_FALLBACK (enabled:true) y el
    // gate nunca dispararía. Los getters de zona/label/family siguen igual.
    const rows = await pgQuery(
      `SELECT source_log, sensor_name, sensor_family, source_category,
              network_zone, iceberg_table, enabled, notes
         FROM legacyhunt_soc.source_log_catalog`,
    );
    const next = new Map();
    for (const r of rows) next.set(r.source_log, _rowToObj(r));
    _cache = next;
    _cachedAt = Date.now();
    return _cache;
  } catch (err) {
    logger.warn({ err: err.message }, "[sourceLogCatalog] read failed, using stale cache");
    return _cache;
  }
}

/**
 * Snapshot sync — para hot paths (resolveNetworkZone, labelOrigenSistema).
 * Si el cache está stale, dispara refresh background sin bloquear.
 */
export function getCachedCatalog() {
  if (Date.now() - _cachedAt > TTL_MS) {
    if (!_refreshInflight) {
      _refreshInflight = refreshCatalog()
        .catch(() => { /* logged en refreshCatalog */ })
        .finally(() => { _refreshInflight = null; });
    }
  }
  return _cache;
}

/**
 * Lookup principal. Devuelve la fila del catálogo o un objeto con defaults.
 * Nunca devuelve `null` — siempre garantiza que los getters tengan algo
 * con que trabajar.
 *
 * @param {string} sourceLog
 * @returns {{ source_log, sensor_name, sensor_family, source_category,
 *             network_zone, iceberg_table, enabled, notes }}
 */
export function lookupSourceLog(sourceLog) {
  const key = String(sourceLog ?? "").trim();
  const cat = getCachedCatalog();
  const row = cat.get(key);
  if (row) return row;
  // Lookup case-insensitive secundario para tolerar 'WAZUH_ALERTS' etc.
  const lk = key.toLowerCase();
  for (const [k, v] of cat) {
    if (k.toLowerCase() === lk) return v;
  }
  // Fallback explícito — sensor_name = source_log si vino, sino 'Desconocido'.
  return {
    source_log:      key,
    sensor_name:     key || "Desconocido",
    ...DEFAULT_FALLBACK,
    notes:           "fallback (source_log no presente en catálogo)",
  };
}

// ── Getters específicos ──────────────────────────────────────────────────────

/** Reemplazo de `routes/incidents.mjs#resolveNetworkZone`. */
export function getNetworkZone(sourceLog) {
  return lookupSourceLog(sourceLog).network_zone;
}

/** Reemplazo de `routes/incidents.mjs#labelOrigenSistema`. */
export function getSensorLabel(sourceLog) {
  return lookupSourceLog(sourceLog).sensor_name;
}

/** Família agrupadora (wazuh, fortigate, opnsense, suricata, pmg, syslog, manual). */
export function getSensorFamily(sourceLog) {
  return lookupSourceLog(sourceLog).sensor_family;
}

/**
 * Categoría tipo SIEM/firewall/IDS/email/etc.
 *
 * NOTA: NO sustituir `dedupKey.mjs#sourceCategoryOf` por este getter — ese
 * helper alimenta el hash dedup_key y la contraparte Python debe estar
 * alineada. Este getter devuelve el valor canónico de la tabla; cualquier
 * divergencia con `sourceCategoryOf` se detecta en `sourceLogCatalog.test.mjs`.
 */
export function getSourceCategory(sourceLog) {
  return lookupSourceLog(sourceLog).source_category;
}

/** Tabla Iceberg cruda asociada (informacional). */
export function getIcebergTable(sourceLog) {
  return lookupSourceLog(sourceLog).iceberg_table;
}

// ── Toggle de fuentes (deshabilitar → deja de alimentar casos) ───────────────
// El toggle opera a nivel de `sensor_family` (lo que representan las tarjetas
// del dashboard), pero el storage es por `source_log` (columna `enabled`).
// Una familia se considera deshabilitada cuando TODOS sus source_log están
// enabled=false; deshabilitarla pone enabled=false en todas sus filas, lo que
// cubre los aliases (p.ej. opnsense ⇒ filterlog/opnsense/opnsense_filterlog).

/** Familias pseudo-fuente (manual) que NO son fuentes de detección reales. */
const NON_DETECTION_FAMILIES = new Set(["manual"]);

/**
 * ¿Esta fuente alimenta casos? Fail-open: un source_log desconocido (no en el
 * catálogo) devuelve true — nunca bloqueamos una fuente que no mapeamos.
 */
export function isSourceEnabled(sourceLog) {
  return lookupSourceLog(sourceLog).enabled !== false;
}

/**
 * Lista de source_log con enabled=false — para inyectar en el filtro de
 * candidatos (DAG) o gatear escritores. Snapshot sync desde el cache.
 */
export function getDisabledSourceLogs() {
  const out = [];
  for (const r of getCachedCatalog().values()) {
    if (r.enabled === false) out.push(r.source_log);
  }
  return out;
}

/**
 * Vista agrupada por familia para la UI de Ajustes. Excluye pseudo-fuentes
 * manuales. Una familia está `enabled` si AL MENOS un source_log suyo lo está.
 * @returns {Array<{ family, label, category, enabled, sourceLogs: string[] }>}
 */
export function getDetectionFamilies() {
  const byFamily = new Map();
  for (const r of getCachedCatalog().values()) {
    if (NON_DETECTION_FAMILIES.has(r.sensor_family)) continue;
    let f = byFamily.get(r.sensor_family);
    if (!f) {
      f = {
        family:     r.sensor_family,
        label:      r.sensor_name,
        category:   r.source_category,
        enabled:    false,
        sourceLogs: [],
      };
      byFamily.set(r.sensor_family, f);
    }
    f.sourceLogs.push(r.source_log);
    if (r.enabled !== false) f.enabled = true;
  }
  return [...byFamily.values()].sort((a, b) => a.family.localeCompare(b.family));
}

/**
 * Habilita/deshabilita TODAS las filas (source_log) de una familia de sensor.
 * Refresca el cache de inmediato para que el gate aplique sin esperar el TTL.
 * @returns {Promise<number>} filas afectadas
 */
export async function setFamilyEnabled(family, enabled, operator) {
  const fam = String(family ?? "").trim();
  if (!fam || NON_DETECTION_FAMILIES.has(fam)) {
    throw new Error(`familia inválida o no toggleable: '${fam}'`);
  }
  const res = await pgQuery(
    `UPDATE legacyhunt_soc.source_log_catalog
        SET enabled    = $1,
            notes      = CASE WHEN $2::text IS NULL THEN notes
                              ELSE concat_ws(' · ', notes,
                                   concat('toggle ', CASE WHEN $1 THEN 'ON' ELSE 'OFF' END,
                                          ' por ', $2::text)) END,
            updated_at = NOW()
      WHERE sensor_family = $3
      RETURNING source_log`,
    [Boolean(enabled), operator ?? null, fam],
  );
  await refreshCatalog();   // re-read inmediato (no esperar TTL de 5min)
  logger.info({
    msg: "source_family_toggled", family: fam, enabled: Boolean(enabled),
    operator: operator ?? null, affected: res.length,
  });
  return res.length;
}

/** Invalida cache — usar tras INSERT/UPDATE en `source_log_catalog`. */
export function invalidateCatalogCache() {
  _cachedAt = 0;
}

/**
 * Llamar una vez al boot del API (server.mjs/index.mjs) — evita que el
 * primer caller de `getCachedCatalog` vea el Map vacío.
 */
export async function primeCatalogCache() {
  await refreshCatalog();
  logger.info({
    msg: "source_log_catalog_primed",
    rows: _cache.size,
  });
}

/** Snapshot crudo del cache — solo para tests/diagnóstico. */
export function _debugSnapshot() {
  return { size: _cache.size, cachedAt: _cachedAt, entries: [..._cache.values()] };
}
