/**
 * socThresholds.mjs — R15 (audit 2026-05-13, P3)
 *
 * Cache + getters para los umbrales de scoring mutables en runtime.
 *
 * R11 (P2) externalizó los umbrales a env vars → consumibles vía `config.soc*`,
 * pero ajustar uno requería editar .env + restart. R15 los mueve a
 * `legacyhunt_soc.soc_thresholds` (single row) que un manager edita desde el
 * UI; este módulo expone:
 *
 *   - `getThresholds()`        → async, retorna los valores frescos de PG y
 *                                 actualiza el cache. Usar en endpoints HTTP.
 *   - `getCachedThresholds()`  → sync, retorna el snapshot cacheado (con
 *                                 fallback a defaults). Usar en hot paths
 *                                 sync como workflowEngine.shouldAutoEscalate.
 *   - `setThresholds({ values, operatorCi })` → valida, UPDATE PG dentro de
 *                                 TX con INSERT en _audit, invalida el cache.
 *   - `primeThresholdsCache()` → al boot del API, carga el cache inicial.
 *
 * El cache se refresca pasivamente cuando `getThresholds()` corre y el TTL
 * venció. No hay polling — el worker activo (workflowEngine) usa el snapshot
 * cacheado, así un cambio del manager se propaga en máximo TTL_MS.
 */

import { pgQuery, withPgClient } from "../db/postgres.mjs";
import { config } from "../config.mjs";
import { logger } from "../logger.mjs";

const TTL_MS = 30_000;

// Defaults — Zod en config.mjs es la única fuente de verdad (P4 M6,
// 2026-05-13). Antes esta lista duplicaba `?? 70, ?? 80, ?? 60, ?? 35`
// que se desincronizarían si alguien editaba sólo uno.
const DEFAULTS = Object.freeze({
  auto_escalate_score:   config.socAutoEscalateScore,
  severity_critical_min: config.socSeverityCriticalMin,
  severity_high_min:     config.socSeverityHighMin,
  severity_medium_min:   config.socSeverityMediumMin,
});

let _cached = { ...DEFAULTS, updated_by: null, updated_at: null };
let _cachedAt = 0;
// Coalescing del refresh en background (P4 A5, 2026-05-13). Sin esto, N
// callers concurrentes después del TTL disparan N queries idénticas
// (thundering herd). Guardamos la Promise en vuelo para que callers
// adicionales reusen el mismo refresh.
let _refreshInflight = null;

function _fromRow(row) {
  return {
    auto_escalate_score:   Number(row.auto_escalate_score),
    severity_critical_min: Number(row.severity_critical_min),
    severity_high_min:     Number(row.severity_high_min),
    severity_medium_min:   Number(row.severity_medium_min),
    updated_by:            row.updated_by ?? null,
    updated_at:            row.updated_at ?? null,
  };
}

/**
 * Lee el row activo de PG y actualiza el cache. Si la query falla, devuelve
 * el último valor cacheado (sin tocar `_cachedAt`, para que el próximo call
 * reintente).
 */
export async function getThresholds() {
  try {
    const rows = await pgQuery(
      `SELECT auto_escalate_score, severity_critical_min, severity_high_min,
              severity_medium_min, updated_by, updated_at
         FROM legacyhunt_soc.soc_thresholds
         WHERE id = 1
         LIMIT 1`,
    );
    if (rows.length > 0) {
      _cached = _fromRow(rows[0]);
      _cachedAt = Date.now();
    }
    return { ..._cached };
  } catch (err) {
    logger.warn({ err: err.message }, "[socThresholds] read failed, using cache");
    return { ..._cached };
  }
}

/**
 * Snapshot sincrónico — para hot paths que no pueden esperar la query (la
 * mayoría de los callers de shouldAutoEscalate son sync). El cache se
 * refresca a través de los endpoints HTTP que sí son async + getThresholds().
 *
 * Si el cache está stale (> TTL), se dispara un refresh en background sin
 * bloquear al caller. El primer caller después de un TTL ve el valor viejo;
 * los siguientes ven el nuevo en cuanto el refresh termina (típicamente
 * <50ms para una lectura indexada single-row).
 */
export function getCachedThresholds() {
  if (Date.now() - _cachedAt > TTL_MS) {
    // dispara refresh pero no esperes — el caller no debe bloquearse.
    // Si ya hay un refresh in-flight, no encolamos otro (coalescing).
    if (!_refreshInflight) {
      _refreshInflight = getThresholds()
        .catch(() => { /* warned in getThresholds */ })
        .finally(() => { _refreshInflight = null; });
    }
  }
  return { ..._cached };
}

/** Limpia el cache (forza un re-read en el próximo call). */
export function invalidateThresholdsCache() {
  _cachedAt = 0;
}

/**
 * severityFromScore — AUTORIDAD ÚNICA en Node del mapeo score→severidad (R3
 * audit 2026-06-05). Antes el cálculo vivía inline en routes/incidents.mjs con
 * sólo 4 niveles (score<10 → "LOW"), divergiendo del DAG `_severity_from_score`
 * (data/airflow/dags/incident_cases_sync_daily.py), que es el escritor dominante
 * de incident_cases_pg y usa 5 niveles con piso NEGLIGIBLE<10. Dos paths daban
 * severidades distintas para el mismo score. Esta función espeja exactamente al
 * DAG; cualquier cambio en uno debe replicarse en el otro (paridad cross-lenguaje,
 * igual que dedup_key — ver tests/severityFromScore.test.mjs).
 *
 * @param {number} score — 0..100 (se clampa).
 * @param {object} [thresholds] — shape de getCachedThresholds()
 *   ({ severity_critical_min, severity_high_min, severity_medium_min }).
 *   Por defecto usa el snapshot cacheado.
 * @returns {"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"NEGLIGIBLE"}
 */
export function severityFromScore(score, thresholds = getCachedThresholds()) {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  if (s >= thresholds.severity_critical_min) return "CRITICAL";
  if (s >= thresholds.severity_high_min)     return "HIGH";
  if (s >= thresholds.severity_medium_min)   return "MEDIUM";
  if (s >= 10)                               return "LOW";
  return "NEGLIGIBLE";
}

/**
 * Aplica un patch a los thresholds. Validaciones:
 *   - Todos los campos dentro de [1, 200].
 *   - critical > high > medium (el CHECK de la tabla también lo enforce,
 *     pero el chequeo aquí permite devolver 400 con mensaje claro antes de
 *     llegar al DB).
 *   - OCC opcional (P4 A5, 2026-05-13): si el caller pasa
 *     `expectedUpdatedAt` (ISO string del GET previo), validamos dentro de
 *     la TX que el `updated_at` actual coincida. Si no, error CONFLICT
 *     (otro manager modificó los thresholds entre el read del caller y este
 *     PUT). El SELECT FOR UPDATE ya serializa escrituras, pero sin OCC el
 *     segundo PUT sobreescribe silenciosamente al primero (lost update).
 *
 * Retorna `{ ok: true, before, after }` o lanza Error con `.code` y `.message`.
 */
export async function setThresholds({ values, operatorCi, expectedUpdatedAt }) {
  if (!values || typeof values !== "object") {
    const e = new Error("Payload inválido");
    e.code = "INVALID_PAYLOAD";
    throw e;
  }
  const inRange = (v) => Number.isInteger(v) && v >= 1 && v <= 200;
  const next = {
    auto_escalate_score:   Number(values.auto_escalate_score),
    severity_critical_min: Number(values.severity_critical_min),
    severity_high_min:     Number(values.severity_high_min),
    severity_medium_min:   Number(values.severity_medium_min),
  };
  for (const [k, v] of Object.entries(next)) {
    if (!inRange(v)) {
      const e = new Error(`Valor inválido para ${k}: debe ser entero entre 1 y 200`);
      e.code = "OUT_OF_RANGE";
      throw e;
    }
  }
  if (!(next.severity_critical_min > next.severity_high_min &&
        next.severity_high_min     > next.severity_medium_min)) {
    const e = new Error("Orden inválido: CRITICAL > HIGH > MEDIUM");
    e.code = "BAD_ORDER";
    throw e;
  }

  // TX: lee before, escribe after, audita en una sola transacción.
  const result = await withPgClient(async (client) => {
    await client.query("BEGIN");
    try {
      const beforeRes = await client.query(
        `SELECT auto_escalate_score, severity_critical_min, severity_high_min,
                severity_medium_min, updated_by, updated_at
           FROM legacyhunt_soc.soc_thresholds
           WHERE id = 1
           FOR UPDATE`,
      );
      const before = beforeRes.rows[0] ?? { ...DEFAULTS };

      // OCC: si el caller envió expectedUpdatedAt, validar contra el row actual.
      // Toleramos ±1s para evitar falsos positivos por precisión de timestamp.
      // El catch del withPgClient hace ROLLBACK.
      if (expectedUpdatedAt && before.updated_at) {
        const expectedMs = Date.parse(expectedUpdatedAt);
        const currentMs  = new Date(before.updated_at).getTime();
        if (Number.isFinite(expectedMs) && Math.abs(currentMs - expectedMs) > 1000) {
          const e = new Error("Thresholds modificados por otro usuario — refrescá y reintentá");
          e.code = "CONFLICT";
          e.currentUpdatedAt = before.updated_at;
          e.currentUpdatedBy = before.updated_by;
          throw e;
        }
      }

      const updatedBy = operatorCi || "system";
      const afterRes = await client.query(
        `UPDATE legacyhunt_soc.soc_thresholds
            SET auto_escalate_score   = $1,
                severity_critical_min = $2,
                severity_high_min     = $3,
                severity_medium_min   = $4,
                updated_by            = $5,
                updated_at            = NOW()
          WHERE id = 1
          RETURNING auto_escalate_score, severity_critical_min, severity_high_min,
                    severity_medium_min, updated_by, updated_at`,
        [next.auto_escalate_score, next.severity_critical_min,
         next.severity_high_min,   next.severity_medium_min, updatedBy],
      );
      const after = afterRes.rows[0];

      await client.query(
        `INSERT INTO legacyhunt_soc.soc_thresholds_audit (changed_by, before, after)
         VALUES ($1, $2::jsonb, $3::jsonb)`,
        [updatedBy, JSON.stringify(before), JSON.stringify(after)],
      );

      await client.query("COMMIT");
      return { before, after };
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
  });

  // Actualiza el cache inmediatamente — no esperar al próximo TTL.
  _cached = _fromRow(result.after);
  _cachedAt = Date.now();

  logger.info({
    msg: "soc_thresholds_updated",
    by: operatorCi || "system",
    before: result.before,
    after:  result.after,
  });

  return { ok: true, before: result.before, after: _fromRow(result.after) };
}

/**
 * Llamar una vez al boot del API (server.mjs / index.mjs) para evitar que el
 * primer hit a `getCachedThresholds()` devuelva DEFAULTS si la query fresca
 * tarda. No-op si la query falla — los DEFAULTS siguen vigentes.
 */
export async function primeThresholdsCache() {
  await getThresholds();
  logger.info({
    msg: "soc_thresholds_primed",
    ..._cached,
  });
}

/**
 * Listado de las últimas N entradas del audit. Para la UI que muestra
 * "última modificación" + drill-down a historial completo.
 */
export async function getThresholdsAudit(limit = 20) {
  const lim = Math.max(1, Math.min(200, Number(limit) || 20));
  const rows = await pgQuery(
    `SELECT id, changed_at, changed_by, before, after
       FROM legacyhunt_soc.soc_thresholds_audit
       ORDER BY changed_at DESC
       LIMIT $1`,
    [lim],
  );
  return rows;
}
