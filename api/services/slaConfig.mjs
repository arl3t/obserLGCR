/**
 * slaConfig.mjs — M5 (audit Gestión de Incidentes 2026-05-13, P4)
 *
 * Cache + getters para los SLAs por severidad mutables en runtime. Reemplaza
 * las 4 fuentes hardcoded que vivían en:
 *   · services/casePlaybookService.mjs SLA_MIN
 *   · routes/incidents.mjs SLA_SEC
 *   · services/schedulerService.mjs CASE WHEN (inline SQL)
 *   · server.mjs SLA_SEC (duplicado parcial)
 *
 * API:
 *   - `getSla()`        → async, lee de PG y refresca cache. Para endpoints HTTP.
 *   - `getCachedSla()`  → sync, retorna snapshot cacheado (fallback a defaults).
 *                         Para hot paths (response builders, scheduler loops).
 *   - `getSlaSec(sev)`  → sync helper, segundos para una severidad concreta.
 *   - `getSlaMin(sev)`  → sync helper, minutos para una severidad concreta.
 *   - `setSla({ values, operatorCi, expectedUpdatedAt? })` → TX UPDATE + audit.
 *   - `primeSlaCache()` → al boot, hidrata el cache.
 *   - `invalidateSlaCache()` → fuerza re-read en el próximo call.
 *   - `getSlaAudit(limit)` → últimas N filas de sla_config_audit.
 *
 * El cache se refresca pasivamente cuando `getSla()` corre o cuando un caller
 * sync detecta TTL vencido. No hay polling. Coalescing del refresh para evitar
 * thundering herd (mismo patrón que socThresholds).
 */

import { pgQuery, withPgClient } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const TTL_MS = 30_000;

// Defaults históricos — coinciden con casePlaybookService.SLA_MIN expresado
// en segundos. La tabla los tiene seedeados pero los duplicamos acá como
// fallback cuando PG no está listo al boot.
const DEFAULTS = Object.freeze({
  sla_critical_sec:   900,    // 15 min
  sla_high_sec:       3600,   // 60 min
  sla_medium_sec:     14400,  // 240 min
  sla_low_sec:        86400,  // 1440 min
  sla_negligible_sec: 259200, // 4320 min
});

// Severidad → columna sec. Caso-insensitive en `getSlaSec/Min` (lookup
// normaliza upper-case primero).
const SEV_TO_COL = {
  CRITICAL:   "sla_critical_sec",
  HIGH:       "sla_high_sec",
  MEDIUM:     "sla_medium_sec",
  LOW:        "sla_low_sec",
  NEGLIGIBLE: "sla_negligible_sec",
};

let _cached = { ...DEFAULTS, updated_by: null, updated_at: null };
let _cachedAt = 0;
let _refreshInflight = null;

function _fromRow(row) {
  return {
    sla_critical_sec:   Number(row.sla_critical_sec),
    sla_high_sec:       Number(row.sla_high_sec),
    sla_medium_sec:     Number(row.sla_medium_sec),
    sla_low_sec:        Number(row.sla_low_sec),
    sla_negligible_sec: Number(row.sla_negligible_sec),
    updated_by:         row.updated_by ?? null,
    updated_at:         row.updated_at ?? null,
  };
}

export async function getSla() {
  try {
    const rows = await pgQuery(
      `SELECT sla_critical_sec, sla_high_sec, sla_medium_sec,
              sla_low_sec, sla_negligible_sec, updated_by, updated_at
         FROM legacyhunt_soc.sla_config
         WHERE id = 1
         LIMIT 1`,
    );
    if (rows.length > 0) {
      _cached = _fromRow(rows[0]);
      _cachedAt = Date.now();
    }
    return { ..._cached };
  } catch (err) {
    logger.warn({ err: err.message }, "[slaConfig] read failed, using cache");
    return { ..._cached };
  }
}

/**
 * Snapshot sincrónico. Para hot paths donde no se puede esperar la query.
 * Si el cache está stale (>TTL) dispara un refresh en background sin bloquear.
 */
export function getCachedSla() {
  if (Date.now() - _cachedAt > TTL_MS) {
    if (!_refreshInflight) {
      _refreshInflight = getSla()
        .catch(() => { /* warned in getSla */ })
        .finally(() => { _refreshInflight = null; });
    }
  }
  return { ..._cached };
}

/** Segundos para una severidad concreta. Fallback al MEDIUM si la sev no existe. */
export function getSlaSec(severity) {
  const sev = String(severity ?? "MEDIUM").toUpperCase();
  const col = SEV_TO_COL[sev] ?? SEV_TO_COL.MEDIUM;
  return _cached[col] ?? DEFAULTS[col];
}

/** Minutos para una severidad concreta (= sec / 60, redondeado). */
export function getSlaMin(severity) {
  return Math.round(getSlaSec(severity) / 60);
}

/** Fuerza un re-read en el próximo call. */
export function invalidateSlaCache() {
  _cachedAt = 0;
}

/**
 * Aplica un patch a sla_config.
 *
 * Validaciones:
 *   - Cada campo entero en [60, 31_536_000] (1 año máximo, 1 min mínimo).
 *   - Orden ascendente estricto critical < high < medium < low < negligible
 *     (el CHECK de la tabla también lo enforce; chequear acá permite 400 con
 *     mensaje claro antes de llegar a PG).
 *   - OCC opcional: si el caller envía `expectedUpdatedAt` (ISO del GET previo),
 *     se rechaza con CONFLICT si otro manager cambió el row mientras tanto.
 */
export async function setSla({ values, operatorCi, expectedUpdatedAt }) {
  if (!values || typeof values !== "object") {
    const e = new Error("Payload inválido");
    e.code = "INVALID_PAYLOAD";
    throw e;
  }
  const inRange = (v) => Number.isInteger(v) && v >= 60 && v <= 31_536_000;
  const next = {
    sla_critical_sec:   Number(values.sla_critical_sec),
    sla_high_sec:       Number(values.sla_high_sec),
    sla_medium_sec:     Number(values.sla_medium_sec),
    sla_low_sec:        Number(values.sla_low_sec),
    sla_negligible_sec: Number(values.sla_negligible_sec),
  };
  for (const [k, v] of Object.entries(next)) {
    if (!inRange(v)) {
      const e = new Error(`Valor inválido para ${k}: entero entre 60 y 31536000 segundos`);
      e.code = "OUT_OF_RANGE";
      throw e;
    }
  }
  if (!(next.sla_critical_sec < next.sla_high_sec   &&
        next.sla_high_sec     < next.sla_medium_sec &&
        next.sla_medium_sec   < next.sla_low_sec    &&
        next.sla_low_sec      < next.sla_negligible_sec)) {
    const e = new Error("Orden inválido: CRITICAL < HIGH < MEDIUM < LOW < NEGLIGIBLE");
    e.code = "BAD_ORDER";
    throw e;
  }

  const result = await withPgClient(async (client) => {
    await client.query("BEGIN");
    try {
      const beforeRes = await client.query(
        `SELECT sla_critical_sec, sla_high_sec, sla_medium_sec,
                sla_low_sec, sla_negligible_sec, updated_by, updated_at
           FROM legacyhunt_soc.sla_config
           WHERE id = 1
           FOR UPDATE`,
      );
      const before = beforeRes.rows[0] ?? { ...DEFAULTS };

      if (expectedUpdatedAt && before.updated_at) {
        const expectedMs = Date.parse(expectedUpdatedAt);
        const currentMs  = new Date(before.updated_at).getTime();
        if (Number.isFinite(expectedMs) && Math.abs(currentMs - expectedMs) > 1000) {
          const e = new Error("SLA modificado por otro usuario — refrescá y reintentá");
          e.code = "CONFLICT";
          e.currentUpdatedAt = before.updated_at;
          e.currentUpdatedBy = before.updated_by;
          throw e;
        }
      }

      const updatedBy = operatorCi || "system";
      const afterRes = await client.query(
        `UPDATE legacyhunt_soc.sla_config
            SET sla_critical_sec   = $1,
                sla_high_sec       = $2,
                sla_medium_sec     = $3,
                sla_low_sec        = $4,
                sla_negligible_sec = $5,
                updated_by         = $6,
                updated_at         = NOW()
          WHERE id = 1
          RETURNING sla_critical_sec, sla_high_sec, sla_medium_sec,
                    sla_low_sec, sla_negligible_sec, updated_by, updated_at`,
        [next.sla_critical_sec, next.sla_high_sec, next.sla_medium_sec,
         next.sla_low_sec,      next.sla_negligible_sec, updatedBy],
      );
      const after = afterRes.rows[0];

      await client.query(
        `INSERT INTO legacyhunt_soc.sla_config_audit (changed_by, before, after)
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

  _cached = _fromRow(result.after);
  _cachedAt = Date.now();

  logger.info({
    msg: "sla_config_updated",
    by: operatorCi || "system",
    before: result.before,
    after:  result.after,
  });

  return { ok: true, before: result.before, after: _fromRow(result.after) };
}

/**
 * Pre-carga al boot del API. No-op si la query falla (defaults vigentes
 * y el siguiente getCachedSla dispara un refresh async).
 */
export async function primeSlaCache() {
  await getSla();
  logger.info({
    msg: "sla_config_primed",
    ..._cached,
  });
}

/** Últimas N entradas del audit. */
export async function getSlaAudit(limit = 20) {
  const lim = Math.max(1, Math.min(200, Number(limit) || 20));
  const rows = await pgQuery(
    `SELECT id, changed_at, changed_by, before, after
       FROM legacyhunt_soc.sla_config_audit
       ORDER BY changed_at DESC
       LIMIT $1`,
    [lim],
  );
  return rows;
}
