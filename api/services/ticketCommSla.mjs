/**
 * ticketCommSla.mjs — SLA de COMUNICACIÓN del sistema de tickets público.
 *
 * Espejo de slaConfig.mjs (mig 054) pero para el plano comunicacional: mide el
 * tiempo de RESPUESTA al cliente, no el de contención del ataque. Tres relojes
 * por prioridad VISIBLE del ticket (URGENT < HIGH < MEDIUM < LOW):
 *   · FRT — First Response Time
 *   · NRT — Next Response Time
 *   · RES — Resolución comunicada
 *
 * Tabla singleton ticket_comm_sla_config (id=1), cache TTL 30s, audit en
 * ticket_comm_sla_audit. Ver docs/PROPUESTA-TICKETING-PUBLICO.md §3.5.
 *
 * API:
 *   - getCommSla()            → async, lee de PG y refresca cache.
 *   - getCachedCommSla()      → sync, snapshot cacheado (fallback a defaults).
 *   - getCommSlaSec(metric, priority) → sync, segundos para un reloj+prioridad.
 *   - setCommSla({ values, operatorCi }) → TX UPDATE + audit.
 *   - getCommSlaAudit(limit)  → últimas N filas de auditoría.
 */

import { pgQuery, withPgClient } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const TTL_MS = 30_000;

// Defaults — coinciden con el seed de mig 102 (§3.5). Duplicados como fallback
// cuando PG no está listo al boot.
const DEFAULTS = Object.freeze({
  frt_urgent_sec: 1800,  frt_high_sec: 7200,  frt_medium_sec: 28800,  frt_low_sec: 86400,
  nrt_urgent_sec: 3600,  nrt_high_sec: 14400, nrt_medium_sec: 86400,  nrt_low_sec: 172800,
  res_urgent_sec: 14400, res_high_sec: 86400, res_medium_sec: 259200, res_low_sec: 432000,
  business_hours_aware: false,
  enabled: true,
});

const COLS = Object.keys(DEFAULTS);

// (métrica, prioridad) → columna. Prioridad case-insensitive (se upper-casea).
const METRIC_PREFIX = { FRT: "frt", NRT: "nrt", RES: "res" };
const PRIORITY_SUFFIX = { URGENT: "urgent", HIGH: "high", MEDIUM: "medium", LOW: "low" };

let _cached = { ...DEFAULTS, updated_by: null, updated_at: null };
let _cachedAt = 0;

function _fromRow(row) {
  const out = {};
  for (const c of COLS) {
    out[c] = typeof DEFAULTS[c] === "boolean" ? Boolean(row[c]) : Number(row[c]);
  }
  out.updated_by = row.updated_by ?? null;
  out.updated_at = row.updated_at ?? null;
  return out;
}

export async function getCommSla() {
  try {
    const rows = await pgQuery(
      `SELECT ${COLS.join(", ")}, updated_by, updated_at
         FROM ticket_comm_sla_config WHERE id = 1 LIMIT 1`,
    );
    if (rows.length > 0) {
      _cached = _fromRow(rows[0]);
      _cachedAt = Date.now();
    }
    return { ..._cached };
  } catch (err) {
    logger.warn({ err: err.message }, "[ticketCommSla] read failed, using cache");
    return { ..._cached };
  }
}

/** Snapshot sincrónico para hot paths (no espera la query). */
export function getCachedCommSla() {
  return { ..._cached };
}

/** Segundos para un reloj (FRT|NRT|RES) y prioridad (URGENT|HIGH|MEDIUM|LOW). */
export function getCommSlaSec(metric, priority) {
  const m = METRIC_PREFIX[String(metric).toUpperCase()];
  const p = PRIORITY_SUFFIX[String(priority).toUpperCase()];
  if (!m || !p) return null;
  const col = `${m}_${p}_sec`;
  return Number(_cached[col] ?? DEFAULTS[col]);
}

/** Hidrata el cache al boot. */
export async function primeCommSlaCache() {
  await getCommSla();
}

/**
 * Actualiza la config con TX + audit (before/after snapshot completo).
 * `values` es un objeto parcial con cualquiera de las columnas de DEFAULTS.
 * Los CHECK de la tabla (orden URGENT<HIGH<MEDIUM<LOW) hacen de red de seguridad.
 */
export async function setCommSla({ values = {}, operatorCi }) {
  const editable = COLS.filter((c) => c in values);
  if (editable.length === 0) return getCommSla();

  return withPgClient(async (client) => {
    await client.query("BEGIN");
    try {
      const beforeRows = await client.query(
        `SELECT ${COLS.join(", ")}, updated_by, updated_at
           FROM ticket_comm_sla_config WHERE id = 1 FOR UPDATE`,
      );
      const before = beforeRows.rows[0] ?? {};

      const setSql = editable.map((c, i) => `${c} = $${i + 1}`).join(", ");
      const params = editable.map((c) => values[c]);
      params.push(operatorCi ?? "system");
      const afterRows = await client.query(
        `UPDATE ticket_comm_sla_config
            SET ${setSql}, updated_by = $${params.length}, updated_at = now()
          WHERE id = 1
        RETURNING ${COLS.join(", ")}, updated_by, updated_at`,
        params,
      );
      const after = afterRows.rows[0];

      await client.query(
        `INSERT INTO ticket_comm_sla_audit (changed_by, before, after)
         VALUES ($1, $2, $3)`,
        [operatorCi ?? "system", JSON.stringify(before), JSON.stringify(after)],
      );

      await client.query("COMMIT");
      _cached = _fromRow(after);
      _cachedAt = Date.now();
      return { ..._cached };
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
  });
}

export async function getCommSlaAudit(limit = 50) {
  return pgQuery(
    `SELECT id, changed_at, changed_by, before, after
       FROM ticket_comm_sla_audit
      ORDER BY changed_at DESC
      LIMIT $1`,
    [Math.min(Number(limit) || 50, 500)],
  );
}
