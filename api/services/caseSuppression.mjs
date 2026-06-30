/**
 * services/caseSuppression.mjs — Alta de supresiones por dedup_key (P0 dedup-churn).
 *
 * Contexto (auditoría 2026-06-04 "dedup churn diagnosis"):
 *   El índice único `idx_cases_dedup_key_open_unique` y los lookups de dedup
 *   (DAG `incident_cases_sync_daily.py:665`, `routes/incidents.mjs:1492`) solo
 *   bloquean recreaciones mientras el caso está ABIERTO. Los LOW se auto-cierran
 *   en minutos → el mismo dedup_key vuelve a materializarse → ~90k LOW/semana de
 *   churn. La defensa correcta es `case_suppressions`: el DAG y la API la
 *   consultan antes de crear y saltan si `suppressed_until > NOW()`.
 *
 *   Antes de este módulo, `case_suppressions` solo se alimentaba en el cierre
 *   MANUAL (`routes/incidents.mjs`). Los cierres AUTOMÁTICOS
 *   (`autoCloseLowNegligible`, `autoClassifyController.persistCase`) cerraban sin
 *   suprimir → la próxima ocurrencia no quedaba bloqueada. Este helper centraliza
 *   el upsert para que ambos paths automáticos lo usen (P0).
 *
 * Semántica del upsert (espejo de `routes/incidents.mjs` PATCH /:id/status):
 *   - `suppressed_until` se deriva de `legacyhunt_soc.suppression_days(reason, severity)`.
 *     AUTO_CLOSED ⇒ 30 días fijos; FALSO_POSITIVO ⇒ 14/30/60 según severidad.
 *   - ON CONFLICT (dedup_key): si el motivo coincide, extiende la ventana
 *     (GREATEST); si cambia, la reemplaza.
 *   - `original_case_id` es UUID; los casos auto-clasificados usan ids hex de 32
 *     chars (incidentKey) que NO son UUID → se pasa NULL en ese caso.
 *   - Best-effort en el audit trail (`incident_case_audit`); su fallo no
 *     revierte la supresión.
 */

import { logger } from "../logger.mjs";
import { isRfc1918 } from "./netClass.mjs";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Devuelve el id si es un UUID válido (para columnas `::uuid`), o null. */
function uuidOrNull(id) {
  const s = String(id ?? "").trim();
  return UUID_RE.test(s) ? s : null;
}

/**
 * Inserta/actualiza supresiones para un lote de cierres automáticos.
 *
 * @param {Function} pgQuery  — db/postgres.mjs pgQuery
 * @param {Array<{dedupKey:string, reason:string, severity?:string, caseId?:string, iocValue?:string}>} rows
 * @param {object}  [opts]
 * @param {string}  [opts.by="auto-sistema"] — quién origina la supresión
 * @returns {Promise<{suppressed:number, skipped:number}>}
 */
export async function upsertSuppressionsBatch(pgQuery, rows, { by = "auto-sistema" } = {}) {
  // P3 audit 2026-06-06: NO suprimir AUTO_CLOSED de IPs internas RFC1918. Un host
  // interno que reaparece es señal de movimiento lateral este-oeste, no ruido — la
  // supresión lo taparía durante la ventana y nadie lo revisaría. La 1ª ocurrencia
  // se auto-cierra igual (acota volumen), pero al no suprimirse, la recurrencia
  // vuelve a entrar y se reabre (ver incident_cases_sync_daily.py + mig 079). El FP
  // explícito sí suprime (determinación deliberada de benignidad).
  const eligible = (rows ?? []).filter(
    (r) => !(r && isRfc1918(r.iocValue) && (r.reason ?? "AUTO_CLOSED") === "AUTO_CLOSED"),
  );
  const valid = eligible.filter((r) => r && String(r.dedupKey ?? "").trim());
  const skipped = (rows?.length ?? 0) - valid.length;
  if (!valid.length) return { suppressed: 0, skipped };

  const dedupKeys = valid.map((r) => String(r.dedupKey).trim());
  const reasons   = valid.map((r) => r.reason ?? "AUTO_CLOSED");
  const severities = valid.map((r) => (r.severity ? String(r.severity).toUpperCase() : null));
  const suppressedBy = valid.map(() => by);
  const caseIds   = valid.map((r) => uuidOrNull(r.caseId));
  const iocs      = valid.map((r) => (r.iocValue != null ? String(r.iocValue) : null));

  try {
    await pgQuery(
      `INSERT INTO legacyhunt_soc.case_suppressions
         (dedup_key, reason, severity, suppressed_until, suppressed_by, original_case_id, original_ioc)
       SELECT
         t.dedup_key, t.reason, t.severity,
         NOW() + (legacyhunt_soc.suppression_days(t.reason, t.severity) || ' days')::interval,
         t.suppressed_by, t.original_case_id, t.original_ioc
       FROM unnest($1::varchar[], $2::varchar[], $3::varchar[], $4::varchar[], $5::uuid[], $6::varchar[])
         AS t(dedup_key, reason, severity, suppressed_by, original_case_id, original_ioc)
       ON CONFLICT (dedup_key) DO UPDATE SET
         reason           = EXCLUDED.reason,
         severity         = COALESCE(EXCLUDED.severity, case_suppressions.severity),
         suppressed_until = CASE
           WHEN case_suppressions.reason = EXCLUDED.reason
             THEN GREATEST(case_suppressions.suppressed_until, EXCLUDED.suppressed_until)
           ELSE EXCLUDED.suppressed_until
         END,
         suppressed_by    = EXCLUDED.suppressed_by,
         original_case_id = COALESCE(EXCLUDED.original_case_id, case_suppressions.original_case_id),
         original_ioc     = COALESCE(EXCLUDED.original_ioc, case_suppressions.original_ioc),
         updated_at       = NOW()`,
      [dedupKeys, reasons, severities, suppressedBy, caseIds, iocs],
    );
  } catch (err) {
    logger.error("case_suppression.batch_upsert_failed", { count: valid.length, err: err.message });
    return { suppressed: 0, skipped: skipped + valid.length };
  }

  // Audit trail (best-effort). case_id solo si es UUID; dedup_key siempre.
  try {
    await pgQuery(
      `INSERT INTO legacyhunt_soc.incident_case_audit (case_id, dedup_key, action, detail)
       SELECT t.case_id, t.dedup_key, 'SUPPRESSION_SET', t.detail
       FROM unnest($1::uuid[], $2::varchar[], $3::jsonb[])
         AS t(case_id, dedup_key, detail)`,
      [
        caseIds,
        dedupKeys,
        valid.map((r, i) => JSON.stringify({ reason: reasons[i], severity: severities[i], by, auto: true })),
      ],
    );
  } catch (auditErr) {
    logger.warn("case_suppression.batch_audit_failed", { err: auditErr.message });
  }

  return { suppressed: valid.length, skipped };
}

/**
 * Upsert de una sola supresión. Wrapper conveniente sobre el batch.
 *
 * @param {Function} pgQuery
 * @param {{dedupKey:string, reason:string, severity?:string, caseId?:string, iocValue?:string}} row
 * @param {object} [opts]
 * @returns {Promise<{suppressed:number, skipped:number}>}
 */
export async function upsertSuppression(pgQuery, row, opts = {}) {
  return upsertSuppressionsBatch(pgQuery, [row], opts);
}
