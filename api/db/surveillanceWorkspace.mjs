/**
 * surveillanceWorkspace — queries para las 3 tablas Postgres de Ola B.
 *
 *   - surveillance_analyses              (#1 histórico)
 *   - surveillance_finding_annotations   (#3 anotaciones)
 *   - surveillance_audit_events          (#9 audit log)
 *
 * Funciones puras sobre `pgQuery` — sin lógica de negocio (validación,
 * autenticación, rate limiting). Eso se hace en server.mjs.
 */

import { pgQuery } from "./postgres.mjs";

// ─────────────────────────────────────────────────────────────────────────────
// 1. Histórico de análisis (#1)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Inserta un snapshot del análisis. Devuelve la fila creada con id+queriedAt.
 * Llamado por el frontend tras cargar un dominio (o por el cron de watchlist).
 */
export async function insertAnalysis(input) {
  const {
    domain,
    operatorCi = null,
    riskScore,
    riskBand,
    findingsSummary = {},
    findingsCritical = 0,
    findingsHigh = 0,
    findingsTotal = 0,
    dataSnapshot = {},
    engineVersion = null,
  } = input;

  const sql = `
    INSERT INTO surveillance_analyses (
      domain, operator_ci, risk_score, risk_band,
      findings_summary, findings_critical, findings_high, findings_total,
      data_snapshot, engine_version
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    RETURNING id, domain, queried_at, risk_score, risk_band,
              findings_critical, findings_high, findings_total, engine_version
  `;
  const params = [
    domain.toLowerCase().slice(0, 253),
    operatorCi,
    Math.max(0, Math.min(100, Math.round(riskScore))),
    riskBand,
    JSON.stringify(findingsSummary),
    findingsCritical,
    findingsHigh,
    findingsTotal,
    JSON.stringify(dataSnapshot),
    engineVersion ? String(engineVersion).slice(0, 16) : null,
  ];
  const rows = await pgQuery(sql, params);
  return rows[0];
}

/**
 * Lista los últimos N análisis del dominio, descendente por queried_at.
 * No incluye `data_snapshot` para mantener payloads chicos — consultarlo
 * con `getAnalysisById`.
 */
export async function listAnalyses(domain, limit = 20) {
  const sql = `
    SELECT id, domain, queried_at, operator_ci, risk_score, risk_band,
           findings_summary, findings_critical, findings_high, findings_total
    FROM surveillance_analyses
    WHERE domain = $1
    ORDER BY queried_at DESC
    LIMIT $2
  `;
  return pgQuery(sql, [domain.toLowerCase(), Math.min(100, Math.max(1, limit))]);
}

/**
 * Lookup por id — devuelve la fila completa incluyendo data_snapshot.
 * Para reproducir vista histórica o computar diff.
 */
export async function getAnalysisById(id) {
  const sql = `SELECT * FROM surveillance_analyses WHERE id = $1`;
  const rows = await pgQuery(sql, [id]);
  return rows[0] ?? null;
}

/**
 * Devuelve los últimos N análisis con data_snapshot completo, descendente.
 * Para diff "¿qué cambió?" — comparar los dos más recientes.
 */
export async function listRecentAnalysesWithSnapshot(domain, limit = 2) {
  const sql = `
    SELECT id, domain, queried_at, risk_score, risk_band,
           findings_critical, findings_high, findings_total, data_snapshot
    FROM surveillance_analyses
    WHERE domain = $1
    ORDER BY queried_at DESC
    LIMIT $2
  `;
  return pgQuery(sql, [domain.toLowerCase(), Math.min(10, Math.max(1, limit))]);
}

/**
 * Para cada dominio en `domains`, devuelve el análisis MÁS RECIENTE con
 * `data_snapshot.findings`. Usa LATERAL para resolver "top-1 por grupo" sin
 * traer toda la historia. Sirve para correlación cross-watchlist (#6).
 */
export async function listLatestAnalysesForDomains(domains) {
  if (!Array.isArray(domains) || domains.length === 0) return [];
  const lowered = domains.map((d) => String(d).toLowerCase());
  const sql = `
    SELECT a.id, a.domain, a.queried_at, a.risk_score, a.risk_band,
           a.findings_total, a.data_snapshot
    FROM unnest($1::text[]) AS d(domain)
    JOIN LATERAL (
      SELECT id, domain, queried_at, risk_score, risk_band,
             findings_total, data_snapshot
      FROM surveillance_analyses
      WHERE domain = d.domain
      ORDER BY queried_at DESC
      LIMIT 1
    ) a ON TRUE
  `;
  return pgQuery(sql, [lowered]);
}


// ─────────────────────────────────────────────────────────────────────────────
// 2. Anotaciones por finding (#3)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sentinel para "no conflict" en OCC. La función devuelve un objeto:
 *   { ok: true, row } cuando el upsert tuvo éxito.
 *   { ok: false, conflict: true, currentVersion: N } cuando expectedVersion
 *     fue provisto y no coincide con la fila viva.
 */
export async function upsertAnnotation(input) {
  const {
    findingId,
    domain,
    state,
    note = null,
    operatorCi,
    operatorLabel = null,
    expectedVersion = null,
  } = input;

  // Si el cliente envió expectedVersion, primero verificamos la fila viva.
  // La verificación + update no son atómicos; en práctica el riesgo de race
  // es bajo (un solo analista actuando por finding). Para garantía estricta
  // se puede mover a transacción serializable; v1 no lo necesita.
  if (expectedVersion !== null && expectedVersion !== undefined) {
    const live = await pgQuery(
      `SELECT version FROM surveillance_finding_annotations
        WHERE domain = $1 AND finding_id = $2`,
      [domain.toLowerCase(), findingId.slice(0, 255)],
    );
    const currentVersion = live[0]?.version ?? 0;
    // expectedVersion=0 significa "crear nuevo" — solo válido si no existe.
    if (expectedVersion !== currentVersion) {
      return { ok: false, conflict: true, currentVersion };
    }
  }

  const sql = `
    INSERT INTO surveillance_finding_annotations (
      finding_id, domain, state, note, operator_ci, operator_label, version
    ) VALUES ($1, $2, $3, $4, $5, $6, 1)
    ON CONFLICT (domain, finding_id) DO UPDATE SET
      state = EXCLUDED.state,
      note = EXCLUDED.note,
      operator_ci = EXCLUDED.operator_ci,
      operator_label = EXCLUDED.operator_label,
      version = surveillance_finding_annotations.version + 1,
      updated_at = now()
    RETURNING id, finding_id, domain, state, note, operator_ci, operator_label,
              version, created_at, updated_at
  `;
  const params = [
    findingId.slice(0, 255),
    domain.toLowerCase().slice(0, 253),
    state,
    note,
    operatorCi,
    operatorLabel,
  ];
  const rows = await pgQuery(sql, params);
  return { ok: true, row: rows[0] };
}

/**
 * Lista todas las anotaciones de un dominio. El frontend hace overlay sobre
 * los findings vivos para mostrar el state.
 */
export async function listAnnotations(domain) {
  const sql = `
    SELECT id, finding_id, domain, state, note, operator_ci, operator_label,
           version, created_at, updated_at
    FROM surveillance_finding_annotations
    WHERE domain = $1
    ORDER BY updated_at DESC
  `;
  return pgQuery(sql, [domain.toLowerCase()]);
}

/** Borra anotación específica. */
export async function deleteAnnotation(domain, findingId) {
  const sql = `
    DELETE FROM surveillance_finding_annotations
    WHERE domain = $1 AND finding_id = $2
    RETURNING id
  `;
  const rows = await pgQuery(sql, [domain.toLowerCase(), findingId]);
  return rows[0] ?? null;
}


// ─────────────────────────────────────────────────────────────────────────────
// 3. Audit log (#9)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Inserta un evento de auditoría. No-throw — si la query falla logueamos pero
 * no rompemos la operación que la disparó (audit no debe bloquear el flujo).
 */
export async function logAuditEvent(input) {
  const {
    action,
    actorCi = null,
    targetDomain = null,
    targetRef = null,
    metadata = {},
  } = input;

  const sql = `
    INSERT INTO surveillance_audit_events (
      action, actor_ci, target_domain, target_ref, metadata
    ) VALUES ($1, $2, $3, $4, $5)
    RETURNING id
  `;
  try {
    const rows = await pgQuery(sql, [
      action,
      actorCi,
      targetDomain ? targetDomain.toLowerCase().slice(0, 253) : null,
      targetRef ? String(targetRef).slice(0, 255) : null,
      JSON.stringify(metadata),
    ]);
    return rows[0];
  } catch (err) {
    // Best-effort: el audit no debería bloquear el flujo principal.
    console.error("[audit] Insert failed:", err.message);
    return null;
  }
}

/**
 * Lista eventos con filtros opcionales — orden descendente por created_at.
 * El page de auditoría paginaría con offset; por simplicidad acá usamos limit.
 */
export async function listAuditEvents(opts = {}) {
  const {
    actorCi = null,
    targetDomain = null,
    action = null,
    sinceIso = null,
    untilIso = null,
    limit = 100,
  } = opts;

  const where = [];
  const params = [];
  if (actorCi)      { params.push(actorCi);      where.push(`actor_ci = $${params.length}`); }
  if (targetDomain) { params.push(targetDomain.toLowerCase()); where.push(`target_domain = $${params.length}`); }
  if (action)       { params.push(action);       where.push(`action = $${params.length}`); }
  if (sinceIso)     { params.push(sinceIso);     where.push(`created_at >= $${params.length}`); }
  if (untilIso)     { params.push(untilIso);     where.push(`created_at <= $${params.length}`); }

  const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
  params.push(Math.min(1000, Math.max(1, limit)));

  const sql = `
    SELECT id, action, actor_ci, target_domain, target_ref, metadata, created_at
    FROM surveillance_audit_events
    ${whereClause}
    ORDER BY created_at DESC
    LIMIT $${params.length}
  `;
  return pgQuery(sql, params);
}

/**
 * Cleanup de retención — borra eventos > N días. Se llama desde cron en
 * server.mjs. Devuelve el número de filas borradas.
 */
export async function cleanupAuditOldRows(daysToKeep = 30) {
  const sql = `
    DELETE FROM surveillance_audit_events
    WHERE created_at < NOW() - ($1 || ' days')::INTERVAL
    RETURNING id
  `;
  const rows = await pgQuery(sql, [String(daysToKeep)]);
  return rows.length;
}
