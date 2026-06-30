import { createHash, randomBytes } from "node:crypto";

export const SCORING_CODE_TTL_MS = 5 * 60 * 1_000;

export const DEFAULT_SCORING_FORMULA = Object.freeze({
  wMitre: 1,
  wEvidence: 1,
  wWazuh: 1,
  wContext: 1,
  wTor: 1,
  wMisp: 1,
  bonusVtPositive: 3,
  bonusAbuseHigh: 4,
  abuseHighThreshold: 80,
  bonusUrlhaus: 5,
  bonusOpenphish: 5,
  // Alineados con la fuente canónica (config.mjs / soc_thresholds / v4).
  // Audit flujo P0 2026-06-06: antes 55/30 → drift silencioso con el resto.
  thresholdCritical: 80,
  thresholdHigh: 60,
  thresholdMedium: 35,
  thresholdLow: 10,
});

/** @type {Map<string, { code: string, expiresAt: number, used: boolean }>} */
const _publishChallenges = new Map();

function n(v, fallback) {
  const x = Number(v);
  return Number.isFinite(x) ? x : fallback;
}

export function normalizeScoringFormulaConfig(input) {
  const cfg = {
    wMitre: n(input?.wMitre, DEFAULT_SCORING_FORMULA.wMitre),
    wEvidence: n(input?.wEvidence, DEFAULT_SCORING_FORMULA.wEvidence),
    wWazuh: n(input?.wWazuh, DEFAULT_SCORING_FORMULA.wWazuh),
    wContext: n(input?.wContext, DEFAULT_SCORING_FORMULA.wContext),
    wTor:  n(input?.wTor,  DEFAULT_SCORING_FORMULA.wTor),
    wMisp: n(input?.wMisp, DEFAULT_SCORING_FORMULA.wMisp),
    bonusVtPositive: n(input?.bonusVtPositive, DEFAULT_SCORING_FORMULA.bonusVtPositive),
    bonusAbuseHigh: n(input?.bonusAbuseHigh, DEFAULT_SCORING_FORMULA.bonusAbuseHigh),
    abuseHighThreshold: n(input?.abuseHighThreshold, DEFAULT_SCORING_FORMULA.abuseHighThreshold),
    bonusUrlhaus: n(input?.bonusUrlhaus, DEFAULT_SCORING_FORMULA.bonusUrlhaus),
    bonusOpenphish: n(input?.bonusOpenphish, DEFAULT_SCORING_FORMULA.bonusOpenphish),
    thresholdCritical: n(input?.thresholdCritical, DEFAULT_SCORING_FORMULA.thresholdCritical),
    thresholdHigh: n(input?.thresholdHigh, DEFAULT_SCORING_FORMULA.thresholdHigh),
    thresholdMedium: n(input?.thresholdMedium, DEFAULT_SCORING_FORMULA.thresholdMedium),
    thresholdLow: n(input?.thresholdLow, DEFAULT_SCORING_FORMULA.thresholdLow),
  };
  return cfg;
}

export function validateScoringFormulaConfig(cfg) {
  if (!(cfg.thresholdCritical > cfg.thresholdHigh && cfg.thresholdHigh > cfg.thresholdMedium && cfg.thresholdMedium > cfg.thresholdLow)) {
    return { ok: false, error: "Umbrales inválidos: CRITICAL > HIGH > MEDIUM > LOW." };
  }
  return { ok: true };
}

export function hashScoringFormulaConfig(cfg) {
  return createHash("sha256").update(JSON.stringify(cfg)).digest("hex");
}

export function generateScoringPublishCode(payloadHash) {
  const hex = randomBytes(4).toString("hex").toUpperCase();
  const code = `${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
  const expiresAt = Date.now() + SCORING_CODE_TTL_MS;
  _publishChallenges.set(payloadHash, { code, expiresAt, used: false });
  return { code, expiresAt };
}

export function consumeScoringPublishCode(payloadHash, submittedCode) {
  const entry = _publishChallenges.get(payloadHash);
  if (!entry) return { ok: false, reason: "challenge_not_found" };
  if (entry.used) return { ok: false, reason: "already_used" };
  if (Date.now() > entry.expiresAt) return { ok: false, reason: "expired" };
  const normalize = (s) => String(s ?? "").toUpperCase().replace(/-/g, "");
  if (normalize(entry.code) !== normalize(submittedCode)) return { ok: false, reason: "wrong_code" };
  entry.used = true;
  return { ok: true };
}

export function sqlEnsureScoringConfigTable() {
  return `
CREATE TABLE IF NOT EXISTS minio_iceberg.hunting.scoring_formula_config (
  applied_at TIMESTAMP(6) WITH TIME ZONE,
  applied_by VARCHAR,
  w_mitre DOUBLE,
  w_evidence DOUBLE,
  w_wazuh DOUBLE,
  w_context DOUBLE,
  w_tor DOUBLE,
  bonus_vt_positive INTEGER,
  bonus_abuse_high INTEGER,
  abuse_high_threshold INTEGER,
  bonus_urlhaus INTEGER,
  bonus_openphish INTEGER,
  threshold_critical INTEGER,
  threshold_high INTEGER,
  threshold_medium INTEGER,
  threshold_low INTEGER
)
WITH (
  format = 'PARQUET',
  location = 's3://iceberg-lakehouse/hunting/scoring_formula_config'
)
`.trim();
}

function sq(s) {
  return `'${String(s ?? "").replace(/'/g, "''")}'`;
}

export function sqlInsertScoringConfig(cfg, appliedBy = "dashboard") {
  return `
INSERT INTO minio_iceberg.hunting.scoring_formula_config (
  applied_at, applied_by,
  w_mitre, w_evidence, w_wazuh, w_context, w_tor,
  bonus_vt_positive, bonus_abuse_high, abuse_high_threshold, bonus_urlhaus, bonus_openphish,
  threshold_critical, threshold_high, threshold_medium, threshold_low
) VALUES (
  current_timestamp, ${sq(appliedBy)},
  ${cfg.wMitre}, ${cfg.wEvidence}, ${cfg.wWazuh}, ${cfg.wContext}, ${cfg.wTor},
  ${Math.round(cfg.bonusVtPositive)}, ${Math.round(cfg.bonusAbuseHigh)}, ${Math.round(cfg.abuseHighThreshold)}, ${Math.round(cfg.bonusUrlhaus)}, ${Math.round(cfg.bonusOpenphish)},
  ${Math.round(cfg.thresholdCritical)}, ${Math.round(cfg.thresholdHigh)}, ${Math.round(cfg.thresholdMedium)}, ${Math.round(cfg.thresholdLow)}
)
`.trim();
}

/** Vista Iceberg creada por `scripts/bootstrap-trino-scoring-v2-views.sh` (y prerequisitos MinIO/Hive). */
export const SCORING_V2_BASE_VIEW_NAME = "minio_iceberg.hunting.v_incident_score_v2";

export const SCORING_V2_BOOTSTRAP_HINT =
  "En el host con Trino en marcha: ./scripts/bootstrap-trino-scoring-v2-views.sh (antes: ./scripts/bootstrap-trino-minio.sh). " +
  "Documentación: docs/TROUBLESHOOTING-TRINO-SCHEMA-HUNTING.md.";

/**
 * Comprueba que la vista base existe SIN ejecutarla.
 *
 * IMPORTANTE (2026-06-26): `v_incident_score_v2` es una vista agregada cara
 * (recompute de varios minutos a decenas de minutos bajo saturación del nodo
 * único). El antiguo `SELECT 1 ... LIMIT 1` NO es un check barato: para emitir
 * una fila Trino debe materializar el cuerpo agregado completo de la vista →
 * cada arranque del API (este probe corre en ensureScoringRuntimeInitialized)
 * disparaba un full-compute de ~28 min que saturaba Trino y ahogaba la cadena
 * de detección (extract_iocs_trino timeout).
 *
 * `EXPLAIN` planifica la consulta (resuelve la definición de la vista) pero NO
 * la ejecuta: no escanea datos → milisegundos/segundos. Si la vista no existe,
 * EXPLAIN lanza "does not exist"/VIEW_NOT_FOUND igual que antes, por lo que
 * `isMissingTrinoRelationError` sigue detectando la ausencia.
 */
export function sqlProbeScoringV2BaseView() {
  return `EXPLAIN SELECT 1 FROM ${SCORING_V2_BASE_VIEW_NAME} LIMIT 1`.trim();
}

/**
 * Errores Trino típicos cuando falta tabla/vista o catálogo.
 * @param {unknown} err
 */
export function isMissingTrinoRelationError(err) {
  const m = err instanceof Error ? err.message : String(err);
  return /does not exist|TABLE_NOT_FOUND|SCHEMA_NOT_FOUND|CATALOG_NOT_FOUND|Table .* not found|View .* not found/i.test(
    m,
  );
}

export function sqlSeedDefaultScoringConfigIfEmpty() {
  const d = DEFAULT_SCORING_FORMULA;
  return `
INSERT INTO minio_iceberg.hunting.scoring_formula_config (
  applied_at, applied_by,
  w_mitre, w_evidence, w_wazuh, w_context, w_tor,
  bonus_vt_positive, bonus_abuse_high, abuse_high_threshold, bonus_urlhaus, bonus_openphish,
  threshold_critical, threshold_high, threshold_medium, threshold_low
)
SELECT
  current_timestamp, 'system-default',
  ${d.wMitre}, ${d.wEvidence}, ${d.wWazuh}, ${d.wContext}, ${d.wTor},
  ${d.bonusVtPositive}, ${d.bonusAbuseHigh}, ${d.abuseHighThreshold}, ${d.bonusUrlhaus}, ${d.bonusOpenphish},
  ${d.thresholdCritical}, ${d.thresholdHigh}, ${d.thresholdMedium}, ${d.thresholdLow}
WHERE NOT EXISTS (
  SELECT 1 FROM minio_iceberg.hunting.scoring_formula_config
)
`.trim();
}

export function sqlCreateRuntimeScoringView() {
  return `
CREATE VIEW minio_iceberg.hunting.v_incident_score_v2_runtime AS
WITH cfg AS (
  SELECT *
  FROM minio_iceberg.hunting.scoring_formula_config
  ORDER BY applied_at DESC
  LIMIT 1
),
base AS (
  SELECT * FROM minio_iceberg.hunting.v_incident_score_v2
),
scored AS (
  SELECT
    b.*,
    LEAST(100, GREATEST(0, CAST(ROUND(
      (COALESCE(b.score_mitre, 0)    * cfg.w_mitre) +
      (COALESCE(b.score_evidence, 0) * cfg.w_evidence) +
      (COALESCE(b.score_wazuh, 0)    * cfg.w_wazuh) +
      (COALESCE(b.score_context, 0)  * cfg.w_context) +
      (COALESCE(b.score_tor, 0)      * cfg.w_tor) +
      COALESCE(b.score_misp, 0) +
      CASE WHEN COALESCE(b.vt_malicious, 0) > 0 THEN cfg.bonus_vt_positive ELSE 0 END +
      CASE WHEN COALESCE(b.abuse_confidence, 0) >= cfg.abuse_high_threshold THEN cfg.bonus_abuse_high ELSE 0 END +
      CASE WHEN COALESCE(b.in_urlhaus, false) THEN cfg.bonus_urlhaus ELSE 0 END +
      CASE WHEN COALESCE(b.in_openphish, false) THEN cfg.bonus_openphish ELSE 0 END
    ) AS integer))) AS score_runtime,
    cfg.threshold_critical,
    cfg.threshold_high,
    cfg.threshold_medium,
    cfg.threshold_low
  FROM base b
  CROSS JOIN cfg
)
SELECT
  ioc_value,
  ioc_type,
  source_log,
  source_event_id,
  origen_sistema,
  origen_tabla,
  ip_origen_log,
  ip_destino_log,
  host_agente_log,
  mitre_technique_id,
  mitre_tactic_id,
  mitre_tactic_name,
  score_mitre,
  score_evidence,
  score_wazuh,
  score_context,
  score_tor,
  score_misp,
  in_misp,
  score_runtime AS score,
  CASE
    WHEN score_runtime >= threshold_critical THEN 'CRITICAL'
    WHEN score_runtime >= threshold_high THEN 'HIGH'
    WHEN score_runtime >= threshold_medium THEN 'MEDIUM'
    WHEN score_runtime >= threshold_low THEN 'LOW'
    ELSE 'NEGLIGIBLE'
  END AS severity,
  confidence_level,
  CASE
    WHEN score_runtime >= threshold_critical THEN 'BLOQUEAR IP inmediatamente. Aislar sistema afectado. Registrar caso SOC. SLA: 15min'
    WHEN score_runtime >= threshold_high THEN 'Investigar y considerar bloqueo. Revisar logs de autenticación. SLA: 1h'
    WHEN score_runtime >= threshold_medium THEN 'Monitorizar durante 4h. Correlacionar con otros eventos del mismo origen. SLA: 4h'
    WHEN score_runtime >= threshold_low THEN 'Registrar y revisar en siguiente turno. Actualizar reglas si es falso positivo. SLA: 24h'
    ELSE 'Ruido / falso positivo probable. Sin acción inmediata. SLA: 72h'
  END AS recommended_action,
  vt_malicious,
  vt_suspicious,
  vt_permalink,
  shodan_ports,
  shodan_vulns,
  abuse_confidence,
  in_urlhaus,
  in_openphish,
  n_sources,
  source_severity,
  source_category,
  alert_count,
  dt
FROM scored
`.trim();
}

export function sqlDropRuntimeScoringView() {
  return `DROP VIEW IF EXISTS minio_iceberg.hunting.v_incident_score_v2_runtime`.trim();
}

/**
 * Migración idempotente: añade w_misp a scoring_formula_config si no existe.
 * Iceberg soporta ADD COLUMN; si la columna ya existe Trino devuelve un error
 * que se debe ignorar en el caller.
 */
export function sqlAlterScoringConfigAddWMisp() {
  return `ALTER TABLE minio_iceberg.hunting.scoring_formula_config ADD COLUMN w_misp DOUBLE`.trim();
}

