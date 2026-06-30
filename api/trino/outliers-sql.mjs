/**
 * outliers-sql.mjs — SQL builders para la superficie de Outlier Detection.
 *
 * Todas las queries van contra `minio_iceberg.hunting.outliers` + sus dos
 * vistas (`v_outliers_last_24h`, `v_outliers_by_log_family`), creadas por
 * `scripts/sql/threat-hunt/60_outliers_ddl.sql`.
 *
 * Los queryIds registrados en registry.mjs con prefijo `lh.outliers.*` son
 * la única superficie pública hacia el frontend; no se exponen SQL strings.
 *
 * Diseño: docs/OUTLIER-DETECTION.md
 */

/**
 * @param {string} catalog  e.g. "minio_iceberg"
 * @param {string} schema   e.g. "hunting"
 */
export function createOutliersSql(catalog, schema) {
  const t = `${catalog}.${schema}.outliers`;
  const v24 = `${catalog}.${schema}.v_outliers_last_24h`;
  const vFam = `${catalog}.${schema}.v_outliers_by_log_family`;

  /** Helper para escapar strings en predicates IN/WHERE. Params validados
   *  por Zod antes de llegar acá, pero mantengo el escape por defensa. */
  const sq = (v) => `'${String(v ?? "").replace(/'/g, "''")}'`;

  return {
    /**
     * Lista detallada de outliers en una ventana. Usada por
     * `GET /api/outliers?window=...&entity_type=...&severity=...`.
     * Todos los filtros son opcionales — si params vienen null/undefined
     * simplemente se omite la cláusula.
     *
     * @param {object} p
     * @param {number} p.hours
     * @param {number} p.limit
     * @param {string} [p.entity_type]
     * @param {string} [p.severity]
     * @param {string} [p.log_family]
     */
    lastWindow(p) {
      const filters = [
        `detection_time >= current_timestamp - INTERVAL '${Number(p.hours)}' HOUR`,
      ];
      if (p.entity_type) filters.push(`entity_type = ${sq(p.entity_type)}`);
      if (p.severity)    filters.push(`severity    = ${sq(p.severity)}`);
      if (p.log_family)  filters.push(`log_family  = ${sq(p.log_family)}`);
      const l = Number(p.limit);
      return `
SELECT
  outlier_id,
  CAST(detection_time AS varchar)        AS detection_time,
  entity_type, entity_value,
  ROUND(score, 2)                        AS score,
  ROUND(z_score, 2)                      AS z_score,
  ROUND(iqr_score, 2)                    AS iqr_score,
  ROUND(isolation_score, 3)              AS isolation_score,
  anomaly_type, severity, log_family,
  window_hours,
  ROUND(baseline_value, 2)               AS baseline_value,
  ROUND(observed_value, 2)               AS observed_value,
  baseline_window_days,
  details,
  related_ioc_id, related_case_id,
  CAST(acknowledged_at AS varchar)       AS acknowledged_at,
  acknowledged_by,
  notes
FROM ${t}
WHERE ${filters.join("\n  AND ")}
ORDER BY
  CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5 END ASC,
  score DESC, detection_time DESC
LIMIT ${l}`.trim();
    },

    /**
     * KPIs agregados para /api/outliers/dashboard. Un solo row con totales
     * por severity + cantidad de entidades únicas.
     */
    summary24h() {
      return `
SELECT
  COUNT(*)                                                      AS total,
  COUNT(*) FILTER (WHERE severity = 'critical')                 AS critical,
  COUNT(*) FILTER (WHERE severity = 'high')                     AS high,
  COUNT(*) FILTER (WHERE severity = 'medium')                   AS medium,
  COUNT(*) FILTER (WHERE severity = 'low')                      AS low,
  COUNT(*) FILTER (WHERE acknowledged_at IS NULL)               AS unack_count,
  COUNT(DISTINCT entity_value)                                  AS unique_entities,
  COUNT(DISTINCT entity_type)                                   AS entity_type_diversity,
  COUNT(DISTINCT log_family)                                    AS log_family_count,
  ROUND(AVG(score), 2)                                          AS avg_score,
  MAX(score)                                                    AS max_score
FROM ${t}
WHERE detection_time >= current_timestamp - INTERVAL '24' HOUR`.trim();
    },

    /**
     * Idéntico a summary24h pero con ventana parametrizable y los mismos
     * filtros opcionales que `lastWindow`. Los KPIs del panel frontend
     * consumen esta variante para que los números cuadren con la tabla
     * filtrada (bug histórico: summary siempre era 24h sin filtros).
     *
     * @param {object} p
     * @param {number} p.hours
     * @param {string} [p.entity_type]
     * @param {string} [p.severity]
     * @param {string} [p.log_family]
     */
    summaryWindow(p) {
      const filters = [
        `detection_time >= current_timestamp - INTERVAL '${Number(p.hours)}' HOUR`,
      ];
      if (p.entity_type) filters.push(`entity_type = ${sq(p.entity_type)}`);
      if (p.severity)    filters.push(`severity    = ${sq(p.severity)}`);
      if (p.log_family)  filters.push(`log_family  = ${sq(p.log_family)}`);
      return `
SELECT
  COUNT(*)                                                      AS total,
  COUNT(*) FILTER (WHERE severity = 'critical')                 AS critical,
  COUNT(*) FILTER (WHERE severity = 'high')                     AS high,
  COUNT(*) FILTER (WHERE severity = 'medium')                   AS medium,
  COUNT(*) FILTER (WHERE severity = 'low')                      AS low,
  COUNT(*) FILTER (WHERE acknowledged_at IS NULL)               AS unack_count,
  COUNT(DISTINCT entity_value)                                  AS unique_entities,
  COUNT(DISTINCT entity_type)                                   AS entity_type_diversity,
  COUNT(DISTINCT log_family)                                    AS log_family_count,
  ROUND(AVG(score), 2)                                          AS avg_score,
  MAX(score)                                                    AS max_score
FROM ${t}
WHERE ${filters.join("\n  AND ")}`.trim();
    },

    /**
     * Breakdown N días por (log_family, anomaly_type, severity). Alimenta
     * el panel de Recharts del Detection Center.
     *
     * @param {object} p
     * @param {number} p.days
     */
    byLogFamily(p) {
      const d = Number(p.days);
      return `
SELECT
  log_family, anomaly_type, severity,
  COUNT(*)                                  AS detections,
  COUNT(DISTINCT entity_value)              AS unique_entities,
  ROUND(AVG(score), 2)                      AS avg_score,
  MAX(score)                                AS max_score,
  COUNT(*) FILTER (WHERE acknowledged_at IS NULL) AS unack_count
FROM ${t}
WHERE detection_time >= current_timestamp - INTERVAL '${d}' DAY
GROUP BY log_family, anomaly_type, severity
ORDER BY detections DESC
LIMIT 200`.trim();
    },

    /**
     * Top N entidades por score en una ventana. Soporta filtro por
     * entity_type (opcional: si null, devuelve de todos los tipos).
     * Usa v_outliers_last_24h cuando days=1 para aprovechar el pre-agregado.
     *
     * @param {object} p
     * @param {string} [p.entity_type]
     * @param {number} p.days
     * @param {number} p.limit
     */
    topEntities(p) {
      const d = Number(p.days);
      const l = Number(p.limit);
      // days=1 → la vista agregada 24h es más rápida y tiene el severity ya ordenado
      if (d === 1 && !p.entity_type) {
        return `
SELECT entity_type, entity_value,
       severity, max_score AS score,
       anomaly_type, log_family,
       detection_count, all_acknowledged,
       CAST(last_seen AS varchar)  AS last_seen,
       CAST(first_seen AS varchar) AS first_seen
FROM ${v24}
ORDER BY
  CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5 END ASC,
  max_score DESC
LIMIT ${l}`.trim();
      }
      const entityFilter = p.entity_type
        ? `AND entity_type = ${sq(p.entity_type)}`
        : "";
      return `
WITH agg AS (
  SELECT entity_type, entity_value,
         MAX(score) AS score,
         arbitrary(severity) AS severity,
         arbitrary(anomaly_type) AS anomaly_type,
         arbitrary(log_family) AS log_family,
         COUNT(*) AS detection_count,
         MAX(detection_time) AS last_seen
    FROM ${t}
   WHERE detection_time >= current_timestamp - INTERVAL '${d}' DAY
     ${entityFilter}
   GROUP BY entity_type, entity_value
)
SELECT entity_type, entity_value,
       severity, ROUND(score, 2) AS score,
       anomaly_type, log_family, detection_count,
       CAST(last_seen AS varchar) AS last_seen
FROM agg
ORDER BY score DESC
LIMIT ${l}`.trim();
    },

    /**
     * Outliers asociados a un IOC específico (entity_value == ioc_value, o
     * related_ioc_id == ioc). Usado por el tab "Outliers relacionados" en
     * CaseInvestigationView y por calcOutlierBonus (scoring).
     *
     * @param {object} p
     * @param {string} p.ioc_value
     */
    forIoc(p) {
      const v = sq(p.ioc_value);
      return `
SELECT
  outlier_id,
  CAST(detection_time AS varchar) AS detection_time,
  entity_type, entity_value,
  ROUND(score, 2) AS score,
  ROUND(z_score, 2) AS z_score,
  anomaly_type, severity, log_family,
  window_hours,
  details,
  related_ioc_id, related_case_id,
  CAST(acknowledged_at AS varchar) AS acknowledged_at
FROM ${t}
WHERE detection_time >= current_timestamp - INTERVAL '7' DAY
  AND (entity_value = ${v} OR related_ioc_id = ${v})
ORDER BY detection_time DESC, score DESC
LIMIT 50`.trim();
    },
  };
}
