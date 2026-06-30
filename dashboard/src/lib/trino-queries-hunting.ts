/**
 * SQL para tablas Iceberg `enriched_ioc` / `vt_results`.
 * Duplica la lógica de `legacyhunt-api/trino/hunting-enrichment-sql.mjs` para el fallback
 * del dashboard cuando `POST /api/trino/run` no conoce aún los ids `lh.hunting.*`.
 */
import { getTrinoHuntingIcebergCatalog, getTrinoSchema } from "@/lib/trino-catalog";

function te(): string {
  return `${getTrinoHuntingIcebergCatalog()}.${getTrinoSchema()}.enriched_ioc`;
}

function tv(): string {
  return `${getTrinoHuntingIcebergCatalog()}.${getTrinoSchema()}.vt_results`;
}

function priorityScore(alias: string): string {
  return `(
  CASE WHEN ${alias}.mitre_technique_id IS NOT NULL THEN 2 ELSE 0 END
  + CASE
      WHEN ${alias}.source_log = 'wazuh_alerts'
      AND TRY_CAST(json_extract_scalar(try(json_parse(${alias}.raw_context)), '$.rule.level') AS integer) >= 9
      THEN TRY_CAST(json_extract_scalar(try(json_parse(${alias}.raw_context)), '$.rule.level') AS integer)
      ELSE 0
    END
)`;
}

export function huntingEnrichedKpis(days: number): string {
  const d = Math.min(365, Math.max(1, Math.floor(days)));
  return `
SELECT
  COUNT(*) AS total_rows,
  SUM(CASE WHEN dt >= current_date - INTERVAL '${d}' DAY THEN 1 ELSE 0 END) AS rows_in_window,
  SUM(CASE WHEN dt >= current_date - INTERVAL '${d}' DAY AND mitre_technique_id IS NOT NULL THEN 1 ELSE 0 END) AS rows_with_mitre_in_window,
  MAX(dt) AS max_dt_seen
FROM ${te()}
`.trim();
}

export function huntingEnrichedDailyTrend(days: number): string {
  const d = Math.min(365, Math.max(1, Math.floor(days)));
  return `
SELECT CAST(dt AS varchar) AS dt, COUNT(*) AS cnt
FROM ${te()}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY dt
ORDER BY dt
`.trim();
}

export function huntingEnrichedSourceBreakdown(days: number): string {
  const d = Math.min(365, Math.max(1, Math.floor(days)));
  return `
SELECT COALESCE(source_log, '(null)') AS source_log, COUNT(*) AS cnt
FROM ${te()}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY source_log
ORDER BY cnt DESC
`.trim();
}

export function huntingEnrichedScoreBuckets(days: number): string {
  const d = Math.min(365, Math.max(1, Math.floor(days)));
  const ps = priorityScore("e");
  return `
WITH base AS (
  SELECT ${ps} AS vt_priority_score
  FROM ${te()} e
  WHERE e.dt >= current_date - INTERVAL '${d}' DAY
)
SELECT vt_priority_score, COUNT(*) AS cnt
FROM base
GROUP BY vt_priority_score
ORDER BY vt_priority_score DESC
`.trim();
}

export function huntingEnrichedVtTopSample(limit: number, days: number): string {
  const l = Math.min(500, Math.max(1, Math.floor(limit)));
  const d = Math.min(90, Math.max(1, Math.floor(days)));
  const ps = priorityScore("e");
  return `
SELECT
  e.ioc_value,
  e.ioc_type,
  CAST(e.dt AS varchar) AS dt,
  e.source_log,
  e.mitre_technique_id,
  ${ps} AS vt_priority_score,
  v.vt_malicious,
  v.vt_suspicious,
  CASE WHEN v.vt_row_key IS NOT NULL THEN true ELSE false END AS has_vt_row
FROM ${te()} e
LEFT JOIN ${tv()} v
  ON v.ioc_value = e.ioc_value
 AND v.ioc_type = e.ioc_type
 AND v.dt = e.dt
WHERE e.dt >= current_date - INTERVAL '${d}' DAY
ORDER BY COALESCE(v.vt_malicious, 0) DESC, vt_priority_score DESC, e.dt DESC
LIMIT ${l}
`.trim();
}

export function huntingEnrichedVtCoverage(days: number): string {
  const d = Math.min(365, Math.max(1, Math.floor(days)));
  return `
SELECT
  COUNT(*) AS enriched_rows_in_window,
  COUNT(v.vt_row_key) AS rows_with_vt_join,
  SUM(CASE WHEN COALESCE(v.vt_malicious, 0) > 0 THEN 1 ELSE 0 END) AS rows_vt_malicious_positive
FROM ${te()} e
LEFT JOIN ${tv()} v
  ON v.ioc_value = e.ioc_value
 AND v.ioc_type = e.ioc_type
 AND v.dt = e.dt
WHERE e.dt >= current_date - INTERVAL '${d}' DAY
`.trim();
}

/**
 * Misma consulta que `lh.incidents.live_top_v2` en legacyhunt-api (fallback si /api/trino/run devuelve 404).
 */
export function incidentsLiveTopV2(limit: number, days: number): string {
  const l = Math.min(500, Math.max(1, Math.floor(limit)));
  const d = Math.min(90, Math.max(1, Math.floor(days)));
  const cat = getTrinoHuntingIcebergCatalog();
  const sch = getTrinoSchema();
  const tv2 = `${cat}.${sch}.v_incident_score_v2`;
  return `
SELECT
  ioc_value,
  ioc_type,
  source_log,
  mitre_technique_id,
  mitre_tactic_id,
  mitre_tactic_name,
  score_mitre,
  score_evidence,
  score_wazuh,
  score_context,
  score,
  severity,
  confidence_level,
  recommended_action,
  vt_malicious,
  vt_suspicious,
  vt_permalink,
  shodan_ports,
  shodan_vulns,
  abuse_confidence,
  in_urlhaus,
  in_openphish,
  n_sources,
  source_category,
  alert_count,
  CAST(dt AS varchar) AS dt
FROM ${tv2}
WHERE dt >= current_date - INTERVAL '${d}' DAY
ORDER BY score DESC, dt DESC
LIMIT ${l}
`.trim();
}
