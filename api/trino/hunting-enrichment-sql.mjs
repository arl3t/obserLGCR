/**
 * Lecturas sobre Iceberg `enriched_ioc` / `vt_results` (esquema hunting).
 * El score `vt_priority_score` no es columna física: replica la expresión del DAG
 * `threat_hunt_enrichment_daily.py` (_fetch_pending_vt) para KPIs coherentes con VT.
 */
export function createHuntingEnrichmentSql(catalog, schema) {
  const te = `${catalog}.${schema}.enriched_ioc`;
  const tv = `${catalog}.${schema}.vt_results`;

  /** @param {string} alias */
  function priorityScore(alias) {
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

  return {
    /** @param {number} days */
    enrichedKpis(days) {
      const d = Number(days);
      return `
SELECT
  COUNT(*) AS total_rows,
  SUM(CASE WHEN dt >= current_date - INTERVAL '${d}' DAY THEN 1 ELSE 0 END) AS rows_in_window,
  SUM(CASE WHEN dt >= current_date - INTERVAL '${d}' DAY AND mitre_technique_id IS NOT NULL THEN 1 ELSE 0 END) AS rows_with_mitre_in_window,
  MAX(dt) AS max_dt_seen
FROM ${te}
`.trim();
    },

    /** @param {number} days */
    enrichedDailyTrend(days) {
      const d = Number(days);
      return `
SELECT CAST(dt AS varchar) AS dt, COUNT(*) AS cnt
FROM ${te}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY dt
ORDER BY dt
`.trim();
    },

    /** @param {number} days */
    enrichedSourceBreakdown(days) {
      const d = Number(days);
      return `
SELECT COALESCE(source_log, '(null)') AS source_log, COUNT(*) AS cnt
FROM ${te}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY source_log
ORDER BY cnt DESC
`.trim();
    },

    /** @param {number} days */
    enrichedScoreBuckets(days) {
      const d = Number(days);
      const ps = priorityScore("e");
      return `
WITH base AS (
  SELECT ${ps} AS vt_priority_score
  FROM ${te} e
  WHERE e.dt >= current_date - INTERVAL '${d}' DAY
)
SELECT vt_priority_score, COUNT(*) AS cnt
FROM base
GROUP BY vt_priority_score
ORDER BY vt_priority_score DESC
`.trim();
    },

    /** @param {number} limit @param {number} days */
    enrichedVtTopSample(limit, days) {
      const l = Number(limit);
      const d = Number(days);
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
FROM ${te} e
LEFT JOIN ${tv} v
  ON v.ioc_value = e.ioc_value
 AND v.ioc_type = e.ioc_type
 AND v.dt = e.dt
WHERE e.dt >= current_date - INTERVAL '${d}' DAY
ORDER BY COALESCE(v.vt_malicious, 0) DESC, vt_priority_score DESC, e.dt DESC
LIMIT ${l}
`.trim();
    },

    /** @param {number} days */
    enrichedVtCoverage(days) {
      const d = Number(days);
      return `
SELECT
  COUNT(*) AS enriched_rows_in_window,
  COUNT(v.vt_row_key) AS rows_with_vt_join,
  SUM(CASE WHEN COALESCE(v.vt_malicious, 0) > 0 THEN 1 ELSE 0 END) AS rows_vt_malicious_positive
FROM ${te} e
LEFT JOIN ${tv} v
  ON v.ioc_value = e.ioc_value
 AND v.ioc_type = e.ioc_type
 AND v.dt = e.dt
WHERE e.dt >= current_date - INTERVAL '${d}' DAY
`.trim();
    },

    /**
     * Circuit-breaker failures: IOCs con enrichment_failed=true en la ventana.
     * Columna añadida por migration 24_enriched_ioc_circuit_breaker_cols.sql.
     * TRY_CAST protege consultas en entornos donde la columna aún no existe.
     * @param {number} days
     */
    enrichedCbFailed(days) {
      const d = Number(days);
      return `
SELECT
  COUNT(*) AS failed_total,
  COUNT(DISTINCT COALESCE(TRY(enrichment_fail_source), '(unknown)')) AS sources_affected,
  SUM(CASE WHEN TRY(enrichment_fail_source) = 'virustotal'  THEN 1 ELSE 0 END) AS failed_vt,
  SUM(CASE WHEN TRY(enrichment_fail_source) = 'shodan'      THEN 1 ELSE 0 END) AS failed_shodan,
  SUM(CASE WHEN TRY(enrichment_fail_source) = 'abuseipdb'   THEN 1 ELSE 0 END) AS failed_abuseipdb,
  SUM(CASE WHEN TRY(enrichment_fail_source) = 'thc_rdns'    THEN 1 ELSE 0 END) AS failed_thc_rdns,
  MAX(TRY(CAST(enrichment_failed_at AS varchar))) AS last_failed_at
FROM ${te}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  AND TRY(enrichment_failed) = true
`.trim();
    },
  };
}
