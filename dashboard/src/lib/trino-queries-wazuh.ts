/**
 * Consultas sobre vista/tabla Wazuh en Trino (JSON en `message`).
 * Si `VITE_TRINO_WAZUH_TABLE` no está definido, usa el mismo catálogo/esquema que el syslog (`VITE_TRINO_CATALOG` / `VITE_TRINO_SCHEMA`).
 * Valores `s3.*` se normalizan a `minio.*`.
 * Por defecto `wazuh_alerts` (tabla DDL bootstrap); la vista `wazuh` (syslog ∪ alerts) es opcional.
 */

import { getTrinoCatalog, getTrinoSchema } from "@/lib/trino-catalog";
import { syslogIngestTimestampExpr } from "@/lib/syslog-ingest-time";

const INGEST_TS = syslogIngestTimestampExpr("ingest_time");

function resolveWazuhTable(): string {
  const raw = import.meta.env.VITE_TRINO_WAZUH_TABLE?.trim();
  let q =
    raw && raw.length > 0
      ? raw
      : `${getTrinoCatalog()}.${getTrinoSchema()}.wazuh_alerts`;
  if (/^s3\./i.test(q)) q = q.replace(/^s3\./i, "minio.");
  if (/^s3_iceberg\./i.test(q)) q = q.replace(/^s3_iceberg\./i, "minio_iceberg.");
  return q;
}

export function getWazuhTrinoTable(): string {
  return resolveWazuhTable();
}

export function wazuhCriticalCount24h(): string {
  const t = resolveWazuhTable();
  return `
    SELECT COUNT(*) AS c
    FROM ${t}
    WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND COALESCE(
        TRY_CAST(
          json_extract_scalar(
            json_parse(CAST(message AS varchar)),
            '$.rule.level'
          ) AS integer
        ),
        0
      ) >= 12
  `.trim();
}

export function wazuhSeverityBuckets24h(): string {
  const t = resolveWazuhTable();
  return `
    WITH parsed AS (
      SELECT
        COALESCE(
          TRY_CAST(
            json_extract_scalar(
              json_parse(CAST(message AS varchar)),
              '$.rule.level'
            ) AS integer
          ),
          0
        ) AS lvl
      FROM ${t}
      WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    )
    SELECT
      CASE
        WHEN lvl >= 12 THEN 'critical'
        WHEN lvl >= 8 THEN 'high'
        WHEN lvl >= 4 THEN 'medium'
        ELSE 'low'
      END AS bucket,
      COUNT(*) AS c
    FROM parsed
    GROUP BY 1
    ORDER BY
      CASE bucket
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        ELSE 4
      END
  `.trim();
}

export function wazuhTopRules24h(limit: number): string {
  const t = resolveWazuhTable();
  return `
    SELECT
      json_extract_scalar(
        json_parse(CAST(message AS varchar)),
        '$.rule.id'
      ) AS rule_id,
      MAX(
        json_extract_scalar(
          json_parse(CAST(message AS varchar)),
          '$.rule.description'
        )
      ) AS description,
      COUNT(*) AS hits
    FROM ${t}
    WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
}

export function wazuhTopAgents24h(limit: number): string {
  const t = resolveWazuhTable();
  return `
    SELECT
      COALESCE(
        json_extract_scalar(
          json_parse(CAST(message AS varchar)),
          '$.agent.name'
        ),
        json_extract_scalar(
          json_parse(CAST(message AS varchar)),
          '$.predecoder.hostname'
        ),
        'unknown'
      ) AS agent,
      COUNT(*) AS hits
    FROM ${t}
    WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
}

/** Conteo de alertas Wazuh en las últimas 24 h (misma ventana que el resto de consultas Wazuh del dashboard). */
export function wazuhAlertsLast24h(): string {
  const t = resolveWazuhTable();
  return `
    SELECT COUNT(*) AS c
    FROM ${t}
    WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  `.trim();
}

/**
 * Alertas de vulnerability-detector con CVE y CVSS crítico (≥9.0 en CVSSv2 o v3, o severidad Critical).
 * Rutas JSON alineadas al evento estándar de Wazuh (module vulnerability-detector).
 */
export function wazuhCriticalCves24h(limit: number): string {
  const t = resolveWazuhTable();
  return `
    WITH p AS (
      SELECT
        ${INGEST_TS} AS ts,
        TRY(json_parse(CAST(message AS varchar))) AS j
      FROM ${t}
      WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    ),
    v AS (
      SELECT
        ts,
        j,
        nullif(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.cve'), '')), '') AS cve_id,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.cvss.cv3.base_score'), '')), '') AS double) AS cvss3,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.cvss.cv2.base_score'), '')), '') AS double) AS cvss2,
        lower(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.severity'), ''))) AS vuln_severity,
        COALESCE(
          nullif(trim(COALESCE(json_extract_scalar(j, '$.agent.name'), '')), ''),
          nullif(trim(COALESCE(json_extract_scalar(j, '$.predecoder.hostname'), '')), ''),
          '—'
        ) AS host_name,
        COALESCE(
          nullif(trim(COALESCE(json_extract_scalar(j, '$.agent.ip'), '')), ''),
          nullif(trim(COALESCE(json_extract_scalar(j, '$.data.srcip'), '')), ''),
          nullif(trim(COALESCE(json_extract_scalar(j, '$.data.dstip'), '')), ''),
          '—'
        ) AS host_ip,
        nullif(trim(COALESCE(json_extract_scalar(j, '$.rule.description'), '')), '') AS rule_description,
        substr(
          COALESCE(TRY(json_format(json_extract(j, '$.rule.groups'))), ''),
          1,
          240
        ) AS incident_taxonomy
      FROM p
      WHERE j IS NOT NULL
    )
    SELECT
      CAST(ts AS varchar) AS ingest_time,
      cve_id,
      GREATEST(COALESCE(cvss3, 0), COALESCE(cvss2, 0)) AS cvss_score,
      CASE
        WHEN COALESCE(cvss3, 0) >= COALESCE(cvss2, 0) AND cvss3 IS NOT NULL THEN 'CVSSv3'
        WHEN cvss2 IS NOT NULL THEN 'CVSSv2'
        ELSE 'n/d'
      END AS cvss_source,
      COALESCE(vuln_severity, '') AS severity,
      host_name,
      host_ip,
      COALESCE(rule_description, '') AS rule_description,
      COALESCE(incident_taxonomy, '') AS incident_taxonomy
    FROM v
    WHERE cve_id IS NOT NULL
      AND (
        GREATEST(COALESCE(cvss3, 0), COALESCE(cvss2, 0)) >= 9.0
        OR vuln_severity = 'critical'
      )
    ORDER BY ts DESC
    LIMIT ${limit}
  `.trim();
}

/** Agregado por host: cuántas alertas CVE críticas y CVEs distintos (24h). */
export function wazuhCriticalCveHosts24h(limit: number): string {
  const t = resolveWazuhTable();
  return `
    WITH p AS (
      SELECT
        ${INGEST_TS} AS ts,
        TRY(json_parse(CAST(message AS varchar))) AS j
      FROM ${t}
      WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    ),
    v AS (
      SELECT
        nullif(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.cve'), '')), '') AS cve_id,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.cvss.cv3.base_score'), '')), '') AS double) AS cvss3,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.cvss.cv2.base_score'), '')), '') AS double) AS cvss2,
        lower(trim(COALESCE(json_extract_scalar(j, '$.data.vulnerability.severity'), ''))) AS vuln_severity,
        COALESCE(
          nullif(trim(COALESCE(json_extract_scalar(j, '$.agent.ip'), '')), ''),
          nullif(trim(COALESCE(json_extract_scalar(j, '$.data.srcip'), '')), ''),
          nullif(trim(COALESCE(json_extract_scalar(j, '$.data.dstip'), '')), ''),
          '—'
        ) AS host_ip,
        COALESCE(
          nullif(trim(COALESCE(json_extract_scalar(j, '$.agent.name'), '')), ''),
          nullif(trim(COALESCE(json_extract_scalar(j, '$.predecoder.hostname'), '')), ''),
          '—'
        ) AS host_name
      FROM p
      WHERE j IS NOT NULL
    )
    SELECT
      host_ip,
      host_name,
      COUNT(DISTINCT cve_id) AS distinct_cves,
      COUNT(*) AS alert_count,
      MAX(GREATEST(COALESCE(cvss3, 0), COALESCE(cvss2, 0))) AS max_cvss_seen
    FROM v
    WHERE cve_id IS NOT NULL
      AND (
        GREATEST(COALESCE(cvss3, 0), COALESCE(cvss2, 0)) >= 9.0
        OR vuln_severity = 'critical'
      )
    GROUP BY 1, 2
    ORDER BY alert_count DESC, distinct_cves DESC
    LIMIT ${limit}
  `.trim();
}

export function wazuhRecentLines(limit: number, minutes: number): string {
  const t = resolveWazuhTable();
  return `
    SELECT
      CAST(ingest_time AS varchar) AS ingest_time,
      json_extract_scalar(
        json_parse(CAST(message AS varchar)),
        '$.rule.description'
      ) AS rule_desc,
      json_extract_scalar(
        json_parse(CAST(message AS varchar)),
        '$.rule.level'
      ) AS level,
      json_extract_scalar(
        json_parse(CAST(message AS varchar)),
        '$.agent.name'
      ) AS agent
    FROM ${t}
    WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${minutes}' MINUTE
    ORDER BY ${INGEST_TS} DESC
    LIMIT ${limit}
  `.trim();
}
