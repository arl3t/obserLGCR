import { syslogIngestTimestampExpr } from "./ingest-time.mjs";
import { integerStyleWindow } from "./time-window.mjs";

const INGEST_TS = syslogIngestTimestampExpr("ingest_time");

/**
 * Filtro de partición para la tabla wazuh (particionada por year/month/day/hour).
 * Limita el scan a hoy + ayer para habilitar partition pruning. Se combina
 * SIEMPRE con el filtro INGEST_TS para precisión de 24h exactas.
 */
const { PART_2D: WAZUH_PART_FILTER } = integerStyleWindow();

export function resolveWazuhTableName(cfg) {
  const raw = (cfg.intelWazuhTable ?? "").trim();
  if (raw) {
    if (/^s3\./i.test(raw)) return raw.replace(/^s3\./i, "minio.");
    if (/^s3_iceberg\./i.test(raw)) return raw.replace(/^s3_iceberg\./i, "minio_iceberg.");
    return raw;
  }
  return `${cfg.trinoCatalog}.${cfg.trinoSchema}.wazuh`;
}

export function createWazuhSql(tableQualified) {
  const t = tableQualified;

  /**
   * CTE shareable para queries 24h sobre la tabla wazuh.
   *
   * Evalúa `json_parse(message)` UNA sola vez por fila (alias `j`). Antes
   * cada query hacía `json_extract_scalar(json_parse(message), '$.x')` por
   * cada campo extraído (2-4 veces por fila → 2-4× json_parse). Con el CTE,
   * las extracciones downstream operan sobre el objeto JSON ya parseado.
   *
   * El filtro `WAZUH_PART_FILTER` + `INGEST_TS >= now-24h` se aplican aquí
   * para que el CTE entregue solamente las filas que las queries necesitan
   * (evita scan de toda la tabla en queries que olvidaban el filtro de
   * partición — bug histórico en `alertsLast24h` y `recentLines`).
   */
  const RAW_24H = `raw_24h AS (
    SELECT
      TRY(json_parse(CAST(message AS varchar))) AS j,
      ${INGEST_TS} AS ev_ingest
    FROM ${t}
    WHERE ${WAZUH_PART_FILTER}
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  )`;

  return {
    alertsLast24h() {
      // FIX: este query no tenía WAZUH_PART_FILTER y escaneaba toda la
      // tabla wazuh (años de partition). Ahora lo aplica vía RAW_24H.
      return `
    WITH ${RAW_24H}
    SELECT COUNT(*) AS c
    FROM raw_24h
  `.trim();
    },
    /**
     * KPIs 24h para la tarjeta del Resumen de detección (Detection Overview).
     * Shape idéntico a lh.wazuh_fluent.kpis_24h (alerts / critical / active_agents
     * / manager_nodes) pero sobre el canal VIVO `wazuh_alerts` (alert Wazuh en
     * JSON dentro de `message`), porque el pipeline Fluent Bit → wazuh_fluent
     * puede quedar sin feed y dejar la tarjeta en 0.
     */
    kpis24hOverview() {
      // MV-backed (wazuh_kpis_hourly, DAG wazuh_summary_refresh_30min). Antes
      // escaneaba ~1.4M filas leyendo el blob `message` → 59 s → timeout 60 s
      // del front. Ahora lee agregados horarios con HLL → sub-segundo.
      return `
    SELECT
      COALESCE(SUM(total_alerts), 0)                                          AS alerts,
      COALESCE(SUM(critical_alerts), 0)                                       AS critical,
      COALESCE(cardinality(merge(CAST(hll_agent   AS HyperLogLog))), 0)       AS active_agents,
      COALESCE(cardinality(merge(CAST(hll_manager AS HyperLogLog))), 0)       AS manager_nodes
    FROM minio_iceberg.hunting.wazuh_kpis_hourly
    WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  `.trim();
    },
    criticalCount24h() {
      return `
    SELECT COUNT(*) AS c
    FROM ${t}
    WHERE ${WAZUH_PART_FILTER}
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
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
    },
    severityBuckets24h() {
      // MV-backed (wazuh_rule_hourly). Antes 214 s (parse de 1.4M message).
      return `
    SELECT bucket, c FROM (
      SELECT
        CASE
          WHEN rule_level >= 12 THEN 'critical'
          WHEN rule_level >= 8  THEN 'high'
          WHEN rule_level >= 4  THEN 'medium'
          ELSE 'low'
        END AS bucket,
        SUM(hits) AS c
      FROM minio_iceberg.hunting.wazuh_rule_hourly
      WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      GROUP BY 1
    )
    ORDER BY CASE bucket WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
  `.trim();
    },
    /** @param {number} limit */
    topRules24h(limit) {
      // MV-backed (wazuh_rule_hourly).
      return `
    SELECT
      rule_id,
      MAX(rule_description)                                        AS description,
      SUM(hits)                                                    AS hits
    FROM minio_iceberg.hunting.wazuh_rule_hourly
    WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND rule_id <> ''
    GROUP BY rule_id
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },
    /** @param {number} limit */
    topAgents24h(limit) {
      // MV-backed (wazuh_agent_hourly).
      return `
    SELECT
      agent_name AS agent,
      SUM(hits)  AS hits
    FROM minio_iceberg.hunting.wazuh_agent_hourly
    WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    GROUP BY agent_name
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },
    /**
     * Agentes Wazuh activos 24h (autodescubrimiento de sensores) — MV-backed.
     * Repunta `lh.wazuh_alerts.active_agents_24h` desde el raw (json_parse del blob,
     * ~108s → timeout 60s del front) a `wazuh_agent_hourly` (Iceberg, ~ms). Shape
     * compatible con SensorsManager: agent_name, agent_id, agent_ip, hits. El grano
     * horario no persiste agent.id → '—' (el front matchea por nombre/IP).
     * @param {number} limit
     */
    activeAgents24h(limit) {
      return `
    SELECT
      agent_name                  AS agent_name,
      '—'                         AS agent_id,
      MAX(agent_ip)               AS agent_ip,
      SUM(hits)                   AS hits
    FROM minio_iceberg.hunting.wazuh_agent_hourly
    WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND agent_name IS NOT NULL
    GROUP BY agent_name
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },
    /** @param {number} limit */
    criticalCves24h(limit) {
      // MV-backed (wazuh_cve_daily; grano cve+host). El feed per-evento original
      // se colapsa a 1 fila por (cve,host) — shape compatible con el front
      // (ingest_time←last_seen). cvss_source aproximado a CVSSv3 (el dominante
      // en los datos críticos); la fuente exacta v2/v3 no se persiste en la MV.
      return `
    SELECT
      last_seen                                  AS ingest_time,
      cve_id,
      cvss_score,
      CASE WHEN cvss_score > 0 THEN 'CVSSv3' ELSE 'n/d' END AS cvss_source,
      COALESCE(severity, '')                     AS severity,
      COALESCE(status, '')                       AS status,
      host_name,
      host_ip,
      COALESCE(rule_description, '')             AS rule_description,
      COALESCE(incident_taxonomy, '')            AS incident_taxonomy
    FROM minio_iceberg.hunting.wazuh_cve_daily
    WHERE dt >= current_date - INTERVAL '1' DAY
      AND COALESCE(status, '') <> 'solved'   -- solo exposiciones ACTIVAS
    ORDER BY last_seen DESC
    LIMIT ${limit}
  `.trim();
    },
    /**
     * Top N CVEs críticos agregados POR CVE en 24h. Un row = una CVE.
     *
     * A diferencia de `criticalCves24h` (filas per-evento ordenadas por ts),
     * este builder agrupa por `cve_id` y devuelve `hosts_count` (DISTINCT)
     * + alert_count + max_cvss + lista de hosts truncada — el shape que
     * espera el tab "CVEs Críticos" de /hunt.
     *
     * @param {number} limit
     */
    criticalCvesAggregated24h(limit) {
      return `
    WITH p AS (
      SELECT ${INGEST_TS} AS ts, TRY(json_parse(CAST(message AS varchar))) AS j
      FROM ${t}
      WHERE ${WAZUH_PART_FILTER}
        AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    ),
    v AS (
      SELECT ts, j,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cve'),'')),       '') AS cve_id,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cvss.cvss3.base_score'),'')), '') AS double) AS cvss3,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cvss.cvss2.base_score'),'')), '') AS double) AS cvss2,
        lower(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.severity'),'')))   AS vuln_severity,
        COALESCE(
          nullif(trim(COALESCE(json_extract_scalar(j,'$.agent.name'),'')),           ''),
          nullif(trim(COALESCE(json_extract_scalar(j,'$.predecoder.hostname'),'')),  ''),
          '—'
        ) AS host_name
      FROM p WHERE j IS NOT NULL
    )
    SELECT
      cve_id,
      MAX(GREATEST(COALESCE(cvss3,0), COALESCE(cvss2,0)))                  AS cvss_score,
      arbitrary(vuln_severity)                                              AS severity,
      COUNT(DISTINCT host_name)                                             AS hosts_count,
      COUNT(*)                                                              AS alert_count,
      CAST(MAX(ts) AS varchar)                                              AS last_seen,
      -- hosts afectados (DISTINCT, hasta 10): la UI muestra top-3 inline
      -- y el resto en el expand. '—' es el placeholder cuando agent.name
      -- y predecoder.hostname venían vacíos — lo filtramos.
      slice(array_distinct(filter(array_agg(host_name), x -> x IS NOT NULL AND x <> '—')), 1, 10) AS top_hosts
    FROM v
    WHERE cve_id IS NOT NULL
      AND (GREATEST(COALESCE(cvss3,0), COALESCE(cvss2,0)) >= 9.0 OR vuln_severity = 'critical')
    GROUP BY cve_id
    ORDER BY hosts_count DESC, alert_count DESC, cvss_score DESC
    LIMIT ${limit}
  `.trim();
    },
    /** @param {number} limit */
    criticalCveHosts24h(limit) {
      // MV-backed (wazuh_cve_daily) agregado por host.
      return `
    SELECT
      host_ip,
      host_name,
      COUNT(DISTINCT cve_id)  AS distinct_cves,
      SUM(alert_count)        AS alert_count,
      MAX(cvss_score)         AS max_cvss_seen
    FROM minio_iceberg.hunting.wazuh_cve_daily
    WHERE dt >= current_date - INTERVAL '1' DAY
      AND COALESCE(status, '') <> 'solved'   -- solo exposiciones ACTIVAS
    GROUP BY host_ip, host_name
    ORDER BY alert_count DESC, distinct_cves DESC
    LIMIT ${limit}
  `.trim();
    },
    /**
     * B1 audit Casos 2026-05-21 — CVEs del agente Wazuh `vulnerability-detector`
     * filtrados por host del caso (hostname y/o IP). Ventana configurable
     * (default 7 días) porque un caso puede tener semanas y los CVEs no
     * "vencen" igual que las alertas de exploit.
     *
     * Devuelve todas las severidades (no solo critical) — el caller decide
     * cuáles mostrar. Para "Resumen" del caso típicamente filtrar CVSS≥7.
     *
     * @param {string|null} hostName  — agent.name o predecoder.hostname
     * @param {string|null} hostIp    — agent.ip, data.srcip o data.dstip
     * @param {number} days  — ventana en días (1–90, default 7)
     * @param {number} limit — filas máximo (default 100)
     */
    cvesForHost(hostName, hostIp, days = 7, limit = 100) {
      const d  = Math.max(1, Math.min(90, Number(days)  || 7));
      const n  = Math.max(1, Math.min(500, Number(limit) || 100));
      // Columna `year` es varchar → comparar bare (sin CAST) para preservar el
      // partition pruning (CAST(year AS integer) lo degrada a full scan). Ver nota
      // en time-window.mjs::dayClause.
      const partHint = d <= 1 ? WAZUH_PART_FILTER
                              : `year = CAST(YEAR(CURRENT_DATE) AS varchar)`;

      // Sanitizar: solo letras/dígitos/punto/guion/_ — el resto se descarta para
      // bloquear inyección en string literal (Trino no soporta prepared
      // statements para JSON path filtering trivialmente desde este path).
      const sanHost = String(hostName ?? "").replace(/[^A-Za-z0-9._-]/g, "");
      const sanIp   = String(hostIp   ?? "").replace(/[^0-9.:a-fA-F]/g, "");

      const filters = [];
      if (sanHost) filters.push(
        `(json_extract_scalar(j,'$.agent.name') = '${sanHost}'
          OR json_extract_scalar(j,'$.predecoder.hostname') = '${sanHost}')`);
      if (sanIp) filters.push(
        `(json_extract_scalar(j,'$.agent.ip') = '${sanIp}'
          OR json_extract_scalar(j,'$.data.srcip') = '${sanIp}'
          OR json_extract_scalar(j,'$.data.dstip') = '${sanIp}')`);

      if (!filters.length) {
        // Sin filtro alguno → query inocua que no devuelve filas. Evita escan
        // global accidental cuando el caso no tiene asset resoluble.
        return `SELECT NULL::varchar AS cve_id WHERE false`;
      }

      return `
    WITH p AS (
      SELECT ${INGEST_TS} AS ts, TRY(json_parse(CAST(message AS varchar))) AS j
      FROM ${t}
      WHERE ${partHint}
        AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${d}' DAY
    ),
    v AS (
      SELECT ts, j,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cve'),'')),       '') AS cve_id,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cvss.cvss3.base_score'),'')), '') AS double) AS cvss3,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cvss.cvss2.base_score'),'')), '') AS double) AS cvss2,
        lower(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.severity'),'')))   AS vuln_severity,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.package.name'),'')), '') AS package_name,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.package.version'),'')), '') AS package_version,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.title'),'')), '')    AS vuln_title,
        COALESCE(
          nullif(trim(COALESCE(json_extract_scalar(j,'$.agent.name'),'')),           ''),
          nullif(trim(COALESCE(json_extract_scalar(j,'$.predecoder.hostname'),'')),  ''),
          '—'
        ) AS host_name,
        COALESCE(
          nullif(trim(COALESCE(json_extract_scalar(j,'$.agent.ip'),'')),    ''),
          nullif(trim(COALESCE(json_extract_scalar(j,'$.data.srcip'),'')),''),
          nullif(trim(COALESCE(json_extract_scalar(j,'$.data.dstip'),'')),''),
          '—'
        ) AS host_ip,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.rule.description'),'')), '')          AS rule_description
      FROM p WHERE j IS NOT NULL
        AND (${filters.join(" OR ")})
    )
    -- Deduplicar por cve_id quedándose con la cvss/severidad mayor observada
    SELECT
      cve_id,
      MAX(GREATEST(COALESCE(cvss3,0), COALESCE(cvss2,0))) AS cvss_score,
      MAX(CASE WHEN cvss3 IS NOT NULL THEN 'CVSSv3'
               WHEN cvss2 IS NOT NULL THEN 'CVSSv2' ELSE 'n/d' END) AS cvss_source,
      MAX(vuln_severity) AS severity,
      MAX(package_name)    AS package_name,
      MAX(package_version) AS package_version,
      MAX(vuln_title)      AS vuln_title,
      MAX(host_name)       AS host_name,
      MAX(host_ip)         AS host_ip,
      MAX(rule_description) AS rule_description,
      COUNT(*)             AS alert_count,
      CAST(MAX(ts) AS varchar) AS last_seen
    FROM v
    WHERE cve_id IS NOT NULL
    GROUP BY cve_id
    ORDER BY cvss_score DESC, alert_count DESC
    LIMIT ${n}
  `.trim();
    },

    /* ── Versiones con ventana variable (hours) ─────────────────────────── */

    /** Partition hint dinámico para cualquier ventana de horas. */
    _wazuhPartHint(hours) {
      if (hours <= 25) return WAZUH_PART_FILTER;
      // `year` varchar → bare compare para no romper el partition pruning.
      return `year = CAST(YEAR(CURRENT_DATE) AS varchar)`;
    },

    /** Conteo de alertas críticas (level ≥ 12) en ventana de N horas. */
    criticalCountNh(hours) {
      const part = this._wazuhPartHint(hours);
      return `
    SELECT COUNT(*) AS c
    FROM ${t}
    WHERE ${part}
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      AND COALESCE(
        TRY_CAST(
          json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.level') AS integer
        ), 0
      ) >= 12
  `.trim();
    },

    /** Distribución de severidad en ventana de N horas. */
    severityBucketsNh(hours) {
      const part = this._wazuhPartHint(hours);
      return `
    WITH parsed AS (
      SELECT
        COALESCE(
          TRY_CAST(
            json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.level') AS integer
          ), 0
        ) AS lvl
      FROM ${t}
      WHERE ${part}
        AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
    )
    SELECT
      CASE WHEN lvl >= 12 THEN 'critical' WHEN lvl >= 8 THEN 'high' WHEN lvl >= 4 THEN 'medium' ELSE 'low' END AS bucket,
      COUNT(*) AS c
    FROM parsed
    GROUP BY 1
    ORDER BY CASE bucket WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
  `.trim();
    },

    /**
     * Top reglas activadas en ventana de N horas.
     * @param {number} limit
     * @param {number} hours
     */
    topRulesNh(limit, hours) {
      const part = this._wazuhPartHint(hours);
      return `
    SELECT
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')               AS rule_id,
      MAX(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description')) AS description,
      COUNT(*) AS hits
    FROM ${t}
    WHERE ${part}
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },

    /**
     * CVE críticos (CVSS ≥ 9 o severidad critical) en ventana de N horas.
     * @param {number} limit
     * @param {number} hours
     */
    criticalCvesNh(limit, hours) {
      const part = this._wazuhPartHint(hours);
      return `
    WITH p AS (
      SELECT ${INGEST_TS} AS ts, TRY(json_parse(CAST(message AS varchar))) AS j
      FROM ${t}
      WHERE ${part}
        AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
    ),
    v AS (
      SELECT ts, j,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cve'),'')), '')       AS cve_id,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cvss.cvss3.base_score'),'')), '') AS double) AS cvss3,
        TRY_CAST(nullif(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.cvss.cvss2.base_score'),'')), '') AS double) AS cvss2,
        lower(trim(COALESCE(json_extract_scalar(j,'$.data.vulnerability.severity'),'')))       AS vuln_severity,
        COALESCE(nullif(trim(COALESCE(json_extract_scalar(j,'$.agent.name'),'')), ''),
                 nullif(trim(COALESCE(json_extract_scalar(j,'$.predecoder.hostname'),'')), ''), '—') AS host_name,
        COALESCE(nullif(trim(COALESCE(json_extract_scalar(j,'$.agent.ip'),'')), ''),
                 nullif(trim(COALESCE(json_extract_scalar(j,'$.data.srcip'),'')),''),
                 nullif(trim(COALESCE(json_extract_scalar(j,'$.data.dstip'),'')),''), '—')     AS host_ip,
        nullif(trim(COALESCE(json_extract_scalar(j,'$.rule.description'),'')), '')             AS rule_description
      FROM p WHERE j IS NOT NULL
    )
    SELECT
      CAST(ts AS varchar) AS ingest_time, cve_id,
      GREATEST(COALESCE(cvss3,0), COALESCE(cvss2,0))    AS cvss_score,
      CASE WHEN COALESCE(cvss3,0) >= COALESCE(cvss2,0) AND cvss3 IS NOT NULL THEN 'CVSSv3'
           WHEN cvss2 IS NOT NULL THEN 'CVSSv2' ELSE 'n/d' END AS cvss_source,
      COALESCE(vuln_severity,'') AS severity, host_name, host_ip,
      COALESCE(rule_description,'') AS rule_description
    FROM v
    WHERE cve_id IS NOT NULL
      AND (GREATEST(COALESCE(cvss3,0), COALESCE(cvss2,0)) >= 9.0 OR vuln_severity = 'critical')
    ORDER BY ts DESC
    LIMIT ${limit}
  `.trim();
    },

    /**
     * Top IPs origen externas con más alertas Wazuh (data.srcip via JSON).
     * @param {number} limit
     */
    topSrcIps24h(limit) {
      return `
WITH ${RAW_24H},
parsed AS (
  SELECT
    trim(COALESCE(json_extract_scalar(j, '$.data.srcip'), '')) AS src_ip,
    COALESCE(TRY_CAST(json_extract_scalar(j, '$.rule.level') AS integer), 0) AS lvl,
    COALESCE(json_extract_scalar(j, '$.rule.id'), '') AS rule_id
  FROM raw_24h
  WHERE j IS NOT NULL
)
SELECT
  src_ip,
  COUNT(*)                              AS hits,
  MAX(lvl)                              AS max_level,
  MAX_BY(rule_id, lvl)                  AS top_rule_id
FROM parsed
WHERE src_ip <> ''
  AND src_ip NOT IN ('127.0.0.1', '::1')
  AND src_ip NOT LIKE '10.%'
  AND src_ip NOT LIKE '192.168.%'
  AND src_ip NOT LIKE '172.16.%'
  AND src_ip NOT LIKE '172.17.%'
  AND src_ip NOT LIKE '172.18.%'
  AND src_ip NOT LIKE '172.19.%'
  AND src_ip NOT LIKE '172.2_.%'
  AND src_ip NOT LIKE '172.30.%'
  AND src_ip NOT LIKE '172.31.%'
GROUP BY src_ip
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Top tácticas MITRE ATT&CK detectadas por Wazuh (rule.mitre.tactic via JSON).
     * @param {number} limit
     */
    topMitreTactics24h(limit) {
      // `cast(json_array AS varchar)` falla silenciosamente en este Trino
      // (devuelve NULL → INVALID_CAST_ARGUMENT). La forma correcta es
      // `CAST(json_value AS array<varchar>)` directo. Además, defensivo contra
      // pipelines que doble-encoden elementos como JSON-string (mismo patrón
      // que wazuh-fluent topMitreTactics24h).
      return `
WITH raw AS (
  SELECT TRY(CAST(
           json_extract(json_parse(CAST(message AS varchar)), '$.rule.mitre.tactic')
           AS array<varchar>
         )) AS tactics_arr
  FROM ${t}
  WHERE ${WAZUH_PART_FILTER}
    AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
),
exploded AS (
  SELECT u.elem AS raw_elem
  FROM raw
  CROSS JOIN UNNEST(tactics_arr) AS u(elem)
  WHERE tactics_arr IS NOT NULL
),
flat AS (
  SELECT COALESCE(
           TRY(CAST(json_parse(raw_elem) AS array<varchar>)),
           ARRAY[raw_elem]
         ) AS tactics
  FROM exploded
)
SELECT trim(tactic) AS tactic,
       COUNT(*)     AS c
FROM flat
CROSS JOIN UNNEST(tactics) AS t(tactic)
WHERE tactic IS NOT NULL
  AND trim(tactic) <> ''
GROUP BY 1
ORDER BY c DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * @param {number} limit
     * @param {number} minutes
     */
    recentLines(limit, minutes) {
      const lim = Number(limit);
      const lookback = Math.max(50, lim * 5);
      // FIX: este query no tenía WAZUH_PART_FILTER → escaneaba toda la tabla.
      // TopN-early: tomamos las ${lim*5} filas más recientes por ev_ingest
      // ANTES de hacer 4× json_extract por fila. El factor ×5 cubre que el
      // ORDER BY final es por la misma columna (sólo formatea, no reordena).
      return `
    WITH base AS (
      SELECT
        CAST(ingest_time AS varchar) AS ingest_time,
        ${INGEST_TS} AS ev_ingest,
        message
      FROM ${t}
      WHERE ${WAZUH_PART_FILTER}
        AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${minutes}' MINUTE
      ORDER BY ${INGEST_TS} DESC
      LIMIT ${lookback}
    ),
    parsed AS (
      SELECT
        ingest_time,
        ev_ingest,
        TRY(json_parse(CAST(message AS varchar))) AS j
      FROM base
    )
    SELECT
      ingest_time,
      json_extract_scalar(j, '$.rule.description') AS rule_desc,
      json_extract_scalar(j, '$.rule.level')       AS level,
      json_extract_scalar(j, '$.agent.name')       AS agent
    FROM parsed
    WHERE j IS NOT NULL
    ORDER BY ev_ingest DESC
    LIMIT ${lim}
  `.trim();
    },
  };
}
