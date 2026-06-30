/**
 * wazuh-fluent-sql.mjs — Consultas sobre minio.hunting.wazuh_fluent
 *
 * La tabla wazuh_fluent es el destino del pipeline:
 *   Wazuh Manager → Fluent Bit → Vector :24224 → S3 wazuh_fluent/
 *
 * Particiones: year / month / day / hour  (igual que wazuh_alerts)
 * Columnas top-level extraídas por VRL:
 *   rule_level, rule_id, agent_name, agent_ip, src_ip,
 *   ingest_source ('alerts.json' | 'archives.json'),
 *   wazuh_manager_host / sensor_host (VRL copia ambos; datos anteriores solo tienen wazuh_manager_host)
 *
 * Solo consultar ingest_source = 'alerts.json' para el pipeline de detección.
 * 'archives.json' va a la tabla wazuh_fluent_archives (forensia).
 */

import { integerStyleWindow } from "./time-window.mjs";

const { PART_TODAY, WINDOW_24H_LEX: WINDOW_24H } = integerStyleWindow();

/**
 * @param {string} tableQualified — p.ej. "minio.hunting.wazuh_fluent"
 */
export function createWazuhFluentSql(tableQualified) {
  const t = tableQualified;

  return {
    /**
     * KPIs principales: alerts, archives, críticos (level≥12), agentes activos.
     * Una sola query con COUNTs condicionales — evita N round-trips a Trino.
     */
    kpis24h() {
      return `
SELECT
  COUNT(CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
             THEN 1 END)                                                   AS alerts,
  COUNT(CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'archives.json'
             THEN 1 END)                                                   AS archives,
  COUNT(CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
              AND COALESCE(TRY_CAST(rule_level AS integer), 0) >= 12
             THEN 1 END)                                                   AS critical,
  COUNT(DISTINCT
    CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
          AND cast(coalesce(agent_name,'') AS varchar) <> ''
         THEN cast(coalesce(agent_name,'') AS varchar)
    END
  )                                                                        AS active_agents,
  COUNT(DISTINCT
    CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
          AND cast(coalesce(sensor_host, wazuh_manager_host,'') AS varchar) <> ''
         THEN cast(coalesce(sensor_host, wazuh_manager_host,'') AS varchar)
    END
  )                                                                        AS manager_nodes
FROM ${t}
WHERE ${WINDOW_24H}
      `.trim();
    },

    /**
     * Distribución por severidad (alerts.json únicamente).
     * Salida: [{ severity: 'critical'|'high'|'medium'|'low', c: number }]
     */
    severityBuckets24h() {
      return `
SELECT
  CASE
    WHEN COALESCE(TRY_CAST(rule_level AS integer), 0) >= 15 THEN 'critical'
    WHEN COALESCE(TRY_CAST(rule_level AS integer), 0) >= 12 THEN 'high'
    WHEN COALESCE(TRY_CAST(rule_level AS integer), 0) >= 9  THEN 'medium'
    ELSE 'low'
  END                                                                AS severity,
  COUNT(*)                                                           AS c
FROM ${t}
WHERE ${WINDOW_24H}
  AND cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
GROUP BY 1
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high'     THEN 2
    WHEN 'medium'   THEN 3
    ELSE 4
  END
      `.trim();
    },

    /**
     * Top reglas por frecuencia (alerts.json).
     * Salida: [{ rule_id, max_level, c }]
     */
    topRules24h(limit = 15) {
      const n = Math.min(Math.max(1, +limit), 200);
      return `
SELECT
  cast(coalesce(rule_id, 'unknown') AS varchar)                     AS rule_id,
  MAX(COALESCE(TRY_CAST(rule_level AS integer), 0))                AS max_level,
  COUNT(*)                                                           AS c
FROM ${t}
WHERE ${WINDOW_24H}
  AND cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
  AND cast(coalesce(rule_id,'') AS varchar) <> ''
GROUP BY 1
ORDER BY c DESC
LIMIT ${n}
      `.trim();
    },

    /**
     * Top agentes por número de alertas (alerts.json).
     * Salida: [{ agent_name, agent_ip, c, max_level }]
     */
    topAgents24h(limit = 12) {
      const n = Math.min(Math.max(1, +limit), 100);
      return `
SELECT
  cast(coalesce(agent_name, 'unknown') AS varchar)                  AS agent_name,
  cast(coalesce(agent_ip,   '') AS varchar)                         AS agent_ip,
  cast(coalesce(sensor_host, wazuh_manager_host,'') AS varchar)                         AS manager_host,
  COUNT(*)                                                           AS c,
  MAX(COALESCE(TRY_CAST(rule_level AS integer), 0))                AS max_level
FROM ${t}
WHERE ${WINDOW_24H}
  AND cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
GROUP BY agent_name, agent_ip, sensor_host, wazuh_manager_host
ORDER BY c DESC
LIMIT ${n}
      `.trim();
    },

    /**
     * Alertas vs archivos por hora (solo hoy).
     * Salida: [{ hour, alerts, archives }] ordenado por hora
     */
    alertsByHourToday() {
      return `
SELECT
  lpad(cast(CAST(hour AS integer) AS varchar), 2, '0') AS hr,
  COUNT(CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
             THEN 1 END)                               AS alerts,
  COUNT(CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'archives.json'
             THEN 1 END)                               AS archives
FROM ${t}
WHERE ${PART_TODAY}
GROUP BY hour
ORDER BY CAST(hour AS integer)
      `.trim();
    },

    /**
     * Nodos Wazuh Manager que reportan (sensor_host = manager_host).
     * Salida: [{ manager_host, alerts, archives, agents }]
     */
    managerNodes24h() {
      return `
SELECT
  cast(coalesce(sensor_host, wazuh_manager_host,'unknown') AS varchar) AS manager_host,
  COUNT(CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
             THEN 1 END)                                            AS alerts,
  COUNT(CASE WHEN cast(coalesce(ingest_source,'') AS varchar) = 'archives.json'
             THEN 1 END)                                            AS archives,
  COUNT(DISTINCT
    CASE WHEN cast(coalesce(agent_name,'') AS varchar) <> ''
         THEN cast(coalesce(agent_name,'') AS varchar) END
  )                                                                 AS agents
FROM ${t}
WHERE ${WINDOW_24H}
GROUP BY sensor_host, wazuh_manager_host
ORDER BY alerts DESC
      `.trim();
    },

    /**
     * Distribución de tácticas MITRE ATT&CK (campo mitre_tactic ARRAY top-level).
     * Solo alerts.json con tácticas asignadas. Unnest del array para contar por táctica.
     */
    topMitreTactics24h(limit = 10) {
      // mitre_tactic es array<varchar>, pero algunos pipelines de ingesta
      // guardan elementos que son ellos mismos un array JSON-encoded
      // (ej. ["Defense Evasion","Persistence"]). Hay que aplanar los dos casos.
      return `
WITH base AS (
  SELECT mitre_tactic
  FROM ${t}
  WHERE ${WINDOW_24H}
    AND cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
    AND mitre_tactic IS NOT NULL
    AND cardinality(mitre_tactic) > 0
),
exploded AS (
  SELECT raw
  FROM base
  CROSS JOIN UNNEST(mitre_tactic) AS u(raw)
),
flat AS (
  SELECT COALESCE(
           TRY(CAST(json_parse(raw) AS array<varchar>)),
           ARRAY[raw]
         ) AS tactics_arr
  FROM exploded
)
SELECT trim(tactic) AS tactic,
       COUNT(*)     AS c
FROM flat
CROSS JOIN UNNEST(tactics_arr) AS t(tactic)
WHERE tactic IS NOT NULL
  AND trim(tactic) <> ''
GROUP BY 1
ORDER BY c DESC
LIMIT ${limit}
      `.trim();
    },

    /**
     * Top IPs origen externas con mayor número de alertas (src_ip top-level).
     * Excluye loopback y RFC 1918.
     */
    topSrcIps24h(limit = 15) {
      return `
SELECT
  cast(src_ip AS varchar)                                               AS src_ip,
  COUNT(*)                                                              AS hits,
  COUNT(DISTINCT cast(coalesce(agent_name,'') AS varchar))              AS agents_affected,
  MAX(COALESCE(TRY_CAST(rule_level AS integer), 0))                    AS max_level,
  MAX_BY(cast(coalesce(rule_id,'') AS varchar),
         COALESCE(TRY_CAST(rule_level AS integer), 0))                 AS top_rule_id
FROM ${t}
WHERE ${WINDOW_24H}
  AND cast(coalesce(ingest_source,'') AS varchar) = 'alerts.json'
  AND src_ip IS NOT NULL
  AND trim(cast(src_ip AS varchar)) NOT IN ('', '127.0.0.1', '::1')
  AND trim(cast(src_ip AS varchar)) NOT LIKE '10.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '192.168.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '172.16.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '172.17.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '172.18.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '172.19.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '172.2_.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '172.30.%'
  AND trim(cast(src_ip AS varchar)) NOT LIKE '172.31.%'
GROUP BY 1
ORDER BY hits DESC
LIMIT ${limit}
      `.trim();
    },
  };
}
