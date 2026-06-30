/**
 * Consultas de caza sobre tabla Hive `wazuh_alerts` (JSON en `message`; Manager → :9014).
 * Misma expresión de tiempo de ingesta que syslog/wazuh vía ingest-time.mjs.
 */
import { syslogIngestTimestampExpr } from "./ingest-time.mjs";

const INGEST_TS = syslogIngestTimestampExpr("ingest_time");

/** Partición calendario “hoy” para poda en MinIO/S3. */
const PARTITION_TODAY = `year = CAST(year(current_date) AS varchar)
  AND month = lpad(CAST(month(current_date) AS varchar), 2, '0')
  AND day = lpad(CAST(day(current_date) AS varchar), 2, '0')`;

const PARTITION_MONTH = `year = CAST(year(current_date) AS varchar)
  AND month = lpad(CAST(month(current_date) AS varchar), 2, '0')`;

/**
 * Poda por RANGO de días naturales (columnas de partición DESNUDAS vs constante →
 * Trino las traduce a TupleDomain y elimina particiones en el coordinador). Úsese en
 * lugar de PARTITION_MONTH cuando la consulta ya filtra por una ventana temporal corta:
 * PARTITION_MONTH escanea las ~293 particiones del mes haciendo json_parse por fila
 * aunque sólo se pidan unos días (causa de saturación del nodo único, 2026-06-24).
 * `windowDays` = amplitud de la ventana; se añade +1 día de margen por cruce de medianoche.
 * Mismo patrón validado que el extractor 03. Limitación heredada (igual que PARTITION_MONTH):
 * no cubre el mes anterior en los primeros días del mes.
 * @param {number} windowDays
 */
const partitionLastDays = (windowDays) => {
  const back = Math.max(1, Math.ceil(windowDays) + 1);
  return `year = CAST(year(current_date) AS varchar)
  AND month = lpad(CAST(month(current_date) AS varchar), 2, '0')
  AND day >= lpad(CAST(GREATEST(day(current_date) - ${back}, 1) AS varchar), 2, '0')`;
};

/**
 * @param {string} tableQualified p.ej. minio.hunting.wazuh_alerts
 */
export function createWazuhAlertsHuntSql(tableQualified) {
  const tbl = tableQualified;
  return {
    severityBuckets24h() {
      return `
WITH p AS (
  SELECT
    COALESCE(
      TRY_CAST(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.level') AS integer),
      0
    ) AS lvl
  FROM ${tbl}
  WHERE ${INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
)
SELECT
  CASE
    WHEN lvl >= 12 THEN 'critical'
    WHEN lvl >= 8  THEN 'high'
    WHEN lvl >= 4  THEN 'medium'
    ELSE 'low'
  END AS bucket,
  COUNT(*) AS c
FROM p
GROUP BY 1
ORDER BY CASE bucket WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
`.trim();
    },

    /** @param {number} limit */
    topRules24h(limit) {
      return `
SELECT
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') AS rule_id,
  MAX(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description')) AS description,
  COUNT(*) AS hits
FROM ${tbl}
WHERE ${partitionLastDays(1)}
  AND ${INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
GROUP BY 1
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** @param {number} limit */
    topSrcIpCurrentMonth(limit) {
      return `
SELECT
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') AS srcip,
  COUNT(*) AS c
FROM ${tbl}
WHERE ${PARTITION_MONTH}
  AND json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') IS NOT NULL
GROUP BY 1
ORDER BY c DESC
LIMIT ${limit}
`.trim();
    },

    /** @param {number} limit */
    criticalSample(limit) {
      return `
SELECT
  CAST(ingest_time AS varchar) AS ingest_time,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') AS rule_id,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name') AS agent,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') AS srcip,
  substr(CAST(message AS varchar), 1, 280) AS snippet
FROM ${tbl}
-- 2026-06-24: muestra de críticos recientes (ORDER BY ts DESC LIMIT). Acotada a los
-- últimos ~7 días en vez del mes entero para no escanear ~293 particiones por una
-- muestra de N filas. Cambio de semántica: si en 7 días hay < LIMIT críticos, devuelve
-- menos que antes (antes barría el mes); aceptable para un panel de "críticos recientes".
WHERE ${partitionLastDays(7)}
  AND COALESCE(
    TRY_CAST(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.level') AS integer),
    0
  ) >= 12
ORDER BY ${INGEST_TS} DESC
LIMIT ${limit}
`.trim();
    },

    /** @param {number} limit */
    sshInvalidUser5710(limit) {
      return `
SELECT
  CAST(ingest_time AS varchar) AS ingest_time,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') AS srcip,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcuser') AS tried_user,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name') AS agent
FROM ${tbl}
-- 2026-06-24: muestra reciente de intentos SSH 5710 (ORDER BY ts DESC LIMIT). Acotada a
-- ~7 días en vez del mes (evita full-scan del mes). Devuelve menos sólo si en 7 días hay
-- < LIMIT filas. Para conteos por mes usar sshInvalidUsersAggregated con su ventana.
WHERE ${partitionLastDays(7)}
  AND json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') = '5710'
ORDER BY ${INGEST_TS} DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Agrupado por IP+usuario SSH inválido — ventana configurable en horas.
     *
     * Rutas JSON de srcip (Wazuh varía según versión y regla):
     *   $.data.srcip          → reglas clásicas 5710/5711
     *   $.data.src_ip         → algunas versiones Wazuh 4.x
     *   $.predecoder.srcip    → decodificador predecl.
     *   $.agent.ip            → último fallback (IP del agente, no del atacante)
     *
     * Bug corregido: el WHERE srcip IS NOT NULL previo eliminaba filas donde la IP
     * no estaba en $.data.srcip aunque sí en otras rutas. Ahora se incluyen todas
     * las reglas SSH con poda por rango de días (partitionLastDays) para evitar
     * full-scan del mes (la ventana `hours` ya acota el resultado).
     */
    sshInvalidUsersAggregated(hours = 24, limit = 200) {
      return `
WITH ssh_raw AS (
  SELECT
    COALESCE(
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.src_ip'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.predecoder.srcip'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.ip')
    )                                                                              AS srcip,
    COALESCE(
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcuser'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.dstuser'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.user'),
      'unknown'
    )                                                                              AS invalid_user,
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name')     AS agent_name,
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.id')       AS agent_id,
    COALESCE(
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcpassword'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.dstpassword'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.a1')
    )                                                                              AS tried_password,
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')        AS rule_id,
    ${INGEST_TS}                                                                   AS ts
  FROM ${tbl}
  WHERE ${partitionLastDays(hours / 24)}
    AND ${INGEST_TS} >= current_timestamp - INTERVAL '${hours}' HOUR
    AND json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')
        IN ('5710','5711','5712','5716','5718','5720','5721','5723','5758')
)
SELECT
  COALESCE(srcip, '(unknown)')      AS srcip,
  invalid_user,
  agent_name,
  agent_id,
  COUNT(*)                          AS attempts_count,
  CAST(MIN(ts) AS varchar)          AS first_seen,
  CAST(MAX(ts) AS varchar)          AS last_seen,
  COALESCE(
    NULLIF(
      array_join(
        array_distinct(FILTER(array_agg(tried_password), p -> p IS NOT NULL AND p != '')),
        ', '
      ),
      ''
    ),
    '—'
  )                                 AS tried_passwords
FROM ssh_raw
GROUP BY
  COALESCE(srcip, '(unknown)'),
  invalid_user,
  agent_name,
  agent_id
ORDER BY attempts_count DESC
LIMIT ${limit}
`.trim();
    },

    /* ── Diagnóstico: estado de la tabla wazuh_alerts ─────────────────────── */

    /** Verifica que la tabla existe y devuelve una fila raw para inspeccionar formato. */
    diagAnyRow() {
      return `
SELECT
  CAST(ingest_time AS varchar)                                          AS ingest_time_raw,
  ${INGEST_TS}                                                          AS ingest_ts_parsed,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') AS rule_id,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.level') AS rule_level,
  substr(CAST(message AS varchar), 1, 120)                             AS message_snippet
FROM ${tbl}
LIMIT 1
`.trim();
    },

    /** Cuenta filas en los últimos N días (poda por rango de días, no mes entero). */
    diagCountRecent(days = 3) {
      return `
SELECT
  COUNT(*)                                                              AS total_rows,
  COUNT(DISTINCT json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id'))
                                                                        AS distinct_rule_ids,
  MIN(${INGEST_TS})                                                     AS oldest_ts,
  MAX(${INGEST_TS})                                                     AS newest_ts
FROM ${tbl}
WHERE ${partitionLastDays(days)}
  AND ${INGEST_TS} >= current_timestamp - INTERVAL '${days * 24}' HOUR
`.trim();
    },

    /** Top reglas SSH vistas sin filtro de tiempo ni de srcip — detecta si hay datos SSH. */
    diagSshRulesRaw(limit = 20) {
      return `
SELECT
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')           AS rule_id,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description')  AS rule_desc,
  COUNT(*)                                                                           AS hits,
  COUNT(CASE WHEN json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') IS NOT NULL THEN 1 END)
                                                                                    AS with_srcip,
  COUNT(CASE WHEN json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcuser') IS NOT NULL THEN 1 END)
                                                                                    AS with_srcuser
FROM ${tbl}
WHERE ${PARTITION_MONTH}
  AND json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')
      IN ('5710','5711','5712','5716','5718','5720','5721','5723','5758')
GROUP BY 1, 2
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** Top 15 rule_id vistos hoy — para detectar qué reglas SSH llegan con nombres distintos. */
    diagTopRuleIdsToday(limit = 15) {
      return `
SELECT
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')           AS rule_id,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description')  AS description,
  COUNT(*)                                                                           AS hits
FROM ${tbl}
WHERE ${PARTITION_TODAY}
  AND (
    lower(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description'))
      LIKE '%ssh%'
    OR lower(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description'))
      LIKE '%brute%'
    OR lower(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description'))
      LIKE '%invalid user%'
    OR lower(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description'))
      LIKE '%authentication fail%'
    OR lower(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description'))
      LIKE '%login attempt%'
  )
GROUP BY 1, 2
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    alertsByHourToday() {
      return `
SELECT hour, COUNT(*) AS c
FROM ${tbl}
WHERE ${PARTITION_TODAY}
GROUP BY hour
ORDER BY hour
`.trim();
    },

    /** @param {number} limit */
    topAgents24h(limit) {
      return `
SELECT
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name'),
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.predecoder.hostname'),
    'unknown'
  ) AS agent,
  COUNT(*) AS c
FROM ${tbl}
WHERE ${partitionLastDays(1)}
  AND ${INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
GROUP BY 1
ORDER BY c DESC
LIMIT ${limit}
`.trim();
    },

    /** Agentes Wazuh activos en las últimas 24 h con nombre, ID, IP y conteo de alertas. */
    activeAgents24h(limit) {
      return `
SELECT
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name'),
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.predecoder.hostname'),
    'unknown'
  )                                                                                   AS agent_name,
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.id'),
    '—'
  )                                                                                   AS agent_id,
  COALESCE(
    NULLIF(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.ip'), '127.0.0.1'),
    NULLIF(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.ip'), ''),
    NULL
  )                                                                                   AS agent_ip,
  COUNT(*)                                                                            AS hits
FROM ${tbl}
WHERE ${partitionLastDays(1)}
  AND ${INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
  AND COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name'),
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.predecoder.hostname')
  ) IS NOT NULL
GROUP BY 1, 2, 3
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** @param {number} limit */
    mitreCredentialHunt(limit) {
      return `
SELECT
  CAST(ingest_time AS varchar) AS ingest_time,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') AS rule_id,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name') AS agent
FROM ${tbl}
-- 2026-06-24: hunt de credenciales reciente (ORDER BY ts DESC LIMIT). Acotado a ~7 días
-- en vez del mes entero (evita full-scan json_parse del mes). Misma semántica que
-- criticalSample: devuelve menos filas sólo si en 7 días hay < LIMIT coincidencias.
WHERE ${partitionLastDays(7)}
  AND (
    CAST(message AS varchar) LIKE '%T1110%'
    OR CAST(message AS varchar) LIKE '%Credential Access%'
  )
ORDER BY ${INGEST_TS} DESC
LIMIT ${limit}
`.trim();
    },

    /** @param {number} limit */
    pamDstUser5501(limit) {
      return `
SELECT
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.dstuser') AS dstuser,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.uid') AS uid,
  COUNT(*) AS c
FROM ${tbl}
WHERE ${PARTITION_MONTH}
  AND json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') = '5501'
GROUP BY 1, 2
ORDER BY c DESC
LIMIT ${limit}
`.trim();
    },

    /** Comandos y procesos sospechosos (auditd) — reglas 80700-80799 */
    auditdCommands(hours = 24, limit = 100) {
      return `
SELECT
  CAST(${INGEST_TS} AS varchar)                                                              AS ts,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name')                  AS agent_name,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')                     AS rule_id,
  json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description')            AS rule_desc,
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.command'),
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.command'),
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.execve.a0'),
    '—'
  )                                                                                           AS command,
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.exe'),
    '—'
  )                                                                                           AS exe,
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.auid'),
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.uid'),
    '—'
  )                                                                                           AS uid,
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.euid'),
    '—'
  )                                                                                           AS euid,
  COALESCE(
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.mitre.technique'),
    '—'
  )                                                                                           AS mitre_technique
FROM ${tbl}
WHERE ${partitionLastDays(hours / 24)}
  AND ${INGEST_TS} >= current_timestamp - INTERVAL '${hours}' HOUR
  AND (
    TRY_CAST(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') AS integer)
      BETWEEN 80700 AND 80799
    OR CAST(message AS varchar) LIKE '%"auditd"%'
  )
ORDER BY ${INGEST_TS} DESC
LIMIT ${limit}
`.trim();
    },

    /** Comandos auditd agrupados por (command, exe, agent_name) — ventana configurable en horas */
    auditdCommandsAggregated(hours = 24, limit = 100) {
      return `
WITH auditd_raw AS (
  SELECT
    COALESCE(
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.command'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.command'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.execve.a0'),
      '—'
    )                                                                              AS command,
    COALESCE(
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.exe'),
      '—'
    )                                                                              AS exe,
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name')     AS agent_name,
    COALESCE(
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.auid'),
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.uid'),
      '—'
    )                                                                              AS uid,
    COALESCE(
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.audit.euid'),
      '—'
    )                                                                              AS euid,
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')        AS rule_id,
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.mitre.technique') AS mitre_technique,
    ${INGEST_TS}                                                                   AS ts
  FROM ${tbl}
  WHERE ${partitionLastDays(hours / 24)}
    AND ${INGEST_TS} >= current_timestamp - INTERVAL '${hours}' HOUR
    AND (
      TRY_CAST(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id') AS integer)
        BETWEEN 80700 AND 80799
      OR CAST(message AS varchar) LIKE '%"auditd"%'
    )
)
SELECT
  command,
  exe,
  agent_name,
  COUNT(*)                                                                                     AS execution_count,
  CAST(MIN(ts) AS varchar)                                                                     AS first_seen,
  CAST(MAX(ts) AS varchar)                                                                     AS last_seen,
  array_join(array_distinct(FILTER(array_agg(uid),  u -> u IS NOT NULL AND u != '—')), ', ')  AS uid_list,
  array_join(array_distinct(FILTER(array_agg(euid), e -> e IS NOT NULL AND e != '—')), ', ')  AS euid_list,
  MAX(rule_id)                                                                                 AS top_rule_id,
  COALESCE(MAX(mitre_technique), '—')                                                          AS top_mitre
FROM auditd_raw
WHERE command != '—'
GROUP BY command, exe, agent_name
ORDER BY execution_count DESC
LIMIT ${limit}
`.trim();
    },

    /** @param {number} limit */
    newSrcIpLast6h(limit) {
      return `
WITH first_seen AS (
  SELECT
    json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') AS srcip,
    MIN(${INGEST_TS}) AS first_t
  FROM ${tbl}
  WHERE ${PARTITION_TODAY}
    AND json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') IS NOT NULL
  GROUP BY 1
)
SELECT
  srcip,
  CAST(first_t AS varchar) AS first_seen
FROM first_seen
WHERE first_t >= current_timestamp - INTERVAL '6' HOUR
ORDER BY first_t DESC
LIMIT ${limit}
`.trim();
    },
  };
}
