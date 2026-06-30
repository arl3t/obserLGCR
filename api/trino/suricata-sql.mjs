/**
 * Consultas SQL para eventos Suricata IDS/IPS.
 * Fuente: minio.hunting.syslog
 *
 * Vector almacena el evento Suricata completo como JSON en la columna `message`.
 * La tabla Hive no tiene columnas estructuradas (src_ip, suricata_signature…);
 * todos los campos se extraen con json_extract_scalar desde $.alert.* y raíz.
 *
 * Filtro de eventos Suricata: $.event_type = 'alert'
 *
 * Patrón: cada query empieza con un CTE `raw` que extrae el string JSON del
 * message una sola vez por fila (columna `j`), y luego `json_extract_scalar(j, …)`
 * reutiliza ese string. Evita que Trino reevalúe substr/strpos N veces por fila
 * (una por cada campo extraído).
 */
import { stringStyleWindow } from "./time-window.mjs";

export function createSuricataSql(catalog, schema) {
  const s = `${catalog}.${schema}.syslog`;

  const { INGEST_TS, PART_2D, W24 } = stringStyleWindow();

  // Vector envuelve el JSON de Suricata en un prefix RFC5424 (p.ej.
  //   `<174>1 2026-04-20T00:59:48-03:00 opn01.dc.lgcserver.net suricata 97898 - ... {"timestamp":"...",...}`).
  // json_extract_scalar NO tolera el prefix: falla silenciosamente y devuelve NULL.
  // Extraemos la parte JSON con strpos+substr; si no hay `{` devolvemos NULL
  // (evita que substr(x, 0) rompa en Trino o devuelva el string completo).
  const M = `
    CASE WHEN strpos(cast(message AS varchar), '{') > 0
         THEN substr(cast(message AS varchar), strpos(cast(message AS varchar), '{'))
         ELSE NULL
    END`;

  // CTE base: extrae `j` (string JSON) y `ev_ingest` una sola vez por fila.
  //
  // CRÍTICO: filtramos por la columna nativa `log_family LIKE 'suricata_%'`
  // ANTES de extraer JSON. La tabla `syslog` mezcla varias fuentes
  // (filterlog/wazuh/fortigate/pmg/suricata/etc) — sin push-down filter,
  // Trino debía evaluar `event_type='alert'` (json_extract) sobre 2-3
  // millones de filas en 24h sólo para descartar las no-Suricata. Con
  // filtro nativo, el dataset baja a ~300k filas Suricata directo, sin
  // tocar JSON. Ese cambio convierte el cold-start de ~50s a unidades.
  const RAW = `raw AS (
    SELECT
      ${M} AS j,
      ${INGEST_TS} AS ev_ingest
    FROM ${s}
    WHERE ${PART_2D}
      AND ${W24}
      AND log_family LIKE 'suricata_%'
  )`;

  // Filtro vacío: el push-down `log_family LIKE 'suricata_%'` ya restringe
  // a alertas Suricata sin necesidad de evaluar `event_type='alert'` en
  // cada fila. Mantenemos `FAM` como placeholder por si en el futuro
  // alguna query necesita refinar (p.ej. excluir un sub-evento).
  const FAM = `TRUE`;

  // Shortcuts de extracción sobre la columna `j` (ya extraída en el CTE raw).
  const J_SRC_IP   = `TRY(json_extract_scalar(j, '$.src_ip'))`;
  const J_DEST_IP  = `TRY(json_extract_scalar(j, '$.dest_ip'))`;
  const J_DEST_PORT= `TRY(CAST(json_extract_scalar(j, '$.dest_port') AS INTEGER))`;
  const J_PROTO    = `TRY(json_extract_scalar(j, '$.proto'))`;
  const J_SIG      = `TRY(json_extract_scalar(j, '$.alert.signature'))`;
  const J_CAT      = `TRY(json_extract_scalar(j, '$.alert.category'))`;
  const J_SEV      = `TRY(CAST(json_extract_scalar(j, '$.alert.severity') AS INTEGER))`;
  const J_ACTION   = `TRY(json_extract_scalar(j, '$.alert.action'))`;
  // Timestamp del evento Suricata (más preciso que ingest_time).
  const J_TS       = `TRY(from_iso8601_timestamp(json_extract_scalar(j, '$.timestamp')))`;

  return {
    /** KPIs: total alertas, IPs únicas, firmas únicas, puertos atacados. */
    kpis24h() {
      return `
WITH ${RAW},
parsed AS (
  SELECT
    ${J_SRC_IP}    AS src_ip,
    ${J_SIG}       AS signature,
    ${J_DEST_PORT} AS dest_port
  FROM raw
  WHERE ${FAM}
)
SELECT
  COUNT(*)                                AS total_alerts,
  COUNT(DISTINCT src_ip)                  AS unique_src_ips,
  COUNT(DISTINCT signature)               AS unique_signatures,
  COUNT(DISTINCT CAST(dest_port AS VARCHAR)) AS unique_ports_targeted
FROM parsed
`.trim();
    },

    /** Top firmas Suricata por número de hits. */
    topSignatures24h(limit) {
      return `
WITH ${RAW},
parsed AS (
  SELECT
    COALESCE(${J_SIG}, '(sin firma)') AS signature,
    COALESCE(${J_CAT}, '(sin categ)') AS category,
    COALESCE(${J_SEV}, 0)             AS severity,
    ${J_SRC_IP}                        AS src_ip
  FROM raw
  WHERE ${FAM}
)
SELECT
  signature,
  category,
  severity,
  COUNT(*)                   AS hits,
  COUNT(DISTINCT src_ip)     AS unique_attackers
FROM parsed
GROUP BY signature, category, severity
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** Top IPs atacantes por número de alertas generadas. */
    topAttackers24h(limit) {
      return `
WITH ${RAW},
parsed AS (
  SELECT
    ${J_SRC_IP}    AS src_ip,
    ${J_SIG}       AS signature,
    ${J_DEST_PORT} AS dest_port
  FROM raw
)
SELECT
  src_ip,
  COUNT(*)                                    AS hits,
  COUNT(DISTINCT signature)                   AS unique_sigs,
  COUNT(DISTINCT CAST(dest_port AS VARCHAR))  AS unique_ports
FROM parsed
WHERE src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** Puertos de destino más atacados. */
    topTargetedPorts24h(limit) {
      return `
WITH ${RAW},
parsed AS (
  SELECT
    ${J_DEST_PORT} AS dest_port,
    ${J_PROTO}     AS proto,
    ${J_SRC_IP}    AS src_ip
  FROM raw
)
SELECT
  CAST(COALESCE(CAST(dest_port AS VARCHAR), '?') AS VARCHAR) AS dest_port,
  COALESCE(proto, '?')                                       AS proto,
  COUNT(*)                                                   AS hits,
  COUNT(DISTINCT src_ip)                                     AS unique_attackers
FROM parsed
WHERE dest_port IS NOT NULL
GROUP BY dest_port, proto
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** Alertas agrupadas por hora (timeline 24 h). */
    alertsByHour24h() {
      return `
WITH ${RAW},
parsed AS (
  SELECT
    COALESCE(${J_TS}, ev_ingest) AS ts,
    ${J_SRC_IP}                  AS src_ip
  FROM raw
  WHERE ${FAM}
)
SELECT
  date_format(date_trunc('hour', ts), '%H:00') AS hour,
  COUNT(*)                                     AS alerts,
  COUNT(DISTINCT src_ip)                       AS unique_ips
FROM parsed
WHERE ts IS NOT NULL
GROUP BY date_trunc('hour', ts)
ORDER BY date_trunc('hour', ts) ASC
`.trim();
    },

    /** Distribución de severidad Suricata (1=crítica … 4=informativa). */
    severityDistribution24h() {
      return `
WITH ${RAW},
parsed AS (
  SELECT
    COALESCE(${J_SEV}, 0) AS severity
  FROM raw
  WHERE ${FAM}
)
SELECT
  severity,
  COUNT(*) AS hits
FROM parsed
GROUP BY severity
ORDER BY severity ASC
`.trim();
    },

    /** Distribución por categoría de alerta Suricata (top N categorías). */
    topCategories24h(limit) {
      return `
WITH ${RAW},
parsed AS (
  SELECT
    COALESCE(${J_CAT}, '(sin categoría)') AS category,
    COALESCE(${J_SEV}, 0)                  AS severity,
    ${J_SRC_IP}                             AS src_ip
  FROM raw
  WHERE ${FAM}
)
SELECT
  category,
  COUNT(*)                  AS hits,
  COUNT(DISTINCT src_ip)    AS unique_attackers,
  MIN(severity)             AS min_severity,
  MAX(severity)             AS max_severity
FROM parsed
GROUP BY category
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** Muestra de alertas recientes.
     *
     *  Optimización TopN-early:
     *    1. CTE `raw` (compartida) entrega 24h de filas con `j` y `ev_ingest`.
     *    2. CTE `topN` recorta a las {limit*5} filas más recientes por
     *       `ev_ingest DESC` ANTES de extraer los 9 campos JSON. Suricata
     *       suele generar j_ts ≈ ev_ingest ± segundos; ×5 cubre con margen
     *       cualquier divergencia por buffering del vector.
     *    3. CTE `parsed` extrae los 9 campos sólo sobre el subset acotado.
     *    4. Refinamos el orden por `ts` (= j_ts ?? ev_ingest).
     *
     *  Antes este patrón ordenaba 300k+ filas tras extraer JSON × 9 →
     *  ~50s. TopN-early baja la extracción a O(limit*5) filas. */
    recentAlerts(limit) {
      const lim = Number(limit);
      const lookback = Math.max(50, lim * 5);
      return `
WITH ${RAW},
topN AS (
  SELECT j, ev_ingest
  FROM raw
  ORDER BY ev_ingest DESC
  LIMIT ${lookback}
),
parsed AS (
  SELECT
    COALESCE(${J_TS}, ev_ingest)         AS ts,
    COALESCE(${J_SRC_IP},   '?')         AS src_ip,
    COALESCE(${J_DEST_IP},  '?')         AS dest_ip,
    COALESCE(${J_DEST_PORT}, -1)         AS dest_port,
    COALESCE(${J_PROTO},    '?')         AS proto,
    COALESCE(${J_SIG},      '(sin firma)') AS signature,
    COALESCE(${J_CAT},      '(sin categ)') AS category,
    COALESCE(${J_SEV},      0)           AS severity,
    COALESCE(${J_ACTION},   '?')         AS action
  FROM topN
)
SELECT ts, src_ip, dest_ip, dest_port, proto, signature, category, severity, action
FROM parsed
ORDER BY ts DESC
LIMIT ${lim}
`.trim();
    },
  };
}
