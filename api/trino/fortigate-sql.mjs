/**
 * Consultas SQL para eventos Fortigate UTM/Firewall.
 * Fuente: minio.hunting.fortigate (tabla Hive JSON, particiones year/month/day/hour)
 *
 * Campos normalizados por Vector VRL (enriched_syslog → fortigate_events sink):
 *   src_ip, dest_ip, dest_port, proto, action, log_family, level, devname, ingest_time
 *   fortigate (JSON map con todos los pares key=value del log original)
 *
 * Acciones relevantes:
 *   bloqueado → action IN ('deny','block','drop','reset-drop','reset-server','reset-client')
 *   permitido → action IN ('accept','passthrough','close')
 */
import { stringStyleWindow } from "./time-window.mjs";

export function createFortigateSql(catalog, schema) {
  const tbl = `${catalog}.${schema}.fortigate`;

  const { INGEST_TS, PART_2D, W24 } = stringStyleWindow();

  // Clasificación de acción en dos categorías.
  const IS_BLOCKED = `lower(cast(coalesce(action,'') AS varchar)) IN ('deny','block','drop','reset-drop','reset-server','reset-client')`;
  const IS_ALLOWED = `lower(cast(coalesce(action,'') AS varchar)) IN ('accept','passthrough','close')`;

  return {
    /** KPIs 24 h: total, bloqueados, permitidos, IPs atacantes, puertos objetivo, dispositivos. */
    kpis24h() {
      return `
SELECT
  COUNT(*)                                                    AS total_events,
  COUNT(*) FILTER (WHERE ${IS_BLOCKED})                      AS blocked,
  COUNT(*) FILTER (WHERE ${IS_ALLOWED})                      AS allowed,
  COUNT(DISTINCT CASE WHEN ${IS_BLOCKED} THEN trim(cast(coalesce(src_ip,'') AS varchar)) END) AS unique_attacker_ips,
  COUNT(DISTINCT CASE WHEN ${IS_BLOCKED} THEN TRY_CAST(dest_port AS integer) END)             AS unique_dest_ports,
  COUNT(DISTINCT trim(cast(coalesce(devname,'') AS varchar))) AS unique_devices
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
`.trim();
    },

    /**
     * Top IPs origen bloqueadas en 24 h.
     *
     * Pre-selecciona las top N IPs con COUNT(*) en un CTE (barato) y luego
     * hace JOIN contra la tabla original para calcular los agregados caros
     * (COUNT DISTINCT, max_by) sobre sólo las N ganadoras. Evita agrupar
     * 50 K+ IPs únicas antes del LIMIT.
     */
    topBlockedIps24h(limit) {
      // Filtro común: IP válida y no privada (RFC1918 + link-local típico).
      const IP_FILTER = `
  trim(cast(coalesce(src_ip,'') AS varchar)) <> ''
  AND trim(cast(coalesce(src_ip,'') AS varchar)) NOT LIKE '10.%'
  AND trim(cast(coalesce(src_ip,'') AS varchar)) NOT LIKE '192.168.%'
  AND NOT REGEXP_LIKE(trim(cast(coalesce(src_ip,'') AS varchar)), '^172\\.(1[6-9]|2[0-9]|3[01])\\.')`;
      return `
WITH top_ips AS (
  SELECT
    trim(cast(coalesce(src_ip,'') AS varchar)) AS src_ip_key,
    COUNT(*)                                   AS hits
  FROM ${tbl}
  WHERE ${PART_2D} AND ${W24}
    AND ${IS_BLOCKED}
    AND ${IP_FILTER}
  GROUP BY trim(cast(coalesce(src_ip,'') AS varchar))
  ORDER BY hits DESC
  LIMIT ${limit}
)
SELECT
  t.src_ip_key                                                           AS src_ip,
  t.hits                                                                  AS hits,
  COUNT(DISTINCT TRY_CAST(f.dest_port AS integer))                       AS ports_targeted,
  MAX(${INGEST_TS})                                                      AS last_seen,
  max_by(lower(trim(cast(coalesce(f.proto,'') AS varchar))), ${INGEST_TS})      AS top_proto,
  max_by(trim(cast(coalesce(f.log_family,'') AS varchar)), ${INGEST_TS})         AS top_type
FROM top_ips t
JOIN ${tbl} f
  ON trim(cast(coalesce(f.src_ip,'') AS varchar)) = t.src_ip_key
WHERE ${PART_2D} AND ${W24}
  AND ${IS_BLOCKED}
GROUP BY t.src_ip_key, t.hits
ORDER BY t.hits DESC
`.trim();
    },

    /** Top puertos destino atacados en 24 h. */
    topDestPorts24h(limit) {
      return `
SELECT
  TRY_CAST(dest_port AS integer)                              AS dest_port,
  cast(coalesce(proto,'') AS varchar)                         AS proto,
  COUNT(*)                                                    AS hits,
  COUNT(DISTINCT trim(cast(coalesce(src_ip,'') AS varchar))) AS unique_src_ips
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
  AND ${IS_BLOCKED}
  AND dest_port IS NOT NULL
GROUP BY 1, 2
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** Distribución de eventos por acción (deny/block/accept/…). */
    byAction24h() {
      return `
SELECT
  lower(trim(cast(coalesce(action,'unknown') AS varchar))) AS action,
  COUNT(*)                                                  AS total
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
GROUP BY 1
ORDER BY total DESC
`.trim();
    },

    /** Distribución por tipo/subtipo Fortigate (log_family). */
    byType24h() {
      return `
SELECT
  trim(cast(coalesce(log_family,'unknown') AS varchar))     AS log_family,
  COUNT(*)                                                   AS total,
  COUNT(*) FILTER (WHERE ${IS_BLOCKED})                     AS blocked
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
GROUP BY 1
ORDER BY total DESC
LIMIT 20
`.trim();
    },

    /** Eventos por hora en las últimas 24 h (bloqueados vs permitidos). */
    eventsByHour24h() {
      return `
SELECT
  date_format(date_trunc('hour', ${INGEST_TS}), '%H:00') AS hour,
  COUNT(*)                                                 AS total,
  COUNT(*) FILTER (WHERE ${IS_BLOCKED})                   AS blocked,
  COUNT(*) FILTER (WHERE ${IS_ALLOWED})                   AS allowed
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
GROUP BY date_trunc('hour', ${INGEST_TS})
ORDER BY date_trunc('hour', ${INGEST_TS})
`.trim();
    },

    /** Distribución de eventos por dispositivo Fortigate (devname). */
    byDevice24h() {
      return `
SELECT
  trim(cast(coalesce(devname,'unknown') AS varchar))        AS device,
  COUNT(*)                                                   AS total,
  COUNT(*) FILTER (WHERE ${IS_BLOCKED})                     AS blocked,
  COUNT(*) FILTER (WHERE ${IS_ALLOWED})                     AS allowed
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
GROUP BY 1
ORDER BY total DESC
LIMIT 20
`.trim();
    },

    /** Top protocolos por volumen en 24 h. */
    byProto24h() {
      return `
SELECT
  lower(trim(cast(coalesce(proto,'unknown') AS varchar)))   AS proto,
  COUNT(*)                                                   AS total,
  COUNT(*) FILTER (WHERE ${IS_BLOCKED})                     AS blocked
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
GROUP BY 1
ORDER BY total DESC
LIMIT 15
`.trim();
    },

    /** Top puertos origen que más veces son bloqueados (src_port). */
    topSrcPorts24h(limit) {
      return `
SELECT
  TRY_CAST(src_port AS integer)                              AS src_port,
  cast(coalesce(proto,'') AS varchar)                         AS proto,
  COUNT(*)                                                    AS hits,
  COUNT(DISTINCT trim(cast(coalesce(src_ip,'') AS varchar))) AS unique_src_ips,
  COUNT(*) FILTER (WHERE ${IS_BLOCKED})                      AS blocked
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
  AND src_port IS NOT NULL
GROUP BY 1, 2
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /** Eventos recientes (raw feed). */
    recentEvents(limit) {
      return `
SELECT
  ${INGEST_TS}                                              AS ts,
  trim(cast(coalesce(src_ip,'')       AS varchar))          AS src_ip,
  trim(cast(coalesce(dest_ip,'')      AS varchar))          AS dest_ip,
  TRY_CAST(dest_port AS integer)                            AS dest_port,
  trim(cast(coalesce(proto,'')        AS varchar))          AS proto,
  lower(trim(cast(coalesce(action,'') AS varchar)))         AS action,
  trim(cast(coalesce(log_family,'')   AS varchar))          AS log_family,
  lower(trim(cast(coalesce(level,'')  AS varchar)))         AS level,
  trim(cast(coalesce(devname,'')      AS varchar))          AS device
FROM ${tbl}
WHERE ${PART_2D} AND ${W24}
ORDER BY ${INGEST_TS} DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Devices FortiGate activos 24h para el autodescubrimiento de sensores —
     * MV-backed (fortigate_events_slim), NO toca el raw (que escaneando devname
     * distintos daría >60s). Identifica el sensor por `devname` (la appliance no
     * expone una IP de sender única como syslog/wazuh). Shape: device, hits,
     * unique_src_ips, last_seen.
     * @param {number} limit
     */
    activeDevices24h(limit) {
      return `
SELECT
  devname                                                   AS device,
  COUNT(*)                                                  AS hits,
  COUNT(DISTINCT src_ip)                                    AS unique_src_ips,
  CAST(MAX(ev_ts) AS varchar)                               AS last_seen
FROM minio_iceberg.hunting.fortigate_events_slim
WHERE ev_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  AND devname IS NOT NULL AND devname <> ''
GROUP BY devname
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },
  };
}
