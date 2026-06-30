/**
 * SQL para consultas sobre la tabla Iceberg syslog_events (hito 2).
 * Catálogo: minio_iceberg.hunting.syslog_events — partición por dt (DATE).
 * Mucho más rápido que Hive gracias a columnar PARQUET + poda de particiones exactas.
 */

/**
 * @param {string} catalog  p.ej. minio_iceberg
 * @param {string} schema   p.ej. hunting
 */
export function createSyslogIcebergSql(catalog, schema) {
  const tbl = `${catalog}.${schema}.syslog_events`;

  return {
    /** KPIs globales últimos N días */
    kpis(days = 7) {
      return `
SELECT
  COUNT(*)                                                  AS total_events,
  COUNT(CASE WHEN fl_is_filterlog = true THEN 1 END)        AS filterlog_events,
  COUNT(CASE WHEN fl_action = 'block' THEN 1 END)           AS blocks,
  COUNT(CASE WHEN fl_action = 'pass'  THEN 1 END)           AS passes,
  COUNT(DISTINCT fl_src_ip)                                  AS unique_src_ips,
  COUNT(DISTINCT host)                                       AS unique_hosts,
  MIN(event_ts)                                              AS oldest_event,
  MAX(event_ts)                                              AS newest_event
FROM ${tbl}
WHERE dt >= current_date - INTERVAL '${days}' DAY
`.trim();
    },

    /** Top IPs bloqueadas últimas N horas */
    topBlockedIps(hours = 24, limit = 50) {
      const days = Math.ceil(hours / 24) + 1;
      return `
SELECT
  fl_src_ip,
  COUNT(*)          AS block_count,
  MIN(event_ts)     AS first_seen,
  MAX(event_ts)     AS last_seen,
  COUNT(DISTINCT fl_dst_port) AS distinct_ports
FROM ${tbl}
WHERE dt >= current_date - INTERVAL '${days}' DAY
  AND event_ts >= current_timestamp - INTERVAL '${hours}' HOUR
  AND fl_is_filterlog = true
  AND fl_action = 'block'
  AND fl_src_ip IS NOT NULL
GROUP BY fl_src_ip
ORDER BY block_count DESC
LIMIT ${limit}
`.trim();
    },

    /** Bloques por hora (serie temporal) últimas 24 h */
    blocksByHour24h() {
      return `
SELECT
  date_trunc('hour', event_ts) AS hour_bucket,
  COUNT(*) AS block_count
FROM ${tbl}
WHERE dt >= current_date - INTERVAL '2' DAY
  AND event_ts >= current_timestamp - INTERVAL '24' HOUR
  AND fl_is_filterlog = true
  AND fl_action = 'block'
GROUP BY 1
ORDER BY 1
`.trim();
    },

    /** Top puertos destino atacados últimas N horas */
    topAttackedPorts(hours = 24, limit = 20) {
      const days = Math.ceil(hours / 24) + 1;
      return `
SELECT
  fl_dst_port,
  fl_protocol,
  COUNT(*)          AS hit_count,
  COUNT(DISTINCT fl_src_ip) AS unique_attackers
FROM ${tbl}
WHERE dt >= current_date - INTERVAL '${days}' DAY
  AND event_ts >= current_timestamp - INTERVAL '${hours}' HOUR
  AND fl_is_filterlog = true
  AND fl_action = 'block'
  AND fl_dst_port IS NOT NULL
GROUP BY fl_dst_port, fl_protocol
ORDER BY hit_count DESC
LIMIT ${limit}
`.trim();
    },

    /** Bloques por día (serie N días) */
    blocksByDay(days = 30) {
      return `
SELECT
  dt,
  COUNT(*) AS block_count
FROM ${tbl}
WHERE dt >= current_date - INTERVAL '${days}' DAY
  AND fl_is_filterlog = true
  AND fl_action = 'block'
GROUP BY dt
ORDER BY dt
`.trim();
    },

    /** Actividad por host/firewall */
    eventsByHost(days = 7, limit = 20) {
      return `
SELECT
  host,
  COUNT(*)                                                 AS total_events,
  COUNT(CASE WHEN fl_action = 'block' THEN 1 END)          AS blocks,
  COUNT(CASE WHEN fl_action = 'pass'  THEN 1 END)          AS passes,
  COUNT(DISTINCT fl_src_ip)                                 AS unique_src_ips,
  MAX(event_ts)                                            AS last_event
FROM ${tbl}
WHERE dt >= current_date - INTERVAL '${days}' DAY
GROUP BY host
ORDER BY total_events DESC
LIMIT ${limit}
`.trim();
    },

    /** Verificación: cuántas filas hay en la tabla (muestra si ETL corrió) */
    rowCount(days = 30) {
      return `
SELECT
  dt,
  COUNT(*) AS rows
FROM ${tbl}
WHERE dt >= current_date - INTERVAL '${days}' DAY
GROUP BY dt
ORDER BY dt DESC
`.trim();
    },
  };
}
