/** Consultas Trino alineadas al lake LegacyHunt (por defecto catálogo minio local). */

import { getTrinoCatalog, getTrinoSchema } from "@/lib/trino-catalog";
import { SYSLOG_INGEST_TIMESTAMP_SQL } from "@/lib/syslog-ingest-time";

function tbl(name: "syslog"): string {
  return `${getTrinoCatalog()}.${getTrinoSchema()}.${name}`;
}

const esc = (s: string) => s.replace(/'/g, "''");

/** filterlog en JSON syslog (OPNsense/Vector); tolera mayúsculas y espacios */
const FL_APP = "lower(trim(cast(coalesce(appname, '') AS varchar))) = 'filterlog'";

/**
 * Incluye líneas OPNsense aunque la columna Hive `appname` venga vacía (solo queda en `message`).
 */
const FL_MATCH = `(
  ${FL_APP}
  OR strpos(lower(cast(coalesce(message, '') AS varchar)), 'filterlog') > 0
)`;

/** Ver syslog-ingest-time.ts — ISO + fallback partición y/m/d. */
const INGEST_TS = SYSLOG_INGEST_TIMESTAMP_SQL;

/**
 * “Hoy” según calendario de la sesión Trino: ingest_time en ese día o partición year/month/day del JSON (Vector).
 */
const FL_DAY_SESSION = `(
  ${INGEST_TS} >= date_trunc('day', current_timestamp)
  OR (
    trim(cast(coalesce(year, '') AS varchar)) = date_format(current_timestamp, '%Y')
    AND lpad(trim(cast(coalesce(month, '') AS varchar)), 2, '0') = date_format(current_timestamp, '%m')
    AND lpad(trim(cast(coalesce(day, '') AS varchar)), 2, '0') = date_format(current_timestamp, '%d')
  )
)`;

/** Ventana “24 h” alineada al overview: reloj Trino o partición calendario hoy en el JSON (Vector). */
const WINDOW_24H_OR_TODAY = `(
  ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  OR ${FL_DAY_SESSION}
)`;

export function blocksLast24h(): string {
  const s = tbl("syslog");
  return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${WINDOW_24H_OR_TODAY}
  `.trim();
}

/** Ventana 24h anterior (t48→t24) para tendencias ↑↓ */
export function blocksPrevious24h(): string {
  const s = tbl("syslog");
  return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '48' HOUR
      AND ${INGEST_TS} < CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  `.trim();
}

export function uniqueBlockedIpsPrevious24h(): string {
  const s = tbl("syslog");
  return `
    SELECT COUNT(DISTINCT SPLIT_PART(message, ',', 19)) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '48' HOUR
      AND ${INGEST_TS} < CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
  `.trim();
}

export function uniqueBlockedIps24h(): string {
  const s = tbl("syslog");
  return `
    SELECT COUNT(DISTINCT SPLIT_PART(message, ',', 19)) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
  `.trim();
}

export function blocksByDay(days: number): string {
  const s = tbl("syslog");
  return `
    SELECT
      DATE(${INGEST_TS}) AS day,
      COUNT(*) AS blocks
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${days}' DAY
    GROUP BY 1
    ORDER BY 1
  `.trim();
}

/** Serie horaria últimas 24h (sparklines / gráficos de perímetro). */
export function blocksByHourLast24h(): string {
  const s = tbl("syslog");
  return `
    SELECT
      date_trunc('hour', ${INGEST_TS}) AS hour,
      COUNT(*) AS blocks
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    GROUP BY 1
    ORDER BY 1
  `.trim();
}

export function uniqueBlockedIpsByHourLast24h(): string {
  const s = tbl("syslog");
  return `
    SELECT
      date_trunc('hour', ${INGEST_TS}) AS hour,
      COUNT(DISTINCT SPLIT_PART(message, ',', 19)) AS uniq_ips
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
    GROUP BY 1
    ORDER BY 1
  `.trim();
}

export function topBlockedIps(limit: number, hours: number): string {
  const s = tbl("syslog");
  return `
    SELECT
      SPLIT_PART(message, ',', 19) AS src_ip,
      COUNT(*) AS hits
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      AND SPLIT_PART(message, ',', 19) NOT LIKE '192.168.%'
      AND SPLIT_PART(message, ',', 19) NOT LIKE '10.%'
      AND SPLIT_PART(message, ',', 19) != ''
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
}

export function topAttackedPorts(limit: number, hours: number): string {
  const s = tbl("syslog");
  return `
    SELECT
      SPLIT_PART(message, ',', 22) AS dst_port,
      COUNT(*) AS hits
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
}

/**
 * IPs bloqueadas recientes (filterlog) agregadas por IP, para panel “casi tiempo real”.
 * Ajusta `minutes` según carga del cluster (consultas sobre JSON en el lake pueden ser pesadas).
 */
export function blockCountForIp(ip: string, hours: number): string {
  const s = tbl("syslog");
  const ipLit = esc(ip);
  return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND SPLIT_PART(message, ',', 19) = '${ipLit}'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
  `.trim();
}

/** Eventos filterlog recientes (texto crudo para feed SOC). */
export function recentFilterlogLines(limit: number, minutes: number): string {
  const s = tbl("syslog");
  return `
    SELECT CAST(ingest_time AS varchar) AS ingest_time, message
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${minutes}' MINUTE
    ORDER BY ${INGEST_TS} DESC
    LIMIT ${limit}
  `.trim();
}

export function recentBlockedIpsForLiveFeed(limit: number, minutes: number): string {
  const s = tbl("syslog");
  return `
    SELECT
      SPLIT_PART(message, ',', 19) AS src_ip,
      COUNT(*) AS hits,
      MAX(ingest_time) AS last_seen
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${minutes}' MINUTE
      AND SPLIT_PART(message, ',', 19) IS NOT NULL
      AND TRIM(SPLIT_PART(message, ',', 19)) <> ''
    GROUP BY 1
    ORDER BY MAX(${INGEST_TS}) DESC
    LIMIT ${limit}
  `.trim();
}

/** IPs que envían syslog a Vector (campo nativo `source_ip` en JSON; no es la IP dentro del filterlog). */
export function syslogSendersLast24h(): string {
  const s = tbl("syslog");
  return `
    SELECT TRIM(CAST(source_ip AS varchar)) AS source_ip, COUNT(*) AS c
    FROM ${s}
    WHERE (
        ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
        OR ${FL_DAY_SESSION}
      )
      AND source_ip IS NOT NULL
      AND TRIM(CAST(source_ip AS varchar)) <> ''
    GROUP BY 1
    ORDER BY c DESC
    LIMIT 12
  `.trim();
}

/** Eventos filterlog en las últimas 24 h (ingest_time) o con partición JSON “hoy” (misma lógica que bloqueos). */
export function filterlogEventsLast24h(): string {
  const s = tbl("syslog");
  return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND ${WINDOW_24H_OR_TODAY}
  `.trim();
}

export function filterlogEventsToday(): string {
  const s = tbl("syslog");
  return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND ${FL_DAY_SESSION}
  `.trim();
}

/** Diagnóstico: ¿la tabla tiene datos recientes? (ingest_time en 7 d o partición “hoy”) */
export function syslogRowsLast168hOrTodayPartition(): string {
  const s = tbl("syslog");
  return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '168' HOUR
      OR ${FL_DAY_SESSION}
  `.trim();
}

/** Diagnóstico barato: ¿existe al menos una fila en la tabla? (no full COUNT) */
export function syslogAnyRowSql(): string {
  const s = tbl("syslog");
  return `SELECT 1 AS ok FROM ${s} LIMIT 1`;
}

/** Diagnóstico: ¿hay algún evento que coincida con filterlog (appname o message)? */
export function filterlogAnyRowSql(): string {
  const s = tbl("syslog");
  return `
    SELECT 1 AS ok
    FROM ${s}
    WHERE ${FL_MATCH}
    LIMIT 1
  `.trim();
}

/**
 * Heurística east-west: IP RFC1918 con muchos puertos destino distintos en filterlog hoy.
 * Campo 22 ≈ puerto destino en plantilla OPNsense típica del lab.
 */
export function lateralMovementCandidatesToday(limit: number): string {
  const s = tbl("syslog");
  return `
    SELECT
      TRIM(SPLIT_PART(message, ',', 19)) AS src_ip,
      COUNT(DISTINCT COALESCE(TRIM(SPLIT_PART(message, ',', 22)), '')) AS unique_dst_ports,
      COUNT(*) AS events
    FROM ${s}
    WHERE ${FL_MATCH}
      AND ${FL_DAY_SESSION}
      AND TRIM(SPLIT_PART(message, ',', 19)) <> ''
      AND (
        TRIM(SPLIT_PART(message, ',', 19)) LIKE '192.168.%'
        OR TRIM(SPLIT_PART(message, ',', 19)) LIKE '10.%'
        OR REGEXP_LIKE(TRIM(SPLIT_PART(message, ',', 19)), '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
      )
    GROUP BY 1
    HAVING COUNT(DISTINCT COALESCE(TRIM(SPLIT_PART(message, ',', 22)), '')) >= 4
    ORDER BY unique_dst_ports DESC, events DESC
    LIMIT ${limit}
  `.trim();
}

export function topBlockedIpsCalendar(
  limit: number,
  year: string,
  month: string,
): string {
  const s = tbl("syslog");
  const y = esc(year);
  const m = esc(month);
  return `
    SELECT
      SPLIT_PART(message, ',', 19) AS src_ip,
      COUNT(*) AS hits
    FROM ${s}
    WHERE year = '${y}' AND month = '${m}'
      AND ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND SPLIT_PART(message, ',', 19) NOT LIKE '192.168.%'
      AND SPLIT_PART(message, ',', 19) NOT LIKE '10.%'
      AND SPLIT_PART(message, ',', 19) != ''
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
}
