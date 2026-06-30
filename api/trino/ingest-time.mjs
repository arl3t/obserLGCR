/**
 * Expresión SQL única para “cuándo ingresó la fila” en hunting.syslog (y vistas derivadas).
 * Orden: ISO en ingest_time → si falta, medianoche UTC del día de partición year/month/day.
 * Sincronizar con legacyhunt-dashboard/src/lib/syslog-ingest-time.ts
 */
export function syslogIngestTimestampExpr(column = "ingest_time") {
  return `COALESCE(
  TRY(from_iso8601_timestamp(trim(CAST(${column} AS varchar)))),
  TRY(CAST(
    CONCAT(
      lpad(trim(cast(coalesce(year, '') AS varchar)), 4, '0'),
      '-',
      lpad(trim(cast(coalesce(month, '') AS varchar)), 2, '0'),
      '-',
      lpad(trim(cast(coalesce(day, '') AS varchar)), 2, '0'),
      ' 00:00:00'
    ) AS timestamp
  ))
)`;
}

export const SYSLOG_INGEST_TIMESTAMP_SQL = syslogIngestTimestampExpr("ingest_time");
