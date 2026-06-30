/**
 * Timestamp canónico syslog/Wazuh (vista sobre syslog) en Trino.
 * Mantener alineado con legacyhunt-api/trino/ingest-time.mjs
 */
export function syslogIngestTimestampExpr(column = "ingest_time"): string {
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
