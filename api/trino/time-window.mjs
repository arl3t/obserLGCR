/**
 * time-window.mjs — helpers compartidos para construir filtros de ventana 24h
 * y de partition prune en queries Trino sobre tablas Iceberg/Hive de hunting.
 *
 * Antes cada `*-sql.mjs` repetía sus propios PART_2D / PART_3D / W24 / INGEST_TS
 * con variaciones sutiles (pueden divergir → bugs de datos viejos colándose en
 * KPIs 24h). Este módulo unifica ambos estilos:
 *
 *   1. **string** — columnas year/month/day como varchar ('2026','04','24'):
 *      usado por suricata, fortigate, pmg, syslog. Compara con date_format()
 *      de current_timestamp (con lpad para tolerar '4' vs '04').
 *
 *   2. **integer** — columnas year/month/day como integer:
 *      usado por wazuh y wazuh_fluent. Compara con YEAR()/MONTH()/DAY() de
 *      CURRENT_DATE.
 *
 * Las funciones son determinísticas y devuelven SQL templated. El consumidor
 * elige qué constantes desestructurar (no todos los dashboards usan todo).
 */

import { syslogIngestTimestampExpr } from "./ingest-time.mjs";

const STYLES = ["string", "integer"];

/**
 * Devuelve la condición SQL para un único día (offset hacia atrás desde hoy).
 * @param {number} daysBack - 0 = hoy, 1 = ayer, 2 = anteayer, …
 * @param {'string'|'integer'} style
 */
function dayClause(daysBack, style) {
  if (style === "integer") {
    // NOTA 2026-06-26: las columnas year/month/day de wazuh_alerts / wazuh_fluent
    // son VARCHAR con padding a 2 dígitos ('2026','06','26'), NO integer. El antiguo
    // `CAST(year AS integer) = YEAR(...)` envolvía la columna de partición, así que
    // Trino lo degradaba a filterPredicate post-scan → FULL JSON SCAN (~9 min) en vez
    // de partition pruning. Verificado con EXPLAIN: con CAST aparece
    // `ScanFilterProject[... filterPredicate=(CAST("year" AS integer)=2026)]`; sin CAST
    // (columna bare, funciones sólo en el lado del literal) → `TableScan` con
    // `year:string:PARTITION_KEY` y sin filterPredicate. Mismo patrón que
    // threatPatternScan.mjs. El nombre del estilo "integer" se conserva por
    // compatibilidad de los callers, pero el SQL ya NO castea la columna.
    const offset =
      daysBack === 0 ? "CURRENT_DATE" : `CURRENT_DATE - INTERVAL '${daysBack}' DAY`;
    return `(year = CAST(YEAR(${offset}) AS varchar)
      AND month = lpad(CAST(MONTH(${offset}) AS varchar), 2, '0')
      AND day = lpad(CAST(DAY(${offset}) AS varchar), 2, '0'))`;
  }
  // string-style con lpad para tolerar '4' vs '04'.
  const ts =
    daysBack === 0
      ? "current_timestamp"
      : `current_timestamp - INTERVAL '${daysBack}' DAY`;
  return `(trim(cast(coalesce(year,'') AS varchar)) = date_format(${ts}, '%Y')
     AND lpad(trim(cast(coalesce(month,'') AS varchar)), 2, '0') = date_format(${ts}, '%m')
     AND lpad(trim(cast(coalesce(day,'') AS varchar)), 2, '0') = date_format(${ts}, '%d'))`;
}

/**
 * Genera un OR de partitions para los días indicados.
 * @param {number[]} daysBack - p.ej. [0, 1] para hoy+ayer.
 * @param {'string'|'integer'} style
 */
export function partitionFilter(daysBack, style = "string") {
  if (!STYLES.includes(style)) {
    throw new Error(`partitionFilter: style debe ser ${STYLES.join("|")}`);
  }
  if (!Array.isArray(daysBack) || daysBack.length === 0) {
    throw new Error("partitionFilter: daysBack debe ser array no vacío");
  }
  const clauses = daysBack.map((d) => dayClause(d, style));
  return `(\n    ${clauses.join("\n    OR\n    ")}\n  )`;
}

/**
 * Filtro "solo año en curso" (string-style). Útil para queries multi-semana
 * que ya filtran por timestamp pero quieren podar años anteriores.
 */
export const PART_CURRENT_YEAR_STRING = `trim(cast(coalesce(year,'') AS varchar)) = date_format(current_timestamp, '%Y')`;

/**
 * Comparación lex sobre columna varchar ISO 8601 sortable (`yyyy-MM-ddTHH:mm:ss.sssZ`).
 * Mucho más eficiente que parsear timestamp por fila: Iceberg puede usar min/max
 * stats de la columna para skip de archivos.
 *
 * @param {string} column - nombre de la columna varchar a comparar
 * @param {number} hours - horas hacia atrás (default 24)
 */
export function isoLexWindow(column = "ingest_time", hours = 24) {
  return `${column} >= format_datetime(CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR, 'yyyy-MM-dd''T''HH:mm:ss')`;
}

/**
 * Ventana 24h sobre un timestamp resuelto + fallback al partition de hoy.
 * El OR con partition fallback es defensivo: si ingest_time falla en el COALESCE
 * del syslogIngestTimestampExpr, igual capturamos eventos del día actual por
 * particion. Único patrón W24 estandarizado entre suricata/fortigate.
 */
export function window24hWithTodayFallback(ingestTsExpr, style = "string") {
  const partToday = partitionFilter([0], style);
  return `(
    ${ingestTsExpr} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    OR ${partToday}
  )`;
}

/**
 * Bundle conveniente para dashboards string-style (suricata, fortigate, pmg,
 * syslog). Reproduce las constantes que cada archivo definía.
 *
 * @param {object} [opts]
 * @param {string} [opts.ingestTsExpr] - override (p.ej. PMG usa `ts`).
 *   Default: syslogIngestTimestampExpr("ingest_time").
 */
export function stringStyleWindow(opts = {}) {
  const INGEST_TS =
    opts.ingestTsExpr ?? syslogIngestTimestampExpr("ingest_time");
  const PART_2D = partitionFilter([0, 1], "string");
  const PART_3D = partitionFilter([0, 1, 2], "string");
  const PART_TODAY = partitionFilter([0], "string");
  const W24 = window24hWithTodayFallback(INGEST_TS, "string");
  return {
    INGEST_TS,
    PART_2D,
    PART_3D,
    PART_TODAY,
    PART_CURRENT_YEAR: PART_CURRENT_YEAR_STRING,
    W24,
  };
}

/**
 * Bundle para dashboards integer-style (wazuh, wazuh_fluent).
 * `WINDOW_24H_LEX` usa string-comparison sobre `ingest_time` (varchar ISO 8601),
 * que es más rápido que parsear timestamp por fila.
 */
export function integerStyleWindow() {
  const PART_2D = partitionFilter([0, 1], "integer");
  const PART_TODAY = partitionFilter([0], "integer");
  const INGEST_24H_LEX = isoLexWindow("ingest_time", 24);
  const WINDOW_24H_LEX = `${PART_2D} AND ${INGEST_24H_LEX}`;
  return {
    PART_2D,
    PART_TODAY,
    INGEST_24H_LEX,
    WINDOW_24H_LEX,
  };
}
