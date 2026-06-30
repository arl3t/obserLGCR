/**
 * Consultas nombradas para POST /api/trino/run.
 * El dashboard nunca envía SQL libre; solo IDs con params validados aquí.
 * Prefijo lh.* reservado para LegacyHunt.
 */
import { z } from "zod";
import { createHuntingEnrichmentSql } from "./hunting-enrichment-sql.mjs";
import { createIncidentScoringSql } from "./incident-scoring-sql.mjs";
import { createSocSql } from "./soc-sql.mjs";
import { createSuricataSql } from "./suricata-sql.mjs";
import { createSyslogSql } from "./syslog-sql.mjs";
import { createSyslogIcebergSql } from "./syslog-iceberg-sql.mjs";
import { createWazuhAlertsHuntSql } from "./wazuh-alerts-hunt-sql.mjs";
import { createWazuhSql, resolveWazuhTableName } from "./wazuh-sql.mjs";
import { createWazuhFluentSql } from "./wazuh-fluent-sql.mjs";
import { createFortigateSql } from "./fortigate-sql.mjs";
import { createPmgSql } from "./pmg-sql.mjs";
import { createOutliersSql } from "./outliers-sql.mjs";

const empty = z.object({});

/** Escape seguro para inline dentro de string literals SQL de Trino. */
function sq(v) {
  return `'${String(v ?? "").replace(/'/g, "''")}'`;
}

const daysSchema = z.object({
  days: z.coerce.number().int().min(1).max(365),
});

const limitHoursSchema = z.object({
  limit: z.coerce.number().int().min(1).max(50_000),
  hours: z.coerce.number().int().min(1).max(24 * 90),
});

const limitMinutesSchema = z.object({
  limit: z.coerce.number().int().min(1).max(50_000),
  minutes: z.coerce.number().int().min(1).max(60 * 24 * 7),
});

const limitOnlySchema = z.object({
  limit: z.coerce.number().int().min(1).max(10000),
});

const limitDaysSchema = z.object({
  limit: z.coerce.number().int().min(1).max(10000),
  days: z.coerce.number().int().min(1).max(90),
});

/**
 * Para queries del chat SOC que aceptan filtro opcional de severidad mínima.
 * El valor se propaga al builder SQL; si es inválido o "NEGLIGIBLE" la cláusula
 * queda vacía (equivale a sin filtro).
 */
const limitDaysSeveritySchema = z.object({
  limit: z.coerce.number().int().min(1).max(10000),
  days:  z.coerce.number().int().min(1).max(90),
  severityMin: z.enum(["CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE"]).optional(),
});

// ── Outlier Detection ─────────────────────────────────────────────────────────
const OUTLIER_ENTITY_TYPES = [
  "ip", "host", "port", "hour", "user", "country",
  "sensor", "source_log", "business_tag",
];
const OUTLIER_SEVERITIES = ["low", "medium", "high", "critical"];
const OUTLIER_LOG_FAMILIES = [
  "syslog", "wazuh", "filterlog", "fortigate", "suricata", "pmg", "multi",
];

/** Lista paginada de outliers con filtros opcionales por entidad/severidad/fuente. */
const outlierListSchema = z.object({
  hours: z.coerce.number().int().min(1).max(24 * 7),  // cap 7d
  limit: z.coerce.number().int().min(1).max(500),
  entity_type: z.enum(OUTLIER_ENTITY_TYPES).optional(),
  severity:    z.enum(OUTLIER_SEVERITIES).optional(),
  log_family:  z.enum(OUTLIER_LOG_FAMILIES).optional(),
});

/** Top N entities por score con days 1-30. */
const outlierTopEntitiesSchema = z.object({
  days:  z.coerce.number().int().min(1).max(30),
  limit: z.coerce.number().int().min(1).max(100),
  entity_type: z.enum(OUTLIER_ENTITY_TYPES).optional(),
});

/** Breakdown por log_family days 1-30. */
const outlierDaysOnlySchema = z.object({
  days: z.coerce.number().int().min(1).max(30),
});

/** Outliers de un IOC específico. ioc_value acepta IPs, hashes, domains. */
const outlierForIocSchema = z.object({
  ioc_value: z.string().min(3).max(256).regex(/^[0-9a-zA-Z.:/_\-]+$/, "ioc_value con chars inválidos"),
});

/** Solo días — sin parámetro limit (para analysis_flow que no tiene LIMIT). */
const daysOnlySchema = z.object({
  days: z.coerce.number().int().min(1).max(90),
});

const hoursOnlySchema = z.object({
  hours: z.coerce.number().int().min(1).max(24 * 365),
});

/** IPv4 / IPv6 solo chars legales [0-9a-fA-F.:], longitud 7-45. */
const ipHoursSchema = z.object({
  ip: z
    .string()
    .min(7)
    .max(45)
    .regex(/^[0-9a-fA-F.:]+$/, "Invalid IP address format"),
  hours: z.coerce.number().int().min(1).max(24 * 90),
});

/** Identificador de sensor: hostname, IP v4/v6, nombre de agente Wazuh. */
const sensorDaysSchema = z.object({
  sensor: z
    .string()
    .min(1)
    .max(100)
    .regex(/^[0-9a-zA-Z\-_.:/]{1,100}$/, "Invalid sensor identifier"),
  days: z.coerce.number().int().min(1).max(90),
});

/** Top IPs por mes calendario. */
const calendarSchema = z.object({
  limit: z.coerce.number().int().min(1).max(500),
  year: z.string().regex(/^\d{4}$/, "Year must be YYYY"),
  month: z.string().regex(/^\d{1,2}$/, "Month must be 1-2 digits"),
});

/** Catálogo Trino para tablas Iceberg de threat-hunt (`enriched_ioc`, `vt_results`). No usar el conector Hive `minio`. */
function huntingIcebergCatalogFromConfig(config, hiveCatalog) {
  const explicit = (config.INTEL_SOURCES_ICEBERG_CATALOG ?? "").trim().toLowerCase();
  if (explicit) {
    // `s3` / `minio` en .env suelen referirse al lake Hive; Iceberg del lab vive en minio_iceberg.
    if (
      explicit === "3" ||
      explicit === "s3" ||
      explicit === "s3_iceberg" ||
      explicit === "minio"
    ) {
      return "minio_iceberg";
    }
    return explicit;
  }
  const h = String(hiveCatalog ?? "minio").trim().toLowerCase();
  if (h === "minio") return "minio_iceberg";
  return h;
}

function ctxFromConfig(config) {
  let cat = (config.trinoCatalog ?? "minio").trim().toLowerCase();
  if (cat === "3" || cat === "s3") cat = "minio";
  if (cat === "s3_iceberg") cat = "minio_iceberg";
  const schema = (config.trinoSchema ?? "hunting").trim();
  const huntingSchema = (config.INTEL_SOURCES_ICEBERG_SCHEMA ?? schema).trim();
  const syslog = createSyslogSql(cat, schema);
  const wazuhTable = resolveWazuhTableName({
    trinoCatalog: cat,
    trinoSchema: schema,
    intelWazuhTable: config.intelWazuhTable ?? "",
  });
  const wazuh = createWazuhSql(wazuhTable);
  const wazuhAlertsHunt = createWazuhAlertsHuntSql(`${cat}.${schema}.wazuh_alerts`);
  const soc = createSocSql(cat, schema);
  const suricata = createSuricataSql(cat, schema);
  const huntingCat = huntingIcebergCatalogFromConfig(config, cat);
  const hunting = createHuntingEnrichmentSql(huntingCat, huntingSchema);
  const syslogIce = createSyslogIcebergSql(huntingCat, huntingSchema);
  // MTTD multi-sensor: además de wazuh_alerts, cruzamos syslog (suricata +
  // filterlog), fortigate y pmg_phishing por ioc_value para tomar la PRIMERA
  // alerta global de cualquier sensor — no sólo de Wazuh.
  const incidents = createIncidentScoringSql(huntingCat, huntingSchema, {
    wazuh:       `${cat}.${schema}.wazuh_alerts`,
    syslog:      `${cat}.${schema}.syslog`,
    fortigate:   `${cat}.${schema}.fortigate`,
    pmgPhishing: `${cat}.${schema}.pmg_phishing`,
  });
  const pmg = createPmgSql(cat, schema);
  const fortigate = createFortigateSql(cat, schema);
  const wazuhFluent = createWazuhFluentSql(`${cat}.${schema}.wazuh_fluent`);
  const outliers = createOutliersSql(huntingCat, huntingSchema);
  return { syslog, wazuh, wazuhAlertsHunt, soc, suricata, hunting, syslogIce, incidents, pmg, fortigate, wazuhFluent, outliers };
}

/** @type {Record<string, { params: z.ZodTypeAny, build: (p: any, c: ReturnType<typeof ctxFromConfig>) => string }>} */
const REGISTRY = {
  "lh.syslog.blocks_last_24h": {
    params: empty,
    build: (_, c) => c.syslog.blocksLast24h(),
  },
  "lh.syslog.blocks_previous_24h": {
    params: empty,
    build: (_, c) => c.syslog.blocksPrevious24h(),
  },
  "lh.syslog.unique_blocked_ips_24h": {
    params: empty,
    build: (_, c) => c.syslog.uniqueBlockedIps24h(),
  },
  "lh.syslog.perimeter_kpis_24h": {
    params: empty,
    build: (_, c) => c.syslog.perimeterKpis24h(),
  },
  "lh.syslog.unique_blocked_ips_previous_24h": {
    params: empty,
    build: (_, c) => c.syslog.uniqueBlockedIpsPrevious24h(),
  },
  "lh.syslog.blocks_last_Nh": {
    params: hoursOnlySchema,
    build: (p, c) => c.syslog.blocksLastNh(p.hours),
  },
  "lh.syslog.unique_blocked_ips_Nh": {
    params: hoursOnlySchema,
    build: (p, c) => c.syslog.uniqueBlockedIpsNh(p.hours),
  },
  "lh.syslog.blocks_by_day": {
    params: daysSchema,
    build: (p, c) => c.syslog.blocksByDay(p.days),
  },
  "lh.syslog.blocks_by_hour_24h": {
    params: empty,
    build: (_, c) => c.syslog.blocksByHourLast24h(),
  },
  "lh.syslog.unique_ips_by_hour_24h": {
    params: empty,
    build: (_, c) => c.syslog.uniqueBlockedIpsByHourLast24h(),
  },
  "lh.syslog.top_blocked_ips": {
    params: limitHoursSchema,
    build: (p, c) => c.syslog.topBlockedIps(p.limit, p.hours),
  },
  "lh.syslog.top_attacked_ports": {
    params: limitHoursSchema,
    build: (p, c) => c.syslog.topAttackedPorts(p.limit, p.hours),
  },
  "lh.syslog.overview_bundle_Nh": {
    params: z.object({
      hours:        z.coerce.number().int().min(1).max(24 * 365),
      topIpLimit:   z.coerce.number().int().min(1).max(50).default(8),
      topPortLimit: z.coerce.number().int().min(1).max(50).default(6),
    }),
    build: (p, c) => c.syslog.overviewBundleNh(p.hours, p.topIpLimit, p.topPortLimit),
  },
  "lh.syslog.lateral_movement_today": {
    params: limitOnlySchema,
    build: (p, c) => c.syslog.lateralMovementCandidatesToday(p.limit),
  },
  "lh.syslog.filterlog_events_24h": {
    params: empty,
    build: (_, c) => c.syslog.filterlogEventsLast24h(),
  },
  "lh.syslog.diag_168h_or_today_partition": {
    params: empty,
    build: (_, c) => c.syslog.syslogRowsLast168hOrTodayPartition(),
  },
  "lh.syslog.senders_24h": {
    params: empty,
    build: (_, c) => c.syslog.syslogSendersLast24h(),
  },
  "lh.syslog.any_row": {
    params: empty,
    build: (_, c) => c.syslog.syslogAnyRowSql(),
  },
  "lh.syslog.filterlog_any_row": {
    params: empty,
    build: (_, c) => c.syslog.filterlogAnyRowSql(),
  },
  // ── syslog queries nuevas ────────────────────────────────────────────────
  "lh.syslog.filterlog_events_today": {
    params: empty,
    build: (_, c) => c.syslog.filterlogEventsToday(),
  },
  "lh.syslog.block_count_for_ip": {
    params: ipHoursSchema,
    build: (p, c) => c.syslog.blockCountForIp(p.ip, p.hours),
  },
  "lh.syslog.recent_blocked_ips_live": {
    params: limitMinutesSchema,
    build: (p, c) => c.syslog.recentBlockedIpsForLiveFeed(p.limit, p.minutes),
  },
  "lh.syslog.recent_filterlog_lines": {
    params: limitMinutesSchema,
    build: (p, c) => c.syslog.recentFilterlogLines(p.limit, p.minutes),
  },
  "lh.syslog.top_blocked_ips_calendar": {
    params: calendarSchema,
    build: (p, c) => c.syslog.topBlockedIpsCalendar(p.limit, p.year, p.month),
  },
  /** Top atacantes enriquecido con sensor de origen (source_ip / interfaz OPNsense). */
  "lh.syslog.top_blocked_ips_with_sensor": {
    params: limitHoursSchema,
    build: (p, c) => c.syslog.topBlockedIpsWithSensor(p.limit, p.hours),
  },

  /**
   * Variante materializada: lee de `filterlog_top_blocked_hourly`
   * (grain horario, refresh 30 min vía DAG
   * `filterlog_top_blocked_refresh_30min`). Shape idéntico al live —
   * re-agrega arrays con ARRAY_DISTINCT + FLATTEN y los serializa a
   * string con ARRAY_JOIN (misma salida del live para drop-in).
   *
   * Umbral del CTAS: solo guarda filas con hits >= 3 por (hora, IP).
   * Query time: solo filtra la ventana `hours` del cliente; no re-aplica
   * el threshold (el filtrado por volumen ya se hizo).
   */
  "lh.syslog.top_blocked_ips_with_sensor_mat": {
    params: limitHoursSchema,
    build: (p) => `
SELECT
  src_ip,
  SUM(hits)                                                                       AS hits,
  ARRAY_JOIN(ARRAY_DISTINCT(FLATTEN(ARRAY_AGG(sensor_ips))), ', ')                AS sensor_ips,
  ARRAY_JOIN(ARRAY_DISTINCT(FLATTEN(ARRAY_AGG(ifaces))),     ', ')                AS ifaces,
  ARRAY_JOIN(ARRAY_DISTINCT(FLATTEN(ARRAY_AGG(protos))),     ', ')                AS protos,
  ARRAY_JOIN(ARRAY_DISTINCT(FLATTEN(ARRAY_AGG(dst_ports))),  ', ')                AS dst_ports_sample
FROM minio_iceberg.hunting.filterlog_top_blocked_hourly
WHERE dt >= current_date - INTERVAL '2' DAY
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '${p.hours}' HOUR
GROUP BY src_ip
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  /** Desglose por sensor para una IP atacante específica — panel Investigar. */
  "lh.syslog.sensor_breakdown_for_ip": {
    params: ipHoursSchema,
    build: (p, c) => c.syslog.sensorBreakdownForIp(p.ip, p.hours),
  },

  /**
   * Variantes materializadas (audit 2026-06-10). Leen de las tablas Iceberg
   * `filterlog_kpis_hourly` / `filterlog_port_hourly` / `filterlog_vpn_hourly`,
   * refrescadas cada 30 min vía DAG `filterlog_summary_refresh_30min` (SQL
   * `56_mv_filterlog_summary_hourly`). Reemplazan los full-scan con SPLIT_PART
   * que dominaban: perimeter_kpis 8.7s · blocks_by_hour 7.2s · vpn_events 7.2s.
   * Shape idéntico al live. COUNT(DISTINCT) de perimeter_kpis vía HyperLogLog
   * mergeable (~1.6% error).
   */
  "lh.syslog.perimeter_kpis_24h_mat": {
    params: empty,
    build: () => `
SELECT
  SUM(total_events)                                                AS total_events,
  SUM(blocks)                                                      AS blocks,
  SUM(allowed)                                                     AS allowed,
  cardinality(merge(CAST(hll_attacker_ips AS HyperLogLog)))        AS unique_attacker_ips,
  cardinality(merge(CAST(hll_dest_ports   AS HyperLogLog)))        AS unique_dest_ports
FROM minio_iceberg.hunting.filterlog_kpis_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
`.trim(),
  },
  "lh.syslog.blocks_by_hour_24h_mat": {
    params: empty,
    build: () => `
SELECT
  hour_ts                                                          AS hour,
  blocks
FROM minio_iceberg.hunting.filterlog_kpis_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  AND blocks > 0
ORDER BY hour_ts ASC
`.trim(),
  },
  "lh.syslog.top_attacked_ports_mat": {
    params: limitHoursSchema,
    build: (p) => `
SELECT
  dst_port,
  SUM(hits)                                                        AS hits
FROM minio_iceberg.hunting.filterlog_port_hourly
WHERE dt >= current_date - INTERVAL '2' DAY
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '${p.hours}' HOUR
GROUP BY dst_port
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.syslog.vpn_events_24h_mat": {
    params: empty,
    build: () => `
SELECT
  COUNT(*)                                                         AS c
FROM minio_iceberg.hunting.filterlog_vpn_events
WHERE ev_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
`.trim(),
  },
  /**
   * Feed de conexiones VPN materializado. El live (vpnConnectionEvents) hacía
   * un regexp full-scan de ~17.6s que gateaba toda la página /firewall (el
   * batch espera a la query más lenta). Lee de `filterlog_vpn_events`
   * (event_type ya clasificado en el CTAS). Trade-off: frescura ≤ refresh del
   * DAG (30 min).
   */
  "lh.syslog.vpn_connections_mat": {
    params: limitHoursSchema,
    build: (p) => `
SELECT
  CAST(ev_ts AS varchar)                                          AS ts,
  service,
  source_ip,
  message,
  event_type
FROM minio_iceberg.hunting.filterlog_vpn_events
WHERE ev_ts >= CURRENT_TIMESTAMP - INTERVAL '${p.hours}' HOUR
ORDER BY ev_ts DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.syslog.vpn_failed_auth_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  CAST(ev_ts AS varchar)                                          AS ts,
  service,
  source_ip,
  message
FROM minio_iceberg.hunting.filterlog_vpn_events
WHERE event_type = 'failed'
  AND ev_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
ORDER BY ev_ts DESC
LIMIT ${p.limit}
`.trim(),
  },
  // ── wazuh queries — ventana variable ─────────────────────────────────────
  "lh.wazuh.critical_count_Nh": {
    params: hoursOnlySchema,
    build: (p, c) => c.wazuh.criticalCountNh(p.hours),
  },
  "lh.wazuh.severity_buckets_Nh": {
    params: hoursOnlySchema,
    build: (p, c) => c.wazuh.severityBucketsNh(p.hours),
  },
  "lh.wazuh.top_rules_Nh": {
    params: limitHoursSchema,
    build: (p, c) => c.wazuh.topRulesNh(p.limit, p.hours),
  },
  "lh.wazuh.critical_cves_Nh": {
    params: limitHoursSchema,
    build: (p, c) => c.wazuh.criticalCvesNh(p.limit, p.hours),
  },
  // ── wazuh queries ────────────────────────────────────────────────────────
  "lh.wazuh.alerts_24h": {
    params: empty,
    build: (_, c) => c.wazuh.alertsLast24h(),
  },
  "lh.wazuh.critical_count_24h": {
    params: empty,
    build: (_, c) => c.wazuh.criticalCount24h(),
  },
  "lh.wazuh.severity_buckets_24h": {
    params: empty,
    build: (_, c) => c.wazuh.severityBuckets24h(),
  },
  "lh.wazuh.top_rules_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuh.topRules24h(p.limit),
  },
  "lh.wazuh.top_agents_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuh.topAgents24h(p.limit),
  },
  "lh.wazuh.critical_cves_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuh.criticalCves24h(p.limit),
  },
  /**
   * Agregado por CVE (1 row = 1 CVE) con hosts_count DISTINCT, alert_count
   * y max cvss en 24h. Lo consume el tab "CVEs Críticos" de /hunt para
   * mostrar un ranking real, en vez del feed per-evento de critical_cves_24h
   * (que sigue siendo el query usado por WazuhIntelligence).
   */
  "lh.wazuh.critical_cves_aggregated_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuh.criticalCvesAggregated24h(p.limit),
  },
  "lh.wazuh.critical_cve_hosts_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuh.criticalCveHosts24h(p.limit),
  },
  // B1 audit Casos 2026-05-21: CVEs del Wazuh vulnerability-detector
  // filtrados por host (agent.name o IP) — alimenta el panel del caso.
  "lh.wazuh.cves_for_host": {
    params: z.object({
      host_name: z.string().max(255).optional().nullable(),
      host_ip:   z.string().max(45).optional().nullable(),
      days:      z.coerce.number().int().min(1).max(90).default(7),
      limit:     z.coerce.number().int().min(1).max(500).default(100),
    }).refine((p) => p.host_name || p.host_ip, {
      message: "host_name o host_ip es requerido",
    }),
    build: (p, c) => c.wazuh.cvesForHost(p.host_name, p.host_ip, p.days, p.limit),
  },
  "lh.wazuh.recent_lines": {
    params: limitMinutesSchema,
    build: (p, c) => c.wazuh.recentLines(p.limit, p.minutes),
  },
  // ── Caza sobre hunting.wazuh_alerts (Manager :9014 → lake) ─────────────────
  "lh.wazuh_alerts.hunt_severity_buckets_24h": {
    params: empty,
    build: (_, c) => c.wazuhAlertsHunt.severityBuckets24h(),
  },
  "lh.wazuh_alerts.hunt_top_rules_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.topRules24h(p.limit),
  },
  "lh.wazuh_alerts.hunt_top_srcip_month": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.topSrcIpCurrentMonth(p.limit),
  },
  "lh.wazuh_alerts.hunt_critical_sample": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.criticalSample(p.limit),
  },
  "lh.wazuh_alerts.hunt_ssh_5710": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.sshInvalidUser5710(p.limit),
  },
  "lh.wazuh_alerts.hunt_ssh_invalid_users": {
    params: z.object({
      hours: z.coerce.number().int().min(1).max(720).default(24),
      limit: z.coerce.number().int().min(1).max(500).default(200),
    }),
    build: (p, c) => c.wazuhAlertsHunt.sshInvalidUsersAggregated(p.hours, p.limit),
  },
  "lh.wazuh_alerts.hunt_by_hour_today": {
    params: empty,
    build: (_, c) => c.wazuhAlertsHunt.alertsByHourToday(),
  },
  "lh.wazuh_alerts.hunt_top_agents_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.topAgents24h(p.limit),
  },
  "lh.wazuh_alerts.active_agents_24h": {
    params: limitOnlySchema,
    // MV-backed (wazuh_agent_hourly) — antes c.wazuhAlertsHunt.activeAgents24h
    // re-parseaba el blob raw (~108s → timeout 60s, rompía el autodescubrimiento).
    build: (p, c) => c.wazuh.activeAgents24h(p.limit),
  },
  "lh.wazuh_alerts.hunt_mitre_credential": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.mitreCredentialHunt(p.limit),
  },
  "lh.wazuh_alerts.hunt_pam_dstuser_5501": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.pamDstUser5501(p.limit),
  },
  "lh.wazuh_alerts.hunt_new_srcip_6h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.newSrcIpLast6h(p.limit),
  },
  // ── Diagnóstico wazuh_alerts ─────────────────────────────────────────────
  "lh.wazuh_alerts.diag_any_row": {
    params: empty,
    build: (_, c) => c.wazuhAlertsHunt.diagAnyRow(),
  },
  "lh.wazuh_alerts.diag_count_recent": {
    params: z.object({ days: z.coerce.number().int().min(1).max(30).default(3) }),
    build: (p, c) => c.wazuhAlertsHunt.diagCountRecent(p.days),
  },
  "lh.wazuh_alerts.diag_ssh_rules_raw": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.diagSshRulesRaw(p.limit),
  },
  "lh.wazuh_alerts.diag_top_rule_ids_today": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhAlertsHunt.diagTopRuleIdsToday(p.limit),
  },
  "lh.wazuh_alerts.hunt_auditd_commands": {
    params: z.object({
      hours: z.coerce.number().int().min(1).max(720).default(24),
      limit: z.coerce.number().int().min(1).max(500).default(100),
    }),
    build: (p, c) => c.wazuhAlertsHunt.auditdCommands(p.hours, p.limit),
  },
  "lh.wazuh_alerts.hunt_auditd_commands_agg": {
    params: z.object({
      hours: z.coerce.number().int().min(1).max(720).default(24),
      limit: z.coerce.number().int().min(1).max(500).default(100),
    }),
    build: (p, c) => c.wazuhAlertsHunt.auditdCommandsAggregated(p.hours, p.limit),
  },
  // ── SOC MITRE — tablas ioc_* (materializar con scripts/run-soc-mitre-hunts.sh) ──
  "lh.soc.ioc_port_scanners": {
    params: limitOnlySchema,
    build: (p, c) => c.soc.iocPortScannersPreview(p.limit),
  },
  "lh.soc.ioc_initial_access_attempts": {
    params: limitOnlySchema,
    build: (p, c) => c.soc.iocInitialAccessPreview(p.limit),
  },
  "lh.soc.ioc_persistent_connections": {
    params: limitOnlySchema,
    build: (p, c) => c.soc.iocPersistentPreview(p.limit),
  },
  "lh.soc.ioc_defense_evasion_udp": {
    params: limitOnlySchema,
    build: (p, c) => c.soc.iocUdpPreview(p.limit),
  },
  "lh.soc.ioc_credential_stuffing": {
    params: limitOnlySchema,
    build: (p, c) => c.soc.iocCredentialStuffingPreview(p.limit),
  },
  "lh.soc.ioc_lateral_movement": {
    params: limitOnlySchema,
    build: (p, c) => c.soc.iocLateralMovementPreview(p.limit),
  },
  // ── Syslog Iceberg (hito 2) — minio_iceberg.hunting.syslog_events ────────
  "lh.syslog_ice.kpis": {
    params: daysSchema,
    build: (p, c) => c.syslogIce.kpis(p.days),
  },
  "lh.syslog_ice.top_blocked_ips": {
    params: limitHoursSchema,
    build: (p, c) => c.syslogIce.topBlockedIps(p.hours, p.limit),
  },
  "lh.syslog_ice.blocks_by_hour_24h": {
    params: empty,
    build: (_, c) => c.syslogIce.blocksByHour24h(),
  },
  "lh.syslog_ice.top_attacked_ports": {
    params: limitHoursSchema,
    build: (p, c) => c.syslogIce.topAttackedPorts(p.hours, p.limit),
  },
  "lh.syslog_ice.blocks_by_day": {
    params: daysSchema,
    build: (p, c) => c.syslogIce.blocksByDay(p.days),
  },
  "lh.syslog_ice.events_by_host": {
    params: limitDaysSchema,
    build: (p, c) => c.syslogIce.eventsByHost(p.days, p.limit),
  },
  "lh.syslog_ice.row_count": {
    params: daysSchema,
    build: (p, c) => c.syslogIce.rowCount(p.days),
  },
  // ── Hunting enrichment — enriched_ioc + vt_results (Iceberg) ─────────────
  "lh.hunting.enriched_kpis": {
    params: daysSchema,
    build: (p, c) => c.hunting.enrichedKpis(p.days),
  },
  "lh.hunting.enriched_daily_trend": {
    params: daysSchema,
    build: (p, c) => c.hunting.enrichedDailyTrend(p.days),
  },
  "lh.hunting.enriched_source_breakdown": {
    params: daysSchema,
    build: (p, c) => c.hunting.enrichedSourceBreakdown(p.days),
  },
  "lh.hunting.enriched_score_buckets": {
    params: daysSchema,
    build: (p, c) => c.hunting.enrichedScoreBuckets(p.days),
  },
  "lh.hunting.enriched_vt_coverage": {
    params: daysSchema,
    build: (p, c) => c.hunting.enrichedVtCoverage(p.days),
  },
  "lh.hunting.enriched_vt_top_sample": {
    params: limitDaysSchema,
    build: (p, c) => c.hunting.enrichedVtTopSample(p.limit, p.days),
  },
  "lh.hunting.enriched_cb_failed": {
    params: daysSchema,
    build: (p, c) => c.hunting.enrichedCbFailed(p.days),
  },
  // ── Incident Classification — v_incident_score (Iceberg) ─────────────────
  "lh.incidents.kpis": {
    params: daysSchema,
    build: (p, c) => c.incidents.kpis(p.days),
  },
  "lh.incidents.top": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.topIncidents(p.limit, p.days),
  },
  "lh.incidents.live_top_v2": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.liveTopIncidentsV2(p.limit, p.days),
  },
  /** Versión materializada — tabla física Iceberg generada por el DAG diario.
   *  Usar este ID en el dashboard una vez ejecutado t_materialize_score_v2 al menos 1 vez.
   *  Latencia objetivo: <300 ms vs 5-15 s de la vista. */
  "lh.incidents.live_top_v2_mat": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.liveTopIncidentsV2Mat(p.limit, p.days),
  },
  "lh.incidents.by_severity": {
    params: daysSchema,
    build: (p, c) => c.incidents.bySeverity(p.days),
  },
  "lh.incidents.daily_trend": {
    params: daysSchema,
    build: (p, c) => c.incidents.dailyTrend(p.days),
  },
  "lh.incidents.score_components": {
    params: daysSchema,
    build: (p, c) => c.incidents.scoreComponents(p.days),
  },
  "lh.incidents.score_breakdown": {
    params: ipHoursSchema,
    build: (p, c) => c.incidents.scoreBreakdown(p.ip),
  },
  "lh.incidents.score_multipliers": {
    params: ipHoursSchema,
    build: (p, c) => c.incidents.scoreMultipliers(p.ip),
  },
  "lh.incidents.saved_classifications": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.savedClassifications(p.limit, p.days),
  },
  "lh.incidents.analysis_flow": {
    params: daysOnlySchema,
    build: (p, c) => c.incidents.analysisFlow(p.days),
  },
  "lh.incidents.scoring_formula_history": {
    params: limitOnlySchema,
    build: (p, c) => c.incidents.scoringFormulaHistory(p.limit),
  },
  "lh.chat.top_attacked_hosts": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.chatTopAttackedHosts(p.limit, p.days),
  },
  "lh.chat.highest_cves": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.chatHighestCves(p.limit, p.days),
  },
  "lh.chat.top_attacker_ips": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.chatTopAttackerIps(p.limit, p.days),
  },
  "lh.chat.business_most_attacked": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.chatBusinessMostAttacked(p.limit, p.days),
  },
  "lh.chat.recent_critical": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.chatRecentCritical(p.limit, p.days),
  },
  "lh.chat.top_source_countries": {
    params: limitDaysSeveritySchema,
    build: (p, c) => c.incidents.chatTopSourceCountries(p.limit, p.days, p.severityMin),
  },
  "lh.chat.top_mitre_tactics": {
    params: limitDaysSeveritySchema,
    build: (p, c) => c.incidents.chatTopMitreTactics(p.limit, p.days, p.severityMin),
  },
  "lh.chat.top_source_logs": {
    params: limitDaysSeveritySchema,
    build: (p, c) => c.incidents.chatTopSourceLogs(p.limit, p.days, p.severityMin),
  },
  "lh.chat.fortigate_vpn_logins": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.chatFortigateVpnLogins(p.limit, p.days),
  },
  // ── Outlier Detection (docs/OUTLIER-DETECTION.md) ────────────────────────
  "lh.outliers.last_window": {
    params: outlierListSchema,
    build: (p, c) => c.outliers.lastWindow(p),
  },
  "lh.outliers.summary_24h": {
    params: empty,
    build: (_, c) => c.outliers.summary24h(),
  },
  "lh.outliers.summary_window": {
    params: outlierListSchema.omit({ limit: true }),
    build: (p, c) => c.outliers.summaryWindow(p),
  },
  "lh.outliers.by_log_family": {
    params: outlierDaysOnlySchema,
    build: (p, c) => c.outliers.byLogFamily(p),
  },
  "lh.outliers.top_entities": {
    params: outlierTopEntitiesSchema,
    build: (p, c) => c.outliers.topEntities(p),
  },
  "lh.outliers.for_ioc": {
    params: outlierForIocSchema,
    build: (p, c) => c.outliers.forIoc(p),
  },
  "lh.incidents.adopted": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.adoptedIncidents(p.limit, p.days),
  },
  "lh.incidents.managed": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.managedIncidents(p.limit, p.days),
  },
  "lh.incidents.open_severe_unadopted": {
    params: daysSchema,
    build: (p, c) => c.incidents.openSevereUnadoptedCount(p.days),
  },
  "lh.incidents.response_metrics": {
    params: daysSchema,
    build: (p, c) => c.incidents.responseMetrics(p.days),
  },
  "lh.incidents.fp_candidates": {
    params: daysSchema,
    build: (p, c) => c.incidents.fpCandidates(p.days),
  },
  /** Patrones en casos abiertos: pública vs interna, fuentes, MITRE, categorías. */
  "lh.incidents.patterns": {
    params: daysSchema,
    build: (p, c) => c.incidents.casePatterns(p.days),
  },
  /** Candidatos a duplicado: misma ioc_value con múltiples case_ids activos. */
  "lh.incidents.duplicates": {
    params: daysSchema,
    build: (p, c) => c.incidents.duplicateCandidates(p.days),
  },
  /** Desglose scoring gap público vs interno — explica por qué IPs internas puntúan bajo. */
  "lh.incidents.internal_vs_public": {
    params: daysSchema,
    build: (p, c) => c.incidents.internalVsPublicBreakdown(p.days),
  },
  "lh.incidents.pending_auto_process": {
    params: daysSchema,
    build: (p, c) => c.incidents.pendingAutoProcess(p.days),
  },
  "lh.incidents.soc_metrics": {
    params: daysSchema,
    build: (p, c) => c.incidents.socMetrics(p.days),
  },
  "lh.incidents.mttd": {
    params: daysSchema,
    build: (p, c) => c.incidents.mttdMultiSensor(p.days),
  },
  // ── Scoring v4 — bonos Trino-native: kill-chain + temporal + geo-risk ────
  /** KPIs de scoring v4: distribución severity_v4, avg_score_v4, uplift promedio,
   *  conteo de IOCs con cada tipo de bono activo. */
  "lh.incidents.kpis_v4": {
    params: daysSchema,
    build: (p, c) => c.incidents.kpisV4(p.days),
  },
  /** Top N incidentes por score_v4 — incluye campos de bonus para desglose. */
  "lh.incidents.live_top_v4_mat": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.liveTopIncidentsV4Mat(p.limit, p.days),
  },
  /** Distribución severity_v4 vs severity_base — compara v4 con v3 (base). */
  "lh.incidents.by_severity_v4": {
    params: daysSchema,
    build: (p, c) => c.incidents.bySeverityV4(p.days),
  },
  /** IOCs donde los bonos v4 modificaron el score — auditoría de impacto. */
  "lh.incidents.bonus_breakdown": {
    params: daysSchema,
    build: (p, c) => c.incidents.bonusBreakdown(p.days),
  },
  /** Top sensores por volumen de IOCs (enriched_ioc.sensor_host).
   *  Desglose por source_log — útil para identificar el sensor más activo. */
  "lh.incidents.by_sensor": {
    params: limitDaysSchema,
    build: (p, c) => c.incidents.bySensor(p.days, p.limit),
  },
  /** Timeline diario de IOCs para un sensor específico.
   *  Params: sensor (hostname/IP), days. */
  "lh.incidents.sensor_timeline": {
    params: sensorDaysSchema,
    build: (p, c) => c.incidents.sensorTimeline(p.sensor, p.days),
  },
  // ── VPN — OPNsense OpenVPN / IPsec / WireGuard ───────────────────────────
  "lh.syslog.vpn_events_24h": {
    params: empty,
    build: (_, c) => c.syslog.vpnEventsLast24h(),
  },
  "lh.syslog.vpn_connections": {
    params: limitHoursSchema,
    build: (p, c) => c.syslog.vpnConnectionEvents(p.limit, p.hours),
  },
  "lh.syslog.vpn_failed_auth_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.syslog.vpnFailedAuthLast24h(p.limit),
  },
  "lh.syslog.vpn_by_hour_24h": {
    params: empty,
    build: (_, c) => c.syslog.vpnEventsByHour24h(),
  },
  // ── Wazuh Fluent — minio.hunting.wazuh_fluent (Fluent Bit → Vector :24224) ──
  "lh.wazuh_fluent.kpis_24h": {
    params: empty,
    build: (_, c) => c.wazuhFluent.kpis24h(),
  },
  // KPIs 24h del Resumen sobre el canal VIVO wazuh_alerts (mismo shape que
  // wazuh_fluent.kpis_24h). Usado por DetectionOverview cuando Fluent Bit no
  // alimenta wazuh_fluent. Ver wazuh-sql.mjs::kpis24hOverview.
  "lh.wazuh_alerts.kpis_24h": {
    params: empty,
    build: (_, c) => c.wazuh.kpis24hOverview(),
  },
  "lh.wazuh_fluent.severity_buckets_24h": {
    params: empty,
    build: (_, c) => c.wazuhFluent.severityBuckets24h(),
  },
  "lh.wazuh_fluent.top_rules_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhFluent.topRules24h(p.limit),
  },
  "lh.wazuh_fluent.top_agents_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhFluent.topAgents24h(p.limit),
  },
  "lh.wazuh_fluent.alerts_by_hour_today": {
    params: empty,
    build: (_, c) => c.wazuhFluent.alertsByHourToday(),
  },
  "lh.wazuh_fluent.manager_nodes_24h": {
    params: empty,
    build: (_, c) => c.wazuhFluent.managerNodes24h(),
  },
  // ── Suricata IDS — minio.hunting.syslog WHERE log_family LIKE 'suricata_%' ─
  "lh.suricata.kpis_24h": {
    params: empty,
    build: (_, c) => c.suricata.kpis24h(),
  },
  "lh.suricata.top_signatures_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.suricata.topSignatures24h(p.limit),
  },
  "lh.suricata.top_attackers_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.suricata.topAttackers24h(p.limit),
  },
  "lh.suricata.top_ports_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.suricata.topTargetedPorts24h(p.limit),
  },
  "lh.suricata.alerts_by_hour_24h": {
    params: empty,
    build: (_, c) => c.suricata.alertsByHour24h(),
  },
  "lh.suricata.severity_distribution_24h": {
    params: empty,
    build: (_, c) => c.suricata.severityDistribution24h(),
  },
  "lh.suricata.recent_alerts": {
    params: limitOnlySchema,
    build: (p, c) => c.suricata.recentAlerts(p.limit),
  },

  /**
   * Variantes materializadas (audit 2026-06-10). Leen de las tablas Iceberg
   * `suricata_kpis_hourly` / `suricata_sig_hourly` / `suricata_port_hourly` /
   * `suricata_top_attackers_daily`, refrescadas cada 30 min vía DAG
   * `suricata_summary_refresh_30min` (SQL `55_mv_suricata_summary_hourly`).
   * Antes TODO el batch costaba ~6-8s (parsing JSON sobre ~300k alertas).
   * Shape de salida idéntico al live.
   *
   * Aproximaciones:
   *   - COUNT(DISTINCT) de kpis/firmas/categorías/puertos vía HyperLogLog
   *     mergeable (~1.6% error).
   *   - top_attackers: SUM de los distinct diarios (over-counta el tail entre
   *     2 días; irrelevante para top-N). Sólo top-500 IPs/día materializadas.
   */
  "lh.suricata.kpis_24h_mat": {
    params: empty,
    build: () => `
SELECT
  SUM(total_alerts)                                                AS total_alerts,
  cardinality(merge(CAST(hll_src_ip    AS HyperLogLog)))           AS unique_src_ips,
  cardinality(merge(CAST(hll_signature AS HyperLogLog)))           AS unique_signatures,
  cardinality(merge(CAST(hll_dest_port AS HyperLogLog)))           AS unique_ports_targeted
FROM minio_iceberg.hunting.suricata_kpis_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
`.trim(),
  },
  "lh.suricata.alerts_by_hour_24h_mat": {
    params: empty,
    build: () => `
SELECT
  date_format(hour_ts, '%H:00')                            AS hour,
  total_alerts                                             AS alerts,
  cardinality(CAST(hll_src_ip AS HyperLogLog))             AS unique_ips
FROM minio_iceberg.hunting.suricata_kpis_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
ORDER BY hour_ts ASC
`.trim(),
  },
  "lh.suricata.top_signatures_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  signature,
  category,
  severity,
  SUM(hits)                                                AS hits,
  cardinality(merge(CAST(hll_src_ip AS HyperLogLog)))      AS unique_attackers
FROM minio_iceberg.hunting.suricata_sig_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY signature, category, severity
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.suricata.top_categories_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  category,
  SUM(hits)                                                AS hits,
  cardinality(merge(CAST(hll_src_ip AS HyperLogLog)))      AS unique_attackers,
  MIN(severity)                                            AS min_severity,
  MAX(severity)                                            AS max_severity
FROM minio_iceberg.hunting.suricata_sig_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY category
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.suricata.severity_distribution_24h_mat": {
    params: empty,
    build: () => `
SELECT
  severity,
  SUM(hits)                                                AS hits
FROM minio_iceberg.hunting.suricata_sig_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY severity
ORDER BY severity ASC
`.trim(),
  },
  "lh.suricata.top_ports_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  CAST(dest_port AS VARCHAR)                               AS dest_port,
  proto,
  SUM(hits)                                                AS hits,
  cardinality(merge(CAST(hll_src_ip AS HyperLogLog)))      AS unique_attackers
FROM minio_iceberg.hunting.suricata_port_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY dest_port, proto
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.suricata.top_attackers_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  src_ip,
  SUM(hits)                                                AS hits,
  SUM(unique_sigs)                                         AS unique_sigs,
  SUM(unique_ports)                                        AS unique_ports
FROM minio_iceberg.hunting.suricata_top_attackers_daily
WHERE dt >= current_date - INTERVAL '1' DAY
GROUP BY src_ip
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  /**
   * Feed de alertas recientes materializado (top-500 por ts, refresh 30 min).
   * El live (recentAlerts) parseaba JSON + sort (~6.5s) y gateaba la página.
   * Trade-off: frescura ≤ 30 min.
   */
  "lh.suricata.recent_alerts_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  ts, src_ip, dest_ip, dest_port, proto, signature, category, severity, action
FROM minio_iceberg.hunting.suricata_recent_alerts
ORDER BY ts DESC
LIMIT ${p.limit}
`.trim(),
  },

  // ── Fortigate UTM/Firewall — minio.hunting.fortigate ───────────────────────
  // MV-backed (2026-06-14): la versión live escaneaba la tabla raw `fortigate`
  // (~6.7M filas/24h) → ~115 s → superaba TRINO_QUERY_TOTAL_TIMEOUT_MS y colgaba
  // el batch del Resumen (DetectionOverview), dejando las 6 tarjetas en
  // "actualizando". Este id lo consume SOLO el Resumen, que tolera 15 min de
  // staleness; se repunta al mismo agregado horario que `lh.fg.kpis_24h_mat`
  // (DAG fortigate_summary_refresh_15min). Shape idéntico al live. El método
  // live `c.fortigate.kpis24h()` sigue disponible para usos que requieran tiempo
  // real puntual.
  "lh.fg.kpis_24h": {
    params: empty,
    build: () => `
SELECT
  SUM(total_events)                                                       AS total_events,
  SUM(blocked)                                                            AS blocked,
  SUM(allowed)                                                            AS allowed,
  cardinality(merge(CAST(hll_attacker_ips AS HyperLogLog)))               AS unique_attacker_ips,
  cardinality(merge(CAST(hll_dest_ports   AS HyperLogLog)))               AS unique_dest_ports,
  cardinality(merge(CAST(hll_devices      AS HyperLogLog)))               AS unique_devices
FROM minio_iceberg.hunting.fortigate_kpis_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
`.trim(),
  },
  "lh.fg.top_blocked_ips_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.fortigate.topBlockedIps24h(p.limit),
  },

  // Autodescubrimiento de sensores: devices FortiGate activos 24h (MV-backed
  // fortigate_events_slim, ~ms). Complementa lh.wazuh_alerts.active_agents_24h
  // y lh.syslog.senders_24h — antes el perfil fortigate (el activo) no se descubría.
  "lh.fortigate.active_devices_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.fortigate.activeDevices24h(p.limit),
  },

  /**
   * Variante materializada: lee de `fortigate_top_blocked_daily`
   * (top-500 IPs bloqueadas por día, refresh 1 h vía DAG
   * `fortigate_top_blocked_refresh_1h`). Shape idéntico al live.
   *
   * Aproximaciones:
   *   - `ports_targeted`: SUM de los COUNT(DISTINCT) diarios (over-count
   *     si la misma IP repite los mismos puertos en 2 días).
   *   - IPs que caen del top-500 algún día quedan fuera del agregado de
   *     ese día. Top-N (<=20) no se ve afectado en la práctica.
   */
  "lh.fg.top_blocked_ips_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  src_ip,
  SUM(hits)                                                                AS hits,
  SUM(ports_targeted)                                                      AS ports_targeted,
  MAX(last_seen)                                                           AS last_seen,
  max_by(top_proto, last_seen)                                             AS top_proto,
  max_by(top_type,  last_seen)                                             AS top_type
FROM minio_iceberg.hunting.fortigate_top_blocked_daily
WHERE dt >= current_date - INTERVAL '1' DAY
  AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY src_ip
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.fg.top_dest_ports_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.fortigate.topDestPorts24h(p.limit),
  },
  "lh.fg.top_dest_ports_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  port                                                     AS dest_port,
  proto,
  SUM(total)                                               AS hits,
  cardinality(merge(CAST(hll_src_ip AS HyperLogLog)))      AS unique_src_ips
FROM minio_iceberg.hunting.fortigate_port_hourly
WHERE port_kind = 'dst'
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY port, proto
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.fg.top_src_ports_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  port                                                     AS src_port,
  proto,
  SUM(total)                                               AS hits,
  cardinality(merge(CAST(hll_src_ip AS HyperLogLog)))      AS unique_src_ips,
  SUM(blocked)                                             AS blocked
FROM minio_iceberg.hunting.fortigate_port_hourly
WHERE port_kind = 'src'
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY port, proto
ORDER BY hits DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.fg.by_action_24h": {
    params: empty,
    build: (_, c) => c.fortigate.byAction24h(),
  },
  "lh.fg.by_type_24h": {
    params: empty,
    build: (_, c) => c.fortigate.byType24h(),
  },
  "lh.fg.events_by_hour_24h": {
    params: empty,
    build: (_, c) => c.fortigate.eventsByHour24h(),
  },
  "lh.fg.by_device_24h": {
    params: empty,
    build: (_, c) => c.fortigate.byDevice24h(),
  },
  "lh.fg.by_proto_24h": {
    params: empty,
    build: (_, c) => c.fortigate.byProto24h(),
  },

  /**
   * Variantes materializadas (audit 2026-06-10). Leen de las tablas Iceberg
   * `fortigate_kpis_hourly` (grano hour_ts) y `fortigate_dim_hourly`
   * (grano hour_ts, dim_kind, dim_value), refrescadas cada 15 min vía DAG
   * `fortigate_summary_refresh_15min` (SQL `54_mv_fortigate_summary_hourly`).
   * Filtran `hour_ts >= now - 24h` → ventana 24h rodante EXACTA. Reemplazan
   * los full-scan de la tabla cruda que dominaban la latencia de la página
   * (kpis 24.5s · by_type 15.7s · by_device 11.1s · events_by_hour 7.3s ·
   * by_action 5.5s). Shape de salida idéntico al live.
   *
   * Aproximación: los COUNT(DISTINCT) de kpis se sirven vía HyperLogLog
   * mergeable (~1.6% error) en vez de exacto. Aceptable para KPIs indicador.
   */
  "lh.fg.kpis_24h_mat": {
    params: empty,
    build: () => `
SELECT
  SUM(total_events)                                                       AS total_events,
  SUM(blocked)                                                            AS blocked,
  SUM(allowed)                                                            AS allowed,
  cardinality(merge(CAST(hll_attacker_ips AS HyperLogLog)))               AS unique_attacker_ips,
  cardinality(merge(CAST(hll_dest_ports   AS HyperLogLog)))               AS unique_dest_ports,
  cardinality(merge(CAST(hll_devices      AS HyperLogLog)))               AS unique_devices
FROM minio_iceberg.hunting.fortigate_kpis_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
`.trim(),
  },
  "lh.fg.events_by_hour_24h_mat": {
    params: empty,
    build: () => `
SELECT
  date_format(hour_ts, '%H:00')                            AS hour,
  total_events                                             AS total,
  blocked,
  allowed
FROM minio_iceberg.hunting.fortigate_kpis_hourly
WHERE hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
ORDER BY hour_ts
`.trim(),
  },
  "lh.fg.by_action_24h_mat": {
    params: empty,
    build: () => `
SELECT
  dim_value                                AS action,
  SUM(total)                               AS total
FROM minio_iceberg.hunting.fortigate_dim_hourly
WHERE dim_kind = 'action'
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY dim_value
ORDER BY total DESC
`.trim(),
  },
  "lh.fg.by_type_24h_mat": {
    params: empty,
    build: () => `
SELECT
  dim_value                                AS log_family,
  SUM(total)                               AS total,
  SUM(blocked)                             AS blocked
FROM minio_iceberg.hunting.fortigate_dim_hourly
WHERE dim_kind = 'type'
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY dim_value
ORDER BY total DESC
LIMIT 20
`.trim(),
  },
  "lh.fg.by_device_24h_mat": {
    params: empty,
    build: () => `
SELECT
  dim_value                                AS device,
  SUM(total)                               AS total,
  SUM(blocked)                             AS blocked,
  SUM(allowed)                             AS allowed
FROM minio_iceberg.hunting.fortigate_dim_hourly
WHERE dim_kind = 'device'
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY dim_value
ORDER BY total DESC
LIMIT 20
`.trim(),
  },
  "lh.fg.by_proto_24h_mat": {
    params: empty,
    build: () => `
SELECT
  dim_value                                AS proto,
  SUM(total)                               AS total,
  SUM(blocked)                             AS blocked
FROM minio_iceberg.hunting.fortigate_dim_hourly
WHERE dim_kind = 'proto'
  AND hour_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY dim_value
ORDER BY total DESC
LIMIT 15
`.trim(),
  },
  /**
   * Feed de eventos recientes materializado (top-500 por ts, refrescado cada
   * 15 min). El live (recentEvents) ordenaba sobre el scan 24h crudo (~5.2s) y
   * gateaba la página. Trade-off: frescura ≤ 15 min.
   */
  "lh.fg.recent_events_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  ts, src_ip, dest_ip, dest_port, proto, action, log_family, level, device
FROM minio_iceberg.hunting.fortigate_recent_events
ORDER BY ts DESC
LIMIT ${p.limit}
`.trim(),
  },
  "lh.fg.recent_events": {
    params: limitOnlySchema,
    build: (p, c) => c.fortigate.recentEvents(p.limit),
  },

  // ── InfraGOVPY v2 (2026-04-17) ────────────────────────────────────────────
  // Rediseño: ya no consumimos la lista GitHub pública. La plataforma genera
  // su propia lista de IPs maliciosas desde nuestro scoring interno y la
  // expone en la tab /intel?tab=infragovpy con descarga CSV + push diario.
  //
  // Fuentes:
  //   - minio_iceberg.hunting.incident_cases  (scoring unificado v4)
  //   - minio_iceberg.hunting.business_ip_tags (allowlist corporativa)
  //
  // Criterio de inclusión:
  //   - ioc_type='ip' + IP pública (no RFC1918/loopback/link-local)
  //   - last_seen dentro de la ventana (default 24 h)
  //   - severity CRITICAL/HIGH  OR  severity_score ≥ 60
  //   - NO en business_ip_tags con enabled=true (allowlist)
  // ---------------------------------------------------------------------------
  "lh.infragovpy.malicious_24h": {
    params: z.object({
      hours: z.coerce.number().int().min(1).max(168).default(24),
      limit: z.coerce.number().int().min(1).max(5000).default(500),
    }),
    build: (p) => `
      WITH allow AS (
        SELECT DISTINCT source_ip FROM minio_iceberg.hunting.business_ip_tags
         WHERE enabled = true
      )
      SELECT
        ic.ioc_value                                       AS ip,
        MAX(ic.severity_score)                             AS score,
        MAX(ic.severity_text)                              AS severity,
        MAX(ic.mitre_tactic_id)                            AS mitre_tactic_id,
        MAX(ic.mitre_tactic_name)                          AS mitre_tactic_name,
        COUNT(*)                                           AS case_count,
        SUM(COALESCE(ic.occurrence_count, 1))              AS occurrences,
        MIN(ic.first_seen)                                 AS first_seen,
        MAX(ic.last_seen)                                  AS last_seen,
        MAX(ic.source_log)                                 AS source_log,
        MAX(ic.mitre_technique_id)                         AS mitre_technique_id
      FROM minio_iceberg.hunting.incident_cases ic
      LEFT JOIN allow a ON a.source_ip = ic.ioc_value
      WHERE ic.ioc_type = 'ip'
        AND a.source_ip IS NULL
        AND ic.last_seen >= current_timestamp - INTERVAL '${p.hours}' HOUR
        AND (ic.severity_text IN ('CRITICAL','HIGH') OR ic.severity_score >= 60)
        AND NOT regexp_like(
          ic.ioc_value,
          '^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|127\\.|169\\.254\\.|0\\.|fe80::|::1)'
        )
      GROUP BY ic.ioc_value
      ORDER BY score DESC, last_seen DESC
      LIMIT ${p.limit}
    `,
  },
  "lh.infragovpy.kpis_24h": {
    params: z.object({
      hours: z.coerce.number().int().min(1).max(168).default(24),
    }),
    build: (p) => `
      WITH allow AS (
        SELECT DISTINCT source_ip FROM minio_iceberg.hunting.business_ip_tags
         WHERE enabled = true
      ),
      flagged AS (
        SELECT
          ic.ioc_value                                     AS ip,
          MAX(ic.severity_score)                           AS score,
          MAX(ic.severity_text)                            AS severity
        FROM minio_iceberg.hunting.incident_cases ic
        LEFT JOIN allow a ON a.source_ip = ic.ioc_value
        WHERE ic.ioc_type = 'ip'
          AND a.source_ip IS NULL
          AND ic.last_seen >= current_timestamp - INTERVAL '${p.hours}' HOUR
          AND (ic.severity_text IN ('CRITICAL','HIGH') OR ic.severity_score >= 60)
          AND NOT regexp_like(
            ic.ioc_value,
            '^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|127\\.|169\\.254\\.|0\\.|fe80::|::1)'
          )
        GROUP BY ic.ioc_value
      )
      SELECT
        COUNT(*)                                              AS total,
        COUNT(*) FILTER (WHERE severity = 'CRITICAL')         AS critical,
        COUNT(*) FILTER (WHERE severity = 'HIGH')             AS high,
        COUNT(*) FILTER (WHERE severity = 'MEDIUM')           AS medium,
        CAST(AVG(score) AS integer)                           AS avg_score,
        MAX(score)                                            AS max_score
      FROM flagged
    `,
  },
  /**
   * Cobertura por fuente — transparencia del pipeline. Muestra, para cada
   * source_log, cuántos IOCs/casos hay y cuántos pasan el umbral del feed.
   * Útil para entender por qué una fuente aparente (p. ej. Suricata) no se
   * ve en el feed — puede ser tema de opening_profiles, no del feed.
   */
  /**
   * IOC deep-analysis: volumen diario (enriched_ioc + incident_cases)
   * para pintar la serie temporal en el panel Hunting.
   */
  /**
   * IOC deep-analysis: historial de casos en SOC para el IOC.
   * Fuente: incident_cases (Iceberg — sincronizado desde PG por el
   * reconcile DAG cada 30 min; drift ≤30 min aceptable).
   */
  "lh.ioc.analysis_cases_history": {
    params: z.object({
      ioc:  z.string().min(4).max(200),
      days: z.coerce.number().int().min(1).max(365).default(90),
    }),
    build: (p) => `
      SELECT
        case_id,
        severity_text   AS severity,
        severity_score  AS score,
        status,
        assigned_to     AS operator,
        mitre_tactic_id,
        mitre_tactic_name,
        mitre_technique_id,
        source_log,
        occurrence_count,
        CAST(created_at AS varchar) AS created_at,
        CAST(adopted_at AS varchar) AS adopted_at,
        CAST(last_seen  AS varchar) AS last_seen,
        closure_reason
      FROM minio_iceberg.hunting.incident_cases
      WHERE ioc_value = ${sq(p.ioc)}
        AND anchor_dt >= current_date - INTERVAL '${p.days}' DAY
      ORDER BY created_at DESC
      LIMIT 20
    `,
  },
  "lh.ioc.analysis_volume_daily": {
    params: z.object({
      ioc:  z.string().min(4).max(200),
      days: z.coerce.number().int().min(1).max(60).default(14),
    }),
    build: (p) => `
      WITH enr AS (
        SELECT dt, source_log, alert_count
        FROM minio_iceberg.hunting.enriched_ioc
        WHERE ioc_value = ${sq(p.ioc)}
          AND dt >= current_date - INTERVAL '${p.days}' DAY
      )
      SELECT
        CAST(dt AS varchar) AS dt,
        COALESCE(NULLIF(source_log, ''), '(none)') AS source_log,
        SUM(alert_count)                            AS events,
        COUNT(*)                                    AS ioc_rows
      FROM enr
      GROUP BY 1, 2
      ORDER BY 1 DESC, events DESC
    `,
  },

  /**
   * IOC deep-analysis: sample raw Wazuh (con partition pruning).
   * Devuelve primeras 5 filas cuyo message contenga el IOC.
   */
  "lh.ioc.analysis_raw_sample": {
    params: z.object({
      ioc:  z.string().min(4).max(200),
      days: z.coerce.number().int().min(1).max(60).default(7),
    }),
    build: (p) => {
      // Enumerar (year, month, day) del rango para partition filter
      const todayUtc = new Date();
      const keys = [];
      for (let offset = 0; offset < Math.min(p.days, 60); offset++) {
        const x = new Date(todayUtc.getTime() - offset * 86400_000);
        const y  = String(x.getUTCFullYear());
        const mo = String(x.getUTCMonth() + 1).padStart(2, "0");
        const d  = String(x.getUTCDate()).padStart(2, "0");
        keys.push(`(year=${sq(y)} AND month=${sq(mo)} AND day=${sq(d)})`);
      }
      const partFilter = keys.join(" OR ");
      return `
        SELECT
          "timestamp"                AS ts,
          source_ip                  AS sensor,
          hostname                   AS agent,
          substr(message, 1, 400)    AS msg_preview
        FROM minio.hunting.wazuh_alerts
        WHERE (${partFilter})
          AND strpos(message, ${sq(p.ioc)}) > 0
        ORDER BY "timestamp" DESC
        LIMIT 5
      `;
    },
  },

  "lh.infragovpy.source_coverage_7d": {
    params: z.object({
      hours: z.coerce.number().int().min(1).max(168).default(24),
    }),
    build: (p) => `
      WITH enr AS (
        SELECT
          COALESCE(NULLIF(source_log, ''), '(none)') AS source_log,
          COUNT(*)                                   AS iocs
        FROM minio_iceberg.hunting.enriched_ioc
        WHERE dt >= current_date - INTERVAL '7' DAY
        GROUP BY 1
      ),
      cases AS (
        SELECT
          COALESCE(NULLIF(source_log, ''), '(none)') AS source_log,
          COUNT(*)                                                         AS total_cases,
          COUNT(*) FILTER (
            WHERE ioc_type = 'ip' AND last_seen >= current_timestamp - INTERVAL '${p.hours}' HOUR
          )                                                                AS cases_ip_window,
          COUNT(*) FILTER (
            WHERE ioc_type = 'ip'
              AND last_seen >= current_timestamp - INTERVAL '${p.hours}' HOUR
              AND (severity_text IN ('CRITICAL','HIGH') OR severity_score >= 60)
              AND NOT regexp_like(
                ioc_value,
                '^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|127\\.|169\\.254\\.|0\\.|fe80::|::1)'
              )
          )                                                                AS feed_eligible
        FROM minio_iceberg.hunting.incident_cases
        WHERE anchor_dt >= current_date - INTERVAL '7' DAY
        GROUP BY 1
      )
      SELECT
        COALESCE(e.source_log, c.source_log)     AS source_log,
        COALESCE(e.iocs, 0)                       AS enriched_iocs_7d,
        COALESCE(c.total_cases, 0)                AS cases_7d,
        COALESCE(c.cases_ip_window, 0)            AS cases_ip_window,
        COALESCE(c.feed_eligible, 0)              AS feed_eligible
      FROM enr e
      FULL OUTER JOIN cases c ON c.source_log = e.source_log
      ORDER BY feed_eligible DESC, enriched_iocs_7d DESC
    `,
  },
  "lh.infragovpy.source_breakdown_24h": {
    params: z.object({
      hours: z.coerce.number().int().min(1).max(168).default(24),
    }),
    build: (p) => `
      SELECT
        COALESCE(NULLIF(ic.source_log, ''), 'unknown')      AS source_log,
        COALESCE(ic.mitre_tactic_name, '(sin mapeo)')       AS mitre_tactic_name,
        COUNT(DISTINCT ic.ioc_value)                        AS distinct_ips,
        COUNT(*)                                            AS cases,
        CAST(AVG(ic.severity_score) AS integer)             AS avg_score
      FROM minio_iceberg.hunting.incident_cases ic
      WHERE ic.ioc_type = 'ip'
        AND ic.last_seen >= current_timestamp - INTERVAL '${p.hours}' HOUR
        AND (ic.severity_text IN ('CRITICAL','HIGH') OR ic.severity_score >= 60)
        AND NOT regexp_like(
          ic.ioc_value,
          '^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|127\\.|169\\.254\\.|0\\.|fe80::|::1)'
        )
      GROUP BY ic.source_log, ic.mitre_tactic_name
      ORDER BY distinct_ips DESC
      LIMIT 20
    `,
  },

  // ── PMG — Proxmox Mail Gateway (phishing / email security) ──────────────────
  // Tabla: minio.hunting.pmg_phishing  (vista sobre hunting.pmg)
  // Bootstrap: ./scripts/bootstrap-trino-pmg-view.sh
  // Vector: puerto 9025 (TCP/UDP) en la VM pública

  /** KPIs globales de email phishing (últimas 24 h). */
  "lh.pmg.kpis_24h": {
    params: empty,
    build: (_, c) => c.pmg.kpis24h(),
  },

  /** Top N remitentes (IP + dominio) bloqueados o con más eventos. */
  "lh.pmg.top_senders_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.topSenders24h(p.limit),
  },

  /**
   * Variante materializada: lee de `pmg_sender_stats_daily` (refresh 1 h,
   * DAG `pmg_sender_stats_refresh_1h`) y re-agrega por (sender_ip,
   * sender_domain) sobre las últimas 24-48 h (dt >= hoy-1). Shape idéntico
   * al live para ser drop-in.
   *
   * Aproximaciones conocidas:
   *   - `avg_spam_score`: media ponderada por volumen entre días.
   *   - `unique_recipients`: SUM de los COUNT(DISTINCT) diarios (over-count
   *     si un destinatario aparece en dos días).
   */
  "lh.pmg.top_senders_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  sender_ip,
  sender_domain,
  SUM(total_events)                                                        AS total_events,
  SUM(blocked)                                                             AS blocked,
  MAX(max_spam_score)                                                      AS max_spam_score,
  ROUND(CAST(
    SUM(avg_spam_score * total_events) / NULLIF(SUM(total_events), 0)
  AS DOUBLE), 2)                                                           AS avg_spam_score,
  SUM(unique_recipients)                                                   AS unique_recipients,
  BOOL_OR(has_auth_failure)                                                AS has_auth_failure
FROM minio_iceberg.hunting.pmg_sender_stats_daily
WHERE dt >= current_date - INTERVAL '1' DAY
  AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  AND sender_ip IS NOT NULL
  AND sender_ip <> '(desconocida)'
GROUP BY sender_ip, sender_domain
ORDER BY blocked DESC, total_events DESC
LIMIT ${p.limit}
`.trim(),
  },

  /** Timeline de acciones por hora (24 h): blocked / quarantined / accepted. */
  "lh.pmg.actions_by_hour_24h": {
    params: empty,
    build: (_, c) => c.pmg.actionsByHour24h(),
  },

  /** Remitentes con fallos de autenticación DMARC / SPF / DKIM. */
  "lh.pmg.auth_failures_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.authFailures24h(p.limit),
  },

  /** Top blocklists activadas (Spamhaus zen, SBL, DBL, etc.). */
  "lh.pmg.top_blocklists_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.topBlocklists24h(p.limit),
  },

  /** Top URLs sospechosas detectadas en mensajes. */
  "lh.pmg.top_suspicious_urls_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.topSuspiciousUrls24h(p.limit),
  },

  /** Distribución de spam score en buckets (para histograma). */
  "lh.pmg.spam_score_distribution_24h": {
    params: empty,
    build: (_, c) => c.pmg.spamScoreDistribution24h(),
  },

  /** Feed de actividad reciente (últimas N filas de las últimas 24 h). */
  "lh.pmg.recent_events": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.recentEvents(p.limit),
  },

  /** Desglose por proceso PMG (postfix/smtpd, pmg-smtp-filter, opendkim, etc.). */
  "lh.pmg.by_process_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.byProcess24h(p.limit),
  },

  /** Tendencia diaria de eventos PMG (N días). */
  "lh.pmg.daily_trend": {
    params: daysSchema,
    build: (p, c) => c.pmg.dailyTrend(p.days),
  },

  /** Top destinatarios más atacados (más correos bloqueados/spam). */
  "lh.pmg.top_recipients_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.topRecipients24h(p.limit),
  },

  /** IPs que atacan 2+ dominios distintos — detección de campañas coordinadas. */
  "lh.pmg.campaign_clusters_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.campaignClusters24h(p.limit),
  },

  /**
   * Variante materializada: lee de `pmg_campaign_patterns_daily` (refresh 1 h,
   * DAG `pmg_campaign_patterns_refresh_1h`). El HAVING COUNT(DISTINCT
   * sender_domain) >= 2 ya se aplicó al materializar, así que la query
   * runtime es trivial.
   *
   * Aproximaciones:
   *   - targeted_domains re-agregado con SUM over-counta si una IP atacó
   *     los mismos dominios en 2 días (p.ej. 3+3 = 6 en vez de 3 distintos).
   *     Acotado en la práctica porque ventana es 24 h ≈ 1 partición dt.
   *   - unique_recipients: mismo trade-off que top_senders_24h_mat.
   */
  "lh.pmg.campaign_clusters_24h_mat": {
    params: limitOnlySchema,
    build: (p) => `
SELECT
  sender_ip,
  SUM(targeted_domains)             AS targeted_domains,
  SUM(total_emails)                 AS total_emails,
  SUM(blocked)                      AS blocked,
  MAX(max_spam_score)               AS max_spam_score,
  BOOL_OR(has_auth_fail)            AS has_auth_fail,
  BOOL_OR(has_malicious_url)        AS has_malicious_url,
  SUM(unique_recipients)            AS unique_recipients
FROM minio_iceberg.hunting.pmg_campaign_patterns_daily
WHERE dt >= current_date - INTERVAL '1' DAY
  AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  AND sender_ip <> '(desconocida)'
GROUP BY sender_ip
ORDER BY targeted_domains DESC, total_emails DESC
LIMIT ${p.limit}
`.trim(),
  },

  /** Resumen DMARC / SPF / DKIM pass/fail/none (fila única). */
  "lh.pmg.auth_breakdown_24h": {
    params: empty,
    build: (_, c) => c.pmg.authBreakdown24h(),
  },

  /** Top N direcciones email remitentes completas (sender_email) con contexto de bloqueo. */
  "lh.pmg.top_sender_emails_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.pmg.topSenderEmails24h(p.limit),
  },

  /** Detección de spike: compara última hora vs anterior (ratio_vs_prev). */
  "lh.pmg.volume_spike_2h": {
    params: empty,
    build: (_, c) => c.pmg.volumeSpike2h(),
  },

  // ── Wazuh (Manager vía syslog/wazuh) — nuevas tarjetas de detección ─────────
  /** Top IPs externas origen con más alertas Wazuh (data.srcip). */
  "lh.wazuh.top_src_ips_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuh.topSrcIps24h(p.limit),
  },

  /** Top tácticas MITRE ATT&CK detectadas por Wazuh. */
  "lh.wazuh.top_mitre_tactics_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuh.topMitreTactics24h(p.limit),
  },

  // ── Wazuh Fluent — nuevas tarjetas de detección ────────────────────────────
  /** Top tácticas MITRE ATT&CK (campo mitre_tactic ARRAY, solo alerts.json). */
  "lh.wazuh_fluent.top_mitre_tactics_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhFluent.topMitreTactics24h(p.limit),
  },

  /** Top IPs origen externas con mayor número de alertas Wazuh Fluent. */
  "lh.wazuh_fluent.top_src_ips_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.wazuhFluent.topSrcIps24h(p.limit),
  },

  // ── Suricata IDS — distribución por categoría ──────────────────────────────
  /** Top categorías de alerta Suricata por volumen de hits. */
  "lh.suricata.top_categories_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.suricata.topCategories24h(p.limit),
  },

  // ── Fortigate UTM — análisis de puertos origen ─────────────────────────────
  /** Top puertos origen más frecuentes en eventos Fortigate. */
  "lh.fg.top_src_ports_24h": {
    params: limitOnlySchema,
    build: (p, c) => c.fortigate.topSrcPorts24h(p.limit),
  },
};

export function listNamedQueryIds() {
  return Object.keys(REGISTRY).sort();
}

/**
 * @param {string} id
 * @param {unknown} params
 * @param {{ trinoCatalog?: string, trinoSchema?: string, intelWazuhTable?: string }} appConfig
 */
export function resolveNamedTrinoQuery(id, params, appConfig) {
  const def = REGISTRY[id];
  if (!def) {
    return { ok: false, status: 404, error: `Unknown query id: ${id}` };
  }
  const parsed = def.params.safeParse(params ?? {});
  if (!parsed.success) {
    return {
      ok: false,
      status: 400,
      error: "Invalid params",
      details: parsed.error.flatten(),
    };
  }
  const c = ctxFromConfig(appConfig);
  const sql = def.build(parsed.data, c);
  return { ok: true, sql };
}
