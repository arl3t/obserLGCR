/**
 * SQL equivalente a las consultas nombradas del API (`lh.*`).
 * Se usa si `POST /api/trino/run` devuelve 404 (API antiguo o sin desplegar la ruta).
 */
import * as Hunting from "@/lib/trino-queries-hunting";
import * as Syslog from "@/lib/trino-queries";
import * as Wazuh from "@/lib/trino-queries-wazuh";

function coerceInt(v: unknown, fallback: number, min: number, max: number): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

export function buildSqlForNamedQuery(
  id: string,
  params: Record<string, unknown>,
): string | null {
  switch (id) {
    case "lh.syslog.blocks_last_24h":
      return Syslog.blocksLast24h();
    case "lh.syslog.blocks_previous_24h":
      return Syslog.blocksPrevious24h();
    case "lh.syslog.unique_blocked_ips_24h":
      return Syslog.uniqueBlockedIps24h();
    case "lh.syslog.unique_blocked_ips_previous_24h":
      return Syslog.uniqueBlockedIpsPrevious24h();
    case "lh.syslog.blocks_by_day":
      return Syslog.blocksByDay(coerceInt(params.days, 7, 1, 365));
    case "lh.syslog.blocks_by_hour_24h":
      return Syslog.blocksByHourLast24h();
    case "lh.syslog.unique_ips_by_hour_24h":
      return Syslog.uniqueBlockedIpsByHourLast24h();
    case "lh.syslog.top_blocked_ips":
      return Syslog.topBlockedIps(
        coerceInt(params.limit, 10, 1, 50_000),
        coerceInt(params.hours, 24, 1, 24 * 90),
      );
    case "lh.syslog.top_attacked_ports":
      return Syslog.topAttackedPorts(
        coerceInt(params.limit, 10, 1, 50_000),
        coerceInt(params.hours, 24, 1, 24 * 90),
      );
    case "lh.syslog.lateral_movement_today":
      return Syslog.lateralMovementCandidatesToday(coerceInt(params.limit, 8, 1, 500));
    case "lh.syslog.filterlog_events_24h":
      return Syslog.filterlogEventsLast24h();
    case "lh.syslog.diag_168h_or_today_partition":
      return Syslog.syslogRowsLast168hOrTodayPartition();
    case "lh.syslog.senders_24h":
      return Syslog.syslogSendersLast24h();
    case "lh.syslog.any_row":
      return Syslog.syslogAnyRowSql();
    case "lh.syslog.filterlog_any_row":
      return Syslog.filterlogAnyRowSql();
    // ── syslog nuevas ──────────────────────────────────────────────────
    case "lh.syslog.filterlog_events_today":
      return Syslog.filterlogEventsToday();
    case "lh.syslog.block_count_for_ip":
      return Syslog.blockCountForIp(
        String(params.ip ?? "0.0.0.0"),
        coerceInt(params.hours, 24, 1, 24 * 90),
      );
    case "lh.syslog.recent_blocked_ips_live":
      return Syslog.recentBlockedIpsForLiveFeed(
        coerceInt(params.limit, 40, 1, 50_000),
        coerceInt(params.minutes, 15, 1, 60 * 24 * 7),
      );
    case "lh.syslog.recent_filterlog_lines":
      return Syslog.recentFilterlogLines(
        coerceInt(params.limit, 50, 1, 50_000),
        coerceInt(params.minutes, 15, 1, 60 * 24 * 7),
      );
    case "lh.syslog.top_blocked_ips_calendar":
      return Syslog.topBlockedIpsCalendar(
        coerceInt(params.limit, 15, 1, 500),
        String(params.year ?? new Date().getFullYear()),
        String(params.month ?? String(new Date().getMonth() + 1)),
      );
    // ── wazuh ──────────────────────────────────────────────────────────
    case "lh.wazuh.alerts_24h":
      return Wazuh.wazuhAlertsLast24h();
    case "lh.wazuh.critical_count_24h":
      return Wazuh.wazuhCriticalCount24h();
    case "lh.wazuh.severity_buckets_24h":
      return Wazuh.wazuhSeverityBuckets24h();
    case "lh.wazuh.top_rules_24h":
      return Wazuh.wazuhTopRules24h(coerceInt(params.limit, 12, 1, 500));
    case "lh.wazuh.top_agents_24h":
      return Wazuh.wazuhTopAgents24h(coerceInt(params.limit, 12, 1, 500));
    case "lh.wazuh.critical_cves_24h":
      return Wazuh.wazuhCriticalCves24h(coerceInt(params.limit, 40, 1, 500));
    case "lh.wazuh.critical_cve_hosts_24h":
      return Wazuh.wazuhCriticalCveHosts24h(coerceInt(params.limit, 20, 1, 500));
    case "lh.wazuh.recent_lines":
      return Wazuh.wazuhRecentLines(
        coerceInt(params.limit, 50, 1, 50_000),
        coerceInt(params.minutes, 15, 1, 60 * 24 * 7),
      );
    // ── hunting Iceberg (enriched_ioc / vt_results) ─────────────────────
    case "lh.hunting.enriched_kpis":
      return Hunting.huntingEnrichedKpis(coerceInt(params.days, 7, 1, 365));
    case "lh.hunting.enriched_daily_trend":
      return Hunting.huntingEnrichedDailyTrend(coerceInt(params.days, 7, 1, 365));
    case "lh.hunting.enriched_source_breakdown":
      return Hunting.huntingEnrichedSourceBreakdown(coerceInt(params.days, 7, 1, 365));
    case "lh.hunting.enriched_score_buckets":
      return Hunting.huntingEnrichedScoreBuckets(coerceInt(params.days, 7, 1, 365));
    case "lh.hunting.enriched_vt_coverage":
      return Hunting.huntingEnrichedVtCoverage(coerceInt(params.days, 7, 1, 365));
    case "lh.hunting.enriched_vt_top_sample":
      return Hunting.huntingEnrichedVtTopSample(
        coerceInt(params.limit, 24, 1, 500),
        coerceInt(params.days, 7, 1, 90),
      );
    case "lh.incidents.live_top_v2":
      return Hunting.incidentsLiveTopV2(
        coerceInt(params.limit, 50, 1, 500),
        coerceInt(params.days, 30, 1, 90),
      );
    default:
      return null;
  }
}
