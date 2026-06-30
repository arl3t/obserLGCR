/**
 * Exportación batch PG → lake layout (JSONL) para Hive external tables.
 * Ejecutar vía cron o: node api/scripts/export-noc-lake.mjs
 */
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import "../config.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const LAKE_ROOT = process.env.NOC_LAKE_ROOT ?? join(process.cwd(), "data", "lake", "noc");
const DEFAULT_REGION = process.env.NOC_DEFAULT_REGION ?? "global";

function dtPartition(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

function partitionDir(table, dt, region = DEFAULT_REGION) {
  return join(LAKE_ROOT, table, `dt=${dt}`, `region=${region}`);
}

function writeJsonl(dir, filename, rows) {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, filename);
  const body = rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : "");
  writeFileSync(path, body, "utf8");
  return path;
}

export async function exportNocLake({ dt = dtPartition(), region = DEFAULT_REGION } = {}) {
  const stats = { dt, region, tables: {} };

  // Software inventory
  const software = await pgQuery(
    `SELECT ss.server_id::text, ss.node_id::text, ss.hostname, ss.name, ss.version,
            ss.publisher, ss.install_date, ss.package_manager, ss.cpe,
            ss.is_whitelisted, ss.is_blacklisted, ss.collected_at,
            CASE
              WHEN ss.is_blacklisted THEN 'forbidden'
              WHEN ss.is_whitelisted THEN 'approved'
              ELSE 'unknown'
            END AS governance_status
       FROM server_software ss
      WHERE ss.collected_at >= $1::date
        AND ss.collected_at < ($1::date + INTERVAL '1 day')`,
    [dt],
  );
  const swDir = partitionDir("fact_server_software", dt, region);
  stats.tables.fact_server_software = writeJsonl(swDir, "data.jsonl", software);

  // Hardware
  const hardware = await pgQuery(
    `SELECT sh.server_id::text, sh.node_id::text, sh.hostname,
            ih.site AS site, sh.manufacturer, sh.model, sh.serial_number,
            sh.cpu_model, sh.cpu_cores, sh.ram_mb, sh.disk_total_gb,
            sh.virtualization, ih.os_name, ih.os_version, ih.os_arch,
            sh.collected_at
       FROM server_hardware sh
       JOIN inventory_hosts ih ON ih.id = sh.server_id
      WHERE sh.collected_at >= $1::date
        AND sh.collected_at < ($1::date + INTERVAL '1 day')`,
    [dt],
  );
  stats.tables.fact_server_hardware = writeJsonl(
    partitionDir("fact_server_hardware", dt, region),
    "data.jsonl",
    hardware,
  );

  // Blacklist dimension snapshot
  const blacklist = await pgQuery(
    `SELECT id::text AS rule_id, software_name, match_type, pattern, publisher,
            severity, mitre_technique, enabled, NOW() AS snapshot_ts
       FROM software_blacklist`,
  );
  stats.tables.dim_software_blacklist = writeJsonl(
    partitionDir("dim_software_blacklist", dt, region),
    "data.jsonl",
    blacklist,
  );

  // Governance incidents processed
  const incidents = await pgQuery(
    `SELECT id::text AS queue_id, case_id, incident_type, severity, hostname,
            server_id::text, payload->>'software_name' AS software_name,
            payload->>'software_version' AS software_version,
            payload->>'pattern' AS rule_pattern,
            created_at, processed_at, status
       FROM incidents_queue
      WHERE created_at >= $1::date
        AND created_at < ($1::date + INTERVAL '1 day')`,
    [dt],
  );
  stats.tables.fact_governance_incidents = writeJsonl(
    partitionDir("fact_governance_incidents", dt, region),
    "data.jsonl",
    incidents,
  );

  // CPU hourly roll-up (si TimescaleDB disponible)
  try {
    const cpuHourly = await pgQuery(
      `SELECT node_id::text, hostname, site,
              time_bucket('1 hour', time) AS hour_ts,
              AVG(usage_pct)::float AS avg_usage_pct,
              MAX(usage_pct)::float AS max_usage_pct,
              COUNT(*)::bigint AS sample_count
         FROM cpu_usage
        WHERE time >= $1::date AND time < ($1::date + INTERVAL '1 day')
        GROUP BY 1,2,3,4`,
      [dt],
    );
    if (cpuHourly.length > 0) {
      stats.tables.fact_cpu_usage_hourly = writeJsonl(
        partitionDir("fact_cpu_usage_hourly", dt, region),
        "data.jsonl",
        cpuHourly,
      );
    }
  } catch {
    /* cpu_usage hypertable puede no existir aún */
  }

  logger.info({ msg: "noc_lake_export_done", ...stats, root: LAKE_ROOT });
  return stats;
}
