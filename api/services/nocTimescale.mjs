/**
 * Capa TimescaleDB para métricas NOC, keepalive y logs estructurados.
 * Dual-write desde heartbeat/watcher; consultas con fallback a noc_metrics.
 */
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

let _available = null;
let _checkedAt = 0;
const CHECK_TTL_MS = 60_000;

const METRIC_TABLE = {
  cpu_pct: { table: "cpu_usage", column: "usage_pct" },
  mem_pct: { table: "memory_usage", column: "usage_pct" },
  rtt_ms: { table: "network_traffic", column: "rtt_ms" },
  bw_in_bps: { table: "network_traffic", column: "rx_bps" },
  bw_out_bps: { table: "network_traffic", column: "tx_bps" },
};

export async function isTimescaleAvailable(force = false) {
  if (!force && _available !== null && Date.now() - _checkedAt < CHECK_TTL_MS) {
    return _available;
  }
  try {
    const [row] = await pgQuery(
      `SELECT EXISTS (
         SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'
       ) AS ext,
       EXISTS (
         SELECT 1 FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name = 'cpu_usage'
       ) AS tbl`,
    );
    _available = Boolean(row?.ext && row?.tbl);
  } catch {
    _available = false;
  }
  _checkedAt = Date.now();
  return _available;
}

function numOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * Ingesta heartbeat → hypertables vía función SQL.
 */
export async function ingestHeartbeatTimescale({
  nodeId,
  hostname,
  site = null,
  region = null,
  status = "online",
  metrics = {},
  agentVersion = null,
  agentId = null,
  iface = "default",
  diskMounts = [],
  logLines = [],
}) {
  if (!(await isTimescaleAvailable())) return { ok: false, reason: "timescale_unavailable" };

  try {
    await pgQuery(
      `SELECT noc_ingest_heartbeat_ts(
         $1::uuid, $2, $3, $4, $5,
         $6::numeric, $7::numeric, $8::numeric,
         $9::bigint, $10::bigint,
         $11, $12, $13, $14::jsonb
       )`,
      [
        nodeId,
        hostname,
        site,
        region ?? site ?? "global",
        status,
        numOrNull(metrics.cpu_pct),
        numOrNull(metrics.mem_pct),
        numOrNull(metrics.rtt_ms),
        numOrNull(metrics.bw_in_bps) ?? 0,
        numOrNull(metrics.bw_out_bps) ?? 0,
        iface,
        agentVersion,
        agentId,
        JSON.stringify(Array.isArray(diskMounts) ? diskMounts : []),
      ],
    );

    if (Array.isArray(logLines) && logLines.length > 0) {
      await insertSystemLogs(nodeId, hostname, site, region, logLines);
    }

    return { ok: true };
  } catch (err) {
    logger.warn("noc_timescale_ingest_failed", { msg: err.message, nodeId, hostname });
    return { ok: false, reason: err.message };
  }
}

export async function ingestKeepaliveOffline({
  nodeId,
  hostname,
  site = null,
  region = null,
  lastSeenAt = null,
  timeoutSecs = 120,
}) {
  if (!(await isTimescaleAvailable())) return;

  const msg = `Device offline: no heartbeat recibido en ${timeoutSecs} segundos`;
  await pgQuery(
    `INSERT INTO keepalive_status (time, node_id, hostname, site, region, status, source, details)
     VALUES (NOW(), $1, $2, $3, $4, 'offline', 'watcher', $5::jsonb)`,
    [
      nodeId,
      hostname,
      site,
      region ?? site ?? "global",
      JSON.stringify({ last_seen_at: lastSeenAt, timeout_secs: timeoutSecs }),
    ],
  );

  await insertSystemLog({
    nodeId,
    hostname,
    site,
    region,
    severity: "error",
    source: "heartbeat-watcher",
    logType: "watcher",
    message: msg,
    raw: { last_seen_at: lastSeenAt, timeout_secs: timeoutSecs },
  });
}

export async function insertSystemLog({
  nodeId,
  hostname,
  site = null,
  region = null,
  severity = "info",
  source = null,
  logType = "agent",
  message,
  raw = {},
}) {
  if (!(await isTimescaleAvailable())) return;
  await pgQuery(
    `INSERT INTO system_logs (time, node_id, hostname, site, region, severity, source, log_type, message, raw)
     VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
    [
      nodeId,
      hostname,
      site,
      region ?? site ?? "global",
      severity,
      source,
      logType,
      message,
      JSON.stringify(raw ?? {}),
    ],
  );
}

export async function insertSystemLogs(nodeId, hostname, site, region, lines) {
  for (const line of lines) {
    const msg = String(line?.message ?? line?.msg ?? line ?? "").trim();
    if (!msg) continue;
    await insertSystemLog({
      nodeId,
      hostname,
      site,
      region,
      severity: String(line?.severity ?? "info").toLowerCase(),
      source: line?.source ?? "agent",
      logType: line?.log_type ?? "agent",
      message: msg.slice(0, 8000),
      raw: line?.raw ?? line,
    });
  }
}

/**
 * Serie temporal desde TimescaleDB (time_bucket) o fallback caller.
 */
export async function queryMetricSeries(nodeId, metricName, windowInterval) {
  if (!(await isTimescaleAvailable())) return null;

  const spec = METRIC_TABLE[metricName];
  if (!spec) return null;

  const useMinute = ["1 hour", "2 hours", "6 hours"].includes(windowInterval);
  const bucket = useMinute ? "1 minute" : "1 hour";

  const rows = await pgQuery(
    `SELECT time_bucket($1::interval, time) AS t,
            AVG(${spec.column})::NUMERIC(15,4) AS v
       FROM ${spec.table}
      WHERE node_id = $2::uuid
        AND time >= NOW() - $3::interval
        AND ${spec.column} IS NOT NULL
      GROUP BY 1
      ORDER BY 1 ASC`,
    [bucket, nodeId, windowInterval],
  );

  return rows.map((r) => ({ t: r.t, v: parseFloat(r.v) }));
}

export async function queryDeviceLogs(nodeId, { severity = null, limit = 100 } = {}) {
  if (!(await isTimescaleAvailable())) return null;

  const conditions = ["node_id = $1"];
  const vals = [nodeId];
  let idx = 2;

  if (severity) {
    conditions.push(`severity = $${idx++}`);
    vals.push(severity);
  }
  vals.push(limit);

  const rows = await pgQuery(
    `SELECT ingestion_id AS id, node_id AS device_id, time AS ts,
            severity, source, log_type, message, raw
       FROM system_logs
      WHERE ${conditions.join(" AND ")}
      ORDER BY time DESC
      LIMIT $${idx}`,
    vals,
  );

  return rows;
}

export async function queryLatestMetrics(nodeId) {
  if (!(await isTimescaleAvailable())) return null;

  const [row] = await pgQuery(
    `SELECT
       (SELECT usage_pct FROM cpu_usage WHERE node_id = $1 ORDER BY time DESC LIMIT 1) AS cpu_pct,
       (SELECT usage_pct FROM memory_usage WHERE node_id = $1 ORDER BY time DESC LIMIT 1) AS mem_pct,
       (SELECT rtt_ms FROM network_traffic WHERE node_id = $1 ORDER BY time DESC LIMIT 1) AS rtt_ms`,
    [nodeId],
  );
  return row ?? null;
}
