/**
 * NOC API — dispositivos, métricas, alertas, acciones remotas y heartbeat de agentes.
 * Portado desde lgcrTI (Next.js API routes → Express).
 */
import { Router } from "express";
import { timingSafeEqual } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { runNocHeartbeatWatcher } from "../services/nocHeartbeatWatcher.mjs";
import { openCaseFromNocAlert, syncNocDownIncidents } from "../services/nocIncidentBridge.mjs";
import { verifyAgentToken } from "../services/agentAuth.mjs";
import {
  ingestHeartbeatTimescale,
  queryMetricSeries,
  queryDeviceLogs,
  queryLatestMetrics,
  insertSystemLog,
} from "../services/nocTimescale.mjs";
import { processIncidentsQueueBatch } from "../services/governanceIncidentWorker.mjs";
import { exportNocLake } from "../services/nocLakeExportService.mjs";
import { ingestSnmpTelegrafBatch } from "../services/snmpIngestService.mjs";
import {
  getSnmpSettings,
  updateSnmpSettings,
  syncSnmpTargetForDevice,
} from "../services/nocSettingsService.mjs";

const NOC_AGENT_TOKEN = (process.env.NOC_AGENT_TOKEN ?? "").trim();
const CRON_SECRET = (process.env.CRON_SECRET ?? process.env.INTERNAL_SERVICE_TOKEN ?? "").trim();
const OIDC_ENABLED = process.env.OIDC_ENABLED?.trim() === "true";

const DEVICES_LIST_SQL = `
  SELECT
    d.id, d.hostname, d.ip_address::text AS ip_address, d.mac_address, d.device_type,
    d.site, d.tags, d.description, d.heartbeat_timeout_secs,
    d.cpu_threshold_pct, d.mem_threshold_pct, d.rtt_threshold_ms,
    d.status, d.last_seen_at, d.ssh_host, d.ssh_port, d.ssh_user,
    d.agent_version, d.created_at, d.updated_at,
    m_cpu.value::float  AS cpu_pct,
    m_mem.value::float  AS mem_pct,
    m_rtt.value::float  AS rtt_ms,
    COALESCE(al.open_alerts, 0)::int AS open_alerts
  FROM noc_devices d
  LEFT JOIN LATERAL (
    SELECT value FROM noc_metrics
    WHERE device_id = d.id AND metric_name = 'cpu_pct'
    ORDER BY recorded_at DESC LIMIT 1
  ) m_cpu ON true
  LEFT JOIN LATERAL (
    SELECT value FROM noc_metrics
    WHERE device_id = d.id AND metric_name = 'mem_pct'
    ORDER BY recorded_at DESC LIMIT 1
  ) m_mem ON true
  LEFT JOIN LATERAL (
    SELECT value FROM noc_metrics
    WHERE device_id = d.id AND metric_name = 'rtt_ms'
    ORDER BY recorded_at DESC LIMIT 1
  ) m_rtt ON true
  LEFT JOIN LATERAL (
    SELECT COUNT(*)::int AS open_alerts
    FROM noc_alerts
    WHERE device_id = d.id AND status = 'open'
  ) al ON true
`;

function timingSafeStrEq(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) {
    timingSafeEqual(ba, ba);
    return false;
  }
  return timingSafeEqual(ba, bb);
}

/** Auth para agentes NOC: JWT (PostgreSQL login) o token estático legacy. */
function requireNocAgent(req, res, next) {
  const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, "")?.trim() ?? "";

  if (!bearer) {
    if (!NOC_AGENT_TOKEN && !OIDC_ENABLED) return next();
    return res.status(401).json({ success: false, error: "Token de agente requerido." });
  }

  if (NOC_AGENT_TOKEN && timingSafeStrEq(bearer, NOC_AGENT_TOKEN)) {
    return next();
  }

  try {
    verifyAgentToken(bearer);
    return next();
  } catch {
    if (!NOC_AGENT_TOKEN && !OIDC_ENABLED) return next();
    return res.status(401).json({ success: false, error: "No autorizado." });
  }
}

function requireCronSecret(req, res, next) {
  const auth = req.headers.authorization?.replace(/^Bearer\s+/i, "")?.trim() ?? "";
  if (!CRON_SECRET || !auth || !timingSafeStrEq(auth, CRON_SECRET)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

const METRIC_WINDOWS = {
  "1h": "1 hour",
  "2h": "2 hours",
  "6h": "6 hours",
  "24h": "24 hours",
  "7d": "7 days",
};

const PATCHABLE_DEVICE_FIELDS = [
  "hostname", "ip_address", "mac_address", "device_type", "site", "tags",
  "description", "heartbeat_timeout_secs", "cpu_threshold_pct", "mem_threshold_pct",
  "rtt_threshold_ms", "ssh_host", "ssh_port", "ssh_user",
];

export default function nocRouter() {
  const router = Router();

  // ── Heartbeat (agentes) ─────────────────────────────────────────────────────
  router.post("/heartbeat", requireNocAgent, async (req, res) => {
    try {
      const {
        hostname,
        ip_address,
        mac_address,
        agent_version,
        device_id,
        metrics = {},
        site,
        region,
        iface,
        disk = [],
        log_lines = [],
      } = req.body ?? {};
      if (!hostname) {
        return res.status(400).json({ success: false, error: "hostname requerido." });
      }

      const agentId =
        req.headers["x-agent-id"]?.toString() ?? req.body?.agent_id ?? null;

      let devId = device_id ?? null;
      let deviceSite = site ?? null;

      if (devId) {
        const updated = await pgQuery(
          `UPDATE noc_devices SET status='online', last_seen_at=NOW(),
             ip_address=COALESCE($2::inet, ip_address),
             mac_address=COALESCE($3, mac_address),
             agent_version=COALESCE($4, agent_version),
             site=COALESCE($5, site)
           WHERE id=$1 RETURNING id, site`,
          [devId, ip_address ?? null, mac_address ?? null, agent_version ?? null, site ?? null],
        );
        if (updated.length === 0) devId = null;
        else deviceSite = updated[0].site ?? deviceSite;
      }

      if (!devId) {
        const inserted = await pgQuery(
          `INSERT INTO noc_devices (hostname, ip_address, mac_address, agent_version, site, status, last_seen_at)
           VALUES ($1, $2::inet, $3, $4, $5, 'online', NOW())
           ON CONFLICT (hostname) DO UPDATE SET
             ip_address    = COALESCE(EXCLUDED.ip_address, noc_devices.ip_address),
             mac_address   = COALESCE(EXCLUDED.mac_address, noc_devices.mac_address),
             agent_version = COALESCE(EXCLUDED.agent_version, noc_devices.agent_version),
             site          = COALESCE(EXCLUDED.site, noc_devices.site),
             status        = 'online',
             last_seen_at  = NOW()
           RETURNING id, site`,
          [hostname, ip_address ?? null, mac_address ?? null, agent_version ?? null, site ?? null],
        );
        devId = inserted[0].id;
        deviceSite = inserted[0].site ?? deviceSite;
      }

      await pgQuery(
        `UPDATE noc_alerts SET status='resolved', resolved_at=NOW()
         WHERE device_id=$1 AND alert_type='down' AND status IN ('open','ack')`,
        [devId],
      );

      const metricNames = ["cpu_pct", "mem_pct", "rtt_ms", "bw_in_bps", "bw_out_bps"];
      for (const name of metricNames) {
        const val = metrics[name];
        if (val === undefined || val === null || Number.isNaN(Number(val))) continue;

        await pgQuery(
          `INSERT INTO noc_metrics (device_id, metric_name, value) VALUES ($1,$2,$3)`,
          [devId, name, Number(val)],
        );

        if (name === "cpu_pct" || name === "mem_pct") {
          const alertType = name === "cpu_pct" ? "high_cpu" : "high_mem";
          const col = name === "cpu_pct" ? "cpu_threshold_pct" : "mem_threshold_pct";
          const [thrRow] = await pgQuery(`SELECT ${col} AS thr FROM noc_devices WHERE id=$1`, [devId]);
          const thr = parseFloat(thrRow?.thr ?? "90");
          if (Number(val) >= thr) {
            const existing = await pgQuery(
              `SELECT id FROM noc_alerts WHERE device_id=$1 AND alert_type=$2 AND status='open' LIMIT 1`,
              [devId, alertType],
            );
            if (existing.length === 0) {
              await pgQuery(
                `INSERT INTO noc_alerts (device_id, alert_type, details) VALUES ($1,$2,$3)`,
                [devId, alertType, JSON.stringify({ measured: val, threshold: thr })],
              );
            }
          } else {
            await pgQuery(
              `UPDATE noc_alerts SET status='resolved', resolved_at=NOW()
               WHERE device_id=$1 AND alert_type=$2 AND status='open'`,
              [devId, alertType],
            );
          }
        }

        if (name === "rtt_ms") {
          const [thrRow] = await pgQuery(
            `SELECT rtt_threshold_ms AS thr FROM noc_devices WHERE id=$1`,
            [devId],
          );
          const thr = parseFloat(thrRow?.thr ?? "500");
          if (Number(val) >= thr) {
            const existing = await pgQuery(
              `SELECT id FROM noc_alerts WHERE device_id=$1 AND alert_type='high_rtt' AND status='open' LIMIT 1`,
              [devId],
            );
            if (existing.length === 0) {
              await pgQuery(
                `INSERT INTO noc_alerts (device_id, alert_type, details) VALUES ($1,'high_rtt',$2)`,
                [devId, JSON.stringify({ measured: val, threshold: thr })],
              );
            }
          } else {
            await pgQuery(
              `UPDATE noc_alerts SET status='resolved', resolved_at=NOW()
               WHERE device_id=$1 AND alert_type='high_rtt' AND status='open'`,
              [devId],
            );
          }
        }
      }

      await ingestHeartbeatTimescale({
        nodeId: devId,
        hostname,
        site: deviceSite,
        region: region ?? deviceSite ?? "global",
        status: "online",
        metrics,
        agentVersion: agent_version,
        agentId,
        iface: iface ?? "default",
        diskMounts: Array.isArray(disk) ? disk : [],
        logLines: Array.isArray(log_lines) ? log_lines : [],
      });

      if (!Array.isArray(log_lines) || log_lines.length === 0) {
        insertSystemLog({
          nodeId: devId,
          hostname,
          site: deviceSite,
          region: region ?? deviceSite ?? "global",
          severity: "info",
          source: "noc-agent",
          logType: "agent",
          message: `Heartbeat cpu=${metrics.cpu_pct ?? "?"}% mem=${metrics.mem_pct ?? "?"}% rtt=${metrics.rtt_ms ?? "?"}ms`,
          raw: { metrics, agent_version, agent_id: agentId },
        }).catch(() => {});
      }

      return res.json({ success: true, device_id: devId });
    } catch (err) {
      logger.error("noc_heartbeat_error", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  // ── SNMP Telegraf ingest ────────────────────────────────────────────────────
  router.post("/snmp/ingest", requireNocAgent, async (req, res) => {
    try {
      const result = await ingestSnmpTelegrafBatch(req.body);
      return res.status(201).json({ success: true, ...result });
    } catch (err) {
      logger.error("snmp_ingest_error", { msg: err.message });
      if (err.code === "42P01") {
        return res.status(503).json({
          success: false,
          error: "Esquema SNMP no migrado. Ejecute 124_snmp_telegraf_timescale.sql",
        });
      }
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  // ── Cron heartbeat watcher ──────────────────────────────────────────────────
  router.get("/cron/heartbeat-watcher", requireCronSecret, async (_req, res) => {
    try {
      const result = await runNocHeartbeatWatcher();
      return res.json({ ok: true, ...result });
    } catch (err) {
      return res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Dispositivos ────────────────────────────────────────────────────────────
  router.get("/devices", async (_req, res) => {
    try {
      const rows = await pgQuery(`${DEVICES_LIST_SQL} ORDER BY
        CASE d.status WHEN 'offline' THEN 0 WHEN 'degraded' THEN 1 WHEN 'online' THEN 2 ELSE 3 END,
        d.hostname ASC`);

      for (const row of rows) {
        const latest = await queryLatestMetrics(row.id);
        if (latest) {
          if (latest.cpu_pct != null) row.cpu_pct = parseFloat(latest.cpu_pct);
          if (latest.mem_pct != null) row.mem_pct = parseFloat(latest.mem_pct);
          if (latest.rtt_ms != null) row.rtt_ms = parseFloat(latest.rtt_ms);
        }
      }

      return res.json({ success: true, data: rows, devices: rows, meta: { total: rows.length } });
    } catch (err) {
      logger.error("noc_devices_list", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.post("/devices", async (req, res) => {
    try {
      const {
        hostname,
        ip_address,
        mac_address,
        device_type = "server",
        site,
        description,
        heartbeat_timeout_secs = 120,
        cpu_threshold_pct = 90,
        mem_threshold_pct = 90,
        rtt_threshold_ms = 500,
        ssh_host,
        ssh_port = 22,
        ssh_user,
      } = req.body ?? {};

      if (!hostname) {
        return res.status(400).json({ success: false, error: "hostname requerido." });
      }

      const [row] = await pgQuery(
        `INSERT INTO noc_devices
           (hostname, ip_address, mac_address, device_type, site, description,
            heartbeat_timeout_secs, cpu_threshold_pct, mem_threshold_pct, rtt_threshold_ms,
            ssh_host, ssh_port, ssh_user)
         VALUES ($1,$2::inet,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         RETURNING *`,
        [
          hostname,
          ip_address ?? null,
          mac_address ?? null,
          device_type,
          site ?? null,
          description ?? null,
          heartbeat_timeout_secs,
          cpu_threshold_pct,
          mem_threshold_pct,
          rtt_threshold_ms,
          ssh_host ?? null,
          ssh_port,
          ssh_user ?? null,
        ],
      );

      await syncSnmpTargetForDevice(row);

      return res.status(201).json({ success: true, data: row, device: row });
    } catch (err) {
      logger.error("noc_devices_create", { msg: err.message });
      if (err.code === "23505") {
        return res.status(409).json({ success: false, error: "Hostname ya registrado." });
      }
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.get("/devices/:id/metrics", async (req, res) => {
    try {
      const { id } = req.params;
      const metric = req.query.metric ?? "cpu_pct";
      const windowKey = req.query.window ?? "2h";

      if (!METRIC_WINDOWS[windowKey]) {
        return res.status(400).json({
          success: false,
          error: `window inválido. Opciones: ${Object.keys(METRIC_WINDOWS).join(", ")}`,
        });
      }

      const useMinute = ["1h", "2h", "6h"].includes(windowKey);
      const truncUnit = useMinute ? "minute" : "hour";

      let data = await queryMetricSeries(id, metric, METRIC_WINDOWS[windowKey]);

      if (!data || data.length === 0) {
        const rows = await pgQuery(
          `SELECT DATE_TRUNC($1, recorded_at) AS t, AVG(value)::NUMERIC(15,4) AS v
           FROM noc_metrics
           WHERE device_id = $2 AND metric_name = $3
             AND recorded_at >= NOW() - $4::INTERVAL
           GROUP BY DATE_TRUNC($1, recorded_at)
           ORDER BY t ASC`,
          [truncUnit, id, metric, METRIC_WINDOWS[windowKey]],
        );
        data = rows.map((r) => ({ t: r.t, v: parseFloat(r.v) }));
      }

      return res.json({ success: true, metric, window: windowKey, data });
    } catch (err) {
      logger.error("noc_device_metrics", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.get("/devices/:id/logs", async (req, res) => {
    try {
      const { id } = req.params;
      const { severity } = req.query;
      const conditions = ["device_id = $1"];
      const vals = [id];
      let idx = 2;

      if (severity) {
        conditions.push(`severity = $${idx++}`);
        vals.push(severity);
      }

      let rows = await queryDeviceLogs(id, { severity: severity ?? null, limit: 100 });

      if (!rows) {
        rows = await pgQuery(
          `SELECT id, device_id, ts, severity, source, message, raw
           FROM noc_logs
           WHERE ${conditions.join(" AND ")}
           ORDER BY ts DESC
           LIMIT 100`,
          vals,
        );
      }

      return res.json({ success: true, data: rows, logs: rows, meta: { total: rows.length } });
    } catch (err) {
      logger.error("noc_device_logs", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.get("/devices/:id", async (req, res) => {
    try {
      const [row] = await pgQuery(
        `SELECT *, ip_address::text AS ip_address FROM noc_devices WHERE id = $1`,
        [req.params.id],
      );
      if (!row) {
        return res.status(404).json({ success: false, error: "Dispositivo no encontrado." });
      }
      return res.json({ success: true, data: row, device: row });
    } catch (err) {
      logger.error("noc_device_get", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.patch("/devices/:id", async (req, res) => {
    try {
      const body = req.body ?? {};
      const sets = [];
      const vals = [];
      let idx = 1;

      for (const key of PATCHABLE_DEVICE_FIELDS) {
        if (key in body) {
          sets.push(`${key} = $${idx++}`);
          vals.push(body[key]);
        }
      }

      if (sets.length === 0) {
        return res.status(400).json({ success: false, error: "Sin campos para actualizar." });
      }

      vals.push(req.params.id);
      const [row] = await pgQuery(
        `UPDATE noc_devices SET ${sets.join(", ")} WHERE id = $${idx} RETURNING *`,
        vals,
      );

      if (!row) {
        return res.status(404).json({ success: false, error: "Dispositivo no encontrado." });
      }
      return res.json({ success: true, data: row, device: row });
    } catch (err) {
      logger.error("noc_device_patch", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.delete("/devices/:id", async (req, res) => {
    try {
      const [dev] = await pgQuery(
        `SELECT id, hostname, ip_address::text AS ip_address FROM noc_devices WHERE id = $1`,
        [req.params.id],
      );
      if (!dev) {
        return res.status(404).json({ success: false, error: "Dispositivo no encontrado." });
      }

      try {
        await pgQuery(
          `DELETE FROM snmp_targets
            WHERE noc_device_id = $1
               OR ($2::text IS NOT NULL AND device_ip = $2::inet)`,
          [dev.id, dev.ip_address],
        );
      } catch (snmpErr) {
        if (snmpErr.code !== "42P01") {
          logger.warn("noc_device_delete_snmp_target", { id: dev.id, msg: snmpErr.message });
        }
      }

      await pgQuery(`DELETE FROM noc_devices WHERE id = $1`, [dev.id]);
      return res.json({ success: true, data: { id: dev.id, hostname: dev.hostname } });
    } catch (err) {
      logger.error("noc_device_delete", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  // ── Alertas ─────────────────────────────────────────────────────────────────
  router.get("/alerts", async (req, res) => {
    try {
      const conditions = [];
      const vals = [];
      let idx = 1;

      if (req.query.status) {
        conditions.push(`a.status = $${idx++}`);
        vals.push(req.query.status);
      }
      if (req.query.device_id) {
        conditions.push(`a.device_id = $${idx++}`);
        vals.push(req.query.device_id);
      }

      const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

      const rows = await pgQuery(
        `SELECT a.id, a.device_id, d.hostname, a.alert_type, a.status,
                a.triggered_at, a.resolved_at, a.ack_by, a.ack_at, a.notified, a.details
         FROM noc_alerts a
         JOIN noc_devices d ON d.id = a.device_id
         ${where}
         ORDER BY a.triggered_at DESC
         LIMIT 50`,
        vals,
      );

      return res.json({ success: true, data: rows, alerts: rows, meta: { total: rows.length } });
    } catch (err) {
      logger.error("noc_alerts_list", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.patch("/alerts/:id", async (req, res) => {
    try {
      const { action, ack_by } = req.body ?? {};
      if (!["ack", "resolve"].includes(action)) {
        return res.status(400).json({ success: false, error: "action debe ser 'ack' o 'resolve'." });
      }

      const ackBy = ack_by ?? req.user?.email ?? req.user?.preferred_username ?? "operator";

      let rows;
      if (action === "ack") {
        rows = await pgQuery(
          `UPDATE noc_alerts SET status='ack', ack_by=$2, ack_at=NOW() WHERE id=$1 RETURNING *`,
          [req.params.id, ackBy],
        );
      } else {
        rows = await pgQuery(
          `UPDATE noc_alerts SET status='resolved', resolved_at=NOW() WHERE id=$1 RETURNING *`,
          [req.params.id],
        );
      }

      if (rows.length === 0) {
        return res.status(404).json({ success: false, error: "Alerta no encontrada." });
      }
      return res.json({ success: true, data: rows[0] });
    } catch (err) {
      logger.error("noc_alert_patch", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.post("/alerts/:id/open-incident", async (req, res) => {
    try {
      const operatorCi = req.user?.email ?? req.user?.preferred_username ?? "operator";
      const result = await openCaseFromNocAlert(req.params.id, { operatorCi });
      if (result.outcome === "not_found") {
        return res.status(404).json({ success: false, error: "Alerta no encontrada." });
      }
      if (result.outcome === "not_down") {
        return res.status(400).json({ success: false, error: "Solo alertas tipo down generan incidente." });
      }
      return res.json({ success: true, ...result });
    } catch (err) {
      logger.error("noc_alert_open_incident", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.post("/incidents/sync", async (_req, res) => {
    try {
      const result = await syncNocDownIncidents();
      return res.json({ success: true, ...result });
    } catch (err) {
      logger.error("noc_incidents_sync", { msg: err.message });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/cron/governance-worker", requireCronSecret, async (_req, res) => {
    try {
      const result = await processIncidentsQueueBatch();
      return res.json({ ok: true, ...result });
    } catch (err) {
      return res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.get("/cron/lake-export", requireCronSecret, async (req, res) => {
    try {
      const dt = req.query.dt?.toString();
      const result = await exportNocLake({ dt });
      return res.json({ ok: true, ...result });
    } catch (err) {
      return res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Acciones remotas ────────────────────────────────────────────────────────
  /** Poll de acciones pendientes para agentes (requiere auth de agente). */
  router.get("/agent/actions", requireNocAgent, async (req, res) => {
    try {
      const deviceId = String(req.query.device_id ?? "").trim();
      if (!deviceId) {
        return res.status(400).json({ success: false, error: "device_id requerido." });
      }

      const rows = await pgQuery(
        `SELECT ra.id, ra.device_id, d.hostname, ra.action_type, ra.payload, ra.status,
                ra.output, ra.requested_by, ra.requested_at, ra.started_at, ra.completed_at
         FROM noc_remote_actions ra
         JOIN noc_devices d ON d.id = ra.device_id
         WHERE ra.device_id = $1 AND ra.status = $2
         ORDER BY ra.requested_at ASC
         LIMIT 20`,
        [deviceId, String(req.query.status ?? "pending")],
      );

      return res.json({ success: true, data: rows, meta: { total: rows.length } });
    } catch (err) {
      logger.error("noc_agent_actions", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.get("/actions", async (req, res) => {
    try {
      const conditions = [];
      const vals = [];
      let idx = 1;

      if (req.query.device_id) {
        conditions.push(`ra.device_id = $${idx++}`);
        vals.push(req.query.device_id);
      }
      if (req.query.status) {
        conditions.push(`ra.status = $${idx++}`);
        vals.push(req.query.status);
      }

      const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

      const rows = await pgQuery(
        `SELECT ra.id, ra.device_id, d.hostname, ra.action_type, ra.payload, ra.status,
                ra.output, ra.requested_by, ra.requested_at, ra.started_at, ra.completed_at
         FROM noc_remote_actions ra
         JOIN noc_devices d ON d.id = ra.device_id
         ${where}
         ORDER BY ra.requested_at DESC
         LIMIT 50`,
        vals,
      );

      return res.json({ success: true, data: rows, meta: { total: rows.length } });
    } catch (err) {
      logger.error("noc_actions_list", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.post("/actions", async (req, res) => {
    try {
      const { device_id, action_type, payload = {} } = req.body ?? {};
      if (!device_id || !action_type) {
        return res.status(400).json({ success: false, error: "device_id y action_type son requeridos." });
      }

      const deviceCheck = await pgQuery("SELECT id FROM noc_devices WHERE id = $1", [device_id]);
      if (deviceCheck.length === 0) {
        return res.status(404).json({ success: false, error: "Dispositivo no encontrado." });
      }

      const requestedBy =
        req.user?.email ?? req.user?.preferred_username ?? req.user?.sub ?? "operator";

      const [row] = await pgQuery(
        `INSERT INTO noc_remote_actions (device_id, action_type, payload, requested_by)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [device_id, action_type, JSON.stringify(payload), requestedBy],
      );

      await pgQuery(
        `INSERT INTO noc_logs (device_id, severity, source, message)
         VALUES ($1, 'info', 'remote_actions', $2)`,
        [device_id, `Acción ${action_type} solicitada por ${requestedBy}`],
      );

      return res.status(201).json({ success: true, data: row });
    } catch (err) {
      logger.error("noc_actions_create", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.get("/actions/:id", async (req, res) => {
    try {
      const [row] = await pgQuery(
        `SELECT ra.*, d.hostname
         FROM noc_remote_actions ra
         JOIN noc_devices d ON d.id = ra.device_id
         WHERE ra.id = $1`,
        [req.params.id],
      );
      if (!row) {
        return res.status(404).json({ success: false, error: "Acción no encontrada." });
      }
      return res.json({ success: true, data: row });
    } catch (err) {
      logger.error("noc_action_get", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  router.patch("/actions/:id", requireNocAgent, async (req, res) => {
    try {
      const { status, output } = req.body ?? {};
      const valid = ["running", "done", "failed"];
      if (!valid.includes(status)) {
        return res.status(400).json({
          success: false,
          error: `status inválido. Opciones: ${valid.join(", ")}`,
        });
      }

      const sets = ["status = $2"];
      const vals = [req.params.id, status];
      let idx = 3;

      if (status === "running") {
        sets.push("started_at = NOW()");
      } else if (status === "done" || status === "failed") {
        sets.push("completed_at = NOW()");
      }

      if (output !== undefined) {
        sets.push(`output = $${idx++}`);
        vals.push(output);
      }

      const rows = await pgQuery(
        `UPDATE noc_remote_actions SET ${sets.join(", ")} WHERE id = $1 RETURNING *`,
        vals,
      );

      if (rows.length === 0) {
        return res.status(404).json({ success: false, error: "Acción no encontrada." });
      }
      return res.json({ success: true, data: rows[0] });
    } catch (err) {
      logger.error("noc_action_patch", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno del servidor." });
    }
  });

  // ── Configuración NOC (SNMP, etc.) ─────────────────────────────────────────
  router.get("/settings/snmp", async (_req, res) => {
    try {
      const data = await getSnmpSettings();
      const { checkSnmpDiscoveryAvailable } = await import("../services/snmpDiscoveryService.mjs");
      const mod = await checkSnmpDiscoveryAvailable();
      return res.json({ success: true, data: { ...data, discovery_module: mod } });
    } catch (err) {
      logger.error("noc_snmp_settings_get", { msg: err.message });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.patch("/settings/snmp", async (req, res) => {
    try {
      const b = req.body ?? {};
      const data = await updateSnmpSettings(b);
      return res.json({ success: true, data });
    } catch (err) {
      logger.error("noc_snmp_settings_patch", { msg: err.message });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.post("/snmp/discover", async (req, res) => {
    try {
      const { checkSnmpDiscoveryAvailable, runSnmpDiscovery } = await import(
        "../services/snmpDiscoveryService.mjs",
      );
      const mod = await checkSnmpDiscoveryAvailable();
      if (!mod.available) {
        return res.status(503).json({
          success: false,
          error: `Módulo SNMP no disponible (${mod.error}). Reconstruya la API: docker compose build api && docker compose up -d api`,
        });
      }

      const b = req.body ?? {};
      if (!b.cidr?.trim()) {
        return res.status(400).json({ success: false, error: "cidr requerido (ej. 192.168.1.0/24)." });
      }
      const data = await runSnmpDiscovery({
        cidr: b.cidr.trim(),
        communities: b.communities,
        port: b.port,
        site: b.site,
        register: b.register !== false,
      });
      return res.json({ success: true, data });
    } catch (err) {
      logger.error("noc_snmp_discover", { msg: err.message, stack: err.stack });
      const status = err.message?.includes("inválido") || err.message?.includes("demasiado") ? 400 : 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  });

  return router;
}
