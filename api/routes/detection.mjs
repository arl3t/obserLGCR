/**
 * Detection API — ingesta y consulta de logs por tipo (PostgreSQL).
 * Complementa el catálogo source_log_catalog para obserLGCR sin Trino.
 */
import { Router } from "express";
import { timingSafeEqual } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { verifyAgentToken } from "../services/agentAuth.mjs";
import {
  getDetectionFamilies,
  lookupSourceLog,
  setFamilyEnabled,
  isSourceEnabled,
} from "../services/sourceLogCatalog.mjs";

const NOC_AGENT_TOKEN = (process.env.NOC_AGENT_TOKEN ?? "").trim();
const OIDC_ENABLED = process.env.OIDC_ENABLED?.trim() === "true";
const MAX_INGEST_BATCH = 500;
const VALID_SEVERITIES = new Set(["debug", "info", "warn", "error", "critical"]);

function timingSafeStrEq(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) {
    timingSafeEqual(ba, ba);
    return false;
  }
  return timingSafeEqual(ba, bb);
}

function requireIngestAuth(req, res, next) {
  const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, "")?.trim() ?? "";
  if (!bearer) {
    if (!NOC_AGENT_TOKEN && !OIDC_ENABLED) return next();
    return res.status(401).json({ success: false, error: "Token de agente requerido." });
  }
  if (NOC_AGENT_TOKEN && timingSafeStrEq(bearer, NOC_AGENT_TOKEN)) return next();
  try {
    verifyAgentToken(bearer);
    return next();
  } catch {
    if (!NOC_AGENT_TOKEN && !OIDC_ENABLED) return next();
    return res.status(401).json({ success: false, error: "No autorizado." });
  }
}

function normalizeSeverity(s) {
  const v = String(s ?? "info").toLowerCase().trim();
  return VALID_SEVERITIES.has(v) ? v : "info";
}

function normalizeEvent(raw, agentId) {
  const sourceLog = String(raw?.source_log ?? "").trim();
  if (!sourceLog) throw new Error("source_log requerido");
  const cat = lookupSourceLog(sourceLog);
  if (cat.sensor_family === "manual") {
    throw new Error(`source_log '${sourceLog}' no admite ingesta`);
  }
  if (!isSourceEnabled(sourceLog)) {
    throw new Error(`source_log '${sourceLog}' está deshabilitado`);
  }
  const message = String(raw?.message ?? "").trim();
  if (!message) throw new Error("message requerido");

  return {
    source_log: sourceLog,
    sensor_family: cat.sensor_family,
    severity: normalizeSeverity(raw?.severity),
    hostname: raw?.hostname ? String(raw.hostname).slice(0, 255) : null,
    source: raw?.source ? String(raw.source).slice(0, 128) : null,
    message: message.slice(0, 8000),
    raw: raw?.raw && typeof raw.raw === "object" ? raw.raw : null,
    src_ip: raw?.src_ip ? String(raw.src_ip) : null,
    dst_ip: raw?.dst_ip ? String(raw.dst_ip) : null,
    rule_id: raw?.rule_id ? String(raw.rule_id).slice(0, 64) : null,
    event_time: raw?.event_time ? new Date(raw.event_time) : new Date(),
    agent_id: agentId ?? null,
  };
}

async function ingestHandler(req, res) {
  try {
    const events = req.body?.events;
    if (!Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ success: false, error: "events[] requerido." });
    }
    if (events.length > MAX_INGEST_BATCH) {
      return res.status(400).json({
        success: false,
        error: `Máximo ${MAX_INGEST_BATCH} eventos por lote.`,
      });
    }

    const agentId =
      req.headers["x-agent-id"]?.toString() ??
      req.body?.agent_id ??
      null;

    const normalized = [];
    const errors = [];
    for (let i = 0; i < events.length; i++) {
      try {
        normalized.push(normalizeEvent(events[i], agentId));
      } catch (e) {
        errors.push({ index: i, error: e.message });
      }
    }

    if (normalized.length === 0) {
      return res.status(400).json({ success: false, error: "Ningún evento válido.", errors });
    }

    const inserted = [];
    for (const ev of normalized) {
      const [row] = await pgQuery(
        `INSERT INTO detection_events
           (source_log, sensor_family, severity, hostname, source, message,
            raw, src_ip, dst_ip, rule_id, event_time, agent_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::inet,$9::inet,$10,$11,$12)
         RETURNING id, source_log, event_time`,
        [
          ev.source_log,
          ev.sensor_family,
          ev.severity,
          ev.hostname,
          ev.source,
          ev.message,
          ev.raw ? JSON.stringify(ev.raw) : null,
          ev.src_ip,
          ev.dst_ip,
          ev.rule_id,
          ev.event_time,
          ev.agent_id,
        ],
      );
      inserted.push(row);
    }

    logger.info({
      msg: "detection_ingest",
      count: inserted.length,
      rejected: errors.length,
      agent_id: agentId,
    });

    res.status(201).json({
      success: true,
      inserted: inserted.length,
      rejected: errors.length,
      errors: errors.length ? errors : undefined,
      ids: inserted.map((r) => r.id),
    });
  } catch (err) {
    logger.error("detection_ingest", { msg: err.message });
    res.status(500).json({ success: false, error: err.message });
  }
}

export function detectionIngestRouter() {
  const router = Router();
  router.post("/ingest", requireIngestAuth, ingestHandler);
  return router;
}

export default function detectionRouter() {
  const router = Router();

  /** KPIs por familia — ventana 24h desde detection_events. */
  router.get("/kpis", async (_req, res) => {
    try {
      const families = getDetectionFamilies();
      const statsRows = await pgQuery(
        `SELECT
           sensor_family,
           COUNT(*)::int AS events_24h,
           COUNT(*) FILTER (WHERE severity IN ('critical', 'error'))::int AS critical_24h,
           COUNT(*) FILTER (WHERE severity = 'warn')::int AS warn_24h,
           COUNT(DISTINCT hostname) FILTER (WHERE hostname IS NOT NULL)::int AS hosts_24h,
           MAX(event_time) AS last_event_at
         FROM detection_events
         WHERE event_time >= NOW() - INTERVAL '24 hours'
           AND sensor_family IS NOT NULL
         GROUP BY sensor_family`,
      );
      const byFamily = new Map(statsRows.map((r) => [r.sensor_family, r]));

      const out = families.map((f) => {
        const st = byFamily.get(f.family) ?? {};
        return {
          family: f.family,
          label: f.label,
          category: f.category,
          enabled: f.enabled,
          source_logs: f.sourceLogs,
          events_24h: st.events_24h ?? 0,
          critical_24h: st.critical_24h ?? 0,
          warn_24h: st.warn_24h ?? 0,
          hosts_24h: st.hosts_24h ?? 0,
          last_event_at: st.last_event_at ?? null,
        };
      });
      res.json({ ok: true, families: out });
    } catch (err) {
      logger.error("detection_kpis", { msg: err.message });
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  /** Catálogo de fuentes + estadísticas (alias de detection-sources). */
  router.get("/sources", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT source_log, COUNT(*)::int AS events_24h, MAX(event_time) AS last_event_at
           FROM detection_events
          WHERE event_time >= NOW() - INTERVAL '24 hours'
          GROUP BY source_log`,
      );
      const counts = new Map(rows.map((r) => [r.source_log, r]));
      const families = getDetectionFamilies().map((f) => ({
        ...f,
        sources: f.sourceLogs.map((sl) => {
          const c = counts.get(sl) ?? {};
          const cat = lookupSourceLog(sl);
          return {
            source_log: sl,
            sensor_name: cat.sensor_name,
            network_zone: cat.network_zone,
            iceberg_table: cat.iceberg_table,
            enabled: cat.enabled,
            events_24h: c.events_24h ?? 0,
            last_event_at: c.last_event_at ?? null,
          };
        }),
      }));
      res.json({ ok: true, sources: families });
    } catch (err) {
      logger.error("detection_sources", { msg: err.message });
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  /** Habilitar/deshabilitar familia de sensor (admin). */
  router.patch("/sources/:family", async (req, res) => {
    try {
      const role = req.user?.roles?.[0] ?? req.user?.role ?? "";
      const isAdmin =
        role === "admin" ||
        req.user?.isLabMode ||
        process.env.OIDC_ENABLED?.trim() !== "true";
      if (!isAdmin) {
        return res.status(403).json({ ok: false, error: "Solo administradores." });
      }
      const enabled = req.body?.enabled !== false;
      const operator = req.user?.email ?? req.user?.preferredUsername ?? "operator";
      const affected = await setFamilyEnabled(req.params.family, enabled, operator);
      res.json({ ok: true, affected, enabled });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  /** Estadísticas globales + timeline por hora. */
  router.get("/stats", async (req, res) => {
    try {
      const hours = Math.min(Math.max(parseInt(req.query.hours ?? "24", 10) || 24, 1), 168);
      const interval = `${hours} hours`;

      const [totals] = await pgQuery(
        `SELECT
           COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE severity IN ('critical', 'error'))::int AS critical,
           COUNT(*) FILTER (WHERE severity = 'warn')::int AS warn,
           COUNT(DISTINCT hostname) FILTER (WHERE hostname IS NOT NULL)::int AS hosts,
           COUNT(DISTINCT source_log)::int AS source_logs,
           MAX(event_time) AS last_event_at
         FROM detection_events
         WHERE event_time >= NOW() - $1::interval`,
        [interval],
      );

      const severityRows = await pgQuery(
        `SELECT severity, COUNT(*)::int AS count
           FROM detection_events
          WHERE event_time >= NOW() - $1::interval
          GROUP BY severity
          ORDER BY count DESC`,
        [interval],
      );

      const timelineRows = await pgQuery(
        `SELECT
           date_trunc('hour', event_time) AS bucket,
           COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE severity IN ('critical', 'error'))::int AS critical
         FROM detection_events
         WHERE event_time >= NOW() - $1::interval
         GROUP BY 1
         ORDER BY 1`,
        [interval],
      );

      const familyRows = await pgQuery(
        `SELECT sensor_family AS family, COUNT(*)::int AS count
           FROM detection_events
          WHERE event_time >= NOW() - $1::interval
            AND sensor_family IS NOT NULL
          GROUP BY sensor_family
          ORDER BY count DESC
          LIMIT 8`,
        [interval],
      );

      res.json({
        ok: true,
        hours,
        total: totals?.total ?? 0,
        critical: totals?.critical ?? 0,
        warn: totals?.warn ?? 0,
        hosts: totals?.hosts ?? 0,
        source_logs: totals?.source_logs ?? 0,
        last_event_at: totals?.last_event_at ?? null,
        severity: severityRows,
        timeline: timelineRows.map((row) => ({
          bucket: row.bucket,
          total: row.total,
          critical: row.critical,
        })),
        top_families: familyRows,
      });
    } catch (err) {
      logger.error("detection_stats", { msg: err.message });
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  /** Detalle de un evento. */
  router.get("/events/:id", async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, source_log, sensor_family, severity, hostname, source, message,
                raw, src_ip::text AS src_ip, dst_ip::text AS dst_ip, rule_id,
                event_time, ingested_at, agent_id
           FROM detection_events
          WHERE id = $1::uuid`,
        [req.params.id],
      );
      if (!rows.length) {
        return res.status(404).json({ ok: false, error: "Evento no encontrado." });
      }
      res.json({ ok: true, data: rows[0] });
    } catch (err) {
      logger.error("detection_event_get", { msg: err.message });
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  /** Listar eventos con filtros. */
  router.get("/events", async (req, res) => {
    try {
      const hours = Math.min(Math.max(parseInt(req.query.hours ?? "24", 10) || 24, 1), 168);
      const limit = Math.min(Math.max(parseInt(req.query.limit ?? "100", 10) || 100, 1), 500);
      const offset = Math.max(parseInt(req.query.offset ?? "0", 10) || 0, 0);
      const sourceLog = String(req.query.source_log ?? "").trim();
      const family = String(req.query.family ?? "").trim();
      const severity = String(req.query.severity ?? "").trim();
      const q = String(req.query.q ?? "").trim().slice(0, 200);

      const where = ["event_time >= NOW() - $1::interval"];
      const params = [`${hours} hours`];
      let idx = 2;

      if (sourceLog) {
        where.push(`source_log = $${idx++}`);
        params.push(sourceLog);
      }
      if (family) {
        where.push(`sensor_family = $${idx++}`);
        params.push(family);
      }
      if (severity && VALID_SEVERITIES.has(severity)) {
        where.push(`severity = $${idx++}`);
        params.push(severity);
      }
      if (q) {
        where.push(
          `(message ILIKE $${idx} OR hostname ILIKE $${idx} OR src_ip::text ILIKE $${idx} OR dst_ip::text ILIKE $${idx} OR rule_id ILIKE $${idx})`,
        );
        params.push(`%${q}%`);
        idx++;
      }

      params.push(limit, offset);
      const sql = `
        SELECT id, source_log, sensor_family, severity, hostname, source, message,
               raw, src_ip::text AS src_ip, dst_ip::text AS dst_ip, rule_id,
               event_time, ingested_at, agent_id
          FROM detection_events
         WHERE ${where.join(" AND ")}
         ORDER BY event_time DESC
         LIMIT $${idx++} OFFSET $${idx}`;
      const rows = await pgQuery(sql, params);

      const countSql = `SELECT COUNT(*)::int AS total FROM detection_events WHERE ${where.join(" AND ")}`;
      const [{ total }] = await pgQuery(countSql, params.slice(0, -2));

      res.json({ ok: true, data: rows, total, limit, offset });
    } catch (err) {
      logger.error("detection_events_list", { msg: err.message });
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  /** Tipos de log admitidos para scripts (desde catálogo). */
  router.get("/log-types", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT source_log, sensor_name, sensor_family, source_category,
                network_zone, iceberg_table, enabled, notes
           FROM legacyhunt_soc.source_log_catalog
          WHERE sensor_family <> 'manual'
          ORDER BY sensor_family, source_log`,
      );
      res.json({ ok: true, log_types: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  return router;
}
