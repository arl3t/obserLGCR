/**
 * API de inventario hardware/software + gobernanza.
 */
import { Router } from "express";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { verifyAgentToken } from "../services/agentAuth.mjs";
import { ingestInventoryReport } from "../services/inventoryReportService.mjs";
import { timingSafeEqual } from "node:crypto";

const NOC_AGENT_TOKEN = (process.env.NOC_AGENT_TOKEN ?? "").trim();

function timingSafeStrEq(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) {
    timingSafeEqual(ba, ba);
    return false;
  }
  return timingSafeEqual(ba, bb);
}

function requireAgent(req, res, next) {
  const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, "")?.trim() ?? "";
  if (!bearer) {
    return res.status(401).json({ success: false, error: "Token de agente requerido." });
  }
  if (NOC_AGENT_TOKEN && timingSafeStrEq(bearer, NOC_AGENT_TOKEN)) return next();
  try {
    verifyAgentToken(bearer);
    return next();
  } catch {
    return res.status(401).json({ success: false, error: "No autorizado." });
  }
}

export default function inventoryRouter() {
  const router = Router();

  router.post("/report", requireAgent, async (req, res) => {
    try {
      const payload = req.body ?? {};
      const sourceIp = req.ip ?? req.headers["x-forwarded-for"]?.toString()?.split(",")[0]?.trim();
      const result = await ingestInventoryReport(payload, { sourceIp });
      return res.status(result.unchanged ? 200 : 201).json({ success: true, ...result });
    } catch (err) {
      logger.error("inventory_report_error", { msg: err.message });
      if (err.code === "42P01") {
        return res.status(503).json({
          success: false,
          error: "Esquema de inventario no migrado. Ejecute migraciones 115 y 122.",
        });
      }
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/hosts/by-noc-device/:deviceId", async (req, res) => {
    try {
      const [dev] = await pgQuery(
        `SELECT id, hostname, ip_address::text AS ip_address FROM noc_devices WHERE id = $1`,
        [req.params.deviceId],
      );
      if (!dev) {
        return res.status(404).json({ success: false, error: "Dispositivo NOC no encontrado." });
      }

      const ipPlain = dev.ip_address ? String(dev.ip_address).split("/")[0] : null;
      const rows = await pgQuery(
        `SELECT id, hostname, os_name, os_version, ip_address::text AS ip_address,
                software_count, last_report_at, report_count, cpu_cores, ram_mb,
                manufacturer, model
           FROM inventory_hosts
          WHERE lower(hostname) = lower($1)
             OR ($2::text IS NOT NULL AND host(ip_address) = $2::text)
          ORDER BY last_report_at DESC NULLS LAST
          LIMIT 1`,
        [dev.hostname, ipPlain],
      );

      return res.json({ success: true, data: rows[0] ?? null });
    } catch (err) {
      if (err.code === "42P01") {
        return res.json({ success: true, data: null });
      }
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/hosts", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, hostname, os_name, os_version, ip_address, software_count,
                last_report_at, report_count, cpu_cores, ram_mb, manufacturer, model
           FROM inventory_hosts
          ORDER BY last_report_at DESC NULLS LAST
          LIMIT 200`,
      );
      return res.json({ success: true, data: rows, meta: { total: rows.length } });
    } catch (err) {
      if (err.code === "42P01") {
        return res.json({ success: true, data: [], meta: { total: 0 } });
      }
      logger.error("inventory_hosts_list", { msg: err.message });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/hosts/:id/software", async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT name, version, publisher, install_date FROM inventory_software
          WHERE host_id = $1 ORDER BY lower(name)`,
        [req.params.id],
      );
      return res.json({ success: true, data: rows });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/hosts/:id/server-software", async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, name, version, publisher, install_date, package_manager,
                is_whitelisted, is_blacklisted, collected_at
           FROM server_software
          WHERE server_id = $1
          ORDER BY is_blacklisted DESC, lower(name)`,
        [req.params.id],
      );
      return res.json({ success: true, data: rows });
    } catch (err) {
      if (err.code === "42P01") return res.json({ success: true, data: [] });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/governance/blacklist", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, software_name, match_type, pattern, publisher, severity,
                mitre_technique, enabled, auto_incident, notes, created_at
           FROM software_blacklist ORDER BY software_name`,
      );
      return res.json({ success: true, data: rows });
    } catch (err) {
      if (err.code === "42P01") return res.json({ success: true, data: [] });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.post("/governance/blacklist", async (req, res) => {
    try {
      const b = req.body ?? {};
      if (!b.pattern || !b.software_name) {
        return res.status(400).json({ success: false, error: "software_name y pattern requeridos." });
      }
      const [row] = await pgQuery(
        `INSERT INTO software_blacklist (
           software_name, match_type, pattern, publisher, severity,
           mitre_technique, enabled, auto_incident, notes, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING *`,
        [
          b.software_name,
          b.match_type ?? "exact",
          b.pattern,
          b.publisher ?? null,
          b.severity ?? "HIGH",
          b.mitre_technique ?? null,
          b.enabled !== false,
          b.auto_incident !== false,
          b.notes ?? null,
          b.created_by ?? "admin",
        ],
      );
      try {
        await pgQuery(
          `UPDATE server_software ss
              SET name = ss.name
            FROM software_blacklist bl
           WHERE bl.id = $1
             AND bl.enabled
             AND noc_match_software_rule(
                   ss.name, ss.version, ss.publisher,
                   bl.match_type, bl.pattern, bl.publisher
                 )`,
          [row.id],
        );
      } catch (reapplyErr) {
        logger.warn("governance_reapply_failed", { id: row.id, msg: reapplyErr.message });
      }
      return res.status(201).json({ success: true, data: row });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.delete("/governance/blacklist/:id", async (req, res) => {
    try {
      const rows = await pgQuery(`DELETE FROM software_blacklist WHERE id = $1 RETURNING id`, [
        req.params.id,
      ]);
      if (!rows.length) return res.status(404).json({ success: false, error: "No encontrado." });
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/governance/whitelist", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, software_name, match_type, pattern, publisher, enabled, notes, created_at
           FROM software_whitelist ORDER BY software_name`,
      );
      return res.json({ success: true, data: rows });
    } catch (err) {
      if (err.code === "42P01") return res.json({ success: true, data: [] });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.post("/governance/whitelist", async (req, res) => {
    try {
      const b = req.body ?? {};
      if (!b.pattern || !b.software_name) {
        return res.status(400).json({ success: false, error: "software_name y pattern requeridos." });
      }
      const [row] = await pgQuery(
        `INSERT INTO software_whitelist (
           software_name, match_type, pattern, publisher, enabled, notes, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)
         RETURNING *`,
        [
          b.software_name,
          b.match_type ?? "exact",
          b.pattern,
          b.publisher ?? null,
          b.enabled !== false,
          b.notes ?? null,
          b.created_by ?? "admin",
        ],
      );
      try {
        await pgQuery(
          `UPDATE server_software ss
              SET name = ss.name
            FROM software_whitelist wl
           WHERE wl.id = $1
             AND wl.enabled
             AND noc_match_software_rule(
                   ss.name, ss.version, ss.publisher,
                   wl.match_type, wl.pattern, wl.publisher
                 )`,
          [row.id],
        );
      } catch (reapplyErr) {
        logger.warn("governance_reapply_failed", { id: row.id, msg: reapplyErr.message });
      }
      return res.status(201).json({ success: true, data: row });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.delete("/governance/whitelist/:id", async (req, res) => {
    try {
      const rows = await pgQuery(`DELETE FROM software_whitelist WHERE id = $1 RETURNING id`, [
        req.params.id,
      ]);
      if (!rows.length) return res.status(404).json({ success: false, error: "No encontrado." });
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/governance/incidents-queue", async (req, res) => {
    try {
      const status = req.query.status ?? "pending";
      const rows = await pgQuery(
        `SELECT id, created_at, incident_type, severity, hostname, status, case_id, payload
           FROM incidents_queue
          WHERE status = $1
          ORDER BY created_at DESC
          LIMIT 100`,
        [status],
      );
      return res.json({ success: true, data: rows });
    } catch (err) {
      if (err.code === "42P01") return res.json({ success: true, data: [] });
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  router.get("/governance/config", async (_req, res) => {
    try {
      const [row] = await pgQuery(
        `SELECT strict_whitelist, updated_at FROM software_governance_config WHERE id = true`,
      );
      return res.json({ success: true, data: row ?? { strict_whitelist: false } });
    } catch (err) {
      return res.json({ success: true, data: { strict_whitelist: false } });
    }
  });

  router.patch("/governance/config", async (req, res) => {
    try {
      const { strict_whitelist } = req.body ?? {};
      const [row] = await pgQuery(
        `INSERT INTO software_governance_config (id, strict_whitelist, updated_at)
         VALUES (true, $1, NOW())
         ON CONFLICT (id) DO UPDATE SET strict_whitelist = EXCLUDED.strict_whitelist, updated_at = NOW()
         RETURNING *`,
        [Boolean(strict_whitelist)],
      );
      return res.json({ success: true, data: row });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  return router;
}
