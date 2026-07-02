/**
 * API de credenciales de agentes NOC (agent_credentials en PostgreSQL).
 * Usadas por scripts de registro de activos, shipper de detección y SNMP/Telegraf.
 */
import { Router } from "express";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { requireAuth } from "../middleware/auth.middleware.mjs";
import { hashAgentPassword } from "../services/agentAuth.mjs";

const VALID_ROLES = ["infraestructura"];

function agentRow(r) {
  return {
    id: r.id,
    email: r.email,
    display_name: r.display_name,
    role: r.role,
    enabled: r.enabled,
    last_auth_at: r.last_auth_at,
    created_at: r.created_at,
  };
}

export default function agentCredentialsRouter() {
  const router = Router();

  router.get("/", requireAuth("admin"), async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, email, display_name, role, enabled, last_auth_at, created_at
         FROM agent_credentials
         ORDER BY created_at ASC`,
      );
      return res.json({ success: true, data: rows.map(agentRow) });
    } catch (err) {
      if (err.code === "42P01") {
        return res.status(503).json({
          success: false,
          error: "Tabla agent_credentials no migrada. Ejecute migración 118.",
        });
      }
      logger.error("agents_list", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  router.post("/", requireAuth("admin"), async (req, res) => {
    try {
      const { email, password, display_name: displayName, role = "infraestructura" } = req.body ?? {};
      if (!email || !password) {
        return res.status(400).json({ success: false, error: "email y password son requeridos." });
      }
      if (!VALID_ROLES.includes(role)) {
        return res.status(400).json({
          success: false,
          error: `role inválido: ${VALID_ROLES.join(", ")}`,
        });
      }
      if (String(password).length < 8) {
        return res.status(400).json({ success: false, error: "password debe tener al menos 8 caracteres." });
      }

      const passHash = await hashAgentPassword(password);
      const rows = await pgQuery(
        `INSERT INTO agent_credentials (email, pass_hash, display_name, role)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, display_name, role, enabled, last_auth_at, created_at`,
        [String(email).trim().toLowerCase(), passHash, displayName ?? email, role],
      );
      return res.status(201).json({ success: true, data: agentRow(rows[0]) });
    } catch (err) {
      if (err.code === "23505") {
        return res.status(409).json({ success: false, error: "El email ya está registrado." });
      }
      logger.error("agents_create", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  router.patch("/:id", requireAuth("admin"), async (req, res) => {
    try {
      const { email, password, display_name: displayName, enabled } = req.body ?? {};
      const sets = [];
      const vals = [req.params.id];
      let idx = 2;

      if (email !== undefined) {
        sets.push(`email = $${idx++}`);
        vals.push(String(email).trim().toLowerCase());
      }
      if (displayName !== undefined) {
        sets.push(`display_name = $${idx++}`);
        vals.push(displayName);
      }
      if (enabled !== undefined) {
        sets.push(`enabled = $${idx++}`);
        vals.push(Boolean(enabled));
      }
      if (password !== undefined) {
        if (String(password).length < 8) {
          return res.status(400).json({ success: false, error: "password debe tener al menos 8 caracteres." });
        }
        sets.push(`pass_hash = $${idx++}`);
        vals.push(await hashAgentPassword(password));
      }

      if (sets.length === 0) {
        return res.status(400).json({ success: false, error: "Nada que actualizar." });
      }

      const rows = await pgQuery(
        `UPDATE agent_credentials SET ${sets.join(", ")} WHERE id = $1
         RETURNING id, email, display_name, role, enabled, last_auth_at, created_at`,
        vals,
      );
      if (!rows[0]) {
        return res.status(404).json({ success: false, error: "Agente no encontrado." });
      }
      return res.json({ success: true, data: agentRow(rows[0]) });
    } catch (err) {
      if (err.code === "23505") {
        return res.status(409).json({ success: false, error: "El email ya está registrado." });
      }
      logger.error("agents_patch", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  return router;
}
