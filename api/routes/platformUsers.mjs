/**
 * API de usuarios del dashboard (platform_users en PostgreSQL).
 */
import { Router } from "express";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { requireAuth } from "../middleware/auth.middleware.mjs";
import { hashAgentPassword, verifyAgentPassword } from "../services/agentAuth.mjs";

const VALID_ROLES = ["analyst", "hunter", "manager", "admin"];

function userRow(r) {
  return {
    id: r.id,
    email: r.email,
    display_name: r.display_name,
    role: r.role,
    enabled: r.enabled,
    last_login_at: r.last_login_at,
    created_at: r.created_at,
  };
}

export default function platformUsersRouter() {
  const router = Router();

  router.get("/me", requireAuth(), async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, email, display_name, role, enabled, last_login_at, created_at
         FROM platform_users WHERE id = $1 LIMIT 1`,
        [req.user.sub],
      );
      if (!rows[0]) {
        return res.status(404).json({ success: false, error: "Usuario no encontrado." });
      }
      return res.json({ success: true, data: userRow(rows[0]) });
    } catch (err) {
      logger.error("users_me", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  router.patch("/me/password", requireAuth(), async (req, res) => {
    try {
      const { current_password: current, new_password: next } = req.body ?? {};
      if (!current || !next || String(next).length < 8) {
        return res.status(400).json({
          success: false,
          error: "current_password y new_password (mín. 8 caracteres) son requeridos.",
        });
      }

      const rows = await pgQuery(
        `SELECT id, pass_hash FROM platform_users WHERE id = $1 AND enabled = true`,
        [req.user.sub],
      );
      const row = rows[0];
      if (!row) {
        return res.status(404).json({ success: false, error: "Usuario no encontrado." });
      }

      const ok = await verifyAgentPassword(current, row.pass_hash);
      if (!ok) {
        return res.status(401).json({ success: false, error: "Contraseña actual incorrecta." });
      }

      const passHash = await hashAgentPassword(next);
      await pgQuery(`UPDATE platform_users SET pass_hash = $2 WHERE id = $1`, [row.id, passHash]);
      return res.json({ success: true, message: "Contraseña actualizada." });
    } catch (err) {
      logger.error("users_me_password", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  router.get("/", requireAuth("admin"), async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT id, email, display_name, role, enabled, last_login_at, created_at
         FROM platform_users ORDER BY created_at ASC`,
      );
      return res.json({ success: true, data: rows.map(userRow) });
    } catch (err) {
      logger.error("users_list", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  router.post("/", requireAuth("admin"), async (req, res) => {
    try {
      const { email, password, display_name: displayName, role = "analyst" } = req.body ?? {};
      if (!email || !password) {
        return res.status(400).json({ success: false, error: "email y password son requeridos." });
      }
      if (!VALID_ROLES.includes(role)) {
        return res.status(400).json({ success: false, error: `role inválido: ${VALID_ROLES.join(", ")}` });
      }
      if (String(password).length < 8) {
        return res.status(400).json({ success: false, error: "password debe tener al menos 8 caracteres." });
      }

      const passHash = await hashAgentPassword(password);
      const rows = await pgQuery(
        `INSERT INTO platform_users (email, pass_hash, display_name, role)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, display_name, role, enabled, last_login_at, created_at`,
        [String(email).trim().toLowerCase(), passHash, displayName ?? email, role],
      );
      return res.status(201).json({ success: true, data: userRow(rows[0]) });
    } catch (err) {
      if (err.code === "23505") {
        return res.status(409).json({ success: false, error: "El email ya está registrado." });
      }
      logger.error("users_create", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  router.patch("/:id", requireAuth("admin"), async (req, res) => {
    try {
      const { display_name: displayName, role, enabled, password } = req.body ?? {};
      const sets = [];
      const vals = [req.params.id];
      let idx = 2;

      if (displayName !== undefined) {
        sets.push(`display_name = $${idx++}`);
        vals.push(displayName);
      }
      if (role !== undefined) {
        if (!VALID_ROLES.includes(role)) {
          return res.status(400).json({ success: false, error: `role inválido: ${VALID_ROLES.join(", ")}` });
        }
        sets.push(`role = $${idx++}`);
        vals.push(role);
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
        `UPDATE platform_users SET ${sets.join(", ")} WHERE id = $1
         RETURNING id, email, display_name, role, enabled, last_login_at, created_at`,
        vals,
      );
      if (!rows[0]) {
        return res.status(404).json({ success: false, error: "Usuario no encontrado." });
      }
      return res.json({ success: true, data: userRow(rows[0]) });
    } catch (err) {
      logger.error("users_patch", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  return router;
}
