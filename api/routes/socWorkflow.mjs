/**
 * socWorkflow.mjs
 * API del flujo de trabajo SOC: roles, operadores, transiciones, notificaciones,
 * auto-acciones y handover.
 *
 * Monta en: /api/workflow
 *
 * Endpoints:
 *   — Roles
 *   GET  /roles                        Lista todos los roles con permisos
 *
 *   — Operadores SOC
 *   GET  /operators                    Lista operadores (con KPIs)
 *   POST /operators/register           Registrar operador con rol
 *   GET  /operators/:id                Detalle de un operador
 *   PATCH /operators/:id/role          Cambiar rol (LEADER/ADMIN only)
 *   GET  /operators/shift-manager/current  Shift Manager activo
 *   PATCH /operators/:id/shift-manager     Designar como Shift Manager
 *
 *   — Cola de trabajo
 *   GET  /queue                        Cola de casos activos por prioridad
 *   GET  /queue/l1                     Cola para triaje L1
 *   GET  /queue/l2                     Cola para investigación L2
 *   GET  /queue/l3                     Cola de respuesta L3
 *
 *   — Transiciones de estado
 *   POST /cases/:id/transition         Transicionar caso (con validación de rol)
 *
 *   — Automatizaciones manuales (admin / shift manager)
 *   POST /automation/trigger-auto-close   Forzar cierre de LOW/NEGLIGIBLE ahora
 *   POST /automation/trigger-auto-assign  Forzar auto-asignación por timeout
 *   GET  /automation/auto-actions         Historial de acciones automáticas
 *
 *   — Notificaciones
 *   GET  /notifications/:operatorId       Notificaciones del operador
 *   PATCH /notifications/:id/read         Marcar como leída
 *   DELETE /notifications/:operatorId/all  Borrar todas las leídas
 *
 *   — Handover
 *   POST /handover                     Crear reporte de handover
 *   GET  /handover/latest              Último reporte
 *   GET  /handover                     Lista de reportes (paginado)
 *   PATCH /handover/:id/acknowledge    Confirmar recepción del handover
 *
 *   — Health
 *   GET  /health                       Estado del scheduler y tareas
 */

import express from "express";
import { randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import {
  kcFindUser,
  kcFindUserByEmail,
  kcGetUserById,
  kcCreateUser,
  kcSetPassword,
  kcAssignRealmRole,
  kcHealthCheck,
} from "../services/kcAdmin.mjs";
import { trinoExec } from "../services/trinoWriter.mjs";

// ── Mapas de rol para compatibilidad con la tabla Trino soc_operators ────────
// La PG usa role_id ∈ {L1, L1L2, L2, L3, LEADER, ADMIN}.
// La Trino soc_operators (legacy) usa role ∈ {analyst, leader, admin, viewer, senior, lead}.
// Durante Fase 1 de unificación escribimos a ambas; este mapa controla la
// traducción bidireccional.
const PG_ROLE_FROM_LEGACY = {
  analyst: "L1L2", ANALYST: "L1L2",
  leader:  "LEADER", LEADER:  "LEADER",
  admin:   "ADMIN",  ADMIN:   "ADMIN",
  l1:      "L1",     L1:      "L1",
  l1l2:    "L1L2",   L1L2:    "L1L2",
  l2:      "L2",     L2:      "L2",
  l3:      "L3",     L3:      "L3",
};
const LEGACY_ROLE_FROM_PG = {
  L1:    "analyst",
  L1L2:  "analyst",
  L2:    "analyst",
  L3:    "analyst",
  LEADER:"leader",
  ADMIN: "admin",
};

/**
 * Replica un operador a la tabla Trino `minio_iceberg.hunting.soc_operators`
 * para que los consumidores que aún leen de Trino (fetchOperatorsCatalog,
 * resolveOperatorContext, GET /api/operators, soc-chat) vean al operador.
 *
 * Dual-write de Fase 1 — se elimina cuando Fase 2 migre esos lectores a PG.
 * No bloquea el registro en PG si Trino está caído; emite warning.
 */
async function syncOperatorToTrino({ id, name, roleId, team }) {
  const legacyRole = LEGACY_ROLE_FROM_PG[roleId] ?? "analyst";
  const esc = (s) => `'${String(s ?? "").replace(/'/g, "''")}'`;
  const table = "minio_iceberg.hunting.soc_operators";
  const delSql = `DELETE FROM ${table} WHERE operator_id = ${esc(id)}`;
  const insSql = `
INSERT INTO ${table} (operator_id, display_name, role, ci_hash, team, active, updated_at)
VALUES (${esc(id)}, ${esc(name)}, ${esc(legacyRole)}, NULL, ${esc(team || "SOC")}, true, current_timestamp)
`.trim();
  const del = await trinoExec(delSql, { catalog: "minio_iceberg", schema: "hunting" });
  if (!del.ok) {
    logger.warn("trino_sync_delete_failed", { id, error: del.error });
    return { ok: false, error: del.error };
  }
  const ins = await trinoExec(insSql, { catalog: "minio_iceberg", schema: "hunting" });
  if (!ins.ok) {
    logger.warn("trino_sync_insert_failed", { id, error: ins.error });
    return { ok: false, error: ins.error };
  }
  return { ok: true };
}
import {
  validateTransition,
  shouldAutoEscalate,
  getActiveShiftManager,
  createNotification,
  recordAutoAction,
  autoCloseLowNegligible,
  autoAssignTimeoutCases,
  transitionCase,
  createHandoverReport,
} from "../services/workflowEngine.mjs";
import {
  getSchedulerStatus, getSchedulerMetrics,
  withAdvisoryLock, LOCK_AUTO_CLOSE, LOCK_AUTO_ASSIGN, LOCK_FOLLOWUP_DIGEST,
} from "../services/schedulerService.mjs";
import { getWorkflowMetrics } from "../services/workflowEngine.mjs";
import { sendFollowupDigest, collectFollowupData } from "../services/followupDigestService.mjs";
import { getCacheStats } from "../trino/query-cache.mjs";
import { optionalAuth } from "../middleware/auth.middleware.mjs";

// ── Middleware ligero de rol ──────────────────────────────────────────────────
// Resolución de operador en este orden:
//   1. JWT sub (req.user.sub) → soc_operators.kc_user_id   (preferido)
//   2. Header x-operator-ci → soc_operators.id             (legacy / lab)
//   3. JWT preferred_username → soc_operators.id           (fallback: kc_user_id no vinculado)
//      Si encuentra match por preferred_username, vincula kc_user_id automáticamente
//      para que la próxima request use el path 1.
async function resolveOperatorRole(req, _res, next) {
  req.operator = null;
  req.operatorRole = null;

  const sub = req.user?.sub;
  const ci  = req.headers["x-operator-ci"] ?? req.body?.operatorCi ?? req.query?.operatorCi;

  try {
    let rows = [];
    if (sub && !req.user?.isLabMode && !req.user?.isApiKey) {
      rows = await pgQuery(
        `SELECT id, name, role_id, is_shift_manager, kc_user_id
           FROM soc_operators WHERE kc_user_id = $1`,
        [sub]
      );
    }
    if (!rows.length && ci) {
      rows = await pgQuery(
        `SELECT id, name, role_id, is_shift_manager, kc_user_id
           FROM soc_operators WHERE id = $1`,
        [ci]
      );
    }
    // Fallback: intentar vincular por preferred_username cuando kc_user_id es null.
    // Cubre el caso de operadores creados antes de conectar Keycloak cuyo id
    // coincide con el username de KC (cédula, legajo, etc.).
    if (!rows.length && sub && !req.user?.isLabMode && req.user?.preferred_username) {
      rows = await pgQuery(
        `SELECT id, name, role_id, is_shift_manager, kc_user_id
           FROM soc_operators WHERE id = $1 AND kc_user_id IS NULL`,
        [req.user.preferred_username]
      );
      if (rows.length) {
        // Auto-vincular para evitar este camino en solicitudes futuras.
        void pgQuery(
          `UPDATE soc_operators SET kc_user_id = $1 WHERE id = $2`,
          [sub, rows[0].id]
        );
      }
    }
    req.operator = rows[0] ?? null;
    req.operatorRole = rows[0]?.role_id ?? null;
  } catch (_) {
    req.operator = null;
    req.operatorRole = null;
  }
  next();
}

export default function socWorkflowRouter(getIo) {
  const r = express.Router();
  r.use(express.json());
  r.use(optionalAuth);         // Pobla req.user desde JWT si viene; no bloquea si falta.
  r.use(resolveOperatorRole);  // Resuelve operador por kc_user_id (JWT) o x-operator-ci.

  const io = () => { try { return getIo(); } catch { return null; } };

  // ───────────────────────────────────────────────────────────────────────────
  // ROLES
  // ───────────────────────────────────────────────────────────────────────────

  r.get("/roles", async (_req, res) => {
    try {
      const rows = await pgQuery(`SELECT * FROM soc_roles ORDER BY id`);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // OPERADORES
  // ───────────────────────────────────────────────────────────────────────────

  r.get("/operators", async (_req, res) => {
    try {
      const rows = await pgQuery(`
        SELECT o.*, r.name AS role_name, r.can_review_kpis, r.receives_auto_assign
        FROM soc_operators o
        JOIN soc_roles r ON r.id = o.role_id
        ORDER BY r.id, o.name
      `);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Acepta dos shapes de payload:
  //   (a) "nuevo": { id, name, email, roleId, shift, notes, team, ci_hash }
  //   (b) "legacy" del UI de auto-registro: { display_name, ci, role, team }
  //       con role ∈ {analyst, leader, admin} mapeado a role_id PG.
  // Ambos caen en el mismo INSERT sobre PG y dual-write a Trino (Fase 1).
  r.post("/operators/register", async (req, res) => {
    const body = req.body ?? {};
    // Normalización del payload
    const id    = String(body.id    ?? body.ci ?? "").trim().replace(/\D/g, "") || String(body.id ?? "").trim();
    const name  = String(body.name  ?? body.display_name ?? "").trim();
    const email = body.email ? String(body.email).trim() : null;
    const team  = body.team  ? String(body.team).trim()  : "SOC";
    const shift = String(body.shift ?? "MORNING").toUpperCase();
    const notes = body.notes ? String(body.notes) : null;
    const ciHash = body.ci_hash ? String(body.ci_hash) : null;

    // roleId directo o derivado del legacy `role`
    let roleId = body.roleId ? String(body.roleId).trim() : null;
    if (!roleId && body.role) {
      const legacy = String(body.role).trim().toLowerCase();
      roleId = PG_ROLE_FROM_LEGACY[legacy] ?? null;
    }
    if (!roleId) roleId = "L1";

    if (!id   || id.length   < 2) return res.status(400).json({ error: "id/ci obligatorio (mínimo 2 caracteres)" });
    if (!name || name.length < 2) return res.status(400).json({ error: "name/display_name obligatorio (mínimo 2 caracteres)" });

    try {
      await pgQuery(
        `INSERT INTO soc_operators (id, name, email, role_id, shift, notes, team, ci_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (id) DO UPDATE
           SET name=$2, email=$3, role_id=$4, shift=$5, notes=$6, team=$7, ci_hash=$8, last_active_at=now()`,
        [id, name, email, roleId, shift, notes, team, ciHash]
      );

      // Auto-vincular kc_user_id si el operador ya existe en Keycloak.
      // Evita que un DELETE + re-registro pierda el vínculo OIDC y bloquee al admin
      // por 403 en endpoints que requieren LEADER/ADMIN (resolveOperatorRole lo
      // resuelve por kc_user_id = JWT.sub).
      try {
        const [{ kc_user_id: existing } = {}] =
          await pgQuery(`SELECT kc_user_id FROM soc_operators WHERE id=$1`, [id]);
        if (!existing) {
          let kcUser = await kcFindUser(id).catch(() => null);
          if (!kcUser && email) kcUser = await kcFindUserByEmail(email).catch(() => null);
          if (kcUser?.id) {
            await pgQuery(
              `UPDATE soc_operators SET kc_user_id=$1 WHERE id=$2`,
              [kcUser.id, id],
            );
          }
        }
      } catch (linkErr) {
        // No bloquea el register si KC no está disponible
        logger.warn("kc_auto_link_failed", { id, error: String(linkErr?.message ?? linkErr) });
      }

      // Dual-write a Trino legacy (Fase 1 del plan de unificación).
      // Falla aislado: si Trino está caído o lento, el operador queda en PG
      // y aparecerá en la tabla Trino en el próximo re-registro o al correr
      // el script de backfill.
      await syncOperatorToTrino({ id, name, roleId, team }).catch((e) => {
        logger.warn("trino_sync_exception", { id, error: String(e?.message ?? e) });
      });

      const [op] = await pgQuery(`SELECT * FROM soc_operators WHERE id=$1`, [id]);
      res.json(op);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.get("/operators/shift-manager/current", async (_req, res) => {
    try {
      const manager = await getActiveShiftManager();
      res.json(manager ?? { message: "No hay Shift Manager activo" });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.get("/operators/:id", async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT o.*, r.name AS role_name, r.can_review_kpis, r.can_assign_cases,
                r.can_escalate_to_l2, r.can_escalate_to_l3, r.can_post_mortem
         FROM soc_operators o JOIN soc_roles r ON r.id=o.role_id
         WHERE o.id=$1`, [req.params.id]
      );
      if (!rows.length) return res.status(404).json({ error: "Operador no encontrado" });
      res.json(rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── PATCH /operators/:id — editar campos (nombre, email, turno, notas) ──────
  r.patch("/operators/:id", async (req, res) => {
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) return res.status(403).json({ error: "Solo LEADER/ADMIN pueden editar operadores" });
    const { name, email, shift, notes } = req.body ?? {};
    const sets = []; const vals = []; let i = 2;
    if (name  !== undefined) { sets.push(`name=$${i++}`);  vals.push(String(name).trim() || null); }
    if (email !== undefined) { sets.push(`email=$${i++}`); vals.push(String(email).trim() || null); }
    if (shift !== undefined) { sets.push(`shift=$${i++}`); vals.push(shift); }
    if (notes !== undefined) { sets.push(`notes=$${i++}`); vals.push(String(notes).trim() || null); }
    if (!sets.length) return res.status(400).json({ error: "Sin campos a actualizar" });
    try {
      await pgQuery(`UPDATE soc_operators SET ${sets.join(", ")} WHERE id=$1`, [req.params.id, ...vals]);
      const [op] = await pgQuery(
        `SELECT o.*, r.name AS role_name FROM soc_operators o JOIN soc_roles r ON r.id=o.role_id WHERE o.id=$1`,
        [req.params.id]
      );
      res.json(op ?? { ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── PATCH /operators/:id/status — activar / desactivar ───────────────────
  r.patch("/operators/:id/status", async (req, res) => {
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) return res.status(403).json({ error: "Solo LEADER/ADMIN pueden cambiar el estado" });
    const { isActive } = req.body ?? {};
    if (typeof isActive !== "boolean") return res.status(400).json({ error: "isActive (boolean) requerido" });
    try {
      await pgQuery(`UPDATE soc_operators SET is_active=$2 WHERE id=$1`, [req.params.id, isActive]);
      res.json({ ok: true, id: req.params.id, is_active: isActive });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── DELETE /operators/:id — eliminación definitiva (LEADER o ADMIN) ──────
  // Consistente con PATCH /operators/:id y /role (ambos LEADER+ADMIN).
  // Salvaguardas:
  //   1. No auto-eliminación (un operador no puede borrarse a sí mismo).
  //   2. No dejar el SOC sin LEADER/ADMIN activos: si la baja deja 0
  //      operadores con rol LEADER o ADMIN y is_active=true, bloquear (409).
  // Para bajas suaves (vacaciones, off-boarding temporal) sigue disponible
  // PATCH /operators/:id/status que solo cambia is_active sin borrar fila.
  r.delete("/operators/:id", async (req, res) => {
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN pueden eliminar operadores" });
    }

    const targetId = String(req.params.id ?? "").trim();
    if (!targetId) return res.status(400).json({ error: "id requerido" });

    // 1. Self-delete
    if (req.operator?.id && req.operator.id === targetId) {
      return res.status(400).json({ error: "No podés eliminarte a vos mismo" });
    }

    try {
      // Resolver rol del target para saber si su baja afecta el quórum.
      const [target] = await pgQuery(
        `SELECT id, role_id, is_active FROM soc_operators WHERE id=$1`,
        [targetId],
      );
      if (!target) return res.status(404).json({ error: "Operador no encontrado" });

      // 2. Quórum de líderes: si target es LEADER/ADMIN activo y es el último,
      //    bloquear. Ignora lab-user para no falsear el conteo en lab mode.
      if (target.is_active && ["LEADER","ADMIN"].includes(target.role_id)) {
        const [{ remaining = 0 } = {}] = await pgQuery(
          `SELECT COUNT(*)::int AS remaining
             FROM soc_operators
            WHERE role_id IN ('LEADER','ADMIN')
              AND is_active = true
              AND id <> $1
              AND id <> 'lab-user'`,
          [targetId],
        );
        if (Number(remaining) === 0) {
          return res.status(409).json({
            error: "No se puede eliminar al último LEADER/ADMIN activo. " +
                   "Promové otro operador o usá PATCH status para desactivar sin borrar.",
          });
        }
      }

      await pgQuery(`DELETE FROM soc_operators WHERE id=$1`, [targetId]);
      res.json({ ok: true, deleted: targetId });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.patch("/operators/:id/role", async (req, res) => {
    // Solo LEADER o ADMIN pueden cambiar roles
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN pueden cambiar roles" });
    }
    const { roleId } = req.body ?? {};
    if (!roleId) return res.status(400).json({ error: "roleId requerido" });
    try {
      await pgQuery(`UPDATE soc_operators SET role_id=$2 WHERE id=$1`, [req.params.id, roleId]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── GET /operators/:id/kc-status — estado de la cuenta Keycloak ─────────────
  r.get("/operators/:id/kc-status", async (req, res) => {
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) return res.status(403).json({ error: "Solo LEADER/ADMIN pueden ver estado KC" });
    try {
      const [op] = await pgQuery(
        `SELECT id, name, email, kc_user_id FROM soc_operators WHERE id=$1`,
        [req.params.id],
      );
      if (!op) return res.status(404).json({ error: "Operador no encontrado" });

      // Verificar salud de KC primero
      const kcAlive = await kcHealthCheck();
      if (!kcAlive) return res.json({ kcAvailable: false, kcUser: null });

      // Buscar usuario KC por username (= op.id)
      let kcUser = await kcFindUser(op.id);

      // Cachear el kc_user_id si lo encontramos ahora
      if (kcUser && !op.kc_user_id) {
        await pgQuery(`UPDATE soc_operators SET kc_user_id=$1 WHERE id=$2`, [kcUser.id, op.id]);
      }

      res.json({
        kcAvailable: true,
        kcUser: kcUser ? {
          id:       kcUser.id,
          username: kcUser.username,
          enabled:  kcUser.enabled,
          email:    kcUser.email ?? null,
        } : null,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn("kc-status error", { error: msg });
      res.json({ kcAvailable: false, kcUser: null, error: msg });
    }
  });

  // ── POST /operators/:id/set-password — crear cuenta KC y/o cambiar contraseña ─
  r.post("/operators/:id/set-password", async (req, res) => {
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) return res.status(403).json({ error: "Solo LEADER/ADMIN pueden gestionar contraseñas" });

    const { password, temporary = false } = req.body ?? {};
    // Validación local pre-KC: refleja la política del realm (length≥10, 1 mayúscula, 1 dígito)
    const pwd = String(password ?? "");
    if (pwd.length < 10)           return res.status(400).json({ error: "Mínimo 10 caracteres." });
    if (!/[A-Z]/.test(pwd))        return res.status(400).json({ error: "Debe incluir al menos una mayúscula." });
    if (!/[0-9]/.test(pwd))        return res.status(400).json({ error: "Debe incluir al menos un número." });
    if (pwd.length > 128)          return res.status(400).json({ error: "Máximo 128 caracteres." });

    try {
      const [op] = await pgQuery(
        `SELECT id, name, email, role_id, kc_user_id FROM soc_operators WHERE id=$1`,
        [req.params.id],
      );
      if (!op) return res.status(404).json({ error: "Operador no encontrado" });

      const kcAlive = await kcHealthCheck();
      if (!kcAlive) return res.status(503).json({ error: "Keycloak no disponible" });

      // Resolución en cascada del usuario KC:
      //   1. kc_user_id ya vinculado en la BD → verificar que existe en KC y usarlo.
      //   2. Buscar por username = op.id.
      //   3. Buscar por email (evita colisión 409 "User exists with same email" cuando
      //      el operador tiene CI numérico pero en KC se creó con username alfabético,
      //      p.ej. CI=3988739 ↔ KC username="soc-admin" ↔ mismo email).
      //   4. Crear usuario KC nuevo.
      let kcUser = null;
      let created = false;

      if (op.kc_user_id) {
        kcUser = await kcGetUserById(op.kc_user_id).catch(() => null);
      }
      if (!kcUser) {
        kcUser = await kcFindUser(op.id);
      }
      if (!kcUser && op.email) {
        kcUser = await kcFindUserByEmail(op.email).catch(() => null);
      }

      if (!kcUser) {
        // Crear usuario KC nuevo con el mismo username que el CI del operador
        const nameParts = (op.name ?? op.id).split(" ");
        const kcUserId  = await kcCreateUser({
          username:  op.id,
          firstName: nameParts[0],
          lastName:  nameParts.slice(1).join(" "),
          email:     op.email ?? undefined,
          socRoleId: op.role_id,
        });
        kcUser  = { id: kcUserId };
        created = true;
      }

      // Sincronizar kc_user_id en soc_operators si estaba desactualizado
      if (!op.kc_user_id || op.kc_user_id !== kcUser.id) {
        await pgQuery(`UPDATE soc_operators SET kc_user_id=$1 WHERE id=$2`, [kcUser.id, op.id]);
      }

      await kcSetPassword(kcUser.id, password, temporary);

      res.json({
        ok:        true,
        created,
        temporary,
        kcUserId:  kcUser.id,
        message:   created
          ? "Usuario Keycloak creado y contraseña establecida"
          : "Contraseña actualizada en Keycloak",
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error("set-password error", { error: msg });
      // KC rechazó la contraseña (política, usuario bloqueado, etc.) → 400 al cliente
      const isKcReject = msg.includes("400") || msg.includes("Invalid") || msg.includes("policy");
      res.status(isKcReject ? 400 : 500).json({ error: msg });
    }
  });

  // ── POST /operators/:id/assign-kc-role — asignar realm role KC ──────────────
  r.post("/operators/:id/assign-kc-role", async (req, res) => {
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) return res.status(403).json({ error: "Solo LEADER/ADMIN pueden asignar roles KC" });
    try {
      const [op] = await pgQuery(
        `SELECT id, role_id, kc_user_id FROM soc_operators WHERE id=$1`,
        [req.params.id],
      );
      if (!op) return res.status(404).json({ error: "Operador no encontrado" });

      let kcUser = op.kc_user_id ? { id: op.kc_user_id } : await kcFindUser(op.id);
      if (!kcUser) return res.status(404).json({ error: "El operador no tiene usuario Keycloak" });

      await kcAssignRealmRole(kcUser.id, op.role_id);
      res.json({ ok: true, role: op.role_id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  r.patch("/operators/:id/shift-manager", async (req, res) => {
    const isAdmin = ["LEADER","ADMIN"].includes(req.operatorRole) || req.user?.isLabMode;
    if (!isAdmin) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN pueden designar Shift Manager" });
    }
    try {
      // Desactivar el Shift Manager anterior
      await pgQuery(`UPDATE soc_operators SET is_shift_manager=false WHERE is_shift_manager=true`);
      await pgQuery(
        `UPDATE soc_operators SET is_shift_manager=true, role_id='LEADER' WHERE id=$1`,
        [req.params.id]
      );
      res.json({ ok: true, shiftManagerId: req.params.id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // COLA DE TRABAJO
  // ───────────────────────────────────────────────────────────────────────────

  // Cola general — todos los casos activos ordenados por prioridad
  r.get("/queue", async (req, res) => {
    const limit  = Math.min(100, Number(req.query.limit ?? 50));
    const offset = Number(req.query.offset ?? 0);
    try {
      const rows = await pgQuery(
        `SELECT * FROM v_workflow_queue LIMIT $1 OFFSET $2`,
        [limit, offset]
      );
      const [{ cnt }] = await pgQuery(`SELECT COUNT(*) AS cnt FROM v_workflow_queue`);
      res.json({ items: rows, total: Number(cnt), limit, offset });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Cola L1: casos NUEVO/EN_ANALISIS sin confirmar
  r.get("/queue/l1", async (_req, res) => {
    try {
      const rows = await pgQuery(`
        SELECT * FROM v_workflow_queue
        WHERE status IN ('NUEVO','EN_ANALISIS')
          AND (assigned_role IS NULL OR assigned_role IN ('L1','L1L2'))
        ORDER BY sla_pct_consumed DESC NULLS LAST, score DESC
        LIMIT 50
      `);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Cola L2: casos CONFIRMADO o escalados que esperan investigación
  r.get("/queue/l2", async (_req, res) => {
    try {
      const rows = await pgQuery(`
        SELECT * FROM v_workflow_queue
        WHERE status IN ('CONFIRMADO','EN_ANALISIS')
          AND (escalation_suggested=true OR assigned_role IN ('L2','L1L2'))
        ORDER BY sla_pct_consumed DESC, score DESC
        LIMIT 50
      `);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Cola L1L2: unión de cola L1 + L2 (triaje + investigación)
  r.get("/queue/l1l2", async (_req, res) => {
    try {
      const rows = await pgQuery(`
        SELECT * FROM v_workflow_queue
        WHERE status IN ('NUEVO','EN_ANALISIS','CONFIRMADO')
          AND (assigned_role IS NULL OR assigned_role IN ('L1','L2','L1L2')
               OR escalation_suggested=true)
        ORDER BY sla_pct_consumed DESC NULLS LAST, score DESC
        LIMIT 100
      `);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Cola L3: casos ESCALADO activos
  r.get("/queue/l3", async (_req, res) => {
    try {
      const rows = await pgQuery(`
        SELECT * FROM v_workflow_queue
        WHERE status='ESCALADO' OR assigned_role='L3'
        ORDER BY sla_pct_consumed DESC, score DESC
        LIMIT 50
      `);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // TRANSICIÓN DE ESTADO
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * POST /api/workflow/cases/:id/transition
   * Body: { toStatus, operatorCi, roleId?, reason }
   *
   * El sistema valida que el rol tenga permiso para la transición.
   */
  r.post("/cases/:id/transition", async (req, res) => {
    const {
      toStatus, operatorCi, roleId, reason,
      adoptionCode, secondApproverCi,
      lessonsLearned,                  // postmortem (fix #8: requerido en CERRADO ≥ MEDIUM)
    } = req.body ?? {};
    const caseId = req.params.id;

    if (!toStatus || !operatorCi) {
      return res.status(400).json({ error: "toStatus y operatorCi son obligatorios" });
    }

    // Obtener el rol del operador si no se pasó explícitamente
    let effectiveRole = roleId;
    if (!effectiveRole) {
      const [op] = await pgQuery(
        `SELECT role_id FROM soc_operators WHERE id=$1`, [operatorCi]
      ).catch(() => []);
      effectiveRole = op?.role_id ?? "L1";
    }

    try {
      const result = await transitionCase(
        {
          caseId, toStatus, operatorCi, roleId: effectiveRole, reason,
          adoptionCode, secondApproverCi, lessonsLearned,
        },
        io()
      );
      res.json(result);
    } catch (err) {
      // Clasificar errores para devolver el status HTTP adecuado
      const msg = err.message ?? String(err);
      let status = 500;
      if (msg.includes("no puede transicionar"))             status = 403;
      else if (msg.includes("adoption_code"))                status = 400;
      else if (msg.includes("Segundo aprobador"))            status = 400;
      else if (msg.includes("Postmortem requerido"))         status = 422;
      else if (msg.includes("requiere"))                     status = 400;
      else if (msg.includes("not found"))                    status = 404;
      res.status(status).json({ error: msg });
    }
  });

  // Obtener transiciones posibles para un operador sobre un caso
  r.get("/cases/:id/transitions", async (req, res) => {
    const { operatorCi } = req.query;
    try {
      const [c] = await pgQuery(
        `SELECT status FROM incident_cases_pg WHERE id=$1`, [req.params.id]
      );
      if (!c) return res.status(404).json({ error: "Caso no encontrado" });

      let roleId = req.operatorRole;
      if (!roleId && operatorCi) {
        const [op] = await pgQuery(
          `SELECT role_id FROM soc_operators WHERE id=$1`, [operatorCi]
        ).catch(() => []);
        roleId = op?.role_id ?? "L1";
      }

      const allowed = (await pgQuery(
        `SELECT can_escalate_to_l2, can_escalate_to_l3, can_close_fp, can_close_case, can_assign_cases
         FROM soc_roles WHERE id=$1`, [roleId]
      ).catch(() => [{}]))[0] ?? {};

      // Filtrar transiciones según permisos
      const TRANSITION_MAP = {
        NUEVO:          ["EN_ANALISIS", "FALSO_POSITIVO"],
        EN_ANALISIS:    ["CONFIRMADO", "ESCALADO", "FALSO_POSITIVO", "MONITOREADO"],
        CONFIRMADO:     ["ESCALADO", "CERRADO", "MONITOREADO"],
        ESCALADO:       ["CONFIRMADO", "CERRADO"],
        MONITOREADO:    ["EN_ANALISIS", "CERRADO"],
        FALSO_POSITIVO: ["EN_ANALISIS"],
        CERRADO:        [],
      };

      const all = TRANSITION_MAP[c.status] ?? [];
      const filtered = all.filter((s) => {
        if (s === "CERRADO" && !allowed.can_close_case) return false;
        if (s === "FALSO_POSITIVO" && !allowed.can_close_fp) return false;
        if (s === "ESCALADO" && !allowed.can_escalate_to_l2 && !allowed.can_escalate_to_l3) return false;
        return true;
      });

      res.json({ fromStatus: c.status, allowed: filtered, role: roleId });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // AUTOMATIZACIONES MANUALES (admin / shift manager)
  // ───────────────────────────────────────────────────────────────────────────

  // Trigger manuales — comparten advisory locks con el scheduler para evitar
  // que un disparo manual concurra con un tick automático (mismas filas →
  // doble UPDATE en audit log + posible deadlock contra v_auto_close_candidates).
  r.post("/automation/trigger-auto-close", async (req, res) => {
    if (!["LEADER","ADMIN"].includes(req.operatorRole)) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN pueden forzar auto-close" });
    }
    try {
      const result = await withAdvisoryLock(LOCK_AUTO_CLOSE, () => autoCloseLowNegligible(io()));
      if (result?.skipped === "lock_busy") {
        return res.status(409).json({ ok: false, error: "auto-close en curso (scheduler u otro disparo) — reintenta en unos segundos" });
      }
      res.json({ ok: true, ...result });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.post("/automation/trigger-auto-assign", async (req, res) => {
    if (!["LEADER","ADMIN"].includes(req.operatorRole)) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN pueden forzar auto-assign" });
    }
    try {
      const result = await withAdvisoryLock(LOCK_AUTO_ASSIGN, () => autoAssignTimeoutCases(io()));
      if (result?.skipped === "lock_busy") {
        return res.status(409).json({ ok: false, error: "auto-assign en curso (scheduler u otro disparo) — reintenta en unos segundos" });
      }
      res.json({ ok: true, ...result });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Preview del digest de seguimiento (sin enviar email ni nudges) — para que el
  // manager vea AHORA qué casos están sin seguimiento. ?hours=N (default 6).
  r.get("/automation/followup-preview", async (req, res) => {
    if (!["LEADER","ADMIN"].includes(req.operatorRole)) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN" });
    }
    try {
      const hours = Math.min(168, Math.max(1, Number(req.query.hours ?? 6)));
      const data = await collectFollowupData(hours);
      res.json({ ok: true, ...data });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Forzar el envío del digest 6h ahora (email a managers/leaders + nudges).
  r.post("/automation/trigger-followup-digest", async (req, res) => {
    if (!["LEADER","ADMIN"].includes(req.operatorRole)) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN pueden forzar el digest" });
    }
    try {
      const result = await withAdvisoryLock(LOCK_FOLLOWUP_DIGEST, () => sendFollowupDigest(io()));
      if (result?.skipped === "lock_busy") {
        return res.status(409).json({ ok: false, error: "digest en curso — reintenta en unos segundos" });
      }
      res.json(result);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Historial de acciones automáticas
  r.get("/automation/auto-actions", async (req, res) => {
    const limit  = Math.min(200, Number(req.query.limit ?? 50));
    const offset = Number(req.query.offset ?? 0);
    const type   = req.query.type; // filtro opcional por tipo
    try {
      const cond = type ? `AND action_type=$3` : "";
      const params = type ? [limit, offset, type] : [limit, offset];
      const rows = await pgQuery(
        `SELECT a.*, c.severity, c.ioc_value
         FROM incident_auto_actions a
         JOIN incident_cases_pg c ON c.id=a.case_id
         WHERE 1=1 ${cond}
         ORDER BY a.performed_at DESC
         LIMIT $1 OFFSET $2`,
        params
      );
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Candidatos actuales (vista en tiempo real)
  r.get("/automation/candidates", async (_req, res) => {
    try {
      const [closeCandidates, timeoutCases] = await Promise.all([
        pgQuery(`SELECT * FROM v_auto_close_candidates`),
        pgQuery(`SELECT * FROM v_timeout_cases`),
      ]);
      res.json({ autoCloseCandidates: closeCandidates, timeoutCases });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // NOTIFICACIONES IN-APP
  // ───────────────────────────────────────────────────────────────────────────

  r.get("/notifications/:operatorId", async (req, res) => {
    const limit = Math.min(50, Number(req.query.limit ?? 20));
    const unreadOnly = req.query.unread === "true";
    try {
      const cond = unreadOnly ? "AND read_at IS NULL" : "";
      const rows = await pgQuery(
        `SELECT * FROM soc_notifications
         WHERE operator_id=$1 ${cond}
         ORDER BY created_at DESC LIMIT $2`,
        [req.params.operatorId, limit]
      );
      const [{ cnt }] = await pgQuery(
        `SELECT COUNT(*) AS cnt FROM soc_notifications
         WHERE operator_id=$1 AND read_at IS NULL`,
        [req.params.operatorId]
      );
      res.json({ notifications: rows, unreadCount: Number(cnt) });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.patch("/notifications/:id/read", async (req, res) => {
    try {
      await pgQuery(
        `UPDATE soc_notifications SET read_at=now() WHERE id=$1 AND read_at IS NULL`,
        [req.params.id]
      );
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.patch("/notifications/:operatorId/read-all", async (req, res) => {
    try {
      const { count } = await pgQuery(
        `UPDATE soc_notifications SET read_at=now()
         WHERE operator_id=$1 AND read_at IS NULL`,
        [req.params.operatorId]
      );
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // HANDOVER
  // ───────────────────────────────────────────────────────────────────────────

  r.post("/handover", async (req, res) => {
    if (!["LEADER","ADMIN"].includes(req.operatorRole)) {
      return res.status(403).json({ error: "Solo LEADER/ADMIN pueden crear handover" });
    }
    const { outgoingManagerCi: bodyOut, incomingManagerCi, shift, notes, pendingActions } = req.body ?? {};
    // Preferimos el CI derivado del JWT (más seguro que el body).
    const jwtCi = req.user?.preferred_username && req.user.preferred_username !== "lab-anonymous"
      ? String(req.user.preferred_username).trim()
      : null;
    const outgoingManagerCi = jwtCi ?? bodyOut;
    if (!outgoingManagerCi || !shift) {
      return res.status(400).json({ error: "outgoingManagerCi y shift son obligatorios" });
    }
    try {
      const result = await createHandoverReport(
        { outgoingManagerCi, incomingManagerCi, shift, notes, pendingActions },
        io()
      );
      res.json({ ok: true, ...result });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  r.get("/handover/latest", async (_req, res) => {
    try {
      const [row] = await pgQuery(
        `SELECT * FROM soc_handover_reports ORDER BY created_at DESC LIMIT 1`
      );
      res.json(row ?? null);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.get("/handover", async (req, res) => {
    const limit = Math.min(50, Number(req.query.limit ?? 20));
    try {
      const rows = await pgQuery(
        `SELECT * FROM soc_handover_reports ORDER BY created_at DESC LIMIT $1`,
        [limit]
      );
      res.json({ ok: true, reports: rows });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  const ackHandover = async (req, res) => {
    try {
      const rows = await pgQuery(
        `UPDATE soc_handover_reports
            SET acknowledged_at = now()
          WHERE id = $1 AND acknowledged_at IS NULL
          RETURNING id, outgoing_manager_ci, incoming_manager_ci, shift`,
        [req.params.id]
      );
      const h = rows[0];
      // Notificar al manager saliente que el entrante recibió el handover.
      if (h?.outgoing_manager_ci) {
        try {
          await createNotification({
            operatorId: h.outgoing_manager_ci,
            type: "SHIFT_HANDOVER_ACK",
            priority: "NORMAL",
            title: `Handover reconocido — Turno ${h.shift}`,
            body: `${h.incoming_manager_ci ?? "El manager entrante"} confirmó la recepción del turno.`,
            io: io(),
          });
        } catch { /* notificación best-effort */ }
      }
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  };
  r.patch("/handover/:id/acknowledge", ackHandover);
  r.post("/handover/:id/acknowledge", ackHandover);

  // ───────────────────────────────────────────────────────────────────────────
  // HEALTH / STATUS
  // ───────────────────────────────────────────────────────────────────────────

  r.get("/health", async (_req, res) => {
    try {
      const [manager, candidates, timeout, autoActionsRecent] = await Promise.all([
        getActiveShiftManager(),
        pgQuery(`SELECT COUNT(*) AS cnt FROM v_auto_close_candidates`),
        pgQuery(`SELECT COUNT(*) AS cnt FROM v_timeout_cases`),
        pgQuery(`SELECT COUNT(*) AS cnt FROM incident_auto_actions WHERE performed_at >= now() - INTERVAL '1 hour'`),
      ]);
      res.json({
        // Estado operacional inmediato
        scheduler:           getSchedulerStatus(),
        shiftManager:        manager,
        shiftManagerAbsent:  !manager,
        pendingAutoClose:    Number(candidates[0]?.cnt ?? 0),
        pendingAutoAssign:   Number(timeout[0]?.cnt ?? 0),
        autoActionsLastHour: Number(autoActionsRecent[0]?.cnt ?? 0),
        // Métricas acumulativas desde arranque del proceso
        schedulerMetrics:    getSchedulerMetrics(),
        workflowMetrics:     getWorkflowMetrics(),
        cacheStats:          getCacheStats(),
        ts:                  new Date().toISOString(),
      });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  return r;
}
