/**
 * routes/inventory.mjs — Collector: AUTH del agente + INGESTA + LECTURA interna.
 *
 * Router AISLADO (espejo de routes/publicApi.mjs): tiene su propio bearer de
 * agente (JWT HS256 propio, NO el OIDC interno) y rate-limit. Devuelve dos
 * sub-routers que se montan por separado en server.mjs:
 *
 *   app.use("/api/auth",      authRouter);        // POST /api/auth/token        (público)
 *   app.use("/api/inventory", inventoryRouter);   // POST /api/inventory/report  (bearer agente)
 *                                                 // GET  /api/inventory/hosts    (requireAuth OIDC)
 *
 * IMPORTANTE: el parser de mayor límite para /api/inventory/report se registra en
 * server.mjs ANTES del express.json({limit:"2mb"}) global (un payload de ~10MB
 * sería rechazado por el global con 413 antes de llegar aquí).
 */
import { Router } from "express";
import express from "express";
import rateLimit from "express-rate-limit";
import { requireAuth } from "../middleware/auth.middleware.mjs";
import { logger } from "../logger.mjs";
import {
  authenticateAgent, signAgentToken, verifyAgentToken, credentialEnabled,
} from "../services/agentAuthService.mjs";
import {
  ingestReport, listHosts, getHostDetail, listHostReports,
} from "../services/inventoryService.mjs";
import {
  ACTIONS, DESTRUCTIVE, commandsEnabled, enqueueCommand,
  listCommandsForHost, claimCommands, recordResult, cancelCommand,
} from "../services/inventoryCommandsService.mjs";

function clientIp(req) {
  return (req.headers["x-forwarded-for"]?.toString().split(",")[0].trim())
      || req.ip || req.socket?.remoteAddress || null;
}

export default function inventoryRouters() {
  // ── /api/auth ───────────────────────────────────────────────────────────────
  const authRouter = Router();

  // Anti-bruteforce de credenciales del agente.
  const tokenLimiter = rateLimit({
    windowMs: 60_000, max: 10, standardHeaders: true, legacyHeaders: false,
    message: { success: false, error: "Demasiados intentos; reintente en un minuto." },
  });

  // POST /api/auth/token — { email, password, expires_in } → { success, token }
  authRouter.post("/token", tokenLimiter, express.json({ limit: "16kb" }), async (req, res) => {
    try {
      const { email, password, expires_in } = req.body ?? {};
      if (!email || !password) {
        return res.status(400).json({ success: false, error: "email y password son obligatorios" });
      }
      const agent = await authenticateAgent(email, password);
      if (!agent) {
        return res.status(401).json({ success: false, error: "credenciales inválidas" });
      }
      const token = signAgentToken({ credId: agent.id, email: agent.email, expiresIn: expires_in ?? "24h" });
      return res.json({ success: true, token });
    } catch (err) {
      logger?.error?.(`[collector] /auth/token error: ${err.message}`);
      return res.status(500).json({ success: false, error: "error interno" });
    }
  });

  // ── /api/inventory ────────────────────────────────────────────────────────────
  const inventoryRouter = Router();

  // Middleware: Bearer del AGENTE (HS256). En fallo → 401 para que el agente
  // renueve el token (el .sh reintenta una vez tras 401).
  async function requireAgentToken(req, res, next) {
    try {
      const h = req.headers.authorization || "";
      const m = /^Bearer\s+(.+)$/i.exec(h);
      const payload = m ? verifyAgentToken(m[1]) : null;
      if (!payload) return res.status(401).json({ error: "token de agente inválido o expirado" });
      // no-stale: la credencial debe seguir habilitada
      if (!(await credentialEnabled(payload.sub))) {
        return res.status(401).json({ error: "credencial deshabilitada" });
      }
      req.agent = { id: payload.sub, email: payload.email };
      next();
    } catch (err) {
      logger?.error?.(`[collector] requireAgentToken error: ${err.message}`);
      return res.status(401).json({ error: "token inválido" });
    }
  }

  const reportLimiter = rateLimit({
    windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false,
    message: { error: "Rate-limit de reportes excedido." },
  });

  // POST /api/inventory/report — payload del agente (el parser 16mb se aplica en server.mjs)
  inventoryRouter.post("/report", reportLimiter, requireAgentToken, async (req, res) => {
    try {
      const result = await ingestReport(req.body, { sourceIp: clientIp(req) });
      logger?.info?.(`[collector] report host=${req.body?.base?.name ?? "?"} agent=${req.agent?.email} id=${result.inventory_id}`);
      return res.json(result);
    } catch (err) {
      const code = err.statusCode === 400 ? 400 : 500;
      if (code === 500) logger?.error?.(`[collector] /report error: ${err.message}`);
      return res.status(code).json({ error: err.message || "error interno" });
    }
  });

  // ── Canal de COMANDOS — lado AGENTE (Bearer agente) ───────────────────────────
  // El JWT de agente es compartido por la flota; el host se identifica con
  // X-Host-Id (el agente lo cacheó del response de /report). Si el canal está
  // apagado o no hay host, devuelve lista vacía (no rompe el poll del agente).
  inventoryRouter.get("/commands", reportLimiter, requireAgentToken, async (req, res) => {
    try {
      if (!commandsEnabled()) return res.json({ enabled: false, commands: [] });
      const hostId = String(req.headers["x-host-id"] || "").trim();
      if (!/^[0-9a-f-]{36}$/i.test(hostId)) return res.json({ enabled: true, commands: [] });
      const commands = await claimCommands(hostId);
      if (commands.length) logger?.info?.(`[collector] deliver host=${hostId} cmds=${commands.map((c) => c.action).join(",")} agent=${req.agent?.email}`);
      return res.json({ enabled: true, commands });
    } catch (err) {
      logger?.error?.(`[collector] GET /commands error: ${err.message}`);
      return res.status(500).json({ error: "error interno" });
    }
  });

  // POST /api/inventory/commands/:id/result — el agente reporta resultado
  inventoryRouter.post("/commands/:id/result", reportLimiter, requireAgentToken, async (req, res) => {
    try {
      const hostId = String(req.headers["x-host-id"] || "").trim();
      const { status, exit_code, output, error } = req.body ?? {};
      const ok = await recordResult(req.params.id, hostId, { status, exit_code, output, error });
      if (!ok) return res.status(404).json({ error: "comando no encontrado o no entregado a este host" });
      logger?.info?.(`[collector] result cmd=${req.params.id} host=${hostId} status=${status} exit=${exit_code}`);
      return res.json({ ok: true });
    } catch (err) {
      logger?.error?.(`[collector] POST /commands/:id/result error: ${err.message}`);
      return res.status(500).json({ error: "error interno" });
    }
  });

  // ── Lectura interna (dashboard) — JWT OIDC del SOC ────────────────────────────
  inventoryRouter.get("/hosts", requireAuth(), async (_req, res) => {
    try {
      const hosts = await listHosts();
      res.json({ hosts, total: hosts.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  inventoryRouter.get("/hosts/:id", requireAuth(), async (req, res) => {
    try {
      const detail = await getHostDetail(req.params.id);
      if (!detail) return res.status(404).json({ error: "host no encontrado" });
      res.json(detail);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  inventoryRouter.get("/hosts/:id/reports", requireAuth(), async (req, res) => {
    try {
      const reports = await listHostReports(req.params.id, req.query.limit);
      res.json({ reports, total: reports.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── Canal de COMANDOS — lado DASHBOARD (JWT OIDC del SOC) ──────────────────────
  function operatorOf(req) {
    return req.user?.email || req.user?.preferred_username || req.user?.sub || "system";
  }

  // Lista comandos del host + metadatos del canal (acciones, flag, destructivas).
  inventoryRouter.get("/hosts/:id/commands", requireAuth(), async (req, res) => {
    try {
      const commands = await listCommandsForHost(req.params.id, req.query.limit);
      res.json({
        enabled: commandsEnabled(),
        actions: ACTIONS,
        destructive: [...DESTRUCTIVE],
        commands,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Encola una acción. Destructivas → confirm:true + reason obligatorios (servicio).
  inventoryRouter.post("/hosts/:id/commands", requireAuth(), async (req, res) => {
    try {
      if (!commandsEnabled()) return res.status(403).json({ error: "canal de comandos deshabilitado (COLLECTOR_COMMANDS_ENABLED)" });
      const { action, params, reason, confirm } = req.body ?? {};
      const cmd = await enqueueCommand({
        hostId: req.params.id, action, params, reason,
        confirm: confirm === true, requestedBy: operatorOf(req),
      });
      logger?.info?.(`[collector] enqueue host=${req.params.id} action=${action} by=${operatorOf(req)}`);
      res.status(201).json({ command: cmd });
    } catch (err) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  // Cancela un comando aún no ejecutado.
  inventoryRouter.post("/hosts/:id/commands/:cmdId/cancel", requireAuth(), async (req, res) => {
    try {
      const ok = await cancelCommand(req.params.cmdId, req.params.id);
      if (!ok) return res.status(404).json({ error: "comando no cancelable" });
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return { authRouter, inventoryRouter };
}
