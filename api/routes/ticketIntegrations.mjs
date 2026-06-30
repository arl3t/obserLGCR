/**
 * routes/ticketIntegrations.mjs — F7: administración de INTEGRACIONES de tickets.
 *
 * Superficie INTERNA (manager: LEADER/ADMIN). Gestiona, por organización:
 *   · Webhooks salientes (endpoints + bitácora de entregas)   → webhookService
 *   · Tokens de servicio de la API pública                    → apiTokensService
 *
 * Montado en server.mjs: app.use("/api/integrations", requireAuth("manager"), …).
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#17/#18), §11 (F7).
 */
import express from "express";
import * as webhooks from "../services/webhookService.mjs";
import * as tokens from "../services/apiTokensService.mjs";

function actor(req) { return req.user?.preferred_username || req.user?.sub || "system"; }

export default function ticketIntegrationsRouter() {
  const router = express.Router();

  // Catálogos (para poblar selects en la UI).
  router.get("/meta", (_req, res) => {
    res.json({ ok: true, events: webhooks.knownEvents(), scopes: tokens.knownScopes() });
  });

  // ── Webhooks ────────────────────────────────────────────────────────────────
  router.get("/webhooks", async (req, res) => {
    try { res.json({ ok: true, endpoints: await webhooks.listEndpoints(req.query.org || null) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.post("/webhooks", async (req, res) => {
    try {
      const { orgId, url, events, description } = req.body ?? {};
      const r = await webhooks.createEndpoint({ orgId, url, events, description, createdBy: actor(req) });
      // El secreto se devuelve UNA sola vez.
      res.status(201).json({ ok: true, id: r.id, secret: r.secret });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.patch("/webhooks/:id", async (req, res) => {
    try { await webhooks.updateEndpoint(req.params.id, req.body ?? {}); res.json({ ok: true }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.post("/webhooks/:id/rotate-secret", async (req, res) => {
    try { res.json({ ok: true, ...(await webhooks.rotateSecret(req.params.id)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.delete("/webhooks/:id", async (req, res) => {
    try { await webhooks.deleteEndpoint(req.params.id); res.json({ ok: true }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.get("/webhooks/:id/deliveries", async (req, res) => {
    try { res.json({ ok: true, deliveries: await webhooks.listDeliveries(req.params.id, Number(req.query.limit) || 50) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Tokens de API ─────────────────────────────────────────────────────────────
  router.get("/tokens", async (req, res) => {
    try { res.json({ ok: true, tokens: await tokens.listTokens(req.query.org || null) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.post("/tokens", async (req, res) => {
    try {
      const { orgId, name, scopes, expiresAt } = req.body ?? {};
      const r = await tokens.createToken({ orgId, name, scopes, expiresAt, createdBy: actor(req) });
      // El token en claro se devuelve UNA sola vez.
      res.status(201).json({ ok: true, id: r.id, token: r.token });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.post("/tokens/:id/revoke", async (req, res) => {
    try { await tokens.revokeToken(req.params.id); res.json({ ok: true }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.delete("/tokens/:id", async (req, res) => {
    try { await tokens.deleteToken(req.params.id); res.json({ ok: true }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  return router;
}
