/**
 * routes/publicApi.mjs — F7: API PÚBLICA programática del Sistema de Tickets.
 *
 * Superficie EXTERNA para que el cliente integre apertura/consulta de tickets
 * desde su propio sistema (token de servicio bearer, multi-tenant por org).
 * Router AISLADO con su propio middleware de auth (token, NO el JWT interno),
 * rate-limiting, scopes y un SERIALIZADOR que filtra todo lo interno (notas
 * INTERNAL, CIs, scoring, org_id) — mismo invariante que routes/portal.mjs.
 *
 * Montado en server.mjs: app.use("/api/v1", publicApiRouter(getIo)) SIN requireAuth.
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#18), §8.2, §11 (F7).
 */
import express from "express";
import rateLimit from "express-rate-limit";
import { pgQuery } from "../db/postgres.mjs";
import * as tickets from "../services/ticketService.mjs";
import { resolveToken } from "../services/apiTokensService.mjs";

// ── Serializadores: SÓLO campos seguros para el cliente (espejo de portal.mjs) ──
function pubTicket(t) {
  return {
    ref: t.public_ref, subject: t.subject, status: t.status, priority: t.priority,
    waitingOn: t.waiting_on, createdAt: t.created_at, updatedAt: t.updated_at,
    firstResponseAt: t.first_response_at, resolvedAt: t.resolved_at,
    publicMsgs: Number(t.public_msgs ?? 0), csatScore: t.csat_score ?? null,
  };
}
function pubMessage(m) {
  return {
    id: m.id,
    author: m.author_type === "CLIENT" ? "client" : m.author_type === "SOC" ? "support" : "system",
    body: m.body, createdAt: m.created_at, hasReport: !!m.has_report,
  };
}
function pubActionRequest(ar) {
  return {
    id: ar.id, actionType: ar.action_type, title: ar.title, rationale: ar.rationale,
    recommendedSteps: ar.recommended_steps, urgency: ar.urgency, dueAt: ar.due_at,
    status: ar.status, decidedAt: ar.decided_at, decisionNote: ar.decision_note,
    riskAcceptedBy: ar.risk_accepted_by, riskAcceptanceScope: ar.risk_acceptance_scope,
    riskReviewAt: ar.risk_review_at,
  };
}

export default function publicApiRouter(getIo) {
  const router = express.Router();

  function emit(event, payload) { try { getIo?.()?.emit(event, payload); } catch { /* opcional */ } }

  // Rate-limit por token/IP (anti-abuso de la superficie externa).
  router.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

  // ── Auth por token bearer ─────────────────────────────────────────────────────
  async function requireToken(req, res, next) {
    try {
      const h = req.headers.authorization || "";
      const m = /^Bearer\s+(.+)$/i.exec(h);
      const raw = m ? m[1] : (req.headers["x-api-key"] || "");
      const ctx = await resolveToken(String(raw));
      if (!ctx) return res.status(401).json({ ok: false, error: "token inválido o expirado" });
      req.apiCtx = ctx;
      next();
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  }
  function requireScope(scope) {
    return (req, res, next) => {
      if (!req.apiCtx?.scopes?.includes(scope)) {
        return res.status(403).json({ ok: false, error: `falta el scope ${scope}` });
      }
      next();
    };
  }

  async function getOrgTicketByRef(orgId, ref) {
    const rows = await pgQuery(`SELECT * FROM tickets WHERE public_ref = $1 AND org_id = $2 LIMIT 1`, [ref, orgId]);
    return rows[0] ?? null;
  }

  router.use(requireToken);

  // Identidad del token (útil para validar credenciales del cliente).
  router.get("/ping", async (req, res) => {
    const org = (await pgQuery(`SELECT slug, name FROM organizations WHERE id = $1`, [req.apiCtx.orgId]))[0];
    res.json({ ok: true, org, scopes: req.apiCtx.scopes });
  });

  // ── Lectura ───────────────────────────────────────────────────────────────────
  router.get("/tickets", requireScope("tickets:read"), async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT t.*,
                (SELECT count(*) FROM ticket_messages m WHERE m.ticket_id = t.id AND m.visibility = 'PUBLIC') AS public_msgs
           FROM tickets t WHERE t.org_id = $1 ORDER BY t.updated_at DESC LIMIT 200`,
        [req.apiCtx.orgId],
      );
      res.json({ ok: true, tickets: rows.map(pubTicket) });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.get("/tickets/:ref", requireScope("tickets:read"), async (req, res) => {
    try {
      const t = await getOrgTicketByRef(req.apiCtx.orgId, req.params.ref);
      if (!t) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      const messages = await pgQuery(
        `SELECT id, author_type, body, created_at, (report_html IS NOT NULL) AS has_report
           FROM ticket_messages WHERE ticket_id = $1 AND visibility = 'PUBLIC' ORDER BY created_at ASC`,
        [t.id],
      );
      const ars = await pgQuery(
        `SELECT * FROM ticket_action_requests WHERE ticket_id = $1 ORDER BY created_at DESC`, [t.id],
      );
      res.json({ ok: true, ticket: { ...pubTicket(t), messages: messages.map(pubMessage), actionRequests: ars.map(pubActionRequest) } });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.get("/tickets/:ref/action-requests", requireScope("tickets:read"), async (req, res) => {
    try {
      const t = await getOrgTicketByRef(req.apiCtx.orgId, req.params.ref);
      if (!t) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      const ars = await pgQuery(`SELECT * FROM ticket_action_requests WHERE ticket_id = $1 ORDER BY created_at DESC`, [t.id]);
      res.json({ ok: true, actionRequests: ars.map(pubActionRequest) });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Escritura ───────────────────────────────────────────────────────────────────
  router.post("/tickets", requireScope("tickets:write"), async (req, res) => {
    try {
      const subject = String(req.body?.subject ?? "").trim();
      if (!subject) return res.status(400).json({ ok: false, error: "subject obligatorio" });
      const priority = ["LOW", "MEDIUM", "HIGH", "URGENT"].includes(req.body?.priority) ? req.body.priority : "MEDIUM";
      const t = await tickets.createTicket({
        subject, priority, channel: "API", orgId: req.apiCtx.orgId,
        requesterContact: req.body?.requester ?? {}, operatorCi: "api",
      });
      // Primer mensaje opcional del cliente.
      const body = String(req.body?.body ?? "").trim();
      if (body) {
        await tickets.addMessage(t.id, { authorType: "CLIENT", authorRef: "api", visibility: "PUBLIC", body, operatorCi: "api" });
      }
      emit("ticket:created", { ticketId: t.id });
      const fresh = await getOrgTicketByRef(req.apiCtx.orgId, t.public_ref);
      res.status(201).json({ ok: true, ticket: pubTicket(fresh) });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.post("/tickets/:ref/reply", requireScope("tickets:write"), async (req, res) => {
    try {
      const t = await getOrgTicketByRef(req.apiCtx.orgId, req.params.ref);
      if (!t) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      const body = String(req.body?.body ?? "").trim();
      if (!body) return res.status(400).json({ ok: false, error: "mensaje vacío" });
      await tickets.addMessage(t.id, {
        authorType: "CLIENT", authorRef: "api", visibility: "PUBLIC", body, operatorCi: "api",
      });
      emit("ticket:message", { ticketId: t.id });
      res.status(201).json({ ok: true });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.post("/action-requests/:id/decide", requireScope("tickets:write"), async (req, res) => {
    try {
      // La solicitud debe pertenecer a un ticket de ESTA org.
      const owns = await pgQuery(
        `SELECT 1 FROM ticket_action_requests ar JOIN tickets t ON t.id = ar.ticket_id
          WHERE ar.id = $1 AND t.org_id = $2 LIMIT 1`,
        [req.params.id, req.apiCtx.orgId],
      );
      if (owns.length === 0) return res.status(404).json({ ok: false, error: "solicitud no encontrada" });
      const { decision, decisionNote, deferredUntil, riskAcceptedBy, riskAcceptanceScope, riskReviewAt } = req.body ?? {};
      const ar = await tickets.decideActionRequest(req.params.id, {
        decision, decidedBy: "api", decisionNote, deferredUntil, riskAcceptedBy, riskAcceptanceScope, riskReviewAt,
      });
      emit("ticket:action-decision", { actionRequestId: ar.id, decision });
      res.json({ ok: true, actionRequest: pubActionRequest(ar) });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  return router;
}
