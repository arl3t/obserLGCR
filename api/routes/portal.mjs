/**
 * routes/portal.mjs — Superficie PÚBLICA del Sistema de Tickets (F5).
 *
 * Portal del cliente: auth por magic-link (services/portalAuth.mjs), sesión corta,
 * rate-limiting y un SERIALIZADOR que filtra TODO lo interno (notas INTERNAL, CIs
 * de operadores, scoring, IOCs, case_id, nombres de tablas). NUNCA comparte
 * handlers con la superficie interna (routes/tickets.mjs).
 *
 * Aislamiento multi-tenant: toda consulta se filtra por la org de la sesión.
 *
 * ⚠ Antes de exponer públicamente: revisión /security-review + decidir exposición
 * vía reverse-proxy. Montado sin requireAuth en server.mjs.
 *
 * docs/PROPUESTA-TICKETING-PUBLICO.md §7.2 / §9.
 */
import express from "express";
import rateLimit from "express-rate-limit";
import { pgQuery } from "../db/postgres.mjs";
import {
  requestMagicLink, verifyMagicLink, resolvePortalSession, revokePortalSession,
} from "../services/portalAuth.mjs";
import * as tickets from "../services/ticketService.mjs";
import * as kb from "../services/kbService.mjs";

// ── Serializadores: SOLO campos seguros para el cliente ──────────────────────
function pubTicket(t) {
  return {
    ref: t.public_ref, subject: t.subject, status: t.status, priority: t.priority,
    waitingOn: t.waiting_on, createdAt: t.created_at, updatedAt: t.updated_at,
    firstResponseAt: t.first_response_at, resolvedAt: t.resolved_at,
    publicMsgs: Number(t.public_msgs ?? 0),
    csatScore: t.csat_score ?? null,
  };
}
// El autor se anonimiza: el cliente ve "Tú" / "Equipo de soporte", nunca el CI.
function pubMessage(m) {
  return {
    id: m.id,
    author: m.author_type === "CLIENT" ? "Tú" : m.author_type === "SOC" ? "Equipo de soporte" : "Sistema",
    authorType: m.author_type, body: m.body, createdAt: m.created_at,
    hasReport: !!m.has_report,
    hasPlaybook: !!m.has_playbook,
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

export default function portalRouter(getIo) {
  const router = express.Router();

  function emit(event, payload) {
    try { getIo?.()?.emit(event, payload); } catch { /* opcional */ }
  }

  // Rate-limiters: agresivo en auth (anti fuerza-bruta de enlaces), suave en el resto.
  const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10, standardHeaders: true, legacyHeaders: false });
  const apiLimiter  = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
  router.use(apiLimiter);

  // Middleware de sesión del portal (req.portal = { orgId, email }).
  async function requireSession(req, res, next) {
    try {
      const sess = await resolvePortalSession(req);
      if (!sess) return res.status(401).json({ ok: false, error: "sesión inválida o expirada" });
      req.portal = sess;
      next();
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  }

  // Helper: resolver un ticket del cliente por ref, SCOPED a su org.
  async function getOrgTicketByRef(orgId, ref) {
    const rows = await pgQuery(
      `SELECT * FROM tickets WHERE public_ref = $1 AND org_id = $2 LIMIT 1`, [ref, orgId],
    );
    return rows[0] ?? null;
  }

  // ── Auth ────────────────────────────────────────────────────────────────────
  router.post("/auth/request-link", authLimiter, async (req, res) => {
    const { orgSlug, email } = req.body ?? {};
    const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.ip;
    // SIEMPRE 200 (anti-enumeración). devLink solo en entornos sin SMTP.
    const out = await requestMagicLink({ orgSlug, email, ip });
    res.json(out);
  });

  router.post("/auth/verify", authLimiter, async (req, res) => {
    const out = await verifyMagicLink({ token: req.body?.token });
    res.status(out.ok ? 200 : 401).json(out);
  });

  router.post("/auth/logout", async (req, res) => {
    await revokePortalSession(req);
    res.json({ ok: true });
  });

  router.get("/me", requireSession, async (req, res) => {
    const org = (await pgQuery(`SELECT slug, name FROM organizations WHERE id = $1`, [req.portal.orgId]))[0];
    res.json({ ok: true, email: req.portal.email, org });
  });

  // ── Confirmación de cierre (sign-off #23) — PÚBLICO por token, SIN sesión ─────
  // El token del vínculo ES la credencial (single-use, TTL). Página ligera: el
  // cliente NO inicia sesión. Solo expone ref/asunto/estado del ticket en cuestión.
  router.get("/closure", authLimiter, async (req, res) => {
    try {
      const info = await tickets.getClosureByToken((req.query.ct ?? "").toString());
      if (!info) return res.status(404).json({ ok: false, error: "enlace no encontrado" });
      res.json({ ok: true, ...info });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.post("/closure/decide", authLimiter, async (req, res) => {
    try {
      const { ct, decision } = req.body ?? {};
      const reason = (req.body?.reason ?? "").toString().trim().slice(0, 2000) || null;
      const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.ip;
      const out = await tickets.decideClosure((ct ?? "").toString(), { decision, reason, ip });
      emit("ticket:status", { ref: out.ref, status: out.status });
      res.json({ ok: true, ...out });
    } catch (err) {
      const code = err.code === "CLOSURE_LINK_INVALID" ? 410 : 400;
      res.status(code).json({ ok: false, error: err.message });
    }
  });

  // ── Tickets (scoped a la org de la sesión) ───────────────────────────────────
  router.get("/tickets", requireSession, async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT t.*,
                (SELECT count(*) FROM ticket_messages m WHERE m.ticket_id = t.id AND m.visibility = 'PUBLIC') AS public_msgs
           FROM tickets t
          WHERE t.org_id = $1
          ORDER BY t.updated_at DESC LIMIT 200`,
        [req.portal.orgId],
      );
      res.json({ ok: true, tickets: rows.map(pubTicket) });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.get("/tickets/:ref", requireSession, async (req, res) => {
    try {
      const t = await getOrgTicketByRef(req.portal.orgId, req.params.ref);
      if (!t) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      const messages = await pgQuery(
        `SELECT id, author_type, body, created_at,
                (report_html IS NOT NULL) AS has_report,
                (playbook_html IS NOT NULL) AS has_playbook
           FROM ticket_messages
          WHERE ticket_id = $1 AND visibility = 'PUBLIC' ORDER BY created_at ASC`,
        [t.id],
      );
      const ars = await pgQuery(
        `SELECT * FROM ticket_action_requests WHERE ticket_id = $1 ORDER BY created_at DESC`, [t.id],
      );
      res.json({
        ok: true,
        ticket: { ...pubTicket(t), messages: messages.map(pubMessage), actionRequests: ars.map(pubActionRequest) },
      });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.post("/tickets/:ref/reply", requireSession, async (req, res) => {
    try {
      const t = await getOrgTicketByRef(req.portal.orgId, req.params.ref);
      if (!t) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      const body = String(req.body?.body ?? "").trim();
      if (!body) return res.status(400).json({ ok: false, error: "mensaje vacío" });
      // visibility SIEMPRE PUBLIC desde el portal; el cliente nunca crea notas internas.
      await tickets.addMessage(t.id, {
        authorType: "CLIENT", authorRef: req.portal.email, visibility: "PUBLIC",
        body, operatorCi: req.portal.email,
      });
      emit("ticket:message", { ticketId: t.id });
      res.status(201).json({ ok: true });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Informe (HTML) adjunto a un mensaje — scoped a la org de la sesión ────────
  router.get("/tickets/:ref/messages/:msgId/report", requireSession, async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT m.report_html
           FROM ticket_messages m
           JOIN tickets t ON t.id = m.ticket_id
          WHERE m.id = $1 AND t.public_ref = $2 AND t.org_id = $3
            AND m.visibility = 'PUBLIC' AND m.report_html IS NOT NULL
          LIMIT 1`,
        [req.params.msgId, req.params.ref, req.portal.orgId],
      );
      if (!rows.length) return res.status(404).send("Informe no encontrado");
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(rows[0].report_html);
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Playbook (HTML) adjunto a un mensaje — scoped a la org de la sesión ───────
  router.get("/tickets/:ref/messages/:msgId/playbook", requireSession, async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT m.playbook_html
           FROM ticket_messages m
           JOIN tickets t ON t.id = m.ticket_id
          WHERE m.id = $1 AND t.public_ref = $2 AND t.org_id = $3
            AND m.visibility = 'PUBLIC' AND m.playbook_html IS NOT NULL
          LIMIT 1`,
        [req.params.msgId, req.params.ref, req.portal.orgId],
      );
      if (!rows.length) return res.status(404).send("Playbook no encontrado");
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(rows[0].playbook_html);
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── CSAT: el cliente puntúa la atención de un ticket resuelto/cerrado ─────────
  router.post("/tickets/:ref/csat", requireSession, async (req, res) => {
    try {
      const t = await getOrgTicketByRef(req.portal.orgId, req.params.ref);
      if (!t) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      await tickets.submitCsat(t.id, { score: req.body?.score, comment: req.body?.comment });
      res.json({ ok: true });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.post("/tickets/:ref/reopen", requireSession, async (req, res) => {
    try {
      const t = await getOrgTicketByRef(req.portal.orgId, req.params.ref);
      if (!t) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      const ticket = await tickets.transitionStatus(t.id, {
        toStatus: "REABIERTO", operatorCi: req.portal.email,
        note: req.body?.reason ? `Reabierto por el cliente: ${req.body.reason}` : "Reabierto por el cliente",
      });
      res.json({ ok: true, status: ticket.status });
    } catch (err) {
      const code = err.code === "INVALID_TRANSITION" ? 422 : 400;
      res.status(code).json({ ok: false, error: err.message });
    }
  });

  // ── Decisión del cliente sobre una solicitud accionable (§6) ──────────────────
  router.post("/action-requests/:id/decide", requireSession, async (req, res) => {
    try {
      // Verificar que la solicitud pertenece a un ticket de ESTA org.
      const owns = await pgQuery(
        `SELECT 1 FROM ticket_action_requests ar
            JOIN tickets t ON t.id = ar.ticket_id
          WHERE ar.id = $1 AND t.org_id = $2 LIMIT 1`,
        [req.params.id, req.portal.orgId],
      );
      if (owns.length === 0) return res.status(404).json({ ok: false, error: "solicitud no encontrada" });

      const { decision, decisionNote, deferredUntil,
              riskAcceptedBy, riskAcceptanceScope, riskReviewAt } = req.body ?? {};
      const ar = await tickets.decideActionRequest(req.params.id, {
        decision, decidedBy: req.portal.email, decisionNote, deferredUntil,
        riskAcceptedBy, riskAcceptanceScope, riskReviewAt,
      });
      emit("ticket:action-decision", { actionRequestId: ar.id, decision });
      res.json({ ok: true, actionRequest: pubActionRequest(ar) });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Abrir un ticket desde el portal (autoservicio → escalar a soporte) ────────
  router.post("/tickets", requireSession, async (req, res) => {
    try {
      const subject = String(req.body?.subject ?? "").trim();
      const body = String(req.body?.body ?? "").trim();
      if (!subject) return res.status(400).json({ ok: false, error: "asunto obligatorio" });
      if (!body) return res.status(400).json({ ok: false, error: "describí tu consulta" });
      const priority = ["LOW", "MEDIUM", "HIGH", "URGENT"].includes(req.body?.priority) ? req.body.priority : "MEDIUM";
      const t = await tickets.createTicket({
        subject, priority, channel: "PORTAL", orgId: req.portal.orgId,
        requesterContact: { email: req.portal.email }, operatorCi: req.portal.email,
      });
      await tickets.addMessage(t.id, {
        authorType: "CLIENT", authorRef: req.portal.email, visibility: "PUBLIC", body, operatorCi: req.portal.email,
      });
      emit("ticket:created", { ticketId: t.id });
      res.status(201).json({ ok: true, ref: t.public_ref });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Base de Conocimiento (autoservicio) — SÓLO artículos PUBLICADOS ───────────
  router.get("/kb/categories", requireSession, async (req, res) => {
    try { res.json({ ok: true, categories: await kb.portalCategories(req.portal.orgId) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.get("/kb/articles", requireSession, async (req, res) => {
    try {
      const articles = await kb.portalList({
        orgId: req.portal.orgId, category: req.query.category || null, q: (req.query.q || "").toString().trim() || null,
      });
      res.json({ ok: true, articles });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.get("/kb/articles/:slug", requireSession, async (req, res) => {
    try {
      const art = await kb.portalGet(req.params.slug, req.portal.orgId);
      if (!art) return res.status(404).json({ ok: false, error: "artículo no encontrado" });
      res.json({ ok: true, article: art });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.post("/kb/articles/:slug/vote", requireSession, async (req, res) => {
    try { res.json({ ok: true, ...(await kb.vote(req.params.slug, !!req.body?.helpful, req.portal.orgId)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  return router;
}
