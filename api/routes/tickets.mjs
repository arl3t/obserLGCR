/**
 * routes/tickets.mjs — Superficie INTERNA del Sistema de Tickets Público (F2).
 *
 * Solo personal del SOC (JWT + RBAC existente). La superficie PÚBLICA del cliente
 * (token/magic-link) vivirá en routes/portal.mjs (F5), router SEPARADO con su
 * propio middleware de auth y serializador filtrado — nunca comparte handlers.
 *
 * docs/PROPUESTA-TICKETING-PUBLICO.md §8.1. Montado con requireAuth() en server.mjs.
 *
 * NOTA de orden: las rutas estáticas (/metrics, /sla-com, /action-requests,
 * /risk-acceptances) se declaran ANTES de /:id para que no matcheen como :id
 * (mismo cuidado que operators.mjs::/me).
 */

import express from "express";
import { pgQuery } from "../db/postgres.mjs";
import { resolveJwtOperatorCi } from "../services/operatorResolver.mjs";
import * as tickets from "../services/ticketService.mjs";
import * as rules from "../services/ticketRules.mjs";
import {
  getCommSla, setCommSla, getCommSlaAudit,
} from "../services/ticketCommSla.mjs";

export default function ticketsRouter(getIo) {
  const router = express.Router();

  // CI del operador autenticado (fallback no-bloqueante para entornos de lab).
  async function actorCi(req) {
    return (await resolveJwtOperatorCi(req)) || req.user?.preferred_username || "system";
  }

  function emit(event, payload) {
    try { getIo?.()?.emit(event, payload); } catch { /* socket opcional */ }
  }

  // ── Cola / listado ──────────────────────────────────────────────────────────
  router.get("/", async (req, res) => {
    try {
      const { status, waitingOn, operator, org, limit,
              type, tag, service, pinned, includeSnoozed, includeMerged, mine } = req.query;
      const op = mine === "true" ? await actorCi(req) : operator;
      const rows = await tickets.listTickets({
        status, waitingOn, operator: op, org, limit, type, tag, service,
        pinned, includeSnoozed: includeSnoozed === "true", includeMerged: includeMerged === "true",
      });
      res.json({ ok: true, tickets: rows });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Métricas de comunicación (§5) ────────────────────────────────────────────
  router.get("/metrics", async (req, res) => {
    try {
      const days = Number(req.query.days) || 30;
      const operator = req.query.operator || null;
      res.json({ ok: true, metrics: await tickets.getCommMetrics({ days, operator }) });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Métricas de solicitudes accionables (§6.4) ───────────────────────────────
  router.get("/action-requests/metrics", async (req, res) => {
    try {
      const days = Number(req.query.days) || 30;
      res.json({ ok: true, metrics: await tickets.getActionMetrics({ days }) });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Registro de riesgos aceptados vigentes (§6.3) ────────────────────────────
  router.get("/risk-acceptances", async (_req, res) => {
    try {
      res.json({ ok: true, riskAcceptances: await tickets.getOpenRiskAcceptances() });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Tickets + solicitudes vinculados a un caso (vista de Investigación) ───────
  router.get("/by-case/:caseId", async (req, res) => {
    try {
      res.json({ ok: true, tickets: await tickets.getTicketsByCase(req.params.caseId) });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Orgs activas (selector de cliente al solicitar una acción desde un caso) ──
  router.get("/orgs", async (_req, res) => {
    try {
      res.json({ ok: true, organizations: await tickets.getActiveOrgs() });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── HTML del informe adjunto a un mensaje (para el modal/iframe) ──────────────
  router.get("/messages/:msgId/report", async (req, res) => {
    try {
      const m = await tickets.getMessageReportHtml(req.params.msgId);
      if (!m || !m.report_html) return res.status(404).send("Informe no encontrado");
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(m.report_html);
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── HTML del playbook adjunto a un mensaje (para el modal/iframe) ─────────────
  router.get("/messages/:msgId/playbook", async (req, res) => {
    try {
      const m = await tickets.getMessagePlaybookHtml(req.params.msgId);
      if (!m || !m.playbook_html) return res.status(404).send("Playbook no encontrado");
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(m.playbook_html);
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Plantillas de respuesta (CRUD) ────────────────────────────────────────────
  router.get("/templates", async (_req, res) => {
    try { res.json({ ok: true, templates: await tickets.listTemplates() }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });
  router.post("/templates", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const t = await tickets.createTemplate({ ...(req.body ?? {}), createdBy: ci });
      res.status(201).json({ ok: true, template: t });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.delete("/templates/:id", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.deleteTemplate(req.params.id)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── SLA de comunicación (get/set + audit) ────────────────────────────────────
  router.get("/sla-com", async (_req, res) => {
    try {
      const [config, audit] = await Promise.all([getCommSla(), getCommSlaAudit(20)]);
      res.json({ ok: true, config, audit });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.put("/sla-com", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const config = await setCommSla({ values: req.body?.values ?? req.body ?? {}, operatorCi: ci });
      res.json({ ok: true, config });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Actividad reciente (campana de tickets de la barra superior) ─────────────
  router.get("/activity", async (req, res) => {
    try { res.json({ ok: true, activity: await tickets.listRecentActivity(Number(req.query.limit) || 25) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Crear solicitud accionable (desde un caso o ticket) (§6) ─────────────────
  router.post("/action-requests", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { ticketId, caseId, orgSlug, orgId, actionType, title, rationale,
              recommendedSteps, urgency, dueAt } = req.body ?? {};
      const ar = await tickets.createActionRequest({
        ticketId, caseId, orgSlug, orgId, requestedBy: ci, actionType, title, rationale,
        recommendedSteps, urgency, dueAt,
      });
      emit("ticket:action-request", { id: ar.id, ticketId: ar.ticket_id });
      res.status(201).json({ ok: true, actionRequest: ar });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ═══ Bloque clasificación / orden / workflow (20 mejoras) ════════════════════

  // ── (#2) Nube de etiquetas ───────────────────────────────────────────────────
  router.get("/tag-cloud", async (req, res) => {
    try { res.json({ ok: true, tags: await tickets.getTagCloud({ limit: Number(req.query.limit) || 50 }) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── (#5) Catálogo de servicios / productos ───────────────────────────────────
  router.get("/services", async (req, res) => {
    try { res.json({ ok: true, services: await tickets.listServices({ activeOnly: req.query.active === "true" }) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });
  router.post("/services", async (req, res) => {
    try { res.status(201).json({ ok: true, service: await tickets.createService(req.body ?? {}) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.patch("/services/:id", async (req, res) => {
    try { res.json({ ok: true, service: await tickets.updateService(req.params.id, req.body ?? {}) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.delete("/services/:id", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.deleteService(req.params.id)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#10) Vistas guardadas (por operador / compartidas) ──────────────────────
  router.get("/saved-views", async (req, res) => {
    try { res.json({ ok: true, views: await tickets.listSavedViews(await actorCi(req)) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });
  router.post("/saved-views", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const view = await tickets.createSavedView({ operatorCi: ci, ...(req.body ?? {}) });
      res.status(201).json({ ok: true, view });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.delete("/saved-views/:id", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.deleteSavedView(req.params.id, await actorCi(req))) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#12/#16) Preferencias del usuario (orden multi-columna + layout) ────────
  router.get("/prefs", async (req, res) => {
    try { res.json({ ok: true, prefs: await tickets.getUserPrefs(await actorCi(req)) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });
  router.put("/prefs", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { sort, defaultView, layout } = req.body ?? {};
      res.json({ ok: true, prefs: await tickets.setUserPrefs(ci, { sort, defaultView, layout }) });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#19) Reglas de negocio configurables ─────────────────────────────────────
  router.get("/rules", async (_req, res) => {
    try { res.json({ ok: true, rules: await rules.listRules() }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });
  router.post("/rules", async (req, res) => {
    try { res.status(201).json({ ok: true, rule: await rules.createRule({ ...(req.body ?? {}), createdBy: await actorCi(req) }) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.patch("/rules/:id", async (req, res) => {
    try { res.json({ ok: true, rule: await rules.updateRule(req.params.id, req.body ?? {}) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.delete("/rules/:id", async (req, res) => {
    try { res.json({ ok: true, ...(await rules.deleteRule(req.params.id)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#17) Acciones masivas ────────────────────────────────────────────────────
  router.post("/bulk", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { ids, assignedOperator, priority, addTag, status } = req.body ?? {};
      const r = await tickets.bulkUpdate(ids, { assignedOperator, priority, addTag, status, operatorCi: ci });
      emit("ticket:bulk", { count: r.affected });
      res.json({ ok: true, ...r });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Crear ticket (SOC-initiated) ─────────────────────────────────────────────
  router.post("/", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { subject, priority, channel, orgId, orgSlug,
              requesterContact, assignedOperator, caseId,
              ticketType, technicalSeverity, serviceId, serviceSlug, tags, ccContacts } = req.body ?? {};
      if (!subject) return res.status(400).json({ ok: false, error: "subject obligatorio" });
      const ticket = await tickets.createTicket({
        subject, priority, channel: channel ?? "SOC_INITIATED",
        orgId, orgSlug, requesterContact, assignedOperator, caseId, operatorCi: ci,
        ticketType, technicalSeverity, serviceId, serviceSlug, tags, ccContacts,
      });
      emit("ticket:created", { id: ticket.id, publicRef: ticket.public_ref });
      res.status(201).json({ ok: true, ticket });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Detalle + hilo + solicitudes ─────────────────────────────────────────────
  router.get("/:id", async (req, res) => {
    try {
      const ticket = await tickets.getTicket(req.params.id, { includeInternal: true });
      if (!ticket) return res.status(404).json({ ok: false, error: "ticket no encontrado" });
      res.json({ ok: true, ticket });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Marcar como leído por el SOC (apaga el resaltado de no-leídos) ────────────
  router.post("/:id/mark-read", async (req, res) => {
    try {
      await tickets.markSocRead(req.params.id);
      emit("ticket:read", { id: req.params.id });
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Responder en el hilo ─────────────────────────────────────────────────────
  router.post("/:id/messages", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { body, visibility, expectsReply, attachments } = req.body ?? {};
      const msg = await tickets.addMessage(req.params.id, {
        authorType: "SOC", authorRef: ci, visibility: visibility ?? "PUBLIC",
        body, attachments, expectsReply: expectsReply !== false, operatorCi: ci,
      });
      emit("ticket:message", { ticketId: req.params.id, id: msg.id });
      res.status(201).json({ ok: true, message: msg });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Transición de estado ─────────────────────────────────────────────────────
  router.patch("/:id/status", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { toStatus, note } = req.body ?? {};
      const ticket = await tickets.transitionStatus(req.params.id, { toStatus, operatorCi: ci, note });
      emit("ticket:status", { id: req.params.id, status: ticket.status });
      res.json({ ok: true, ticket });
    } catch (err) {
      const code = err.code === "INVALID_TRANSITION" ? 422
        : err.code === "CLOSURE_REQUIRES_CONFIRMATION" ? 409 : 400;
      res.status(code).json({ ok: false, error: err.message, code: err.code });
    }
  });

  // ── Solicitar confirmación de cierre al cliente (sign-off #23) ────────────────
  // Genera el VÍNCULO single-use que el cliente debe abrir para CERRAR el ticket.
  // El cierre directo a CERRADO está bloqueado: esta es la única vía (más el
  // rechazo del cliente, que devuelve la pelota al SOC).
  router.post("/:id/request-closure", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const out = await tickets.requestClosureConfirmation(req.params.id, { operatorCi: ci });
      emit("ticket:status", { id: req.params.id, status: out.ticket.status });
      res.json({ ok: true, link: out.link, expiresAt: out.expiresAt, ticket: out.ticket });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Vincular / desvincular caso ──────────────────────────────────────────────
  router.post("/:id/link-case", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { caseId, linkType } = req.body ?? {};
      if (!caseId) return res.status(400).json({ ok: false, error: "caseId obligatorio" });
      const r = await tickets.linkCase(req.params.id, { caseId, linkType, operatorCi: ci });
      res.json({ ok: true, ...r });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.post("/:id/unlink-case", async (req, res) => {
    try {
      const { caseId } = req.body ?? {};
      if (!caseId) return res.status(400).json({ ok: false, error: "caseId obligatorio" });
      res.json({ ok: true, ...(await tickets.unlinkCase(req.params.id, caseId)) });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Asignar operador (gate can_assign_cases si es a un tercero) ───────────────
  router.post("/:id/assign", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const target = req.body?.operatorCi || ci;
      // Anti-suplantación: asignar a OTRO operador requiere can_assign_cases
      // (espejo de incidents.mjs::adopt).
      if (target !== ci) {
        const rows = await pgQuery(
          `SELECT r.can_assign_cases FROM soc_operators o
             LEFT JOIN soc_roles r ON r.id = o.role_id WHERE o.id = $1 LIMIT 1`,
          [ci],
        ).catch(() => []);
        if (rows[0] && rows[0].can_assign_cases === false) {
          return res.status(403).json({
            ok: false,
            error: "Tu rol no puede asignar tickets a otros operadores (requiere can_assign_cases).",
          });
        }
      }
      const ticket = await tickets.assignTicket(req.params.id, { operatorCi: target });
      emit("ticket:assigned", { id: req.params.id, operator: target });
      res.json({ ok: true, ticket });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Solicitudes accionables de un ticket ─────────────────────────────────────
  router.get("/:id/action-requests", async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT * FROM ticket_action_requests WHERE ticket_id = $1 ORDER BY created_at DESC`,
        [req.params.id],
      );
      res.json({ ok: true, actionRequests: rows });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── (#1/#4/#5) Reclasificar (tipo / severidad técnica / servicio / prioridad) ─
  router.patch("/:id/classification", async (req, res) => {
    try {
      const ticket = await tickets.setClassification(req.params.id, req.body ?? {});
      emit("ticket:updated", { id: req.params.id });
      res.json({ ok: true, ticket });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#2) Etiquetas ────────────────────────────────────────────────────────────
  router.put("/:id/tags", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.setTags(req.params.id, req.body?.tags ?? [])) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#3/#7) Clasificar por IA (sugerencia) + aplicar sugerencia ───────────────
  router.post("/:id/classify", async (req, res) => {
    try {
      const suggestion = await tickets.classifyTicket(req.params.id);
      emit("ticket:updated", { id: req.params.id });
      res.json({ ok: true, suggestion });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.post("/:id/ai-apply", async (req, res) => {
    try {
      const ticket = await tickets.applyAiSuggestion(req.params.id, req.body ?? {});
      emit("ticket:updated", { id: req.params.id });
      res.json({ ok: true, ticket });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#14) Fijar / desfijar ─────────────────────────────────────────────────────
  router.post("/:id/pin", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.pinTicket(req.params.id, req.body?.pinned !== false)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#18) Posponer (snooze) ─────────────────────────────────────────────────────
  router.post("/:id/snooze", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.snoozeTicket(req.params.id, req.body?.until ?? null)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#6) Duplicados + merge ─────────────────────────────────────────────────────
  router.get("/:id/duplicates", async (req, res) => {
    try { res.json({ ok: true, candidates: await tickets.findDuplicateCandidates(req.params.id) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });
  router.post("/:id/merge", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const { intoId } = req.body ?? {};
      if (!intoId) return res.status(400).json({ ok: false, error: "intoId obligatorio" });
      const r = await tickets.mergeTickets(req.params.id, intoId, ci);
      emit("ticket:merged", { id: req.params.id, into: intoId });
      res.json({ ok: true, ...r });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#20) Watchers internos ──────────────────────────────────────────────────
  router.post("/:id/watchers", async (req, res) => {
    try {
      const ci = await actorCi(req);
      const target = req.body?.operatorCi || ci;
      res.status(201).json({ ok: true, ...(await tickets.addWatcher(req.params.id, target, ci)) });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });
  router.delete("/:id/watchers/:ci", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.removeWatcher(req.params.id, req.params.ci)) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── (#20) CC del cliente ──────────────────────────────────────────────────────
  router.put("/:id/cc", async (req, res) => {
    try { res.json({ ok: true, ...(await tickets.setCcContacts(req.params.id, req.body?.ccContacts ?? [])) }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  return router;
}
