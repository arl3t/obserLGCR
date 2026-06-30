/**
 * ticketService.mjs — lógica del Sistema de Tickets Público (F2).
 *
 * Plano COMUNICACIONAL (tickets) separado del OPERACIONAL (incident_cases_pg),
 * unidos por ticket_case_links. Ver docs/PROPUESTA-TICKETING-PUBLICO.md.
 *
 * Responsabilidades:
 *   · Máquina de estados del ticket (VALID_TRANSITIONS propia, §3.4).
 *   · Ball-in-court (waiting_on) y métricas de cadencia (turnaround_seconds,
 *     is_first_response) calculadas al insertar cada mensaje (§5).
 *   · Espejo de la conversación y de las solicitudes accionables al timeline del
 *     caso vinculado (§4) vía timelineService.addTimelineEvent.
 *   · Solicitudes accionables al cliente con disposición / aceptación de riesgo (§6).
 *
 * Notas de diseño:
 *   · El personal del SOC es GLOBAL (multi-tenant se aísla en el portal F5, no acá).
 *   · public_ref es no-enumerable (sufijo aleatorio) — anti-enumeración del portal.
 *   · Toda escritura al timeline va en try/catch: un fallo de espejo NO debe
 *     romper la operación del ticket.
 */

import { pgQuery, withPgClient } from "../db/postgres.mjs";
import { randomUUID } from "node:crypto";
import { addTimelineEvent } from "./timelineService.mjs";
import { logger } from "../logger.mjs";
import { enqueueEvent } from "./webhookService.mjs";
import { autoAssignTicket, isActiveOperator, emitTicketActivity } from "./ticketAssignment.mjs";
import { sendMail } from "./mailTransport.mjs";
import { portalBaseUrl, closureConfirmUrl } from "./portalAuth.mjs";
import { randomBytes, createHash } from "node:crypto";
import { applyRulesOnCreate } from "./ticketRules.mjs";
import { classifyTicketText } from "./ticketClassifier.mjs";

// Notifica al CLIENTE por email que el SOC abrió un ticket en su nombre (apertura
// desde Investigación). Best-effort: nunca rompe la creación del ticket. El webhook
// `ticket.created` cubre el canal del ITSM del cliente; esto cubre el canal humano.
async function notifyClientTicketOpened(ticket) {
  try {
    const rows = await pgQuery(`SELECT name, contacts FROM organizations WHERE id = $1`, [ticket.org_id]);
    const org = rows[0];
    if (!org) return;
    const emails = (Array.isArray(org.contacts) ? org.contacts : [])
      .map((c) => (typeof c === "string" ? c : c?.email)).filter(Boolean);
    if (!emails.length) return;
    const portal = portalBaseUrl();
    const subject = `Se abrió un ticket de soporte — ${ticket.public_ref}`;
    const text =
      `Hola,\n\nNuestro equipo de soporte abrió un ticket para ${org.name}:\n\n` +
      `Referencia: ${ticket.public_ref}\nAsunto: ${ticket.subject}\n\n` +
      `Podés ver el detalle y responder desde el portal de soporte:\n${portal}\n\n` +
      `Ingresá tu email y te enviaremos un enlace de acceso seguro (sin contraseñas).`;
    const r = await sendMail({ to: emails.join(", "), subject, text });
    if (!r?.ok) logger.warn({ err: r?.error, ref: ticket.public_ref }, "[ticketService] email de apertura no enviado");
    else logger.info({ ref: ticket.public_ref, recipients: emails.length }, "[ticketService] apertura notificada al cliente");
  } catch (err) {
    logger.warn({ err: err.message }, "[ticketService] notifyClientTicketOpened falló (no-fatal)");
  }
}

// F7: dispara un webhook saliente del ciclo de vida del ticket (fire-and-forget,
// nunca bloquea ni rompe la operación; sólo eventos PÚBLICOS, sin datos internos).
function fireWebhook(orgId, eventType, payload) {
  void enqueueEvent(orgId, eventType, payload);
}

// ── Máquina de estados del ticket (espejo del patrón de incidents.mjs) ────────
export const TICKET_STATUSES = new Set([
  "ABIERTO", "EN_ATENCION", "ESPERANDO_CLIENTE", "RESUELTO", "REABIERTO", "CERRADO",
]);

const VALID_TRANSITIONS = {
  ABIERTO:           new Set(["EN_ATENCION", "ESPERANDO_CLIENTE", "RESUELTO", "CERRADO"]),
  EN_ATENCION:       new Set(["ESPERANDO_CLIENTE", "RESUELTO", "CERRADO"]),
  ESPERANDO_CLIENTE: new Set(["EN_ATENCION", "RESUELTO", "CERRADO"]),
  RESUELTO:          new Set(["CERRADO", "REABIERTO"]),
  REABIERTO:         new Set(["EN_ATENCION", "RESUELTO", "CERRADO"]),
  CERRADO:           new Set(["REABIERTO"]),
};

export function isValidTransition(from, to) {
  return VALID_TRANSITIONS[from]?.has(to) ?? false;
}

const ACTION_TYPES = new Set([
  "CONTENCION_FIREWALL", "AISLAR_HOST", "BLOQUEO_IOC", "RESET_CREDENCIALES",
  "APLICAR_PARCHE", "DESHABILITAR_CUENTA", "DESHABILITAR_SERVICIO", "OTRO",
]);
const ACTION_DECISIONS = new Set([
  "EJECUTADA", "RECHAZADA", "RIESGO_ACEPTADO", "DIFERIDA", "CANCELADA",
]);

// ── Helpers ───────────────────────────────────────────────────────────────────

function genPublicRef() {
  // TKT- + 8 hex del uuid → legible pero no secuencial-adivinable (§9).
  return `TKT-${randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase()}`;
}

async function resolveOrgId({ orgId, orgSlug } = {}) {
  if (orgId) return orgId;
  const slug = orgSlug || "default";
  const rows = await pgQuery(`SELECT id FROM organizations WHERE slug = $1 LIMIT 1`, [slug]);
  return rows[0]?.id ?? null;
}

async function getPrimaryCaseId(ticketId) {
  const rows = await pgQuery(
    `SELECT case_id FROM ticket_case_links
      WHERE ticket_id = $1 AND link_type = 'PRIMARY' LIMIT 1`,
    [ticketId],
  );
  return rows[0]?.case_id ?? null;
}

// Espejo defensivo al timeline del caso (nunca rompe la operación del ticket).
async function mirrorToCase(caseId, event) {
  if (!caseId) return;
  try {
    await addTimelineEvent(caseId, event);
  } catch (err) {
    logger.warn({ err: err.message, caseId }, "[ticketService] timeline mirror failed");
  }
}

// ── Crear ticket ──────────────────────────────────────────────────────────────

async function resolveServiceId({ serviceId, serviceSlug } = {}) {
  if (serviceId) return serviceId;
  if (!serviceSlug) return null;
  const rows = await pgQuery(`SELECT id FROM ticket_services WHERE slug = $1 LIMIT 1`, [serviceSlug]);
  return rows[0]?.id ?? null;
}

export async function createTicket({
  subject, priority = "MEDIUM", channel = "SOC_INITIATED",
  orgId, orgSlug, requesterContact = {}, assignedOperator = null,
  caseId = null, operatorCi = "system",
  ticketType = "CONSULTA", technicalSeverity = null,
  serviceId = null, serviceSlug = null, tags = [], ccContacts = [],
}) {
  const org = await resolveOrgId({ orgId, orgSlug });
  if (!org) throw new Error("organización no encontrada (org_id/orgSlug inválido)");
  const svc = await resolveServiceId({ serviceId, serviceSlug });
  const cleanTags = Array.isArray(tags)
    ? [...new Set(tags.map((t) => String(t).toLowerCase().trim()).filter(Boolean))].slice(0, 12)
    : [];
  const cc = Array.isArray(ccContacts) ? ccContacts.filter(Boolean) : [];

  // Ball-in-court inicial: si el SOC inicia, la pelota la tiene el cliente;
  // si el cliente abrió (portal/email), la tiene el SOC.
  const waitingOn = channel === "SOC_INITIATED" ? "CLIENT" : "SOC";
  const id = randomUUID();
  const publicRef = genPublicRef();

  const rows = await pgQuery(
    `INSERT INTO tickets
       (id, public_ref, org_id, subject, status, priority, channel,
        requester_contact, assigned_operator, waiting_on,
        ticket_type, technical_severity, service_id, tags, cc_contacts)
     VALUES ($1,$2,$3,$4,'ABIERTO',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING *`,
    [id, publicRef, org, subject, priority, channel,
     JSON.stringify(requesterContact), assignedOperator, waitingOn,
     ticketType, technicalSeverity, svc, cleanTags, JSON.stringify(cc)],
  );

  if (caseId) {
    await pgQuery(
      `INSERT INTO ticket_case_links (ticket_id, case_id, link_type, linked_by)
       VALUES ($1,$2,'PRIMARY',$3)
       ON CONFLICT (ticket_id, case_id) DO NOTHING`,
      [id, caseId, operatorCi],
    );
    await mirrorToCase(caseId, {
      eventType: "TICKET_STATUS", title: `Ticket ${publicRef} abierto`,
      description: subject, operatorCi, source: "TICKET",
      metadata: { ticketId: id, publicRef, status: "ABIERTO" },
    });
  }

  // ── Auto-asignación + balanceo por tiers (no rompe la creación si falla) ──────
  const ticket = rows[0];
  if (assignedOperator) {
    // Asignación explícita: respetar y solo difundir la actividad.
    emitTicketActivity("assigned", ticket, assignedOperator);
  } else if (channel === "SOC_INITIATED" && await isActiveOperator(operatorCi)) {
    // Ticket nacido desde un caso: lo posee el operador que lo creó.
    await pgQuery(`UPDATE tickets SET assigned_operator = $1 WHERE id = $2`, [operatorCi, ticket.id]);
    ticket.assigned_operator = operatorCi;
    emitTicketActivity("assigned", ticket, operatorCi);
  } else {
    // Entrante (portal/API/email): balanceo por tier según prioridad + notificación.
    ticket.assigned_operator = await autoAssignTicket(ticket);
  }

  // (#19) Reglas de negocio: pueden re-asignar / re-priorizar / etiquetar / avisar
  // al SM. Corren DESPUÉS del balanceo para poder sobreescribirlo. No rompen nada.
  await applyRulesOnCreate(ticket);

  // Si el SOC abrió el ticket (p.ej. desde Investigación), avisar al cliente por
  // email; el cliente lo abrió él mismo en portal/API, no hace falta notificarlo.
  if (channel === "SOC_INITIATED") void notifyClientTicketOpened(ticket);

  fireWebhook(org, "ticket.created", {
    ref: publicRef, subject, status: "ABIERTO", priority: ticket.priority, channel,
  });
  return ticket;
}

// ── Añadir mensaje al hilo (ping-pong) ────────────────────────────────────────

export async function addMessage(ticketId, {
  authorType, authorRef = null, visibility = "PUBLIC", body,
  attachments = [], expectsReply = true, operatorCi = "system", reportHtml = null,
  playbookHtml = null,
}) {
  if (!["CLIENT", "SOC", "SYSTEM"].includes(authorType)) {
    throw new Error("authorType inválido");
  }
  if (!body || !String(body).trim()) throw new Error("body vacío");

  const ticketRows = await pgQuery(`SELECT * FROM tickets WHERE id = $1 LIMIT 1`, [ticketId]);
  const ticket = ticketRows[0];
  if (!ticket) throw new Error("ticket no encontrado");

  const isPublic = visibility === "PUBLIC";

  // turnaround: segundos desde el último mensaje PUBLIC del lado CONTRARIO.
  let turnaround = null;
  if (isPublic && authorType !== "SYSTEM") {
    const opposite = authorType === "SOC" ? "CLIENT" : "SOC";
    const prev = await pgQuery(
      `SELECT created_at FROM ticket_messages
        WHERE ticket_id = $1 AND visibility = 'PUBLIC' AND author_type = $2
        ORDER BY created_at DESC LIMIT 1`,
      [ticketId, opposite],
    );
    if (prev[0]) {
      turnaround = Math.max(0, Math.round((Date.now() - new Date(prev[0].created_at).getTime()) / 1000));
    }
  }

  // is_first_response: primer mensaje PUBLIC del SOC en el ticket.
  let isFirstResponse = false;
  if (isPublic && authorType === "SOC" && !ticket.first_response_at) {
    const priorSoc = await pgQuery(
      `SELECT 1 FROM ticket_messages
        WHERE ticket_id = $1 AND author_type = 'SOC' AND visibility = 'PUBLIC' LIMIT 1`,
      [ticketId],
    );
    if (priorSoc.length === 0) isFirstResponse = true;
  }

  const msgId = randomUUID();
  await pgQuery(
    `INSERT INTO ticket_messages
       (id, ticket_id, author_type, author_ref, visibility, body, attachments,
        is_first_response, turnaround_seconds, report_html, playbook_html)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [msgId, ticketId, authorType, authorRef, visibility, body,
     JSON.stringify(attachments), isFirstResponse, turnaround, reportHtml, playbookHtml],
  );

  // Notas internas NO mueven el ball-in-court ni el estado público.
  if (isPublic) {
    let waitingOn = ticket.waiting_on;
    if (authorType === "CLIENT") waitingOn = "SOC";
    else if (authorType === "SOC") waitingOn = expectsReply ? "CLIENT" : "NONE";

    // Auto-transición de conveniencia (respeta VALID_TRANSITIONS).
    let nextStatus = ticket.status;
    if (authorType === "SOC" && ticket.status === "ABIERTO") nextStatus = "EN_ATENCION";
    else if (authorType === "CLIENT" && ticket.status === "ESPERANDO_CLIENTE") nextStatus = "EN_ATENCION";
    if (nextStatus !== ticket.status && !isValidTransition(ticket.status, nextStatus)) {
      nextStatus = ticket.status;
    }
    if (authorType === "SOC" && expectsReply && nextStatus === "EN_ATENCION") {
      // mensaje del SOC que espera respuesta → estado "esperando cliente"
      if (isValidTransition("EN_ATENCION", "ESPERANDO_CLIENTE")) nextStatus = "ESPERANDO_CLIENTE";
    }

    await pgQuery(
      `UPDATE tickets
          SET waiting_on = $1, status = $2,
              first_response_at = COALESCE(first_response_at, $3),
              updated_at = now()
        WHERE id = $4`,
      [waitingOn, nextStatus, isFirstResponse ? new Date().toISOString() : ticket.first_response_at, ticketId],
    );

    const caseId = await getPrimaryCaseId(ticketId);
    await mirrorToCase(caseId, {
      eventType: "TICKET_MSG",
      title: `${authorType === "CLIENT" ? "Cliente" : "SOC"} · ${ticket.public_ref}`,
      description: String(body).slice(0, 500),
      operatorCi, source: "TICKET",
      metadata: { ticketId, msgId, authorType, turnaroundSeconds: turnaround, isFirstResponse },
    });

    // Webhook saliente SÓLO de mensajes públicos (las notas INTERNAL nunca salen).
    fireWebhook(ticket.org_id, "ticket.message", {
      ref: ticket.public_ref, author: authorType, body: String(body),
      isFirstResponse, turnaroundSeconds: turnaround,
    });
  }

  return { id: msgId, ticketId, isFirstResponse, turnaroundSeconds: turnaround };
}

// ── Transición de estado ──────────────────────────────────────────────────────

export async function transitionStatus(ticketId, { toStatus, operatorCi = "system", note = null, allowDirectClose = false }) {
  if (!TICKET_STATUSES.has(toStatus)) throw new Error(`estado inválido: ${toStatus}`);
  // Sign-off del cliente OBLIGATORIO para cerrar (#23): el SOC no puede mover a
  // CERRADO directo. La única ruta es decideClosure() (confirmación del cliente)
  // o un auto-cierre interno, ambos pasan allowDirectClose:true.
  if (toStatus === "CERRADO" && !allowDirectClose) {
    const err = new Error("El cierre requiere confirmación del cliente: usá «Solicitar confirmación de cierre».");
    err.code = "CLOSURE_REQUIRES_CONFIRMATION";
    throw err;
  }
  const rows = await pgQuery(`SELECT * FROM tickets WHERE id = $1 LIMIT 1`, [ticketId]);
  const ticket = rows[0];
  if (!ticket) throw new Error("ticket no encontrado");
  if (ticket.status === toStatus) return ticket;
  if (!isValidTransition(ticket.status, toStatus)) {
    const err = new Error(`transición inválida ${ticket.status} → ${toStatus}`);
    err.code = "INVALID_TRANSITION";
    throw err;
  }

  // Efectos de timestamp / ball-in-court por estado destino.
  const sets = ["status = $1", "updated_at = now()"];
  const params = [toStatus];
  let waitingOn = ticket.waiting_on;

  if (toStatus === "RESUELTO") { sets.push("resolved_at = now()"); waitingOn = "NONE"; }
  if (toStatus === "CERRADO")  { sets.push("closed_at = now()", "closure_requested_at = NULL"); waitingOn = "NONE"; }
  if (toStatus === "ESPERANDO_CLIENTE") waitingOn = "CLIENT";
  if (toStatus === "EN_ATENCION") waitingOn = "SOC";
  if (toStatus === "REABIERTO") {
    sets.push("reopened_count = reopened_count + 1");
    sets.push("resolved_at = NULL", "closed_at = NULL", "closure_requested_at = NULL");
    waitingOn = "SOC";
  }
  params.push(waitingOn);
  sets.push(`waiting_on = $${params.length}`);
  params.push(ticketId);

  const updated = await pgQuery(
    `UPDATE tickets SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`,
    params,
  );

  const caseId = await getPrimaryCaseId(ticketId);
  await mirrorToCase(caseId, {
    eventType: "TICKET_STATUS",
    title: `Ticket ${ticket.public_ref}: ${ticket.status} → ${toStatus}`,
    description: note, operatorCi, source: "TICKET",
    metadata: { ticketId, from: ticket.status, to: toStatus },
  });

  fireWebhook(ticket.org_id, "ticket.status_changed", {
    ref: ticket.public_ref, from: ticket.status, to: toStatus, waitingOn,
  });
  return updated[0];
}

// ── Confirmación de cierre por el cliente (sign-off #23) ──────────────────────
// Para CERRAR un ticket es OBLIGATORIA la confirmación del cliente. El SOC dispara
// requestClosureConfirmation() → token single-use + vínculo; el cliente lo resuelve
// vía decideClosure() en una página ligera (sin login). Solo se guarda el SHA-256
// del token (el crudo viaja únicamente en el enlace), espejo de portal_magic_links.

const CLOSURE_TTL_DAYS = Math.max(1, Number(process.env.TICKET_CLOSURE_TTL_DAYS ?? 14) || 14);

function _sha256(s) { return createHash("sha256").update(String(s)).digest("hex"); }
function _closureToken() { return randomBytes(32).toString("base64url"); }

// Notifica al cliente (best-effort) con el vínculo de confirmación de cierre.
async function notifyClientClosureRequested(ticket, link) {
  try {
    const rows = await pgQuery(`SELECT name, contacts FROM organizations WHERE id = $1`, [ticket.org_id]);
    const org = rows[0];
    const orgEmails = (Array.isArray(org?.contacts) ? org.contacts : [])
      .map((c) => (typeof c === "string" ? c : c?.email)).filter(Boolean);
    const ccEmails = (Array.isArray(ticket.cc_contacts) ? ticket.cc_contacts : [])
      .map((c) => (typeof c === "string" ? c : c?.email)).filter(Boolean);
    const to = [...new Set([...orgEmails, ...ccEmails])];
    if (!to.length) return;
    const subject = `Confirmá el cierre del ticket ${ticket.public_ref}`;
    const text =
      `Hola,\n\nNuestro equipo considera resuelto el ticket ${ticket.public_ref} — «${ticket.subject}».\n\n` +
      `Para CERRARLO necesitamos tu confirmación. Abrí este enlace (válido ${CLOSURE_TTL_DAYS} días):\n\n${link}\n\n` +
      `Si el problema todavía NO está resuelto, desde el mismo enlace podés indicarlo y lo retomamos.`;
    const r = await sendMail({ to: to.join(", "), subject, text });
    if (!r?.ok) logger.warn({ err: r?.error, ref: ticket.public_ref }, "[ticketService] email de confirmación de cierre no enviado");
  } catch (err) {
    logger.warn({ err: err.message }, "[ticketService] notifyClientClosureRequested falló (no-fatal)");
  }
}

/** El SOC solicita al cliente que confirme el cierre: genera token single-use +
 *  vínculo (TTL CLOSURE_TTL_DAYS), pone la pelota en el cliente y lo notifica.
 *  Devuelve el enlace crudo para que el SOC pueda copiarlo además del email. */
export async function requestClosureConfirmation(ticketId, { operatorCi = "system" } = {}) {
  const rows = await pgQuery(`SELECT * FROM tickets WHERE id = $1 LIMIT 1`, [ticketId]);
  const ticket = rows[0];
  if (!ticket) throw new Error("ticket no encontrado");
  if (ticket.status === "CERRADO") throw new Error("el ticket ya está cerrado");

  const token = _closureToken();
  const expires = new Date(Date.now() + CLOSURE_TTL_DAYS * 86400_000).toISOString();
  // Una sola confirmación pendiente por ticket: invalidar las previas vivas.
  await pgQuery(`DELETE FROM ticket_closure_confirmations WHERE ticket_id = $1 AND decided_at IS NULL`, [ticketId]);
  await pgQuery(
    `INSERT INTO ticket_closure_confirmations (ticket_id, token_hash, requested_by, expires_at)
     VALUES ($1,$2,$3,$4)`,
    [ticketId, _sha256(token), operatorCi, expires],
  );

  // Registro visible en el hilo (antes de fijar la marca: addMessage recalcula
  // waiting_on a partir del snapshot del ticket; el UPDATE posterior gana).
  try {
    await addMessage(ticketId, {
      authorType: "SYSTEM", authorRef: operatorCi, visibility: "PUBLIC",
      body: "Te enviamos un enlace para que confirmes el cierre de este ticket.",
      operatorCi, expectsReply: false,
    });
  } catch (err) { logger.warn({ err: err.message }, "[ticketService] mensaje de solicitud de cierre falló (no-fatal)"); }

  const updated = await pgQuery(
    `UPDATE tickets SET waiting_on = 'CLIENT', closure_requested_at = now(), updated_at = now()
      WHERE id = $1 RETURNING *`,
    [ticketId],
  );

  const link = closureConfirmUrl(token);
  await notifyClientClosureRequested(ticket, link);

  const caseId = await getPrimaryCaseId(ticketId);
  await mirrorToCase(caseId, {
    eventType: "TICKET_STATUS",
    title: `Ticket ${ticket.public_ref}: confirmación de cierre solicitada al cliente`,
    description: null, operatorCi, source: "TICKET",
    metadata: { ticketId, action: "closure_requested" },
  });
  fireWebhook(ticket.org_id, "ticket.closure_requested", { ref: ticket.public_ref, expiresAt: expires });

  return { ticket: updated[0], link, expiresAt: expires };
}

/** Estado del vínculo (para renderizar la página ligera). No consume el token. */
export async function getClosureByToken(token) {
  if (!token) return null;
  const rows = await pgQuery(
    `SELECT c.expires_at, c.decided_at, c.decision, t.public_ref, t.subject, t.status
       FROM ticket_closure_confirmations c
       JOIN tickets t ON t.id = c.ticket_id
      WHERE c.token_hash = $1 LIMIT 1`,
    [_sha256(token)],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    ref: r.public_ref, subject: r.subject, ticketStatus: r.status,
    decided: !!r.decided_at, decision: r.decision ?? null,
    expired: new Date(r.expires_at).getTime() <= Date.now(), expiresAt: r.expires_at,
  };
}

/** El cliente resuelve la confirmación (single-use). CONFIRMADO → CERRADO (única
 *  ruta de cierre); RECHAZADO → vuelve la pelota al SOC y se limpia la marca. */
export async function decideClosure(token, { decision, reason = null, ip = null } = {}) {
  if (!["CONFIRMADO", "RECHAZADO"].includes(decision)) throw new Error("decisión inválida");
  // Consumir atómicamente el token pendiente y no expirado (single-use, anti-replay).
  const consumed = await pgQuery(
    `UPDATE ticket_closure_confirmations
        SET decided_at = now(), decision = $2, reject_reason = $3, decided_ip = $4
      WHERE token_hash = $1 AND decided_at IS NULL AND expires_at > now()
    RETURNING ticket_id`,
    [_sha256(token), decision, decision === "RECHAZADO" ? reason : null, ip],
  );
  if (consumed.length === 0) {
    const err = new Error("enlace inválido, expirado o ya utilizado");
    err.code = "CLOSURE_LINK_INVALID";
    throw err;
  }
  const ticketId = consumed[0].ticket_id;
  const ticket = (await pgQuery(`SELECT public_ref, org_id, status FROM tickets WHERE id = $1`, [ticketId]))[0];

  if (decision === "CONFIRMADO") {
    await addMessage(ticketId, {
      authorType: "CLIENT", authorRef: "cliente", visibility: "PUBLIC",
      body: "Confirmo que el incidente está resuelto; pueden cerrar el ticket.",
      operatorCi: "cliente", expectsReply: false,
    }).catch((err) => logger.warn({ err: err.message }, "[ticketService] mensaje de confirmación falló (no-fatal)"));
    const updated = await transitionStatus(ticketId, {
      toStatus: "CERRADO", operatorCi: "cliente",
      note: "Cierre confirmado por el cliente.", allowDirectClose: true,
    });
    fireWebhook(ticket.org_id, "ticket.closure_confirmed", { ref: ticket.public_ref });
    return { ref: ticket.public_ref, status: updated.status, decision };
  }

  // RECHAZADO: el cliente indica que aún no está resuelto.
  await addMessage(ticketId, {
    authorType: "CLIENT", authorRef: "cliente", visibility: "PUBLIC",
    body: reason ? `El incidente todavía NO está resuelto: ${reason}` : "El incidente todavía no está resuelto.",
    operatorCi: "cliente", expectsReply: true,
  }).catch((err) => logger.warn({ err: err.message }, "[ticketService] mensaje de rechazo falló (no-fatal)"));
  await pgQuery(
    `UPDATE tickets SET waiting_on = 'SOC', closure_requested_at = NULL, updated_at = now() WHERE id = $1`,
    [ticketId],
  );
  const caseId = await getPrimaryCaseId(ticketId);
  await mirrorToCase(caseId, {
    eventType: "TICKET_STATUS",
    title: `Ticket ${ticket.public_ref}: el cliente rechazó el cierre`,
    description: reason ?? null, operatorCi: "cliente", source: "TICKET",
    metadata: { ticketId, action: "closure_rejected" },
  });
  fireWebhook(ticket.org_id, "ticket.closure_rejected", { ref: ticket.public_ref, reason: reason ?? null });
  return { ref: ticket.public_ref, status: ticket.status, decision };
}

// ── Vincular / desvincular caso ───────────────────────────────────────────────

export async function linkCase(ticketId, { caseId, linkType = "PRIMARY", operatorCi = "system" }) {
  if (!["PRIMARY", "RELATED"].includes(linkType)) throw new Error("linkType inválido");
  // Un solo PRIMARY por ticket: si se pide PRIMARY, degradar el actual a RELATED.
  if (linkType === "PRIMARY") {
    await pgQuery(
      `UPDATE ticket_case_links SET link_type = 'RELATED'
        WHERE ticket_id = $1 AND link_type = 'PRIMARY' AND case_id <> $2`,
      [ticketId, caseId],
    );
  }
  await pgQuery(
    `INSERT INTO ticket_case_links (ticket_id, case_id, link_type, linked_by)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT (ticket_id, case_id) DO UPDATE SET link_type = EXCLUDED.link_type`,
    [ticketId, caseId, linkType, operatorCi],
  );
  return getPrimaryCaseId(ticketId).then(() => ({ ok: true }));
}

export async function unlinkCase(ticketId, caseId) {
  await pgQuery(`DELETE FROM ticket_case_links WHERE ticket_id = $1 AND case_id = $2`, [ticketId, caseId]);
  return { ok: true };
}

// Garantiza el vínculo PRIMARY caso↔ticket de forma idempotente: inserta el
// PRIMARY sólo si el ticket aún no tiene uno (no pisa un PRIMARY de otro caso).
// Usado para auto-vincular cuando se envía el informe del caso a un ticket.
export async function ensurePrimaryCaseLink(ticketId, caseId, operatorCi = "system") {
  if (!ticketId || !caseId) return;
  await pgQuery(
    `INSERT INTO ticket_case_links (ticket_id, case_id, link_type, linked_by)
     SELECT $1,$2,'PRIMARY',$3
      WHERE NOT EXISTS (
        SELECT 1 FROM ticket_case_links WHERE ticket_id = $1 AND link_type = 'PRIMARY'
      )
     ON CONFLICT (ticket_id, case_id) DO NOTHING`,
    [ticketId, caseId, operatorCi],
  );
}

// ── Asignar operador (el gate RBAC can_assign_cases se valida en la ruta) ─────

export async function assignTicket(ticketId, { operatorCi }) {
  const rows = await pgQuery(
    `UPDATE tickets SET assigned_operator = $1, updated_at = now()
      WHERE id = $2 RETURNING *`,
    [operatorCi, ticketId],
  );
  if (!rows[0]) throw new Error("ticket no encontrado");
  return rows[0];
}

// ── Solicitudes accionables (§6) ──────────────────────────────────────────────

export async function createActionRequest({
  ticketId = null, caseId = null, orgSlug = null, orgId = null,
  requestedBy, actionType, title, rationale,
  recommendedSteps = null, urgency = "MEDIUM", dueAt = null,
}) {
  if (!ACTION_TYPES.has(actionType)) throw new Error(`action_type inválido: ${actionType}`);
  if (!title || !rationale) throw new Error("title y rationale son obligatorios");

  // Resolver/crear ticket: si viene desde un caso sin ticket, reusar el PRIMARY
  // existente o crear uno SOC_INITIATED y vincularlo. Al crear uno NUEVO hay que
  // saber para QUÉ cliente (org) es — si no, no llegaría al portal del cliente.
  let tid = ticketId;
  if (!tid) {
    if (!caseId) throw new Error("se requiere ticketId o caseId");
    const existing = await pgQuery(
      `SELECT ticket_id FROM ticket_case_links
        WHERE case_id = $1 AND link_type = 'PRIMARY' LIMIT 1`,
      [caseId],
    );
    if (existing[0]) {
      tid = existing[0].ticket_id;
    } else {
      let effOrgSlug = orgSlug;
      let effOrgId = orgId;
      if (!effOrgSlug && !effOrgId) {
        const lgcrId = await resolveOrgId({ orgSlug: "lgcr" });
        if (lgcrId) effOrgId = lgcrId;
        else {
          const orgs = await getActiveOrgs();
          if (orgs[0]) effOrgId = orgs[0].id;
        }
      }
      if (!effOrgSlug && !effOrgId) {
        throw new Error("especificá la organización (cliente) para la solicitud");
      }
      const t = await createTicket({
        subject: title, priority: urgency, channel: "SOC_INITIATED",
        caseId, operatorCi: requestedBy, orgSlug: effOrgSlug, orgId: effOrgId,
      });
      tid = t.id;
    }
  }

  const effectiveCase = caseId || (await getPrimaryCaseId(tid));
  const id = randomUUID();
  const rows = await pgQuery(
    `INSERT INTO ticket_action_requests
       (id, ticket_id, case_id, requested_by, action_type, title, rationale,
        recommended_steps, urgency, due_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     RETURNING *`,
    [id, tid, effectiveCase, requestedBy, actionType, title, rationale,
     recommendedSteps, urgency, dueAt],
  );

  // La pelota pasa al cliente: debe decidir.
  await pgQuery(`UPDATE tickets SET waiting_on = 'CLIENT', updated_at = now() WHERE id = $1`, [tid]);

  await mirrorToCase(effectiveCase, {
    eventType: "TICKET_ACTION_REQUEST",
    title: `Solicitud al cliente: ${actionType}`,
    description: title, operatorCi: requestedBy, source: "TICKET",
    metadata: { ticketId: tid, actionRequestId: id, actionType, urgency },
  });

  return rows[0];
}

/**
 * Registra la disposición del cliente sobre una solicitud (§6).
 * Para RIESGO_ACEPTADO exige el bloque de aceptación (quién/alcance) — los CHECK
 * de la tabla son la red de seguridad, acá validamos antes para dar buen error.
 */
export async function decideActionRequest(actionRequestId, {
  decision, decidedBy, decisionNote = null, deferredUntil = null,
  riskAcceptedBy = null, riskAcceptanceScope = null, riskReviewAt = null,
}) {
  if (!ACTION_DECISIONS.has(decision)) throw new Error(`disposición inválida: ${decision}`);
  if (decision === "RIESGO_ACEPTADO" && (!riskAcceptedBy || !riskAcceptanceScope)) {
    throw new Error("RIESGO_ACEPTADO requiere risk_accepted_by y risk_acceptance_scope");
  }

  const rows = await pgQuery(
    `UPDATE ticket_action_requests
        SET status = $1, decided_by = $2, decided_at = now(), decision_note = $3,
            deferred_until = $4, risk_accepted_by = $5, risk_acceptance_scope = $6,
            risk_review_at = $7, updated_at = now()
      WHERE id = $8
    RETURNING *`,
    [decision, decidedBy, decisionNote, deferredUntil,
     riskAcceptedBy, riskAcceptanceScope, riskReviewAt, actionRequestId],
  );
  const ar = rows[0];
  if (!ar) throw new Error("solicitud no encontrada");

  // Decidida → la pelota vuelve al SOC.
  await pgQuery(`UPDATE tickets SET waiting_on = 'SOC', updated_at = now() WHERE id = $1`, [ar.ticket_id]);

  await mirrorToCase(ar.case_id, {
    eventType: "TICKET_ACTION_DECISION",
    title: `Cliente decidió: ${decision} (${ar.action_type})`,
    description: decision === "RIESGO_ACEPTADO"
      ? `Riesgo asumido por ${riskAcceptedBy}: ${riskAcceptanceScope}`
      : decisionNote,
    operatorCi: decidedBy, source: "TICKET",
    metadata: { ticketId: ar.ticket_id, actionRequestId, decision },
  });

  const tk = (await pgQuery(`SELECT org_id, public_ref FROM tickets WHERE id = $1 LIMIT 1`, [ar.ticket_id]))[0];
  if (tk) {
    fireWebhook(tk.org_id, "action_request.decided", {
      ref: tk.public_ref, actionType: ar.action_type, title: ar.title, decision,
    });
  }

  return ar;
}

// ── Lecturas ──────────────────────────────────────────────────────────────────

export async function listTickets({
  status, waitingOn, operator, org, limit = 100,
  type, tag, service, pinned, includeSnoozed = false, includeMerged = false,
} = {}) {
  const where = [];
  const params = [];
  if (status)    { params.push(status);    where.push(`t.status = $${params.length}`); }
  if (waitingOn) { params.push(waitingOn);  where.push(`t.waiting_on = $${params.length}`); }
  if (operator)  { params.push(operator);   where.push(`t.assigned_operator = $${params.length}`); }
  if (org)       { params.push(org);        where.push(`o.slug = $${params.length}`); }
  if (type)      { params.push(type);       where.push(`t.ticket_type = $${params.length}`); }
  if (service)   { params.push(service);    where.push(`s.slug = $${params.length}`); }
  if (tag)       { params.push(tag);        where.push(`$${params.length} = ANY(t.tags)`); }
  if (pinned === true || pinned === "true") where.push(`t.pinned = true`);
  // (#6) los tickets absorbidos por un merge no se muestran en la cola por defecto.
  if (!includeMerged) where.push(`t.merged_into IS NULL`);
  // (#18) los pospuestos vigentes se ocultan de la cola activa (salvo que se pidan).
  if (!includeSnoozed) where.push(`(t.snoozed_until IS NULL OR t.snoozed_until <= now())`);
  params.push(Math.min(Number(limit) || 100, 500));

  return pgQuery(
    `SELECT t.*, o.slug AS org_slug, o.name AS org_name, op.name AS assigned_operator_name,
            s.slug AS service_slug, s.name AS service_name,
            (SELECT case_id FROM ticket_case_links l
              WHERE l.ticket_id = t.id AND l.link_type = 'PRIMARY' LIMIT 1) AS primary_case_id,
            (SELECT count(*) FROM ticket_messages m WHERE m.ticket_id = t.id AND m.visibility = 'PUBLIC') AS public_msgs,
            (SELECT count(*) FROM ticket_messages m
               WHERE m.ticket_id = t.id AND m.visibility = 'PUBLIC' AND m.author_type = 'CLIENT'
                 AND m.created_at > COALESCE(t.soc_last_read_at, 'epoch'::timestamptz)) AS unread_client,
            (SELECT count(*) FROM ticket_watchers w WHERE w.ticket_id = t.id) AS watcher_count
       FROM tickets t
       JOIN organizations o ON o.id = t.org_id
       LEFT JOIN soc_operators op ON op.id = t.assigned_operator
       LEFT JOIN ticket_services s ON s.id = t.service_id
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY t.pinned DESC, t.updated_at DESC
      LIMIT $${params.length}`,
    params,
  );
}

// Actividad reciente (tickets nuevos + a quién se asignaron) para la campana
// de tickets de la barra superior.
export async function listRecentActivity(limit = 25) {
  return pgQuery(
    `SELECT t.id, t.public_ref, t.subject, t.priority, t.channel, t.status,
            t.assigned_operator, op.name AS assigned_operator_name,
            t.created_at, t.updated_at, o.name AS org_name
       FROM tickets t JOIN organizations o ON o.id = t.org_id
       LEFT JOIN soc_operators op ON op.id = t.assigned_operator
      ORDER BY t.created_at DESC LIMIT $1`,
    [Math.min(Number(limit) || 25, 100)],
  );
}

export async function getTicket(ticketId, { includeInternal = true } = {}) {
  const rows = await pgQuery(
    `SELECT t.*, o.slug AS org_slug, o.name AS org_name, op.name AS assigned_operator_name,
            s.slug AS service_slug, s.name AS service_name,
            (SELECT case_id FROM ticket_case_links l
              WHERE l.ticket_id = t.id AND l.link_type = 'PRIMARY' LIMIT 1) AS primary_case_id
       FROM tickets t JOIN organizations o ON o.id = t.org_id
       LEFT JOIN soc_operators op ON op.id = t.assigned_operator
       LEFT JOIN ticket_services s ON s.id = t.service_id
      WHERE t.id = $1 LIMIT 1`,
    [ticketId],
  );
  const ticket = rows[0];
  if (!ticket) return null;

  const messages = await pgQuery(
    `SELECT m.id, m.author_type, m.author_ref, m.visibility, m.body, m.attachments,
            m.is_first_response, m.turnaround_seconds, m.created_at,
            (m.report_html IS NOT NULL) AS has_report,
            (m.playbook_html IS NOT NULL) AS has_playbook,
            op.name AS author_operator_name
       FROM ticket_messages m
       LEFT JOIN soc_operators op ON op.id = m.author_ref AND m.author_type = 'SOC'
      WHERE m.ticket_id = $1 ${includeInternal ? "" : "AND m.visibility = 'PUBLIC'"}
      ORDER BY m.created_at ASC`,
    [ticketId],
  );
  // Resolver el nombre humano del autor para el hilo (analista SOC ↔ contacto del
  // cliente). SOC → soc_operators.name (fallback al CI); CLIENT → contacto del
  // ticket o nombre de la organización; SYSTEM → "Sistema".
  // requester_contact es JSONB { name?, email? } (default '{}'); extraer un string.
  const rc = ticket.requester_contact;
  const contactStr = rc && typeof rc === "object"
    ? (rc.name || rc.email || null)
    : (typeof rc === "string" ? rc : null);
  const clientName = contactStr || ticket.org_name || "Cliente";
  for (const m of messages) {
    m.author_name = m.author_type === "SOC"
      ? (m.author_operator_name || m.author_ref || "SOC")
      : m.author_type === "CLIENT"
        ? clientName
        : "Sistema";
    delete m.author_operator_name;
  }
  const links = await pgQuery(
    `SELECT case_id, link_type, linked_by, linked_at FROM ticket_case_links WHERE ticket_id = $1`,
    [ticketId],
  );
  const actionRequests = await pgQuery(
    `SELECT * FROM ticket_action_requests WHERE ticket_id = $1 ORDER BY created_at DESC`,
    [ticketId],
  );
  const watchers = await pgQuery(
    `SELECT w.operator_ci, op.name AS operator_name, w.added_at
       FROM ticket_watchers w LEFT JOIN soc_operators op ON op.id = w.operator_ci
      WHERE w.ticket_id = $1 ORDER BY w.added_at ASC`,
    [ticketId],
  );

  return { ...ticket, messages, links, actionRequests, watchers };
}

// ── Métricas (§5 / §6.4) ──────────────────────────────────────────────────────

export async function getCommMetrics({ days = 30, operator = null } = {}) {
  const params = [days];
  let opFilter = "";
  if (operator) { params.push(operator); opFilter = `AND t.assigned_operator = $${params.length}`; }

  const [agg] = await pgQuery(
    `WITH base AS (
       SELECT t.* FROM tickets t
        WHERE t.created_at >= now() - ($1 || ' days')::interval ${opFilter}
     )
     SELECT
       count(*)                                                           AS tickets,
       count(*) FILTER (WHERE status NOT IN ('CERRADO'))                  AS open_tickets,
       count(*) FILTER (WHERE waiting_on = 'SOC')                         AS waiting_on_soc,
       count(*) FILTER (WHERE waiting_on = 'CLIENT')                      AS waiting_on_client,
       round(avg(EXTRACT(epoch FROM first_response_at - created_at)) FILTER (WHERE first_response_at IS NOT NULL)) AS frt_avg_sec,
       round(avg(EXTRACT(epoch FROM resolved_at - created_at)) FILTER (WHERE resolved_at IS NOT NULL))            AS res_avg_sec,
       sum(reopened_count)                                                AS reopens,
       round(avg(csat_score) FILTER (WHERE csat_score IS NOT NULL), 2)    AS csat_avg,
       count(csat_score) FILTER (WHERE csat_score IS NOT NULL)            AS csat_count
     FROM base`,
    params,
  );

  // NRT (respuestas SOC posteriores) y CRT (respuestas del cliente) desde el hilo.
  const [cadence] = await pgQuery(
    `SELECT
       round(avg(turnaround_seconds) FILTER (WHERE author_type = 'SOC' AND NOT is_first_response))  AS nrt_avg_sec,
       round(avg(turnaround_seconds) FILTER (WHERE author_type = 'CLIENT'))                          AS crt_avg_sec,
       round(avg(rt.round_trips), 1)                                                                 AS round_trips_avg
     FROM ticket_messages msg
     JOIN tickets t ON t.id = msg.ticket_id AND t.created_at >= now() - ($1 || ' days')::interval ${opFilter}
     LEFT JOIN (
       SELECT ticket_id, least(
         count(*) FILTER (WHERE author_type = 'SOC'    AND visibility = 'PUBLIC'),
         count(*) FILTER (WHERE author_type = 'CLIENT' AND visibility = 'PUBLIC')
       ) AS round_trips
       FROM ticket_messages GROUP BY ticket_id
     ) rt ON rt.ticket_id = msg.ticket_id
     WHERE msg.visibility = 'PUBLIC'`,
    params,
  );

  return { ...agg, ...cadence };
}

export async function getActionMetrics({ days = 30 } = {}) {
  const [m] = await pgQuery(
    `SELECT
       count(*)                                                AS total,
       count(*) FILTER (WHERE status = 'PENDIENTE')            AS pending,
       count(*) FILTER (WHERE status = 'EJECUTADA')            AS executed,
       count(*) FILTER (WHERE status = 'RIESGO_ACEPTADO')      AS risk_accepted,
       count(*) FILTER (WHERE status = 'RECHAZADA')            AS rejected,
       count(*) FILTER (WHERE status = 'PENDIENTE' AND due_at IS NOT NULL AND due_at < now()) AS overdue,
       round(avg(EXTRACT(epoch FROM decided_at - created_at)) FILTER (WHERE decided_at IS NOT NULL)) AS ttd_avg_sec
     FROM ticket_action_requests
     WHERE created_at >= now() - ($1 || ' days')::interval`,
    [days],
  );
  return m;
}

export async function getOpenRiskAcceptances() {
  return pgQuery(`SELECT * FROM v_open_risk_acceptances ORDER BY risk_review_at NULLS LAST`);
}

// ── CSAT — satisfacción del cliente (§7 #12) ─────────────────────────────────
export async function submitCsat(ticketId, { score, comment = null }) {
  const s = Number(score);
  if (!Number.isInteger(s) || s < 1 || s > 5) throw new Error("score debe ser 1-5");
  const rows = await pgQuery(
    `UPDATE tickets
        SET csat_score = $1, csat_comment = $2, csat_at = now(), updated_at = now()
      WHERE id = $3 AND status IN ('RESUELTO', 'CERRADO')
    RETURNING id, csat_score`,
    [s, comment, ticketId],
  );
  if (!rows[0]) throw new Error("solo se puede puntuar un ticket resuelto o cerrado");
  return rows[0];
}

// ── Plantillas de respuesta (§7 #9) ──────────────────────────────────────────
export async function listTemplates() {
  return pgQuery(`SELECT id, title, body, category FROM ticket_templates ORDER BY title ASC`);
}
export async function createTemplate({ title, body, category = null, createdBy = "system" }) {
  if (!title || !body) throw new Error("title y body son obligatorios");
  const rows = await pgQuery(
    `INSERT INTO ticket_templates (title, body, category, created_by)
     VALUES ($1,$2,$3,$4) RETURNING id, title, body, category`,
    [String(title).trim(), String(body), category, createdBy],
  );
  return rows[0];
}
export async function deleteTemplate(id) {
  await pgQuery(`DELETE FROM ticket_templates WHERE id = $1`, [id]);
  return { ok: true };
}

// HTML del informe adjunto a un mensaje (para el modal). Scoping de org/caso se
// valida en la ruta que la llama.
export async function getMessageReportHtml(msgId) {
  const rows = await pgQuery(`SELECT ticket_id, report_html FROM ticket_messages WHERE id = $1 LIMIT 1`, [msgId]);
  return rows[0] ?? null;
}

// HTML del playbook adjunto a un mensaje (para el modal). Espejo del informe.
export async function getMessagePlaybookHtml(msgId) {
  const rows = await pgQuery(`SELECT ticket_id, playbook_html FROM ticket_messages WHERE id = $1 LIMIT 1`, [msgId]);
  return rows[0] ?? null;
}

// Marca el ticket como leído por el SOC (analista) → apaga el resaltado de
// "mensajes nuevos del cliente sin leer" en el dashboard.
export async function markSocRead(ticketId) {
  await pgQuery(`UPDATE tickets SET soc_last_read_at = now() WHERE id = $1`, [ticketId]);
  return { ok: true };
}

// Ticket PRIMARY de un caso (para adjuntarle el informe desde la Investigación).
export async function getPrimaryTicketForCase(caseId) {
  const rows = await pgQuery(
    `SELECT ticket_id FROM ticket_case_links WHERE case_id = $1 AND link_type = 'PRIMARY' LIMIT 1`,
    [caseId],
  );
  return rows[0]?.ticket_id ?? null;
}

// Orgs activas (para el selector de cliente al crear solicitudes desde un caso).
export async function getActiveOrgs() {
  return pgQuery(
    `SELECT id, slug, name FROM organizations
      WHERE status = 'ACTIVE' ORDER BY (slug = 'default') DESC, name ASC`,
  );
}

const ORG_STATUSES = new Set(["ACTIVE", "SUSPENDED", "ARCHIVED"]);

function normalizeOrgSlug(raw) {
  return String(raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** Listado completo para administración (Config → Organizaciones). */
export async function listAllOrganizations() {
  return pgQuery(
    `SELECT o.id, o.slug, o.name, o.status, o.created_at, o.updated_at,
            COUNT(t.id)::int AS ticket_count
       FROM organizations o
       LEFT JOIN tickets t ON t.org_id = o.id
      GROUP BY o.id
      ORDER BY o.name ASC`,
  );
}

export async function createOrganization({ slug, name, status = "ACTIVE" }) {
  const cleanSlug = normalizeOrgSlug(slug);
  if (!cleanSlug || cleanSlug.length < 2) {
    throw new Error("slug inválido (mín. 2 caracteres: letras, números o guiones)");
  }
  if (!name?.trim()) throw new Error("name es obligatorio");
  if (!ORG_STATUSES.has(status)) throw new Error("status inválido");

  const rows = await pgQuery(
    `INSERT INTO organizations (slug, name, status)
     VALUES ($1, $2, $3)
     RETURNING id, slug, name, status, created_at, updated_at`,
    [cleanSlug, name.trim(), status],
  );
  return { ...rows[0], ticket_count: 0 };
}

export async function updateOrganization(id, { slug, name, status } = {}) {
  const current = await pgQuery(
    `SELECT id, slug FROM organizations WHERE id = $1`,
    [id],
  );
  if (!current[0]) throw new Error("organización no encontrada");

  const sets = [];
  const vals = [id];
  let n = 2;

  if (slug !== undefined) {
    const cleanSlug = normalizeOrgSlug(slug);
    if (!cleanSlug || cleanSlug.length < 2) {
      throw new Error("slug inválido (mín. 2 caracteres: letras, números o guiones)");
    }
    sets.push(`slug = $${n++}`);
    vals.push(cleanSlug);
  }
  if (name !== undefined) {
    if (!String(name).trim()) throw new Error("name no puede estar vacío");
    sets.push(`name = $${n++}`);
    vals.push(String(name).trim());
  }
  if (status !== undefined) {
    if (!ORG_STATUSES.has(status)) throw new Error("status inválido");
    sets.push(`status = $${n++}`);
    vals.push(status);
  }
  if (!sets.length) return current[0];

  sets.push("updated_at = now()");
  const rows = await pgQuery(
    `UPDATE organizations SET ${sets.join(", ")} WHERE id = $1
     RETURNING id, slug, name, status, created_at, updated_at`,
    vals,
  );
  const counts = await pgQuery(
    `SELECT COUNT(*)::int AS ticket_count FROM tickets WHERE org_id = $1`,
    [id],
  );
  return { ...rows[0], ticket_count: counts[0]?.ticket_count ?? 0 };
}

export async function deleteOrganization(id) {
  const org = await pgQuery(`SELECT id, slug FROM organizations WHERE id = $1`, [id]);
  if (!org[0]) throw new Error("organización no encontrada");
  if (org[0].slug === "default") {
    throw new Error("no se puede eliminar la organización por defecto");
  }

  const counts = await pgQuery(
    `SELECT COUNT(*)::int AS c FROM tickets WHERE org_id = $1`,
    [id],
  );
  if ((counts[0]?.c ?? 0) > 0) {
    throw new Error(`no se puede eliminar: ${counts[0].c} ticket(s) asociados`);
  }

  await pgQuery(`DELETE FROM organizations WHERE id = $1`, [id]);
  return { ok: true };
}

// ── Tickets vinculados a un caso (para la vista de Investigación) ─────────────
// Devuelve los tickets ligados al caso (vía ticket_case_links) con sus solicitudes
// accionables, para mostrar "Acciones al cliente" dentro del caso.
export async function getTicketsByCase(caseId) {
  const tickets = await pgQuery(
    `SELECT t.*, l.link_type
       FROM ticket_case_links l
       JOIN tickets t ON t.id = l.ticket_id
      WHERE l.case_id = $1
      ORDER BY (l.link_type = 'PRIMARY') DESC, t.updated_at DESC`,
    [caseId],
  );
  for (const t of tickets) {
    t.actionRequests = await pgQuery(
      `SELECT * FROM ticket_action_requests WHERE ticket_id = $1 ORDER BY created_at DESC`,
      [t.id],
    );
  }
  return tickets;
}

/**
 * Tickets vinculados a un caso que TODAVÍA no están cerrados (status <> 'CERRADO').
 * Devuelve sólo los campos necesarios para bloquear/explicar el cierre del caso.
 * Si el caso no tiene tickets, o todos están CERRADO, devuelve [].
 */
export async function getOpenTicketsForCase(caseId) {
  if (!caseId) return [];
  return pgQuery(
    `SELECT t.id, t.public_ref, t.subject, t.status, t.waiting_on, l.link_type
       FROM ticket_case_links l
       JOIN tickets t ON t.id = l.ticket_id
      WHERE l.case_id = $1
        AND t.status <> 'CERRADO'
      ORDER BY (l.link_type = 'PRIMARY') DESC, t.updated_at DESC`,
    [caseId],
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bloque de clasificación / orden / workflow (20 mejoras). Ver migración 111.
// ═══════════════════════════════════════════════════════════════════════════════

const TICKET_TYPES = new Set(["INCIDENTE", "CONSULTA", "CAMBIO", "REPORTE_FP", "ACEPTACION_RIESGO"]);
const TECH_SEVERITIES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const PRIORITIES = new Set(["LOW", "MEDIUM", "HIGH", "URGENT"]);
const SENTIMENTS = new Set(["POSITIVO", "NEUTRAL", "FRUSTRADO", "ENOJADO"]);

// ── (#1/#4/#5) Clasificación: tipo, severidad técnica, servicio, prioridad ─────
export async function setClassification(ticketId, {
  ticketType, technicalSeverity, serviceId, serviceSlug, priority, sentiment,
} = {}) {
  const sets = ["updated_at = now()"];
  const params = [];
  const push = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };

  if (ticketType !== undefined) {
    if (ticketType !== null && !TICKET_TYPES.has(ticketType)) throw new Error(`ticket_type inválido: ${ticketType}`);
    push("ticket_type", ticketType);
  }
  if (technicalSeverity !== undefined) {
    if (technicalSeverity !== null && !TECH_SEVERITIES.has(technicalSeverity)) throw new Error("technical_severity inválido");
    push("technical_severity", technicalSeverity);
  }
  if (priority !== undefined) {
    if (!PRIORITIES.has(priority)) throw new Error("priority inválida");
    push("priority", priority);
  }
  if (sentiment !== undefined) {
    if (sentiment !== null && !SENTIMENTS.has(sentiment)) throw new Error("sentiment inválido");
    push("sentiment", sentiment);
  }
  if (serviceId !== undefined) {
    push("service_id", serviceId);
  } else if (serviceSlug !== undefined) {
    const svc = serviceSlug ? await resolveServiceId({ serviceSlug }) : null;
    push("service_id", svc);
  }
  if (params.length === 0) throw new Error("nada para actualizar");
  params.push(ticketId);
  const rows = await pgQuery(`UPDATE tickets SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`, params);
  if (!rows[0]) throw new Error("ticket no encontrado");
  return rows[0];
}

// ── (#2) Etiquetas ─────────────────────────────────────────────────────────────
function normTags(tags) {
  if (!Array.isArray(tags)) return [];
  return [...new Set(tags.map((t) => String(t).toLowerCase().trim()).filter(Boolean))].slice(0, 12);
}
export async function setTags(ticketId, tags) {
  const rows = await pgQuery(
    `UPDATE tickets SET tags = $1, updated_at = now() WHERE id = $2 RETURNING id, tags`,
    [normTags(tags), ticketId],
  );
  if (!rows[0]) throw new Error("ticket no encontrado");
  return rows[0];
}
// Nube de tags (#2): conteo global de etiquetas en tickets no cerrados.
export async function getTagCloud({ limit = 50 } = {}) {
  return pgQuery(
    `SELECT tag, count(*)::int AS n
       FROM tickets t, unnest(t.tags) AS tag
      WHERE t.merged_into IS NULL
      GROUP BY tag ORDER BY n DESC, tag ASC LIMIT $1`,
    [Math.min(Number(limit) || 50, 200)],
  );
}

// ── (#5) Catálogo de servicios ─────────────────────────────────────────────────
export async function listServices({ activeOnly = false } = {}) {
  return pgQuery(
    `SELECT s.*, (SELECT count(*) FROM tickets t WHERE t.service_id = s.id AND t.merged_into IS NULL AND t.status <> 'CERRADO')::int AS open_tickets
       FROM ticket_services s ${activeOnly ? "WHERE s.active = true" : ""}
      ORDER BY s.active DESC, s.name ASC`,
  );
}
export async function createService({ name, slug, description = null, color = null }) {
  if (!name || !slug) throw new Error("name y slug son obligatorios");
  const rows = await pgQuery(
    `INSERT INTO ticket_services (name, slug, description, color) VALUES ($1,$2,$3,$4) RETURNING *`,
    [String(name).trim(), String(slug).toLowerCase().trim(), description, color],
  );
  return rows[0];
}
export async function updateService(id, { name, description, color, active }) {
  const sets = [];
  const params = [];
  const push = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };
  if (name !== undefined) push("name", name);
  if (description !== undefined) push("description", description);
  if (color !== undefined) push("color", color);
  if (active !== undefined) push("active", active);
  if (!sets.length) throw new Error("nada para actualizar");
  params.push(id);
  const rows = await pgQuery(`UPDATE ticket_services SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`, params);
  if (!rows[0]) throw new Error("servicio no encontrado");
  return rows[0];
}
export async function deleteService(id) {
  await pgQuery(`UPDATE tickets SET service_id = NULL WHERE service_id = $1`, [id]);
  await pgQuery(`DELETE FROM ticket_services WHERE id = $1`, [id]);
  return { ok: true };
}

// ── (#14) Fijar / desfijar ─────────────────────────────────────────────────────
export async function pinTicket(ticketId, pinned) {
  const rows = await pgQuery(
    `UPDATE tickets SET pinned = $1, updated_at = now() WHERE id = $2 RETURNING id, pinned`,
    [Boolean(pinned), ticketId],
  );
  if (!rows[0]) throw new Error("ticket no encontrado");
  return rows[0];
}

// ── (#18) Posponer (snooze) ────────────────────────────────────────────────────
export async function snoozeTicket(ticketId, until) {
  const ts = until ? new Date(until) : null;
  if (until && Number.isNaN(ts?.getTime())) throw new Error("fecha de snooze inválida");
  const rows = await pgQuery(
    `UPDATE tickets SET snoozed_until = $1, updated_at = now() WHERE id = $2 RETURNING id, snoozed_until`,
    [ts ? ts.toISOString() : null, ticketId],
  );
  if (!rows[0]) throw new Error("ticket no encontrado");
  return rows[0];
}

// ── (#6) Detección de duplicados + merge ───────────────────────────────────────
// Candidatos: misma org, no cerrados, mismo caso primario O asunto similar (trigram
// si pg_trgm está disponible; si no, coincidencia por prefijo de palabras).
export async function findDuplicateCandidates(ticketId) {
  const [t] = await pgQuery(`SELECT id, org_id, subject FROM tickets WHERE id = $1 LIMIT 1`, [ticketId]);
  if (!t) return [];
  const primaryCase = await getPrimaryCaseId(ticketId);
  return pgQuery(
    `SELECT DISTINCT t.id, t.public_ref, t.subject, t.status, t.priority, t.created_at,
            (SELECT case_id FROM ticket_case_links l WHERE l.ticket_id = t.id AND l.link_type = 'PRIMARY' LIMIT 1) AS primary_case_id,
            similarity(lower(t.subject), lower($2)) AS sim
       FROM tickets t
       LEFT JOIN ticket_case_links l2 ON l2.ticket_id = t.id AND l2.link_type = 'PRIMARY'
      WHERE t.id <> $1
        AND t.org_id IS NOT DISTINCT FROM $3
        AND t.merged_into IS NULL
        AND t.status <> 'CERRADO'
        AND ( ($4::text IS NOT NULL AND l2.case_id = $4)
              OR similarity(lower(t.subject), lower($2)) > 0.35 )
      ORDER BY sim DESC NULLS LAST, t.created_at DESC
      LIMIT 10`,
    [ticketId, t.subject, t.org_id, primaryCase],
  ).catch(async () => {
    // Sin pg_trgm: degradar a coincidencia por primer término del asunto.
    const token = String(t.subject || "").trim().split(/\s+/).slice(0, 2).join(" ");
    return pgQuery(
      `SELECT t.id, t.public_ref, t.subject, t.status, t.priority, t.created_at, NULL::float AS sim
         FROM tickets t
        WHERE t.id <> $1 AND t.org_id IS NOT DISTINCT FROM $2
          AND t.merged_into IS NULL AND t.status <> 'CERRADO'
          AND t.subject ILIKE '%' || $3 || '%'
        ORDER BY t.created_at DESC LIMIT 10`,
      [ticketId, t.org_id, token],
    ).catch(() => []);
  });
}

// Fusiona `sourceId` dentro de `targetId`: mueve los mensajes y vínculos de caso
// al canónico, marca el origen merged_into + lo cierra. Idempotente y defensivo.
export async function mergeTickets(sourceId, targetId, operatorCi = "system") {
  if (!sourceId || !targetId || sourceId === targetId) throw new Error("origen y destino inválidos");
  const [src] = await pgQuery(`SELECT * FROM tickets WHERE id = $1 LIMIT 1`, [sourceId]);
  const [dst] = await pgQuery(`SELECT * FROM tickets WHERE id = $1 LIMIT 1`, [targetId]);
  if (!src || !dst) throw new Error("ticket origen o destino no encontrado");
  if (src.merged_into) throw new Error("el ticket origen ya fue fusionado");

  await withPgClient(async (client) => {
    // Mover mensajes (preservando metadatos) al ticket canónico.
    await client.query(`UPDATE ticket_messages SET ticket_id = $1 WHERE ticket_id = $2`, [targetId, sourceId]);
    // Mover vínculos de caso como RELATED (sin pisar el PRIMARY del destino).
    await client.query(
      `INSERT INTO ticket_case_links (ticket_id, case_id, link_type, linked_by)
       SELECT $1, case_id, 'RELATED', $3 FROM ticket_case_links WHERE ticket_id = $2
       ON CONFLICT (ticket_id, case_id) DO NOTHING`,
      [targetId, sourceId, operatorCi],
    );
    await client.query(`DELETE FROM ticket_case_links WHERE ticket_id = $1`, [sourceId]);
    // Mover watchers.
    await client.query(
      `INSERT INTO ticket_watchers (ticket_id, operator_ci, added_by)
       SELECT $1, operator_ci, added_by FROM ticket_watchers WHERE ticket_id = $2
       ON CONFLICT (ticket_id, operator_ci) DO NOTHING`,
      [targetId, sourceId],
    );
    // Marcar y cerrar el origen.
    await client.query(
      `UPDATE tickets SET merged_into = $1, status = 'CERRADO', closed_at = now(),
              waiting_on = 'NONE', updated_at = now() WHERE id = $2`,
      [targetId, sourceId],
    );
    await client.query(`UPDATE tickets SET updated_at = now() WHERE id = $1`, [targetId]);
  });

  // Nota interna en el canónico (auditoría del merge).
  await pgQuery(
    `INSERT INTO ticket_messages (id, ticket_id, author_type, author_ref, visibility, body)
     VALUES ($1,$2,'SYSTEM',$3,'INTERNAL',$4)`,
    [randomUUID(), targetId, operatorCi,
     `Se fusionó el ticket ${src.public_ref} en este (duplicado).`],
  );
  return { ok: true, mergedInto: targetId, sourceRef: src.public_ref };
}

// ── (#20) Watchers internos ────────────────────────────────────────────────────
export async function addWatcher(ticketId, operatorCi, addedBy = "system") {
  if (!operatorCi) throw new Error("operatorCi obligatorio");
  await pgQuery(
    `INSERT INTO ticket_watchers (ticket_id, operator_ci, added_by)
     VALUES ($1,$2,$3) ON CONFLICT (ticket_id, operator_ci) DO NOTHING`,
    [ticketId, operatorCi, addedBy],
  );
  return { ok: true };
}
export async function removeWatcher(ticketId, operatorCi) {
  await pgQuery(`DELETE FROM ticket_watchers WHERE ticket_id = $1 AND operator_ci = $2`, [ticketId, operatorCi]);
  return { ok: true };
}

// ── (#20) CC del cliente ───────────────────────────────────────────────────────
export async function setCcContacts(ticketId, ccContacts) {
  const cc = Array.isArray(ccContacts) ? ccContacts.filter(Boolean) : [];
  const rows = await pgQuery(
    `UPDATE tickets SET cc_contacts = $1, updated_at = now() WHERE id = $2 RETURNING id, cc_contacts`,
    [JSON.stringify(cc), ticketId],
  );
  if (!rows[0]) throw new Error("ticket no encontrado");
  return rows[0];
}

// ── (#10) Vistas guardadas ─────────────────────────────────────────────────────
export async function listSavedViews(operatorCi) {
  return pgQuery(
    `SELECT * FROM ticket_saved_views
      WHERE operator_ci = $1 OR is_shared = true
      ORDER BY is_shared ASC, name ASC`,
    [operatorCi],
  );
}
export async function createSavedView({ operatorCi, name, filters = {}, sort = [], isShared = false }) {
  if (!name) throw new Error("name obligatorio");
  const rows = await pgQuery(
    `INSERT INTO ticket_saved_views (operator_ci, name, filters, sort, is_shared)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [operatorCi, String(name).trim(), JSON.stringify(filters), JSON.stringify(sort), Boolean(isShared)],
  );
  return rows[0];
}
export async function deleteSavedView(id, operatorCi) {
  await pgQuery(`DELETE FROM ticket_saved_views WHERE id = $1 AND operator_ci = $2`, [id, operatorCi]);
  return { ok: true };
}

// ── (#12/#16) Preferencias por usuario (orden multi-columna + layout) ──────────
export async function getUserPrefs(operatorCi) {
  const rows = await pgQuery(`SELECT * FROM ticket_user_prefs WHERE operator_ci = $1 LIMIT 1`, [operatorCi]);
  return rows[0] ?? { operator_ci: operatorCi, sort: [], default_view: null, layout: "table" };
}
export async function setUserPrefs(operatorCi, { sort, defaultView, layout }) {
  const rows = await pgQuery(
    `INSERT INTO ticket_user_prefs (operator_ci, sort, default_view, layout)
     VALUES ($1, COALESCE($2,'[]'::jsonb), $3, COALESCE($4,'table'))
     ON CONFLICT (operator_ci) DO UPDATE SET
       sort = COALESCE(EXCLUDED.sort, ticket_user_prefs.sort),
       default_view = COALESCE(EXCLUDED.default_view, ticket_user_prefs.default_view),
       layout = COALESCE(EXCLUDED.layout, ticket_user_prefs.layout),
       updated_at = now()
     RETURNING *`,
    [operatorCi, sort !== undefined ? JSON.stringify(sort) : null,
     defaultView ?? null, layout ?? null],
  );
  return rows[0];
}

// ── (#17) Acciones masivas ─────────────────────────────────────────────────────
export async function bulkUpdate(ids, { assignedOperator, priority, addTag, status, operatorCi = "system" } = {}) {
  const list = (Array.isArray(ids) ? ids : []).filter(Boolean);
  if (!list.length) throw new Error("sin tickets seleccionados");

  let affected = 0;
  // Cambio de estado: pasa por la máquina de estados (respeta transiciones).
  if (status) {
    for (const id of list) {
      try { await transitionStatus(id, { toStatus: status, operatorCi, note: "Acción masiva" }); affected++; }
      catch { /* transición inválida para ese ticket: se omite */ }
    }
  }
  if (assignedOperator) {
    const r = await pgQuery(
      `UPDATE tickets SET assigned_operator = $1, updated_at = now() WHERE id = ANY($2) RETURNING id`,
      [assignedOperator, list],
    );
    affected = Math.max(affected, r.length);
  }
  if (priority) {
    if (!PRIORITIES.has(priority)) throw new Error("priority inválida");
    const r = await pgQuery(
      `UPDATE tickets SET priority = $1, updated_at = now() WHERE id = ANY($2) RETURNING id`,
      [priority, list],
    );
    affected = Math.max(affected, r.length);
  }
  if (addTag) {
    const r = await pgQuery(
      `UPDATE tickets SET tags = (SELECT array_agg(DISTINCT x) FROM unnest(tags || $1::text[]) x),
              updated_at = now() WHERE id = ANY($2) RETURNING id`,
      [[String(addTag).toLowerCase().trim()], list],
    );
    affected = Math.max(affected, r.length);
  }
  return { ok: true, affected, total: list.length };
}

// ── (#3/#7) Clasificación por IA (sugerencia con gate humano) ──────────────────
// Corre el clasificador sobre el asunto + primer mensaje del cliente, guarda la
// SUGERENCIA en ai_suggested y el sentimiento detectado. NO cambia tipo/prioridad.
export async function classifyTicket(ticketId) {
  const [t] = await pgQuery(`SELECT id, subject FROM tickets WHERE id = $1 LIMIT 1`, [ticketId]);
  if (!t) throw new Error("ticket no encontrado");
  const [firstMsg] = await pgQuery(
    `SELECT body FROM ticket_messages
      WHERE ticket_id = $1 AND author_type = 'CLIENT' AND visibility = 'PUBLIC'
      ORDER BY created_at ASC LIMIT 1`,
    [ticketId],
  );
  const suggestion = await classifyTicketText({ subject: t.subject, body: firstMsg?.body ?? "" });
  await pgQuery(
    `UPDATE tickets SET ai_suggested = $1, sentiment = COALESCE($2, sentiment), updated_at = now() WHERE id = $3`,
    [JSON.stringify(suggestion), suggestion.sentiment ?? null, ticketId],
  );
  return suggestion;
}

// Aplica una sugerencia de IA al ticket (gate humano: lo llama la ruta cuando el
// analista la acepta). Resuelve service_slug → service_id.
export async function applyAiSuggestion(ticketId, fields = {}) {
  const patch = {};
  if (fields.type) patch.ticketType = fields.type;
  if (fields.priority) patch.priority = fields.priority;
  if (fields.sentiment) patch.sentiment = fields.sentiment;
  if (fields.service_slug) patch.serviceSlug = fields.service_slug;
  const ticket = Object.keys(patch).length ? await setClassification(ticketId, patch) : null;
  if (Array.isArray(fields.tags) && fields.tags.length) {
    await pgQuery(
      `UPDATE tickets SET tags = (SELECT array_agg(DISTINCT x) FROM unnest(tags || $1::text[]) x),
              updated_at = now() WHERE id = $2`,
      [normTags(fields.tags), ticketId],
    );
  }
  return ticket ?? (await pgQuery(`SELECT * FROM tickets WHERE id = $1`, [ticketId]))[0];
}
