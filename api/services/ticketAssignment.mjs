/**
 * ticketAssignment.mjs — auto-asignación de tickets con BALANCEO POR TIERS.
 *
 * Reparte los tickets entrantes entre operadores según prioridad → tier elegible
 * (L1/L2/L3/LEADER) y carga actual (menos cargado primero), y notifica al operador
 * asignado (campana + socket). Espejo del balanceo de casos (workflowEngine).
 *
 * Prioridad → tiers preferidos (en orden; si ninguno disponible, cae al siguiente):
 *   URGENT → L3, LEADER, ADMIN     HIGH → L2, L3, L1L2
 *   MEDIUM → L1L2, L2, L1          LOW  → L1, L1L2
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §5 (cola del operador).
 */
import { randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { getIo } from "./socketService.mjs";

// Tiers preferidos por prioridad (de más a menos prioritario).
const TIER_BY_PRIORITY = {
  URGENT: ["L3", "LEADER", "ADMIN"],
  HIGH:   ["L2", "L3", "L1L2"],
  MEDIUM: ["L1L2", "L2", "L1"],
  LOW:    ["L1", "L1L2"],
};
// (#1) Auto-ruteo de cola por TIPO de ticket: prioridad de tiers según el tipo,
// independiente de la prioridad percibida. Las consultas / reportes FP no necesitan
// un L3; los incidentes y cambios entran por tiers altos.
const TIER_BY_TYPE = {
  INCIDENTE:          ["L2", "L3", "L1L2"],
  CAMBIO:             ["L2", "L1L2", "L3"],
  ACEPTACION_RIESGO:  ["L3", "LEADER", "L2"],
  REPORTE_FP:         ["L1", "L1L2", "L2"],
  CONSULTA:           ["L1", "L1L2", "L2"],
};
// Conjunto de respaldo: cualquier operador activo asignable.
const FALLBACK_ROLES = ["L1", "L1L2", "L2", "L3", "LEADER"];
const NOTIF_PRIORITY = { URGENT: "CRITICAL", HIGH: "HIGH", MEDIUM: "NORMAL", LOW: "LOW" };

// Carga viva por operador = tickets asignados NO terminales.
async function loadByOperator(roleIds) {
  const rows = await pgQuery(
    `SELECT o.id, o.role_id,
            (SELECT count(*) FROM tickets t
              WHERE t.assigned_operator = o.id AND t.status <> 'CERRADO')::int AS load
       FROM soc_operators o
      WHERE o.is_active = true AND o.role_id = ANY($1)`,
    [roleIds],
  );
  return rows;
}

// Elige el operador menos cargado siguiendo el orden de tiers preferidos.
// El tipo manda el ruteo de cola (#1); a igualdad, desempata por prioridad.
async function pickAssignee(priority, ticketType = null) {
  const byType = ticketType ? TIER_BY_TYPE[ticketType] : null;
  const byPrio = TIER_BY_PRIORITY[priority] ?? TIER_BY_PRIORITY.MEDIUM;
  // Combina: primero los tiers del tipo, luego los de la prioridad (sin duplicar).
  const tiers = byType ? [...new Set([...byType, ...byPrio])] : byPrio;
  // 1) recorre los tiers preferidos en orden
  for (const role of tiers) {
    const cand = await loadByOperator([role]);
    if (cand.length) return cand.sort((a, b) => a.load - b.load)[0];
  }
  // 2) respaldo: cualquier operador activo asignable, el menos cargado
  const any = await loadByOperator(FALLBACK_ROLES);
  if (any.length) return any.sort((a, b) => a.load - b.load)[0];
  // 3) último recurso: shift manager / leader activo
  const sm = await pgQuery(
    `SELECT id, role_id FROM soc_operators
      WHERE is_active = true AND (is_shift_manager = true OR role_id IN ('LEADER','ADMIN'))
      ORDER BY is_shift_manager DESC LIMIT 1`,
  );
  return sm[0] ?? null;
}

// ¿`ci` es un operador activo? (para respetar una asignación explícita).
export async function isActiveOperator(ci) {
  if (!ci) return false;
  const r = await pgQuery(`SELECT 1 FROM soc_operators WHERE id = $1 AND is_active = true LIMIT 1`, [ci]);
  return r.length > 0;
}

async function notifyAssignee(operatorId, ticket) {
  try {
    const id = randomUUID();
    const prio = NOTIF_PRIORITY[ticket.priority] ?? "NORMAL";
    const title = `[TICKET] ${ticket.public_ref} — ${ticket.priority}`;
    const body = (ticket.subject || "Nuevo ticket asignado").slice(0, 200);
    await pgQuery(
      `INSERT INTO soc_notifications (id, operator_id, case_id, type, priority, title, body, action_url)
       VALUES ($1,$2,NULL,'TICKET_ASSIGN',$3,$4,$5,'/tickets')`,
      [id, operatorId, prio, title, body],
    );
    getIo()?.to(`operator:${operatorId}`).emit("notification:new", {
      id, type: "TICKET_ASSIGN", priority: prio, title, body, ticketId: ticket.id,
    });
  } catch (err) {
    logger.warn({ err: err.message, operatorId }, "[ticketAssign] notificación falló (no-fatal)");
  }
}

// Emite la actividad global de tickets (campana de tickets en la barra superior).
export function emitTicketActivity(kind, ticket, assignedOperator = null) {
  try {
    getIo()?.emit(`ticket:${kind}`, {
      ticketId: ticket.id, ref: ticket.public_ref, subject: ticket.subject,
      priority: ticket.priority, channel: ticket.channel,
      orgName: ticket.org_name ?? null, assignedOperator,
      at: new Date().toISOString(),
    });
  } catch { /* opcional */ }
}

// Auto-asigna un ticket (objeto fila `tickets`) y notifica. Devuelve el CI asignado
// o null. Nunca lanza: un fallo de asignación no debe romper la creación del ticket.
export async function autoAssignTicket(ticket) {
  try {
    const assignee = await pickAssignee(ticket.priority, ticket.ticket_type);
    if (!assignee) {
      logger.warn({ ref: ticket.public_ref }, "[ticketAssign] sin operadores activos — ticket sin asignar");
      emitTicketActivity("new", ticket, null);
      return null;
    }
    await pgQuery(`UPDATE tickets SET assigned_operator = $1, updated_at = now() WHERE id = $2`, [assignee.id, ticket.id]);
    await notifyAssignee(assignee.id, ticket);
    emitTicketActivity("assigned", ticket, assignee.id);
    logger.info({ ref: ticket.public_ref, operator: assignee.id, tier: assignee.role_id, priority: ticket.priority },
      "[ticketAssign] auto-asignado");
    return assignee.id;
  } catch (err) {
    logger.warn({ err: err.message, ref: ticket.public_ref }, "[ticketAssign] auto-asignación falló (no-fatal)");
    return null;
  }
}
