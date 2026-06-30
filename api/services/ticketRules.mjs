/**
 * ticketRules.mjs — reglas de negocio configurables para tickets (#19).
 *
 * "si tipo=X y prioridad=URGENT → asignar a L3 + avisar al SM".
 * Reglas declarativas (tabla ticket_rules, mig 111) evaluadas al crear el ticket
 * (y bajo demanda). Cada regla:
 *   conditions: { type?, priority?, channel?, service_slug?, tag?, subject_contains? }
 *   actions:    { assign_tier?, assign_ci?, set_priority?, add_tag?, set_type?, notify_sm? }
 *
 * Best-effort: un fallo de regla NUNCA rompe la creación del ticket.
 */
import { randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { getActiveShiftManager } from "./workflowEngine.mjs";
import { getIo } from "./socketService.mjs";

async function loadRules() {
  try {
    return await pgQuery(
      `SELECT * FROM ticket_rules WHERE enabled = true ORDER BY ordering ASC, created_at ASC`,
    );
  } catch {
    return [];
  }
}

// ¿La fila `t` (ticket + service_slug resuelto) cumple todas las condiciones?
function matches(cond, t) {
  if (!cond || typeof cond !== "object") return false;
  if (cond.type && cond.type !== t.ticket_type) return false;
  if (cond.priority && cond.priority !== t.priority) return false;
  if (cond.channel && cond.channel !== t.channel) return false;
  if (cond.service_slug && cond.service_slug !== t.service_slug) return false;
  if (cond.tag && !(Array.isArray(t.tags) && t.tags.includes(cond.tag))) return false;
  if (cond.subject_contains) {
    const hay = `${t.subject ?? ""}`.toLowerCase();
    if (!hay.includes(String(cond.subject_contains).toLowerCase())) return false;
  }
  // Una regla con conditions vacío NO matchea (evita reglas accidentalmente globales).
  if (!cond.type && !cond.priority && !cond.channel && !cond.service_slug &&
      !cond.tag && !cond.subject_contains) return false;
  return true;
}

// Operador menos cargado de un tier (espejo de ticketAssignment).
async function pickByTier(tier) {
  const rows = await pgQuery(
    `SELECT o.id,
            (SELECT count(*) FROM tickets t WHERE t.assigned_operator = o.id AND t.status <> 'CERRADO')::int AS load
       FROM soc_operators o
      WHERE o.is_active = true AND o.role_id = $1
      ORDER BY load ASC LIMIT 1`,
    [tier],
  );
  return rows[0]?.id ?? null;
}

async function notifyShiftManager(ticket, ruleName) {
  try {
    const sm = await getActiveShiftManager?.();
    const smId = sm?.id ?? sm;
    if (!smId) return;
    const id = randomUUID();
    const title = `[REGLA] ${ticket.public_ref} — ${ruleName}`;
    const body = (ticket.subject || "Ticket marcado por regla de negocio").slice(0, 200);
    await pgQuery(
      `INSERT INTO soc_notifications (id, operator_id, case_id, type, priority, title, body, action_url)
       VALUES ($1,$2,NULL,'TICKET_RULE','HIGH',$3,$4,'/tickets')`,
      [id, smId, title, body],
    );
    getIo()?.to(`operator:${smId}`).emit("notification:new", {
      id, type: "TICKET_RULE", priority: "HIGH", title, body, ticketId: ticket.id,
    });
  } catch (err) {
    logger.warn?.({ err: err.message }, "[ticketRules] notify SM falló (no-fatal)");
  }
}

/**
 * Evalúa y aplica las reglas activas a un ticket recién creado.
 * Muta la fila en PG (assigned_operator / priority / tags / type) y devuelve la
 * lista de efectos aplicados (para auditoría/log). NUNCA lanza.
 * @param {object} ticket fila `tickets` (debe incluir id, public_ref, subject, etc.)
 */
export async function applyRulesOnCreate(ticket) {
  const applied = [];
  try {
    const rules = await loadRules();
    if (!rules.length) return applied;

    // Resolver service_slug del ticket (para condiciones por servicio).
    let serviceSlug = null;
    if (ticket.service_id) {
      const s = await pgQuery(`SELECT slug FROM ticket_services WHERE id = $1 LIMIT 1`, [ticket.service_id]);
      serviceSlug = s[0]?.slug ?? null;
    }
    const ctx = { ...ticket, service_slug: serviceSlug };

    for (const rule of rules) {
      if (!matches(rule.conditions, ctx)) continue;
      const a = rule.actions ?? {};

      if (a.set_type && a.set_type !== ctx.ticket_type) {
        await pgQuery(`UPDATE tickets SET ticket_type = $1, updated_at = now() WHERE id = $2`, [a.set_type, ticket.id]);
        ctx.ticket_type = ticket.ticket_type = a.set_type;
        applied.push(`set_type=${a.set_type}`);
      }
      if (a.set_priority && a.set_priority !== ctx.priority) {
        await pgQuery(`UPDATE tickets SET priority = $1, updated_at = now() WHERE id = $2`, [a.set_priority, ticket.id]);
        ctx.priority = ticket.priority = a.set_priority;
        applied.push(`set_priority=${a.set_priority}`);
      }
      if (a.add_tag) {
        await pgQuery(
          `UPDATE tickets SET tags = (SELECT array_agg(DISTINCT x) FROM unnest(tags || $1::text[]) x), updated_at = now()
            WHERE id = $2`,
          [[String(a.add_tag)], ticket.id],
        );
        applied.push(`add_tag=${a.add_tag}`);
      }
      let assignee = null;
      if (a.assign_ci) assignee = a.assign_ci;
      else if (a.assign_tier) assignee = await pickByTier(a.assign_tier);
      if (assignee) {
        await pgQuery(`UPDATE tickets SET assigned_operator = $1, updated_at = now() WHERE id = $2`, [assignee, ticket.id]);
        ticket.assigned_operator = assignee;
        applied.push(`assign=${assignee}`);
      }
      if (a.notify_sm) {
        await notifyShiftManager(ticket, rule.name);
        applied.push("notify_sm");
      }
    }
    if (applied.length) logger.info?.({ ref: ticket.public_ref, applied }, "[ticketRules] reglas aplicadas");
  } catch (err) {
    logger.warn?.({ err: err.message, id: ticket?.id }, "[ticketRules] evaluación falló (no-fatal)");
  }
  return applied;
}

// ── CRUD de reglas (para la UI de administración) ─────────────────────────────
export async function listRules() {
  return pgQuery(`SELECT * FROM ticket_rules ORDER BY ordering ASC, created_at ASC`);
}
export async function createRule({ name, conditions = {}, actions = {}, ordering = 100, enabled = true, createdBy = "system" }) {
  if (!name) throw new Error("name obligatorio");
  const rows = await pgQuery(
    `INSERT INTO ticket_rules (name, conditions, actions, ordering, enabled, created_by)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [String(name).trim(), JSON.stringify(conditions), JSON.stringify(actions), ordering, enabled, createdBy],
  );
  return rows[0];
}
export async function updateRule(id, { name, conditions, actions, ordering, enabled }) {
  const sets = ["updated_at = now()"];
  const params = [];
  const push = (sql, val) => { params.push(val); sets.push(`${sql} = $${params.length}`); };
  if (name !== undefined) push("name", name);
  if (conditions !== undefined) push("conditions", JSON.stringify(conditions));
  if (actions !== undefined) push("actions", JSON.stringify(actions));
  if (ordering !== undefined) push("ordering", ordering);
  if (enabled !== undefined) push("enabled", enabled);
  params.push(id);
  const rows = await pgQuery(`UPDATE ticket_rules SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`, params);
  if (!rows[0]) throw new Error("regla no encontrada");
  return rows[0];
}
export async function deleteRule(id) {
  await pgQuery(`DELETE FROM ticket_rules WHERE id = $1`, [id]);
  return { ok: true };
}
