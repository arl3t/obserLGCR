/**
 * ticketAutomation.mjs — F6: automatización del Sistema de Tickets.
 *
 * Lo ejecuta el scheduler (setInterval bajo advisory-lock):
 *   · Recordatorios: si waiting_on='CLIENT' supera el umbral sin respuesta, se
 *     re-avisa por email a los contactos del cliente (sin spamear: last_reminder_at).
 *   · Auto-cierre: tickets RESUELTO sin actividad N días → CERRADO.
 *
 * Config en ticket_automation_config (mig 105). Ver docs/PROPUESTA-TICKETING-PUBLICO.md.
 */
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { sendMail } from "./mailTransport.mjs";
import { portalBaseUrl } from "./portalAuth.mjs";
import { transitionStatus } from "./ticketService.mjs";

const DEFAULTS = {
  reminders_enabled: true, reminder_after_hours: 48, reminder_repeat_every_hours: 48,
  autoclose_enabled: true, autoclose_resolved_after_days: 5,
};

export async function getAutomationConfig() {
  try {
    const rows = await pgQuery(`SELECT * FROM ticket_automation_config WHERE id = 1 LIMIT 1`);
    return rows[0] ? { ...DEFAULTS, ...rows[0] } : { ...DEFAULTS };
  } catch {
    return { ...DEFAULTS };
  }
}

function contactEmails(contacts) {
  if (!Array.isArray(contacts)) return [];
  return contacts
    .map((c) => (typeof c === "string" ? c : c?.email))
    .filter((e) => typeof e === "string" && e.includes("@"));
}

// ── Recordatorios al cliente ──────────────────────────────────────────────────
export async function runTicketReminders(cfg) {
  if (!cfg.reminders_enabled) return { sent: 0, skipped: "disabled" };
  const rows = await pgQuery(
    `SELECT t.id, t.public_ref, t.subject, o.name AS org_name, o.contacts
       FROM tickets t
       JOIN organizations o ON o.id = t.org_id
      WHERE t.waiting_on = 'CLIENT'
        AND o.status = 'ACTIVE'
        AND t.status NOT IN ('CERRADO', 'RESUELTO')
        AND t.updated_at < now() - ($1 || ' hours')::interval
        AND (t.last_reminder_at IS NULL
             OR t.last_reminder_at < now() - ($2 || ' hours')::interval)
      ORDER BY t.updated_at ASC
      LIMIT 200`,
    [cfg.reminder_after_hours, cfg.reminder_repeat_every_hours],
  );

  let sent = 0;
  for (const t of rows) {
    const emails = contactEmails(t.contacts);
    if (emails.length === 0) continue;
    const subject = `Recordatorio: el ticket ${t.public_ref} espera tu respuesta`;
    const text = `Hola,\n\nTu ticket "${t.subject}" (${t.public_ref}) de ${t.org_name} sigue esperando tu respuesta.\n\nIngresá al portal con tu email para responder:\n${portalBaseUrl()}\n\nSi ya no es necesario, podés ignorar este mensaje.`;
    const mail = await sendMail({ to: emails.join(", "), subject, text });
    // Marcar SIEMPRE last_reminder_at (aunque el envío falle) para no reintentar
    // en cada tick; el próximo intento será tras reminder_repeat_every_hours.
    await pgQuery(`UPDATE tickets SET last_reminder_at = now() WHERE id = $1`, [t.id]);
    if (mail.ok) sent++;
    else logger.warn?.("[ticketAutomation] recordatorio no enviado", { ref: t.public_ref, err: mail.error });
  }
  return { sent, candidates: rows.length };
}

// ── Auto-cierre de tickets resueltos sin actividad ───────────────────────────
export async function runAutoClose(cfg) {
  if (!cfg.autoclose_enabled) return { closed: 0, skipped: "disabled" };
  const rows = await pgQuery(
    `SELECT id, public_ref FROM tickets
      WHERE status = 'RESUELTO' AND resolved_at IS NOT NULL
        AND resolved_at < now() - ($1 || ' days')::interval
      ORDER BY resolved_at ASC
      LIMIT 200`,
    [cfg.autoclose_resolved_after_days],
  );
  let closed = 0;
  for (const t of rows) {
    try {
      await transitionStatus(t.id, {
        toStatus: "CERRADO", operatorCi: "system-auto",
        note: `Auto-cierre: resuelto sin actividad por ${cfg.autoclose_resolved_after_days} días`,
      });
      closed++;
    } catch (err) {
      logger.warn?.("[ticketAutomation] auto-cierre falló", { ref: t.public_ref, err: err.message });
    }
  }
  return { closed, candidates: rows.length };
}

// ── (#18) Despertar tickets pospuestos cuyo snooze ya venció ─────────────────
// Limpia snoozed_until; el ticket reaparece en la cola activa. Marca actividad
// (updated_at) para que el orden por SLA lo reposicione.
export async function runSnoozeWake() {
  const rows = await pgQuery(
    `UPDATE tickets SET snoozed_until = NULL, updated_at = now()
      WHERE snoozed_until IS NOT NULL AND snoozed_until <= now()
        AND status NOT IN ('CERRADO')
      RETURNING id, public_ref`,
  ).catch(() => []);
  return { woken: rows.length };
}

// ── Orquestador (lo llama el scheduler) ──────────────────────────────────────
export async function runTicketMaintenance() {
  const cfg = await getAutomationConfig();
  const reminders = await runTicketReminders(cfg);
  const autoclose = await runAutoClose(cfg);
  const snooze = await runSnoozeWake();
  if (reminders.sent || autoclose.closed || snooze.woken) {
    logger.info({ reminders, autoclose, snooze }, "[ticketAutomation] mantenimiento de tickets");
  }
  return { reminders, autoclose, snooze };
}
