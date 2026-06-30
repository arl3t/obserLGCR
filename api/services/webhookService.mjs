/**
 * webhookService.mjs — F7: WEBHOOKS SALIENTES del Sistema de Tickets.
 *
 * Notifica al sistema del cliente (su ITSM/Jira/ServiceNow) los eventos del
 * ciclo de vida del ticket. Cada entrega se firma con HMAC-SHA256 sobre el cuerpo
 * (cabecera `X-LegacyHunt-Signature: sha256=...`) usando el secreto del endpoint
 * (cifrado en reposo, services/secretCrypto.mjs). Las entregas se encolan en
 * webhook_deliveries y el scheduler reintenta las fallidas con backoff exponencial.
 *
 * Eventos: ticket.created · ticket.message · ticket.status_changed · action_request.decided
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#17), §11 (F7).
 */
import crypto from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { encryptSecret, decryptSecret, encryptionAvailable } from "./secretCrypto.mjs";

const EVENT_TYPES = [
  "ticket.created", "ticket.message", "ticket.status_changed", "action_request.decided",
];
const DELIVERY_TIMEOUT_MS = 8000;
const BACKOFF_BASE_SEC = 30;   // 30s, 60s, 120s, 240s, 480s, 960s …

export function isValidEvent(e) { return e === "*" || EVENT_TYPES.includes(e); }
export function knownEvents() { return [...EVENT_TYPES]; }

function genSecret() { return "whsec_" + crypto.randomBytes(24).toString("base64url"); }
function sign(secret, body) {
  return "sha256=" + crypto.createHmac("sha256", secret).update(body, "utf8").digest("hex");
}

// ── CRUD de endpoints ─────────────────────────────────────────────────────────

export async function listEndpoints(orgId = null) {
  const rows = await pgQuery(
    `SELECT e.id, e.org_id, o.slug AS org_slug, o.name AS org_name, e.url, e.events,
            e.description, e.enabled, e.failure_count, e.last_delivery_at, e.created_at, e.updated_at
       FROM webhook_endpoints e
       JOIN organizations o ON o.id = e.org_id
      ${orgId ? "WHERE e.org_id = $1" : ""}
      ORDER BY e.created_at DESC`,
    orgId ? [orgId] : [],
  );
  return rows;
}

// Devuelve { endpoint, secret } — el secreto en claro se muestra UNA sola vez.
export async function createEndpoint({ orgId, url, events = ["*"], description = null, createdBy = "system" }) {
  if (!encryptionAvailable()) throw new Error("SETTINGS_ENC_KEY no configurada — no se pueden guardar secretos de webhook");
  if (!orgId) throw new Error("orgId obligatorio");
  if (!/^https?:\/\/.+/i.test(String(url ?? ""))) throw new Error("url inválida (debe ser http(s)://…)");
  const evs = Array.isArray(events) && events.length ? events : ["*"];
  for (const e of evs) if (!isValidEvent(e)) throw new Error(`evento inválido: ${e}`);
  const secret = genSecret();
  const rows = await pgQuery(
    `INSERT INTO webhook_endpoints (org_id, url, secret_enc, events, description, created_by)
     VALUES ($1,$2,$3,$4::jsonb,$5,$6) RETURNING id`,
    [orgId, url, encryptSecret(secret), JSON.stringify(evs), description, createdBy],
  );
  return { id: rows[0].id, secret };
}

export async function updateEndpoint(id, { url, events, description, enabled }) {
  const sets = [], vals = [];
  if (url !== undefined) {
    if (!/^https?:\/\/.+/i.test(String(url))) throw new Error("url inválida");
    vals.push(url); sets.push(`url = $${vals.length}`);
  }
  if (events !== undefined) {
    const evs = Array.isArray(events) && events.length ? events : ["*"];
    for (const e of evs) if (!isValidEvent(e)) throw new Error(`evento inválido: ${e}`);
    vals.push(JSON.stringify(evs)); sets.push(`events = $${vals.length}::jsonb`);
  }
  if (description !== undefined) { vals.push(description); sets.push(`description = $${vals.length}`); }
  if (enabled !== undefined) { vals.push(!!enabled); sets.push(`enabled = $${vals.length}`); }
  if (!sets.length) return;
  vals.push(id);
  await pgQuery(`UPDATE webhook_endpoints SET ${sets.join(", ")}, updated_at = now() WHERE id = $${vals.length}`, vals);
}

// Rota el secreto y lo devuelve una vez.
export async function rotateSecret(id) {
  if (!encryptionAvailable()) throw new Error("SETTINGS_ENC_KEY no configurada");
  const secret = genSecret();
  const rows = await pgQuery(
    `UPDATE webhook_endpoints SET secret_enc = $1, updated_at = now() WHERE id = $2 RETURNING id`,
    [encryptSecret(secret), id],
  );
  if (!rows.length) throw new Error("endpoint no encontrado");
  return { secret };
}

export async function deleteEndpoint(id) {
  await pgQuery(`DELETE FROM webhook_endpoints WHERE id = $1`, [id]);
}

export async function listDeliveries(endpointId, limit = 50) {
  return pgQuery(
    `SELECT id, event_type, status, attempts, response_code, error, created_at, delivered_at, next_retry_at
       FROM webhook_deliveries WHERE endpoint_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [endpointId, Math.min(limit, 200)],
  );
}

// ── Encolado de eventos (llamado fire-and-forget desde ticketService) ─────────

// Inserta una entrega PENDIENTE por cada endpoint activo de la org suscrito al
// evento, e intenta entregarlas inmediatamente (best-effort). Nunca lanza: un
// fallo de webhook jamás debe romper la operación del ticket.
export async function enqueueEvent(orgId, eventType, payload) {
  try {
    if (!orgId || !isValidEvent(eventType) || eventType === "*") return;
    const endpoints = await pgQuery(
      `SELECT id FROM webhook_endpoints
        WHERE org_id = $1 AND enabled
          AND (events @> '["*"]'::jsonb OR events @> $2::jsonb)`,
      [orgId, JSON.stringify([eventType])],
    );
    if (!endpoints.length) return;
    const body = { event: eventType, sentAt: new Date().toISOString(), data: payload };
    const ids = [];
    for (const ep of endpoints) {
      const r = await pgQuery(
        `INSERT INTO webhook_deliveries (endpoint_id, event_type, payload)
         VALUES ($1,$2,$3::jsonb) RETURNING id`,
        [ep.id, eventType, JSON.stringify(body)],
      );
      ids.push(r[0].id);
    }
    // Entrega inmediata best-effort (no await — no bloquea al llamador).
    for (const id of ids) attemptDelivery(id).catch(() => {});
  } catch (err) {
    logger.warn({ err: err.message, eventType }, "[webhook] enqueueEvent falló (no-fatal)");
  }
}

// ── Entrega individual (con firma HMAC + backoff) ─────────────────────────────

export async function attemptDelivery(deliveryId) {
  const rows = await pgQuery(
    `SELECT d.id, d.payload, d.attempts, d.max_attempts, e.url, e.secret_enc, e.id AS endpoint_id
       FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id
      WHERE d.id = $1 AND d.status = 'PENDING' LIMIT 1`,
    [deliveryId],
  );
  if (!rows.length) return;
  const d = rows[0];
  const body = typeof d.payload === "string" ? d.payload : JSON.stringify(d.payload);
  let secret;
  try { secret = decryptSecret(d.secret_enc); }
  catch (err) {
    await pgQuery(`UPDATE webhook_deliveries SET status='FAILED', error=$2 WHERE id=$1`,
      [d.id, `secreto ilegible: ${err.message}`]);
    return;
  }

  let code = null, errText = null, ok = false;
  try {
    const resp = await fetch(d.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-LegacyHunt-Event": JSON.parse(body).event ?? "",
        "X-LegacyHunt-Delivery": d.id,
        "X-LegacyHunt-Signature": sign(secret, body),
        "User-Agent": "LegacyHunt-Webhook/1.0",
      },
      body,
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
    });
    code = resp.status;
    ok = resp.status >= 200 && resp.status < 300;
    if (!ok) errText = `HTTP ${resp.status}`;
  } catch (err) {
    errText = err.name === "TimeoutError" ? "timeout" : err.message;
  }

  const attempts = d.attempts + 1;
  if (ok) {
    await pgQuery(
      `UPDATE webhook_deliveries SET status='DELIVERED', attempts=$2, response_code=$3, error=NULL, delivered_at=now() WHERE id=$1`,
      [d.id, attempts, code],
    );
    await pgQuery(`UPDATE webhook_endpoints SET failure_count=0, last_delivery_at=now() WHERE id=$1`, [d.endpoint_id]);
  } else if (attempts >= d.max_attempts) {
    await pgQuery(
      `UPDATE webhook_deliveries SET status='FAILED', attempts=$2, response_code=$3, error=$4 WHERE id=$1`,
      [d.id, attempts, code, errText],
    );
    await pgQuery(`UPDATE webhook_endpoints SET failure_count=failure_count+1 WHERE id=$1`, [d.endpoint_id]);
  } else {
    const backoffSec = BACKOFF_BASE_SEC * Math.pow(2, attempts - 1);
    await pgQuery(
      `UPDATE webhook_deliveries
          SET attempts=$2, response_code=$3, error=$4, next_retry_at = now() + ($5 || ' seconds')::interval
        WHERE id=$1`,
      [d.id, attempts, code, errText, String(backoffSec)],
    );
  }
  return { ok, code, attempts };
}

// ── Drenado del scheduler: reintenta entregas pendientes vencidas ─────────────

export async function drainDue(limit = 50) {
  const due = await pgQuery(
    `SELECT id FROM webhook_deliveries
      WHERE status='PENDING' AND next_retry_at <= now()
      ORDER BY next_retry_at ASC LIMIT $1`,
    [Math.min(limit, 200)],
  );
  let delivered = 0, failed = 0, retried = 0;
  for (const row of due) {
    const r = await attemptDelivery(row.id).catch(() => null);
    if (!r) continue;
    if (r.ok) delivered++;
    else if (r.attempts >= 1) retried++;
  }
  return { picked: due.length, delivered, failed, retried };
}
