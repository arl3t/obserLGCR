/**
 * webPushService — broadcast de notificaciones Web Push (RFC 8030).
 *
 * VAPID setup en env vars: VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT.
 * Si alguna falta, las funciones devuelven { ok: false } sin tirar; el cron
 * sigue funcionando con slack/email/webhook normales.
 *
 * Sub auto-cleanup: si push falla con 404/410 (subscription expirada),
 * eliminamos la fila — RFC dice que esos status indican subscription muerta.
 */

import webpush from "web-push";
import { logger } from "../logger.mjs";
import {
  listPushSubscriptions,
  deletePushSubscription,
  bumpPushSubscriptionUsed,
} from "../db/surveillanceNotifications.mjs";

let _vapidReady = false;

export function getVapidPublicKey() {
  return (process.env.VAPID_PUBLIC_KEY ?? "").trim() || null;
}

export function webPushReady() {
  return _vapidReady;
}

export function initWebPush() {
  const publicKey  = (process.env.VAPID_PUBLIC_KEY  ?? "").trim();
  const privateKey = (process.env.VAPID_PRIVATE_KEY ?? "").trim();
  const subject    = (process.env.VAPID_SUBJECT     ?? "mailto:soc@legacy-roots.net").trim();
  if (!publicKey || !privateKey) {
    logger.warn("[webPush] VAPID keys ausentes — push notifications deshabilitado");
    return;
  }
  try {
    webpush.setVapidDetails(subject, publicKey, privateKey);
    _vapidReady = true;
    logger.info("[webPush] VAPID configurado");
  } catch (err) {
    logger.warn("[webPush] setVapidDetails falló", { err: String(err?.message ?? err) });
  }
}

/**
 * Envía el payload a las subscriptions activas. Devuelve conteos
 * { sent, failed, removed } para que el cron loguee.
 *
 * @param {object} payload
 * @param {object} [opts]
 * @param {string[]|null} [opts.operatorCis] — si se pasa, SOLO notifica a las
 *   subscriptions de esos operadores (segmentación). Si es null/undefined →
 *   broadcast a todos (comportamiento histórico). Las subs sin operator_ci se
 *   incluyen sólo en el broadcast total, no en el segmentado.
 */
export async function broadcastPush(payload, opts = {}) {
  if (!_vapidReady) return { sent: 0, failed: 0, removed: 0, skipped: true };
  let subs = await listPushSubscriptions().catch((err) => {
    logger.warn("[webPush] list subs falló", { err: String(err?.message ?? err) });
    return [];
  });

  // Segmentación opcional por operador (P2 audit flujo 2026-06-06): evita que
  // TODOS reciban TODO. Si el set queda vacío tras filtrar, no se envía nada
  // (no caemos a broadcast — eso reintroduciría el ruido que queremos evitar).
  if (Array.isArray(opts.operatorCis)) {
    const wanted = new Set(opts.operatorCis.map((c) => String(c)));
    subs = subs.filter((s) => s.operator_ci != null && wanted.has(String(s.operator_ci)));
  }

  if (subs.length === 0) return { sent: 0, failed: 0, removed: 0 };

  const body = JSON.stringify(payload);
  let sent = 0, failed = 0, removed = 0;

  await Promise.all(subs.map(async (s) => {
    const subscription = {
      endpoint: s.endpoint,
      keys: { p256dh: s.p256dh_key, auth: s.auth_key },
    };
    try {
      await webpush.sendNotification(subscription, body, { TTL: 60 });
      sent += 1;
      bumpPushSubscriptionUsed(s.id).catch(() => {});
    } catch (err) {
      const code = err?.statusCode ?? 0;
      if (code === 404 || code === 410) {
        await deletePushSubscription(s.endpoint).catch(() => {});
        removed += 1;
      } else {
        failed += 1;
        logger.warn("[webPush] sendNotification falló", {
          endpoint: s.endpoint.slice(0, 60),
          code,
          err: String(err?.message ?? err),
        });
      }
    }
  }));

  return { sent, failed, removed };
}
