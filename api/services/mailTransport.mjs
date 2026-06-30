/**
 * mailTransport — wrapper liviano sobre nodemailer reutilizable por cualquier
 * notificación SOC (informe diario, alertas de vigilancia, escalación de
 * casos). Comparte la misma config SMTP de `reportService.mjs` para evitar
 * dos sets de variables en `.env`.
 *
 * Variables de entorno (todas en `.env` raíz):
 *   REPORT_SMTP_HOST          hostname del servidor SMTP
 *   REPORT_SMTP_PORT          puerto (587 STARTTLS / 465 SSL)
 *   REPORT_SMTP_SECURE        true para SSL directo (port 465)
 *   REPORT_SMTP_USER          usuario SMTP
 *   REPORT_SMTP_PASS          contraseña SMTP
 *   REPORT_FROM               dirección remitente (fallback si el caller no
 *                             pasa `from`)
 *
 * El transporter se crea perezoso y se reusa (nodemailer mantiene pool de
 * conexiones internamente; recrearlo por cada send es costoso).
 */

import nodemailer from "nodemailer";
import { logger } from "../logger.mjs";
import { getResolvedConfigSync } from "./appConfigService.mjs";

let _transporter = null;
let _from = null;
let _sig = null;   // firma de la config con la que se creó el transporter

// Config resuelta DB(cifrada)→.env→default vía appConfigService → editable desde
// Ajustes sin reiniciar (applyMode "live"). El transporter se recrea cuando
// cambia cualquier campo (firma distinta).
function smtpFields() {
  return {
    host:   (getResolvedConfigSync("REPORT_SMTP_HOST")   ?? "").trim(),
    port:   parseInt(getResolvedConfigSync("REPORT_SMTP_PORT") ?? "587", 10),
    secure: (getResolvedConfigSync("REPORT_SMTP_SECURE") ?? "false").trim().toLowerCase() === "true",
    user:   (getResolvedConfigSync("REPORT_SMTP_USER")   ?? "").trim(),
    pass:   (getResolvedConfigSync("REPORT_SMTP_PASS")   ?? "").trim(),
    from:   (getResolvedConfigSync("REPORT_FROM")        ?? "").trim(),
  };
}

function smtpConfigured() {
  const f = smtpFields();
  return Boolean(f.host && f.user && f.pass);
}

function getTransporter() {
  const f = smtpFields();
  if (!(f.host && f.user && f.pass)) return null;
  const sig = `${f.host}:${f.port}:${f.secure}:${f.user}:${f.pass}`;
  if (_transporter && sig === _sig) return _transporter;
  // Config nueva o cambiada → (re)crear el transporter.
  if (_transporter?.close) { try { _transporter.close(); } catch { /* noop */ } }
  _transporter = nodemailer.createTransport({
    host: f.host,
    port: f.port,
    secure: f.secure,
    auth: { user: f.user, pass: f.pass },
    tls: { rejectUnauthorized: false },
  });
  _sig = sig;
  _from = (f.from || f.user).trim();
  return _transporter;
}

/**
 * Envía un email vía el transporter SMTP compartido.
 *
 * @param {object} opts
 * @param {string} opts.to       Destinatario(s) — string coma-separado.
 * @param {string} opts.subject  Asunto.
 * @param {string} [opts.text]   Body texto plano.
 * @param {string} [opts.html]   Body HTML (al menos uno de text/html requerido).
 * @param {string} [opts.from]   Override del REPORT_FROM env. Opcional.
 *
 * @returns {Promise<{ok: boolean, messageId?: string, error?: string}>}
 */
export async function sendMail({ to, subject, text, html, from } = {}) {
  if (!to || !subject || (!text && !html)) {
    return { ok: false, error: "sendMail: to + subject + text|html requeridos" };
  }
  const transporter = getTransporter();
  if (!transporter) {
    return { ok: false, error: "SMTP no configurado (REPORT_SMTP_*)" };
  }
  try {
    const info = await transporter.sendMail({
      from: from ?? _from,
      to,
      subject,
      text,
      html,
    });
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    const msg = String(err?.message ?? err);
    logger.warn?.("[mailTransport] sendMail failed", { to, subject, err: msg });
    return { ok: false, error: msg };
  }
}

/** Diagnóstico: ¿SMTP listo para enviar? */
export function mailTransportReady() {
  return smtpConfigured();
}
