/**
 * reportService.mjs — Informe diario SOC por email.
 *
 * Variables de entorno (todas en .env raíz):
 *   REPORT_ENABLED          true|false (default false)
 *   REPORT_SMTP_HOST        hostname del servidor SMTP
 *   REPORT_SMTP_PORT        puerto (587 STARTTLS / 465 SSL)
 *   REPORT_SMTP_SECURE      true si usa SSL directo (port 465)
 *   REPORT_SMTP_USER        usuario SMTP
 *   REPORT_SMTP_PASS        contraseña SMTP
 *   REPORT_FROM             dirección remitente
 *   REPORT_TO               destinatario(s), coma-separados
 *   REPORT_SCHEDULE_UTC     hora UTC de envío formato HH:MM (default 09:00 → 06:00 Asunción UTC-3)
 */

import nodemailer from "nodemailer";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { formatCaseNumber } from "./caseNumber.mjs";
import { getResolvedConfigSync } from "./appConfigService.mjs";

// ── Config ─────────────────────────────────────────────────────────────────────

// Campos SMTP + from/to resueltos DB(cifrada)→.env→default vía appConfigService
// (editables desde Ajustes sin reiniciar). El horario (scheduleUtc) lo fija el
// scheduler al boot → cambiarlo requiere reiniciar (applyMode api-restart).
function getReportConfig() {
  const g = (k, d = "") => (getResolvedConfigSync(k) ?? d).trim();
  return {
    enabled:     g("REPORT_ENABLED", "false").toLowerCase() === "true",
    smtpHost:    g("REPORT_SMTP_HOST"),
    smtpPort:    parseInt(g("REPORT_SMTP_PORT", "587"), 10),
    smtpSecure:  g("REPORT_SMTP_SECURE", "false").toLowerCase() === "true",
    smtpUser:    g("REPORT_SMTP_USER"),
    smtpPass:    g("REPORT_SMTP_PASS"),
    from:        g("REPORT_FROM"),
    to:          g("REPORT_TO"),
    scheduleUtc: g("REPORT_SCHEDULE_UTC", "09:00"),
  };
}

export function reportConfigured() {
  const c = getReportConfig();
  return c.enabled && Boolean(c.smtpHost && c.smtpUser && c.smtpPass && c.from && c.to);
}

/** Devuelve [hh, mm] parseados de "HH:MM". */
export function parseScheduleUtc(scheduleUtc) {
  const parts = (scheduleUtc ?? "09:00").split(":");
  const hh = parseInt(parts[0] ?? "9", 10);
  const mm = parseInt(parts[1] ?? "0", 10);
  return [isNaN(hh) ? 9 : hh, isNaN(mm) ? 0 : mm];
}

// ── Recopilación de datos ──────────────────────────────────────────────────────

async function collectReportData() {
  const [openBySeverity, closedToday, topOperators, topIocs, recentCritical] =
    await Promise.all([
      // Casos abiertos por severidad
      pgQuery(`
        SELECT severity, COUNT(*) AS total
        FROM incident_cases_pg
        WHERE status NOT IN ('CERRADO','FALSO_POSITIVO')
        GROUP BY severity
        ORDER BY CASE severity
          WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3 ELSE 4 END
      `),

      // Casos cerrados en las últimas 24 h
      pgQuery(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'CERRADO')       AS closed,
          COUNT(*) FILTER (WHERE status = 'FALSO_POSITIVO') AS fp,
          ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60)
            FILTER (WHERE resolved_at IS NOT NULL), 1)     AS avg_mttr_min
        FROM incident_cases_pg
        WHERE resolved_at >= now() - INTERVAL '24 hours'
      `),

      // Top 5 operadores activos (últimos 7 días)
      pgQuery(`
        SELECT o.name, o.role_id AS role,
          COUNT(c.id)                                          AS cases,
          ROUND(AVG(EXTRACT(EPOCH FROM (c.resolved_at - c.created_at)) / 60)
            FILTER (WHERE c.resolved_at IS NOT NULL), 1)     AS avg_mttr_min
        FROM soc_operators o
        JOIN incident_cases_pg c ON c.operator_id = o.id
        WHERE c.created_at >= now() - INTERVAL '7 days'
        GROUP BY o.id, o.name, o.role_id
        ORDER BY cases DESC
        LIMIT 5
      `),

      // Top 10 IOCs por score (últimas 48 h, si la vista existe)
      pgQuery(`
        SELECT ioc_value, ioc_type, score, severity
        FROM incident_cases_pg
        WHERE created_at >= now() - INTERVAL '48 hours'
          AND score IS NOT NULL
        ORDER BY score DESC
        LIMIT 10
      `).catch(() => []),

      // Críticos sin cerrar de las últimas 24 h
      pgQuery(`
        SELECT id, case_number,
          COALESCE(ioc_value, '') || ' (' || COALESCE(source_log, 'N/A') || ')' AS title,
          severity, status, score,
          ROUND(EXTRACT(EPOCH FROM (now() - created_at)) / 60) AS age_min
        FROM incident_cases_pg
        WHERE severity = 'CRITICAL'
          AND status NOT IN ('CERRADO','FALSO_POSITIVO')
          AND created_at >= now() - INTERVAL '24 hours'
        ORDER BY created_at DESC
        LIMIT 10
      `),
    ]);

  return { openBySeverity, closedToday: closedToday[0] ?? {}, topOperators, topIocs, recentCritical };
}

// ── Construcción del HTML ──────────────────────────────────────────────────────

function severityColor(sev) {
  const map = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#d97706", LOW: "#65a30d", NEGLIGIBLE: "#6b7280" };
  return map[sev] ?? "#6b7280";
}

function buildHtml(data, reportDate) {
  const { openBySeverity, closedToday, topOperators, topIocs, recentCritical } = data;

  const totalOpen = openBySeverity.reduce((s, r) => s + Number(r.total), 0);

  const severityRows = openBySeverity.map((r) =>
    `<tr>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;">
        <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${severityColor(r.severity)};margin-right:6px;"></span>
        ${r.severity}
      </td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:600;">${r.total}</td>
    </tr>`
  ).join("");

  const operatorRows = topOperators.map((o) =>
    `<tr>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;">${o.name}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:#6b7280;">${o.role}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;text-align:right;">${o.cases}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;text-align:right;">${o.avg_mttr_min ?? "—"} min</td>
    </tr>`
  ).join("");

  const iocRows = topIocs.map((i) =>
    `<tr>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;">${i.ioc_value ?? "—"}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;">${i.ioc_type ?? "—"}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:600;color:${severityColor(i.severity ?? "LOW")};">${i.score ?? "—"}</td>
    </tr>`
  ).join("") || `<tr><td colspan="3" style="padding:10px 12px;color:#6b7280;">Sin IOCs con score en las últimas 48 h.</td></tr>`;

  const criticalRows = recentCritical.map((c) =>
    `<tr>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px;">${formatCaseNumber(c.case_number) ?? c.id.slice(0,8).toUpperCase()}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;">${c.title ?? "—"}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:#dc2626;font-weight:600;">${c.status}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;text-align:right;">${c.age_min} min</td>
    </tr>`
  ).join("") || `<tr><td colspan="4" style="padding:10px 12px;color:#6b7280;">Sin casos CRITICAL abiertos en las últimas 24 h. ✓</td></tr>`;

  return `<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Informe SOC Diario — LegacyHunt</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:'Segoe UI',Arial,sans-serif;font-size:14px;color:#111827;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 0;">
  <tr><td align="center">
    <table width="640" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1);">

      <!-- Header -->
      <tr><td style="background:#0f172a;padding:24px 32px;">
        <p style="margin:0;font-size:20px;font-weight:700;color:#f8fafc;">🛡 LegacyHunt SOC — Informe Diario</p>
        <p style="margin:4px 0 0;color:#94a3b8;font-size:13px;">${reportDate} UTC</p>
      </td></tr>

      <!-- KPI pills -->
      <tr><td style="padding:24px 32px 8px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td align="center" style="background:#fee2e2;border-radius:8px;padding:16px;width:30%;">
              <p style="margin:0;font-size:28px;font-weight:800;color:#dc2626;">${totalOpen}</p>
              <p style="margin:4px 0 0;font-size:12px;color:#991b1b;">Casos abiertos</p>
            </td>
            <td width="2%"></td>
            <td align="center" style="background:#dcfce7;border-radius:8px;padding:16px;width:30%;">
              <p style="margin:0;font-size:28px;font-weight:800;color:#16a34a;">${closedToday.closed ?? 0}</p>
              <p style="margin:4px 0 0;font-size:12px;color:#166534;">Cerrados hoy</p>
            </td>
            <td width="2%"></td>
            <td align="center" style="background:#dbeafe;border-radius:8px;padding:16px;width:36%;">
              <p style="margin:0;font-size:28px;font-weight:800;color:#1d4ed8;">${closedToday.avg_mttr_min ?? "—"} min</p>
              <p style="margin:4px 0 0;font-size:12px;color:#1e40af;">MTTR medio (24 h)</p>
            </td>
          </tr>
        </table>
      </td></tr>

      <!-- Casos abiertos por severidad -->
      <tr><td style="padding:20px 32px 8px;">
        <p style="margin:0 0 10px;font-weight:700;font-size:15px;">Casos abiertos por severidad</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">
          <thead><tr style="background:#f9fafb;">
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">SEVERIDAD</th>
            <th style="padding:8px 12px;text-align:right;font-size:12px;color:#6b7280;font-weight:600;">TOTAL</th>
          </tr></thead>
          <tbody>${severityRows || '<tr><td colspan="2" style="padding:10px 12px;color:#6b7280;">Sin casos abiertos.</td></tr>'}</tbody>
        </table>
      </td></tr>

      <!-- Críticos sin resolver -->
      <tr><td style="padding:20px 32px 8px;">
        <p style="margin:0 0 10px;font-weight:700;font-size:15px;color:#dc2626;">⚠ Críticos sin resolver (últimas 24 h)</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #fecaca;border-radius:6px;overflow:hidden;">
          <thead><tr style="background:#fef2f2;">
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">ID</th>
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">TÍTULO</th>
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">ESTADO</th>
            <th style="padding:8px 12px;text-align:right;font-size:12px;color:#6b7280;font-weight:600;">EDAD</th>
          </tr></thead>
          <tbody>${criticalRows}</tbody>
        </table>
      </td></tr>

      <!-- Top IOCs -->
      <tr><td style="padding:20px 32px 8px;">
        <p style="margin:0 0 10px;font-weight:700;font-size:15px;">Top IOCs por score (48 h)</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">
          <thead><tr style="background:#f9fafb;">
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">IOC</th>
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">TIPO</th>
            <th style="padding:8px 12px;text-align:right;font-size:12px;color:#6b7280;font-weight:600;">SCORE</th>
          </tr></thead>
          <tbody>${iocRows}</tbody>
        </table>
      </td></tr>

      <!-- Top operadores -->
      ${topOperators.length ? `
      <tr><td style="padding:20px 32px 8px;">
        <p style="margin:0 0 10px;font-weight:700;font-size:15px;">Top operadores activos (7 días)</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">
          <thead><tr style="background:#f9fafb;">
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">OPERADOR</th>
            <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;font-weight:600;">ROL</th>
            <th style="padding:8px 12px;text-align:right;font-size:12px;color:#6b7280;font-weight:600;">CASOS</th>
            <th style="padding:8px 12px;text-align:right;font-size:12px;color:#6b7280;font-weight:600;">MTTR</th>
          </tr></thead>
          <tbody>${operatorRows}</tbody>
        </table>
      </td></tr>` : ""}

      <!-- Footer -->
      <tr><td style="padding:24px 32px;background:#f8fafc;border-top:1px solid #e5e7eb;">
        <p style="margin:0;font-size:12px;color:#9ca3af;">
          Generado automáticamente por <strong>LegacyHunt SOC Platform</strong> —
          Legacy Roots Soluciones Tecnológicas Especializadas.<br>
          Este mensaje es confidencial. No lo reenvíe fuera de su organización.
        </p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>`;
}

// ── Envío ──────────────────────────────────────────────────────────────────────

/**
 * Genera y envía el informe diario SOC.
 * @returns {Promise<{ ok: boolean, messageId?: string, error?: string }>}
 */
export async function sendDailyReport() {
  const cfg = getReportConfig();

  if (!cfg.enabled) {
    logger.debug("[report] REPORT_ENABLED=false — skipping");
    return { ok: false, error: "disabled" };
  }
  if (!cfg.smtpHost || !cfg.smtpUser || !cfg.smtpPass) {
    logger.warn("[report] SMTP no configurado — skipping daily report");
    return { ok: false, error: "smtp_not_configured" };
  }

  try {
    const data = await collectReportData();
    const reportDate = new Date().toISOString().slice(0, 16).replace("T", " ");
    const html = buildHtml(data, reportDate);

    const transporter = nodemailer.createTransport({
      host:   cfg.smtpHost,
      port:   cfg.smtpPort,
      secure: cfg.smtpSecure,
      auth:   { user: cfg.smtpUser, pass: cfg.smtpPass },
      tls:    { rejectUnauthorized: false },
    });

    const info = await transporter.sendMail({
      from:    cfg.from,
      to:      cfg.to,
      subject: `[SOC] Informe diario LegacyHunt — ${reportDate} UTC`,
      html,
    });

    logger.info({ messageId: info.messageId, to: cfg.to }, "[report] daily report sent");
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    logger.error({ err: err.message }, "[report] failed to send daily report");
    return { ok: false, error: err.message };
  }
}
