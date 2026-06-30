/**
 * followupDigestService — supervisión de seguimiento de casos.
 *
 * Objetivo: monitorear que los operadores estén dando seguimiento a los casos
 * ABIERTOS. Cada 6h arma un digest por email a managers/leaders y, en paralelo,
 * envía un "nudge" (in-app + web push) al operador cuyo caso lleva > umbral sin
 * actividad MANUAL.
 *
 * §2 del roadmap docs/MEJORAS-ANALISTA-LLM-2026-06-24.md (2026-06-25): detalle
 * por-caso ampliado (categoría/MITRE/IOC, "nunca seguido SEGÚN EL TIMELINE" vs
 * último seguimiento, última actividad de cualquier tipo, veredicto del analista
 * LLM si existe) + sección de actividad del analista LLM en la ventana + KPI de
 * "veredicto LLM sin tomar" (el LLM dio el punto de partida y nadie lo siguió).
 *
 * "Seguimiento" = un evento en case_timeline_events con source='MANUAL' hecho por
 * un operador real (operator_ci numérico, NO 'SYSTEM'/'{}'). updated_at NO sirve
 * solo: lo mueven auto-acciones del sistema (auto-close, SLA, sync).
 *
 * Reusa la infra existente:
 *   - SMTP: mailTransport.sendMail (mismas envs REPORT_SMTP_*).
 *   - Nudge in-app: workflowEngine.createNotification (Socket.IO).
 *   - Nudge push: webPushService.broadcastPush (segmentado por operador).
 *
 * Variables de entorno:
 *   FOLLOWUP_DIGEST_ENABLED   true|false (default false) — activa la tarea 6h.
 *   FOLLOWUP_DIGEST_TO        destinatarios coma-separados (override). Si vacío,
 *                             se resuelve a LEADER/ADMIN activos con email.
 *   FOLLOWUP_STALE_HOURS      umbral horas sin seguimiento (default 6).
 *   FOLLOWUP_NUDGE_ENABLED    true|false (default true) — nudge al operador.
 */

import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { formatCaseNumber } from "./caseNumber.mjs";
import { sendMail, mailTransportReady } from "./mailTransport.mjs";
import { createNotification } from "./workflowEngine.mjs";
import { broadcastPush } from "./webPushService.mjs";
import { collectClosureCompliance } from "./playbookComplianceService.mjs";

const TERMINAL = `('CERRADO','FALSO_POSITIVO')`;
// operator_ci basura visto en datos reales: eventos MANUAL del sistema o vacíos.
const REAL_OPERATOR = `(operator_ci IS NOT NULL AND operator_ci NOT IN ('SYSTEM','system','{}',''))`;

/** Umbral configurable (entero positivo, default 6). */
function staleHours() {
  const n = parseInt(process.env.FOLLOWUP_STALE_HOURS ?? "6", 10);
  return Number.isFinite(n) && n > 0 ? n : 6;
}

/** ¿La tarea está activa? Requiere flag + SMTP configurado. */
export function followupDigestConfigured() {
  return (
    (process.env.FOLLOWUP_DIGEST_ENABLED ?? "false").trim().toLowerCase() === "true" &&
    mailTransportReady()
  );
}

/**
 * Destinatarios del digest: override por env, o LEADER/ADMIN activos con email.
 * @returns {Promise<string>} lista coma-separada (vacía si no hay).
 */
async function resolveRecipients() {
  const override = (process.env.FOLLOWUP_DIGEST_TO ?? "").trim();
  if (override) return override;
  const rows = await pgQuery(
    `SELECT email FROM soc_operators
      WHERE role_id IN ('LEADER','ADMIN') AND is_active = true
        AND email IS NOT NULL AND trim(email) <> ''`,
  );
  return rows.map((r) => r.email.trim()).filter(Boolean).join(", ");
}

/**
 * Recolecta los datos del digest en una sola pasada por las tablas.
 * @param {number} hours umbral de "sin seguimiento".
 */
export async function collectFollowupData(hours) {
  const itv = `${hours} hours`;

  // Último evento de seguimiento (MANUAL por operador real) por caso.
  const lastFollowupCte = `
    last_fu AS (
      SELECT case_id, MAX(event_ts) AS last_followup
      FROM case_timeline_events
      WHERE source = 'MANUAL' AND ${REAL_OPERATOR}
      GROUP BY case_id
    )`;

  // Veredicto más reciente del analista LLM por caso (kind='llm_case_verdict').
  // Permite mostrar que el LLM YA dio un punto de partida que ningún humano siguió.
  const lastVerdictCte = `
    last_verdict AS (
      SELECT case_id,
             MAX(event_ts) AS verdict_at,
             (ARRAY_AGG(metadata->>'verdict'    ORDER BY event_ts DESC))[1] AS verdict,
             (ARRAY_AGG(metadata->>'confidence' ORDER BY event_ts DESC))[1] AS confidence
      FROM case_timeline_events
      WHERE metadata->>'kind' = 'llm_case_verdict'
      GROUP BY case_id
    )`;

  // Último evento de CUALQUIER tipo (incl. sistema) — para "según el timeline":
  // distingue "nada pasó nunca" de "solo se movió por auto-acciones".
  const lastAnyCte = `
    last_any AS (
      SELECT case_id, MAX(event_ts) AS last_any_ts
      FROM case_timeline_events
      GROUP BY case_id
    )`;

  // Sección 1: casos ABIERTOS ADOPTADOS sin seguimiento > umbral, por operador.
  // Detalle ampliado: categoría/MITRE/IOC, si NUNCA tuvo seguimiento humano en el
  // timeline, última actividad de cualquier tipo, y veredicto LLM (si existe).
  const staleRows = await pgQuery(
    `WITH ${lastFollowupCte}, ${lastVerdictCte}, ${lastAnyCte}
     SELECT c.id, c.case_number, c.severity, c.status, c.operator_id,
            COALESCE(o.name, c.operator_id) AS operator_name,
            c.incident_category, c.mitre_technique_id, c.ioc_value,
            c.created_at, lf.last_followup,
            (lf.last_followup IS NULL)              AS never_followed,
            la.last_any_ts,
            lv.verdict     AS llm_verdict,
            lv.confidence  AS llm_confidence,
            lv.verdict_at  AS llm_verdict_at,
            ROUND(EXTRACT(EPOCH FROM (now() - COALESCE(lf.last_followup, c.created_at))) / 3600.0, 1) AS hours_idle
       FROM incident_cases_pg c
       LEFT JOIN last_fu lf       ON lf.case_id = c.id
       LEFT JOIN last_verdict lv  ON lv.case_id = c.id
       LEFT JOIN last_any la      ON la.case_id = c.id
       LEFT JOIN soc_operators o  ON o.id = c.operator_id
      WHERE c.status NOT IN ${TERMINAL}
        AND c.operator_id IS NOT NULL
        AND COALESCE(lf.last_followup, c.created_at) < now() - INTERVAL '${itv}'
      ORDER BY
        CASE c.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
        never_followed DESC,
        hours_idle DESC
      LIMIT 200`,
  );

  // Sección NUEVA: actividad del analista LLM en la ventana (veredictos emitidos),
  // desglosada por veredicto. Conecta §1 (veredicto continuo) con la supervisión.
  const llmActivityRows = await pgQuery(
    `SELECT COALESCE(metadata->>'verdict','(sin clasificar)') AS verdict,
            count(*)                 AS n,
            count(DISTINCT case_id)  AS cases
       FROM case_timeline_events
      WHERE metadata->>'kind' = 'llm_case_verdict'
        AND event_ts >= now() - INTERVAL '${itv}'
      GROUP BY 1
      ORDER BY n DESC`,
  );

  // Casos con veredicto LLM pero SIN ningún seguimiento humano (el LLM dio el punto
  // de partida y nadie lo tomó). KPI honesto para el manager.
  const [llmUntaken] = await pgQuery(
    `WITH ${lastFollowupCte}, ${lastVerdictCte}
     SELECT count(*) AS n
       FROM incident_cases_pg c
       JOIN last_verdict lv ON lv.case_id = c.id
       LEFT JOIN last_fu lf ON lf.case_id = c.id
      WHERE c.status NOT IN ${TERMINAL}
        AND lf.last_followup IS NULL`,
  );

  // Sección 2: actividad MANUAL por operador en la ventana.
  const activityRows = await pgQuery(
    `SELECT operator_ci,
            count(*) FILTER (WHERE event_type = 'NOTE')                          AS notes,
            count(*) FILTER (WHERE event_type = 'STATUS_CHANGE')                 AS status_changes,
            count(*) FILTER (WHERE event_type = 'ESCALATE')                      AS escalations,
            count(*) FILTER (WHERE event_type IN ('EVIDENCE','IOC','ASSET'))     AS docs,
            count(DISTINCT case_id)                                              AS cases_touched,
            count(*)                                                             AS total
       FROM case_timeline_events
      WHERE source = 'MANUAL' AND ${REAL_OPERATOR}
        AND event_ts >= now() - INTERVAL '${itv}'
      GROUP BY operator_ci
      ORDER BY total DESC`,
  );

  // Sección 3 + 4: resumen agregado (abiertos por severidad, sin adoptar, SLA).
  const [summary] = await pgQuery(
    `SELECT
        count(*)                                                       AS open_total,
        count(*) FILTER (WHERE severity = 'CRITICAL')                  AS open_critical,
        count(*) FILTER (WHERE severity = 'HIGH')                      AS open_high,
        count(*) FILTER (WHERE severity = 'MEDIUM')                    AS open_medium,
        count(*) FILTER (WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM')) AS open_low,
        count(*) FILTER (WHERE operator_id IS NULL)                    AS unadopted,
        count(*) FILTER (WHERE sla_breach_at IS NOT NULL)              AS sla_breached
       FROM incident_cases_pg
      WHERE status NOT IN ${TERMINAL}`,
  );

  // Operadores con casos abiertos asignados pero SIN actividad MANUAL en la ventana.
  const idleOperatorRows = await pgQuery(
    `WITH active_ops AS (
        SELECT DISTINCT operator_ci FROM case_timeline_events
         WHERE source = 'MANUAL' AND ${REAL_OPERATOR}
           AND event_ts >= now() - INTERVAL '${itv}'
     )
     SELECT c.operator_id, COALESCE(o.name, c.operator_id) AS operator_name,
            count(*) AS open_cases
       FROM incident_cases_pg c
       LEFT JOIN soc_operators o ON o.id = c.operator_id
      WHERE c.status NOT IN ${TERMINAL}
        AND c.operator_id IS NOT NULL
        AND c.operator_id NOT IN (SELECT operator_ci FROM active_ops)
      GROUP BY c.operator_id, o.name
      ORDER BY open_cases DESC`,
  );

  // §3b: cumplimiento de cierre + completitud de playbook por analista (L1/L2).
  const closureCompliance = await collectClosureCompliance(hours).catch(() => ({ perOperator: [], incompleteCases: [], rows: [] }));

  return {
    hours,
    generatedAt: new Date(),
    staleRows,
    activityRows,
    summary: summary ?? {},
    idleOperatorRows,
    llmActivityRows,
    llmUntaken: Number(llmUntaken?.n ?? 0),
    closureCompliance,
  };
}

/** Agrupa las stale rows por operador (para el digest y los nudges). */
function groupStaleByOperator(staleRows) {
  const byOp = new Map();
  for (const r of staleRows) {
    const k = r.operator_id;
    if (!byOp.has(k)) byOp.set(k, { operatorId: k, name: r.operator_name, cases: [] });
    byOp.get(k).cases.push(r);
  }
  return [...byOp.values()].sort((a, b) => b.cases.length - a.cases.length);
}

const SEV_COLOR = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#ca8a04", LOW: "#6b7280", NEGLIGIBLE: "#6b7280" };
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const dashUrl = () => (process.env.DASHBOARD_URL ?? "http://localhost:5173").replace(/\/$/, "");

// Etiqueta + color del veredicto del analista LLM (para badges en el digest).
const VERDICT_BADGE = {
  amenaza_real:            ["Amenaza real",       "#dc2626"],
  falso_positivo_probable: ["FP probable",        "#16a34a"],
  inconcluso:              ["Inconcluso",         "#ca8a04"],
  benigno:                 ["Benigno",            "#6b7280"],
};
const fmtTs = (ts) => (ts ? new Date(ts).toISOString().replace("T", " ").slice(0, 16) + " UTC" : null);
const llmBadge = (verdict, conf) => {
  if (!verdict) return "";
  const [label, col] = VERDICT_BADGE[verdict] ?? [verdict, "#6b7280"];
  const c = conf != null ? ` ${conf}%` : "";
  return `<span style="display:inline-block;padding:1px 6px;border-radius:10px;background:${col};color:#fff;font-size:11px;">LLM: ${esc(label)}${c}</span>`;
};

/** HTML del digest. */
export function buildFollowupHtml(data) {
  const { hours, generatedAt, staleRows, activityRows, summary, idleOperatorRows,
          llmActivityRows = [], llmUntaken = 0,
          closureCompliance = { perOperator: [], incompleteCases: [] } } = data;
  const grouped = groupStaleByOperator(staleRows);
  const base = dashUrl();

  // Una tarjeta por caso, con detalle: severidad+MITRE/categoría, estado del
  // seguimiento SEGÚN EL TIMELINE (nunca seguido vs último seguimiento), última
  // actividad de cualquier tipo, y veredicto del analista LLM si lo hay.
  const caseCard = (c) => {
    const sev = `<span style="color:${SEV_COLOR[c.severity] ?? "#6b7280"};font-weight:600;">${esc(c.severity)}</span>`;
    const num = esc(formatCaseNumber(c.case_number) ?? String(c.id).slice(0, 12) + "…");
    const meta = [c.incident_category, c.mitre_technique_id, c.ioc_value].filter(Boolean).map(esc).join(" · ");
    // "Según el timeline": distingue NUNCA seguido de sin seguimiento reciente.
    const follow = c.never_followed
      ? `<span style="color:#dc2626;font-weight:600;">⚠ Sin ningún seguimiento registrado en el timeline</span>`
      : `<span style="color:#6b7280;">Último seguimiento: ${esc(fmtTs(c.last_followup))}</span>`;
    const lastAny = c.last_any_ts ? `<span style="color:#9ca3af;"> · última actividad (cualquier tipo): ${esc(fmtTs(c.last_any_ts))}</span>` : "";
    const verdict = c.llm_verdict
      ? ` &nbsp; ${llmBadge(c.llm_verdict, c.llm_confidence)} <span style="color:#9ca3af;font-size:11px;">${esc(fmtTs(c.llm_verdict_at))}</span>`
      : ` &nbsp; <span style="color:#9ca3af;font-size:11px;">sin veredicto LLM</span>`;
    return `
      <div style="margin:6px 0;padding:8px 10px;border:1px solid #e5e7eb;border-left:3px solid ${SEV_COLOR[c.severity] ?? "#6b7280"};border-radius:4px;">
        <div style="display:flex;justify-content:space-between;align-items:baseline;">
          <div>${sev} &nbsp; <a href="${base}/cases/${esc(c.id)}" style="color:#2563eb;text-decoration:none;font-weight:600;">${num}</a>
               <span style="color:#6b7280;font-size:12px;">· ${esc(c.status)}</span></div>
          <div style="color:#dc2626;font-weight:600;font-size:13px;">${c.hours_idle}h sin seguimiento</div>
        </div>
        ${meta ? `<div style="color:#6b7280;font-size:12px;margin-top:2px;">${meta}</div>` : ""}
        <div style="font-size:12px;margin-top:3px;">${follow}${lastAny}</div>
        <div style="margin-top:3px;">${verdict}</div>
      </div>`;
  };

  const staleSection = grouped.length === 0
    ? `<p style="color:#16a34a;margin:6px 0;">✓ Todos los casos abiertos adoptados tuvieron seguimiento en las últimas ${hours}h (según el timeline).</p>`
    : grouped.map((g) => {
        const never = g.cases.filter((x) => x.never_followed).length;
        return `
        <div style="margin:10px 0;">
          <div style="font-weight:600;margin-bottom:4px;">${esc(g.name)}
            <span style="color:#6b7280;font-weight:400;">· ${g.cases.length} caso(s) sin seguimiento${never ? ` · <span style="color:#dc2626;">${never} nunca seguido(s)</span>` : ""}</span></div>
          ${g.cases.slice(0, 25).map(caseCard).join("")}
          ${g.cases.length > 25 ? `<div style="color:#6b7280;font-size:12px;margin-top:4px;">… y ${g.cases.length - 25} más.</div>` : ""}
        </div>`;
      }).join("");

  // Sección NUEVA: actividad del analista LLM en la ventana.
  const llmSection = llmActivityRows.length === 0
    ? `<p style="color:#6b7280;margin:6px 0;">Sin veredictos del analista LLM en las últimas ${hours}h.</p>`
    : `<table style="width:100%;border-collapse:collapse;font-size:13px;">
         <tr style="text-align:left;color:#6b7280;border-bottom:1px solid #e5e7eb;"><th style="padding:4px 6px;">Veredicto LLM</th><th>Eventos</th><th>Casos</th></tr>
         ${llmActivityRows.map((r) => {
           const [label, col] = VERDICT_BADGE[r.verdict] ?? [r.verdict, "#6b7280"];
           return `<tr style="border-bottom:1px solid #f3f4f6;">
             <td style="padding:4px 6px;"><span style="color:${col};font-weight:600;">${esc(label)}</span></td>
             <td style="text-align:center;">${r.n}</td>
             <td style="text-align:center;">${r.cases}</td></tr>`;
         }).join("")}
       </table>
       ${llmUntaken > 0 ? `<p style="color:#ea580c;font-size:12px;margin:6px 0;">⚠ ${llmUntaken} caso(s) abierto(s) tienen veredicto del analista LLM pero <b>ningún</b> seguimiento humano en el timeline.</p>` : ""}`;

  // §3b: cierre + completitud de playbook por analista (L1/L2) en la ventana.
  const cc = closureCompliance;
  const closureSection = (cc.perOperator?.length ?? 0) === 0
    ? `<p style="color:#6b7280;margin:6px 0;">Sin cierres por analistas en las últimas ${hours}h.</p>`
    : `<table style="width:100%;border-collapse:collapse;font-size:13px;">
         <tr style="text-align:left;color:#6b7280;border-bottom:1px solid #e5e7eb;">
           <th style="padding:4px 6px;">Analista</th><th>Nivel</th><th>Cierres</th><th>Con playbook</th><th>Completo</th><th>Incompleto</th><th>% Completitud</th>
         </tr>
         ${cc.perOperator.map((a) => {
           const pct = a.completionPct;
           const pctCol = pct == null ? "#6b7280" : pct >= 80 ? "#16a34a" : pct >= 50 ? "#ca8a04" : "#dc2626";
           return `<tr style="border-bottom:1px solid #f3f4f6;">
             <td style="padding:4px 6px;font-weight:600;">${esc(a.name)}</td>
             <td style="text-align:center;color:#6b7280;">${esc(a.role)}</td>
             <td style="text-align:center;">${a.closures}</td>
             <td style="text-align:center;">${a.withPlaybook}</td>
             <td style="text-align:center;color:#16a34a;">${a.complete}</td>
             <td style="text-align:center;color:${a.incomplete ? "#dc2626" : "#6b7280"};font-weight:${a.incomplete ? 600 : 400};">${a.incomplete}</td>
             <td style="text-align:center;font-weight:600;color:${pctCol};">${pct == null ? "—" : pct + "%"}</td>
           </tr>`;
         }).join("")}
       </table>
       ${(cc.incompleteCases?.length ?? 0) > 0
         ? `<div style="margin-top:8px;font-size:12px;">
              <div style="color:#dc2626;font-weight:600;margin-bottom:3px;">Cerrados con playbook incompleto:</div>
              ${cc.incompleteCases.slice(0, 15).map((c) => `
                <div style="padding:2px 0;">
                  <span style="color:${SEV_COLOR[c.severity] ?? "#6b7280"};font-weight:600;">${esc(c.severity)}</span>
                  <a href="${base}/cases/${esc(c.id)}" style="color:#2563eb;text-decoration:none;">${esc(formatCaseNumber(c.case_number) ?? String(c.id).slice(0, 12) + "…")}</a>
                  <span style="color:#6b7280;">· ${c.pending}/${c.total} tareas sin completar · cerró ${esc(c.operator_name)} (${esc(c.role_id)})</span>
                </div>`).join("")}
              ${cc.incompleteCases.length > 15 ? `<div style="color:#6b7280;">… y ${cc.incompleteCases.length - 15} más.</div>` : ""}
            </div>`
         : `<p style="color:#16a34a;font-size:12px;margin:6px 0;">✓ Ningún cierre con playbook incompleto en la ventana.</p>`}`;

  const activitySection = activityRows.length === 0
    ? `<p style="color:#6b7280;margin:6px 0;">Sin actividad MANUAL de operadores en las últimas ${hours}h.</p>`
    : `<table style="width:100%;border-collapse:collapse;font-size:13px;">
         <tr style="text-align:left;color:#6b7280;border-bottom:1px solid #e5e7eb;">
           <th style="padding:4px 6px;">Operador</th><th>Notas</th><th>Estados</th><th>Escaladas</th><th>Docs</th><th>Casos</th><th>Total</th>
         </tr>
         ${activityRows.map((a) => `
           <tr style="border-bottom:1px solid #f3f4f6;">
             <td style="padding:4px 6px;font-weight:600;">${esc(a.operator_ci)}</td>
             <td style="text-align:center;">${a.notes}</td>
             <td style="text-align:center;">${a.status_changes}</td>
             <td style="text-align:center;">${a.escalations}</td>
             <td style="text-align:center;">${a.docs}</td>
             <td style="text-align:center;">${a.cases_touched}</td>
             <td style="text-align:center;font-weight:600;">${a.total}</td>
           </tr>`).join("")}
       </table>`;

  const idleSection = idleOperatorRows.length === 0
    ? `<p style="color:#16a34a;margin:6px 0;">✓ Todos los operadores con casos asignados registraron actividad.</p>`
    : `<table style="width:100%;border-collapse:collapse;font-size:13px;">
         ${idleOperatorRows.map((o) => `
           <tr><td style="padding:3px 6px;font-weight:600;">${esc(o.operator_name)}</td>
               <td style="padding:3px 6px;text-align:right;color:#dc2626;">${o.open_cases} caso(s) abierto(s) · 0 actividad</td></tr>`).join("")}
       </table>`;

  const s = summary;
  return `
  <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:720px;margin:0 auto;color:#111827;">
    <h2 style="margin:0 0 4px;">Supervisión de seguimiento de casos</h2>
    <p style="color:#6b7280;margin:0 0 16px;font-size:13px;">
      Ventana ${hours}h · generado ${generatedAt.toISOString().replace("T", " ").slice(0, 16)} UTC
    </p>

    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px;">
      ${[
        ["Abiertos", s.open_total, "#111827"],
        ["Crit/High", (Number(s.open_critical || 0) + Number(s.open_high || 0)), "#dc2626"],
        ["Sin adoptar", s.unadopted, "#ea580c"],
        ["SLA vencido", s.sla_breached, "#dc2626"],
        ["Sin seguimiento", staleRows.length, "#dc2626"],
        ["Veredicto LLM sin tomar", llmUntaken, "#ea580c"],
      ].map(([label, val, col]) => `
        <div style="flex:1;min-width:110px;padding:10px;border:1px solid #e5e7eb;border-radius:6px;text-align:center;">
          <div style="font-size:22px;font-weight:700;color:${col};">${val ?? 0}</div>
          <div style="font-size:11px;color:#6b7280;">${label}</div>
        </div>`).join("")}
    </div>

    <h3 style="margin:18px 0 6px;border-bottom:2px solid #dc2626;padding-bottom:4px;">🔴 Casos abiertos SIN seguimiento (&gt; ${hours}h)</h3>
    ${staleSection}

    <h3 style="margin:18px 0 6px;border-bottom:2px solid #16a34a;padding-bottom:4px;">🟢 Actividad de operadores (últimas ${hours}h)</h3>
    ${activitySection}

    <h3 style="margin:18px 0 6px;border-bottom:2px solid #2563eb;padding-bottom:4px;">🤖 Actividad del analista LLM (últimas ${hours}h)</h3>
    ${llmSection}

    <h3 style="margin:18px 0 6px;border-bottom:2px solid #ca8a04;padding-bottom:4px;">🟡 Operadores con casos asignados pero inactivos</h3>
    ${idleSection}

    <h3 style="margin:18px 0 6px;border-bottom:2px solid #7c3aed;padding-bottom:4px;">📋 Cierre de casos y completitud de playbook (L1/L2, últimas ${hours}h)</h3>
    ${closureSection}

    <p style="margin-top:24px;color:#9ca3af;font-size:11px;">
      LegacyHunt SOC · digest automático de supervisión · responde el flag FOLLOWUP_DIGEST_ENABLED.
    </p>
  </div>`;
}

/**
 * Envía nudges (in-app + push) a cada operador con casos sin seguimiento.
 * Uno por operador (agregado), no uno por caso → evita spam.
 */
async function sendNudges(grouped, hours, io) {
  if ((process.env.FOLLOWUP_NUDGE_ENABLED ?? "true").trim().toLowerCase() !== "true") {
    return { nudged: 0 };
  }
  let nudged = 0;
  for (const g of grouped) {
    const n = g.cases.length;
    const title = `${n} caso${n === 1 ? "" : "s"} sin seguimiento (>${hours}h)`;
    const body = `Tenés ${n} caso${n === 1 ? "" : "s"} abierto${n === 1 ? "" : "s"} sin actividad en las últimas ${hours}h. Revisá tu cola y registrá avances.`;
    try {
      await createNotification({
        operatorId: g.operatorId,
        type:       "SYSTEM",
        priority:   "HIGH",
        title,
        body,
        io,
      });
      // Push best-effort, segmentado al operador.
      broadcastPush(
        { title: "Seguimiento pendiente", body, url: `${dashUrl()}/cases` },
        { operatorCis: [g.operatorId] },
      ).catch(() => {});
      nudged++;
    } catch (err) {
      logger.warn({ err: err.message, op: g.operatorId }, "[followup] nudge failed");
    }
  }
  return { nudged };
}

/**
 * Punto de entrada de la tarea 6h: recolecta, envía digest por email a
 * managers/leaders y nudges a operadores. Best-effort, nunca throw al scheduler.
 *
 * @param {object|null} io Socket.IO (para el nudge in-app realtime).
 */
export async function sendFollowupDigest(io = null) {
  if (!followupDigestConfigured()) {
    return { ok: false, skipped: "not_configured" };
  }
  const hours = staleHours();
  try {
    const data = await collectFollowupData(hours);
    const grouped = groupStaleByOperator(data.staleRows);

    // Nudges a operadores (independiente del email — útil aunque no haya SMTP TO).
    const { nudged } = await sendNudges(grouped, hours, io);

    const to = await resolveRecipients();
    if (!to) {
      logger.warn("[followup] sin destinatarios (FOLLOWUP_DIGEST_TO vacío y sin LEADER/ADMIN con email)");
      return { ok: false, skipped: "no_recipients", nudged, stale: data.staleRows.length };
    }

    const html = buildFollowupHtml(data);
    const r = await sendMail({
      to,
      subject: `[SOC] Seguimiento de casos — ${data.staleRows.length} sin seguimiento (${hours}h)`,
      html,
    });
    if (!r.ok) {
      logger.warn({ error: r.error }, "[followup] email failed");
      return { ok: false, error: r.error, nudged, stale: data.staleRows.length };
    }
    logger.info(
      { messageId: r.messageId, to, stale: data.staleRows.length, nudged },
      "[followup] digest sent",
    );
    return { ok: true, messageId: r.messageId, stale: data.staleRows.length, nudged };
  } catch (err) {
    logger.error({ err: err.message }, "[followup] sendFollowupDigest failed");
    return { ok: false, error: err.message };
  }
}
