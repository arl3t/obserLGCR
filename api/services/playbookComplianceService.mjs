/**
 * playbookComplianceService.mjs
 * §3 del roadmap docs/MEJORAS-ANALISTA-LLM-2026-06-24.md — Seguimiento del CIERRE
 * de casos y de la COMPLETITUD del playbook por parte de los analistas L1/L2.
 *
 * Dos capacidades:
 *
 *  3a. GUARDIA DE CALIDAD (detectIncompletePlaybookCloses): detecta casos CERRADOS
 *      por un analista con tareas de playbook aún PENDIENTES (OPEN/IN_PROGRESS) y
 *      escribe un evento de auditoría en el timeline + notifica al operador y a sus
 *      LEADER/ADMIN. NO bloquea el cierre — sólo avisa (el operador con can_close_case
 *      mantiene autoridad; queda registro para auditoría/coaching). Idempotente vía
 *      metadata.kind='playbook_incomplete_close'.
 *
 *  3b. MÉTRICAS DE CIERRE (collectClosureCompliance): por operador y nivel (L1/L2),
 *      cierres en la ventana + % de playbook completado + cierres con playbook
 *      incompleto. Consumido por el digest de seguimiento 6h (§2). Lectura pura.
 *
 * "Playbook completo" = el caso no tiene tareas OPEN/IN_PROGRESS (todas DONE o
 * SKIPPED). Sólo cuenta para casos que TIENEN tareas (total>0) y fueron cerrados por
 * un analista real (no auto-close del sistema).
 */

import { pgQuery } from "../db/postgres.mjs";
import { logger as rootLogger } from "../logger.mjs";
import { addTimelineEvent } from "./timelineService.mjs";
import { createNotification } from "./workflowEngine.mjs";
import { formatCaseNumber } from "./caseNumber.mjs";

const TERMINAL = `('CERRADO','FALSO_POSITIVO')`;
// Cerrado por un analista real (no auto-close del sistema ni owner basura).
const HUMAN_CLOSER = `(c.operator_id IS NOT NULL
  AND c.operator_id NOT IN ('SYSTEM','system','{}','')
  AND c.operator_id NOT LIKE 'auto%')`;

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };

/** Guardia gated (default OFF). Las métricas del digest (3b) NO dependen de esto. */
export function playbookComplianceEnabled() {
  return (process.env.PLAYBOOK_COMPLIANCE_ENABLED ?? "false").trim().toLowerCase() === "true";
}

// CTE de conteo de tareas por caso (playbook).
const TASK_STATS_CTE = `
  task_stats AS (
    SELECT case_id,
           count(*)                                              AS total,
           count(*) FILTER (WHERE status = 'DONE')               AS done,
           count(*) FILTER (WHERE status = 'SKIPPED')            AS skipped,
           count(*) FILTER (WHERE status IN ('OPEN','IN_PROGRESS')) AS pending
      FROM case_tasks
     GROUP BY case_id
  )`;

/**
 * 3b — Compliance de cierre en la ventana: filas por caso + agregado por operador.
 * @param {number} hours ventana hacia atrás.
 */
export async function collectClosureCompliance(hours) {
  const itv = `${num(hours, 6)} hours`;
  const rows = await pgQuery(
    `WITH ${TASK_STATS_CTE}
     SELECT c.id, c.case_number, c.severity, c.operator_id,
            COALESCE(o.name, c.operator_id) AS operator_name,
            COALESCE(o.role_id, '—')        AS role_id,
            c.resolved_at,
            COALESCE(ts.total, 0)   AS total,
            COALESCE(ts.done, 0)    AS done,
            COALESCE(ts.skipped, 0) AS skipped,
            COALESCE(ts.pending, 0) AS pending
       FROM incident_cases_pg c
       LEFT JOIN soc_operators o ON o.id = c.operator_id
       LEFT JOIN task_stats ts   ON ts.case_id = c.id
      WHERE c.status IN ${TERMINAL}
        AND c.resolved_at >= now() - INTERVAL '${itv}'
        AND ${HUMAN_CLOSER}
      ORDER BY c.resolved_at DESC
      LIMIT 500`,
  );

  // Agregado por operador (con su nivel) — cierres y completitud del playbook.
  const byOp = new Map();
  for (const r of rows) {
    const withTasks = Number(r.total) > 0;
    const complete = withTasks && Number(r.pending) === 0;
    const k = r.operator_id;
    if (!byOp.has(k)) {
      byOp.set(k, {
        operatorId: k, name: r.operator_name, role: r.role_id,
        closures: 0, withPlaybook: 0, complete: 0, incomplete: 0,
      });
    }
    const a = byOp.get(k);
    a.closures++;
    if (withTasks) { a.withPlaybook++; complete ? a.complete++ : a.incomplete++; }
  }
  const perOperator = [...byOp.values()]
    .map((a) => ({
      ...a,
      completionPct: a.withPlaybook ? Math.round((a.complete / a.withPlaybook) * 100) : null,
    }))
    .sort((x, y) => y.closures - x.closures);

  // Casos puntuales cerrados con playbook incompleto (para listar en el digest).
  const incompleteCases = rows
    .filter((r) => Number(r.total) > 0 && Number(r.pending) > 0)
    .slice(0, 50);

  return { hours: num(hours, 6), rows, perOperator, incompleteCases };
}

/**
 * 3a — Guardia: detecta cierres recientes con playbook incompleto, escribe auditoría
 * y notifica al operador + LEADER/ADMIN. Idempotente. Best-effort (nunca throw).
 * @param {{ logger?: any, io?: any, hours?: number, limit?: number }} [deps]
 */
export async function detectIncompletePlaybookCloses(deps = {}) {
  const logger = deps.logger ?? rootLogger;
  if (!playbookComplianceEnabled()) return { skipped: "disabled" };
  const hours = num(deps.hours ?? process.env.PLAYBOOK_COMPLIANCE_WINDOW_H, 24);
  const limit = num(deps.limit ?? process.env.PLAYBOOK_COMPLIANCE_BATCH, 50);
  const itv = `${hours} hours`;

  // Cierres con tareas pendientes que aún no fueron auditados.
  const cases = await pgQuery(
    `WITH ${TASK_STATS_CTE}
     SELECT c.id, c.case_number, c.severity, c.operator_id,
            COALESCE(o.name, c.operator_id) AS operator_name,
            COALESCE(o.role_id, '—')        AS role_id,
            ts.total, ts.done, ts.skipped, ts.pending
       FROM incident_cases_pg c
       JOIN task_stats ts        ON ts.case_id = c.id
       LEFT JOIN soc_operators o ON o.id = c.operator_id
      WHERE c.status IN ${TERMINAL}
        AND c.resolved_at >= now() - INTERVAL '${itv}'
        AND ${HUMAN_CLOSER}
        AND ts.pending > 0
        AND NOT EXISTS (
          SELECT 1 FROM case_timeline_events t
           WHERE t.case_id = c.id AND t.metadata->>'kind' = 'playbook_incomplete_close'
        )
      ORDER BY c.resolved_at DESC
      LIMIT ${limit}`,
  );
  if (!cases.length) return { ok: true, flagged: 0 };

  // LEADER/ADMIN activos como destinatarios de supervisión.
  const leaders = await pgQuery(
    `SELECT id FROM soc_operators WHERE role_id IN ('LEADER','ADMIN') AND is_active = true`,
  ).catch(() => []);
  const leaderIds = leaders.map((l) => l.id);

  let flagged = 0;
  for (const c of cases) {
    const numLabel = formatCaseNumber(c.case_number) ?? String(c.id).slice(0, 8);
    try {
      // 1) Auditoría en el timeline (idempotente por kind). source=SYSTEM, no MANUAL
      //    → no cuenta como seguimiento humano ni como acción de analista (MTTA).
      await addTimelineEvent(c.id, {
        eventType: "NOTE",
        title: `Playbook incompleto al cierre: ${c.pending} tarea(s) pendiente(s)`,
        description:
          `El caso se cerró con ${c.pending} de ${c.total} tareas del playbook sin completar `
          + `(${c.done} hechas, ${c.skipped} omitidas). Cerrado por ${c.operator_name} (${c.role_id}).`,
        operatorCi: "system",
        source: "SYSTEM",
        metadata: {
          kind: "playbook_incomplete_close",
          pending: Number(c.pending), total: Number(c.total),
          done: Number(c.done), skipped: Number(c.skipped),
          closed_by: c.operator_id, role_id: c.role_id,
        },
      });

      // 2) Notificar al operador que cerró + a LEADER/ADMIN (supervisión).
      const targets = new Set([c.operator_id, ...leaderIds].filter(Boolean));
      for (const target of targets) {
        await createNotification({
          operatorId: target,
          caseId: c.id,
          type: "SYSTEM",
          priority: c.severity === "CRITICAL" ? "HIGH" : "NORMAL",
          title: `Playbook incompleto — ${numLabel}`,
          body: `${numLabel} (${c.severity}) se cerró con ${c.pending}/${c.total} tareas del playbook sin completar.`,
          io: deps.io ?? null,
        }).catch(() => {});
      }
      flagged++;
    } catch (err) {
      logger.warn?.({ err: err.message, case: numLabel }, "[playbook-compliance] flag failed");
    }
  }
  if (flagged) logger.info?.({ flagged }, "[playbook-compliance] cierres con playbook incompleto");
  return { ok: true, flagged };
}
