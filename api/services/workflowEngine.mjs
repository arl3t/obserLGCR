/**
 * workflowEngine.mjs
 * Motor de flujo de trabajo del ciclo de vida de incidentes SOC.
 * NIST SP 800-61 Rev. 3 — 5 etapas obligatorias.
 *
 * Responsabilidades:
 *  - Máquina de estados: validar transiciones por rol
 *  - autoCloseLowNegligible(): cierra LOW/NEGLIGIBLE automáticamente
 *  - autoAssignTimeoutCases(): asigna al Shift Manager tras 30 min sin adopción
 *  - createNotification(): crea notificación in-app + emite Socket.IO
 *  - recordAutoAction(): persiste en incident_auto_actions (audit trail)
 */

import { randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { trinoExec } from "./trinoWriter.mjs";
import { getCachedThresholds } from "./socThresholds.mjs";
import { decideClosureClassification } from "./closureClassification.mjs";
import { upsertSuppressionsBatch } from "./caseSuppression.mjs";
import { invalidateCasesKpisCache } from "../routes/caseInvestigation.mjs";
import { screenIocMalice, guessIocType } from "./enrichmentService.mjs";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ─────────────────────────────────────────────────────────────────────────────
// Iceberg mirror: sincroniza incident_cases_pg → minio_iceberg.hunting.incident_cases
// ─────────────────────────────────────────────────────────────────────────────
// PG es la fuente de verdad operacional (CRUD, triggers, constraints); Iceberg
// es la proyección analítica que leen los dashboards vía Trino. Cualquier
// mutación en PG (transitionCase, autoClose, autoAssign) debe reflejarse aquí
// para evitar desfase. Usa DELETE+INSERT por case_id (idempotente, best-effort).
// Si Trino no está disponible el error se loggea como warn pero no bloquea el
// flujo de PG — el DAG diario reconciliará.
// ─────────────────────────────────────────────────────────────────────────────

function _sq(v) {
  if (v == null || v === "") return "NULL";
  return "'" + String(v).replace(/'/g, "''") + "'";
}
function _tsz(iso) {
  if (!iso) return "NULL";
  const d = iso instanceof Date ? iso : new Date(iso);
  return `TIMESTAMP '${d.toISOString().replace("T", " ").replace("Z", " UTC")}'`;
}

const _SEV_RANK  = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NEGLIGIBLE: 1 };
const _SEV_SCORE = { CRITICAL: 90, HIGH: 70, MEDIUM: 50, LOW: 30, NEGLIGIBLE: 10 };

/**
 * Construye el JSON `score_breakdown` que el dashboard lee para renderizar las
 * 5 barras (MITRE/Evidencia/Wazuh/MISP/Contexto). Reemplazar la fila Iceberg
 * con NULL aquí dejaba al CaseDetailSheet con todas las barras en 0/X (bug
 * reportado 2026-04-20). Tomamos los valores desde `enrichment_data` JSONB de
 * PG, que es donde scoringBonus / open-from-flow los persisten.
 */
function _buildScoreBreakdownJson(enrichmentData) {
  const ed = enrichmentData ?? {};
  const num = (v) => (v == null || Number.isNaN(Number(v))) ? 0 : Number(v);
  const sm  = num(ed.score_mitre);
  const se  = num(ed.score_evidence);
  const sw  = num(ed.score_wazuh);
  const sms = num(ed.score_misp);
  const sc  = num(ed.score_context);
  // Si TODOS son 0 no escribimos el JSON: mejor NULL que un objeto vacío que
  // pisa lo que pueda haber del DAG diario.
  if (sm + se + sw + sms + sc === 0) return null;
  return JSON.stringify({
    score_mitre:    sm,
    score_evidence: se,
    score_wazuh:    sw,
    score_misp:     sms,
    score_context:  sc,
  });
}

/** Tupla VALUES para una fila de incident_cases (debe alinearse con las columnas del INSERT). */
function _mirrorRowTuple(r) {
  const sev      = (r.severity || "MEDIUM").toUpperCase();
  const sevRank  = _SEV_RANK[sev]  ?? 3;
  const sevScore = r.score ?? _SEV_SCORE[sev] ?? 50;
  const anchor   = r.anchor_dt ? new Date(r.anchor_dt).toISOString().slice(0, 10) : null;
  const anchorSql = anchor ? `DATE '${anchor}'` : "NULL";
  // Preservar score_breakdown reconstruyéndolo desde enrichment_data — bug fix
  // 2026-04-20: el mirror dejaba score_breakdown en NULL y el dashboard mostraba
  // MITRE/Evidencia/Wazuh/MISP/Contexto todos en 0/X.
  const scoreBreakdownJson = _buildScoreBreakdownJson(r.enrichment_data);
  const scoreBreakdownSql  = scoreBreakdownJson ? _sq(scoreBreakdownJson) : "NULL";
  return `(
    ${_sq(r.id)}, ${_sq(r.id)},
    ${_sq(r.ioc_value || "")}, ${_sq(r.ioc_type || "ip")}, ${_sq(r.source_log || "runtime-mirror")},
    ${_sq(r.mitre_technique_id)}, ${_sq(r.mitre_tactic_id)}, ${_sq(r.mitre_tactic_name)},
    NULL, ${_sq(sev)}, ${sevRank}, ${sevScore},
    NULL, ${_sq(r.status || "NUEVO")}, ${r.occurrence_count ?? 1},
    ${_tsz(r.created_at)}, ${_tsz(r.updated_at)},
    ${anchorSql},
    NULL, ${scoreBreakdownSql}, NULL,
    ${_sq(r.operator_id)}, NULL,
    ${_tsz(r.created_at)}, ${_tsz(r.updated_at)},
    ${_tsz(r.adopted_at)},
    ${_sq(r.escalation_level)}, ${_sq(r.escalated_to)},
    ${_tsz(r.escalated_at)}, ${_sq(r.escalation_reason)},
    ${_sq(r.recommended_action)}
  )`;
}

// Chunk tamaño para DELETE IN + INSERT multi-VALUES. 200 mantiene el SQL
// por debajo de ~100 KB (Trino acepta statements mucho mayores pero chunks
// menores también protegen ante contención del commit lock en Iceberg).
const _MIRROR_CHUNK = 200;

/**
 * Reemplaza las filas en Iceberg con el estado actual de PG. Best-effort.
 * Acepta uno o varios caseIds.
 *
 * Batched: cada chunk de ≤ _MIRROR_CHUNK casos genera **sólo 2 commits**
 * (1 DELETE IN + 1 INSERT multi-VALUES). Antes se generaban 2 commits por
 * caso, lo que hacía explotar la metadata Iceberg de incident_cases
 * (5 K+ commits/día con el patrón anterior).
 */
export async function mirrorCasesToIceberg(caseIds) {
  const ids = Array.isArray(caseIds) ? caseIds : [caseIds];
  if (!ids.length) return { mirrored: 0, errors: 0 };

  // Traer el estado actual desde PG (fuente de verdad). enrichment_data trae
  // el desglose score_mitre/evidence/wazuh/misp/context que el mirror debe
  // preservar en la columna `score_breakdown` de Iceberg.
  const rows = await pgQuery(
    `SELECT id, ioc_value, ioc_type, source_log, severity, status, score,
            mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
            operator_id, anchor_dt, created_at, updated_at,
            adopted_at, resolved_at, recommended_action, escalated_at,
            escalation_level, escalated_to, escalation_reason, occurrence_count,
            enrichment_data
       FROM incident_cases_pg
      WHERE id = ANY($1::varchar[])`,
    [ids],
  );
  if (!rows.length) return { mirrored: 0, errors: 0 };

  const INSERT_COLS = `
    case_id, dedup_key, ioc_value, ioc_type, source_log,
    mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
    source_category, severity_text, severity_rank, severity_score,
    confidence_level, status, occurrence_count,
    first_seen, last_seen, anchor_dt,
    linked_evidence, score_breakdown, notes,
    assigned_to, closure_reason, created_at, updated_at,
    adopted_at, escalation_level, escalated_to, escalated_at, escalation_reason,
    recommended_action
  `;

  let mirrored = 0, errors = 0;
  for (let i = 0; i < rows.length; i += _MIRROR_CHUNK) {
    const chunk = rows.slice(i, i + _MIRROR_CHUNK);
    const chunkIds = chunk.map((r) => r.id);
    try {
      // 1 commit: DELETE de todos los case_id del chunk
      await trinoExec(
        `DELETE FROM minio_iceberg.hunting.incident_cases
         WHERE case_id IN (${chunkIds.map(_sq).join(", ")})`,
      );
      // 1 commit: INSERT multi-VALUES con todas las filas
      const valuesSql = chunk.map(_mirrorRowTuple).join(",\n");
      await trinoExec(
        `INSERT INTO minio_iceberg.hunting.incident_cases (${INSERT_COLS}) VALUES\n${valuesSql}`,
      );
      mirrored += chunk.length;
    } catch (err) {
      errors += chunk.length;
      logger.warn({
        caseIdsSample: chunkIds.slice(0, 5),
        chunkSize: chunk.length,
        err: err?.message ?? String(err),
      }, "[workflow:mirror] Iceberg batch upsert failed (PG unchanged)");
    }
  }
  if (mirrored > 0) {
    logger.debug({ mirrored, errors, chunks: Math.ceil(rows.length / _MIRROR_CHUNK) },
      "[workflow:mirror] synced PG → Iceberg");
  }
  return { mirrored, errors };
}

/**
 * Sincroniza el estado de incident_cases_pg al índice canónico
 * `legacyhunt_soc.incident_case_index`. Este índice es consultado por
 * `incident_cases_sync_daily` (DAG) para hacer dedup. Si las transiciones
 * (CERRADO/EN_ANALISIS/ESCALADO) sólo se escriben en PG, el DAG sigue viendo
 * status='NUEVO' y reabre/reduplica casos que ya fueron tomados.
 *
 * Best-effort: errores aquí no bloquean la respuesta. El DAG reconcile y la
 * convergencia eventual cubren los huecos. Sólo UPDATE — la inserción inicial
 * en el índice la hace el DAG sync (single-source de creación).
 */
export async function mirrorCasesToIndex(caseIds) {
  const all = Array.isArray(caseIds) ? caseIds : [caseIds];
  // El índice canónico tiene case_id uuid; los ids hex32 de incident_cases_pg
  // nunca matchean. Filtrarlos a formato uuid permite castear `icp.id::uuid`
  // (cast sobre el lado filtrado, no sobre la columna indexada) y usar el PK
  // index. Antes `ici.case_id::text = icp.id` forzaba seq-scan de ~400k filas
  // en cada mirror — la causa del seq_tup_read de 46e9 sobre incident_case_index.
  const ids = all.filter((x) => UUID_RE.test(String(x ?? "")));
  if (!ids.length) return { synced: 0, errors: 0 };

  try {
    const r = await pgQuery(
      `UPDATE legacyhunt_soc.incident_case_index ici
          SET status        = icp.status,
              severity_text = icp.severity,
              severity_score= icp.score,
              closure_reason= COALESCE(icp.auto_closed_reason, ici.closure_reason),
              last_seen     = GREATEST(ici.last_seen, icp.updated_at),
              updated_at    = NOW()
         FROM incident_cases_pg icp
        WHERE ici.case_id = icp.id::uuid
          AND icp.id = ANY($1::varchar[])
          AND (ici.status         <> icp.status
            OR ici.severity_text  <> icp.severity
            OR ici.severity_score <> icp.score)
        RETURNING ici.case_id`,
      [ids],
    );
    return { synced: r.length, errors: 0 };
  } catch (err) {
    logger.warn({ ids: ids.slice(0, 5), err: err?.message ?? String(err) },
      "[workflow:mirror-index] sync PG → index_index failed");
    return { synced: 0, errors: ids.length };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagrama de estados del incidente
// ─────────────────────────────────────────────────────────────────────────────
//
//  Mermaid:
//  stateDiagram-v2
//    [*] --> NUEVO : scoring engine crea caso
//    NUEVO --> EN_ANALISIS      : L1 adopta / asigna
//    NUEVO --> FALSO_POSITIVO   : L1 cierra como FP
//    NUEVO --> CERRADO          : auto-close LOW/NEGLIGIBLE | LEADER cierra
//    EN_ANALISIS --> CONFIRMADO : L2 confirma incidente real
//    EN_ANALISIS --> FALSO_POSITIVO : L1/L2 descarta
//    EN_ANALISIS --> ESCALADO   : L1 escala (score ≥ 70 | táctica crítica)
//    CONFIRMADO  --> ESCALADO   : L2 escala a L3
//    CONFIRMADO  --> CERRADO    : L2 cierra
//    CONFIRMADO  --> MONITOREADO: L2 pasa a monitoreo
//    ESCALADO    --> CERRADO    : L3 / LEADER cierra
//    ESCALADO    --> CONFIRMADO : L3 rebaja nivel
//    MONITOREADO --> EN_ANALISIS: reactiva
//    MONITOREADO --> CERRADO    : LEADER / L2 cierra
//
//  Etapas NIST (lifecycle_stage):
//    DETECTION      → NUEVO (recién creado por el motor)
//    TRIAGE_L1      → EN_ANALISIS (L1 triaging)
//    INVESTIGATION_L2 → CONFIRMADO / primer ESCALADO
//    RESPONSE_L3    → ESCALADO a IR team
//    CLOSURE        → CERRADO / FALSO_POSITIVO
// ─────────────────────────────────────────────────────────────────────────────

// ── Métricas del motor de workflow ───────────────────────────────────────────
const _wfMetrics = {
  autoCloseTotal:       0,
  autoAssignTotal:      0,
  autoAssignSkipsNoSM:  0, // ciclos donde no había Shift Manager activo
  autoEscalateTotal:    0,
  lastAutoCloseAt:      null,
  lastAutoAssignAt:     null,
  lastNoShiftManagerAt: null,
};

/** Devuelve métricas acumuladas del motor de workflow (desde arranque del proceso). */
export function getWorkflowMetrics() {
  return { ..._wfMetrics };
}

// Tácticas MITRE que disparan escalada automática a L2
const CRITICAL_TACTICS = new Set([
  "TA0002", // Execution
  "TA0008", // Lateral Movement
  "TA0010", // Exfiltration
  "TA0011", // Command and Control
  "TA0005", // Defense Evasion
  "TA0006", // Credential Access
  "TA0040", // Impact
]);

// Transiciones permitidas por status y rol
// { [fromStatus]: { [role]: [allowedNextStatuses] } }
//
// Reconciliación de máquinas de estado (audit 2026-06-05, ALTA-1): esta tabla
// (role-aware, política NIST — la usan transitionCase y los flujos SYSTEM) debe
// mantener PARIDAD de aristas con `VALID_TRANSITIONS` en routes/incidents.mjs
// (la que aplica el PATCH /status humano). VALID_TRANSITIONS define qué arista
// existe; la autorización del cierre humano la decide el cap RBAC
// (`can_close_case` vía checkTransitionRbac), no esta tabla. Cualquier arista
// nueva debe agregarse en AMBOS lados para no contradecirse.
const TRANSITIONS = {
  NUEVO: {
    L1:     ["EN_ANALISIS", "FALSO_POSITIVO", "MONITOREADO"],
    L2:     ["EN_ANALISIS", "CONFIRMADO", "FALSO_POSITIVO", "MONITOREADO"],
    L3:     ["EN_ANALISIS", "CONFIRMADO", "MONITOREADO"],
    LEADER: ["EN_ANALISIS", "CONFIRMADO", "FALSO_POSITIVO", "CERRADO", "ESCALADO", "MONITOREADO"],
    ADMIN:  ["EN_ANALISIS", "CONFIRMADO", "FALSO_POSITIVO", "CERRADO", "ESCALADO", "MONITOREADO"],
    SYSTEM: ["CERRADO", "EN_ANALISIS"],  // used by auto-close and auto-assign
  },
  EN_ANALISIS: {
    L1:     ["CONFIRMADO", "ESCALADO", "FALSO_POSITIVO", "MONITOREADO"],
    L2:     ["CONFIRMADO", "ESCALADO", "FALSO_POSITIVO", "MONITOREADO"],
    L3:     ["CONFIRMADO", "ESCALADO", "CERRADO"],
    LEADER: ["CONFIRMADO", "ESCALADO", "FALSO_POSITIVO", "CERRADO", "MONITOREADO"],
    ADMIN:  ["CONFIRMADO", "ESCALADO", "FALSO_POSITIVO", "CERRADO", "MONITOREADO"],
    SYSTEM: ["ESCALADO"],
  },
  CONFIRMADO: {
    L2:     ["ESCALADO", "CERRADO", "MONITOREADO"],
    L3:     ["ESCALADO", "CERRADO"],
    LEADER: ["ESCALADO", "CERRADO", "MONITOREADO"],
    ADMIN:  ["ESCALADO", "CERRADO", "MONITOREADO"],
    SYSTEM: ["ESCALADO"],
  },
  ESCALADO: {
    L3:     ["CONFIRMADO", "CERRADO", "FALSO_POSITIVO"],
    LEADER: ["CONFIRMADO", "CERRADO", "FALSO_POSITIVO"],
    ADMIN:  ["CONFIRMADO", "CERRADO", "FALSO_POSITIVO"],
  },
  MONITOREADO: {
    L1:     ["EN_ANALISIS", "FALSO_POSITIVO"],
    L2:     ["EN_ANALISIS", "CERRADO", "ESCALADO", "FALSO_POSITIVO"],
    LEADER: ["EN_ANALISIS", "CERRADO", "ESCALADO", "FALSO_POSITIVO"],
    ADMIN:  ["EN_ANALISIS", "CERRADO", "ESCALADO", "FALSO_POSITIVO"],
  },
  FALSO_POSITIVO: {
    L2:     ["EN_ANALISIS"],
    LEADER: ["EN_ANALISIS", "CERRADO"],
    ADMIN:  ["EN_ANALISIS", "CERRADO"],
  },
  CERRADO: {
    LEADER: ["EN_ANALISIS"],  // reapertura excepcional
    ADMIN:  ["EN_ANALISIS"],
  },
};

// Mapeo status → lifecycle_stage
export const STATUS_TO_STAGE = {
  NUEVO:          "DETECTION",
  EN_ANALISIS:    "TRIAGE_L1",
  CONFIRMADO:     "INVESTIGATION_L2",
  ESCALADO:       "RESPONSE_L3",
  MONITOREADO:    "INVESTIGATION_L2",
  FALSO_POSITIVO: "CLOSURE",
  CERRADO:        "CLOSURE",
};

// Roles habilitados para CIERRE FORZADO (cerrar en lote sin postmortem).
// La matriz TRANSITIONS ya permite a estos roles cerrar desde cualquier estado;
// el "force" sólo relaja el gate de postmortem y defaultea la clasificación.
export const FORCE_CLOSE_ROLES = new Set(["ADMIN", "LEADER"]);

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Valida si una transición de estado es permitida para un rol dado.
 * @param {string} fromStatus  - estado actual del caso
 * @param {string} toStatus    - estado destino
 * @param {string} roleId      - ID del rol del operador (L1/L2/L3/LEADER/ADMIN/SYSTEM)
 * @returns {{ ok: boolean, reason?: string }}
 */
export function validateTransition(fromStatus, toStatus, roleId) {
  const allowed = TRANSITIONS[fromStatus]?.[roleId] ?? [];
  if (!allowed.includes(toStatus)) {
    return {
      ok: false,
      reason: `El rol ${roleId} no puede transicionar ${fromStatus} → ${toStatus}`,
    };
  }
  return { ok: true };
}

/**
 * Determina si un caso debe escalarse automáticamente a L2.
 * Regla: score ≥ auto_escalate_score O táctica en CRITICAL_TACTICS.
 * Umbral: R11 (2026-05-13) lo externalizó a env; R15 (P3) lo movió a
 * `legacyhunt_soc.soc_thresholds` con cache TTL 30s para que un manager
 * lo edite desde el UI sin restart.
 */
export function shouldAutoEscalate(score, mitreTacticId) {
  const t = getCachedThresholds();
  const threshold = t.auto_escalate_score;
  if (score >= threshold) {
    return { suggest: true, reason: `Score elevado (${score} ≥ ${threshold})` };
  }
  if (mitreTacticId && CRITICAL_TACTICS.has(mitreTacticId)) {
    return { suggest: true, reason: `Táctica crítica MITRE: ${mitreTacticId}` };
  }
  return { suggest: false };
}

// ── Obtener el Shift Manager activo ──────────────────────────────────────────

export async function getActiveShiftManager() {
  const rows = await pgQuery(
    `SELECT id, name, email, role_id, shift
     FROM soc_operators
     WHERE is_shift_manager = true AND is_active = true
     LIMIT 1`
  );
  return rows[0] ?? null;
}

/**
 * Devuelve el mejor LEADER disponible como fallback cuando no hay Shift Manager
 * activo. Criterio: LEADER más antiguo (lower created_at / registered_at)
 * y activo. Si no hay ningún LEADER, cae a ADMIN.
 *
 * Uso: `autoAssignTimeoutCases()` para evitar que los casos huérfanos se
 * acumulen indefinidamente si ningún SM ha sido designado.
 */
export async function getFallbackLeader() {
  const [leader] = await pgQuery(
    `SELECT id, name, email, role_id
       FROM soc_operators
      WHERE role_id IN ('LEADER','ADMIN')
        AND is_active = true
      ORDER BY
        CASE role_id WHEN 'LEADER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END,
        COALESCE(last_active_at, created_at) ASC
      LIMIT 1`,
  );
  return leader ?? null;
}

/**
 * Notifica a todos los LEADER/ADMIN activos que no hay Shift Manager designado.
 *
 * Rate-limit dinámico: por defecto 1 notificación / hora. Si ya hubo más de 2
 * notificaciones en la última hora (señal de incidente sostenido), reduce el
 * cooldown a 15 min para que el equipo lo tenga top-of-mind hasta resolver.
 */
async function notifyNoShiftManager(io) {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const [{ recent_count }] = await pgQuery(
    `SELECT COUNT(*)::int AS recent_count
       FROM soc_notifications
      WHERE type = 'NO_SHIFT_MANAGER'
        AND created_at >= $1`,
    [oneHourAgo],
  );

  // Cooldown adaptativo: bajada a 15 min si hay incidente sostenido (>2 alertas/h).
  const cooldownMin = recent_count > 2 ? 15 : 60;
  const cooldownAgo = new Date(Date.now() - cooldownMin * 60 * 1000).toISOString();
  const [{ since_cooldown }] = await pgQuery(
    `SELECT COUNT(*)::int AS since_cooldown
       FROM soc_notifications
      WHERE type = 'NO_SHIFT_MANAGER'
        AND created_at >= $1`,
    [cooldownAgo],
  );
  if (since_cooldown > 0) return 0;

  const admins = await pgQuery(
    `SELECT id FROM soc_operators
      WHERE role_id IN ('LEADER','ADMIN') AND is_active = true`,
  );
  let sent = 0;
  for (const a of admins) {
    await createNotification({
      operatorId: a.id,
      type:       "NO_SHIFT_MANAGER",
      priority:   "HIGH",
      title:      "No hay Shift Manager activo",
      body:       "Los casos sin adopción se auto-asignan al LEADER fallback. "
                 +"Designa un Shift Manager para restablecer el flujo normal.",
      io,
    }).then(() => { sent++; }).catch(() => {});
  }
  return sent;
}

// ── Crear notificación in-app ──────────────────────────────────────────────��──

/**
 * @param {{ operatorId: string, caseId?: string, type: string, priority: string, title: string, body?: string, io?: object }} opts
 */
export async function createNotification({ operatorId, caseId, type, priority = "NORMAL", title, body, io }) {
  const id = randomUUID();
  await pgQuery(
    `INSERT INTO soc_notifications (id, operator_id, case_id, type, priority, title, body, action_url)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      id, operatorId, caseId ?? null, type, priority, title, body ?? null,
      caseId ? `/cases/${caseId}` : null,
    ]
  );

  // Emitir en tiempo real si Socket.IO está disponible
  if (io) {
    io.to(`operator:${operatorId}`).emit("notification:new", {
      id, type, priority, title, body, caseId,
    });
    logger.info({ operatorId, type, caseId }, "[workflow] notification pushed via socket");
  }
  return id;
}

// ── Registrar acción automática en el audit trail ────────────────────────────

export async function recordAutoAction({
  caseId, actionType, targetOperator = null,
  beforeStatus, afterStatus, beforeStage, afterStage,
  reason, details = {},
}) {
  const id = randomUUID();
  await pgQuery(
    `INSERT INTO incident_auto_actions
       (id, case_id, action_type, target_operator,
        before_status, after_status, before_stage, after_stage,
        reason, details)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      id, caseId, actionType, targetOperator,
      beforeStatus ?? null, afterStatus ?? null,
      beforeStage ?? null, afterStage ?? null,
      reason, JSON.stringify(details),
    ]
  );

  // También insertar en case_timeline_events para visibilidad en la UI
  const tlId = randomUUID();
  await pgQuery(
    `INSERT INTO case_timeline_events
       (id, case_id, event_type, phase, title, description, operator_ci, source, metadata)
     VALUES ($1,$2,'STATUS_CHANGE','DETECTION',$3,$4,'SYSTEM','SYSTEM',$5)`,
    [
      tlId, caseId,
      actionType.replace(/_/g, " "),
      reason,
      JSON.stringify({ actionType, ...details }),
    ]
  );

  return id;
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTO-CIERRE: LOW / NEGLIGIBLE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cierra automáticamente todos los casos LOW y NEGLIGIBLE que están abiertos.
 * Justificación: "Severity too low for manual triage (auto-closed by system)".
 * Impacto: ↓ MTTR, ↓ cola L1.
 *
 * @param {object} io - instancia Socket.IO (opcional)
 * @returns {{ closed: number, errors: number }}
 */
export async function autoCloseLowNegligible(io) {
  let closed = 0, errors = 0;

  const candidates = await pgQuery(
    `SELECT id, severity, status, lifecycle_stage, score, ioc_value, operator_id, dedup_key
     FROM v_auto_close_candidates`
  );

  if (!candidates.length) {
    logger.debug("[workflow:auto-close] no candidates");
    return { closed: 0, errors: 0 };
  }

  logger.info({ count: candidates.length }, "[workflow:auto-close] processing candidates");

  // ── R1 (audit 2026-06-05): gate de threat-intel antes de auto-cerrar ────────
  // El scoring (SQL nocturno) sólo ve VT/Shodan/AbuseIPDB/TOR/MISP. Los feeds
  // keyless (GreyNoise/ThreatFox/OTX/Spamhaus/URLhaus) sólo corren en
  // investigación, y nadie investiga un caso auto-cerrado → un LOW que es un IOC
  // malicioso conocido en esos feeds se cierra+suprime 30d sin que nadie lo vea.
  // Opt-in (AUTO_CLOSE_INTEL_GATE=on) para no cambiar el default hasta validar.
  // Tope por tick (AUTO_CLOSE_INTEL_GATE_MAX, def 50 IOC distintos) acota la
  // presión sobre APIs externas; lo que excede se loguea (sin truncado silencioso)
  // y se cierra como antes. IOC con hit → escala a MEDIUM (sale del set de cierre).
  const escalatedIds = new Set();
  // P0 #2 (re-enriquecimiento): casos cuyo screen de intel quedó INCOMPLETO este
  // tick (IOC por encima del tope, o screenIocMalice con error/timeout de fuente).
  // No se cierran a ciegas → se DIFIEREN; el próximo tick reintenta el screen.
  const deferredIds = new Set();
  if ((process.env.AUTO_CLOSE_INTEL_GATE ?? "off").toLowerCase() === "on") {
    const gateMax = Math.max(0, Number(process.env.AUTO_CLOSE_INTEL_GATE_MAX ?? 50) || 50);
    const byIoc = new Map(); // ioc_value → { iocType, cases: [candidate] }
    for (const c of candidates) {
      if (!c.ioc_value) continue;
      if (!byIoc.has(c.ioc_value)) byIoc.set(c.ioc_value, { iocType: guessIocType(c.ioc_value), cases: [] });
      byIoc.get(c.ioc_value).cases.push(c);
    }
    const distinct = [...byIoc.keys()];
    const toScreen = distinct.slice(0, gateMax);
    if (distinct.length > gateMax) {
      // P0 #2: lo que excede el tope NO se cierra sin cribar — se difiere al
      // siguiente tick (antes se cerraba a ciegas). Sólo difiere si el caso es
      // suprimible por dedup_key; los sin dedup_key no reaparecen, así que
      // diferirlos eternamente no aporta → se dejan cerrar más abajo.
      for (const ioc of distinct.slice(gateMax)) {
        for (const c of byIoc.get(ioc).cases) if (c.dedup_key) deferredIds.add(c.id);
      }
      logger.warn({ total: distinct.length, screened: gateMax, deferred: deferredIds.size },
        "[workflow:auto-close] intel-gate: tope por tick — el resto se DIFIERE (reintento próximo tick)");
    }
    const results = await Promise.all(toScreen.map(async (ioc) => {
      try {
        const v = await screenIocMalice(ioc, byIoc.get(ioc).iocType);
        return { ioc, v, failed: false };
      } catch (e) {
        logger.debug({ ioc, err: e?.message }, "[workflow:auto-close] intel-gate screen error");
        return { ioc, failed: true };
      }
    }));
    for (const r of results) {
      const cases = byIoc.get(r.ioc).cases;
      if (r.failed) {
        // P0 #2: screen incompleto (fuente caída/timeout) → diferir, no cerrar a
        // ciegas. Sólo casos con dedup_key (los demás no reaparecen).
        for (const c of cases) if (c.dedup_key) deferredIds.add(c.id);
        continue;
      }
      if (!r.v.malicious) continue;   // limpio → se cerrará normalmente
      const { ioc, v } = r;
      const ids = cases.map((c) => c.id);
      try {
        await pgQuery(
          `UPDATE incident_cases_pg
              SET severity = 'MEDIUM',
                  enrichment_data = jsonb_set(COALESCE(enrichment_data,'{}'::jsonb),
                                              '{intel_gate}', $2::jsonb),
                  updated_at = now()
            WHERE id = ANY($1::varchar[]) AND status IN ('NUEVO','EN_ANALISIS')`,
          [ids, JSON.stringify({ escalated_at: new Date().toISOString(), reasons: v.reasons })],
        );
        for (const c of cases) escalatedIds.add(c.id);
        for (const c of cases) {
          await recordAutoAction({
            caseId: c.id, actionType: "AUTO_INTEL_ESCALATE",
            beforeStatus: c.status, afterStatus: c.status,
            reason: `Auto-cierre bloqueado: IOC ${ioc} con intel de malicia (${v.reasons.join("; ")}) → severity MEDIUM`,
            details: { ioc, reasons: v.reasons, from_severity: c.severity },
          }).catch(() => {});
        }
        logger.warn({ ioc, cases: ids.length, reasons: v.reasons },
          "[workflow:auto-close] intel-gate: IOC malicioso → escalado a MEDIUM (no cerrado)");
      } catch (e) {
        logger.error({ ioc, err: e?.message }, "[workflow:auto-close] intel-gate escalate failed");
      }
    }
  }

  // Sólo cerramos los candidatos que el gate NO escaló NI difirió (P0 #2).
  let closeCandidates = (escalatedIds.size || deferredIds.size)
    ? candidates.filter((c) => !escalatedIds.has(c.id) && !deferredIds.has(c.id))
    : candidates;
  if (!closeCandidates.length) {
    if (escalatedIds.size) invalidateCasesKpisCache();
    logger.info({ escalated: escalatedIds.size, deferred: deferredIds.size },
      "[workflow:auto-close] todos los candidatos escalados/diferidos por intel-gate");
    return { closed: 0, errors: 0, escalated: escalatedIds.size, deferred: deferredIds.size };
  }

  // P2 #6 (throttle): un pico de scoring (p.ej. 50k LOW de golpe) cerraría todo
  // en un tick → ráfaga de notificaciones + UPDATE gigante. Capamos por tick; el
  // resto se cierra en ticks siguientes (auto-close corre cada 5 min). 0 = sin tope.
  const maxPerTick = Math.max(0, Number(process.env.AUTO_CLOSE_MAX_PER_TICK ?? 1000) || 0);
  let throttled = 0;
  if (maxPerTick > 0 && closeCandidates.length > maxPerTick) {
    throttled = closeCandidates.length - maxPerTick;
    closeCandidates = closeCandidates.slice(0, maxPerTick);
    logger.info({ capped: maxPerTick, deferred_to_next_tick: throttled },
      "[workflow:auto-close] throttle por tick — el resto se cierra en el próximo tick");
  }

  // Batch UPDATE — un solo round-trip para cerrar todos los candidatos
  const candidateIds = closeCandidates.map((c) => c.id);
  try {
    await pgQuery(
      `UPDATE incident_cases_pg
       SET status             = 'CERRADO',
           lifecycle_stage    = 'CLOSURE',
           auto_closed_at     = now(),
           auto_closed_reason = 'Severity too low for manual triage (auto-closed by system)',
           resolved_at        = now(),
           updated_at         = now()
       WHERE id = ANY($1::varchar[])`,
      [candidateIds],
    );
  } catch (batchErr) {
    logger.error({ err: batchErr.message }, "[workflow:auto-close] batch UPDATE failed");
    return { closed: 0, errors: closeCandidates.length, escalated: escalatedIds.size };
  }

  // ── P0 dedup-churn: suprimir-al-cerrar ─────────────────────────────────────
  // Sin esto, el DAG (incident_cases_sync_daily.py:665) y la API recreaban el
  // mismo dedup_key apenas autoCloseLowNegligible lo cerraba (~90k LOW/semana).
  // Alimentar case_suppressions hace que ambos salten la recreación mientras la
  // ventana (AUTO_CLOSED = 30d) siga vigente. Solo candidatos con dedup_key;
  // los NULL (caso DAG sin ioc_value) no son suprimibles — se omiten.
  try {
    const sup = await upsertSuppressionsBatch(
      pgQuery,
      closeCandidates
        .filter((c) => c.dedup_key)
        .map((c) => ({
          dedupKey: c.dedup_key,
          reason:   "AUTO_CLOSED",
          severity: c.severity,
          caseId:   c.id,
          iocValue: c.ioc_value,
        })),
    );
    if (sup.suppressed) {
      logger.info({ suppressed: sup.suppressed, skipped: sup.skipped },
        "[workflow:auto-close] suppressions upserted");
    }
  } catch (supErr) {
    // Best-effort: el cierre ya está commiteado. Estos casos no reaparecen como
    // candidatos (ya cerrados), pero el self-heal se mantiene: la próxima
    // ocurrencia del mismo dedup_key crea un caso nuevo que, al auto-cerrarse,
    // sí quedará suprimido.
    logger.error({ err: supErr.message }, "[workflow:auto-close] suppression upsert failed");
  }

  // Audit trail + notificaciones (per-case, best-effort)
  for (const c of closeCandidates) {
    try {
      const reason     = `Severity too low for manual triage (auto-closed by system) — severity=${c.severity}`;
      const actionType = c.severity === "LOW" ? "AUTO_CLOSE_LOW" : "AUTO_CLOSE_NEGLIGIBLE";

      await recordAutoAction({
        caseId: c.id, actionType,
        beforeStatus: c.status, afterStatus: "CERRADO",
        beforeStage: c.lifecycle_stage, afterStage: "CLOSURE",
        reason, details: { severity: c.severity, score: c.score },
      });

      if (c.operator_id && io) {
        await createNotification({
          operatorId: c.operator_id,
          caseId: c.id,
          type: "AUTO_CLOSE",
          priority: "LOW",
          title: `Caso ${c.id.slice(0, 7).toUpperCase()} cerrado automáticamente`,
          body: `Severidad ${c.severity}: ${reason}`,
          io,
        });
      }

      closed++;
    } catch (err) {
      logger.error({ caseId: c.id, err: err.message }, "[workflow:auto-close] audit/notify error");
      errors++;
    }
  }

  _wfMetrics.autoCloseTotal += closed;
  _wfMetrics.lastAutoCloseAt = new Date().toISOString();

  // F6/G1 (audit 2026-06-05): cierre masivo (~90k LOW/sem) mueve fuerte el
  // conteo de abiertos/resueltos-hoy. UPDATE crudo → invalidar explícitamente.
  // También si el intel-gate (R1) escaló casos a MEDIUM.
  if (closed > 0 || escalatedIds.size) invalidateCasesKpisCache();

  // Mirror Iceberg + índice canónico (best-effort, no bloquea). Incluye los
  // escalados por el gate para que su nueva severidad llegue al índice.
  const mirrorIds = escalatedIds.size ? [...candidateIds, ...escalatedIds] : candidateIds;
  if (mirrorIds.length) {
    mirrorCasesToIceberg(mirrorIds).catch(() => {});
    mirrorCasesToIndex(mirrorIds).catch(() => {});
  }

  logger.info({ closed, errors, escalated: escalatedIds.size, deferred: deferredIds.size, throttled },
    "[workflow:auto-close] done");
  return { closed, errors, escalated: escalatedIds.size, deferred: deferredIds.size, throttled };
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTO-MERGE DE DUPLICADOS (P0 #3, backlog GESTION-OPTIMIZACION-2026-06-07)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Auto-fusiona clusters de casos ABIERTOS que comparten el mismo `ioc_value` y la
 * misma táctica MITRE pero tienen `dedup_key` distinto (típicamente el mismo IOC
 * visto por dos sensores → distinta source_category → distinta clave para
 * MEDIUM/LOW/NEGLIGIBLE). El índice único `idx_cases_dedup_key_open_unique` ya
 * impide duplicados con la MISMA clave; este job ataca el residuo a nivel de IOC
 * que hoy exige `POST /api/incidents/merge` manual (~64 clusters / 104 casos al
 * 2026-06-07).
 *
 * Política CONSERVADORA y opt-in (env `AUTO_MERGE_DUPLICATES=on`, igual convención
 * que el intel-gate):
 *   · Nunca toca HIGH/CRITICAL (esos clusters quedan para revisión humana — la
 *     combinación IOC+táctica puede ser un ataque multi-fase real).
 *   · Sólo CIERRA como duplicado los casos en NUEVO/MONITOREADO y SIN adoptar.
 *     Jamás cierra un EN_ANALISIS/CONFIRMADO/ESCALADO ni un caso adoptado: están
 *     bajo trabajo/respuesta humana y auto-cerrarlos destruiría ese esfuerzo.
 *   · El canónico (que se conserva) es el de MAYOR atención: prioridad por estado
 *     (ESCALADO>CONFIRMADO>EN_ANALISIS>MONITOREADO>NUEVO), luego score↓, antigüedad↑.
 * Los duplicados se cierran como CERRADO + classification AUTO_DUPLICATE +
 * merged_into; si tienen `dedup_key`, el trigger `trg_suppress_on_close` (mig 078)
 * crea la supresión EN LA MISMA transacción (los de clave vacía sólo se cierran).
 * El canónico absorbe los `occurrence_count`.
 *
 * @param {object} io - instancia Socket.IO (opcional)
 * @returns {{ clusters: number, merged: number, errors: number }}
 */
const _MERGE_STATUS_RANK = { ESCALADO: 5, CONFIRMADO: 4, EN_ANALISIS: 3, MONITOREADO: 2, NUEVO: 1 };
// Estados de un duplicado que es SEGURO auto-cerrar (sin trabajo humano activo).
const _MERGE_CLOSEABLE = new Set(["NUEVO", "MONITOREADO"]);

export async function autoMergeDuplicates(io) {
  if ((process.env.AUTO_MERGE_DUPLICATES ?? "off").toLowerCase() !== "on") {
    return { clusters: 0, merged: 0, errors: 0, disabled: true };
  }
  const maxClusters = Math.max(1, Number(process.env.AUTO_MERGE_MAX_CLUSTERS ?? 50) || 50);

  // Trae todas las filas de los clusters elegibles (cap por nº de clusters).
  // Orden: dentro de cada (ioc,táctica) el canónico queda primero (score↓, antigüedad↑).
  const rows = await pgQuery(
    `WITH open_cases AS (
       SELECT id, ioc_value, COALESCE(mitre_tactic_id,'') AS tac, severity, status,
              COALESCE(score,0) AS score, created_at,
              COALESCE(occurrence_count,1) AS occ, lifecycle_stage, operator_id
         FROM incident_cases_pg
        WHERE status NOT IN ('CERRADO','FALSO_POSITIVO')
          AND ioc_value IS NOT NULL AND btrim(ioc_value) <> ''
          AND upper(severity) IN ('LOW','MEDIUM','NEGLIGIBLE')
          AND created_at >= now() - INTERVAL '90 days'
     ),
     clusters AS (
       SELECT ioc_value, tac
         FROM open_cases
        GROUP BY ioc_value, tac
       HAVING count(*) > 1
        LIMIT $1
     )
     SELECT oc.*
       FROM open_cases oc
       JOIN clusters c ON c.ioc_value = oc.ioc_value AND c.tac = oc.tac`,
    [maxClusters],
  );

  if (!rows.length) return { clusters: 0, merged: 0, errors: 0 };

  // Agrupar por (ioc_value, tac).
  const groups = new Map();
  for (const r of rows) {
    const k = `${r.ioc_value} ${r.tac}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }

  let merged = 0, errors = 0, clusterCount = 0;
  const touchedIds = [];

  for (const cluster of groups.values()) {
    if (cluster.length < 2) continue;
    // Canónico = mayor atención humana → score → más antiguo. Se conserva.
    const sorted = [...cluster].sort((a, b) => {
      const ra = _MERGE_STATUS_RANK[a.status] ?? 0, rb = _MERGE_STATUS_RANK[b.status] ?? 0;
      if (rb !== ra) return rb - ra;
      if (Number(b.score) !== Number(a.score)) return Number(b.score) - Number(a.score);
      return new Date(a.created_at) - new Date(b.created_at);
    });
    const canon = sorted[0];
    // Sólo cerramos duplicados SEGUROS: NUEVO/MONITOREADO y sin adoptar.
    const dups = sorted.slice(1).filter(
      (d) => _MERGE_CLOSEABLE.has(d.status) && !d.operator_id,
    );
    if (dups.length === 0) continue;   // nada seguro que fusionar en este cluster
    const dupIds = dups.map((d) => d.id);
    const addOcc = dups.reduce((s, d) => s + Number(d.occ || 1), 0);
    clusterCount++;

    try {
      // 1) Cerrar duplicados → el trigger 078 inserta/extiende case_suppressions
      //    en esta misma TX. classification AUTO_DUPLICATE los excluye de MTTR/FPR.
      await pgQuery(
        `UPDATE incident_cases_pg
            SET status            = 'CERRADO',
                lifecycle_stage   = 'CLOSURE',
                classification    = 'AUTO_DUPLICATE',
                merged_into_case_id = $2,
                auto_closed_reason = $3,
                auto_closed_at    = now(),
                resolved_at       = now(),
                updated_at        = now()
          WHERE id = ANY($1::varchar[])
            AND status NOT IN ('CERRADO','FALSO_POSITIVO')`,
        [dupIds, String(canon.id), `MERGEADO → ${canon.id} (auto)`],
      );

      // 2) Canónico absorbe occurrence_count + refresca last_seen.
      await pgQuery(
        `UPDATE incident_cases_pg
            SET occurrence_count = COALESCE(occurrence_count,1) + $2,
                last_seen        = now(),
                updated_at       = now()
          WHERE id = $1`,
        [String(canon.id), addOcc],
      );

      // 3) Audit trail + timeline (best-effort, por caso).
      for (const d of dups) {
        await recordAutoAction({
          caseId: d.id, actionType: "AUTO_MERGE_DUPLICATE",
          beforeStatus: d.status, afterStatus: "CERRADO",
          beforeStage: d.lifecycle_stage, afterStage: "CLOSURE",
          reason: `Auto-fusionado en caso canónico ${String(canon.id).slice(0,7).toUpperCase()} (mismo IOC ${canon.ioc_value} · táctica ${canon.tac || "n/a"})`,
          details: { canonical: canon.id, ioc: canon.ioc_value, tactic: canon.tac, severity: d.severity },
        }).catch(() => {});
        merged++;
      }
      await recordAutoAction({
        caseId: canon.id, actionType: "AUTO_MERGE_CANONICAL",
        beforeStatus: canon.status, afterStatus: canon.status,
        reason: `Absorbió ${dups.length} duplicado(s) por auto-merge (occurrence +${addOcc})`,
        details: { absorbed: dupIds, addOcc },
      }).catch(() => {});

      touchedIds.push(String(canon.id), ...dupIds);
    } catch (err) {
      logger.error({ canonical: canon.id, dups: dupIds.length, err: err.message },
        "[workflow:auto-merge] cluster merge failed");
      errors++;
    }
  }

  _wfMetrics.autoMergeTotal = (_wfMetrics.autoMergeTotal ?? 0) + merged;
  _wfMetrics.lastAutoMergeAt = new Date().toISOString();

  if (merged > 0) {
    invalidateCasesKpisCache();
    mirrorCasesToIceberg(touchedIds).catch(() => {});
    mirrorCasesToIndex(touchedIds).catch(() => {});
    if (io) io.emit("incidents:auto-merged", { clusters: clusterCount, merged });
  }

  logger.info({ clusters: clusterCount, merged, errors }, "[workflow:auto-merge] done");
  return { clusters: clusterCount, merged, errors };
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTO-ASIGNACIÓN: 30 MINUTOS SIN ADOPCIÓN → SHIFT MANAGER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detecta casos en NUEVO/EN_ANALISIS sin adopción tras 30 minutos
 * y los auto-asigna al Shift Manager activo.
 * Emite notificación in-app + Socket.IO al líder.
 *
 * @param {object} io - instancia Socket.IO (opcional)
 * @returns {{ assigned: number, errors: number }}
 */
export async function autoAssignTimeoutCases(io) {
  let assigned = 0, errors = 0;

  // R3: si no hay Shift Manager, notificar a LEADER/ADMIN y usar fallback
  // (LEADER más antiguo activo) en lugar de saltar silenciosamente.
  let manager = await getActiveShiftManager();
  let usingFallback = false;
  if (!manager) {
    _wfMetrics.autoAssignSkipsNoSM++;
    _wfMetrics.lastNoShiftManagerAt = new Date().toISOString();
    await notifyNoShiftManager(io).catch(() => {});
    manager = await getFallbackLeader();
    if (!manager) {
      // Sin SM y sin LEADER/ADMIN activo → escalación crítica: no hay nadie que
      // pueda tomar P1s. Subimos a ERROR para que el log monitor (Grafana/Slack)
      // genere alerta inmediata; auto-asign no podrá correr hasta que un humano
      // active al menos un LEADER (PATCH /operators/:id/status).
      logger.error("[workflow:auto-assign] no shift manager AND no fallback leader — SOC sin cobertura, casos quedan sin asignar");
      return { assigned: 0, errors: 0, noShiftManager: true, noFallback: true };
    }
    usingFallback = true;
    logger.warn({ fallback: manager.id, role: manager.role_id },
      "[workflow:auto-assign] no shift manager — using fallback leader");
  }

  const timeoutCases = await pgQuery(`SELECT * FROM v_timeout_cases`);

  if (!timeoutCases.length) {
    logger.debug("[workflow:auto-assign] no timeout cases");
    return { assigned: 0, errors: 0 };
  }

  logger.info({ count: timeoutCases.length, manager: manager.id }, "[workflow:auto-assign] processing");

  // F5 (audit 2026-06-05): reparto entre analistas activos en vez de apilar todo
  // en el Shift Manager (que se volvía cuello de botella/vertedero). Modo:
  //   · 'balance' (default): least-loaded entre analistas activos (L1/L2/L3/L1L2).
  //     Asigna OWNER (operator_id) + deja shift_manager_ci como backstop de
  //     escalación. Notifica al analista asignado.
  //   · 'shift_manager' (o sin pool de analistas, p.ej. off-hours): comportamiento
  //     previo — parquea en el Shift Manager sin owner.
  // Controlable por env AUTO_ASSIGN_MODE.
  const balanceMode = (process.env.AUTO_ASSIGN_MODE ?? "balance").toLowerCase() === "balance";
  let pool = [];
  if (balanceMode) {
    pool = await pgQuery(`
      SELECT o.id, o.role_id,
             (SELECT count(*) FROM incident_cases_pg c
                WHERE c.operator_id = o.id
                  AND c.status NOT IN ('CERRADO','FALSO_POSITIVO'))::int AS load
        FROM soc_operators o
       WHERE o.is_active = true
         AND o.role_id IN ('L1','L2','L3','L1L2')
    `).catch(() => []);
  }
  // Map mutable de carga para el least-loaded incremental dentro del tick.
  const loads = pool.map((p) => ({ id: p.id, role_id: p.role_id, load: Number(p.load) || 0 }));
  const pickAssignee = () => {
    if (!loads.length) return null;
    let best = loads[0];
    for (const a of loads) if (a.load < best.load) best = a;
    best.load += 1;
    return best;
  };

  for (const c of timeoutCases) {
    try {
      // Analista asignado (modo balance) o null → cae al Shift Manager.
      const assignee = pickAssignee();
      const ownerId  = assignee?.id ?? null;
      const reasonLabel = ownerId
        ? `analista ${ownerId} (least-loaded) — SM ${manager.id} como backstop`
        : (usingFallback
            ? `LEADER fallback ${manager.id} (sin Shift Manager designado)`
            : `Shift Manager ${manager.id}`);
      const reason = `Caso sin adopción por ${c.minutes_unadopted} minutos — auto-asignado a ${reasonLabel}`;

      await pgQuery(
        `UPDATE incident_cases_pg
         SET shift_manager_assigned_at = now(),
             shift_manager_ci = $2,
             assigned_role = $3,
             operator_id = CASE WHEN $4::text IS NOT NULL THEN COALESCE(operator_id, $4) ELSE operator_id END,
             adopted_at  = CASE WHEN $4::text IS NOT NULL AND adopted_at IS NULL THEN now() ELSE adopted_at END,
             updated_at = now()
         WHERE id = $1`,
        [c.id, manager.id, manager.role_id, ownerId]
      );

      // R10 (fix #6): si el caso está en NUEVO, transicionar a EN_ANALISIS vía
      // transitionCase(SYSTEM) para que (a) pase por el validador de transiciones,
      // (b) registre STATUS_CHANGE en case_timeline_events con metadata SYSTEM,
      // (c) dispare la heurística shouldAutoEscalate cuando aplique.
      // Para casos ya en EN_ANALISIS (sin Shift Manager) sólo se asigna manager.
      let afterStatus = c.status;
      if (c.status === "NUEVO") {
        try {
          const tr = await transitionCase({
            caseId:     c.id,
            toStatus:   "EN_ANALISIS",
            operatorCi: "SYSTEM",
            roleId:     "SYSTEM",
            reason:     `Auto-transición por timeout — ${reason}`,
            details:    {
              source:            "auto-assign-timeout",
              minutes_unadopted: c.minutes_unadopted,
              manager_id:        manager.id,
            },
          }, io);
          afterStatus = tr?.toStatus ?? "EN_ANALISIS";
        } catch (transErr) {
          logger.warn({ caseId: c.id, err: transErr.message },
            "[workflow:auto-assign] transition NUEVO→EN_ANALISIS failed (assignment OK)");
        }
      }

      await recordAutoAction({
        caseId: c.id,
        actionType: "AUTO_ASSIGN_TIMEOUT",
        targetOperator: ownerId ?? manager.id,
        beforeStatus: c.status, afterStatus,
        reason,
        details: {
          minutes_unadopted: c.minutes_unadopted,
          severity: c.severity,
          owner_id: ownerId,
          manager_id: manager.id,
          manager_name: manager.name,
        },
      });

      // Notificación CRÍTICA al destinatario: el analista asignado (modo balance)
      // o el Shift Manager (fallback). El SM también recibe copia si hubo owner,
      // para que mantenga visibilidad de su turno.
      const notifyTargets = ownerId ? new Set([ownerId, manager.id]) : new Set([manager.id]);
      for (const target of notifyTargets) {
        await createNotification({
          operatorId: target,
          caseId: c.id,
          type: "AUTO_ASSIGN",
          priority: c.severity === "CRITICAL" ? "CRITICAL" : "HIGH",
          title: `[AUTO-ASIGNADO] Caso ${c.severity} sin atención — ${c.minutes_unadopted} min`,
          body: `IOC: ${c.ioc_value ?? "—"} | MITRE: ${c.mitre_tactic_name ?? "—"}\n${reason}`,
          io,
        });
      }

      // También emitir evento global para el dashboard
      if (io) {
        io.emit("workflow:auto_assign", {
          caseId: c.id,
          severity: c.severity,
          managerId: manager.id,
          minutesUnadopted: c.minutes_unadopted,
        });
      }

      assigned++;
    } catch (err) {
      logger.error({ caseId: c.id, err: err.message }, "[workflow:auto-assign] error");
      errors++;
    }
  }

  _wfMetrics.autoAssignTotal += assigned;
  _wfMetrics.lastAutoAssignAt = new Date().toISOString();

  // F6/G1 (audit 2026-06-05): este batch reasigna owner (operator_id) y adopta
  // casos vía UPDATE crudo — bypassa pgUpsertCase, que es donde vive la
  // invalidación de la caché de KPIs por-operador. Sin esto, el panel del LEADER
  // muestra hasta 30s la carga vieja de los analistas recién auto-asignados.
  if (assigned > 0) invalidateCasesKpisCache();

  // Mirror Iceberg + índice canónico (best-effort, no bloquea)
  const assignedIds = timeoutCases.map((c) => c.id);
  if (assignedIds.length) {
    mirrorCasesToIceberg(assignedIds).catch(() => {});
    mirrorCasesToIndex(assignedIds).catch(() => {});
  }

  logger.info({ assigned, errors, manager: manager.id, usingFallback },
    "[workflow:auto-assign] done");
  return { assigned, errors, noShiftManager: usingFallback, usingFallback };
}

// ─────────────────────────────────────────────────────────────────────────────
// TRANSICIÓN DE ESTADO con audit trail completo
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Transiciona el estado de un caso y actualiza el lifecycle_stage.
 * Valida permisos por rol antes de ejecutar.
 *
 * @param {{ caseId, toStatus, operatorCi, roleId, reason, details }} params
 * @param {object} io - Socket.IO instance
 */
export async function transitionCase({ caseId, toStatus, operatorCi, roleId, reason, details = {}, adoptionCode, secondApproverCi, lessonsLearned, classification, escalationMeta, force = false, deferMirror = false }, io) {
  // 1. Cargar estado actual + flags (escalation_suggested, operator_id, lessons_learned)
  const rows = await pgQuery(
    `SELECT id, status, lifecycle_stage, severity, score, mitre_tactic_id,
            escalation_suggested, operator_id, lessons_learned, classification
     FROM incident_cases_pg WHERE id = $1`,
    [caseId]
  );
  if (!rows.length) throw new Error(`Case ${caseId} not found`);
  const c = rows[0];

  // Cierre forzado (LEADER/ADMIN): la matriz TRANSITIONS ya les permite cerrar
  // desde cualquier estado, así que el "force" sólo relaja el gate de postmortem
  // y, más abajo, defaultea la clasificación. Queda auditado para compliance.
  const isForceClose = force === true
    && toStatus === "CERRADO"
    && FORCE_CLOSE_ROLES.has(String(roleId ?? "").toUpperCase());
  if (force === true && toStatus === "CERRADO" && !isForceClose) {
    throw new Error("Cierre forzado (sin postmortem) requiere rol ADMIN o LEADER.");
  }
  if (isForceClose) {
    logger.warn("workflow.force_close_no_postmortem", {
      caseId, operatorCi, roleId, severity: c.severity, fromStatus: c.status,
    });
  }

  // 2. Validar transición
  const check = validateTransition(c.status, toStatus, roleId);
  if (!check.ok) throw new Error(check.reason);

  // 2b. R2: si es adopción (NUEVO → EN_ANALISIS), validar adoption_code
  //     cuando se proporcionó uno. Si el caso tiene un código vigente, exigirlo
  //     (enforcement). Si no hay código generado, permitir adopción directa.
  const isAdoption = c.status === "NUEVO" && toStatus === "EN_ANALISIS" && roleId !== "SYSTEM";
  if (isAdoption) {
    const [pendingCode] = await pgQuery(
      `SELECT code, expires_at, adopted
         FROM adoption_codes
        WHERE incident_id = $1
          AND adopted = false
          AND expires_at > now()`,
      [caseId],
    );
    if (pendingCode) {
      const provided = String(adoptionCode ?? "").trim().toUpperCase();
      if (!provided) {
        throw new Error("Este caso requiere adoption_code para ser adoptado");
      }
      if (provided !== String(pendingCode.code).toUpperCase()) {
        throw new Error("adoption_code inválido o no corresponde a este caso");
      }
      // Marcar código como usado (audit trail)
      await pgQuery(
        `UPDATE adoption_codes
           SET adopted = true, adopted_at = now(),
               operator_id = $2, used_at = now(), used_by_ci = $2
         WHERE incident_id = $1`,
        [caseId, operatorCi],
      );
    }
  }

  // 2c. R7: 4-eyes en cierre FP de casos con escalation_suggested=true.
  //     Requiere: (a) justificación ≥ 80 chars, O (b) second-approver LEADER/ADMIN.
  if (toStatus === "FALSO_POSITIVO"
      && c.escalation_suggested === true
      && roleId !== "SYSTEM") {
    const justification = String(reason ?? "").trim();
    const hasStrongJustification = justification.length >= 80;
    if (!hasStrongJustification) {
      if (!secondApproverCi) {
        throw new Error(
          "Este caso fue marcado para escalación automática. Para cerrarlo como FP requieres: "
          + "(a) justificación de al menos 80 caracteres, O (b) aprobación de un segundo operador LEADER/ADMIN."
        );
      }
      const [approver] = await pgQuery(
        `SELECT id, role_id FROM soc_operators
          WHERE id = $1 AND is_active = true
            AND role_id IN ('LEADER','ADMIN')`,
        [secondApproverCi],
      );
      if (!approver) {
        throw new Error(`Segundo aprobador ${secondApproverCi} inválido (no existe o no es LEADER/ADMIN)`);
      }
      if (approver.id === operatorCi) {
        throw new Error("El segundo aprobador debe ser distinto del operador que cierra el caso");
      }
      details.secondApproverCi = approver.id;
    }
  }

  // 2d. Fix #8: Postmortem obligatorio en CERRADO para severity ≥ MEDIUM.
  //     Excepciones: roleId === 'SYSTEM' (auto-close LOW/NEGLIGIBLE no aplica
  //     porque ya filtra por severidad). El campo se acepta vía param o se exige
  //     que el caso ya lo tenga seteado previamente desde la UI de investigación.
  const SEV_REQUIRES_POSTMORTEM = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
  const POSTMORTEM_MIN_CHARS = 60;
  let lessonsLearnedToWrite = null;
  if (toStatus === "CERRADO"
      && roleId !== "SYSTEM"
      && !isForceClose
      && SEV_REQUIRES_POSTMORTEM.has(String(c.severity ?? "").toUpperCase())) {
    const incoming = String(lessonsLearned ?? "").trim();
    const existing = String(c.lessons_learned ?? "").trim();
    const finalText = incoming.length >= POSTMORTEM_MIN_CHARS
      ? incoming
      : (existing.length >= POSTMORTEM_MIN_CHARS ? existing : "");
    if (!finalText) {
      throw new Error(
        `Postmortem requerido para cerrar casos ${c.severity} (mínimo ${POSTMORTEM_MIN_CHARS} caracteres). `
        + "Plantilla sugerida — respondé las 3 preguntas:\n"
        + "  1) Causa raíz: ¿qué ocurrió y por qué?\n"
        + "  2) Prevención: ¿qué control hubiera evitado este caso?\n"
        + "  3) Mejora de proceso: ¿qué cambia en el playbook/runbook a partir de este aprendizaje?"
      );
    }
    if (incoming.length >= POSTMORTEM_MIN_CHARS && incoming !== existing) {
      lessonsLearnedToWrite = incoming;
    }
  }

  const newStage = STATUS_TO_STAGE[toStatus] ?? c.lifecycle_stage;
  const isClosure = ["CERRADO", "FALSO_POSITIVO"].includes(toStatus);

  // ALTA-5 (audit 2026-06-05): metadata de escalación atómica. Antes el scheduler
  // hacía transitionCase (commit 1: status) + un UPDATE separado (commit 2:
  // escalation_level/escalated_to/…). Un crash entre ambos —o la falta de shift
  // manager— dejaba el caso ESCALADO con escalation_level NULL (huérfano). Ahora
  // la metadata viaja en el MISMO UPDATE del status. escalation_level/_reason/_at
  // se setean siempre que escale; el owner solo si el caller resolvió uno.
  const escLevel  = toStatus === "ESCALADO" ? (escalationMeta?.level ?? null) : null;
  const escTo     = toStatus === "ESCALADO" ? (escalationMeta?.escalatedTo ?? null) : null;
  const escReason = toStatus === "ESCALADO" ? (escalationMeta?.escalationReason ?? null) : null;

  // 2e. P2-9 audit 2026-05-26: classification obligatoria en cierre manual.
  //     Lógica delegada a closureClassification.decideClosureClassification —
  //     misma fuente que routes/incidents.mjs PATCH /status, con tests puros.
  // Cierre forzado sin clasificación explícita → NO_ACTIONABLE (cierre
  // administrativo). Si el operador la envía, se respeta.
  const effectiveClassification = (isForceClose && classification == null && c.classification == null)
    ? "NO_ACTIONABLE"
    : classification;
  const decision = decideClosureClassification({
    toStatus,
    classification: effectiveClassification,
    currentClassification: c.classification,
    roleId,
  });
  if (!decision.ok) {
    throw new Error(decision.message);
  }
  const classificationToWrite = decision.value;

  // 3. Ejecutar UPDATE. Adopción marca también operator_id + adopted_at.
  //    Si vino lessonsLearned nuevo (postmortem en el cierre), lo persiste.
  await pgQuery(
    `UPDATE incident_cases_pg
     SET status = $2,
         lifecycle_stage = $3::text,
         resolved_at = CASE WHEN $4 THEN now() ELSE resolved_at END,
         operator_id = CASE
                         WHEN $5 AND operator_id IS NULL THEN $6
                         WHEN $10::text IS NOT NULL AND operator_id IS NULL THEN $10
                         ELSE operator_id END,
         adopted_at  = CASE
                         WHEN $5 AND adopted_at IS NULL THEN now()
                         WHEN $10::text IS NOT NULL AND adopted_at IS NULL THEN now()
                         ELSE adopted_at END,
         lessons_learned = COALESCE($7, lessons_learned),
         classification  = COALESCE($8, classification),
         is_false_positive = CASE WHEN $8 IN ('FALSE_POSITIVE','FALSO_POSITIVO','AUTO_FP')
                                  THEN true ELSE is_false_positive END,
         escalation_level  = CASE WHEN $9::text  IS NOT NULL THEN COALESCE(escalation_level, $9)  ELSE escalation_level END,
         escalated_to      = CASE WHEN $10::text IS NOT NULL THEN COALESCE(escalated_to, $10)     ELSE escalated_to END,
         escalated_at      = CASE WHEN $9::text  IS NOT NULL THEN COALESCE(escalated_at, now())   ELSE escalated_at END,
         escalation_reason = CASE WHEN $11::text IS NOT NULL THEN COALESCE(escalation_reason, $11) ELSE escalation_reason END,
         -- P2 #19: cadena de escaladas (detecta pingpong L1→L2→L1). Append sólo
         -- cuando esta transición trae metadata de escalación ($9 = nivel).
         escalation_path = CASE WHEN $9::text IS NOT NULL THEN
             COALESCE(escalation_path,'[]'::jsonb) || jsonb_build_array(jsonb_build_object(
               'at', now()::text, 'level', $9, 'to', $10, 'reason', $11, 'by', $6))
           ELSE escalation_path END,
         -- P2 #20: time-in-stage. Al cambiar de fase, acumula los segundos vividos
         -- en la fase anterior en stage_durations y resetea stage_entered_at.
         -- (las referencias a lifecycle_stage/stage_entered_at en el RHS leen el
         --  valor PREVIO de la fila — semántica estándar de UPDATE en Postgres).
         stage_durations = CASE WHEN $3::text IS DISTINCT FROM lifecycle_stage::text THEN
             jsonb_set(COALESCE(stage_durations,'{}'::jsonb),
               ARRAY[COALESCE(lifecycle_stage,'_init')],
               to_jsonb(
                 COALESCE((stage_durations->>COALESCE(lifecycle_stage,'_init'))::numeric, 0)
                 + EXTRACT(EPOCH FROM (now() - COALESCE(stage_entered_at, created_at)))::numeric))
           ELSE stage_durations END,
         stage_entered_at = CASE WHEN $3::text IS DISTINCT FROM lifecycle_stage::text THEN now() ELSE stage_entered_at END,
         updated_at = now()
     WHERE id = $1`,
    [caseId, toStatus, newStage, isClosure, isAdoption, operatorCi, lessonsLearnedToWrite, classificationToWrite, escLevel, escTo, escReason]
  );

  // 3a-bis. F2 (audit 2026-06-05): re-armar SLA en reapertura. Si el caso venía
  // de un estado terminal y vuelve a uno abierto, limpiamos las marcas sla_*_at
  // (idempotencia del scheduler) y sellamos sla_reopened_at. checkSlaBreaches
  // ancla elapsed/ventana a GREATEST(created_at, sla_reopened_at). Sin esto, un
  // caso reabierto por esta puerta (POST /workflow/.../transition, único path
  // que reabre CERRADO) nunca volvía a alertar y leía 400%+ al instante.
  const isReopen = ["CERRADO", "FALSO_POSITIVO"].includes(c.status) && !isClosure;
  if (isReopen) {
    await pgQuery(
      `UPDATE incident_cases_pg
          SET enrichment_data = jsonb_set(
                COALESCE(enrichment_data,'{}'::jsonb)
                  - 'sla_warning_sent_at' - 'sla_alert_sent_at'
                  - 'sla_alert_200_at' - 'sla_alert_400_at',
                '{sla_reopened_at}', to_jsonb(now()::text)),
              resolved_at = NULL
        WHERE id = $1`,
      [caseId],
    ).catch((e) => logger.warn?.({ err: e?.message, caseId }, "[workflow] sla-rearm-on-reopen failed"));
  }

  // 3b. A4 (audit 2026-06-05): al cerrar, las tareas abiertas se marcan SKIPPED.
  //     Antes quedaban OPEN/IN_PROGRESS en un caso terminal → ruido en la UI y
  //     (hasta el fix M1) falsos TASK_SLA_BREACH. Best-effort.
  if (isClosure) {
    await pgQuery(
      `UPDATE case_tasks
          SET status = 'SKIPPED',
              completed_at = COALESCE(completed_at, now()),
              updated_at = now()
        WHERE case_id = $1 AND status IN ('OPEN','IN_PROGRESS')`,
      [caseId],
    ).catch((e) => logger.warn?.({ err: e?.message, caseId }, "[workflow] skip-open-tasks-on-close failed"));
  }

  // 4. Audit trail en timeline
  const tlId = randomUUID();
  await pgQuery(
    `INSERT INTO case_timeline_events
       (id, case_id, event_type, phase, title, description, operator_ci, source, metadata)
     VALUES ($1,$2,'STATUS_CHANGE',$3,$4,$5,$6,'MANUAL',$7)`,
    [
      tlId, caseId, newStage,
      `${c.status} → ${toStatus}`,
      reason ?? null,
      operatorCi,
      JSON.stringify({ fromStatus: c.status, toStatus, roleId, ...details }),
    ]
  );

  // 5. Verificar si debería escalar automáticamente
  if (toStatus === "EN_ANALISIS") {
    const esc = shouldAutoEscalate(c.score, c.mitre_tactic_id);
    if (esc.suggest) {
      await pgQuery(
        `UPDATE incident_cases_pg
         SET escalation_suggested = true, escalation_reason_auto = $2
         WHERE id = $1`,
        [caseId, esc.reason]
      );
    }
  }

  // 6. Mirror al Iceberg + índice canónico (best-effort: errores no bloquean).
  //    Fix #10: AWAIT antes de emitir el socket para que el frontend no vea
  //    estado inconsistente entre PG (ya commit) e Iceberg (en vuelo). Si el
  //    mirror falla se loggea adentro pero el socket igual sale (PG manda).
  //    mirrorCasesToIndex sincroniza legacyhunt_soc.incident_case_index para
  //    que el DAG sync no reabra casos que ya fueron tomados (audit 2026-05-26).
  // deferMirror (acciones en lote): el caller batchea mirror+KPI+socket UNA vez
  // para todos los ids al final. El mirror Iceberg/Trino por-caso es el polo
  // largo (2 escrituras Trino awaited × N casos → timeouts). Batchearlo evita
  // que bulk-status exceda el timeout del cliente.
  if (!deferMirror) {
    await mirrorCasesToIceberg([caseId]).catch(() => {});
    await mirrorCasesToIndex([caseId]).catch(() => {});

    // 6b. F6/G1 (audit 2026-06-05): un cambio de estado mueve casi todos los KPIs
    // de casos (abiertos, por-severidad, MTTC/MTTA, carga por-operador). transitionCase
    // es el path canónico (route socWorkflow, scheduler auto-close, R10 auto-assign)
    // y NINGÚN caller invalidaba la caché → el dashboard leía hasta TTL(30s) el
    // conteo viejo tras cerrar/reabrir/escalar. Centralizado acá para cubrir todos.
    invalidateCasesKpisCache();

    // 7. Emitir evento Socket.IO (post-commit + post-mirror)
    if (io) {
      io.emit("incident:status_change", { caseId, fromStatus: c.status, toStatus, operatorCi });
    }
  }

  return { ok: true, fromStatus: c.status, toStatus, newStage };
}

// ─────────────────────────────────────────────────────────────────────────────
// CREAR HANDOVER REPORT
// ─────────────────────────────────────────────────────────────────────────────

export async function createHandoverReport({ outgoingManagerCi, incomingManagerCi, shift, notes, pendingActions }, io) {
  const id = randomUUID();

  // Snapshot de KPIs del turno (últimas 8 horas)
  const [snapshot] = await pgQuery(`
    SELECT
      COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO'))                      AS open_cases,
      COUNT(*) FILTER (WHERE severity='CRITICAL' AND status NOT IN ('CERRADO','FALSO_POSITIVO')) AS critical_open,
      COUNT(*) FILTER (WHERE status='ESCALADO')                                               AS pending_escalation,
      COUNT(*) FILTER (WHERE status='CERRADO' AND updated_at >= now() - INTERVAL '8 hours')   AS cases_closed_shift,
      COUNT(*) FILTER (WHERE created_at >= now() - INTERVAL '8 hours')                        AS cases_opened_shift,
      -- SLA breached: casos CRITICAL/HIGH con SLA consumido > 100%
      COUNT(*) FILTER (WHERE severity='CRITICAL' AND adopted_at IS NULL
        AND EXTRACT(EPOCH FROM (now()-created_at))/60 > 60)                                   AS sla_breached,
      ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at-created_at))/60)
        FILTER (WHERE adopted_at IS NOT NULL AND created_at >= now()-INTERVAL '8 hours'), 1)  AS mtta_shift,
      ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at-created_at))/60)
        FILTER (WHERE resolved_at IS NOT NULL AND created_at >= now()-INTERVAL '8 hours'), 1) AS mttr_shift
    FROM incident_cases_pg
    WHERE created_at >= now() - INTERVAL '24 hours'
  `);

  const criticalCases = await pgQuery(
    `SELECT id FROM incident_cases_pg
     WHERE severity='CRITICAL' AND status NOT IN ('CERRADO','FALSO_POSITIVO')
     ORDER BY score DESC LIMIT 10`
  );

  await pgQuery(
    `INSERT INTO soc_handover_reports
       (id, outgoing_manager_ci, incoming_manager_ci, shift,
        open_cases_count, critical_open_count, pending_escalation, sla_breached_count,
        cases_closed_shift, cases_opened_shift, mtta_shift_min, mttr_shift_min,
        notes, pending_actions, critical_case_ids)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
    [
      id, outgoingManagerCi, incomingManagerCi ?? null, shift,
      Number(snapshot?.open_cases ?? 0),
      Number(snapshot?.critical_open ?? 0),
      Number(snapshot?.pending_escalation ?? 0),
      Number(snapshot?.sla_breached ?? 0),
      Number(snapshot?.cases_closed_shift ?? 0),
      Number(snapshot?.cases_opened_shift ?? 0),
      snapshot?.mtta_shift ?? null,
      snapshot?.mttr_shift ?? null,
      notes ?? null,
      pendingActions ?? null,
      criticalCases.map(r => r.id),
    ]
  );

  // Notificar al incoming manager
  if (incomingManagerCi) {
    await createNotification({
      operatorId: incomingManagerCi,
      type: "SHIFT_HANDOVER",
      priority: "HIGH",
      title: `Nuevo handover de ${outgoingManagerCi} — Turno ${shift}`,
      body: `${snapshot?.open_cases ?? 0} casos abiertos · ${snapshot?.critical_open ?? 0} críticos · ${snapshot?.sla_breached ?? 0} SLA vencidos`,
      io,
    });
  }

  // Registro automático en auto_actions
  await recordAutoAction({
    caseId: criticalCases[0]?.id ?? "N/A",
    actionType: "HANDOVER_CREATED",
    targetOperator: incomingManagerCi,
    reason: `Handover turno ${shift}: ${outgoingManagerCi} → ${incomingManagerCi ?? "pendiente"}`,
    details: { handoverId: id, shift },
  }).catch(() => {}); // no fatal

  if (io) {
    io.emit("workflow:handover_created", { id, shift, outgoingManagerCi });
  }

  return { id, ...snapshot };
}
