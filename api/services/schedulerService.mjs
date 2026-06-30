/**
 * schedulerService.mjs
 * Scheduler de automatizaciones SOC — sin dependencias externas.
 * Usa setInterval nativo de Node.js.
 *
 * Tareas:
 *  • Cada 5 min  — autoCloseLowNegligible()   cierra LOW/NEGLIGIBLE
 *  • Cada 5 min  — autoAssignTimeoutCases()   asigna al Shift Manager si 30 min sin adopción
 *  • Cada 15 min — checkSlaBreaches()         alerta SLA > 80%
 *  • Cada 5 min  — checkTaskSlaBreaches()     SLA por tarea (preaviso 20 min + breach)
 *  • Cada 15 min — syncDetectedAtFromTrino()  rellena PG.detected_at desde mv_first_alert_per_ioc
 *  • Cada 1 min  — notifyCriticalCases()      Slack + push para CRITICAL/HIGH sin avisar
 *  • Cada 1 hora — updateOperatorKpis()       actualiza métricas de operadores
 */

import { randomUUID } from "node:crypto";
import { pgQuery, withPgClient } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { bootstrapCaseTasks } from "./casePlaybookService.mjs";
import {
  autoCloseLowNegligible,
  autoAssignTimeoutCases,
  autoMergeDuplicates,
  createNotification,
  getActiveShiftManager,
  transitionCase,
} from "./workflowEngine.mjs";
import { sendDailyReport, reportConfigured, parseScheduleUtc } from "./reportService.mjs";
import { sendFollowupDigest, followupDigestConfigured } from "./followupDigestService.mjs";
import { sendSlackAlert, isSlackEnabled } from "../slack-notify.mjs";
import { getCachedSla } from "./slaConfig.mjs";
import { broadcastPush, webPushReady } from "./webPushService.mjs";
import { runTrinoQuery } from "./trinoReader.mjs";
import { runThreatPatternScan, runAuthBruteforceScan } from "./threatPatternScan.mjs";
import { runTicketMaintenance } from "./ticketAutomation.mjs";
import { drainDue as drainWebhooks } from "./webhookService.mjs";
import { runFindingAnalysis, findingAnalystAvailable } from "./threatFindingAnalyst.mjs";
import { reconcileHuntFindingsCases, runHuntAutoOpen, huntAutoOpenEnabled } from "./huntCaseSync.mjs";
import { runCaseVerdictAnalyst, caseVerdictAnalystAvailable } from "./caseVerdictAnalyst.mjs";
import { detectIncompletePlaybookCloses, playbookComplianceEnabled } from "./playbookComplianceService.mjs";
import { invalidateCasesKpisCache } from "../routes/caseInvestigation.mjs";

const FIVE_MIN  = 5  * 60 * 1000;
const FIFTEEN   = 15 * 60 * 1000;
const ONE_HOUR  = 60 * 60 * 1000;
const FOUR_HOUR = 4  * 60 * 60 * 1000;
const ONE_MIN   = 60 * 1000;

// Motor de patrones de caza externa (F1a): gate por env (default on, kill-switch
// "false"). Bounded (LIMIT 300, 90s timeout, poda por día sobre la MV slim).
const threatScanEnabled = () =>
  (process.env.HUNT_SCAN_ENABLED ?? "true").trim().toLowerCase() === "true";

// R6: Advisory-lock keys (int4 estables por tarea).
// Usamos `pg_try_advisory_lock(key)` para serializar auto-close vs auto-assign
// (ambos operan sobre incident_cases_pg y pueden pisarse si coinciden).
// También protegen contra solape entre ticks del setInterval si una ejecución
// tarda > FIVE_MIN (dejaría huérfano el lock hasta que la sesión termine).
//
// Exportados para que los endpoints manuales (`/automation/trigger-auto-close`
// y `/automation/trigger-auto-assign` en socWorkflow.mjs) compartan los mismos
// locks que los ticks del scheduler — evita que un disparo manual concurra
// con un tick automático sobre las mismas filas.
export const LOCK_AUTO_CLOSE      = 4711001;
export const LOCK_AUTO_ASSIGN     = 4711002;
const LOCK_SLA_CHECK       = 4711003;
const LOCK_METRICS_ROLLUP  = 4711004;
const LOCK_NOTIFY_CRITICAL = 4711005;
const LOCK_TASK_SLA_CHECK  = 4711006;
const LOCK_DETECTED_AT_SYNC = 4711007;
const LOCK_TASKS_BOOTSTRAP  = 4711008;
const LOCK_AUTO_MERGE       = 4711009;   // P0 #3 auto-merge de duplicados
const LOCK_RECURRENCE_SURGE = 4711010;   // P2 #8 alerta surge de recurrencia
const LOCK_AUTO_TRIAGE_MED  = 4711011;   // P2 #4 auto-triaje MEDIUM
export const LOCK_FOLLOWUP_DIGEST = 4711012;   // digest de supervisión de seguimiento (6h)
export const LOCK_THREAT_SCAN     = 4711013;   // motor de patrones de caza externa (4h)
export const LOCK_THREAT_ANALYST  = 4711014;   // analista LLM de findings de caza (15min)
export const LOCK_VERDICT_ANALYST = 4711015;   // analista LLM de veredicto por caso, gobernado por SLA (15min)
export const LOCK_PLAYBOOK_COMPLIANCE = 4711016;   // guardia de cierres con playbook incompleto (§3, 15min)
const LOCK_HUNT_RECONCILE = 4711017;   // sync estado caso→finding de caza (Fase 2, 15min)
const LOCK_HUNT_AUTOOPEN  = 4711018;   // auto-open gated de findings de caza (Fase 3, 15min)
const LOCK_TICKET_MAINT   = 4711019;   // F6: recordatorios + auto-cierre de tickets (1h)
const LOCK_WEBHOOK_DRAIN  = 4711020;   // F7: reintento de webhooks salientes pendientes (2min)

/**
 * Ejecuta `fn` solo si el advisory-lock `key` se adquiere. El lock vive en la
 * sesión de un cliente dedicado del pool (withPgClient); al terminar se
 * libera explícitamente y la conexión vuelve al pool. Si otra instancia del
 * scheduler tiene el lock, devuelve `{ skipped: "lock_busy" }` sin bloquear.
 */
export async function withAdvisoryLock(key, fn) {
  return withPgClient(async (client) => {
    const { rows } = await client.query(
      `SELECT pg_try_advisory_lock($1) AS acquired`,
      [key],
    );
    if (!rows[0]?.acquired) {
      return { skipped: "lock_busy" };
    }
    try {
      return await fn();
    } finally {
      await client.query(`SELECT pg_advisory_unlock($1)`, [key]).catch(() => {});
    }
  });
}

/** @type {ReturnType<typeof setInterval>[]} */
const timers = [];
let _io = null;

const _sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * P2 #10 — reintento con backoff exponencial + jitter para jobs que tocan PG/Trino.
 * Un blip transitorio (ECONNREFUSED, Trino reiniciando) ya no salta el tick entero:
 * reintenta `tries` veces. El jitter desincroniza instancias múltiples del scheduler.
 * Si agota reintentos, relanza para que el catch del tick lo loguee como antes.
 */
async function withRetry(label, fn, { tries = 2, baseMs = 2000 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= tries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt < tries) {
        const backoff = baseMs * 2 ** attempt + Math.floor(Math.random() * 500);
        logger.warn({ label, attempt: attempt + 1, backoff, err: err?.message },
          "[scheduler] transient error — retrying");
        await _sleep(backoff);
      }
    }
  }
  throw lastErr;
}

/** Métricas acumulativas del scheduler (desde arranque del proceso). */
const _metrics = {
  autoClosedTotal:        0,
  autoAssignedTotal:      0,
  autoAssignSkipsNoSM:    0, // ciclos donde no había Shift Manager activo
  slaBreachesAlerted:     0,
  kpiRefreshes:           0,
  criticalSlackNotified:  0, // casos CRITICAL auto-notificados a Slack (#3b)
  tasksBootstrappedTotal: 0, // case_tasks insertadas por el job bootstrap (P3.7)
  casesBootstrappedTotal: 0, // casos cubiertos por bootstrap-missing-tasks
  threatFindingsUpserted: 0, // findings de caza externa materializados (F1a)
  threatFindingsAnalyzed: 0, // findings analizados por el LLM (F2)
  lastRun: {
    autoClose:       /** @type {string|null} */ (null),
    autoAssign:      /** @type {string|null} */ (null),
    slaCheck:        /** @type {string|null} */ (null),
    kpiUpdate:       /** @type {string|null} */ (null),
    notifyCritical:  /** @type {string|null} */ (null),
    detectedAtSync:  /** @type {string|null} */ (null),
    tasksBootstrap:  /** @type {string|null} */ (null),
    threatScan:      /** @type {string|null} */ (null),
    threatAnalyst:   /** @type {string|null} */ (null),
  },
};

/** Devuelve las métricas del scheduler para el endpoint de salud del sistema. */
export function getSchedulerMetrics() {
  return { ..._metrics, lastRun: { ..._metrics.lastRun } };
}

// ── SLA breach detection ──────────────────────────────────────────────────────

/**
 * Devuelve los LEADER/ADMIN activos para alertas escalables (preaviso SLA, etc).
 * Se invocan ad-hoc dentro del check; cache no necesaria (lista pequeña, freq 15 min).
 */
async function getActiveLeaders() {
  return pgQuery(
    `SELECT id FROM soc_operators
      WHERE role_id IN ('LEADER','ADMIN') AND is_active = true`,
  );
}

async function checkSlaBreaches() {
  try {
    // ── Fase 1: PREAVISO ≥ 70% & < 80% (notificación previa al breach) ──────
    // M5 (2026-05-13): SLA viene del cache (sla_config). Pasamos los 5 valores
    // en segundos como params; el CASE los selecciona por severidad.
    // Idempotente vía enrichment_data.sla_warning_sent_at + double-check atómico.
    const sla = getCachedSla();
    const slaParams = [
      sla.sla_critical_sec, sla.sla_high_sec, sla.sla_medium_sec,
      sla.sla_low_sec, sla.sla_negligible_sec,
    ];
    const approaching = await pgQuery(`
      WITH params AS (
        SELECT c.*,
          (CASE c.severity
            WHEN 'CRITICAL'   THEN $1::int
            WHEN 'HIGH'       THEN $2::int
            WHEN 'MEDIUM'     THEN $3::int
            WHEN 'LOW'        THEN $4::int
            WHEN 'NEGLIGIBLE' THEN $5::int
          END) / 60 AS sla_min,
          -- Ancla SLA: created_at salvo que el caso haya sido reabierto (audit
          -- 2026-06-05). Al reabrir un terminal, PATCH /status sella
          -- sla_reopened_at y limpia las marcas; acá le damos reloj fresco.
          GREATEST(c.created_at,
            COALESCE((c.enrichment_data->>'sla_reopened_at')::timestamptz, c.created_at)
          ) AS sla_anchor
        FROM incident_cases_pg c
      )
      SELECT
        id, severity, status,
        operator_id, shift_manager_ci,
        ROUND(EXTRACT(EPOCH FROM (now()-sla_anchor))/60) AS elapsed_min,
        sla_min
      FROM params c
      WHERE c.status NOT IN ('CERRADO','FALSO_POSITIVO','MONITOREADO')  -- F4: MONITOREADO pausa el SLA (espera deliberada)
        AND c.severity IN ('CRITICAL','HIGH','MEDIUM')  -- M6 audit 2026-06-05: MEDIUM también vigilado
        AND c.sla_anchor >= now() - INTERVAL '7 days'
        AND c.sla_min > 0
        AND EXTRACT(EPOCH FROM (now()-c.sla_anchor))/60 / c.sla_min
            BETWEEN 0.7 AND 0.7999
        AND (c.enrichment_data->>'sla_warning_sent_at') IS NULL
        AND (c.enrichment_data->>'sla_alert_sent_at')   IS NULL
    `, slaParams);

    if (approaching.length) {
      const leaders = await getActiveLeaders().catch(() => []);
      const leaderIds = leaders.map((l) => l.id);
      for (const c of approaching) {
        const claimed = await pgQuery(
          `UPDATE incident_cases_pg
              SET enrichment_data = jsonb_set(
                COALESCE(enrichment_data,'{}'), '{sla_warning_sent_at}',
                to_jsonb(now()::text))
            WHERE id = $1
              AND (enrichment_data->>'sla_warning_sent_at') IS NULL
            RETURNING id`,
          [c.id],
        );
        if (!claimed.length) continue;
        const pct = Math.round((Number(c.elapsed_min) / Number(c.sla_min)) * 100);
        const targets = new Set([c.operator_id, c.shift_manager_ci, ...leaderIds].filter(Boolean));
        for (const target of targets) {
          await createNotification({
            operatorId: target, caseId: c.id,
            type: "SLA_APPROACHING",
            priority: c.severity === "CRITICAL" ? "HIGH" : "NORMAL",
            title: `Preaviso SLA ${pct}% — ${c.severity}`,
            body: `Caso ${c.id.slice(0,7).toUpperCase()} llegó al ${pct}% del SLA `
                 +`(${c.elapsed_min}/${c.sla_min} min). Quedan ~${Math.max(0, c.sla_min - c.elapsed_min)} min `
                 +`antes de breach.`,
            io: _io,
          }).catch(() => {});
        }
      }
      logger.info({ count: approaching.length }, "[scheduler] SLA approaching warnings sent");
    }

    // ── Fase 2: BREACH escalonado (80%, 200%, 400%) ────────────────────────
    // R9: Envolver cada detección+UPDATE en una transacción por caso evita
    //     que dos ticks concurrentes del scheduler (o una reentrada tras
    //     restart) envíen la misma alerta dos veces.
    //
    // P1-7 audit 2026-05-26: notificación escalonada — además del primer aviso
    // a 80%, re-notificamos a 200% y 400% para casos perpetuamente vencidos.
    // Cada hito tiene su propia marca `sla_alert_<milestone>_at` para que
    // no se repita dentro del mismo nivel. La query trae todos los casos
    // ≥80% y la lógica per-row decide qué hito disparar.
    const breaches = await pgQuery(`
      WITH params AS (
        SELECT c.*,
          (CASE c.severity
            WHEN 'CRITICAL'   THEN $1::int
            WHEN 'HIGH'       THEN $2::int
            WHEN 'MEDIUM'     THEN $3::int
            WHEN 'LOW'        THEN $4::int
            WHEN 'NEGLIGIBLE' THEN $5::int
          END) / 60 AS sla_min,
          -- Ancla SLA re-armable en reapertura (audit 2026-06-05). Ver Fase 1.
          GREATEST(c.created_at,
            COALESCE((c.enrichment_data->>'sla_reopened_at')::timestamptz, c.created_at)
          ) AS sla_anchor
        FROM incident_cases_pg c
      )
      SELECT
        id, severity, status,
        operator_id, shift_manager_ci,
        ROUND(EXTRACT(EPOCH FROM (now()-sla_anchor))/60) AS elapsed_min,
        sla_min,
        (enrichment_data->>'sla_alert_sent_at')  IS NOT NULL AS sent_80,
        (enrichment_data->>'sla_alert_200_at')   IS NOT NULL AS sent_200,
        (enrichment_data->>'sla_alert_400_at')   IS NOT NULL AS sent_400
      FROM params c
      WHERE c.status NOT IN ('CERRADO','FALSO_POSITIVO','MONITOREADO')  -- F4: MONITOREADO pausa el SLA (espera deliberada)
        AND c.severity IN ('CRITICAL','HIGH','MEDIUM')  -- M6 audit 2026-06-05: MEDIUM también vigilado
        AND c.sla_anchor >= now() - INTERVAL '30 days'
        AND c.sla_min > 0
        AND EXTRACT(EPOCH FROM (now()-c.sla_anchor))/60 / c.sla_min >= 0.8
    `, slaParams);

    for (const c of breaches) {
      const pct = Math.round((Number(c.elapsed_min) / Number(c.sla_min)) * 100);

      // Elegir milestone: 400% → 200% → 80%. Solo dispara si:
      //   1. El % consumido supera el umbral del milestone.
      //   2. Ese milestone aún no fue notificado.
      let milestone = null;
      let jsonKey   = null;
      if (pct >= 400 && !c.sent_400) {
        milestone = 400; jsonKey = "sla_alert_400_at";
      } else if (pct >= 200 && !c.sent_200) {
        milestone = 200; jsonKey = "sla_alert_200_at";
      } else if (!c.sent_80) {
        milestone = 80; jsonKey = "sla_alert_sent_at";
      } else {
        continue; // todos los hitos aplicables ya notificados
      }

      // R9: Double-check atomico per milestone.
      // P2 #19: además sellamos sla_breach_at en el primer breach (columna nueva,
      // mig 087) para tener histórico de breach por caso, no sólo el % en KPIs.
      const claimed = await pgQuery(
        `UPDATE incident_cases_pg
            SET enrichment_data = jsonb_set(
              COALESCE(enrichment_data,'{}'), $2::text[],
              to_jsonb(now()::text)),
                sla_breach_at = COALESCE(sla_breach_at, now())
          WHERE id = $1
            AND (enrichment_data->>$3) IS NULL
          RETURNING id`,
        [c.id, `{${jsonKey}}`, jsonKey],
      );
      if (!claimed.length) continue;  // otro proceso ya alertó

      // Notificación SLA_BREACH a operador asignado y Shift Manager.
      // El título incluye el milestone para que el operador distinga
      // re-avisos (200%/400%) de la primera notificación (80%).
      const milestoneLabel = milestone === 80 ? "preaviso" : `re-aviso ${milestone}%`;
      for (const target of [c.operator_id, c.shift_manager_ci].filter(Boolean)) {
        await createNotification({
          operatorId: target, caseId: c.id,
          type: "SLA_BREACH",
          priority: c.severity === "CRITICAL" ? "CRITICAL" : "HIGH",
          title: `SLA ${pct}% consumido — ${c.severity} (${milestoneLabel})`,
          body: `Caso ${c.id.slice(0,7).toUpperCase()} lleva ${c.elapsed_min} min (SLA: ${c.sla_min} min)`,
          io: _io,
        });
      }

      // P2-10 audit 2026-05-26: web push para SLA breach. Aumenta la
      // probabilidad de que el operador note el aviso aún si tiene el
      // dashboard en segundo plano.
      if (webPushReady() && (milestone === 200 || milestone === 400 || c.severity === "CRITICAL")) {
        void broadcastPush({
          title: `⏰ SLA ${pct}% — ${c.severity}`,
          body:  `Caso ${c.id.slice(0,7).toUpperCase()} — ${milestoneLabel}`,
          url:   `/gestion?investigate=${c.id}`,
          tag:   `sla:${c.id}:${milestone}`,
        }).catch(() => {});
      }

      // Auto-escalación por SLA vencido (P2 audit flujo 2026-06-06):
      //   · CRITICAL al 100% (inmediato).
      //   · HIGH a SLA_HIGH_ESCALATE_PCT (default 200% — muy vencido) para no
      //     dejar HIGH vencidos sin escalar pero evitando ruido en el primer breach.
      const highEscalatePct = Number(process.env.SLA_HIGH_ESCALATE_PCT) || 200;
      // P1 #1 (backlog 2026-06-07): MEDIUM vencido también auto-escala (transición
      // real auditada vía transitionCase, no sólo notificación). Más conservador
      // que HIGH — sólo cuando está MUY vencido (default 400%) para no saturar L3
      // con MEDIUM ruidosos en el primer breach.
      const mediumEscalatePct = Number(process.env.SLA_MEDIUM_ESCALATE_PCT) || 400;
      const shouldEscalate =
        !["ESCALADO","CERRADO","FALSO_POSITIVO"].includes(c.status) &&
        ((c.severity === "CRITICAL" && pct >= 100) ||
         (c.severity === "HIGH"     && pct >= highEscalatePct) ||
         (c.severity === "MEDIUM"   && pct >= mediumEscalatePct));
      if (shouldEscalate) {
        try {
          // ALTA-5 (audit 2026-06-05): metadata de escalación atómica. Resolvemos
          // el shift manager ANTES de transicionar y la metadata viaja en el mismo
          // UPDATE del status (escalationMeta) → sin ventana de crash entre commits.
          // Aunque no haya owner, escalation_level/_reason/_at quedan seteados, así
          // el caso NO nace huérfano (escalation_level NULL).
          const manager = await getActiveShiftManager();
          const targetOwner = manager?.id ?? c.shift_manager_ci ?? null;
          await transitionCase({
            caseId:      c.id,
            toStatus:    "ESCALADO",
            operatorCi:  "SYSTEM",
            roleId:      "SYSTEM",
            reason:      `SLA vencido (${pct}%) — auto-escalación por sistema`,
            details:     { elapsed_min: c.elapsed_min, sla_min: c.sla_min },
            escalationMeta: {
              level:            "AUTO_SLA",
              escalatedTo:      targetOwner,
              escalationReason: targetOwner
                ? `Auto-escalación SLA ${pct}% — asignado a shift manager`
                : `Auto-escalación SLA ${pct}% — sin shift manager activo (pendiente de owner)`,
            },
          }, _io);

          if (!targetOwner) {
            logger.warn({ caseId: c.id, pct },
              "[scheduler] auto-escalation sin shift manager — escalado sin owner hasta tener uno");
          }

          if (manager) {
            await createNotification({
              operatorId: manager.id,
              caseId:     c.id,
              type:       "P1_ESCALATION",
              priority:   "CRITICAL",
              title:      `[AUTO-ESCALADO] SLA vencido — ${c.severity}`,
              body:       `Caso ${c.id.slice(0,7).toUpperCase()} (${pct}% SLA) auto-escalado`,
              io:         _io,
            });
          }
          logger.warn({ caseId: c.id, pct, severity: c.severity, owner: targetOwner }, "[scheduler] SLA breach → auto-escalated");
        } catch (escErr) {
          logger.error({ caseId: c.id, err: escErr.message }, "[scheduler] auto-escalation failed");
        }
      }
      // (marcado sla_alert_sent_at ya realizado arriba con double-check atómico)
    }
    if (breaches.length) logger.info({ count: breaches.length }, "[scheduler] SLA breach alerts sent");
  } catch (err) {
    logger.error({ err: err.message }, "[scheduler] checkSlaBreaches failed");
  }
}

/**
 * Guardrail (audit 2026-05-26): repara casos en status='ESCALADO' con
 * escalation_level=NULL. Estos son huérfanos creados por algún path que
 * no escribió la metadata de escalación (históricamente el scheduler SLA
 * auto-escalation; ya corregido pero pueden aparecer si se agrega otro path).
 *
 * Estrategia conservadora:
 *   - Sólo toca filas que ya tienen `shift_manager_ci` registrado (anchor
 *     de identidad — sin él no sabemos a quién asignar).
 *   - Setea escalation_level='AUTO_SLA_RECOVERED' para distinguir del normal.
 *   - Asigna operator_id si está NULL para que el caso tenga owner.
 *   - Loguea WARN con count + sample para detectar paths defectuosos.
 *
 * Idempotente: re-correr no toca filas ya recuperadas.
 */
/**
 * Sync detected_at desde Trino (mv_first_alert_per_ioc) hacia
 * incident_cases_pg. Resuelve el MTTD vacío del audit 2026-05-27 — los casos
 * auto-clasificados quedaban con detected_at NULL porque persistCase no
 * conocía el first_alert_ts en el momento del INSERT.
 *
 * Estrategia:
 *   1. Trino: para cada (ioc_value, dt) en incident_classifications de los
 *      últimos 2 días, buscar el MIN(ingest_ts) cross-source en
 *      mv_first_alert_per_ioc.
 *   2. PG: bulk UPDATE de incident_cases_pg.detected_at usando unnest, solo
 *      filas con detected_at IS NULL para preservar valores ya seteados.
 *
 * Idempotente: WHERE detected_at IS NULL evita sobreescribir. Si Trino está
 * caído o devuelve 0 filas, no-op silenciosa.
 */
async function syncDetectedAtFromTrino() {
  try {
    const tr = await runTrinoQuery(`
      SELECT
        ic.ioc_value,
        CAST(ic.dt AS varchar) AS dt,
        CAST(fa.first_alert_ts AS varchar) AS first_alert_ts
      FROM minio_iceberg.hunting.incident_classifications ic
      JOIN minio_iceberg.hunting.mv_first_alert_per_ioc fa
        ON fa.ioc_value = ic.ioc_value AND fa.dt = ic.dt
      WHERE ic.dt >= current_date - INTERVAL '2' DAY
        AND fa.first_alert_ts IS NOT NULL
    `, { timeoutMs: 30_000 });

    if (!tr.ok) {
      logger.warn({ err: tr.error }, "[scheduler] detected_at sync — trino query failed");
      return { synced: 0 };
    }
    if (!tr.rows.length) return { synced: 0 };

    // Normalizar timestamps Trino → ISO 8601 (PG-friendly).
    const ioc = [], dts = [], ts = [];
    for (const r of tr.rows) {
      const raw = String(r.first_alert_ts ?? "");
      if (!raw) continue;
      const iso = raw.replace(/\sUTC$/i, "Z").replace(" ", "T");
      ioc.push(r.ioc_value);
      dts.push(r.dt);
      ts.push(iso);
    }

    // Bulk UPDATE: solo toca filas con detected_at NULL y delta <= 24h
    // (paridad con clamp MTTD post-mig 063).
    const result = await pgQuery(
      `UPDATE incident_cases_pg cp
          SET detected_at = u.ts::timestamptz
         FROM unnest($1::text[], $2::date[], $3::timestamptz[]) AS u(ioc_value, dt, ts)
        WHERE cp.ioc_value     = u.ioc_value
          AND cp.created_at::date = u.dt
          AND cp.detected_at  IS NULL
          AND u.ts < cp.created_at
          AND EXTRACT(EPOCH FROM cp.created_at - u.ts) <= 86400
       RETURNING cp.id`,
      [ioc, dts, ts],
    );
    const synced = result.length;
    if (synced > 0) {
      logger.info({ synced, candidates: tr.rows.length },
        "[scheduler] detected_at sync — PG updated from Trino mv_first_alert_per_ioc");
    }
    return { synced };
  } catch (err) {
    logger.error({ err: err.message }, "[scheduler] syncDetectedAtFromTrino failed");
    return { synced: 0 };
  }
}

async function reconcileOrphanEscalations() {
  try {
    const r = await pgQuery(`
      WITH orphans AS (
        SELECT id, shift_manager_ci, severity, created_at
          FROM incident_cases_pg
         WHERE status = 'ESCALADO'
           -- ALTA-5: además de escalation_level NULL (huérfano clásico), recoge
           -- los ESCALADO sin owner (auto-escalación sin shift manager activo).
           AND (escalation_level IS NULL OR operator_id IS NULL)
           AND shift_manager_ci IS NOT NULL
         LIMIT 500
      )
      UPDATE incident_cases_pg t
         SET escalation_level  = COALESCE(t.escalation_level, 'AUTO_SLA_RECOVERED'),
             escalated_to      = COALESCE(t.escalated_to, o.shift_manager_ci),
             escalated_at      = COALESCE(t.escalated_at, t.updated_at, NOW()),
             escalation_reason = COALESCE(t.escalation_reason,
                                          'Recovery scheduler — escalation huérfana (auto-fix)'),
             operator_id       = COALESCE(t.operator_id, o.shift_manager_ci),
             adopted_at        = COALESCE(t.adopted_at, NOW()),
             updated_at        = NOW()
        FROM orphans o
       WHERE t.id = o.id
       RETURNING t.id, t.severity
    `);
    if (r.length > 0) {
      const bySev = r.reduce((acc, row) => {
        acc[row.severity] = (acc[row.severity] ?? 0) + 1;
        return acc;
      }, {});
      logger.warn({ recovered: r.length, bySev, sample: r.slice(0, 3).map((x) => x.id) },
        "[scheduler] orphan ESCALADO recovered — investigar qué path los crea");
      // F6/G1: el recovery setea operator_id/adopted_at → mueve carga por-operador.
      invalidateCasesKpisCache();
    }
    return { recovered: r.length };
  } catch (err) {
    logger.error({ err: err.message }, "[scheduler] reconcileOrphanEscalations failed");
    return { recovered: 0 };
  }
}

/**
 * R6 (audit 2026-06-05): caducidad de MONITOREADO.
 *
 * MONITOREADO pausa el SLA (F4) — es una espera deliberada — pero sin caducidad
 * un caso parqueado ahí nunca re-alerta ni vuelve a triaje: se vuelve un agujero
 * negro (intel insuficiente que nadie re-mira). Tras MONITOREADO_MAX_DWELL_DAYS
 * (def 7) sin updates, lo devolvemos a EN_ANALISIS vía transitionCase SYSTEM —
 * que re-arma el SLA y deja audit trail — y notificamos al owner para que decida
 * cerrar o accionar. Cap por tick (MONITOREADO_REVIEW_BATCH, def 50); si se llena
 * se loguea (sin truncado silencioso) y el resto cae al próximo tick.
 */
async function reEvaluateStaleMonitored() {
  const days  = Math.max(1, Number(process.env.MONITOREADO_MAX_DWELL_DAYS ?? 7) || 7);
  const batch = Math.max(1, Number(process.env.MONITOREADO_REVIEW_BATCH ?? 50) || 50);
  let reEvaluated = 0;
  try {
    const stale = await pgQuery(
      `SELECT id, operator_id
         FROM incident_cases_pg
        WHERE status = 'MONITOREADO'
          AND updated_at < NOW() - ($1 || ' days')::interval
        ORDER BY updated_at ASC
        LIMIT $2`,
      [String(days), batch],
    );
    if (!stale.length) return { reEvaluated: 0 };

    for (const c of stale) {
      try {
        await transitionCase({
          caseId:     c.id,
          toStatus:   "EN_ANALISIS",
          operatorCi: "SYSTEM",
          roleId:     "SYSTEM",
          reason:     `Re-evaluación automática: ${days}d en MONITOREADO sin cambios — requiere decisión (cerrar o accionar).`,
          details:    { dwell_days: days, trigger: "MONITOREADO_DWELL_MAX" },
        }, _io);
        if (c.operator_id) {
          await createNotification({
            operatorId: c.operator_id,
            caseId:     c.id,
            type:       "MONITOR_REVIEW",
            priority:   "MEDIUM",
            title:      `Caso ${String(c.id).slice(0, 7).toUpperCase()} de vuelta a análisis`,
            body:       `Llevaba ${days}d en MONITOREADO sin cambios. Revisá si corresponde cerrar o accionar.`,
            io:         _io,
          }).catch(() => {});
        }
        reEvaluated++;
      } catch (e) {
        logger.warn({ caseId: c.id, err: e?.message }, "[scheduler] reEvaluateStaleMonitored: transición falló");
      }
    }
    if (stale.length === batch) {
      logger.info({ batch }, "[scheduler] reEvaluateStaleMonitored: batch lleno — quedan más para el próximo tick");
    }
    if (reEvaluated > 0) {
      invalidateCasesKpisCache();
      logger.info({ reEvaluated, days }, "[scheduler] MONITOREADO estancados → EN_ANALISIS");
    }
    return { reEvaluated };
  } catch (err) {
    logger.error({ err: err.message }, "[scheduler] reEvaluateStaleMonitored failed");
    return { reEvaluated: 0 };
  }
}

/**
 * Bootstrap de case_tasks para casos abiertos sin playbook (audit 2026-05-27 P3.7).
 *
 * Por qué existe: `casePlaybookService.bootstrapCaseTasks` se llama on-insert
 * en `autoClassifyController.persistCase` (fix-forward), pero el grueso de
 * casos lo crea el DAG Python `incident_cases_sync_daily.py` que NO ejecuta
 * JS — esos casos quedan sin tasks. Otros flujos (voluntary, manual) también
 * podrían omitirlo. Este job cierra el gap independiente del creation path.
 *
 * Diseño:
 *   - Tick cada 5 min con advisory lock LOCK_TASKS_BOOTSTRAP.
 *   - Cap 200 casos por tick — evita stampede en arranque tras down prolongado.
 *   - LEFT JOIN + filter NULL para sólo agarrar casos sin tasks.
 *   - Orden por (severity DESC, score DESC, created_at ASC) — CRITICAL/HIGH
 *     primero para que un analista activo encuentre el playbook al abrir.
 *   - Idempotente vía `bootstrapCaseTasks` (no inserta si el caso ya tiene).
 *
 * Métricas (`_metrics.tasksBootstrappedTotal/_metrics.casesBootstrappedTotal`)
 * expuestas en `/api/admin/scheduler/metrics` para verificar cobertura.
 */
async function bootstrapMissingTasks() {
  const CAP = 200;
  const cases = await pgQuery(
    `SELECT c.id, c.severity, c.score, c.source_log,
            c.ioc_value, c.ioc_type,
            c.mitre_tactic_id, c.mitre_tactic_name,
            c.operator_id, c.enrichment_data
       FROM incident_cases_pg c
      WHERE NOT EXISTS (
              SELECT 1 FROM case_tasks t WHERE t.case_id = c.id
            )
        AND c.status NOT IN ('CERRADO','FALSO_POSITIVO')
      ORDER BY
        CASE c.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
        c.score DESC NULLS LAST,
        c.created_at ASC
      LIMIT ${CAP}`,
  );
  if (cases.length === 0) return { processed: 0, inserted: 0 };

  let processed = 0, inserted = 0, failures = 0;
  for (const c of cases) {
    try {
      // enrichment_data: PG JSONB viene como objeto; el fallback {} hace que
      // generatePlaybook use defaults razonables (sin lookups VT/Shodan).
      const enrich = c.enrichment_data && typeof c.enrichment_data === "object"
        ? c.enrichment_data
        : {};
      const r = await bootstrapCaseTasks(
        c.id, c, enrich,
        "scheduler_bootstrap",
        pgQuery,
        { randomUUIDFn: randomUUID },
      );
      processed++;
      inserted += r.inserted ?? 0;
    } catch (err) {
      failures++;
      logger.warn({ caseId: c.id, err: err.message }, "[scheduler] tasks_bootstrap_one_failed");
    }
  }
  if (processed > 0) {
    _metrics.tasksBootstrappedTotal += inserted;
    _metrics.casesBootstrappedTotal += processed;
    logger.info(
      { processed, inserted, failures, severityHead: cases[0]?.severity },
      "[scheduler] bootstrapMissingTasks",
    );
  }
  return { processed, inserted, failures };
}

/**
 * Task-level SLA tracking (Follow-up 6). El check de caso (checkSlaBreaches)
 * sólo cubre CRITICAL/HIGH globales. Los casos abiertos desde Vigilancia/
 * Credenciales suelen ser LOW pero traen 8-10 tareas NIST con due_at concreto
 * por playbook. El analista necesita aviso antes de que una tarea breach.
 *
 * Dos fases (mismo patrón que checkSlaBreaches):
 *   • SLA_WARNING — task OPEN/IN_PROGRESS, due_at en ventana ≤ 20 min,
 *                   sla_warned_at IS NULL → notifica al assignee + shift mgr.
 *   • SLA_BREACH  — task OPEN/IN_PROGRESS, due_at < now, sla_breached_at IS NULL
 *                   → notifica + inserta evento en case_timeline_events.
 *
 * Idempotencia: UPDATE WHERE sla_X_at IS NULL en el mismo statement que el
 * lookup garantiza una sola notificación por tarea, aun con ticks solapados.
 */
async function checkTaskSlaBreaches() {
  try {
    // ── Fase 1: PREAVISO — tareas a ≤ 20 min de due_at ─────────────────────
    // El UPDATE atómico con RETURNING reclama la tarea y devuelve el contexto
    // necesario para notificar. Si dos schedulers compiten, sólo uno reclama.
    const warned = await pgQuery(`
      UPDATE case_tasks t
         SET sla_warned_at = now(),
             updated_at    = now()
       WHERE t.status IN ('OPEN','IN_PROGRESS')
         AND t.due_at IS NOT NULL
         AND t.due_at > now()
         AND t.due_at <= now() + INTERVAL '20 minutes'
         AND t.sla_warned_at IS NULL
         AND t.sla_breached_at IS NULL
         -- M1 audit 2026-06-05: no vigilar tareas de casos ya cerrados.
         AND EXISTS (
           SELECT 1 FROM incident_cases_pg c
            WHERE c.id = t.case_id
              AND c.status NOT IN ('CERRADO','FALSO_POSITIVO'))
      RETURNING
        t.id, t.case_id, t.title, t.phase, t.assignee, t.due_at,
        ROUND(EXTRACT(EPOCH FROM (t.due_at - now()))/60) AS minutes_remaining
    `);

    if (warned.length) {
      for (const w of warned) {
        // Buscar contexto del caso (severity + shift mgr) para el priority.
        let caseRow = null;
        try {
          const rows = await pgQuery(
            `SELECT severity, shift_manager_ci FROM incident_cases_pg WHERE id = $1`,
            [w.case_id],
          );
          caseRow = rows[0] ?? null;
        } catch { /* mejor esfuerzo */ }

        const targets = new Set([w.assignee, caseRow?.shift_manager_ci].filter(Boolean));
        const sev      = String(caseRow?.severity ?? "MEDIUM").toUpperCase();
        const priority = sev === "CRITICAL" ? "HIGH" : sev === "HIGH" ? "HIGH" : "NORMAL";
        for (const target of targets) {
          await createNotification({
            operatorId: target,
            caseId:     w.case_id,
            type:       "TASK_SLA_APPROACHING",
            priority,
            title:      `Tarea próxima a vencer — ${w.minutes_remaining} min restantes`,
            body:       `Tarea "${w.title}" (fase ${w.phase}) del caso ${w.case_id.slice(0,7).toUpperCase()} vence pronto.`,
            io:         _io,
          }).catch(() => {});
        }
      }
      logger.info({ count: warned.length }, "[scheduler] task SLA preavisos enviados");
    }

    // ── Fase 2: BREACH — tareas que pasaron el due_at sin completar ────────
    const breached = await pgQuery(`
      UPDATE case_tasks t
         SET sla_breached_at = now(),
             updated_at      = now()
       WHERE t.status IN ('OPEN','IN_PROGRESS')
         AND t.due_at IS NOT NULL
         AND t.due_at <= now()
         AND t.sla_breached_at IS NULL
         -- M1 audit 2026-06-05: no marcar breach en tareas de casos ya cerrados.
         AND EXISTS (
           SELECT 1 FROM incident_cases_pg c
            WHERE c.id = t.case_id
              AND c.status NOT IN ('CERRADO','FALSO_POSITIVO'))
      RETURNING
        t.id, t.case_id, t.title, t.phase, t.assignee, t.due_at,
        ROUND(EXTRACT(EPOCH FROM (now() - t.due_at))/60) AS minutes_overdue
    `);

    if (breached.length) {
      for (const b of breached) {
        let caseRow = null;
        try {
          const rows = await pgQuery(
            `SELECT severity, shift_manager_ci FROM incident_cases_pg WHERE id = $1`,
            [b.case_id],
          );
          caseRow = rows[0] ?? null;
        } catch { /* */ }

        const targets = new Set([b.assignee, caseRow?.shift_manager_ci].filter(Boolean));
        const sev      = String(caseRow?.severity ?? "MEDIUM").toUpperCase();
        const priority = sev === "CRITICAL" ? "CRITICAL" : sev === "HIGH" ? "HIGH" : "NORMAL";
        for (const target of targets) {
          await createNotification({
            operatorId: target,
            caseId:     b.case_id,
            type:       "TASK_SLA_BREACH",
            priority,
            title:      `Tarea vencida (+${b.minutes_overdue} min) — ${b.title}`,
            body:       `La tarea "${b.title}" (fase ${b.phase}) del caso ${b.case_id.slice(0,7).toUpperCase()} excedió su SLA hace ${b.minutes_overdue} min.`,
            io:         _io,
          }).catch(() => {});
        }

        // Audit en el timeline del caso.
        try {
          await pgQuery(
            `INSERT INTO case_timeline_events
               (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source, metadata)
             VALUES (gen_random_uuid()::text, $1, now(),
               'SLA_BREACH', 'IDENTIFICATION',
               $2, $3, 'system', 'scheduler', $4)`,
            [
              b.case_id,
              `SLA breach: tarea "${b.title}"`,
              `La tarea ${b.id} (fase ${b.phase}) venció hace ${b.minutes_overdue} min sin completarse.`,
              JSON.stringify({ taskId: b.id, minutesOverdue: b.minutes_overdue }),
            ],
          );
        } catch (e) {
          logger.warn({ err: e?.message, taskId: b.id }, "[scheduler] task SLA timeline insert failed");
        }
      }
      logger.info({ count: breached.length }, "[scheduler] task SLA breaches detectados");
    }
  } catch (err) {
    logger.error({ err: err.message }, "[scheduler] checkTaskSlaBreaches failed");
  }
}

// ── R8. Snapshot diario de métricas de operadores ────────────────────────────

// ── Auto-notify CRITICAL a Slack ─────────────────────────────────────────────

/**
 * Notifica a Slack los casos CRITICAL creados automáticamente por el DAG
 * (incident_cases_sync_daily) que aún no tienen slack_notified_at.
 *
 * El DAG crea el caso pero no dispara Slack. Los handlers manuales
 * (/adopt, /escalate, /notify-slack) sólo alertan en su evento específico.
 * Sin esta tarea, un CRITICAL recién nacido podía quedar horas sin aviso
 * al canal hasta que alguien lo adoptara manualmente.
 *
 * Idempotencia: UPDATE atómico con `slack_notified_at IS NULL` en el WHERE —
 * si dos ticks del scheduler se solapan (o hay otra instancia del API),
 * sólo uno reclamará cada caso y enviará el mensaje.
 *
 * Anti-flood: ventana de 6 horas (casos más viejos se asumen ya conocidos)
 * + batch de 10 mensajes por tick + ventana mínima de 60 s desde creación
 * para dar tiempo al scoring/enriquecimiento a estabilizarse.
 */
async function notifyCriticalCases() {
  if (!isSlackEnabled()) return { skipped: "slack_disabled" };

  // P2-11 audit 2026-05-26: además de CRITICAL/NUEVO, incluimos HIGH/ESCALADO
  // sin notificar — antes el flujo manual /escalate fallaba en silencio (24%
  // de cobertura) y los HIGH escalados quedaban invisibles al canal.
  const rows = await pgQuery(`
    SELECT id, ioc_value, ioc_type, source_log, score, severity, status,
           mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
           recommended_action, created_at
    FROM incident_cases_pg
    WHERE (
            (severity = 'CRITICAL' AND status = 'NUEVO')
         OR (severity IN ('HIGH','CRITICAL') AND status = 'ESCALADO')
          )
      AND slack_notified_at IS NULL
      AND created_at >= now() - INTERVAL '6 hours'
      AND created_at <= now() - INTERVAL '1 minute'
    ORDER BY created_at ASC
    LIMIT 10
  `);
  if (!rows.length) return { notified: 0 };

  let notified = 0;
  for (const c of rows) {
    const claimed = await pgQuery(
      `UPDATE incident_cases_pg
          SET slack_notified_at = now()
        WHERE id = $1 AND slack_notified_at IS NULL
      RETURNING id`,
      [c.id],
    );
    if (!claimed.length) continue; // race: otro tick lo tomó

    const mitreParts = [];
    if (c.mitre_tactic_id && c.mitre_tactic_name)
      mitreParts.push(`${c.mitre_tactic_id} - ${c.mitre_tactic_name}`);
    if (c.mitre_technique_id) mitreParts.push(c.mitre_technique_id);
    const mitre = mitreParts.length ? mitreParts.join(" / ") : "—";

    // Header distinto según trigger (NUEVO CRITICAL vs ESCALADO HIGH/CRITICAL).
    const header = c.status === "ESCALADO"
      ? `⚠️ *${c.severity} ESCALADO — sin aviso a canal*`
      : "🚨 *CASO CRÍTICO DETECTADO — NUEVO*";
    const text =
      `${header}\n` +
      `*Caso:* \`${c.id}\`\n` +
      `*IOC:* ${c.ioc_value ?? "—"} (${c.ioc_type ?? "?"})\n` +
      `*Origen:* ${c.source_log ?? "—"}\n` +
      `*Score:* ${c.score ?? "?"}\n` +
      `*MITRE:* ${mitre}\n` +
      `*Acción sugerida:* ${c.recommended_action ?? "—"}`;

    const r = await sendSlackAlert({ text });
    if (!r.ok) {
      // revertir claim para reintentar en próximo tick
      await pgQuery(
        `UPDATE incident_cases_pg SET slack_notified_at = NULL WHERE id = $1`,
        [c.id],
      ).catch(() => {});
      logger.warn({ caseId: c.id, err: r.error, status: r.status },
        "[scheduler] notifyCriticalCases slack send failed — revert claim");
      continue;
    }

    // P2-10 audit 2026-05-26: web push paralelo al Slack para que el operador
    // que tiene el browser abierto reciba el aviso sin depender de Slack.
    // Best-effort: errores no afectan el flujo (Slack ya fue OK).
    if (webPushReady()) {
      void broadcastPush({
        title: `🚨 CRITICAL nuevo — ${c.ioc_value ?? "sin IOC"}`,
        body:  `Score ${c.score ?? "?"} · ${c.source_log ?? "—"} · ${mitre}`,
        url:   `/gestion?investigate=${c.id}`,
        tag:   `incident:${c.id}`,
      }).catch((err) =>
        logger.warn({ caseId: c.id, err: String(err?.message ?? err) },
          "[scheduler] notifyCriticalCases push falló (no bloquea)"),
      );
    }

    notified++;
  }
  return { notified };
}

/**
 * Persiste un snapshot diario en `operator_metrics_daily`.
 * Se ejecuta una vez por día (al arrancar si no existe el snapshot de hoy, y
 * luego cada hora chequeamos si hay que generar el de ayer/hoy).
 * Idempotente: ON CONFLICT DO UPDATE.
 */
async function rollupOperatorMetricsDaily() {
  try {
    await pgQuery(`
      INSERT INTO operator_metrics_daily (
        snapshot_date, operator_id,
        cases_adopted, cases_closed, cases_fp, cases_escalated,
        avg_mtta_min, avg_mttr_min, fp_rate_pct, score_avg
      )
      SELECT
        CURRENT_DATE - INTERVAL '1 day',
        operator_id,
        COUNT(*)                                                      AS cases_adopted,
        COUNT(*) FILTER (WHERE status='CERRADO')                      AS cases_closed,
        COUNT(*) FILTER (WHERE status='FALSO_POSITIVO')               AS cases_fp,
        COUNT(*) FILTER (WHERE status='ESCALADO')                     AS cases_escalated,
        ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at - created_at))/60)
          FILTER (WHERE adopted_at IS NOT NULL), 2)                   AS avg_mtta,
        ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/60)
          FILTER (WHERE resolved_at IS NOT NULL), 2)                  AS avg_mttr,
        ROUND(100.0 * COUNT(*) FILTER (WHERE status='FALSO_POSITIVO')
          / NULLIF(COUNT(*), 0), 2)                                   AS fp_rate,
        ROUND(AVG(score), 2)                                          AS score_avg
      FROM incident_cases_pg
      WHERE operator_id IS NOT NULL
        AND adopted_at::date = CURRENT_DATE - INTERVAL '1 day'
      GROUP BY operator_id
      ON CONFLICT (snapshot_date, operator_id) DO UPDATE SET
        cases_adopted   = EXCLUDED.cases_adopted,
        cases_closed    = EXCLUDED.cases_closed,
        cases_fp        = EXCLUDED.cases_fp,
        cases_escalated = EXCLUDED.cases_escalated,
        avg_mtta_min    = EXCLUDED.avg_mtta_min,
        avg_mttr_min    = EXCLUDED.avg_mttr_min,
        fp_rate_pct     = EXCLUDED.fp_rate_pct,
        score_avg       = EXCLUDED.score_avg,
        computed_at     = now()
    `);
    logger.info("[scheduler] operator_metrics_daily rollup for yesterday OK");
  } catch (err) {
    logger.error({ err: err.message }, "[scheduler] rollupOperatorMetricsDaily failed");
  }
}

// ── Actualizar KPIs de operadores ─────────────────────────────────────────────

async function updateOperatorKpis() {
  try {
    await pgQuery(`
      UPDATE soc_operators o SET
        cases_adopted  = sub.adopted,
        cases_closed   = sub.closed,
        fp_count       = sub.fp,
        avg_mtta_min   = sub.mtta,
        avg_mttr_min   = sub.mttr,
        last_active_at = sub.last_active
      FROM (
        SELECT operator_id,
          COUNT(*)                                                        AS adopted,
          COUNT(*) FILTER (WHERE status='CERRADO')                        AS closed,
          COUNT(*) FILTER (WHERE status='FALSO_POSITIVO')                 AS fp,
          ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at-created_at))/60)
            FILTER (WHERE adopted_at IS NOT NULL), 1)                    AS mtta,
          ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at-created_at))/60)
            FILTER (WHERE resolved_at IS NOT NULL), 1)                   AS mttr,
          MAX(COALESCE(adopted_at, created_at))                           AS last_active
        FROM incident_cases_pg
        WHERE operator_id IS NOT NULL
          AND created_at >= now() - INTERVAL '30 days'
        GROUP BY operator_id
      ) sub
      WHERE o.id = sub.operator_id
    `);
    logger.debug("[scheduler] operator KPIs updated");
  } catch (err) {
    logger.error({ err: err.message }, "[scheduler] updateOperatorKpis failed");
  }
}

// ── Surge de recurrencia (P2 #8) ──────────────────────────────────────────────

/**
 * Alerta cuando un caso abierto acumula recurrencias rápidamente: occurrence_count
 * alto + last_seen reciente. Un IOC suprimido que reaparece muchas veces en poco
 * tiempo suele ser movimiento lateral este-oeste o un atacante persistente, no
 * ruido. Dato ya capturado (occurrence_count/last_seen) → lo convertimos en señal.
 *
 * Dedup por niveles: se alerta al cruzar el umbral y se re-alerta sólo al duplicar
 * el conteo del último aviso (surge_alerted_count), evitando spam por cada +1.
 */
async function checkRecurrenceSurge() {
  const threshold = Math.max(2, Number(process.env.RECURRENCE_SURGE_THRESHOLD ?? 20) || 20);
  const rows = await pgQuery(
    `SELECT id, severity, ioc_value, operator_id, shift_manager_ci,
            COALESCE(occurrence_count,1) AS occ,
            (enrichment_data->>'surge_alerted_count') AS last_alerted
       FROM incident_cases_pg
      WHERE status NOT IN ('CERRADO','FALSO_POSITIVO')
        AND COALESCE(occurrence_count,1) >= $1
        AND last_seen >= now() - INTERVAL '1 hour'`,
    [threshold],
  ).catch(() => []);

  let alerted = 0;
  for (const c of rows) {
    const occ = Number(c.occ);
    const lastAlerted = Number(c.last_alerted) || 0;
    // Primer aviso al cruzar el umbral; re-aviso sólo al duplicar el conteo previo.
    if (lastAlerted > 0 && occ < lastAlerted * 2) continue;

    const claimed = await pgQuery(
      `UPDATE incident_cases_pg
          SET enrichment_data = jsonb_set(
                jsonb_set(COALESCE(enrichment_data,'{}'::jsonb),
                          '{surge_alerted_count}', to_jsonb($2::int)),
                '{surge_alerted_at}', to_jsonb(now()::text))
        WHERE id = $1
          AND COALESCE((enrichment_data->>'surge_alerted_count')::int, 0) = $3
        RETURNING id`,
      [c.id, occ, lastAlerted],
    ).catch(() => []);
    if (!claimed.length) continue;   // otro tick ya alertó este nivel

    const leaders = await getActiveLeaders().catch(() => []);
    const targets = new Set([c.operator_id, c.shift_manager_ci, ...leaders.map((l) => l.id)].filter(Boolean));
    for (const target of targets) {
      await createNotification({
        operatorId: target, caseId: c.id,
        type: "RECURRENCE_SURGE",
        priority: c.severity === "CRITICAL" ? "CRITICAL" : "HIGH",
        title: `Surge de recurrencia — ${occ}× ${c.severity}`,
        body: `IOC ${c.ioc_value ?? "—"} reapareció ${occ} veces (última <1h). `
            + `Posible movimiento lateral o atacante persistente — revisar caso ${c.id.slice(0,7).toUpperCase()}.`,
        io: _io,
      }).catch(() => {});
    }
    alerted++;
  }
  return { alerted, scanned: rows.length };
}

// ── Auto-triaje MEDIUM (P2 #4) ────────────────────────────────────────────────

/**
 * Drena el limbo de MEDIUM (que hoy nunca se auto-cierra ni se promueve: queda en
 * MONITOREADO esperando humano). Opt-in `AUTO_TRIAGE_MEDIUM=on`. Dos políticas:
 *   (a) PROMOVER por evidencia: MEDIUM con occurrence_count ≥ umbral → ESCALADO
 *       (transición SYSTEM auditada). La acumulación de recurrencias es señal real.
 *   (b) CERRAR por inactividad: MEDIUM en MONITOREADO sin recurrencia en N días →
 *       CERRADO/NO_ACTIONABLE. SYSTEM está exento del gate de postmortem; igual
 *       grabamos un lessons_learned del sistema para trazabilidad.
 * Todo vía transitionCase → hereda supresión (trigger 078), mirror e invalidación KPI.
 */
async function autoTriageMedium(io) {
  if ((process.env.AUTO_TRIAGE_MEDIUM ?? "off").toLowerCase() !== "on") return { disabled: true };
  const promoteAt = Math.max(2, Number(process.env.AUTO_TRIAGE_MEDIUM_PROMOTE ?? 10) || 10);
  const staleDays = Math.max(1, Number(process.env.AUTO_TRIAGE_MEDIUM_STALE_DAYS ?? 14) || 14);
  const cap = 100;
  let promoted = 0, closed = 0;

  // (a) Promover por evidencia acumulada.
  const toPromote = await pgQuery(
    `SELECT id FROM incident_cases_pg
      WHERE upper(severity) = 'MEDIUM'
        AND status IN ('NUEVO','EN_ANALISIS','MONITOREADO')
        AND COALESCE(occurrence_count,1) >= $1
      LIMIT $2`,
    [promoteAt, cap],
  ).catch(() => []);
  for (const c of toPromote) {
    try {
      await transitionCase({
        caseId: c.id, toStatus: "ESCALADO", operatorCi: "SYSTEM", roleId: "SYSTEM",
        reason: `Auto-triaje MEDIUM: evidencia acumulada (≥${promoteAt} recurrencias) — escalado por el sistema`,
        escalationMeta: { level: "AUTO_EVIDENCE", escalatedTo: null,
          escalationReason: `Auto-escalación por acumulación de evidencia (occurrence ≥ ${promoteAt})` },
      }, io);
      promoted++;
    } catch (e) { logger.debug({ caseId: c.id, err: e?.message }, "[scheduler] autoTriageMedium promote skip"); }
  }

  // (b) Cerrar MONITOREADO sin recurrencia reciente.
  const toClose = await pgQuery(
    `SELECT id FROM incident_cases_pg
      WHERE upper(severity) = 'MEDIUM'
        AND status = 'MONITOREADO'
        AND COALESCE(last_seen, updated_at, created_at) < now() - ($1 || ' days')::interval
        AND COALESCE(occurrence_count,1) < $2
      LIMIT $3`,
    [String(staleDays), promoteAt, cap],
  ).catch(() => []);
  for (const c of toClose) {
    try {
      await transitionCase({
        caseId: c.id, toStatus: "CERRADO", operatorCi: "SYSTEM", roleId: "SYSTEM",
        reason: `Auto-triaje MEDIUM: ${staleDays} días en MONITOREADO sin nueva recurrencia`,
        classification: "NO_ACTIONABLE",
        lessonsLearned: `Cierre automático del sistema: caso MEDIUM en MONITOREADO sin recurrencia `
          + `durante ${staleDays} días y sin evidencia adicional acumulada. Drenaje del limbo MEDIUM `
          + `según política AUTO_TRIAGE_MEDIUM. Reabrir si reaparece el IOC.`,
      }, io);
      closed++;
    } catch (e) { logger.debug({ caseId: c.id, err: e?.message }, "[scheduler] autoTriageMedium close skip"); }
  }

  if (promoted || closed) logger.info({ promoted, closed }, "[scheduler] autoTriageMedium");
  return { promoted, closed };
}

// ── Iniciar scheduler ─────────────────────────────────────────────────────────

export function startScheduler(io) {
  _io = io;
  logger.info("[scheduler] starting SOC workflow scheduler (setInterval)");

  // Tarea 1: Auto-cierre LOW/NEGLIGIBLE — cada 5 min
  // R6: serializado vía advisory lock (LOCK_AUTO_CLOSE).
  timers.push(setInterval(async () => {
    try {
      const result = await withAdvisoryLock(LOCK_AUTO_CLOSE, async () => {
        return withRetry("autoClose", () => autoCloseLowNegligible(_io));
      });
      if (result?.skipped) {
        logger.debug({ reason: result.skipped }, "[scheduler] autoClose skipped (lock busy)");
        return;
      }
      _metrics.autoClosedTotal += result.closed ?? 0;
      _metrics.lastRun.autoClose = new Date().toISOString();
      if (result.closed > 0) logger.info(result, "[scheduler] autoCloseLowNegligible");
    } catch (err) { logger.error({ err: err.message }, "[scheduler] autoCloseLowNegligible failed"); }
  }, FIVE_MIN));

  // Tarea 1b: Auto-merge de duplicados (P0 #3) — cada 15 min.
  // Opt-in (AUTO_MERGE_DUPLICATES=on). Serializado con LOCK_AUTO_MERGE; usa su
  // propio lock (no toca los mismos candidatos que auto-close: este opera sobre
  // clusters IOC+táctica de severidad ≤ MEDIUM, cierra duplicados → el trigger
  // mig 078 los suprime atómicamente).
  timers.push(setInterval(async () => {
    try {
      const result = await withAdvisoryLock(LOCK_AUTO_MERGE, async () => autoMergeDuplicates(_io));
      if (result?.skipped) {
        logger.debug({ reason: result.skipped }, "[scheduler] autoMerge skipped (lock busy)");
        return;
      }
      if (result?.disabled) return;
      _metrics.autoMergedTotal = (_metrics.autoMergedTotal ?? 0) + (result.merged ?? 0);
      _metrics.lastRun.autoMerge = new Date().toISOString();
      if (result.merged > 0) logger.info(result, "[scheduler] autoMergeDuplicates");
    } catch (err) { logger.error({ err: err.message }, "[scheduler] autoMergeDuplicates failed"); }
  }, FIFTEEN));

  // Tarea 1c: Surge de recurrencia (P2 #8) — cada 15 min.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_RECURRENCE_SURGE, () => withRetry("recurrenceSurge", checkRecurrenceSurge));
      if (r?.skipped) return;
      if (r?.alerted > 0) logger.info(r, "[scheduler] recurrence surge alerts");
    } catch (err) { logger.error({ err: err.message }, "[scheduler] checkRecurrenceSurge failed"); }
  }, FIFTEEN));

  // Tarea 1d: Auto-triaje MEDIUM (P2 #4, opt-in) — cada 15 min.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_AUTO_TRIAGE_MED, () => withRetry("autoTriageMedium", () => autoTriageMedium(_io)));
      if (r?.skipped || r?.disabled) return;
      if ((r?.promoted ?? 0) + (r?.closed ?? 0) > 0) logger.info(r, "[scheduler] autoTriageMedium");
    } catch (err) { logger.error({ err: err.message }, "[scheduler] autoTriageMedium failed"); }
  }, FIFTEEN));

  // Tarea 2: Auto-asignación 30 min sin adopción — cada 5 min
  // R6: serializado vía advisory lock (LOCK_AUTO_ASSIGN). Además coopera con
  // LOCK_AUTO_CLOSE porque ambos se ejecutan en el mismo tick — la lógica
  // garantiza que si auto-close marcó un caso como CERRADO, auto-assign no
  // lo reverá (v_timeout_cases excluye status='CERRADO').
  timers.push(setInterval(async () => {
    try {
      const result = await withAdvisoryLock(LOCK_AUTO_ASSIGN, async () => {
        return withRetry("autoAssign", () => autoAssignTimeoutCases(_io));
      });
      if (result?.skipped) {
        logger.debug({ reason: result.skipped }, "[scheduler] autoAssign skipped (lock busy)");
        return;
      }
      _metrics.autoAssignedTotal += result.assigned ?? 0;
      _metrics.lastRun.autoAssign = new Date().toISOString();
      if (result.noShiftManager) {
        _metrics.autoAssignSkipsNoSM++;
        logger.warn({ skipsTotal: _metrics.autoAssignSkipsNoSM, usingFallback: result.usingFallback },
          "[scheduler] auto-assign: no shift manager (fallback used)");
      } else if (result.assigned > 0) {
        logger.info(result, "[scheduler] autoAssignTimeoutCases");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] autoAssignTimeoutCases failed"); }
  }, FIVE_MIN));

  // Tarea 3: SLA breaches — cada 15 min
  // R6: serializado vía advisory lock (LOCK_SLA_CHECK).
  // Audit 2026-05-26: incluye reconcileOrphanEscalations al final del tick
  // para auto-reparar cualquier caso ESCALADO sin metadata. Mismo lock —
  // ambas operaciones son ligeras y deben correr secuencialmente.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_SLA_CHECK, async () => {
        await checkSlaBreaches();
        await reconcileOrphanEscalations();
        await reEvaluateStaleMonitored();  // R6: caducidad de MONITOREADO
        return {};
      });
      if (r?.skipped) return;
      _metrics.lastRun.slaCheck = new Date().toISOString();
    } catch { /* ya logueado en checkSlaBreaches/reconcileOrphanEscalations */ }
  }, FIFTEEN));

  // Tarea 3c: Task-level SLA — cada 5 min
  // Granularidad fina: los casos de Vigilancia/Credenciales tienen 8-10
  // tareas NIST con due_at por playbook (buildLeakIntelTasks). Cada 5 min
  // detectamos tareas próximas a vencer (preaviso) o ya vencidas (breach).
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_TASK_SLA_CHECK, async () => {
        await checkTaskSlaBreaches();
        return {};
      });
      if (r?.skipped) return;
      _metrics.lastRun.taskSlaCheck = new Date().toISOString();
    } catch { /* ya logueado en checkTaskSlaBreaches */ }
  }, FIVE_MIN));

  // Tarea 3d: Sync detected_at PG ← Trino mv_first_alert_per_ioc — cada 15 min
  // Single source of truth: la UI lee TODO desde incident_cases_pg (gestión).
  // El DAG cross-source mantiene mv_first_alert_per_ioc; este job sincroniza
  // ese valor al campo PG.detected_at, habilitando MTTD operacional desde la
  // función soc_kpis_window sin override Trino en el panel.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_DETECTED_AT_SYNC, () => withRetry("detectedAtSync", syncDetectedAtFromTrino));
      if (r?.skipped) return;
      if (r?.synced > 0) _metrics.lastRun.detectedAtSync = new Date().toISOString();
    } catch (err) {
      logger.error({ err: err.message }, "[scheduler] detected_at sync failed");
    }
  }, FIFTEEN));

  // Tarea 3e: Motor de patrones de caza externa (F1a) — cada 4h.
  // Escanea la MV `fortigate_events_slim` (ya refrescada c/30min, poda por día)
  // buscando CLASES de amenaza externa (P1 egress a nube foránea, P2 beaconing)
  // y las materializa en `hunt_findings` (UPSERT idempotente por dedup_key). El
  // analista LLM (F2) y el Panel del Manager las consumen. 4h alinea con la
  // cadencia de enriquecimiento y mantiene holgado el Trino 1-nodo; la query es
  // bounded (LIMIT 300, 90s timeout). Serializado con LOCK_THREAT_SCAN para no
  // solapar dos instancias del scheduler ni un disparo manual (/api/intel/scan).
  timers.push(setInterval(async () => {
    if (!threatScanEnabled()) return;
    try {
      const r = await withAdvisoryLock(LOCK_THREAT_SCAN, () => runThreatPatternScan({ logger }));
      if (r?.skipped) return;
      if (r?.ok) {
        _metrics.threatFindingsUpserted = (_metrics.threatFindingsUpserted ?? 0) + (r.upserted ?? 0);
        _metrics.lastRun.threatScan = new Date().toISOString();
        if (r.upserted > 0) logger.info(r, "[scheduler] threatPatternScan");
      } else {
        logger.warn({ error: r?.error }, "[scheduler] threatPatternScan failed");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] threatPatternScan failed"); }
  }, FOUR_HOUR));

  // Tarea 3f: Analista LLM de findings de caza externa (F2) — cada 15 min.
  // Drena los findings NEW de hunt_findings pasándolos por el LLM local (qwen3.5
  // vía Ollama) → veredicto razonado + acción recomendada + status ANALYZED. Lote
  // chico (HUNT_ANALYST_BATCH=6) porque cada finding es ~10-40s de razonamiento;
  // 15min vacía el backlog suavemente sin acaparar el LLM. Gated (LLM activo +
  // HUNT_ANALYST_ENABLED). Lock propio: no compite con el scan (4h) ni con PG.
  timers.push(setInterval(async () => {
    if (!findingAnalystAvailable()) return;
    try {
      const r = await withAdvisoryLock(LOCK_THREAT_ANALYST, () => runFindingAnalysis({ logger }));
      if (r?.skipped) return;
      if (r?.analyzed > 0) {
        _metrics.threatFindingsAnalyzed = (_metrics.threatFindingsAnalyzed ?? 0) + r.analyzed;
        _metrics.lastRun.threatAnalyst = new Date().toISOString();
        logger.info(r, "[scheduler] threatFindingAnalyst");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] threatFindingAnalyst failed"); }
  }, FIFTEEN));

  // Tarea 3i: Sync Caza Externa → Gestión, Fase 2 (reconcile) — cada 15 min.
  // Mantiene coherente el enlace finding↔caso cuando el caso muta por fuera del
  // panel: repunta enlaces a casos mergeados y baja a 'dismissed/TRIAGED' los
  // findings cuyo caso se cerró FALSO_POSITIVO. Idempotente, siempre on, sin LLM.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_HUNT_RECONCILE, () => reconcileHuntFindingsCases({ logger }));
      if (r?.skipped) return;
      if ((r?.repointed ?? 0) + (r?.dismissed ?? 0) > 0) {
        _metrics.lastRun.huntReconcile = new Date().toISOString();
        logger.info(r, "[scheduler] huntCaseSync.reconcile");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] huntCaseSync.reconcile failed"); }
  }, FIFTEEN));

  // Tarea 3j: Auto-open gated de findings de caza, Fase 3 — cada 15 min.
  // GATED OFF (HUNT_AUTOOPEN_ENABLED). Doble gate: veredicto LLM malicious + alta
  // confianza + severidad HIGH/CRITICAL + blocklist DURA (screenIocMalice) — el
  // veredicto LLM solo no basta (sobre-marca infra popular). Reusa
  // openCaseFromHuntFinding (dedup + enlace + timeline). Lote chico.
  timers.push(setInterval(async () => {
    if (!huntAutoOpenEnabled()) return;
    try {
      const r = await withAdvisoryLock(LOCK_HUNT_AUTOOPEN, () => runHuntAutoOpen({ logger }));
      if (r?.skipped) return;
      if ((r?.opened ?? 0) > 0) {
        _metrics.huntAutoOpened = (_metrics.huntAutoOpened ?? 0) + r.opened;
        _metrics.lastRun.huntAutoOpen = new Date().toISOString();
        logger.info(r, "[scheduler] huntCaseSync.autoOpen");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] huntCaseSync.autoOpen failed"); }
  }, FIFTEEN));

  // Tarea 3h: Analista LLM de VEREDICTO por caso, gobernado por SLA — cada 15 min.
  // Emite el veredicto honesto sobre casos ABIERTOS aún sin veredicto, ANTES de que
  // venzan (ventana pre-vencimiento, orden por urgencia). Lote chico (default 3) y
  // secuencial: comparte la GPU única con el chat en vivo + el F2. Gated OFF por
  // defecto (CASE_VERDICT_ANALYST_ENABLED). Lock propio. Ver §1 de
  // docs/MEJORAS-ANALISTA-LLM-2026-06-24.md.
  timers.push(setInterval(async () => {
    if (!caseVerdictAnalystAvailable()) return;
    try {
      const r = await withAdvisoryLock(LOCK_VERDICT_ANALYST, () => runCaseVerdictAnalyst({ logger }));
      if (r?.skipped) return;
      if (r?.analyzed > 0) {
        _metrics.caseVerdictsWritten = (_metrics.caseVerdictsWritten ?? 0) + r.analyzed;
        _metrics.lastRun.caseVerdictAnalyst = new Date().toISOString();
        logger.info(r, "[scheduler] caseVerdictAnalyst");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] caseVerdictAnalyst failed"); }
  }, FIFTEEN));

  // Tarea 3i: Guardia de cierres con playbook incompleto (§3a) — cada 15 min.
  // Detecta casos cerrados por un analista con tareas de playbook pendientes, deja
  // auditoría en el timeline y notifica al operador + LEADER/ADMIN. NO bloquea el
  // cierre (sólo avisa). Gated OFF (PLAYBOOK_COMPLIANCE_ENABLED). Idempotente.
  timers.push(setInterval(async () => {
    if (!playbookComplianceEnabled()) return;
    try {
      const r = await withAdvisoryLock(LOCK_PLAYBOOK_COMPLIANCE, () => detectIncompletePlaybookCloses({ logger, io: _io }));
      if (r?.skipped) return;
      if (r?.flagged > 0) {
        _metrics.playbookIncompleteFlagged = (_metrics.playbookIncompleteFlagged ?? 0) + r.flagged;
        _metrics.lastRun.playbookCompliance = new Date().toISOString();
        logger.info(r, "[scheduler] playbookCompliance");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] playbookCompliance failed"); }
  }, FIFTEEN));

  // Tarea 3k: Mantenimiento del Sistema de Tickets (F6) — cada 1 h.
  // Recordatorios al cliente cuando waiting_on='CLIENT' supera el umbral, y
  // auto-cierre de tickets RESUELTO sin actividad. Config en ticket_automation_config.
  // Idempotente, lock propio, no compite con Trino. Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_TICKET_MAINT, () => runTicketMaintenance());
      if (r?.skipped) return;
      if ((r?.reminders?.sent ?? 0) + (r?.autoclose?.closed ?? 0) > 0) {
        _metrics.lastRun.ticketMaintenance = new Date().toISOString();
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] ticketMaintenance failed"); }
  }, ONE_HOUR));

  // Tarea 3l: Drenado de webhooks salientes (F7) — cada 2 min.
  // Reintenta las entregas PENDIENTES vencidas (backoff exponencial) hacia el
  // sistema del cliente. La entrega inmediata ya ocurre fire-and-forget al emitir
  // el evento; este tick recupera las que fallaron. Lock propio, no toca Trino.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_WEBHOOK_DRAIN, () => drainWebhooks(50));
      if (r?.skipped) return;
      if ((r?.picked ?? 0) > 0) logger.info(r, "[scheduler] webhook drain");
    } catch (err) { logger.error({ err: err.message }, "[scheduler] webhook drain failed"); }
  }, 2 * ONE_MIN));

  // Tarea 3g: Brute-force de login (P4, F1b) — cada 4 h.
  // Detecta IPs atacantes con N fallos de login (SSL-VPN ssl-login-fail) sobre el
  // raw FortiGate y las materializa en hunt_findings (auth_bruteforce). Sin MV:
  // la señal es escasa y el filtro es la columna tipada `action` (no LIKE sobre
  // message). Comparte LOCK_THREAT_SCAN con el motor de egress → se serializan y
  // nunca golpean Trino 1-nodo a la vez. Gated HUNT_AUTH_ENABLED (en el servicio).
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_THREAT_SCAN, () => runAuthBruteforceScan({ logger }));
      if (r?.skipped) return;
      if (r?.ok) {
        _metrics.threatFindingsUpserted = (_metrics.threatFindingsUpserted ?? 0) + (r.upserted ?? 0);
        if (r.upserted > 0) { _metrics.lastRun.authScan = new Date().toISOString(); logger.info({ p4: r.p4, upserted: r.upserted }, "[scheduler] authBruteforceScan"); }
      } else {
        logger.warn({ error: r?.error }, "[scheduler] authBruteforceScan failed");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] authBruteforceScan failed"); }
  }, FOUR_HOUR));

  // Tarea 3c: Bootstrap case_tasks para casos sin playbook — cada 5 min.
  // Cierra el gap del DAG Python (~99% de creation volume) y cualquier path
  // futuro que cree casos sin pasar por bootstrapCaseTasks. Idempotente via
  // LEFT JOIN filter NULL + cap 200/tick para evitar stampede.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_TASKS_BOOTSTRAP, bootstrapMissingTasks);
      if (r?.skipped) return;
      if (r?.processed > 0) {
        _metrics.lastRun.tasksBootstrap = new Date().toISOString();
      }
    } catch (err) {
      logger.error({ err: err.message }, "[scheduler] bootstrapMissingTasks failed");
    }
  }, FIVE_MIN));

  // Tarea 3b: Auto-notify CRITICAL a Slack — cada 1 min.
  // Cubre el hueco donde el DAG crea el caso pero no avisa al canal.
  // Anti-spam: ventana 6h, batch 10, grace 60s desde creación.
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_NOTIFY_CRITICAL, notifyCriticalCases);
      if (r?.skipped) return;
      if (r?.notified > 0) {
        _metrics.criticalSlackNotified += r.notified;
        _metrics.lastRun.notifyCritical = new Date().toISOString();
        logger.info({ notified: r.notified }, "[scheduler] notifyCriticalCases");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] notifyCriticalCases failed"); }
  }, ONE_MIN));

  // Tarea 3e: Motor de patrones de caza externa — cada 4 h.
  // Detecta CLASES de amenaza (egress OT a nube foránea, beaconing) sobre la MV
  // fortigate_events_slim y las materializa en hunt_findings (PG). Batch, fuera
  // del path crítico de extracción. Ver docs/CENTRO-INTELIGENCIA-CAZA-EXTERNA-F1.md
  timers.push(setInterval(async () => {
    try {
      const r = await withAdvisoryLock(LOCK_THREAT_SCAN, () => runThreatPatternScan({ logger }));
      if (r?.skipped) return;
      if (r?.upserted > 0) {
        _metrics.lastRun.threatScan = new Date().toISOString();
        logger.info({ p1: r.p1, p2: r.p2, upserted: r.upserted }, "[scheduler] threatPatternScan");
      }
    } catch (err) { logger.error({ err: err.message }, "[scheduler] threatPatternScan failed"); }
  }, 4 * ONE_HOUR));

  // Tarea 4: KPIs de operadores (vista en vivo) — cada hora
  timers.push(setInterval(async () => {
    try {
      await updateOperatorKpis();
      _metrics.kpiRefreshes++;
      _metrics.lastRun.kpiUpdate = new Date().toISOString();
    } catch { /* ya logueado en updateOperatorKpis */ }
  }, ONE_HOUR));

  // Tarea 4b: Snapshot diario operator_metrics_daily — cada hora chequea si
  // falta el snapshot del día anterior. Idempotente (ON CONFLICT DO UPDATE).
  // R6: advisory lock separado para no colisionar con otras tareas.
  timers.push(setInterval(async () => {
    try {
      const [row] = await pgQuery(
        `SELECT 1 FROM operator_metrics_daily
          WHERE snapshot_date = CURRENT_DATE - INTERVAL '1 day' LIMIT 1`,
      );
      if (row) return;   // ya existe, skip
      await withAdvisoryLock(LOCK_METRICS_ROLLUP, rollupOperatorMetricsDaily);
    } catch (err) { logger.error({ err: err.message }, "[scheduler] metricsRollup check failed"); }
  }, ONE_HOUR));

  // Tarea 5: Informe diario SOC por email — dispara al llegar a REPORT_SCHEDULE_UTC
  if (reportConfigured()) {
    const [targetHh, targetMm] = parseScheduleUtc(process.env.REPORT_SCHEDULE_UTC);
    let reportSentDate = null;   // "YYYY-MM-DD" del último envío para evitar duplicados

    timers.push(setInterval(async () => {
      const now = new Date();
      const todayKey = now.toISOString().slice(0, 10);
      if (now.getUTCHours() === targetHh && now.getUTCMinutes() === targetMm && reportSentDate !== todayKey) {
        reportSentDate = todayKey;
        try {
          const r = await sendDailyReport();
          if (r.ok) logger.info({ messageId: r.messageId }, "[scheduler] daily report sent");
          else      logger.warn({ error: r.error }, "[scheduler] daily report skipped/failed");
        } catch (err) {
          logger.error({ err: err.message }, "[scheduler] daily report error");
        }
      }
    }, ONE_MIN));

    logger.info({ hour: targetHh, minute: targetMm }, "[scheduler] daily report task registered");
  } else {
    logger.info("[scheduler] daily report disabled (REPORT_ENABLED=false or SMTP not configured)");
  }

  // Tarea 6: Digest de supervisión de seguimiento — cada 6h alineado a UTC
  // (00/06/12/18 :00). Email a managers/leaders con casos abiertos sin
  // seguimiento + nudge in-app/push al operador responsable. Clock-aligned (como
  // el informe diario) → horarios predecibles y sin email-on-restart. Advisory
  // lock para no duplicar entre instancias.
  if (followupDigestConfigured()) {
    let followupSentKey = null;   // "YYYY-MM-DD-HH" del último envío
    timers.push(setInterval(async () => {
      const now = new Date();
      if (now.getUTCHours() % 6 !== 0 || now.getUTCMinutes() !== 0) return;
      const key = `${now.toISOString().slice(0, 10)}-${now.getUTCHours()}`;
      if (followupSentKey === key) return;
      followupSentKey = key;
      try {
        const r = await withAdvisoryLock(LOCK_FOLLOWUP_DIGEST, () => sendFollowupDigest(_io));
        if (r?.skipped === "lock_busy") return;
        if (r?.ok) logger.info({ messageId: r.messageId, stale: r.stale, nudged: r.nudged }, "[scheduler] followup digest sent");
        else       logger.warn({ reason: r?.skipped ?? r?.error }, "[scheduler] followup digest skipped/failed");
      } catch (err) {
        logger.error({ err: err.message }, "[scheduler] followup digest error");
      }
    }, ONE_MIN));
    logger.info("[scheduler] followup digest task registered (every 6h UTC)");
  } else {
    logger.info("[scheduler] followup digest disabled (FOLLOWUP_DIGEST_ENABLED=false or SMTP not configured)");
  }

  logger.info({ taskCount: timers.length }, "[scheduler] tasks registered");

  // Correr inmediatamente al arrancar.
  // P0 #9 (2026-06-07): la fase de arranque debe adquirir los MISMOS advisory locks
  // que los ticks periódicos. Antes corría autoClose/autoAssign sin lock → si dos
  // instancias del API arrancaban a la vez, ambas cerraban/asignaban en paralelo
  // (mutación duplicada). withAdvisoryLock devuelve undefined sin ejecutar si el lock
  // está tomado → la 2ª instancia simplemente salta el warm-up.
  setImmediate(async () => {
    try { await withAdvisoryLock(LOCK_AUTO_CLOSE,  () => autoCloseLowNegligible(_io)); } catch (_) {}
    try { await withAdvisoryLock(LOCK_AUTO_ASSIGN, () => autoAssignTimeoutCases(_io)); } catch (_) {}
    try { await updateOperatorKpis(); } catch (_) {}
    try {
      const r = await withAdvisoryLock(LOCK_DETECTED_AT_SYNC, () => withRetry("detectedAtSync", syncDetectedAtFromTrino));
      if (r?.synced > 0) _metrics.lastRun.detectedAtSync = new Date().toISOString();
    } catch (_) {}
    // Warm-up del motor de patrones (F1a) para poblar hunt_findings al arrancar
    // y no esperar el primer tick de 4h. Gated + serializado igual que el tick.
    try {
      if (threatScanEnabled()) {
        const r = await withAdvisoryLock(LOCK_THREAT_SCAN, () => runThreatPatternScan({ logger }));
        if (r?.ok) _metrics.lastRun.threatScan = new Date().toISOString();
      }
    } catch (_) {}
    // Warm-up del brute-force de login (P4) — serializado tras el egress bajo el
    // mismo lock para no solapar consultas a Trino al arrancar.
    try {
      const r = await withAdvisoryLock(LOCK_THREAT_SCAN, () => runAuthBruteforceScan({ logger }));
      if (r?.ok) _metrics.lastRun.authScan = new Date().toISOString();
    } catch (_) {}
    // Warm-up del analista de veredicto continuo (§1) — gated + lock propio.
    try {
      if (caseVerdictAnalystAvailable()) {
        const r = await withAdvisoryLock(LOCK_VERDICT_ANALYST, () => runCaseVerdictAnalyst({ logger }));
        if (r?.analyzed > 0) _metrics.lastRun.caseVerdictAnalyst = new Date().toISOString();
      }
    } catch (_) {}
    // Warm-up de la guardia de playbooks incompletos (§3a) — gated + lock propio.
    try {
      if (playbookComplianceEnabled()) {
        const r = await withAdvisoryLock(LOCK_PLAYBOOK_COMPLIANCE, () => detectIncompletePlaybookCloses({ logger, io: _io }));
        if (r?.flagged > 0) _metrics.lastRun.playbookCompliance = new Date().toISOString();
      }
    } catch (_) {}
    logger.info("[scheduler] initial run complete");
  });
}

export function stopScheduler() {
  timers.forEach(clearInterval);
  timers.length = 0;
  logger.info("[scheduler] stopped");
}

export function getSchedulerStatus() {
  return timers.map((_, i) => ({
    name: [
      "auto-close",
      "auto-assign",
      "sla-check",
      "task-sla-check",
      "detected-at-sync",
      "tasks-bootstrap",
      "notify-critical",
      "operator-kpis",
      "metrics-rollup",
      "daily-report",
    ][i] ?? `task-${i}`,
    running: true,
  }));
}
