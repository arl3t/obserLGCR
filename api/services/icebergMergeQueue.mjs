/**
 * icebergMergeQueue.mjs — R9 (audit 2026-05-13)
 *
 * Cola persistente para la mitad Iceberg de POST /api/incidents/merge.
 *
 * Antes el handler hacía `setImmediate(async () => trinoExec(...))` después de
 * actualizar PG. Si el proceso caía en ese microtask, los duplicados quedaban
 * CERRADO en PG pero el canónico no recibía el occurrence_count sumado en
 * Iceberg → estado divergente sin alerta.
 *
 * Ahora el handler hace UN INSERT en `legacyhunt_soc.iceberg_merge_queue` (PG,
 * transaccional con el resto del merge en el mismo request) y retorna 200. Un
 * worker singleton arranca con el API y drena la cola con backoff exponencial.
 * Si el proceso cae, en el siguiente arranque retoma los `pending` cuya
 * `next_retry_at` ya pasó.
 *
 * Payload esperado en `payload`:
 *   {
 *     canonical: { case_id, severity_text, severity_score, ioc_value, ioc_type,
 *                  source_log, mitre_tactic_id, mitre_tactic_name, source_category,
 *                  severity_rank, confidence_level, status, first_seen,
 *                  last_seen, anchor_dt, classified_at, dedup_key, notes,
 *                  parent_case_id, ... — todo lo que buildCasesInsert necesita },
 *     duplicates: [{ case_id, ...mismo shape }],
 *     ci:        "<operator ci>",
 *     now:       "<ISO ts>"
 *   }
 */

import { pgQuery, withPgClient } from "../db/postgres.mjs";
import { trinoExec } from "./trinoWriter.mjs";
import { logger } from "../logger.mjs";

const TCASES  = "minio_iceberg.hunting.incident_cases";
const SESSION = { catalog: "minio_iceberg", schema: "hunting" };

const MAX_ATTEMPTS = 6;          // 6 reintentos con backoff exponencial
const BASE_RETRY_MS = 30_000;    // 30s, 1m, 2m, 4m, 8m, 16m
const POLL_INTERVAL_MS = 15_000; // tick del worker

// Reaper de jobs zombie (P4 C2, audit 2026-05-13). Un job que pasó por COMMIT
// con status='running' pero cuyo process murió antes del UPDATE final queda
// invisible para el filtro `status='pending'` y nunca se reintenta → drift PG↔
// Iceberg permanente. El reaper considera zombie cualquier 'running' con
// `started_at` más viejo que este umbral y lo re-toma. El umbral debe ser
// generoso vs el tiempo real de un job (segundos) para no canibalizar uno en
// curso si el worker es lento.
const ZOMBIE_TIMEOUT_MS = 5 * 60 * 1000; // 5 min

// Cota de seguridad de la cola (P4 M1, 2026-05-13). Si Trino está caído
// y los retries se acumulan, sin esta cota la tabla crece sin límite y
// el polling worker gasta latencia escaneando jobs viejos. 500 es ~3 días
// de operación normal del SOC; por encima de eso hay un problema real
// que requiere atención manual.
const MAX_QUEUE_DEPTH = 500;

let _workerStarted = false;
let _stopRequested = false;
let _currentTimer  = null;

/** Helper para escapar literales SQL Trino (mismo patrón que routes/incidents). */
function sq(v) {
  return `'${String(v ?? "").replace(/'/g, "''")}'`;
}

/** SQL escape para valores opcionales (NULL vs literal). */
function nullOrSq(v) {
  return v == null || v === "" ? "NULL" : sq(v);
}

/**
 * Construye INSERT en Iceberg para `incident_cases`. Equivalente al
 * `buildCasesInsert` de routes/incidents.mjs (no se importa para evitar
 * acoplamiento). Mantener sincronizado si cambia el shape de la tabla.
 */
function buildCasesInsert(r) {
  return `INSERT INTO ${TCASES} (
  case_id, dedup_key, ioc_value, ioc_type, source_log,
  mitre_tactic_id, mitre_tactic_name, source_category,
  severity_text, severity_rank, severity_score, confidence_level,
  status, occurrence_count, first_seen, last_seen, anchor_dt,
  classified_at, assigned_to, closure_reason, notes, score_breakdown,
  parent_case_id, updated_at
) VALUES (
  ${sq(r.case_id)}, ${nullOrSq(r.dedup_key)}, ${sq(r.ioc_value)}, ${sq(r.ioc_type)}, ${sq(r.source_log)},
  ${nullOrSq(r.mitre_tactic_id)}, ${nullOrSq(r.mitre_tactic_name)}, ${nullOrSq(r.source_category)},
  ${sq(r.severity_text)}, ${Number(r.severity_rank ?? 3)}, ${Number(r.severity_score ?? 50)}, ${nullOrSq(r.confidence_level)},
  ${sq(r.status)}, ${Number(r.occurrence_count ?? 1)},
  TIMESTAMP ${sq(r.first_seen)}, TIMESTAMP ${sq(r.last_seen ?? r.first_seen)}, DATE ${sq(r.anchor_dt)},
  ${r.classified_at ? `TIMESTAMP ${sq(r.classified_at)}` : "NULL"},
  ${nullOrSq(r.assigned_to)}, ${nullOrSq(r.closure_reason)}, ${nullOrSq(r.notes)},
  ${r.score_breakdown ? sq(JSON.stringify(r.score_breakdown)) : "NULL"},
  ${nullOrSq(r.parent_case_id)},
  TIMESTAMP ${sq(r.updated_at)}
)`;
}

/**
 * Enqueue un job de merge. Llamar DESPUÉS de que la mitad PG del merge
 * fue exitosa. El job retorna inmediatamente; el worker hace el trabajo
 * real con retry.
 */
export async function enqueueMergeJob({ canonicalId, duplicateIds, totalOccurrence, canonicalRow, duplicateRows, ci, now }) {
  // Backpressure: si la cola superó MAX_QUEUE_DEPTH (pending+failed), rechazar
  // para no permitir crecimiento sin límite mientras Trino está caído. El
  // operador ve el 503 y sabe que algo necesita atención. P4 M1.
  const depthRow = await pgQuery(
    `SELECT COUNT(*)::int AS n FROM legacyhunt_soc.iceberg_merge_queue
      WHERE status IN ('pending','failed')`,
  );
  const depth = depthRow[0]?.n ?? 0;
  if (depth >= MAX_QUEUE_DEPTH) {
    const e = new Error(`Cola de merge Iceberg saturada (${depth}/${MAX_QUEUE_DEPTH}) — revisar /api/incidents/merge-queue/dlq`);
    e.code = "QUEUE_FULL";
    throw e;
  }
  const payload = {
    canonical:  canonicalRow,
    duplicates: duplicateRows,
    ci,
    now,
  };
  const rows = await pgQuery(
    `INSERT INTO legacyhunt_soc.iceberg_merge_queue
       (job_type, canonical_id, duplicate_ids, total_occurrence, payload, status, next_retry_at)
     VALUES ('merge', $1, $2, $3, $4::jsonb, 'pending', now())
     RETURNING id`,
    [canonicalId, duplicateIds, totalOccurrence, JSON.stringify(payload)],
  );
  logger.info({ msg: "iceberg_merge_enqueued", jobId: rows[0]?.id, canonicalId, dupCount: duplicateIds.length });
  return rows[0]?.id ?? null;
}

/**
 * Encola un job de sincronización de un caso a Iceberg post-transición de
 * estado (status/severity/escalation). Reemplaza el patrón
 * `setImmediate(async () => trinoExec(DELETE + INSERT))` que era
 * fire-and-forget. P4 C3.
 *
 * `trinoRow` debe traer todos los campos que `buildCasesInsert` necesita —
 * el caller lo construye con `{ ...originalTrinoRow, status, updated_at,
 * ...overrides }`. El worker no consulta PG/Iceberg para reconstruirlo.
 */
export async function enqueueStatusSyncJob({ caseId, trinoRow, ci, now }) {
  // Backpressure compartido con merge — la cota cubre toda la cola.
  const depthRow = await pgQuery(
    `SELECT COUNT(*)::int AS n FROM legacyhunt_soc.iceberg_merge_queue
      WHERE status IN ('pending','failed')`,
  );
  const depth = depthRow[0]?.n ?? 0;
  if (depth >= MAX_QUEUE_DEPTH) {
    const e = new Error(`Cola Iceberg saturada (${depth}/${MAX_QUEUE_DEPTH}) — revisar /api/incidents/merge-queue/dlq`);
    e.code = "QUEUE_FULL";
    throw e;
  }
  const payload = { trinoRow, ci, now };
  const rows = await pgQuery(
    `INSERT INTO legacyhunt_soc.iceberg_merge_queue
       (job_type, canonical_id, duplicate_ids, total_occurrence, payload, status, next_retry_at)
     VALUES ('status_sync', $1, ARRAY[]::text[], 0, $2::jsonb, 'pending', now())
     RETURNING id`,
    [caseId, JSON.stringify(payload)],
  );
  logger.info({ msg: "iceberg_status_sync_enqueued", jobId: rows[0]?.id, caseId, newStatus: trinoRow?.status });
  return rows[0]?.id ?? null;
}

/**
 * Inspecciona la cola — devuelve resumen por status + N jobs más recientes
 * por status. Para endpoint admin (P4 M1).
 */
export async function getQueueStats({ limit = 50 } = {}) {
  const lim = Math.max(1, Math.min(200, Number(limit) || 50));
  const summary = await pgQuery(
    `SELECT status, COUNT(*)::int AS n,
            MIN(enqueued_at)  AS oldest_enqueued,
            MAX(finished_at)  AS latest_finished
       FROM legacyhunt_soc.iceberg_merge_queue
      GROUP BY status`,
  );
  const recent = await pgQuery(
    `SELECT id, canonical_id, duplicate_ids, total_occurrence,
            status, attempts, last_error,
            enqueued_at, started_at, finished_at, next_retry_at
       FROM legacyhunt_soc.iceberg_merge_queue
      WHERE status IN ('failed','running')
      ORDER BY COALESCE(finished_at, enqueued_at) DESC
      LIMIT $1`,
    [lim],
  );
  return { summary, recent };
}

/**
 * Re-encola un job `failed` resetando attempts y next_retry_at. Útil cuando
 * el operador resolvió la causa raíz (ej. credenciales Trino caducas) y
 * quiere reintentar los jobs marcados como exhausted. P4 M1.
 */
export async function retryFailedJob(jobId) {
  const rows = await pgQuery(
    `UPDATE legacyhunt_soc.iceberg_merge_queue
        SET status        = 'pending',
            attempts      = 0,
            last_error    = NULL,
            started_at    = NULL,
            finished_at   = NULL,
            next_retry_at = now()
      WHERE id = $1 AND status = 'failed'
      RETURNING id, canonical_id`,
    [jobId],
  );
  if (!rows.length) {
    const e = new Error("Job no encontrado o no está en estado 'failed'");
    e.code = "NOT_RETRIABLE";
    throw e;
  }
  logger.info({ msg: "iceberg_merge_retry_queued", jobId, canonicalId: rows[0].canonical_id });
  return rows[0];
}

/**
 * Borra un job de la cola — útil para purgar jobs `failed` cuyo payload está
 * corrupto y no vale la pena reintentar. P4 M1.
 */
export async function deleteQueueJob(jobId) {
  const rows = await pgQuery(
    `DELETE FROM legacyhunt_soc.iceberg_merge_queue
      WHERE id = $1 AND status IN ('failed','done')
      RETURNING id, status`,
    [jobId],
  );
  if (!rows.length) {
    const e = new Error("Job no encontrado o no eliminable (running/pending)");
    e.code = "NOT_DELETABLE";
    throw e;
  }
  logger.info({ msg: "iceberg_merge_job_deleted", jobId, prevStatus: rows[0].status });
  return rows[0];
}

/**
 * Ejecuta UN job: re-escribe canónico (DELETE + INSERT con occurrence_count
 * actualizado) y marca duplicados como CERRADO en Iceberg.
 *
 * Idempotencia: cada paso es DELETE + INSERT (Iceberg no tiene UPDATE de
 * filas mutable estilo RDBMS; el patrón es DELETE-then-INSERT). Si el worker
 * cae a mitad de un job, el siguiente arranque re-corre desde el principio:
 *   - DELETE FROM incident_cases WHERE case_id = canonical → OK aunque ya no
 *     exista (Iceberg lo trata como no-op silencioso si el manifest no lo
 *     incluye).
 *   - INSERT ... → re-escribe el row. Si el INSERT previo había completado y
 *     el caller reintenta, terminaríamos con DUPLICATE rows del mismo case_id.
 *     Pero el DELETE inicial lo previene siempre que se complete antes del
 *     re-arranque. La ventana de duplicado es del orden de ms.
 */
async function executeMergeJob(job) {
  const { canonical, duplicates, ci, now } = job.payload;
  const canonId = canonical.case_id;
  const dupIds  = duplicates.map((d) => d.case_id);
  const newOcc  = job.total_occurrence;

  // 1. Canónico: DELETE + INSERT con occurrence_count nuevo + notes de merge.
  await trinoExec(`DELETE FROM ${TCASES} WHERE case_id = ${sq(canonId)}`, SESSION);
  await trinoExec(buildCasesInsert({
    ...canonical,
    occurrence_count: newOcc,
    updated_at:       now,
    notes: `${String(canonical.notes ?? "")}; MERGE ×${dupIds.length} por ${ci}`.trim(),
  }), SESSION);

  // 2. Duplicados: DELETE + INSERT con status=CERRADO + closure_reason de merge.
  for (const dup of duplicates) {
    await trinoExec(`DELETE FROM ${TCASES} WHERE case_id = ${sq(dup.case_id)}`, SESSION);
    await trinoExec(buildCasesInsert({
      ...dup,
      status:         "CERRADO",
      closure_reason: `MERGEADO → ${canonId}`,
      updated_at:     now,
    }), SESSION);
  }
}

/**
 * Ejecuta UN job de status_sync: DELETE + INSERT del row Iceberg para
 * reflejar la transición de estado más reciente del caso. P4 C3.
 *
 * El payload trae el shape completo del row para construir el INSERT —
 * el worker no toca PG ni Trino para reconstruirlo.
 */
async function executeStatusSyncJob(job) {
  const { trinoRow } = job.payload;
  if (!trinoRow || !trinoRow.case_id) {
    const e = new Error("status_sync: payload sin trinoRow.case_id");
    e.code = "BAD_PAYLOAD";
    throw e;
  }
  await trinoExec(`DELETE FROM ${TCASES} WHERE case_id = ${sq(trinoRow.case_id)}`, SESSION);
  await trinoExec(buildCasesInsert(trinoRow), SESSION);
}

/**
 * Toma un job pendiente con `SELECT ... FOR UPDATE SKIP LOCKED` para
 * permitir múltiples workers (escalabilidad futura). Marca status=running,
 * ejecuta, y al final actualiza status=done|failed con backoff.
 */
async function processOneJob() {
  return withPgClient(async (client) => {
    await client.query("BEGIN");
    let job;
    try {
      const lock = await client.query(
        `SELECT id, job_type, canonical_id, duplicate_ids, total_occurrence, payload, attempts,
                status AS prev_status, started_at AS prev_started_at
           FROM legacyhunt_soc.iceberg_merge_queue
          WHERE (status = 'pending' AND next_retry_at <= now())
             OR (status = 'running' AND started_at < now() - ($1 || ' milliseconds')::interval)
          ORDER BY next_retry_at ASC
          LIMIT 1
          FOR UPDATE SKIP LOCKED`,
        [String(ZOMBIE_TIMEOUT_MS)],
      );
      if (!lock.rows.length) {
        await client.query("ROLLBACK");
        return null;
      }
      job = lock.rows[0];
      if (job.prev_status === "running") {
        logger.warn({
          msg: "iceberg_merge_zombie_reclaimed",
          jobId: job.id,
          prevStartedAt: job.prev_started_at,
          attempts: job.attempts,
        });
      }
      await client.query(
        `UPDATE legacyhunt_soc.iceberg_merge_queue
            SET status = 'running', started_at = now(), attempts = attempts + 1
          WHERE id = $1`,
        [job.id],
      );
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }

    // Trabajo fuera de la TX para no bloquear el row durante 30+ segundos.
    // Multiplex por job_type — P4 C3.
    const jobType = job.job_type || "merge";
    try {
      if (jobType === "merge") {
        await executeMergeJob(job);
      } else if (jobType === "status_sync") {
        await executeStatusSyncJob(job);
      } else {
        const e = new Error(`job_type desconocido: ${jobType}`);
        e.code = "UNKNOWN_JOB_TYPE";
        throw e;
      }
      await client.query(
        `UPDATE legacyhunt_soc.iceberg_merge_queue
            SET status = 'done', finished_at = now(), last_error = NULL
          WHERE id = $1`,
        [job.id],
      );
      logger.info({ msg: "iceberg_job_done", jobType, jobId: job.id, attempts: job.attempts + 1 });
      return { id: job.id, status: "done" };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const attempt = job.attempts + 1;
      const exhausted = attempt >= MAX_ATTEMPTS;
      const delayMs = BASE_RETRY_MS * (2 ** (attempt - 1));
      await client.query(
        `UPDATE legacyhunt_soc.iceberg_merge_queue
            SET status        = $2,
                last_error    = $3,
                finished_at   = CASE WHEN $4::bool THEN now() ELSE NULL END,
                next_retry_at = CASE WHEN $4::bool THEN next_retry_at
                                    ELSE now() + ($5 || ' milliseconds')::interval
                                END
          WHERE id = $1`,
        [job.id, exhausted ? "failed" : "pending", msg.slice(0, 500), exhausted, String(delayMs)],
      );
      logger[exhausted ? "error" : "warn"]({
        msg: "iceberg_job_failed",
        jobType,
        jobId: job.id,
        attempt,
        exhausted,
        error: msg.slice(0, 200),
      });
      return { id: job.id, status: exhausted ? "failed" : "pending" };
    }
  });
}

/**
 * Arranca el worker (singleton). Idempotente — múltiples llamadas no inician
 * loops adicionales. El loop respeta POLL_INTERVAL_MS entre iteraciones cuando
 * la cola está vacía; corre back-to-back cuando hay trabajo.
 */
export function startIcebergMergeQueueWorker() {
  if (_workerStarted) return;
  _workerStarted = true;
  _stopRequested = false;

  const tick = async () => {
    if (_stopRequested) return;
    try {
      let job;
      do {
        if (_stopRequested) return;
        job = await processOneJob();
      } while (job); // drenar todo lo que esté listo en este tick
    } catch (err) {
      logger.error({ msg: "iceberg_merge_worker_tick_failed", error: err instanceof Error ? err.message : String(err) });
    } finally {
      if (!_stopRequested) {
        _currentTimer = setTimeout(() => { void tick(); }, POLL_INTERVAL_MS);
      }
    }
  };
  // Delay inicial para no chocar con el bootstrap.
  _currentTimer = setTimeout(() => { void tick(); }, 8_000);
  logger.info({ msg: "iceberg_merge_worker_started", pollIntervalMs: POLL_INTERVAL_MS, maxAttempts: MAX_ATTEMPTS, zombieTimeoutMs: ZOMBIE_TIMEOUT_MS });
}

/**
 * Detiene el worker (P4 C4 — graceful shutdown). El flag impide nuevos
 * ticks; los `processOneJob()` ya en vuelo terminan naturalmente. Una vez
 * detenido, `startIcebergMergeQueueWorker()` vuelve a iniciarlo.
 */
export function stopIcebergMergeQueueWorker() {
  _stopRequested = true;
  if (_currentTimer) {
    clearTimeout(_currentTimer);
    _currentTimer = null;
  }
  _workerStarted = false;
  logger.info({ msg: "iceberg_merge_worker_stopped" });
}
