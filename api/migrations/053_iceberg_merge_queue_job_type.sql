-- 053_iceberg_merge_queue_job_type.sql
-- P4 C3 (audit 2026-05-13): backstop PG→Iceberg para transiciones de estado.
--
-- Antes (routes/incidents.mjs:3496 y similares en /severity, /escalate,
-- /bulk-escalate-unadopted): tras pgUpsertCase, el handler hace
--    setImmediate(async () => trinoExec(DELETE + INSERT))
-- fire-and-forget. Si Trino falla o el process muere, el row Iceberg queda
-- viejo y no hay retry. Sólo el merge tenía cola persistente desde R9.
--
-- Esta migración generaliza la cola existente para que soporte dos tipos
-- de job:
--   · 'merge'       — el comportamiento histórico (canonical + duplicates).
--   · 'status_sync' — single-case DELETE + INSERT post-transición.
--
-- Compatible hacia atrás: filas existentes quedan job_type='merge' por el
-- DEFAULT; el worker existente las sigue procesando sin cambios. El
-- shape del payload de status_sync usa canonical_id=case_id, duplicate_ids=[],
-- total_occurrence=0 — no se relajan los NOT NULL para no degradar la
-- garantía de los jobs merge.

ALTER TABLE legacyhunt_soc.iceberg_merge_queue
  ADD COLUMN IF NOT EXISTS job_type VARCHAR(32) NOT NULL DEFAULT 'merge';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_imq_job_type'
  ) THEN
    ALTER TABLE legacyhunt_soc.iceberg_merge_queue
      ADD CONSTRAINT chk_imq_job_type
        CHECK (job_type IN ('merge', 'status_sync'));
  END IF;
END $$;

-- Worker scan: el filtro por status='pending' ya tiene índice (idx_imq_pending_due
-- desde 051). Para inspección operacional por tipo, indexamos también.
CREATE INDEX IF NOT EXISTS idx_imq_job_type_status
  ON legacyhunt_soc.iceberg_merge_queue (job_type, status);

COMMENT ON COLUMN legacyhunt_soc.iceberg_merge_queue.job_type IS
  'Tipo de job: merge (canonical+duplicates, R9) o status_sync (single-case '
  'DELETE+INSERT post-transición, P4 C3). El worker multiplexa según valor.';
