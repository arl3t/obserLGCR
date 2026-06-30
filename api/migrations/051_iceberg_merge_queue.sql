-- 051_iceberg_merge_queue.sql
-- R9 (audit 2026-05-13): cola persistente para la mitad Iceberg de POST /merge.
--
-- Antes (routes/incidents.mjs:2306): tras actualizar PG, el handler hace
-- `setImmediate(async () => { trinoExec(DELETE/INSERT) })` — fire-and-forget.
-- Si el proceso cae entre el PG y la primera trinoExec, los duplicados quedan
-- CERRADO en PG pero el canónico en Iceberg no refleja el occurrence_count
-- sumado, y los duplicados siguen presentes en Iceberg. La auditoría del
-- caso aparece divergente entre lakehouse y PG.
--
-- Con esta cola: el handler hace UN INSERT atómico en la tabla, retorna 200
-- al cliente, y un worker en background drena la cola con retry exponencial.
-- Si el proceso cae, en el siguiente arranque el worker reanuda los jobs que
-- quedaron `pending`.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.iceberg_merge_queue (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  canonical_id    VARCHAR(64)  NOT NULL,
  duplicate_ids   TEXT[]       NOT NULL,    -- IDs de los casos a cerrar en Iceberg
  total_occurrence INTEGER     NOT NULL,    -- occurrence_count sumado para el canónico
  payload         JSONB        NOT NULL DEFAULT '{}'::jsonb,
                                            -- snapshot del row canónico {severity_text, severity_score, ioc_value, etc.}
                                            -- + notes/ci/now ya consolidados — el worker no
                                            -- re-consulta PG para evitar drift si el caso cambia.
  status          VARCHAR(16)  NOT NULL DEFAULT 'pending'
                                            CHECK (status IN ('pending','running','done','failed')),
  attempts        INTEGER      NOT NULL DEFAULT 0,
  last_error      TEXT,
  enqueued_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  next_retry_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Worker scan: filas listas para correr (pending + tiempo cumplido).
CREATE INDEX IF NOT EXISTS idx_imq_pending_due
  ON legacyhunt_soc.iceberg_merge_queue (next_retry_at)
  WHERE status = 'pending';

-- Para inspección operacional: ver fallos recientes.
CREATE INDEX IF NOT EXISTS idx_imq_failed
  ON legacyhunt_soc.iceberg_merge_queue (finished_at DESC)
  WHERE status = 'failed';

COMMENT ON TABLE legacyhunt_soc.iceberg_merge_queue IS
  'Cola persistente para la mitad Iceberg de POST /api/incidents/merge. El '
  'handler hace INSERT atómico y un worker drena con retry exponencial. '
  'R9 audit 2026-05-13 — reemplaza el setImmediate fire-and-forget.';
