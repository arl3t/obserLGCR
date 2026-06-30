-- =============================================================================
-- 037 — Snapshot CTI Cloud & Olé por dominio en watchlist
--
-- El cron horario de watchlist consulta CTI Cloud & Olé para cada dominio due
-- y persiste el resultado crudo en S3 (igual que la búsqueda manual). Para
-- renderizar el último estado en la card "Bajo vigilancia" del frontend sin
-- volver a llamar al API externo, guardamos un resumen por dominio:
--
--   - hits_count        cantidad de credenciales filtradas detectadas
--   - queried_at        timestamp de la consulta exitosa
--   - s3_key            puntero al JSON crudo en S3 (auditable)
--   - top_leak_names    primeras N marcas de leak (para tooltip — sin PII)
--   - error             texto del error si la consulta falló
--
-- Una fila por dominio (UNIQUE). Cada ciclo de cron upserta. El JSON crudo
-- vive en S3 (no duplicamos), esta tabla es solo el resumen rapidísimo de
-- consultar para pintar badges.
--
-- Idempotente: CREATE … IF NOT EXISTS.
-- =============================================================================

CREATE TABLE IF NOT EXISTS surveillance_cti_snapshots (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  domain          VARCHAR(253)    NOT NULL UNIQUE,
  hits_count      INTEGER         NOT NULL DEFAULT 0,
  queried_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
  s3_key          TEXT,
  top_leak_names  TEXT[]          NOT NULL DEFAULT '{}',
  error           TEXT,
  updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cti_snapshots_queried_at
  ON surveillance_cti_snapshots(queried_at DESC);

COMMENT ON TABLE surveillance_cti_snapshots IS
  'Última snapshot por dominio del cron CTI Cloud & Olé. JSON crudo en S3 '
  '(s3_key); esta tabla es el resumen rápido para badges del watchlist.';
