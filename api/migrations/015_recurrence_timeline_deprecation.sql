-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 015 — Reincidencia + deprecación timeline JSONB
--
-- 1. Columnas de reincidencia en incident_cases_pg
--    parent_case_id   → UUID del caso anterior con mismo ioc_value (si existe)
--    is_recurrence    → true cuando el IOC reapareció tras cerrar un caso anterior
--    Permite trazabilidad de campañas APT que superan la ventana de dedup (15d).
--
-- 2. Deprecación de timeline JSONB
--    La columna incident_cases_pg.timeline pasa a read-only legacy.
--    La fuente canónica es case_timeline_events (tabla estructurada con phase NIST).
--    Se añade comentario formal en el catálogo PG.
--
-- 3. Índice de búsqueda por ioc_value + status para la consulta de reincidencia
--    La check de reincidencia en open-from-flow busca casos cerrados por ioc_value;
--    sin índice es seq scan en tablas grandes.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. Columnas de reincidencia
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS parent_case_id VARCHAR(64)  DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS is_recurrence   BOOLEAN      NOT NULL DEFAULT false;

-- FK débil (sin ON DELETE CASCADE — si el padre se borra el hijo queda huérfano
-- con parent_case_id apuntando a un caso que ya no existe, lo cual es aceptable
-- para el audit trail histórico. Usar DEFERRABLE para inserts en el mismo tx.)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'fk_cases_parent'
      AND table_name = 'incident_cases_pg'
  ) THEN
    ALTER TABLE incident_cases_pg
      ADD CONSTRAINT fk_cases_parent
      FOREIGN KEY (parent_case_id)
      REFERENCES incident_cases_pg(id)
      ON DELETE SET NULL
      DEFERRABLE INITIALLY DEFERRED;
  END IF;
END $$;

-- 2. Deprecación formal de la columna timeline JSONB
COMMENT ON COLUMN incident_cases_pg.timeline IS
  '[DEPRECATED desde migration 015 — Abril 2026] '
  'Fuente canónica: tabla case_timeline_events. '
  'Esta columna es read-only legacy para casos anteriores a migration 015. '
  'No escribir nuevas entradas aquí. '
  'Ver GET /api/incidents/:id/timeline para leer el timeline estructurado.';

-- 3. Índice para consulta de reincidencia (ioc_value en casos cerrados)
CREATE INDEX IF NOT EXISTS idx_cases_ioc_closed
  ON incident_cases_pg(ioc_value, status)
  WHERE status IN ('CERRADO', 'FALSO_POSITIVO');

-- 4. Índice para búsqueda de parent_case_id (trazabilidad de cadena de reincidencias)
CREATE INDEX IF NOT EXISTS idx_cases_parent_id
  ON incident_cases_pg(parent_case_id)
  WHERE parent_case_id IS NOT NULL;
