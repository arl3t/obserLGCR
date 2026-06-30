-- =============================================================================
-- 047 — engine_version en surveillance_analyses (#10).
--
-- Cada snapshot persiste qué versión del motor de scoring lo computó. Permite
-- comparar análisis históricos con confianza (un cambio de scoring no
-- corrompe la serie temporal — los análisis viejos están etiquetados con
-- la versión vigente al momento de la captura).
--
-- Default 'v1.0.0' para filas previas a la introducción del registry;
-- nuevas insercion van con la versión vigente del cliente.
-- =============================================================================

ALTER TABLE surveillance_analyses
  ADD COLUMN IF NOT EXISTS engine_version VARCHAR(16);

COMMENT ON COLUMN surveillance_analyses.engine_version IS
  'Versión semántica del motor de scoring al momento del análisis '
  '(p.ej. v1.2.0). Cambia al evolucionar plugins; permite trazar diff '
  'entre snapshots históricos.';

CREATE INDEX IF NOT EXISTS idx_surveillance_analyses_engine_version
  ON surveillance_analyses(engine_version)
  WHERE engine_version IS NOT NULL;
