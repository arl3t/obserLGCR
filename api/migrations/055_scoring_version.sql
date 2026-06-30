-- 055_scoring_version.sql
-- R4 (audit Scoring 2026-05-21): trazabilidad de la versión de fórmula usada
-- al calcular el severity_score de cada caso.
--
-- Problema previo: incident_cases_sync_daily.py detecta dinámicamente v_incident_score_v4
-- → v_incident_score_v3 → v_incident_score_v2_runtime → v_incident_score_v2 y usa la
-- primera disponible. Sin esta columna, retroactivamente no se sabe con qué fórmula
-- (y por extensión, qué pesos/multiplicadores) se calculó el score de un caso. Si
-- mañana se ajustan los pesos de v4 o se introduce v5, los casos viejos quedan sin
-- forma de explicar el score.
--
-- Valores esperados: 'v2', 'v3', 'v4', 'manual' (caso abierto vía /open-from-flow
-- con score calculado en backend Node + scoringBonus.mjs).

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS scoring_version VARCHAR(16);

CREATE INDEX IF NOT EXISTS idx_cases_scoring_version
  ON incident_cases_pg (scoring_version)
  WHERE scoring_version IS NOT NULL;

COMMENT ON COLUMN incident_cases_pg.scoring_version IS
  'Versión de la fórmula que calculó severity_score. Valores: v2|v3|v4|manual. '
  'Seteado por incident_cases_sync_daily (DAG) según la vista usada, y por '
  'POST /api/incidents/open-from-flow (=manual). NULL para casos previos a 055.';
