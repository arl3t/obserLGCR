-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 089 — índice para la agregación de casos similares CERRADOS por clase.
--
-- La tarjeta "Casos similares" (GET /api/cases/:id/similar) agrupa la disposición
-- (classification), MTTR y % escalado sobre casos terminales de la MISMA clase
-- eCSIRT en una ventana reciente. mig 088 sólo indexó incident_class para casos
-- ABIERTOS; la rama de cerrados caía en parallel seq-scan (~180ms para la clase
-- INFO_GATHERING con 400k filas). Este índice parcial lo vuelve un index range
-- scan por (incident_class, created_at) acotado a terminales.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_cases_class_resolved
  ON incident_cases_pg (incident_class, created_at DESC)
  WHERE status IN ('CERRADO', 'FALSO_POSITIVO');
