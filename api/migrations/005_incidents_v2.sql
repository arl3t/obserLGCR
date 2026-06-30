-- =============================================================================
-- 005_incidents_v2.sql
-- Extiende incident_cases_pg con columnas operacionales faltantes:
--   · slack_notified_at  — evita duplicados de notificación Slack por caso
--   · recommended_action — acción recomendada separada de notas de operador
-- Las columnas de escalación (escalation_level, escalated_to, escalated_at,
-- escalation_reason) y adopted_at ya existen desde 001_base + 004_nist_escalation.
-- =============================================================================

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS slack_notified_at  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS recommended_action TEXT;

-- Índice para lookups rápidos de casos con notificación Slack pendiente
CREATE INDEX IF NOT EXISTS idx_cases_slack_notified
  ON incident_cases_pg(slack_notified_at)
  WHERE slack_notified_at IS NOT NULL;
