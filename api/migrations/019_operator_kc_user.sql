-- =============================================================================
-- 019 — Columna kc_user_id en soc_operators
--
-- Almacena el UUID del usuario Keycloak asociado al operador SOC.
-- Null = el operador aún no tiene cuenta KC creada desde el dashboard.
-- Idempotente: ALTER ... IF NOT EXISTS
-- =============================================================================

ALTER TABLE soc_operators
  ADD COLUMN IF NOT EXISTS kc_user_id VARCHAR(36);

COMMENT ON COLUMN soc_operators.kc_user_id IS
  'UUID del usuario en Keycloak (legacyhunt-soc realm). NULL si no tiene cuenta KC.';
