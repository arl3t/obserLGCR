-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 014 — Integridad referencial + índices de rendimiento
--
-- 1. FK incident_cases_pg.operator_id → soc_operators(id) ON DELETE SET NULL
--    Garantiza que ningún CI inválido pueda estar asociado a un caso abierto.
--    ON DELETE SET NULL: si se elimina un operador, los casos quedan sin asignar
--    (no se borran ni quedan con FK inválida).
--
-- 2. UNIQUE partial index en soc_operators.is_shift_manager
--    Solo puede haber UN shift manager activo por turno.
--    Sin esta constraint, autoAssignTimeoutCases puede notificar a un operador
--    incorrecto si hay más de uno marcado como manager.
--
-- 3. INDEX incident_cases_pg(operator_id)
--    Consultas de KPI por operador hacen seq scan sin este índice.
--    Con 50k+ casos, la página de métricas de un analista puede tardar segundos.
--
-- 4. INDEX soc_notifications(operator_id, created_at DESC) WHERE read_at IS NULL
--    Las consultas de notificaciones no leídas siempre terminan en ORDER BY
--    created_at DESC. El índice actual (operator_id, read_at) no cubre eso.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. FK operator_id → soc_operators
--    Usar IF NOT EXISTS para idempotencia en re-runs
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'fk_cases_operator'
      AND table_name = 'incident_cases_pg'
  ) THEN
    ALTER TABLE incident_cases_pg
      ADD CONSTRAINT fk_cases_operator
      FOREIGN KEY (operator_id)
      REFERENCES soc_operators(id)
      ON DELETE SET NULL
      DEFERRABLE INITIALLY DEFERRED;
  END IF;
END $$;

-- 2. Unicidad de Shift Manager activo
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_shift_manager
  ON soc_operators(is_shift_manager)
  WHERE is_shift_manager = true;

-- 3. Índice de operador en casos
CREATE INDEX IF NOT EXISTS idx_cases_operator_id
  ON incident_cases_pg(operator_id)
  WHERE operator_id IS NOT NULL;

-- 4. Índice de notificaciones no leídas con orden temporal
CREATE INDEX IF NOT EXISTS idx_notif_unread_ts
  ON soc_notifications(operator_id, created_at DESC)
  WHERE read_at IS NULL;
