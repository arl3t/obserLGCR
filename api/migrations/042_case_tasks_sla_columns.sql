-- =============================================================================
-- Migration 042 — Tracking de SLA a nivel de case_tasks
-- =============================================================================
-- El scheduler ya cubría SLA al nivel del caso (incident_cases_pg) para
-- CRITICAL/HIGH. Con los casos abiertos desde Vigilancia/Credenciales
-- (severidades LOW frecuentes pero con 8-10 tasks NIST con due_at concreto),
-- necesitamos tracking SLA por tarea — el analista quiere saber qué tarea
-- está próxima al breach, no qué caso.
--
-- Dos columnas:
--   sla_warned_at  — set una vez al entrar en ventana de preaviso (≥80% del
--                    tiempo desde created_at → due_at). Idempotente.
--   sla_breached_at— set una vez al pasar due_at sin DONE/SKIPPED.
--
-- Idempotencia: el job UPDATE ... WHERE sla_X_at IS NULL garantiza una sola
-- notificación por tarea.
-- =============================================================================

ALTER TABLE case_tasks
  ADD COLUMN IF NOT EXISTS sla_warned_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_breached_at TIMESTAMPTZ;

-- Índice parcial para que el scheduler escanee solo tareas relevantes en
-- vez de full-scan: OPEN/IN_PROGRESS con due_at fijado y sin breach todavía.
CREATE INDEX IF NOT EXISTS idx_case_tasks_sla_pending
  ON case_tasks (due_at)
  WHERE status IN ('OPEN','IN_PROGRESS')
    AND due_at IS NOT NULL
    AND sla_breached_at IS NULL;

COMMENT ON COLUMN case_tasks.sla_warned_at IS
  'Timestamp del primer preaviso SLA (≥80% del tiempo entre created_at y due_at). NULL hasta dispararse.';
COMMENT ON COLUMN case_tasks.sla_breached_at IS
  'Timestamp del primer evento SLA breach (due_at pasó sin completar). NULL hasta dispararse.';
