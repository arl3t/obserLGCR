-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 086 — extender el CHECK de soc_notifications.type.
--
-- Contexto (backlog GESTION-OPTIMIZACION-2026-06-07, P2 #8): se agrega el tipo
-- RECURRENCE_SURGE (alerta de recurrencia). Al auditar se detectó que el CHECK
-- original (mig 008) NUNCA se extendió pese a que el código ya emitía varios tipos
-- nuevos vía createNotification (todos con .catch silencioso) → esas notificaciones
-- fallaban sin rastro: SLA_APPROACHING, CASE_ASSIGNED_BULK, MONITOR_REVIEW,
-- NO_SHIFT_MANAGER, SHIFT_HANDOVER_ACK, TASK_SLA_APPROACHING, TASK_SLA_BREACH.
-- Esta migración los habilita todos.
--
-- Idempotente: DROP CONSTRAINT IF EXISTS + ADD.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE soc_notifications
  DROP CONSTRAINT IF EXISTS soc_notifications_type_check;

ALTER TABLE soc_notifications
  ADD CONSTRAINT soc_notifications_type_check
  CHECK (type IN (
    'AUTO_ASSIGN', 'P1_ESCALATION', 'SLA_BREACH', 'SHIFT_HANDOVER',
    'CASE_ESCALATED', 'AUTO_CLOSE', 'MENTION', 'SYSTEM',
    'SLA_APPROACHING', 'RECURRENCE_SURGE', 'CASE_ASSIGNED_BULK',
    'MONITOR_REVIEW', 'NO_SHIFT_MANAGER', 'SHIFT_HANDOVER_ACK',
    'TASK_SLA_APPROACHING', 'TASK_SLA_BREACH'
  ));
