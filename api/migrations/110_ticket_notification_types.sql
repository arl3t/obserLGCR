-- 110_ticket_notification_types.sql
-- Extiende el CHECK de soc_notifications.type con los tipos del Sistema de Tickets
-- (auto-asignación de ticket al operador). Permite que la campana de notificaciones
-- existente muestre también las asignaciones de ticket. Ver docs/PROPUESTA-TICKETING-PUBLICO.md.
ALTER TABLE soc_notifications DROP CONSTRAINT IF EXISTS soc_notifications_type_check;
ALTER TABLE soc_notifications
  ADD CONSTRAINT soc_notifications_type_check
  CHECK (type IN (
    'AUTO_ASSIGN', 'P1_ESCALATION', 'SLA_BREACH', 'SHIFT_HANDOVER',
    'CASE_ESCALATED', 'AUTO_CLOSE', 'MENTION', 'SYSTEM',
    'SLA_APPROACHING', 'RECURRENCE_SURGE', 'CASE_ASSIGNED_BULK',
    'MONITOR_REVIEW', 'NO_SHIFT_MANAGER', 'SHIFT_HANDOVER_ACK',
    'TASK_SLA_APPROACHING', 'TASK_SLA_BREACH',
    'TICKET_ASSIGN', 'TICKET_NEW'
  ));
