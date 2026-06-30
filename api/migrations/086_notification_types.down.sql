-- Revertir mig 086 — restaurar CHECK original (mig 008).
-- Fallará si existen filas con tipos nuevos; borrarlas/reasignar antes.
ALTER TABLE soc_notifications DROP CONSTRAINT IF EXISTS soc_notifications_type_check;
ALTER TABLE soc_notifications ADD CONSTRAINT soc_notifications_type_check
  CHECK (type IN ('AUTO_ASSIGN','P1_ESCALATION','SLA_BREACH','SHIFT_HANDOVER','CASE_ESCALATED','AUTO_CLOSE','MENTION','SYSTEM'));
