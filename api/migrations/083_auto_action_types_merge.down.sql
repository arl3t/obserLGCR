-- Revertir mig 083 — restaurar el CHECK original de mig 008.
-- NOTA: si existen filas con AUTO_INTEL_ESCALATE / AUTO_MERGE_* este ADD fallará;
-- borrarlas o reasignar el action_type antes de revertir.

ALTER TABLE incident_auto_actions
  DROP CONSTRAINT IF EXISTS incident_auto_actions_action_type_check;

ALTER TABLE incident_auto_actions
  ADD CONSTRAINT incident_auto_actions_action_type_check
  CHECK (action_type IN (
    'AUTO_CLOSE_LOW',
    'AUTO_CLOSE_NEGLIGIBLE',
    'AUTO_ASSIGN_TIMEOUT',
    'AUTO_ESCALATE_SCORE',
    'AUTO_ESCALATE_TACTIC',
    'SLA_BREACH_ALERT',
    'HANDOVER_CREATED'
  ));
