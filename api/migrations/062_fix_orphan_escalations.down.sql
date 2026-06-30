-- Down 062: revierte los campos backfilled identificándolos por el
-- sentinel 'AUTO_SLA_BACKFILL'. No toca otras escalation_level (TIER*,
-- AUTO_SLA del path nuevo, AUTO_SLA_RECOVERED del reconciler).
--
-- Reduce el CHECK constraint a sólo los valores manuales originales — esto
-- fallará si hay datos AUTO_SLA o AUTO_SLA_RECOVERED escritos por flujos
-- post-deploy. En ese caso correr el cleanup correspondiente primero.

BEGIN;

UPDATE incident_cases_pg
   SET escalation_level  = NULL,
       escalated_to      = NULL,
       escalated_at      = NULL,
       escalation_reason = NULL,
       operator_id       = NULL,
       adopted_at        = NULL
 WHERE escalation_level = 'AUTO_SLA_BACKFILL';

ALTER TABLE incident_cases_pg
  DROP CONSTRAINT IF EXISTS incident_cases_pg_escalation_level_check;
ALTER TABLE incident_cases_pg
  ADD CONSTRAINT incident_cases_pg_escalation_level_check
  CHECK (escalation_level IN ('TIER1', 'TIER2', 'IR', 'EXECUTIVE', 'EXTERNAL'));

COMMIT;
