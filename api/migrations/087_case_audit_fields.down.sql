-- Revertir mig 087.
DROP INDEX IF EXISTS idx_cases_reopened;
ALTER TABLE incident_cases_pg
  DROP COLUMN IF EXISTS resolution_action,
  DROP COLUMN IF EXISTS root_cause_category,
  DROP COLUMN IF EXISTS reopened_count,
  DROP COLUMN IF EXISTS sla_breach_at,
  DROP COLUMN IF EXISTS escalation_path,
  DROP COLUMN IF EXISTS stage_entered_at,
  DROP COLUMN IF EXISTS stage_durations;
