-- Revertir mig 088.
DROP INDEX IF EXISTS idx_cases_incident_class;
ALTER TABLE incident_cases_pg
  DROP COLUMN IF EXISTS incident_class;
