-- 055_scoring_version.down.sql — rollback de 055_scoring_version.sql

DROP INDEX IF EXISTS idx_cases_scoring_version;

ALTER TABLE incident_cases_pg
  DROP COLUMN IF EXISTS scoring_version;
