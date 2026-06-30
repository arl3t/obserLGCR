-- 091_case_number.down.sql — revierte 091_case_number.sql
DROP TRIGGER IF EXISTS trg_assign_case_number ON incident_cases_pg;
DROP FUNCTION IF EXISTS assign_case_number();
DROP INDEX IF EXISTS idx_incident_cases_case_number;
DROP INDEX IF EXISTS uq_incident_cases_case_number;
ALTER TABLE incident_cases_pg DROP COLUMN IF EXISTS case_number;
DROP SEQUENCE IF EXISTS incident_case_number_seq;
