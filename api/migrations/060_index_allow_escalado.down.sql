-- Down migration 060.
BEGIN;

ALTER TABLE legacyhunt_soc.incident_case_index
  DROP CONSTRAINT IF EXISTS incident_case_index_status_check;

ALTER TABLE legacyhunt_soc.incident_case_index
  ADD CONSTRAINT incident_case_index_status_check
  CHECK (status IN (
    'NUEVO', 'EN_ANALISIS', 'CONFIRMADO', 'MONITOREADO',
    'FALSO_POSITIVO', 'CERRADO',
    'OPEN', 'IN_PROGRESS', 'UNDER_REVIEW',
    'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'
  ));

COMMIT;
