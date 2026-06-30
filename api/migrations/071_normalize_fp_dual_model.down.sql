-- =============================================================================
-- Down: revertir mig 071 — volver a dual-model CERRADO+FP
-- =============================================================================
-- Esto sólo es seguro porque el modelo canónico nuevo usa
--   status=FALSO_POSITIVO + classification=AUTO_FP (no 'FALSO_POSITIVO')
-- así que el filtro `classification='FALSO_POSITIVO'` selecciona exactamente
-- las filas que mig 071 normalizó.
-- =============================================================================

BEGIN;

UPDATE incident_cases_pg
   SET status     = 'CERRADO',
       updated_at = now()
 WHERE status         = 'FALSO_POSITIVO'
   AND classification = 'FALSO_POSITIVO';

-- Borra el audit trail de la normalización para mantener idempotencia
-- (sí se vuelve a aplicar el up, vuelve a insertar las filas).
DELETE FROM case_timeline_events
 WHERE source = 'MIGRATION'
   AND metadata ->> 'via' = 'migration_071';

COMMIT;
