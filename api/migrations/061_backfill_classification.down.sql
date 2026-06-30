-- Down 061: revierte los valores backfilled a NULL.
-- Sólo limpia los 4 valores que esta migración introdujo, dejando intactas
-- las classification escritas por flujos posteriores (humano, transitionCase).

BEGIN;

UPDATE incident_cases_pg
   SET classification = NULL,
       is_false_positive = false
 WHERE classification = 'AUTO_FP'
   AND auto_closed_reason ILIKE '[AUTO-SISTEMA]%FALSO POSITIVO%';

UPDATE incident_cases_pg
   SET classification = NULL
 WHERE classification = 'AUTO_NO_ACTIONABLE';

UPDATE incident_cases_pg
   SET classification = NULL
 WHERE classification = 'LEGACY_UNCLASSIFIED';

-- FALSE_POSITIVE backfilled (paso 3 del up): no se puede distinguir con certeza
-- de un FALSE_POSITIVE legítimo escrito post-061 por el UI, así que NO se revierte
-- masivamente. Si necesitás revertir esos 2.846 puntualmente, hacelo con un
-- script consciente del timestamp updated_at < deploy de 061.

COMMIT;
