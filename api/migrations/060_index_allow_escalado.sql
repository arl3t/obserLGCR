-- Migration 060: agregar ESCALADO al check constraint de incident_case_index
--
-- Audit 2026-05-26: el índice canónico nunca aceptó ESCALADO como status,
-- mientras incident_cases_pg sí lo usa. Resultado: 1.009 casos están
-- ESCALADO en PG pero quedaron NUEVO en el índice, y el DAG sync_daily
-- los reabre como nuevos (su query de dedup tampoco filtra ESCALADO).
--
-- Esta migración:
--   1. Reemplaza el check constraint para incluir 'ESCALADO'.
--   2. Define el set de status válidos como referencia en comentario.
--
-- El DAG `incident_cases_sync_daily` debe agregar ESCALADO a su query de
-- dedup en un cambio paralelo (línea 619-620, 665-666, etc.).

BEGIN;

ALTER TABLE legacyhunt_soc.incident_case_index
  DROP CONSTRAINT IF EXISTS incident_case_index_status_check;

ALTER TABLE legacyhunt_soc.incident_case_index
  ADD CONSTRAINT incident_case_index_status_check
  CHECK (status IN (
    -- estados v2 (canónicos hoy)
    'NUEVO', 'EN_ANALISIS', 'CONFIRMADO', 'MONITOREADO',
    'ESCALADO', 'FALSO_POSITIVO', 'CERRADO',
    -- estados v1 (legacy, lectura solo)
    'OPEN', 'IN_PROGRESS', 'UNDER_REVIEW',
    'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'
  ));

COMMIT;
