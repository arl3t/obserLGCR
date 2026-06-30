-- =============================================================================
-- Migration 071 — Normalizar dual-model FALSO_POSITIVO
-- =============================================================================
-- Audit 2026-05-27 (P3.6): 2846 casos legacy quedaron con
--   status='CERRADO' + classification='FALSO_POSITIVO'
-- en lugar del modelo canónico actual:
--   status='FALSO_POSITIVO' + classification='AUTO_FP' (o similar)
--
-- Esto rompía KPIs y filtros que cuentan FP por status — el operador veía
-- "FP=1266" cuando la realidad histórica era 4112. Era doble-modelo porque
-- versiones anteriores del workflow seteaban status=CERRADO con la razón
-- como classification.
--
-- Esta migración normaliza moviendo el flag al campo correcto. Como la
-- transición es semánticamente equivalente (cerrado por FP en ambos casos)
-- no requiere postmortem ni audit en case_timeline_events — pero dejamos
-- una fila por caso con event_type='LEGACY_NORMALIZATION' para trazabilidad.
--
-- Idempotente: WHERE classification='FALSO_POSITIVO' AND status='CERRADO'
-- excluye lo ya migrado en ejecuciones previas.
-- =============================================================================

BEGIN;

-- Snapshot pre-migración para validación.
DO $$
DECLARE
  to_migrate INTEGER;
BEGIN
  SELECT COUNT(*) INTO to_migrate
    FROM incident_cases_pg
   WHERE status = 'CERRADO' AND classification = 'FALSO_POSITIVO';
  RAISE NOTICE 'mig 071: a normalizar % casos (CERRADO+FP→FALSO_POSITIVO)', to_migrate;
END
$$;

-- 1. Audit trail — fila en case_timeline_events por cada caso. event_type
--    custom porque no es una transición operacional (no la dispara un
--    operador). 'LEGACY_NORMALIZATION' identifica la causa para que el
--    historial siga siendo legible.
INSERT INTO case_timeline_events
  (id, case_id, event_type, phase, title, description, operator_ci, source, metadata, created_at)
SELECT
  gen_random_uuid(),
  c.id,
  'STATUS_CHANGE',
  'CLOSURE',
  'CERRADO → FALSO_POSITIVO (normalización legacy)',
  'Migración 071: ajuste de modelo legacy (classification ya era FALSO_POSITIVO).',
  'system',
  'MIGRATION',
  jsonb_build_object(
    'fromStatus',  'CERRADO',
    'toStatus',    'FALSO_POSITIVO',
    'via',         'migration_071',
    'reason',      'dual_model_normalization'
  ),
  now()
  FROM incident_cases_pg c
 WHERE c.status = 'CERRADO'
   AND c.classification = 'FALSO_POSITIVO';

-- 2. Update status. updated_at refresca el timestamp para que cualquier cache
--    o vista materializada que dependa de él se re-derive.
UPDATE incident_cases_pg
   SET status     = 'FALSO_POSITIVO',
       updated_at = now()
 WHERE status     = 'CERRADO'
   AND classification = 'FALSO_POSITIVO';

-- Verificación final.
DO $$
DECLARE
  remaining INTEGER;
  total_fp  INTEGER;
BEGIN
  SELECT COUNT(*) INTO remaining
    FROM incident_cases_pg
   WHERE status = 'CERRADO' AND classification = 'FALSO_POSITIVO';
  SELECT COUNT(*) INTO total_fp
    FROM incident_cases_pg
   WHERE status = 'FALSO_POSITIVO';
  RAISE NOTICE 'mig 071: % casos dual-model restantes; FALSO_POSITIVO total = %', remaining, total_fp;
END
$$;

COMMIT;
