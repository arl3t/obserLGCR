-- 061_backfill_classification.sql
-- Audit 2026-05-26 (P1 derivado de P2-9): backfill de classification para los
-- 288 K casos cerrados sin clasificación. El nuevo flujo PATCH /status exige
-- classification al cerrar, pero el histórico nunca la tuvo → las métricas FP/TP
-- son ruido hoy.
--
-- Heurística (no destructiva, sólo afecta `classification IS NULL`):
--   1. status=FALSO_POSITIVO con `[AUTO-SISTEMA]...FALSO POSITIVO confirmado`
--      → AUTO_FP (1.266 casos, valor ya existente en VALID_CLASSIFICATIONS).
--   2. status=CERRADO con `Severity too low for manual triage (auto-closed by system)`
--      → AUTO_NO_ACTIONABLE (20.426 casos, valor nuevo system-only).
--   3. status=CERRADO|FALSO_POSITIVO con is_false_positive=true (sin reason auto)
--      → FALSE_POSITIVE (~2.846 casos manuales pre-classification).
--   4. resto (histórico manual sin clasificar) → LEGACY_UNCLASSIFIED
--      (~266.760 casos, valor nuevo system-only). Marca que no se puede usar
--      este caso en cálculos de precisión TP/FP — son datos sin verdad básica.
--
-- Valores nuevos NO están en VALID_CLASSIFICATIONS (workflowEngine.mjs) ni en
-- VALID_CLASS (routes/incidents.mjs) — son **system-only**, no aparecen en el
-- dropdown del UI. Sólo viven en el histórico backfilled.
--
-- Idempotente: re-correrla no toca filas con classification ya seteada.

BEGIN;

-- 1. AUTO_FP — auto-cerrados como FP por intel limpio + score bajo
UPDATE incident_cases_pg
   SET classification     = 'AUTO_FP',
       is_false_positive  = true
 WHERE classification IS NULL
   AND status = 'FALSO_POSITIVO'
   AND auto_closed_reason ILIKE '[AUTO-SISTEMA]%FALSO POSITIVO%';

-- 2. AUTO_NO_ACTIONABLE — severidad demasiado baja para triage manual
UPDATE incident_cases_pg
   SET classification = 'AUTO_NO_ACTIONABLE'
 WHERE classification IS NULL
   AND status = 'CERRADO'
   AND auto_closed_reason ILIKE 'Severity too low%';

-- 3. FALSE_POSITIVE — cierres manuales pre-classification con flag is_false_positive
UPDATE incident_cases_pg
   SET classification = 'FALSE_POSITIVE'
 WHERE classification IS NULL
   AND status IN ('CERRADO','FALSO_POSITIVO')
   AND is_false_positive = true;

-- 4. LEGACY_UNCLASSIFIED — resto del histórico (sin metadata para clasificar)
UPDATE incident_cases_pg
   SET classification = 'LEGACY_UNCLASSIFIED'
 WHERE classification IS NULL
   AND status IN ('CERRADO','FALSO_POSITIVO');

-- Verificación post-backfill: deben quedar 0 cerrados sin classification.
-- Si NO es 0 (porque entró un caso entre los UPDATE), igual queda como
-- backfill incremental — re-correr la migración lo recupera.
DO $$
DECLARE
  remaining INTEGER;
BEGIN
  SELECT COUNT(*) INTO remaining
    FROM incident_cases_pg
   WHERE status IN ('CERRADO','FALSO_POSITIVO') AND classification IS NULL;
  RAISE NOTICE 'cerrados sin classification tras backfill: %', remaining;
END
$$;

COMMIT;
