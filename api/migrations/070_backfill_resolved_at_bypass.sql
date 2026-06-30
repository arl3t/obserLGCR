-- =============================================================================
-- Migration 070 — Backfill resolved_at para closures que bypassearon workflowEngine
-- =============================================================================
-- Audit 2026-05-27: 1571 casos en status terminal con resolved_at NULL.
-- Root cause: pgUpsertCase (routes/incidents.mjs) y autoClassifyController
-- escribían status='CERRADO'/'FALSO_POSITIVO' sin setear resolved_at —
-- workflowEngine.transitionCase era el único path que lo hacía. Fixes en
-- código:
--   - routes/incidents.mjs::pgUpsertCase  → setea resolved_at en TERMINAL_STATUSES
--   - controllers/autoClassifyController  → setea resolved_at junto a auto_closed_at
--
-- Esta migración recupera el histórico:
--   * 1263 AUTO_FP (auto-clasificación):  resolved_at ← auto_closed_at
--   * 308  LEGACY_UNCLASSIFIED (manual):  resolved_at ← last STATUS_CHANGE ts
--                                          en JSONB timeline; fallback updated_at
--                                          (caveat: 68 de esos 308 tienen
--                                           updated_at corrompido por mig 064 →
--                                           el timeline-derived ts es mejor proxy)
--
-- Una vez aplicada, mig 069 puede revertirse (el filtro defensivo era workaround
-- de este síntoma) — no se hace en este commit, requiere validación KPI separada.
--
-- Idempotente: WHERE resolved_at IS NULL excluye las ya backfilleadas.
-- =============================================================================

BEGIN;

-- 1. AUTO_FP — auto_closed_at es la fuente canónica del momento de cierre.
UPDATE incident_cases_pg
   SET resolved_at = auto_closed_at
 WHERE status IN ('CERRADO','FALSO_POSITIVO')
   AND resolved_at IS NULL
   AND auto_closed_at IS NOT NULL;

-- 2. LEGACY_UNCLASSIFIED — buscar el último STATUS_CHANGE→terminal en el
--    JSONB `timeline`. pgUpsertCase appendea entries con shape
--    {ts, action, operator, detail}, action='STATUS_CHANGE',
--    detail='CERRADO[: reason]' o 'FALSO_POSITIVO[: reason]'.
WITH derived AS (
  SELECT
    c.id,
    (
      SELECT (elem ->> 'ts')::timestamptz
        FROM jsonb_array_elements(c.timeline) AS elem
       WHERE elem ->> 'action' = 'STATUS_CHANGE'
         AND (elem ->> 'detail' ILIKE 'CERRADO%'
              OR elem ->> 'detail' ILIKE 'FALSO_POSITIVO%')
       ORDER BY (elem ->> 'ts')::timestamptz DESC
       LIMIT 1
    ) AS tl_ts
    FROM incident_cases_pg c
   WHERE c.status IN ('CERRADO','FALSO_POSITIVO')
     AND c.resolved_at IS NULL
     AND c.timeline IS NOT NULL
)
UPDATE incident_cases_pg c
   SET resolved_at = d.tl_ts
  FROM derived d
 WHERE c.id = d.id
   AND d.tl_ts IS NOT NULL;

-- 3. Fallback — los pocos sin timeline parseable usan updated_at.
--    Best effort; semánticamente "cuándo se cerró" se pierde, pero el filtro
--    KPI ya no los excluye (resolved_at IS NULL → MTTR los descartaba).
UPDATE incident_cases_pg
   SET resolved_at = updated_at
 WHERE status IN ('CERRADO','FALSO_POSITIVO')
   AND resolved_at IS NULL;

-- Verificación final.
DO $$
DECLARE
  remaining INTEGER;
BEGIN
  SELECT COUNT(*) INTO remaining
    FROM incident_cases_pg
   WHERE status IN ('CERRADO','FALSO_POSITIVO') AND resolved_at IS NULL;
  RAISE NOTICE 'casos terminales sin resolved_at tras backfill: %', remaining;
END
$$;

COMMIT;
