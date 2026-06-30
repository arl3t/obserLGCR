-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 012 — Fix v_auto_close_candidates
--
-- Problema: la vista original usaba `status NOT IN ('CERRADO','FALSO_POSITIVO')`
-- lo que incluía CONFIRMADO, ESCALADO y MONITOREADO — estados en los que un
-- analista L2/L3 puede estar trabajando activamente aunque la severidad sea LOW.
-- El auto-close cerraba esos casos por debajo del analista.
--
-- Fix: restringir a status IN ('NUEVO','EN_ANALISIS') — solo triaje pendiente.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE VIEW v_auto_close_candidates AS
SELECT id, severity, status, lifecycle_stage, score, created_at, ioc_value, operator_id
FROM incident_cases_pg
WHERE severity IN ('LOW','NEGLIGIBLE')
  AND status IN ('NUEVO','EN_ANALISIS')
  AND auto_closed_at IS NULL
  AND created_at >= now() - INTERVAL '7 days';
