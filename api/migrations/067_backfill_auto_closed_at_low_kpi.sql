-- =============================================================================
-- Migration 067 — Backfill auto_closed_at para cierres LOW del DAG sync
-- =============================================================================
-- Audit 2026-05-27: MTTR en soc_kpis_window mostraba n_mttr=0 sobre 97,255
-- casos cerrados sin auto_closed_at. Análisis:
--   - 79,259 con scoring_version='v4' del DAG incident_cases_sync_daily.
--   - 18,019 sin scoring_version (legacy, mismo path).
--   - TODOS son LOW con operator_id NULL.
--
-- Causa raíz: data/airflow/dags/incident_cases_sync_daily.py:1146 cerraba
-- via UPDATE simple sin escribir auto_closed_at — esos casos caían en el
-- filtro "huérfanos LOW" del MTTR (`NOT (severity IN ('LOW','NEGLIGIBLE')
-- AND operator_id IS NULL)`), excluyéndolos del agregado.
--
-- Fix DAG: el UPDATE ahora setea auto_closed_at + auto_closed_reason +
-- resolved_at (commit 2026-05-27). Esta migration backfillea los huérfanos
-- existentes: usa updated_at como proxy del momento real de auto-cierre.
--
-- Idempotente: filtro `auto_closed_at IS NULL` excluye los ya backfilleados.
-- =============================================================================

UPDATE incident_cases_pg
   SET auto_closed_at     = COALESCE(updated_at, now()),
       auto_closed_reason = 'AUTO-CERRADO: severidad LOW — backfill 067 (DAG sync histórico)',
       resolved_at        = COALESCE(resolved_at, updated_at, now())
 WHERE status = 'CERRADO'
   AND severity IN ('LOW','NEGLIGIBLE')
   AND auto_closed_at IS NULL
   AND operator_id IS NULL;
