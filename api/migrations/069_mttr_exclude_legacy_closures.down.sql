-- Rollback 069 → vuelve a la fórmula MTTR de la migración 068
-- (closed_in_w sin filtros adicionales de resolved_at / classification).
-- Re-aplica 068 manualmente para revertir.

\echo 'Para revertir, re-aplica la migración 068_mttr_filter_closed_in_window.sql'
