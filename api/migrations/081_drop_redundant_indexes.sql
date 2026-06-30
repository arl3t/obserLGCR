-- 081_drop_redundant_indexes.sql
-- Optimización 2026-06-06 (Fase 2, revisión de índices de bajo uso).
-- Complementa 080 (índices con idx_scan=0 >1MB). Aquí: redundancia de prefijo y
-- dos índices muertos pequeños sobre incident_cases_pg (la tabla más caliente,
-- con churn constante de auto-cierre → cada índice cuesta en cada INSERT/UPDATE).
--
--   · idx_cases_status (status): redundante — prefijo de idx_cases_status_created
--     (status, created_at DESC). Verificado con EXPLAIN: el planner YA usa la
--     composite para `WHERE status = ?` (Index Only Scan), no este.
--   · idx_cases_escalated (escalated_at) e idx_cases_escalated_sev
--     (escalated_at, severity): ambos idx_scan=0 sobre la vida de la BD.
--
-- Reversible: ver .down.sql. NO auto-aplicada (ver memoria pg_migrations_manual).

DROP INDEX IF EXISTS public.idx_cases_status;          -- redundante (prefijo de status_created)
DROP INDEX IF EXISTS public.idx_cases_escalated;       -- idx_scan=0
DROP INDEX IF EXISTS public.idx_cases_escalated_sev;   -- idx_scan=0
