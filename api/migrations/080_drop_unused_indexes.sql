-- 080_drop_unused_indexes.sql
-- Optimización 2026-06-06 (capa Datos/PG): elimina índices con idx_scan=0 sobre
-- la vida entera de la BD (pg_stat_database.stats_reset IS NULL → contadores
-- acumulados desde siempre). Ninguno respalda constraint (verificado contra
-- pg_constraint). Liberan ~330 MB y reducen amplificación de escritura +
-- presión de autovacuum en las tablas calientes (incident_cases_pg ~465k filas,
-- incident_case_audit ~750k, case_timeline_events ~503k).
--
-- Reversible: ver 080_drop_unused_indexes.down.sql (recrea las definiciones
-- exactas). Si alguna query futura los necesita, el planner los echará en falta
-- y se recrean; hoy NINGUNO es elegido por el planner.
--
-- NO auto-aplicada (ver memoria pg_migrations_manual). Aplicar manualmente.

-- incident_cases_pg (public) — ~163 MB de índices muertos
DROP INDEX IF EXISTS public.idx_cases_lifecycle;            --  41 MB
DROP INDEX IF EXISTS public.idx_cases_enrichment_data_gin;  --  39 MB (GIN)
DROP INDEX IF EXISTS public.idx_incpg_ioc_decay;            --  25 MB
DROP INDEX IF EXISTS public.idx_cases_ioc_closed;           -- ~10 MB
DROP INDEX IF EXISTS public.idx_cases_mitre_tactic;         -- ~6.6 MB
DROP INDEX IF EXISTS public.idx_cases_detected_at;          -- ~4.2 MB
DROP INDEX IF EXISTS public.idx_cases_scoring_version;      -- ~3.5 MB

-- incident_case_audit (legacyhunt_soc) — ~138 MB de índices muertos
DROP INDEX IF EXISTS legacyhunt_soc.idx_incident_audit_dedup;  -- 100 MB
DROP INDEX IF EXISTS legacyhunt_soc.idx_incident_audit_case;   --  38 MB

-- case_timeline_events (public) — ~7 MB
DROP INDEX IF EXISTS public.idx_case_timeline_ts;          -- ~7.1 MB

-- incident_auto_actions (public) — ~3.2 MB
DROP INDEX IF EXISTS public.idx_auto_actions_case;         -- ~3.2 MB
