-- 080_drop_unused_indexes.down.sql — rollback de 080.
-- Recrea las definiciones EXACTAS capturadas de pg_indexes antes del drop.
-- Usa CONCURRENTLY para no bloquear las tablas calientes al recrear.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_lifecycle
  ON public.incident_cases_pg USING btree (lifecycle_stage, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_enrichment_data_gin
  ON public.incident_cases_pg USING gin (enrichment_data jsonb_path_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incpg_ioc_decay
  ON public.incident_cases_pg USING btree (ioc_value, created_at DESC)
  WHERE ((is_false_positive = false) AND ((status)::text <> 'FALSO_POSITIVO'::text));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_ioc_closed
  ON public.incident_cases_pg USING btree (ioc_value, status)
  WHERE ((status)::text = ANY ((ARRAY['CERRADO'::character varying, 'FALSO_POSITIVO'::character varying])::text[]));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_mitre_tactic
  ON public.incident_cases_pg USING btree (mitre_tactic_id) WHERE (mitre_tactic_id IS NOT NULL);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_detected_at
  ON public.incident_cases_pg USING btree (detected_at) WHERE (detected_at IS NOT NULL);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_scoring_version
  ON public.incident_cases_pg USING btree (scoring_version) WHERE (scoring_version IS NOT NULL);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incident_audit_dedup
  ON legacyhunt_soc.incident_case_audit USING btree (dedup_key, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incident_audit_case
  ON legacyhunt_soc.incident_case_audit USING btree (case_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_case_timeline_ts
  ON public.case_timeline_events USING btree (event_ts DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_auto_actions_case
  ON public.incident_auto_actions USING btree (case_id, performed_at DESC);
