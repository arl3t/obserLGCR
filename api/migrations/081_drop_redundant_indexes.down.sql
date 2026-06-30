-- 081_drop_redundant_indexes.down.sql — rollback de 081 (CONCURRENTLY, sin lock).

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_status
  ON public.incident_cases_pg USING btree (status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_escalated
  ON public.incident_cases_pg USING btree (escalated_at) WHERE (escalated_at IS NOT NULL);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_escalated_sev
  ON public.incident_cases_pg USING btree (escalated_at, severity) WHERE (escalated_at IS NOT NULL);
