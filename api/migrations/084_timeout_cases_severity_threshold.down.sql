-- Revertir mig 084 — restaurar umbral fijo de 30 min para todas las severidades.
CREATE OR REPLACE VIEW v_timeout_cases AS
SELECT id, severity, status, score, created_at, ioc_value, mitre_tactic_name,
       round(EXTRACT(epoch FROM now() - created_at) / 60::numeric) AS minutes_unadopted
  FROM incident_cases_pg c
 WHERE (status::text = ANY (ARRAY['NUEVO','EN_ANALISIS']::text[]))
   AND adopted_at IS NULL AND shift_manager_assigned_at IS NULL
   AND (EXTRACT(epoch FROM now() - created_at) / 60::numeric) >= 30::numeric
   AND (severity::text <> ALL (ARRAY['LOW','NEGLIGIBLE']::text[]))
   AND created_at >= (now() - '7 days'::interval);
