-- Revierte 072: restaura v_auto_close_candidates sin la columna dedup_key.

CREATE OR REPLACE VIEW v_auto_close_candidates AS
  SELECT id,
         severity,
         status,
         lifecycle_stage,
         score,
         created_at,
         ioc_value,
         operator_id
    FROM incident_cases_pg
   WHERE severity::text = ANY (ARRAY['LOW'::varchar, 'NEGLIGIBLE'::varchar]::text[])
     AND status::text   = ANY (ARRAY['NUEVO'::varchar, 'EN_ANALISIS'::varchar]::text[])
     AND auto_closed_at IS NULL
     AND created_at >= (now() - '7 days'::interval);
