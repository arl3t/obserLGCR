-- 072_auto_close_candidates_dedup_key.sql
-- P0 dedup-churn (auditoría 2026-06-04): `autoCloseLowNegligible` cierra LOW/
-- NEGLIGIBLE en lote pero no alimentaba `case_suppressions`, así que el DAG y la
-- API recreaban el mismo dedup_key apenas el caso se cerraba (~90k LOW/semana).
--
-- Para suprimir-al-cerrar, el job necesita el `dedup_key` de cada candidato.
-- `v_auto_close_candidates` no lo exponía. Esta migración lo agrega (idempotente
-- vía CREATE OR REPLACE; el orden y nombres de las demás columnas se preservan).

CREATE OR REPLACE VIEW v_auto_close_candidates AS
  SELECT id,
         severity,
         status,
         lifecycle_stage,
         score,
         created_at,
         ioc_value,
         operator_id,
         dedup_key
    FROM incident_cases_pg
   WHERE severity::text = ANY (ARRAY['LOW'::varchar, 'NEGLIGIBLE'::varchar]::text[])
     AND status::text   = ANY (ARRAY['NUEVO'::varchar, 'EN_ANALISIS'::varchar]::text[])
     AND auto_closed_at IS NULL
     AND created_at >= (now() - '7 days'::interval);
