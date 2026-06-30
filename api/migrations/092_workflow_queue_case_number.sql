-- 092_workflow_queue_case_number.sql
-- Expone case_number en la cola de gestión (v_workflow_queue) para que la UI
-- muestre el código corto (INC-000123) como identificador principal del caso.
-- CREATE OR REPLACE exige conservar el orden de columnas existente y solo añadir
-- al final → case_number va último.
CREATE OR REPLACE VIEW v_workflow_queue AS
 SELECT id,
    severity,
    status,
    lifecycle_stage,
    assigned_role,
    score,
    ioc_value,
    ioc_type,
    source_log,
    mitre_tactic_name,
    mitre_technique_id,
    operator_id,
    adopted_at,
    created_at,
    escalation_suggested,
    escalation_reason_auto,
    shift_manager_assigned_at,
    shift_manager_ci,
    EXTRACT(epoch FROM now() - created_at) / 60::numeric AS elapsed_min,
        CASE severity
            WHEN 'CRITICAL'::text THEN 60
            WHEN 'HIGH'::text THEN 240
            WHEN 'MEDIUM'::text THEN 480
            ELSE 1440
        END AS sla_min,
    round(EXTRACT(epoch FROM now() - created_at) / 60::numeric /
        CASE severity
            WHEN 'CRITICAL'::text THEN 60
            WHEN 'HIGH'::text THEN 240
            WHEN 'MEDIUM'::text THEN 480
            ELSE 1440
        END::numeric * 100::numeric) AS sla_pct_consumed,
        CASE
            WHEN adopted_at IS NULL THEN round(EXTRACT(epoch FROM now() - created_at) / 60::numeric)
            ELSE NULL::numeric
        END AS unacknowledged_min,
    case_number
   FROM incident_cases_pg c
  WHERE (status::text <> ALL (ARRAY['CERRADO'::character varying, 'FALSO_POSITIVO'::character varying]::text[])) AND created_at >= (now() - '90 days'::interval)
  ORDER BY (
        CASE severity
            WHEN 'CRITICAL'::text THEN 1
            WHEN 'HIGH'::text THEN 2
            WHEN 'MEDIUM'::text THEN 3
            ELSE 4
        END), score DESC, created_at;
