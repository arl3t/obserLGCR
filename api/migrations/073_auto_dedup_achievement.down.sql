-- Revierte 073: restaura v_soc_kpis con el proxy auto_dedup_pct (1 - distinct/total).

CREATE OR REPLACE VIEW v_soc_kpis AS
WITH base90 AS (
         SELECT incident_cases_pg.id,
            incident_cases_pg.ioc_value,
            incident_cases_pg.severity,
            incident_cases_pg.status,
            incident_cases_pg.operator_id,
            incident_cases_pg.mitre_tactic_id,
            incident_cases_pg.lessons_learned,
            incident_cases_pg.created_at,
            incident_cases_pg.updated_at,
            incident_cases_pg.adopted_at,
            incident_cases_pg.escalated_at,
            incident_cases_pg.resolved_at,
            incident_cases_pg.detected_at,
            incident_cases_pg.anchor_dt,
            incident_cases_pg.auto_closed_at
           FROM incident_cases_pg
          WHERE incident_cases_pg.created_at >= (now() - '90 days'::interval)
        ), base AS (
         SELECT base90.id,
            base90.ioc_value,
            base90.severity,
            base90.status,
            base90.operator_id,
            base90.mitre_tactic_id,
            base90.lessons_learned,
            base90.created_at,
            base90.updated_at,
            base90.adopted_at,
            base90.escalated_at,
            base90.resolved_at,
            base90.detected_at,
            base90.anchor_dt,
            base90.auto_closed_at,
            base90.created_at >= (now() - '7 days'::interval) AS in_w7,
            base90.created_at >= (now() - '30 days'::interval) AS in_w30
           FROM base90
        ), mttc_cte AS (
         SELECT round(avg(EXTRACT(epoch FROM ct.event_ts - c.created_at) / 60.0), 1) AS mttc_min
           FROM base c
             JOIN ( SELECT DISTINCT ON (case_timeline_events.case_id) case_timeline_events.case_id,
                    case_timeline_events.event_ts
                   FROM case_timeline_events
                  WHERE case_timeline_events.event_type::text = 'CONTAINMENT'::text
                  ORDER BY case_timeline_events.case_id, case_timeline_events.event_ts) ct ON ct.case_id::text = c.id::text
          WHERE c.in_w7
        )
 SELECT count(*) FILTER (WHERE status::text <> ALL (ARRAY['CERRADO'::character varying, 'FALSO_POSITIVO'::character varying]::text[])) AS open_cases,
    count(*) FILTER (WHERE status::text = 'CERRADO'::text) AS closed_cases,
    count(*) FILTER (WHERE status::text = 'MONITOREADO'::text) AS monitoring,
    count(*) FILTER (WHERE status::text = 'CERRADO'::text AND updated_at >= CURRENT_DATE AND NOT ((severity::text = ANY (ARRAY['LOW'::character varying, 'NEGLIGIBLE'::character varying]::text[])) AND operator_id IS NULL)) AS resolved_today,
    count(*) FILTER (WHERE in_w7 AND status::text = 'FALSO_POSITIVO'::text) AS auto_fp,
    count(*) FILTER (WHERE in_w7 AND severity::text = 'CRITICAL'::text AND adopted_at IS NOT NULL) AS critical_sla_ok,
    count(*) FILTER (WHERE in_w7 AND severity::text = 'CRITICAL'::text) AS critical_sla_total,
    round(avg(EXTRACT(epoch FROM adopted_at - created_at) / 60.0) FILTER (WHERE in_w7 AND severity::text = 'CRITICAL'::text AND adopted_at IS NOT NULL)) AS critical_avg_ack_min,
    round(avg(EXTRACT(epoch FROM created_at - COALESCE(detected_at, anchor_dt::timestamp with time zone)) / 60.0) FILTER (WHERE in_w7 AND COALESCE(detected_at, anchor_dt::timestamp with time zone) < created_at), 1) AS mttd_min,
    round(avg(EXTRACT(epoch FROM adopted_at - created_at) / 60.0) FILTER (WHERE in_w7 AND adopted_at IS NOT NULL AND auto_closed_at IS NULL AND operator_id IS NOT NULL AND (operator_id::text <> ALL (ARRAY['SYSTEM'::character varying, 'system'::character varying]::text[])) AND operator_id::text !~~ 'auto%'::text), 1) AS mtta_min,
    round(avg(EXTRACT(epoch FROM COALESCE(resolved_at, updated_at) - created_at) / 60.0) FILTER (WHERE in_w7 AND status::text = 'CERRADO'::text AND auto_closed_at IS NULL AND NOT ((severity::text = ANY (ARRAY['LOW'::character varying, 'NEGLIGIBLE'::character varying]::text[])) AND operator_id IS NULL) AND (operator_id IS NULL OR (operator_id::text <> ALL (ARRAY['SYSTEM'::character varying, 'system'::character varying]::text[])) AND operator_id::text !~~ 'auto%'::text)), 1) AS mttr_min,
    ( SELECT mttc_cte.mttc_min
           FROM mttc_cte) AS mttc_min,
    round(count(*) FILTER (WHERE in_w7 AND status::text = 'FALSO_POSITIVO'::text)::numeric * 100.0 / NULLIF(count(*) FILTER (WHERE in_w7 AND (status::text = ANY (ARRAY['CERRADO'::character varying, 'FALSO_POSITIVO'::character varying]::text[]))), 0)::numeric, 1) AS fp_rate,
    round(count(DISTINCT mitre_tactic_id) FILTER (WHERE in_w30 AND mitre_tactic_id IS NOT NULL)::numeric * 100.0 / 14.0, 1) AS mitre_coverage_pct,
    round(
        CASE
            WHEN count(*) FILTER (WHERE in_w7) = 0 THEN NULL::numeric
            ELSE (1.0 - count(DISTINCT COALESCE(ioc_value, id)) FILTER (WHERE in_w7)::numeric / NULLIF(count(*) FILTER (WHERE in_w7), 0)::numeric) * 100.0
        END, 1) AS auto_dedup_pct,
    round(avg(EXTRACT(epoch FROM escalated_at - adopted_at) / 60.0) FILTER (WHERE in_w7 AND escalated_at IS NOT NULL AND adopted_at IS NOT NULL AND (severity::text = ANY (ARRAY['CRITICAL'::character varying, 'HIGH'::character varying]::text[]))), 1) AS l1_l2_esc_min,
    round(count(*) FILTER (WHERE in_w7 AND mitre_tactic_id IS NULL)::numeric * 100.0 / NULLIF(count(*) FILTER (WHERE in_w7), 0)::numeric, 1) AS wazuh_fallback_pct,
    round(count(*) FILTER (WHERE in_w30 AND lessons_learned IS NOT NULL AND lessons_learned <> ''::text)::numeric * 100.0 / NULLIF(count(*) FILTER (WHERE in_w30 AND status::text = 'CERRADO'::text), 0)::numeric, 1) AS postmortem_rate,
    round(count(*) FILTER (WHERE in_w7 AND severity::text = 'CRITICAL'::text AND adopted_at IS NOT NULL AND (EXTRACT(epoch FROM adopted_at - created_at) / 60.0) <= 60::numeric)::numeric * 100.0 / NULLIF(count(*) FILTER (WHERE in_w7 AND severity::text = 'CRITICAL'::text), 0)::numeric, 1) AS sla_critical_pct,
    round(count(*) FILTER (WHERE in_w7 AND escalated_at IS NOT NULL)::numeric * 100.0 / NULLIF(count(*) FILTER (WHERE in_w7), 0)::numeric, 1) AS escalation_rate,
    now() AS computed_at
   FROM base;
;
