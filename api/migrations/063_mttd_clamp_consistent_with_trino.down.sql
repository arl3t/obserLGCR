-- Down 063 — revertir a la versión 049 sin clamp 24h en MTTD.
-- Re-instala soc_kpis_window tal como quedó tras 049_mttc_multisource_and_mitre_coverage.sql.

CREATE OR REPLACE FUNCTION soc_kpis_window(p_hours int DEFAULT 168)
RETURNS TABLE (
  open_cases           bigint,
  closed_cases         bigint,
  monitoring           bigint,
  resolved_today       bigint,
  auto_fp              bigint,
  critical_sla_ok      bigint,
  critical_sla_total   bigint,
  critical_avg_ack_min numeric,
  mttd_min             numeric,
  mtta_min             numeric,
  mttr_min             numeric,
  mttc_min             numeric,
  fp_rate              numeric,
  mitre_coverage_pct   numeric,
  auto_dedup_pct       numeric,
  l1_l2_esc_min        numeric,
  wazuh_fallback_pct   numeric,
  postmortem_rate      numeric,
  sla_critical_pct     numeric,
  escalation_rate      numeric,
  coverage_by_source   jsonb,
  n_mttd               bigint,
  n_mtta               bigint,
  n_mttr               bigint,
  n_mttc               bigint,
  computed_at          timestamptz
) AS $$
  WITH base90 AS (
    SELECT id, ioc_value, severity, status, operator_id,
           mitre_tactic_id, lessons_learned,
           created_at, updated_at, adopted_at, escalated_at,
           resolved_at, detected_at, anchor_dt, auto_closed_at,
           source_log, firewall_action
      FROM incident_cases_pg
     WHERE created_at >= now() - INTERVAL '90 days'
  ),
  base AS (
    SELECT *,
           created_at >= now() - make_interval(hours => p_hours) AS in_w,
           created_at >= now() - INTERVAL '30 days'              AS in_w30
      FROM base90
  ),
  mttc_explicit AS (
    SELECT c.id AS case_id, c.created_at, ct.event_ts AS contained_at
      FROM base c
      JOIN (
        SELECT DISTINCT ON (case_id) case_id, event_ts
          FROM case_timeline_events WHERE event_type = 'CONTAINMENT'
         ORDER BY case_id, event_ts
      ) ct ON ct.case_id::text = c.id::text
     WHERE c.in_w
  ),
  mttc_implicit AS (
    SELECT c.id AS case_id, c.created_at, c.auto_closed_at AS contained_at
      FROM base c
     WHERE c.in_w AND c.auto_closed_at IS NOT NULL
       AND c.status NOT IN ('FALSO_POSITIVO')
       AND UPPER(COALESCE(c.firewall_action, ''))
           IN ('BLOCK','DENY','DROP','RESET-DROP','RESET-CLIENT','RESET-SERVER','BLOCKED')
       AND c.id::text NOT IN (SELECT case_id FROM mttc_explicit)
  ),
  mttc_cte AS (
    SELECT ROUND(AVG(EXTRACT(EPOCH FROM contained_at - created_at) / 60.0)::numeric, 1) AS mttc_min,
           COUNT(*)::bigint AS n_mttc
      FROM (SELECT * FROM mttc_explicit UNION ALL SELECT * FROM mttc_implicit) u
  ),
  coverage_cte AS (
    SELECT jsonb_agg(jsonb_build_object('source_log', COALESCE(source_log, '(sin fuente)'),
             'total', total, 'mapped', mapped, 'pct', pct) ORDER BY total DESC) AS by_source
      FROM (SELECT source_log, COUNT(*) AS total,
             COUNT(*) FILTER (WHERE mitre_tactic_id IS NOT NULL) AS mapped,
             ROUND(COUNT(*) FILTER (WHERE mitre_tactic_id IS NOT NULL)::numeric * 100.0
                   / NULLIF(COUNT(*), 0)::numeric, 1) AS pct
              FROM base WHERE in_w GROUP BY source_log HAVING COUNT(*) >= 1) g
  )
  SELECT
    COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO')),
    COUNT(*) FILTER (WHERE status = 'CERRADO'),
    COUNT(*) FILTER (WHERE status = 'MONITOREADO'),
    COUNT(*) FILTER (WHERE status = 'CERRADO' AND updated_at >= CURRENT_DATE
                      AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)),
    COUNT(*) FILTER (WHERE in_w AND status = 'FALSO_POSITIVO'),
    COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL),
    COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL'),
    ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
          FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL)),
    ROUND(AVG(EXTRACT(EPOCH FROM created_at - detected_at) / 60.0)
          FILTER (WHERE in_w AND detected_at IS NOT NULL AND detected_at < created_at), 1),
    ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
          FILTER (WHERE in_w AND adopted_at IS NOT NULL AND auto_closed_at IS NULL
                    AND operator_id IS NOT NULL AND operator_id NOT IN ('SYSTEM','system')
                    AND operator_id NOT LIKE 'auto%'), 1),
    ROUND(AVG(EXTRACT(EPOCH FROM COALESCE(resolved_at, updated_at) - created_at) / 60.0)
          FILTER (WHERE in_w AND status = 'CERRADO' AND auto_closed_at IS NULL
                    AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                    AND (operator_id IS NULL OR (operator_id NOT IN ('SYSTEM','system')
                         AND operator_id NOT LIKE 'auto%'))), 1),
    (SELECT mttc_min FROM mttc_cte),
    ROUND(COUNT(*) FILTER (WHERE in_w AND status = 'FALSO_POSITIVO')::numeric * 100.0
          / NULLIF(COUNT(*) FILTER (WHERE in_w AND status IN ('CERRADO','FALSO_POSITIVO')), 0)::numeric, 1),
    ROUND(COUNT(DISTINCT mitre_tactic_id) FILTER (WHERE in_w30 AND mitre_tactic_id IS NOT NULL)::numeric
          * 100.0 / 14.0, 1),
    ROUND(CASE WHEN COUNT(*) FILTER (WHERE in_w) = 0 THEN NULL
          ELSE (1.0 - COUNT(DISTINCT COALESCE(ioc_value, id)) FILTER (WHERE in_w)::numeric
                     / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric) * 100.0 END, 1),
    ROUND(AVG(EXTRACT(EPOCH FROM escalated_at - adopted_at) / 60.0)
          FILTER (WHERE in_w AND escalated_at IS NOT NULL AND adopted_at IS NOT NULL
                    AND severity IN ('CRITICAL','HIGH')), 1),
    ROUND(COUNT(*) FILTER (WHERE in_w AND mitre_tactic_id IS NULL)::numeric * 100.0
          / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric, 1),
    ROUND(COUNT(*) FILTER (WHERE in_w30 AND lessons_learned IS NOT NULL AND lessons_learned <> '')::numeric
          * 100.0 / NULLIF(COUNT(*) FILTER (WHERE in_w30 AND status = 'CERRADO'), 0)::numeric, 1),
    ROUND(COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL
                         AND EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0 <= 60)::numeric
          * 100.0 / NULLIF(COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL'), 0)::numeric, 1),
    ROUND(COUNT(*) FILTER (WHERE in_w AND escalated_at IS NOT NULL)::numeric * 100.0
          / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric, 1),
    (SELECT by_source FROM coverage_cte),
    COUNT(*) FILTER (WHERE in_w AND detected_at IS NOT NULL AND detected_at < created_at)::bigint,
    COUNT(*) FILTER (WHERE in_w AND adopted_at IS NOT NULL AND auto_closed_at IS NULL
                       AND operator_id IS NOT NULL AND operator_id NOT IN ('SYSTEM','system')
                       AND operator_id NOT LIKE 'auto%')::bigint,
    COUNT(*) FILTER (WHERE in_w AND status = 'CERRADO' AND auto_closed_at IS NULL
                       AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                       AND (operator_id IS NULL OR (operator_id NOT IN ('SYSTEM','system')
                            AND operator_id NOT LIKE 'auto%')))::bigint,
    (SELECT n_mttc FROM mttc_cte),
    now()
  FROM base;
$$ LANGUAGE sql STABLE;
