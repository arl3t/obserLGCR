-- =============================================================================
-- Migration 069 — MTTR: excluir cierres legacy / sin resolución real
-- =============================================================================
-- Audit 2026-05-27: post-mig 068 el MTTR reportaba 913.8h sobre n=71 cierres.
-- Análisis:
--   - 68 de los 71 cerraron en el mismo timestamp (2026-05-27 07:56:13.579662)
--     por 3 operadores distintos — patrón de cleanup masivo de backlog.
--   - Todos esos 68 con resolved_at NULL + classification='LEGACY_UNCLASSIFIED'
--     (sentinel del backfill 061) + sin STATUS_CHANGE timeline event → fueron
--     cerrados vía UPDATE directo a la DB, no por workflowEngine.transitionCase.
--   - Si filtramos a "cierres con resolución real", n=0: en los últimos 7 días
--     NO hubo cierre legítimo con clasificación, sólo cleanup retroactivo.
--
-- Decisión: el KPI MTTR debe medir tiempo real de resolución, no cleanup.
-- Filtros nuevos:
--   - resolved_at IS NOT NULL (excluye cierres sin populación del flag)
--   - classification NOT IN ('LEGACY_UNCLASSIFIED','AUTO_NO_ACTIONABLE','AUTO_FP')
--     (sentinels de backfill/automatización — no son resoluciones SOC reales)
--
-- Trade-off: hoy MTTR=N/A, lo cual es honesto. Cuando empiecen los cierres
-- manuales con classification real, el número será operacionalmente útil.
--
-- Bug arquitectural pendiente (no resuelto aquí): hay un code path no auditado
-- que setea status='CERRADO' sin pasar por workflowEngine. 308 casos manuales
-- con resolved_at NULL — toda investigación a futuro.
--
-- Contrato: misma firma. Cambia sólo fórmula de mttr_min + n_mttr.
-- =============================================================================

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
           mitre_tactic_id, lessons_learned, classification,
           created_at, updated_at, adopted_at, escalated_at,
           resolved_at, detected_at, anchor_dt, auto_closed_at,
           source_log, firewall_action
      FROM incident_cases_pg
     WHERE created_at >= now() - INTERVAL '90 days'
        OR updated_at >= now() - INTERVAL '90 days'
  ),
  base AS (
    SELECT *,
           created_at >= now() - make_interval(hours => p_hours)            AS in_w,
           created_at >= now() - INTERVAL '30 days'                         AS in_w30,
           COALESCE(resolved_at, updated_at) >= now() - make_interval(hours => p_hours)
                                                                            AS closed_in_w
      FROM base90
  ),
  mttc_explicit AS (
    SELECT c.id AS case_id, c.created_at, ct.event_ts AS contained_at
      FROM base c
      JOIN (SELECT DISTINCT ON (case_id) case_id, event_ts FROM case_timeline_events
             WHERE event_type = 'CONTAINMENT' ORDER BY case_id, event_ts) ct
        ON ct.case_id::text = c.id::text
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
    COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO'))                   AS open_cases,
    COUNT(*) FILTER (WHERE status = 'CERRADO')                                           AS closed_cases,
    COUNT(*) FILTER (WHERE status = 'MONITOREADO')                                       AS monitoring,
    COUNT(*) FILTER (
      WHERE status = 'CERRADO'
        AND updated_at >= CURRENT_DATE
        AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
    )                                                                                    AS resolved_today,
    COUNT(*) FILTER (WHERE in_w AND status = 'FALSO_POSITIVO')                           AS auto_fp,
    COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL)    AS critical_sla_ok,
    COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL')                               AS critical_sla_total,
    ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
          FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL))      AS critical_avg_ack_min,

    ROUND(AVG(EXTRACT(EPOCH FROM created_at - detected_at) / 60.0)
          FILTER (WHERE in_w AND detected_at IS NOT NULL AND detected_at < created_at
                    AND EXTRACT(EPOCH FROM created_at - detected_at) <= 86400), 1)       AS mttd_min,

    ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
          FILTER (WHERE in_w AND adopted_at IS NOT NULL AND auto_closed_at IS NULL
                    AND operator_id IS NOT NULL AND operator_id NOT IN ('SYSTEM','system')
                    AND operator_id NOT LIKE 'auto%'), 1)                                AS mtta_min,

    -- MTTR (mig 069): closed_in_w + sólo cierres con resolved_at populado +
    -- classification real (excluye sentinels de backfill/automatización).
    ROUND(AVG(EXTRACT(EPOCH FROM resolved_at - created_at) / 60.0)
          FILTER (WHERE closed_in_w AND status = 'CERRADO' AND auto_closed_at IS NULL
                    AND resolved_at IS NOT NULL
                    AND (classification IS NULL OR classification NOT IN
                         ('LEGACY_UNCLASSIFIED','AUTO_NO_ACTIONABLE','AUTO_FP'))
                    AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                    AND (operator_id IS NULL OR (operator_id NOT IN ('SYSTEM','system')
                         AND operator_id NOT LIKE 'auto%'))), 1)                         AS mttr_min,

    (SELECT mttc_min FROM mttc_cte)                                                      AS mttc_min,

    ROUND(COUNT(*) FILTER (WHERE in_w AND status = 'FALSO_POSITIVO')::numeric * 100.0
          / NULLIF(COUNT(*) FILTER (WHERE in_w AND status IN ('CERRADO','FALSO_POSITIVO')), 0)::numeric, 1) AS fp_rate,

    ROUND(COUNT(DISTINCT mitre_tactic_id) FILTER (WHERE in_w30 AND mitre_tactic_id IS NOT NULL)::numeric
          * 100.0 / 14.0, 1)                                                             AS mitre_coverage_pct,

    ROUND(CASE WHEN COUNT(*) FILTER (WHERE in_w) = 0 THEN NULL
          ELSE (1.0 - COUNT(DISTINCT COALESCE(ioc_value, id)) FILTER (WHERE in_w)::numeric
                     / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric) * 100.0 END, 1) AS auto_dedup_pct,

    ROUND(AVG(EXTRACT(EPOCH FROM escalated_at - adopted_at) / 60.0)
          FILTER (WHERE in_w AND escalated_at IS NOT NULL AND adopted_at IS NOT NULL
                    AND severity IN ('CRITICAL','HIGH')), 1)                             AS l1_l2_esc_min,

    ROUND(COUNT(*) FILTER (WHERE in_w AND mitre_tactic_id IS NULL)::numeric * 100.0
          / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric, 1)                         AS wazuh_fallback_pct,

    ROUND(
      COUNT(*) FILTER (WHERE in_w30 AND status='CERRADO'
                         AND severity IN ('CRITICAL','HIGH','MEDIUM')
                         AND auto_closed_at IS NULL
                         AND lessons_learned IS NOT NULL AND lessons_learned <> '')::numeric * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w30 AND status='CERRADO'
                                  AND severity IN ('CRITICAL','HIGH','MEDIUM')
                                  AND auto_closed_at IS NULL), 0)::numeric, 1)           AS postmortem_rate,

    ROUND(COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL
                            AND EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0 <= 60)::numeric
          * 100.0 / NULLIF(COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL'), 0)::numeric, 1) AS sla_critical_pct,

    ROUND(COUNT(*) FILTER (WHERE in_w AND escalated_at IS NOT NULL)::numeric * 100.0
          / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric, 1)                         AS escalation_rate,

    (SELECT by_source FROM coverage_cte)                                                 AS coverage_by_source,

    COUNT(*) FILTER (WHERE in_w AND detected_at IS NOT NULL AND detected_at < created_at
                       AND EXTRACT(EPOCH FROM created_at - detected_at) <= 86400)::bigint AS n_mttd,
    COUNT(*) FILTER (WHERE in_w AND adopted_at IS NOT NULL AND auto_closed_at IS NULL
                       AND operator_id IS NOT NULL AND operator_id NOT IN ('SYSTEM','system')
                       AND operator_id NOT LIKE 'auto%')::bigint                         AS n_mtta,
    -- n_mttr con los mismos filtros que mttr_min
    COUNT(*) FILTER (WHERE closed_in_w AND status = 'CERRADO' AND auto_closed_at IS NULL
                       AND resolved_at IS NOT NULL
                       AND (classification IS NULL OR classification NOT IN
                            ('LEGACY_UNCLASSIFIED','AUTO_NO_ACTIONABLE','AUTO_FP'))
                       AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                       AND (operator_id IS NULL OR (operator_id NOT IN ('SYSTEM','system')
                            AND operator_id NOT LIKE 'auto%')))::bigint                  AS n_mttr,
    (SELECT n_mttc FROM mttc_cte)                                                        AS n_mttc,

    now()                                                                                AS computed_at
  FROM base;
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION soc_kpis_window(int) IS
  'KPIs SOC. MTTD clamp 24h (063). POST-M denominador filtrado (065). '
  'MTTR usa closed_in_w + filtra cierres legacy/sin resolved_at (069) — '
  'mide resoluciones SOC reales, no cleanup retroactivo de backlog.';
