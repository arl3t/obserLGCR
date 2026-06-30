-- =============================================================================
-- Migration 048 — MTTD: eliminar fallback anchor_dt
-- =============================================================================
-- Problema: soc_kpis_window(p_hours) calcula MTTD como:
--   AVG(created_at - COALESCE(detected_at, anchor_dt::timestamptz))
-- donde anchor_dt es la fecha de la partición Iceberg (granularidad día).
-- Cuando detected_at es NULL (el caso fue creado sin instrumentación de la
-- ingesta), anchor_dt actúa como proxy con resolución de un día → el MTTD
-- sale inflado a horas o se aplana a 0 según el caso. El backfill de
-- 020_workflow_hardening.sql:121-124 puso detected_at = created_at para casos
-- viejos, lo que reduce aún más la señal: en una mezcla de casos antiguos +
-- nuevos el promedio MTTD termina sesgado por la elección de fallback.
--
-- Solución: medir MTTD sólo sobre casos con detected_at REAL (sin fallback).
-- Si la cifra muestral es chica → mejor "N/D" honesto que un promedio falso.
-- El componente F1 también amplía MTTD via Trino multi-sensor (wazuh +
-- suricata + fortigate + filterlog + pmg) — eso cubre los casos donde
-- detected_at no fue instrumentado, sin depender de anchor_dt.
--
-- Contrato: misma firma. Sólo cambia el CTE de MTTD.
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
  computed_at          timestamptz
) AS $$
  WITH base90 AS (
    SELECT id, ioc_value, severity, status, operator_id,
           mitre_tactic_id, lessons_learned,
           created_at, updated_at, adopted_at, escalated_at,
           resolved_at, detected_at, anchor_dt, auto_closed_at
      FROM incident_cases_pg
     WHERE created_at >= now() - INTERVAL '90 days'
  ),
  base AS (
    SELECT *,
           created_at >= now() - make_interval(hours => p_hours) AS in_w,
           created_at >= now() - INTERVAL '30 days'              AS in_w30
      FROM base90
  ),
  mttc_cte AS (
    SELECT ROUND(AVG(EXTRACT(EPOCH FROM ct.event_ts - c.created_at) / 60.0)::numeric, 1) AS mttc_min
      FROM base c
      JOIN (
        SELECT DISTINCT ON (case_id) case_id, event_ts
          FROM case_timeline_events
         WHERE event_type = 'CONTAINMENT'
         ORDER BY case_id, event_ts
      ) ct ON ct.case_id::text = c.id::text
     WHERE c.in_w
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

    -- MTTD: sólo casos con detected_at REAL (no anchor_dt).
    -- El backfill de migración 020 puso detected_at=created_at para casos viejos,
    -- así que filtramos detected_at < created_at para asegurar señal real.
    -- Para los casos sin instrumentación de detected_at, el panel cae al MTTD
    -- multi-sensor de Trino (lh.incidents.mttd) que cruza wazuh/suricata/
    -- fortigate/filterlog/pmg por ioc_value.
    ROUND(AVG(EXTRACT(EPOCH FROM created_at - detected_at) / 60.0)
          FILTER (WHERE in_w
                    AND detected_at IS NOT NULL
                    AND detected_at < created_at), 1)                                    AS mttd_min,

    ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
          FILTER (WHERE in_w
                    AND adopted_at IS NOT NULL
                    AND auto_closed_at IS NULL
                    AND operator_id IS NOT NULL
                    AND operator_id NOT IN ('SYSTEM','system')
                    AND operator_id NOT LIKE 'auto%'), 1)                                AS mtta_min,

    ROUND(AVG(EXTRACT(EPOCH FROM COALESCE(resolved_at, updated_at) - created_at) / 60.0)
          FILTER (WHERE in_w AND status = 'CERRADO'
                    AND auto_closed_at IS NULL
                    AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                    AND (operator_id IS NULL
                         OR (operator_id NOT IN ('SYSTEM','system')
                             AND operator_id NOT LIKE 'auto%'))), 1)                     AS mttr_min,

    (SELECT mttc_min FROM mttc_cte)                                                      AS mttc_min,

    ROUND(
      COUNT(*) FILTER (WHERE in_w AND status = 'FALSO_POSITIVO')::numeric * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w AND status IN ('CERRADO','FALSO_POSITIVO')), 0)::numeric,
      1)                                                                                 AS fp_rate,

    ROUND(
      COUNT(DISTINCT mitre_tactic_id) FILTER (WHERE in_w30 AND mitre_tactic_id IS NOT NULL)::numeric
      * 100.0 / 14.0,
      1)                                                                                 AS mitre_coverage_pct,

    ROUND(
      CASE WHEN COUNT(*) FILTER (WHERE in_w) = 0 THEN NULL
      ELSE (1.0 - COUNT(DISTINCT COALESCE(ioc_value, id)) FILTER (WHERE in_w)::numeric
                 / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric) * 100.0
      END, 1)                                                                            AS auto_dedup_pct,

    ROUND(AVG(EXTRACT(EPOCH FROM escalated_at - adopted_at) / 60.0)
          FILTER (WHERE in_w AND escalated_at IS NOT NULL AND adopted_at IS NOT NULL
                    AND severity IN ('CRITICAL','HIGH')), 1)                             AS l1_l2_esc_min,

    ROUND(
      COUNT(*) FILTER (WHERE in_w AND mitre_tactic_id IS NULL)::numeric * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric,
      1)                                                                                 AS wazuh_fallback_pct,

    ROUND(
      COUNT(*) FILTER (WHERE in_w30 AND lessons_learned IS NOT NULL AND lessons_learned <> '')::numeric
      * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w30 AND status = 'CERRADO'), 0)::numeric,
      1)                                                                                 AS postmortem_rate,

    ROUND(
      COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL
                         AND EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0 <= 60)::numeric
      * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL'), 0)::numeric,
      1)                                                                                 AS sla_critical_pct,

    ROUND(
      COUNT(*) FILTER (WHERE in_w AND escalated_at IS NOT NULL)::numeric * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric,
      1)                                                                                 AS escalation_rate,

    now()                                                                                AS computed_at
  FROM base;
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION soc_kpis_window(int) IS
  'KPIs SOC con ventana operacional dinámica (p_hours). MTTD usa sólo '
  'detected_at REAL (no fallback a anchor_dt). MITRE coverage y postmortem '
  'rate fijos a 30d. El panel SOC complementa MTTD con la query Trino '
  'multi-sensor lh.incidents.mttd para cubrir casos sin instrumentación de '
  'detected_at en la ingesta.';
