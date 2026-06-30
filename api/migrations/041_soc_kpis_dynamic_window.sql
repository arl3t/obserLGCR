-- =============================================================================
-- Migration 041 — Ventana dinámica para KPIs SOC
-- =============================================================================
-- Problema: v_soc_kpis usa ventanas fijas (in_w7=7d, in_w30=30d). El panel
-- "Centro de mando" tiene un selector de tiempo (24h / 7d / 30d / 365d) pero
-- los KPIs PG ignoran el filtro, así que con el selector en 24h aparecen
-- valores promedio del rango de 7 días (p. ej. MTTR=59.8h).
--
-- Solución: función parametrizada soc_kpis_window(p_hours int) que aplica la
-- ventana del usuario a las métricas operacionales (MTTD, MTTR, MTTC, MTTA,
-- FPR, SLA, Escalation, AutoDedup, L1→L2, Wazuh Fallback).
--
-- Las dos métricas de cobertura (MITRE coverage, Postmortem rate) mantienen
-- 30 días por significancia estadística — necesitan volumen para no oscilar
-- ruidosamente. En el panel se etiqueta explícitamente "30d fijo" en esas
-- tarjetas cuando la ventana global es distinta.
--
-- Contrato: mismas columnas que v_soc_kpis (drop-in).
-- =============================================================================

DROP FUNCTION IF EXISTS soc_kpis_window(int);

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
    -- Contadores base (universo 90d, no depende de ventana — son agregados de estado)
    COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO'))                   AS open_cases,
    COUNT(*) FILTER (WHERE status = 'CERRADO')                                           AS closed_cases,
    COUNT(*) FILTER (WHERE status = 'MONITOREADO')                                       AS monitoring,
    COUNT(*) FILTER (
      WHERE status = 'CERRADO'
        AND updated_at >= CURRENT_DATE
        AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
    )                                                                                    AS resolved_today,

    -- Operacional dentro de la ventana del usuario
    COUNT(*) FILTER (WHERE in_w AND status = 'FALSO_POSITIVO')                           AS auto_fp,
    COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL)    AS critical_sla_ok,
    COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL')                               AS critical_sla_total,
    ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
          FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL))      AS critical_avg_ack_min,

    -- MTTD: detected_at → created_at (proxy)
    ROUND(AVG(EXTRACT(EPOCH FROM created_at - COALESCE(detected_at, anchor_dt::timestamptz)) / 60.0)
          FILTER (WHERE in_w AND COALESCE(detected_at, anchor_dt::timestamptz) < created_at), 1) AS mttd_min,

    -- MTTA: excluye adopciones automáticas
    ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
          FILTER (WHERE in_w
                    AND adopted_at IS NOT NULL
                    AND auto_closed_at IS NULL
                    AND operator_id IS NOT NULL
                    AND operator_id NOT IN ('SYSTEM','system')
                    AND operator_id NOT LIKE 'auto%'), 1)                                AS mtta_min,

    -- MTTR: cierres reales
    ROUND(AVG(EXTRACT(EPOCH FROM COALESCE(resolved_at, updated_at) - created_at) / 60.0)
          FILTER (WHERE in_w AND status = 'CERRADO'
                    AND auto_closed_at IS NULL
                    AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                    AND (operator_id IS NULL
                         OR (operator_id NOT IN ('SYSTEM','system')
                             AND operator_id NOT LIKE 'auto%'))), 1)                     AS mttr_min,

    (SELECT mttc_min FROM mttc_cte)                                                      AS mttc_min,

    -- FP rate
    ROUND(
      COUNT(*) FILTER (WHERE in_w AND status = 'FALSO_POSITIVO')::numeric * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w AND status IN ('CERRADO','FALSO_POSITIVO')), 0)::numeric,
      1)                                                                                 AS fp_rate,

    -- MITRE coverage: SIEMPRE 30d (necesita volumen para que distinct tactics sea estable)
    ROUND(
      COUNT(DISTINCT mitre_tactic_id) FILTER (WHERE in_w30 AND mitre_tactic_id IS NOT NULL)::numeric
      * 100.0 / 14.0,
      1)                                                                                 AS mitre_coverage_pct,

    -- Auto-dedup (proxy: 1 - distinct/total)
    ROUND(
      CASE WHEN COUNT(*) FILTER (WHERE in_w) = 0 THEN NULL
      ELSE (1.0 - COUNT(DISTINCT COALESCE(ioc_value, id)) FILTER (WHERE in_w)::numeric
                 / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric) * 100.0
      END, 1)                                                                            AS auto_dedup_pct,

    -- L1→L2 escalation latency (CRITICAL/HIGH)
    ROUND(AVG(EXTRACT(EPOCH FROM escalated_at - adopted_at) / 60.0)
          FILTER (WHERE in_w AND escalated_at IS NOT NULL AND adopted_at IS NOT NULL
                    AND severity IN ('CRITICAL','HIGH')), 1)                             AS l1_l2_esc_min,

    -- Wazuh fallback
    ROUND(
      COUNT(*) FILTER (WHERE in_w AND mitre_tactic_id IS NULL)::numeric * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric,
      1)                                                                                 AS wazuh_fallback_pct,

    -- Postmortem: SIEMPRE 30d (necesita N cerrados para tasa estable)
    ROUND(
      COUNT(*) FILTER (WHERE in_w30 AND lessons_learned IS NOT NULL AND lessons_learned <> '')::numeric
      * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w30 AND status = 'CERRADO'), 0)::numeric,
      1)                                                                                 AS postmortem_rate,

    -- SLA critical: adoptados ≤ 60 min / total critical (en la ventana)
    ROUND(
      COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL' AND adopted_at IS NOT NULL
                         AND EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0 <= 60)::numeric
      * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w AND severity = 'CRITICAL'), 0)::numeric,
      1)                                                                                 AS sla_critical_pct,

    -- Escalation rate
    ROUND(
      COUNT(*) FILTER (WHERE in_w AND escalated_at IS NOT NULL)::numeric * 100.0
      / NULLIF(COUNT(*) FILTER (WHERE in_w), 0)::numeric,
      1)                                                                                 AS escalation_rate,

    now()                                                                                AS computed_at
  FROM base;
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION soc_kpis_window(int) IS
  'KPIs SOC con ventana operacional dinámica (p_hours). MITRE coverage y '
  'postmortem rate quedan fijos a 30d por significancia estadística. '
  'Reemplaza/complementa la vista v_soc_kpis (que sigue disponible para '
  'consumidores legacy con ventana 7d).';
