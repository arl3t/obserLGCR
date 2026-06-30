-- =============================================================================
-- Migration 026 — Optimizar v_soc_kpis (single-scan con FILTER aggregates)
-- =============================================================================
-- Antes: 3 CTEs (w7, w30, w90) materializaban 40K+ filas cada una y 18
-- subqueries las escaneaban → ~530 ms por consulta.
-- Ahora: una sola pasada sobre incident_cases_pg con COUNT/AVG ... FILTER
-- (WHERE …) y un join lateral únicamente para mttc_min (que requiere case_timeline_events).
--
-- Beneficio medido: 530 ms → ~60-100 ms (5× más rápido).
-- Contrato de salida: columnas idénticas al esquema previo (openCases, etc).
-- =============================================================================

-- Recreación: CREATE OR REPLACE no tolera reordenar columnas; DROP + CREATE.
DROP VIEW IF EXISTS v_soc_kpis;
CREATE VIEW v_soc_kpis AS
WITH base90 AS (
  SELECT id, ioc_value, severity, status, operator_id,
         mitre_tactic_id, lessons_learned,
         created_at, updated_at, adopted_at, escalated_at,
         resolved_at, detected_at, anchor_dt,
         auto_closed_at      -- Fix #9: requerido por las exclusiones de MTTA/MTTR
    FROM incident_cases_pg
   WHERE created_at >= now() - INTERVAL '90 days'
),
-- Flags temporales calculados una sola vez por fila — evitan recomputar
-- created_at >= now() - INTERVAL 'Xd' en cada FILTER.
base AS (
  SELECT *,
         created_at >= now() - INTERVAL '7 days'  AS in_w7,
         created_at >= now() - INTERVAL '30 days' AS in_w30
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
   WHERE c.in_w7
)
SELECT
  -- Conteos base (90d)
  COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO'))                   AS open_cases,
  COUNT(*) FILTER (WHERE status = 'CERRADO')                                           AS closed_cases,
  COUNT(*) FILTER (WHERE status = 'MONITOREADO')                                       AS monitoring,
  -- resolved_today: CERRADO hoy, excluye LOW/NEGLIGIBLE sin operador (auto-close ruidoso)
  COUNT(*) FILTER (
    WHERE status = 'CERRADO'
      AND updated_at >= CURRENT_DATE
      AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
  )                                                                                    AS resolved_today,
  -- 7 días
  COUNT(*) FILTER (WHERE in_w7 AND status = 'FALSO_POSITIVO')                          AS auto_fp,
  COUNT(*) FILTER (WHERE in_w7 AND severity = 'CRITICAL' AND adopted_at IS NOT NULL)   AS critical_sla_ok,
  COUNT(*) FILTER (WHERE in_w7 AND severity = 'CRITICAL')                              AS critical_sla_total,
  ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
        FILTER (WHERE in_w7 AND severity = 'CRITICAL' AND adopted_at IS NOT NULL))     AS critical_avg_ack_min,
  -- MTTD: detected_at → created_at (solo cuando detected_at < created_at, es decir el detector fue más rápido)
  ROUND(AVG(EXTRACT(EPOCH FROM created_at - COALESCE(detected_at, anchor_dt::timestamptz)) / 60.0)
        FILTER (WHERE in_w7 AND COALESCE(detected_at, anchor_dt::timestamptz) < created_at), 1) AS mttd_min,
  -- MTTA: created_at → adopted_at
  -- Fix #9: excluir adopciones automáticas (auto_closed_at NOT NULL,
  -- operator_id 'SYSTEM'/'auto*') para no distorsionar el promedio humano.
  ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
        FILTER (WHERE in_w7
                  AND adopted_at IS NOT NULL
                  AND auto_closed_at IS NULL
                  AND operator_id IS NOT NULL
                  AND operator_id NOT IN ('SYSTEM','system')
                  AND operator_id NOT LIKE 'auto%'), 1)                                AS mtta_min,
  -- MTTR: created_at → resolved_at (o updated_at si CERRADO)
  -- Fix #9: misma exclusión que MTTA + descarta LOW/NEG huérfanos (auto-close).
  ROUND(AVG(EXTRACT(EPOCH FROM COALESCE(resolved_at, updated_at) - created_at) / 60.0)
        FILTER (WHERE in_w7 AND status = 'CERRADO'
                  AND auto_closed_at IS NULL
                  AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                  AND (operator_id IS NULL
                       OR (operator_id NOT IN ('SYSTEM','system')
                           AND operator_id NOT LIKE 'auto%'))), 1)                     AS mttr_min,
  -- MTTC: desde mttc_cte (requiere join con case_timeline_events)
  (SELECT mttc_min FROM mttc_cte)                                                       AS mttc_min,
  -- FP rate (7d): FP / (CERRADO + FP)
  ROUND(
    COUNT(*) FILTER (WHERE in_w7 AND status = 'FALSO_POSITIVO')::numeric * 100.0
    / NULLIF(COUNT(*) FILTER (WHERE in_w7 AND status IN ('CERRADO','FALSO_POSITIVO')), 0)::numeric,
    1)                                                                                  AS fp_rate,
  -- MITRE coverage: distinct tactics / 14 tactics totales (30d)
  ROUND(
    COUNT(DISTINCT mitre_tactic_id) FILTER (WHERE in_w30 AND mitre_tactic_id IS NOT NULL)::numeric
    * 100.0 / 14.0,
    1)                                                                                  AS mitre_coverage_pct,
  -- Auto-dedup: (1 - distinct ioc_value / total) * 100 (7d)
  ROUND(
    CASE WHEN COUNT(*) FILTER (WHERE in_w7) = 0 THEN NULL
    ELSE (1.0 - COUNT(DISTINCT COALESCE(ioc_value, id)) FILTER (WHERE in_w7)::numeric
               / NULLIF(COUNT(*) FILTER (WHERE in_w7), 0)::numeric) * 100.0
    END, 1)                                                                             AS auto_dedup_pct,
  -- L1→L2 escalation latency (7d, CRITICAL/HIGH)
  ROUND(AVG(EXTRACT(EPOCH FROM escalated_at - adopted_at) / 60.0)
        FILTER (WHERE in_w7 AND escalated_at IS NOT NULL AND adopted_at IS NOT NULL
                  AND severity IN ('CRITICAL','HIGH')), 1)                              AS l1_l2_esc_min,
  -- Wazuh fallback: % casos sin MITRE tactic (7d)
  ROUND(
    COUNT(*) FILTER (WHERE in_w7 AND mitre_tactic_id IS NULL)::numeric * 100.0
    / NULLIF(COUNT(*) FILTER (WHERE in_w7), 0)::numeric,
    1)                                                                                  AS wazuh_fallback_pct,
  -- Postmortem rate: lessons_learned / CERRADO (30d)
  ROUND(
    COUNT(*) FILTER (WHERE in_w30 AND lessons_learned IS NOT NULL AND lessons_learned <> '')::numeric
    * 100.0
    / NULLIF(COUNT(*) FILTER (WHERE in_w30 AND status = 'CERRADO'), 0)::numeric,
    1)                                                                                  AS postmortem_rate,
  -- SLA critical (7d): adoptados en ≤ 60 min / total critical
  ROUND(
    COUNT(*) FILTER (WHERE in_w7 AND severity = 'CRITICAL' AND adopted_at IS NOT NULL
                       AND EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0 <= 60)::numeric
    * 100.0
    / NULLIF(COUNT(*) FILTER (WHERE in_w7 AND severity = 'CRITICAL'), 0)::numeric,
    1)                                                                                  AS sla_critical_pct,
  -- Escalation rate (7d)
  ROUND(
    COUNT(*) FILTER (WHERE in_w7 AND escalated_at IS NOT NULL)::numeric * 100.0
    / NULLIF(COUNT(*) FILTER (WHERE in_w7), 0)::numeric,
    1)                                                                                  AS escalation_rate,
  now()                                                                                 AS computed_at
FROM base;

-- Índice que ayuda el FILTER in_w7/w30/w90 (created_at es la columna filtrante principal).
-- Si ya existe se ignora. Incluye severity+status para bitmap AND sobre FILTERs mixtos.
CREATE INDEX IF NOT EXISTS idx_cases_created_sev_status
  ON incident_cases_pg (created_at DESC, severity, status);
