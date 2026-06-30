-- =============================================================================
-- Migration 049 — F2+F3: MTTC multi-fuente + cobertura MITRE + n muestral
-- =============================================================================
-- Cambios:
--   1. MTTC: además de case_timeline_events.event_type='CONTAINMENT', acepta
--      auto_closed_at como contención IMPLÍCITA cuando el caso fue cerrado
--      por una acción de mitigación a nivel sensor (firewall_action en
--      BLOCK/DENY/DROP/RESET-DROP). Esos casos están "contenidos" en el
--      momento en que el sensor bloqueó el evento — el cierre automático
--      registra ese punto. No contamos auto-cierres con firewall_action
--      ACCEPT/PASS (no hubo contención, solo descarte por baja relevancia)
--      ni FP auto-cerrados.
--
--   2. coverage_by_source: nueva columna jsonb que devuelve, por cada
--      source_log presente en la ventana, total de casos y % con táctica
--      MITRE asignada. Reemplaza la métrica agregada wazuh_fallback_pct
--      (que mantenemos por back-compat) con una vista por fuente útil para
--      saber DÓNDE invertir trabajo de mapeo de reglas (Wazuh, Suricata,
--      FortiGate, OPNsense/filterlog, PMG…).
--
--   3. n_mttd/n_mtta/n_mttr/n_mttc: tamaño muestral de cada KPI de tiempo.
--      Necesario para que el panel marque "muestra baja" cuando N<30 — un
--      MTTR de 1h con n=2 es ruido, no señal.
--
-- Contrato: misma firma, columnas nuevas al final.
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
  -- MTTC primario: primer evento CONTAINMENT en la timeline.
  mttc_explicit AS (
    SELECT c.id AS case_id,
           c.created_at,
           ct.event_ts AS contained_at
      FROM base c
      JOIN (
        SELECT DISTINCT ON (case_id) case_id, event_ts
          FROM case_timeline_events
         WHERE event_type = 'CONTAINMENT'
         ORDER BY case_id, event_ts
      ) ct ON ct.case_id::text = c.id::text
     WHERE c.in_w
  ),
  -- MTTC fallback: auto-cierre con acción de bloqueo a nivel firewall
  -- (filterlog/fortigate). El evento ya quedó contenido en el sensor; el
  -- auto-close registra el momento operacional de la contención.
  -- Excluimos los casos que ya tienen un CONTAINMENT explícito.
  mttc_implicit AS (
    SELECT c.id AS case_id,
           c.created_at,
           c.auto_closed_at AS contained_at
      FROM base c
     WHERE c.in_w
       AND c.auto_closed_at IS NOT NULL
       AND c.status NOT IN ('FALSO_POSITIVO')
       AND UPPER(COALESCE(c.firewall_action, ''))
           IN ('BLOCK','DENY','DROP','RESET-DROP','RESET-CLIENT','RESET-SERVER','BLOCKED')
       AND c.id::text NOT IN (SELECT case_id FROM mttc_explicit)
  ),
  mttc_cte AS (
    SELECT
      ROUND(AVG(EXTRACT(EPOCH FROM contained_at - created_at) / 60.0)::numeric, 1) AS mttc_min,
      COUNT(*)::bigint                                                              AS n_mttc
      FROM (
        SELECT * FROM mttc_explicit
        UNION ALL
        SELECT * FROM mttc_implicit
      ) u
  ),
  -- Cobertura MITRE por fuente: para cada source_log en la ventana,
  -- conteo total y mapeado a táctica.
  coverage_cte AS (
    SELECT jsonb_agg(
             jsonb_build_object(
               'source_log', COALESCE(source_log, '(sin fuente)'),
               'total',      total,
               'mapped',     mapped,
               'pct',        pct
             )
             ORDER BY total DESC
           ) AS by_source
      FROM (
        SELECT
          source_log,
          COUNT(*)                                                                AS total,
          COUNT(*) FILTER (WHERE mitre_tactic_id IS NOT NULL)                     AS mapped,
          ROUND(
            COUNT(*) FILTER (WHERE mitre_tactic_id IS NOT NULL)::numeric * 100.0
            / NULLIF(COUNT(*), 0)::numeric,
            1
          )                                                                       AS pct
          FROM base
         WHERE in_w
         GROUP BY source_log
         HAVING COUNT(*) >= 1
      ) g
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

    -- Back-compat: mismo cálculo agregado. La UI nueva consume coverage_by_source.
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

    (SELECT by_source FROM coverage_cte)                                                 AS coverage_by_source,

    -- ── n muestral por KPI de tiempo (F3) ───────────────────────────────────
    COUNT(*) FILTER (WHERE in_w
                       AND detected_at IS NOT NULL
                       AND detected_at < created_at)::bigint                             AS n_mttd,
    COUNT(*) FILTER (WHERE in_w
                       AND adopted_at IS NOT NULL
                       AND auto_closed_at IS NULL
                       AND operator_id IS NOT NULL
                       AND operator_id NOT IN ('SYSTEM','system')
                       AND operator_id NOT LIKE 'auto%')::bigint                         AS n_mtta,
    COUNT(*) FILTER (WHERE in_w AND status = 'CERRADO'
                       AND auto_closed_at IS NULL
                       AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)
                       AND (operator_id IS NULL
                            OR (operator_id NOT IN ('SYSTEM','system')
                                AND operator_id NOT LIKE 'auto%')))::bigint              AS n_mttr,
    (SELECT n_mttc FROM mttc_cte)                                                        AS n_mttc,

    now()                                                                                AS computed_at
  FROM base;
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION soc_kpis_window(int) IS
  'KPIs SOC con ventana operacional dinámica (p_hours). MTTD usa sólo '
  'detected_at REAL. MTTC unifica CONTAINMENT explícito + auto-cierres por '
  'bloqueo de firewall. coverage_by_source devuelve cobertura MITRE por '
  'source_log para diagnóstico de gaps de mapeo. MITRE coverage y postmortem '
  'rate fijos a 30d.';
