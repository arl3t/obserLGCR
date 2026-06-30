-- 021_fix_v_soc_kpis.sql
-- Unifica 007_nist_kpis + 020_workflow_hardening en una sola vista.
-- La migracion 020 elimino 8 columnas que la API (/api/cases/kpis) espera.
-- Tambien corrige nombres (fp_rate vs fp_rate_7d) y calculos (MTTD, MTTC).

DROP VIEW IF EXISTS v_soc_kpis CASCADE;

CREATE VIEW v_soc_kpis AS
WITH
  w7 AS (
    SELECT * FROM incident_cases_pg
    WHERE created_at >= now() - INTERVAL '7 days'
  ),
  w30 AS (
    SELECT * FROM incident_cases_pg
    WHERE created_at >= now() - INTERVAL '30 days'
  ),
  w90 AS (
    SELECT * FROM incident_cases_pg
    WHERE created_at >= now() - INTERVAL '90 days'
  ),
  containment AS (
    SELECT DISTINCT ON (case_id) case_id, event_ts
    FROM case_timeline_events
    WHERE event_type = 'CONTAINMENT'
    ORDER BY case_id, event_ts ASC
  )
SELECT
  -- ── Contadores base (retrocompat) ───────────────────────────────────────
  (SELECT count(*) FROM w90
   WHERE status NOT IN ('CERRADO','FALSO_POSITIVO'))                        AS open_cases,

  -- closed_cases: total cerrados (manual + auto) en ventana 90d
  (SELECT count(*) FROM w90 WHERE status = 'CERRADO')                      AS closed_cases,

  -- resolved_today: solo cierres manuales por operador (excluye auto-close LOW sin operador)
  (SELECT count(*) FROM incident_cases_pg
   WHERE status = 'CERRADO'
     AND updated_at >= CURRENT_DATE
     AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL))    AS resolved_today,

  (SELECT count(*) FROM w90 WHERE status = 'MONITOREADO')                  AS monitoring,

  (SELECT count(*) FROM w7 WHERE status = 'FALSO_POSITIVO')                AS auto_fp,

  (SELECT count(*) FROM w7
   WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL)                 AS critical_sla_ok,

  (SELECT count(*) FROM w7 WHERE severity = 'CRITICAL')                    AS critical_sla_total,

  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at - created_at)) / 60))
   FROM w7 WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL)         AS critical_avg_ack_min,

  -- ── KPI 1: MTTD — Mean Time to Detect ──────────────────────────────────
  -- Tiempo desde el evento original (detected_at o anchor_dt) hasta la
  -- creacion del caso. Solo casos con detected_at real (no NULL).
  -- Si no hay detected_at, se usa anchor_dt como proxy (fecha del IOC).
  (SELECT ROUND(AVG(
    EXTRACT(EPOCH FROM (created_at - COALESCE(detected_at, anchor_dt::timestamp with time zone))) / 60
   ), 1)
   FROM w7
   WHERE COALESCE(detected_at, anchor_dt::timestamp with time zone) < created_at)
                                                                            AS mttd_min,

  -- ── KPI 2: MTTA — Mean Time to Acknowledge ─────────────────────────────
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at - created_at)) / 60), 1)
   FROM w7 WHERE adopted_at IS NOT NULL)                                    AS mtta_min,

  -- ── KPI 3: MTTR — Mean Time to Respond ─────────────────────────────────
  -- Solo casos realmente cerrados por operador (excluye auto-close LOW sin operador).
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (
     COALESCE(resolved_at, updated_at) - created_at
   )) / 60), 1)
   FROM w7
   WHERE status = 'CERRADO'
     AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL))    AS mttr_min,

  -- ── KPI 4: MTTC — Mean Time to Contain ─────────────────────────────────
  -- Primer evento CONTAINMENT del timeline. Si no hay eventos de ese tipo,
  -- devuelve NULL (no usar resolved_at como fallback — eso seria MTTR).
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (ct.event_ts - c.created_at)) / 60), 1)
   FROM w7 c
   JOIN containment ct ON ct.case_id = c.id::varchar)                      AS mttc_min,

  -- ── KPI 5: FPR — False Positive Rate (%) ───────────────────────────────
  (SELECT ROUND(
     count(*) FILTER (WHERE status = 'FALSO_POSITIVO') * 100.0
     / NULLIF(count(*) FILTER (WHERE status IN ('CERRADO','FALSO_POSITIVO')), 0),
   1) FROM w7)                                                              AS fp_rate,

  -- ── KPI 6: MITRE ATT&CK Coverage (%) ──────────────────────────────────
  (SELECT ROUND(count(DISTINCT mitre_tactic_id) * 100.0 / 14.0, 1)
   FROM w30 WHERE mitre_tactic_id IS NOT NULL)                              AS mitre_coverage_pct,

  -- ── KPI 7: Auto-Deduplication Rate (%) ──────────────────────────────────
  -- Proxy: (total - IOCs unicos) / total. Dato exacto requiere dedup_key.
  (SELECT ROUND(CASE WHEN count(*) = 0 THEN NULL
     ELSE (1.0 - count(DISTINCT COALESCE(ioc_value, id))::NUMERIC
                  / NULLIF(count(*), 0)) * 100
   END, 1) FROM w7)                                                         AS auto_dedup_pct,

  -- ── KPI 8: Escalation L1→L2 (minutos) ──────────────────────────────────
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (escalated_at - adopted_at)) / 60), 1)
   FROM w7
   WHERE escalated_at IS NOT NULL AND adopted_at IS NOT NULL
     AND severity IN ('CRITICAL','HIGH'))                                   AS l1_l2_esc_min,

  -- ── KPI 9: Wazuh Fallback Coverage (%) ──────────────────────────────────
  (SELECT ROUND(
     count(*) FILTER (WHERE mitre_tactic_id IS NULL) * 100.0
     / NULLIF(count(*), 0), 1)
   FROM w7)                                                                 AS wazuh_fallback_pct,

  -- ── KPI 10: Post-Mortem Rate (%) ────────────────────────────────────────
  (SELECT ROUND(
     count(*) FILTER (WHERE lessons_learned IS NOT NULL AND lessons_learned <> '') * 100.0
     / NULLIF(count(*) FILTER (WHERE status = 'CERRADO'), 0), 1)
   FROM w30)                                                                AS postmortem_rate,

  -- ── SLA: % criticos atendidos dentro de SLA (< 60 min ack) ─────────────
  (SELECT ROUND(
     count(*) FILTER (
       WHERE adopted_at IS NOT NULL
         AND EXTRACT(EPOCH FROM (adopted_at - created_at)) / 60 <= 60
     ) * 100.0 / NULLIF(count(*), 0), 1)
   FROM w7 WHERE severity = 'CRITICAL')                                    AS sla_critical_pct,

  -- ── Escalation Rate (%) ─────────────────────────────────────────────────
  (SELECT ROUND(
     count(*) FILTER (WHERE escalated_at IS NOT NULL) * 100.0
     / NULLIF(count(*), 0), 1)
   FROM w7)                                                                 AS escalation_rate,

  now() AS computed_at;
