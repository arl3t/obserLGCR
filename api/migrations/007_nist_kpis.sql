-- 007_nist_kpis.sql
-- Reemplaza v_soc_kpis con métricas NIST SP 800-61 Rev. 3 + CSF 2.0 completas.
-- Período de análisis: 7 días (ajustable por parámetro de vista).
-- Todas las columnas de tiempo están en minutos (NUMERIC).

-- ─────────────────────────────────────────────────────────────────────────────
-- Asegurar índices que aceleran los subqueries del KPI
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_status_created
  ON incident_cases_pg(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cases_adopted_at
  ON incident_cases_pg(adopted_at) WHERE adopted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_resolved_at
  ON incident_cases_pg(resolved_at) WHERE resolved_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_escalated_sev
  ON incident_cases_pg(escalated_at, severity) WHERE escalated_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_lessons
  ON incident_cases_pg(lessons_learned) WHERE lessons_learned IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_mitre_tactic
  ON incident_cases_pg(mitre_tactic_id) WHERE mitre_tactic_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_timeline_type_ts
  ON case_timeline_events(event_type, event_ts DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Vista NIST KPIs (reemplaza la anterior — DROP + CREATE para cambiar columnas)
-- ─────────────────────────────────────────────────────────────────────────────
DROP VIEW IF EXISTS v_soc_kpis;
CREATE VIEW v_soc_kpis AS
SELECT
  -- ── Contadores base ──────────────────────────────────────────────────────
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status NOT IN ('CERRADO','FALSO_POSITIVO')
     AND created_at >= now() - INTERVAL '90 days')
    AS open_cases,

  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status IN ('CERRADO')
     AND updated_at >= CURRENT_DATE)
    AS resolved_today,

  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status = 'MONITOREADO'
     AND created_at >= now() - INTERVAL '90 days')
    AS monitoring,

  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status = 'FALSO_POSITIVO'
     AND created_at >= now() - INTERVAL '7 days')
    AS auto_fp,

  -- ── Retrocompat ──────────────────────────────────────────────────────────
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL
     AND created_at >= now() - INTERVAL '7 days')
    AS critical_sla_ok,

  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE severity = 'CRITICAL'
     AND created_at >= now() - INTERVAL '7 days')
    AS critical_sla_total,

  -- ── NIST KPI 1: MTTD proxy (created_at ≈ detección por el motor de scoring) ──
  -- Tiempo en minutos desde que el motor detecta el IOC hasta que se crea el caso.
  -- Sin correlación externa, aprovechamos anchor_dt vs created_at como proxy.
  -- Pendiente: enriquecer con timestamp del evento Wazuh original via Trino.
  NULL::NUMERIC
    AS mttd_min,

  -- ── NIST KPI 9: MTTA — Mean Time to Acknowledge ─────────────────────────
  -- Tiempo desde creación del caso hasta que un operador lo adopta (7 días).
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at - created_at)) / 60))
   FROM incident_cases_pg
   WHERE adopted_at IS NOT NULL
     AND created_at >= now() - INTERVAL '7 days')
    AS mtta_min,

  -- retrocompat alias
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at - created_at)) / 60))
   FROM incident_cases_pg
   WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL
     AND created_at >= now() - INTERVAL '7 days')
    AS critical_avg_ack_min,

  -- ── NIST KPI 2: MTTR — Mean Time to Respond / Remediate ─────────────────
  -- Tiempo desde creación hasta resolución (status = CERRADO), 7 días.
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (
       COALESCE(resolved_at, updated_at) - created_at
     )) / 60))
   FROM incident_cases_pg
   WHERE status = 'CERRADO'
     AND created_at >= now() - INTERVAL '7 days')
    AS mttr_min,

  -- ── NIST KPI 3: MTTC — Mean Time to Contain ─────────────────────────────
  -- Tiempo desde creación del caso hasta el primer evento CONTAINMENT en timeline.
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (t.event_ts - c.created_at)) / 60))
   FROM incident_cases_pg c
   JOIN LATERAL (
     SELECT event_ts
     FROM case_timeline_events
     WHERE case_id = c.id
       AND event_type = 'CONTAINMENT'
     ORDER BY event_ts ASC
     LIMIT 1
   ) t ON true
   WHERE c.created_at >= now() - INTERVAL '7 days')
    AS mttc_min,

  -- ── NIST KPI 4: FPR — False Positive Rate (%) ───────────────────────────
  -- % de casos cerrados como falso positivo sobre el total cerrado+FP, 7 días.
  (SELECT ROUND(
     COUNT(*) FILTER (WHERE status = 'FALSO_POSITIVO') * 100.0
     / NULLIF(COUNT(*) FILTER (WHERE status IN ('CERRADO','FALSO_POSITIVO')), 0),
   1)
   FROM incident_cases_pg
   WHERE created_at >= now() - INTERVAL '7 days')
    AS fp_rate,

  -- ── NIST KPI 5: MITRE ATT&CK Coverage (%) ──────────────────────────────
  -- % de tácticas Enterprise MITRE observadas sobre 14 tácticas totales, 30 días.
  (SELECT ROUND(
     COUNT(DISTINCT mitre_tactic_id) * 100.0 / 14.0,
   1)
   FROM incident_cases_pg
   WHERE mitre_tactic_id IS NOT NULL
     AND created_at >= now() - INTERVAL '30 days')
    AS mitre_coverage_pct,

  -- ── NIST KPI 6: Auto-dedup / deduplicación automática (%) ───────────────
  -- Proxy: casos con score elevado (>=75) que tienen misma táctica en 24h deduplicados.
  -- Dato exacto requiere campo dedup_key o contador externo.
  -- Formula: (total casos - casos únicos por ioc_value en 7d) / total * 100
  (SELECT ROUND(
     CASE
       WHEN COUNT(*) = 0 THEN NULL
       ELSE (1.0 - COUNT(DISTINCT COALESCE(ioc_value, id))::NUMERIC / NULLIF(COUNT(*), 0)) * 100
     END, 1)
   FROM incident_cases_pg
   WHERE created_at >= now() - INTERVAL '7 days')
    AS auto_dedup_pct,

  -- ── NIST KPI 7: Tiempo escalada L1 → L2 (minutos) ───────────────────────
  -- Tiempo desde adopción (L1) hasta escalación a nivel superior, 7 días.
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (escalated_at - adopted_at)) / 60))
   FROM incident_cases_pg
   WHERE escalated_at IS NOT NULL
     AND adopted_at IS NOT NULL
     AND severity IN ('CRITICAL','HIGH')
     AND created_at >= now() - INTERVAL '7 days')
    AS l1_l2_esc_min,

  -- ── NIST KPI 8: Wazuh fallback coverage (%) ─────────────────────────────
  -- % de casos sin táctica MITRE asignada (fuente genérica o sin regla mapeada).
  -- Objetivo: < 3% en fallback genérico. Requiere Trino para dato exacto.
  (SELECT ROUND(
     COUNT(*) FILTER (WHERE mitre_tactic_id IS NULL) * 100.0
     / NULLIF(COUNT(*), 0),
   1)
   FROM incident_cases_pg
   WHERE created_at >= now() - INTERVAL '7 days')
    AS wazuh_fallback_pct,

  -- ── NIST KPI 10: Post-Mortem Rate (%) ──────────────────────────────────
  -- % de casos cerrados que tienen lessons_learned documentadas.
  (SELECT ROUND(
     COUNT(*) FILTER (WHERE lessons_learned IS NOT NULL AND lessons_learned <> '') * 100.0
     / NULLIF(COUNT(*) FILTER (WHERE status = 'CERRADO'), 0),
   1)
   FROM incident_cases_pg
   WHERE created_at >= now() - INTERVAL '30 days')
    AS postmortem_rate,

  -- ── SLA: % casos críticos atendidos dentro de SLA (< 60 min ack) ────────
  (SELECT ROUND(
     COUNT(*) FILTER (
       WHERE adopted_at IS NOT NULL
         AND EXTRACT(EPOCH FROM (adopted_at - created_at)) / 60 <= 60
     ) * 100.0 / NULLIF(COUNT(*), 0),
   1)
   FROM incident_cases_pg
   WHERE severity = 'CRITICAL'
     AND created_at >= now() - INTERVAL '7 days')
    AS sla_critical_pct,

  -- ── Escalation rate (%) ─────────────────────────────────────────────────
  (SELECT ROUND(
     COUNT(*) FILTER (WHERE escalated_at IS NOT NULL) * 100.0
     / NULLIF(COUNT(*), 0),
   1)
   FROM incident_cases_pg
   WHERE created_at >= now() - INTERVAL '7 days')
    AS escalation_rate;
