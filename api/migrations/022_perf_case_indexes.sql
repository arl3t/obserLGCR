-- 022_perf_case_indexes.sql
-- Indices compuestos para acelerar el flujo de gestion de casos SOC.
-- Diagnostico: subqueries de v_soc_kpis, listado /api/incidents/open y
-- batch lookup de case_iocs operaban con seq scans o merge de indices
-- separados. Estos indices cubren las combinaciones reales del WHERE/JOIN.
--
-- NOTA: Postgres no permite predicados no-inmutables (now(), CURRENT_DATE)
-- en CREATE INDEX, por lo que se usan indices completos sobre created_at
-- en orden DESC (eficaz para ventanas recientes).

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. KPI v_soc_kpis: subqueries por ventana (7d/30d/90d) + status + severity
--    Cubre w7/w30/w90 cuando se cruza con filtros de status o severity.
--    El indice (status, created_at) ya existente sirve para 'WHERE status=X'
--    pero no para 'WHERE created_at >= X AND severity=Y'.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_created_status_severity
  ON incident_cases_pg(created_at DESC, status, severity);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. KPI MTTC (containment CTE): DISTINCT ON (case_id) WHERE event_type=X
--    ORDER BY case_id, event_ts ASC.
--    El indice existente (event_type, event_ts DESC) no satisface el ORDER BY
--    por case_id. Este compuesto permite resolver el CTE como index-only scan.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_timeline_event_type_case_ts
  ON case_timeline_events(event_type, case_id, event_ts ASC);

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. pgBatchLookup (incidents.mjs:322): case_iocs WHERE case_id = ANY($1)
--    AND is_primary = true. El indice (case_id) actual hace scan extra del
--    flag. Indice parcial sobre is_primary=true es ~10x mas pequeño y
--    cubre el filtro completo.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_case_iocs_primary
  ON case_iocs(case_id)
  WHERE is_primary = true;

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Listado /api/incidents/open: filtros combinados status + severity +
--    adopted_at (orden por adopcion). Predicado parcial inmutable que
--    descarta casos cerrados (~70% del volumen historico).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_status_severity_adopted
  ON incident_cases_pg(status, severity, adopted_at DESC NULLS FIRST)
  WHERE status NOT IN ('CERRADO','FALSO_POSITIVO');

-- ─────────────────────────────────────────────────────────────────────────────
-- Refrescar estadisticas para que el planner use los nuevos indices.
-- ─────────────────────────────────────────────────────────────────────────────
ANALYZE incident_cases_pg;
ANALYZE case_timeline_events;
ANALYZE case_iocs;
