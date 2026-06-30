-- =============================================================================
-- Migration 027 — Vista v_active_suppressions + audit trail
-- =============================================================================
-- Fix #7 del backlog SOC: las supresiones por dedup_key son invisibles al
-- operador. El panel "Supresiones" lee directamente la tabla, sin filtro de
-- vigencia ni audit trail (quién y cuándo silenció qué IOC).
--
-- Cambios:
--  1. v_active_suppressions: SOLO supresiones vigentes (suppressed_until > NOW),
--     enriquecidas con minutos restantes y join al caso original (ioc_value real
--     resuelto desde incident_cases_pg cuando original_ioc viene NULL).
--  2. Reutiliza el endpoint existente /api/incidents/suppressions para listado;
--     el endpoint nuevo /export.csv se sirve desde routes/incidents.mjs.
-- =============================================================================

DROP VIEW IF EXISTS legacyhunt_soc.v_active_suppressions;

CREATE VIEW legacyhunt_soc.v_active_suppressions AS
SELECT
  s.dedup_key,
  s.reason,
  s.severity,
  s.suppressed_until,
  s.suppressed_by,
  s.original_case_id,
  COALESCE(s.original_ioc, c.ioc_value)            AS ioc_value,
  c.ioc_type,
  c.mitre_tactic_id,
  c.mitre_tactic_name,
  s.created_at,
  s.updated_at,
  ROUND(EXTRACT(EPOCH FROM (s.suppressed_until - now())) / 60.0)::int AS minutes_remaining,
  ROUND(EXTRACT(EPOCH FROM (s.suppressed_until - s.created_at)) / 86400.0, 1)::numeric AS window_days
FROM legacyhunt_soc.case_suppressions s
LEFT JOIN incident_cases_pg c
  ON c.id::text = s.original_case_id::text
WHERE s.suppressed_until > now()
ORDER BY s.suppressed_until ASC;

COMMENT ON VIEW legacyhunt_soc.v_active_suppressions IS
  'Supresiones vigentes (suppressed_until > NOW) con IOC resuelto y minutos restantes. '
  'Origen del panel "Supresiones" del dashboard y del export CSV operativo.';
