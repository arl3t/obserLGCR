-- =============================================================================
-- Migration 028 — Plantillas DFIR con trigger por MITRE tactic
-- =============================================================================
-- Fix #12 del backlog SOC: suggestTemplate() decide qué playbook ofrecer al
-- operador basándose en severity + category, ignorando la táctica MITRE.
-- Una "Credential Access" (TA0006) merece una playbook distinta a "Execution"
-- (TA0002) aunque la severidad sea la misma.
--
-- Cambio: nuevo array `trigger_mitre_tactics` en case_templates. Cuando está
-- vacío la plantilla se considera de aplicación general (compatibilidad con
-- las built-in actuales). Cuando trae IDs (TA000x) sólo aplica a casos cuyo
-- mitre_tactic_id figura en el array.
-- =============================================================================

ALTER TABLE case_templates
  ADD COLUMN IF NOT EXISTS trigger_mitre_tactics TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN case_templates.trigger_mitre_tactics IS
  'Tácticas MITRE (TA000x) que disparan esta plantilla en suggestTemplate(). '
  'Vacío = aplica a todos los casos que cumplan severity+category.';

-- Índice GIN para acelerar el filtro `$3 = ANY(trigger_mitre_tactics)`
CREATE INDEX IF NOT EXISTS idx_case_templates_trigger_mitre
  ON case_templates USING GIN (trigger_mitre_tactics);
