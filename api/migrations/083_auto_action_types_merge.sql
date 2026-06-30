-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 083 — extender el CHECK de incident_auto_actions.action_type.
--
-- Contexto (backlog GESTION-OPTIMIZACION-2026-06-07):
--  · P0 #3 auto-merge de duplicados (workflowEngine.autoMergeDuplicates) registra
--    AUTO_MERGE_DUPLICATE / AUTO_MERGE_CANONICAL en el audit trail.
--  · Bug latente: el intel-gate del auto-cierre (R1, workflowEngine:618) ya usaba
--    AUTO_INTEL_ESCALATE, NO incluido en el CHECK original (mig 008) → cada
--    recordAutoAction de ese tipo lanzaba y se tragaba con .catch(() => {}), por
--    lo que esas escaladas por intel NO dejaban rastro en incident_auto_actions
--    ni en case_timeline_events. Esta migración también lo corrige.
--
-- Idempotente: DROP CONSTRAINT IF EXISTS + ADD.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE incident_auto_actions
  DROP CONSTRAINT IF EXISTS incident_auto_actions_action_type_check;

ALTER TABLE incident_auto_actions
  ADD CONSTRAINT incident_auto_actions_action_type_check
  CHECK (action_type IN (
    'AUTO_CLOSE_LOW',
    'AUTO_CLOSE_NEGLIGIBLE',
    'AUTO_ASSIGN_TIMEOUT',
    'AUTO_ESCALATE_SCORE',
    'AUTO_ESCALATE_TACTIC',
    'SLA_BREACH_ALERT',
    'HANDOVER_CREATED',
    'AUTO_INTEL_ESCALATE',
    'AUTO_MERGE_DUPLICATE',
    'AUTO_MERGE_CANONICAL'
  ));
