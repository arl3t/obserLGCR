-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 087 — campos de auditoría/medición de casos (backlog 2026-06-07).
--
-- P2 #18: resolution_action + root_cause_category (enums "blandos" VARCHAR) →
--          permite reportar "% por causa" y validar que un cierre fue remediación
--          real, no provisional.
-- P2 #19: reopened_count, sla_breach_at, escalation_path (jsonb) → detecta casos
--          "pingpong", cierres prematuros y da histórico SLA por caso.
-- P2 #20: stage_entered_at + stage_durations (jsonb) → tiempo por fase NIST
--          (time-in-stage) para SLA por fase y alertas "atascado en análisis".
--
-- Todas las columnas son nullable / con default no disruptivo. Idempotente
-- (ADD COLUMN IF NOT EXISTS). El wiring (poblar estos campos) vive en
-- workflowEngine.transitionCase, schedulerService.checkSlaBreaches y routes.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS resolution_action    VARCHAR(32),    -- patched|reconfigured|isolated|blocked|monitored|whitelisted|dismissed
  ADD COLUMN IF NOT EXISTS root_cause_category  VARCHAR(40),    -- missing_patch|weak_auth|misconfig|malware|insider|phishing|scanner|unknown
  ADD COLUMN IF NOT EXISTS reopened_count       INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS sla_breach_at        TIMESTAMPTZ,    -- primer instante de breach (lo sella el scheduler)
  ADD COLUMN IF NOT EXISTS escalation_path      JSONB DEFAULT '[]'::jsonb,  -- [{at, level, to, reason}]
  ADD COLUMN IF NOT EXISTS stage_entered_at     TIMESTAMPTZ,    -- entrada a la fase actual
  ADD COLUMN IF NOT EXISTS stage_durations      JSONB DEFAULT '{}'::jsonb;  -- {stage: segundos acumulados}

-- Índice parcial para reporting de reaperturas (casos pingpong).
CREATE INDEX IF NOT EXISTS idx_cases_reopened
  ON incident_cases_pg (reopened_count)
  WHERE reopened_count > 0;
