-- 105_ticket_automation.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F6 del Sistema de Tickets Público — Automatización (recordatorios, auto-cierre)
-- + CSAT (satisfacción del cliente). docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#11-#13).
--
-- - Recordatorios: si la pelota está en el cliente (waiting_on='CLIENT') y pasa
--   un umbral sin respuesta, se le re-envía un aviso por email (sin spamear:
--   last_reminder_at).
-- - Auto-cierre: tickets RESUELTO sin actividad N días → CERRADO.
-- - CSAT: al resolver/cerrar, el cliente puede puntuar 1-5 desde el portal.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE tickets
  ADD COLUMN IF NOT EXISTS last_reminder_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS csat_score       SMALLINT CHECK (csat_score BETWEEN 1 AND 5),
  ADD COLUMN IF NOT EXISTS csat_comment     TEXT,
  ADD COLUMN IF NOT EXISTS csat_at          TIMESTAMPTZ;

-- ── Config de automatización (singleton id=1) ────────────────────────────────
CREATE TABLE IF NOT EXISTS ticket_automation_config (
  id                          INT     PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  -- Recordatorio al cliente cuando waiting_on='CLIENT' supera estas horas.
  reminders_enabled           BOOLEAN NOT NULL DEFAULT true,
  reminder_after_hours        INT     NOT NULL DEFAULT 48  CHECK (reminder_after_hours BETWEEN 1 AND 8760),
  reminder_repeat_every_hours INT     NOT NULL DEFAULT 48  CHECK (reminder_repeat_every_hours BETWEEN 1 AND 8760),
  -- Auto-cierre de tickets RESUELTO sin actividad.
  autoclose_enabled           BOOLEAN NOT NULL DEFAULT true,
  autoclose_resolved_after_days INT   NOT NULL DEFAULT 5   CHECK (autoclose_resolved_after_days BETWEEN 1 AND 365),
  updated_by  TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ticket_automation_config (id, updated_by) VALUES (1, 'migration:105')
ON CONFLICT (id) DO NOTHING;

-- Índices para los barridos del scheduler (parciales, baratos).
CREATE INDEX IF NOT EXISTS idx_tickets_waiting_client
  ON tickets (updated_at) WHERE waiting_on = 'CLIENT';
CREATE INDEX IF NOT EXISTS idx_tickets_resolved_open
  ON tickets (resolved_at) WHERE status = 'RESUELTO';
