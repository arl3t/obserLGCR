-- =============================================================================
-- 045 — Dead-letter queue para notificaciones de Vigilancia fallidas (#8).
--
-- Cuando una notificación outbound (slack/email/webhook) falla repetidamente
-- después de N retries con backoff, en lugar de perderla la guardamos acá
-- para reprocesar manualmente o por job de reintento diario.
--
-- Diferenciado del `surveillance_notification_log` (que ya registra
-- skipped/failed con detail): el LOG es bitácora; el DLQ es cola accionable.
--
-- Idempotente.
-- =============================================================================

CREATE TABLE IF NOT EXISTS surveillance_dead_letters (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  source          VARCHAR(32)     NOT NULL,
  -- Identifica el destino — webhook URL hash, email "to", slack channel.
  target_ref      VARCHAR(255)    NOT NULL,
  -- Payload original como JSON para poder reintentar el envío.
  payload         JSONB           NOT NULL,
  last_error      TEXT            NOT NULL,
  attempts        INT             NOT NULL DEFAULT 1,
  first_failed_at TIMESTAMPTZ     NOT NULL DEFAULT now(),
  last_failed_at  TIMESTAMPTZ     NOT NULL DEFAULT now(),
  -- Resolved indica si fue reprocesada con éxito o descartada manualmente.
  resolved_at     TIMESTAMPTZ,
  resolution      VARCHAR(16)     CHECK (resolution IS NULL OR resolution IN ('retried', 'discarded'))
);

CREATE INDEX IF NOT EXISTS idx_dlq_source_unresolved
  ON surveillance_dead_letters(source)
  WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_dlq_last_failed
  ON surveillance_dead_letters(last_failed_at DESC);

COMMENT ON TABLE surveillance_dead_letters IS
  'Cola de notificaciones outbound que fallaron tras N retries. Endpoint '
  '/api/surveillance/dlq lista las pendientes; manager puede reintentar o '
  'descartar manualmente. Sin cleanup automático — mantener para auditoría.';
