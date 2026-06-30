-- =============================================================================
-- 043 — Webhook outbound + Web Push notifications para Vigilancia.
--
-- 1. Columna webhook_url en surveillance_watchlist_subs:
--    Cuando channel='webhook', el cron POSTea JSON a esta URL. Firma HMAC
--    en header X-LegacyHunt-Signature (secret SURVEILLANCE_WEBHOOK_SECRET).
--    Si NULL pero channel='webhook' → notification_log status='skipped'.
--
-- 2. Tabla surveillance_push_subscriptions:
--    Web Push (RFC 8030) — guarda el endpoint + keys que el navegador
--    produce con pushManager.subscribe(). Una fila por (endpoint), con
--    operator_ci opcional para asociar suscripción a un analista.
--
-- Idempotente. Reaplicable con:
--   psql -U legacyhunt -d legacyhunt -f migrations/043_surveillance_webhook_and_push.sql
-- =============================================================================

-- ── 1. Webhook URL por sub ───────────────────────────────────────────────────
ALTER TABLE surveillance_watchlist_subs
  ADD COLUMN IF NOT EXISTS webhook_url VARCHAR(512);

COMMENT ON COLUMN surveillance_watchlist_subs.webhook_url IS
  'Endpoint HTTPS para el canal webhook. POST JSON con firma HMAC en '
  'header X-LegacyHunt-Signature. Cuando NULL pero channel=webhook, el '
  'cron registra skipped("webhook_url no configurado").';


-- ── 2. Push subscriptions ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS surveillance_push_subscriptions (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint        TEXT            NOT NULL UNIQUE,
  p256dh_key      TEXT            NOT NULL,
  auth_key        TEXT            NOT NULL,
  operator_ci     VARCHAR(64),
  user_agent      VARCHAR(255),
  created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
  last_used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_push_subs_operator
  ON surveillance_push_subscriptions(operator_ci)
  WHERE operator_ci IS NOT NULL;

COMMENT ON TABLE surveillance_push_subscriptions IS
  'Web Push subscriptions (RFC 8030). Una fila por (endpoint). El cron de '
  'watchlist broadcastea alertas urgentes a todas las subs activas; se '
  'eliminan automáticamente si el push falla con 410 Gone.';
