-- =============================================================================
-- 039 — Columna notify_email opcional en surveillance_watchlist_subs.
--
-- Item 3 del plan docs/MEJORA-VIGILANCIA-DETECCION-TEMPRANA.md.
-- Necesaria para que el cron del notifier pueda mandar email por sub cuando
-- channel='email'. Si la columna queda NULL, el cron usa la variable de
-- entorno SURVEILLANCE_NOTIFY_FALLBACK_EMAIL; si tampoco existe, registra
-- skipped('email no configurado para este sub') en notification_log.
--
-- Idempotente. Sin backfill — los subs existentes con channel='email' siguen
-- sin destinatario hasta que el operador edite el sub y complete el campo.
-- =============================================================================

ALTER TABLE surveillance_watchlist_subs
  ADD COLUMN IF NOT EXISTS notify_email VARCHAR(255);

COMMENT ON COLUMN surveillance_watchlist_subs.notify_email IS
  'Destinatario opcional para notificaciones por email. Si NULL, el cron usa '
  'SURVEILLANCE_NOTIFY_FALLBACK_EMAIL. Coma-separada permite múltiples '
  'destinos (mismo formato nodemailer "to").';
