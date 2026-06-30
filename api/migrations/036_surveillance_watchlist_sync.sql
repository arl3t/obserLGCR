-- =============================================================================
-- 036 — Sincronización backend de la Watchlist + log de notificaciones
--
-- Hasta ahora la watchlist vivía sólo en localStorage del navegador. El cron
-- de notificaciones (Ola B #2) necesita persistencia server-side para barrer
-- dominios sin depender de que un cliente esté abierto.
--
-- El cliente sincroniza a la API cuando agrega/edita/borra entradas; el cron
-- lee de esta tabla. La fuente de verdad sigue siendo el cliente para evitar
-- merge complejo entre múltiples ventanas/operadores — la API solo refleja
-- lo último que se le mandó.
--
-- Idempotente: CREATE … IF NOT EXISTS.
-- =============================================================================

CREATE TABLE IF NOT EXISTS surveillance_watchlist_subs (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  domain          VARCHAR(253)    NOT NULL UNIQUE,
  owner_label     VARCHAR(255)    NOT NULL,
  owner_ci        VARCHAR(64),
  frequency       VARCHAR(8)      NOT NULL CHECK (frequency IN ('instant', 'hourly', 'daily', 'weekly')),
  channel         VARCHAR(8)      NOT NULL CHECK (channel IN ('email', 'slack', 'teams', 'sms', 'webhook')),
  alert_on        TEXT[]          NOT NULL DEFAULT '{}',
  notes           TEXT,
  added_at        TIMESTAMPTZ     NOT NULL,
  last_notified_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_watchlist_subs_freq
  ON surveillance_watchlist_subs(frequency, last_notified_at NULLS FIRST);

COMMENT ON TABLE surveillance_watchlist_subs IS
  'Persistencia server-side de la watchlist. El cliente sincroniza vía '
  'POST /api/surveillance/watchlist. Cron consulta para enviar notificaciones.';


-- ── Log de notificaciones enviadas ────────────────────────────────────────────
--
-- Registro de qué notificación se mandó cuándo + a quién. Sirve para no
-- duplicar notificaciones (instant: idempotencia por finding_id) y para
-- debugging del cron.

CREATE TABLE IF NOT EXISTS surveillance_notification_log (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  domain          VARCHAR(253)    NOT NULL,
  channel         VARCHAR(8)      NOT NULL,
  finding_ids     TEXT[]          NOT NULL DEFAULT '{}',
  severity_max    VARCHAR(8),
  status          VARCHAR(16)     NOT NULL CHECK (status IN ('sent', 'skipped', 'failed')),
  detail          TEXT,
  sent_at         TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notification_log_domain
  ON surveillance_notification_log(domain, sent_at DESC);

CREATE INDEX IF NOT EXISTS brin_notification_log_time
  ON surveillance_notification_log USING BRIN (sent_at);

COMMENT ON TABLE surveillance_notification_log IS
  'Bitácora de notificaciones enviadas por el cron de watchlist. Mantener '
  '90d para diagnóstico — agregar cleanup cron si crece mucho.';
