-- 108_ticket_webhooks_api.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F7 del Sistema de Tickets Público — INTEGRACIONES SALIENTES + API PÚBLICA.
--   · webhook_endpoints  — endpoints HTTP del cliente (su ITSM/Jira/ServiceNow)
--   · webhook_deliveries — bitácora de entregas + reintentos con backoff
--   · api_tokens         — tokens de servicio (bearer) por organización, scopes
-- Multi-tenant: todo cuelga de organizations(id). Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#17/#18) y §11 (F7).
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Endpoints de webhook salientes (uno o varios por organización) ───────────
CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  url           TEXT NOT NULL,
  -- secret cifrado en reposo (AES-256-GCM, SETTINGS_ENC_KEY) — se usa para firmar (HMAC-SHA256).
  secret_enc    TEXT NOT NULL,
  -- lista de eventos suscritos: 'ticket.created','ticket.message','ticket.status_changed','action_request.decided'
  events        JSONB NOT NULL DEFAULT '["*"]'::jsonb,
  description   TEXT,
  enabled       BOOLEAN NOT NULL DEFAULT true,
  failure_count INT NOT NULL DEFAULT 0,
  last_delivery_at TIMESTAMPTZ,
  created_by    VARCHAR(64),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_org ON webhook_endpoints(org_id);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_enabled ON webhook_endpoints(enabled) WHERE enabled;

-- ── Bitácora de entregas (cola + reintentos) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id   UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  event_type    VARCHAR(48) NOT NULL,
  payload       JSONB NOT NULL,
  status        VARCHAR(16) NOT NULL DEFAULT 'PENDING'  -- PENDING|DELIVERED|FAILED
                CHECK (status IN ('PENDING','DELIVERED','FAILED')),
  attempts      INT NOT NULL DEFAULT 0,
  max_attempts  INT NOT NULL DEFAULT 6,
  response_code INT,
  error         TEXT,
  next_retry_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at  TIMESTAMPTZ
);
-- Índice para el drenado del scheduler: pendientes vencidas, más antiguas primero.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
  ON webhook_deliveries(next_retry_at)
  WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id, created_at DESC);

-- ── Tokens de servicio para la API pública (bearer, por organización) ────────
CREATE TABLE IF NOT EXISTS api_tokens (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  -- sólo se guardan prefijo (para identificar en la UI) y hash SHA-256 del token.
  token_prefix  VARCHAR(16) NOT NULL,
  token_hash    TEXT NOT NULL UNIQUE,
  -- scopes: 'tickets:read','tickets:write'
  scopes        JSONB NOT NULL DEFAULT '["tickets:read"]'::jsonb,
  enabled       BOOLEAN NOT NULL DEFAULT true,
  expires_at    TIMESTAMPTZ,
  last_used_at  TIMESTAMPTZ,
  created_by    VARCHAR(64),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_org ON api_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash) WHERE revoked_at IS NULL;
