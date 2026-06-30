-- 114_ticket_closure_confirmation.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Sign-off de cierre por el cliente (propuesta #23, docs/PROPUESTA-TICKETING-PUBLICO.md).
--
-- Requerimiento: para CERRAR un ticket es OBLIGATORIA la confirmación del cliente.
-- El SOC ya no puede mover un ticket a CERRADO directamente: dispara una acción
-- explícita ("Solicitar confirmación de cierre") que genera un VÍNCULO single-use
-- con TTL; el token del vínculo ES la credencial (página ligera, sin login). El
-- cliente confirma → CERRADO, o rechaza → vuelve la pelota al SOC (waiting_on=SOC).
--
-- Solo se guarda el SHA-256 del token (el token crudo viaja únicamente en el link),
-- mismo patrón que portal_magic_links (migración 104).
--
-- NO auto-aplicada (ver memoria pg_migrations_manual). Aplicar manualmente:
--   docker exec -i postgres psql -U huntdb -d huntdb < migrations/114_ticket_closure_confirmation.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ticket_closure_confirmations (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id     UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  token_hash    TEXT NOT NULL UNIQUE,           -- SHA-256 del token crudo (nunca en claro)
  requested_by  VARCHAR(128) NOT NULL,          -- CI del operador SOC que solicitó
  requested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  -- Resolución del cliente (NULL = pendiente):
  decided_at    TIMESTAMPTZ,
  decision      VARCHAR(12) CHECK (decision IN ('CONFIRMADO','RECHAZADO')),
  decided_ip    VARCHAR(64),
  reject_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_tcc_ticket ON ticket_closure_confirmations(ticket_id);

-- A lo sumo UNA confirmación pendiente "viva" por ticket: solicitar de nuevo
-- invalida la anterior (el servicio marca las previas como superseded).
CREATE UNIQUE INDEX IF NOT EXISTS uq_tcc_pending
  ON ticket_closure_confirmations(ticket_id) WHERE decided_at IS NULL;

-- Marca de "cierre pendiente de confirmación del cliente" en el propio ticket
-- (deriva del índice anterior pero se materializa para serializar listados sin join).
-- Se setea al solicitar y se limpia al confirmar (→ CERRADO), rechazar o reabrir.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS closure_requested_at TIMESTAMPTZ;
