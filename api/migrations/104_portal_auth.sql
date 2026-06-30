-- 104_portal_auth.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F5 del Sistema de Tickets Público — AUTH del portal del cliente (magic-link).
-- Decisión 2026-06-27: auth de cliente por magic-link (sin contraseñas).
--
-- Superficie PÚBLICA, aislada de la interna. El cliente pide un enlace a su email;
-- al abrirlo se canjea por una sesión corta. NUNCA se guardan tokens en claro:
-- solo su SHA-256 (igual que un password hash). El token crudo viaja solo en el
-- enlace enviado por email.
--
-- Aislamiento multi-tenant: cada link/sesión está atada a una organización; el
-- email debe ser un contacto registrado de esa org (organizations.contacts).
-- Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7.2 / §9.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Magic-links de un solo uso ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS portal_magic_links (
  id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      UUID         NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  email       TEXT         NOT NULL,
  token_hash  TEXT         NOT NULL UNIQUE,        -- sha256(token crudo)
  expires_at  TIMESTAMPTZ  NOT NULL,
  used_at     TIMESTAMPTZ,                         -- NULL = sin canjear
  request_ip  TEXT,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_magic_links_lookup ON portal_magic_links (token_hash) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_portal_magic_links_email  ON portal_magic_links (org_id, email, created_at DESC);

-- ── Sesiones del portal (tras canjear un magic-link) ─────────────────────────
CREATE TABLE IF NOT EXISTS portal_sessions (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID         NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  email         TEXT         NOT NULL,
  token_hash    TEXT         NOT NULL UNIQUE,      -- sha256(session token crudo)
  expires_at    TIMESTAMPTZ  NOT NULL,
  revoked_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_sessions_lookup ON portal_sessions (token_hash)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_portal_sessions_org ON portal_sessions (org_id, email);
