-- =============================================================================
-- 017 — Ampliar contexto de red en incident_cases_pg
--
-- Añade campos que ya existen en los logs raw pero no se persistían:
--   source_port      : puerto TCP/UDP origen del evento
--   protocol         : protocolo de transporte (tcp, udp, icmp…)
--   firewall_action  : acción del firewall (ACCEPT, DENY, DROP…)
--   src_country      : código ISO-3166-1 alfa-2 del país origen (de VT/Shodan)
--
-- Idempotente: ADD COLUMN IF NOT EXISTS
-- =============================================================================

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS source_port     INT            CHECK (source_port BETWEEN 0 AND 65535),
  ADD COLUMN IF NOT EXISTS protocol        VARCHAR(10),
  ADD COLUMN IF NOT EXISTS firewall_action VARCHAR(10),
  ADD COLUMN IF NOT EXISTS src_country     CHAR(2);

CREATE INDEX IF NOT EXISTS idx_cases_src_country
  ON incident_cases_pg(src_country)
  WHERE src_country IS NOT NULL;
