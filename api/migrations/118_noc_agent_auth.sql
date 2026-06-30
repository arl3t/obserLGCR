-- 118_noc_agent_auth.sql
-- Credenciales de agentes NOC (email + password scrypt en PostgreSQL).
-- Los agentes obtienen JWT vía POST /api/auth/token y lo usan en heartbeat/acciones.
-- Compatible con el esquema de agent_credentials de 115_inventory_collector.sql.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS agent_credentials (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT         NOT NULL UNIQUE,
  pass_hash     TEXT         NOT NULL,
  display_name  TEXT,
  role          TEXT         NOT NULL DEFAULT 'infraestructura',
  enabled       BOOLEAN      NOT NULL DEFAULT true,
  last_auth_at  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_email ON agent_credentials (lower(email));

-- Credencial de laboratorio (cambiar en producción):
--   email:    noc-agent@obserlgcr.local
--   password: changeme-noc-agent
INSERT INTO agent_credentials (email, pass_hash, display_name, role)
VALUES (
  'noc-agent@obserlgcr.local',
  'zW8e5FbLo7tgWtD2HOWAEw==.L/rgMxSRQo7z5k6cnI/mtK6WREG61W5FCoBtg1sA9dMWBqKRsZWi8Cwe2YGYlWqkg6m7lRmuwTVPPqKPBl3UKw==',
  'Agente NOC laboratorio',
  'infraestructura'
)
ON CONFLICT (email) DO NOTHING;
