-- 103_organizations.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F2 del Sistema de Tickets Público — MULTI-TENANT desde el inicio
-- (decisión 2026-06-27: arrancar multi-tenant, no solo tenant-ready).
--
-- `organizations` es el tenant: cada cliente externo es una org. El personal del
-- SOC es GLOBAL (ve todas las orgs); el aislamiento por org se aplica en la
-- superficie PÚBLICA del portal (F5), no en la interna. Aquí solo se cablea el
-- modelo: tickets.org_id pasa de nullable-sin-FK (mig 100) a NOT NULL con FK.
--
-- Idempotente: seedea una org por defecto y rellena tickets huérfanos antes de
-- endurecer la columna, por si la mig 100 ya tenía filas.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
  id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         TEXT         NOT NULL UNIQUE,         -- identificador estable para el portal/URL
  name         TEXT         NOT NULL,
  status       VARCHAR(12)  NOT NULL DEFAULT 'ACTIVE'
                 CHECK (status IN ('ACTIVE','SUSPENDED','ARCHIVED')),
  -- Contactos del cliente y config de portal (zona horaria/horario para SLA-com §3.5).
  contacts     JSONB        NOT NULL DEFAULT '[]'::jsonb,
  portal_config JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_organizations_status ON organizations (status);

-- Org por defecto (mono-cliente inicial). slug fijo para que la API la resuelva
-- como fallback hasta que se den de alta clientes reales.
INSERT INTO organizations (slug, name)
  VALUES ('default', 'Organización por defecto')
ON CONFLICT (slug) DO NOTHING;

-- Rellenar tickets sin org (creados bajo mig 100 antes de este endurecimiento).
UPDATE tickets
   SET org_id = (SELECT id FROM organizations WHERE slug = 'default')
 WHERE org_id IS NULL;

-- Endurecer: FK + NOT NULL.
ALTER TABLE tickets
  ADD CONSTRAINT fk_tickets_org
  FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE RESTRICT;

ALTER TABLE tickets
  ALTER COLUMN org_id SET NOT NULL;
