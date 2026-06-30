-- 103_organizations.down.sql — revierte el cableado multi-tenant.
ALTER TABLE tickets ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE tickets DROP CONSTRAINT IF EXISTS fk_tickets_org;
DROP TABLE IF EXISTS organizations;
