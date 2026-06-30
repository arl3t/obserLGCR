-- IPAM enhancements: audit, soft-delete, NOC link, reservations, cron, RIR docs, DHCP.

ALTER TABLE ipam_regions
  ADD COLUMN IF NOT EXISTS contact_name  VARCHAR(128),
  ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255),
  ADD COLUMN IF NOT EXISTS rack_notes    TEXT,
  ADD COLUMN IF NOT EXISTS internal_asn  VARCHAR(32);

ALTER TABLE ipam_subnets
  ADD COLUMN IF NOT EXISTS deleted_at              TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS scan_enabled              BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS scan_cron               VARCHAR(64),
  ADD COLUMN IF NOT EXISTS utilization_alert_pct     NUMERIC(5,2) NOT NULL DEFAULT 85,
  ADD COLUMN IF NOT EXISTS utilization_webhook_url   TEXT;

ALTER TABLE ipam_addresses
  ADD COLUMN IF NOT EXISTS expires_at        TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS noc_device_id     UUID REFERENCES noc_devices(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS dhcp_lease_expires TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_ipam_addresses_noc ON ipam_addresses (noc_device_id);
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_expires ON ipam_addresses (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ipam_subnets_deleted ON ipam_subnets (deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_hostname ON ipam_addresses (hostname);
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_ip_host ON ipam_addresses (host(ip_address));

CREATE TABLE IF NOT EXISTS ipam_audit_log (
  id          BIGSERIAL PRIMARY KEY,
  entity_type VARCHAR(32) NOT NULL,
  entity_id   VARCHAR(64) NOT NULL,
  action      VARCHAR(32) NOT NULL,
  actor       VARCHAR(255),
  changes     JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ipam_audit_entity ON ipam_audit_log (entity_type, entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ipam_audit_created ON ipam_audit_log (created_at DESC);

CREATE TABLE IF NOT EXISTS ipam_dhcp_leases (
  id          SERIAL PRIMARY KEY,
  subnet_id   INTEGER REFERENCES ipam_subnets(id) ON DELETE CASCADE,
  ip_address  INET NOT NULL,
  mac_address MACADDR,
  hostname    VARCHAR(255),
  expires_at  TIMESTAMPTZ,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (subnet_id, ip_address)
);
