-- IPAM — inventario de redes RFC 1918 (regiones, subredes, direcciones).
-- Consumido por el microservicio FastAPI ipam (SQLAlchemy + Pydantic).

CREATE TYPE ipam_address_status AS ENUM (
  'Offline',
  'Online',
  'Reserved',
  'Free',
  'DHCP'
);

CREATE TABLE IF NOT EXISTS ipam_regions (
  id          SERIAL PRIMARY KEY,
  name        VARCHAR(100) NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE IF NOT EXISTS ipam_subnets (
  id               SERIAL PRIMARY KEY,
  region_id        INTEGER NOT NULL REFERENCES ipam_regions(id) ON DELETE RESTRICT,
  vlan_id          INTEGER,
  vlan_name        VARCHAR(64),
  cidr_block       CIDR NOT NULL,
  broadcast_domain VARCHAR(128),
  description      TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT ipam_subnets_vlan_id_check CHECK (vlan_id IS NULL OR (vlan_id >= 1 AND vlan_id <= 4094)),
  CONSTRAINT unique_cidr_per_region UNIQUE (region_id, cidr_block)
);

CREATE INDEX IF NOT EXISTS idx_ipam_subnets_region ON ipam_subnets (region_id);
CREATE INDEX IF NOT EXISTS idx_ipam_subnets_cidr_gist ON ipam_subnets USING gist (cidr_block inet_ops);

CREATE TABLE IF NOT EXISTS ipam_addresses (
  id                   SERIAL PRIMARY KEY,
  subnet_id            INTEGER NOT NULL REFERENCES ipam_subnets(id) ON DELETE CASCADE,
  ip_address           INET NOT NULL,
  status               ipam_address_status NOT NULL DEFAULT 'Free',
  hostname             VARCHAR(255),
  mac_address          MACADDR,
  description          TEXT,
  last_seen            TIMESTAMPTZ,
  is_discovered_by_nmap BOOLEAN NOT NULL DEFAULT FALSE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_ip_per_subnet UNIQUE (subnet_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_ipam_addresses_subnet ON ipam_addresses (subnet_id);
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_status ON ipam_addresses (status);
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_ip ON ipam_addresses (ip_address);

INSERT INTO ipam_regions (name, description) VALUES
  ('DC-ASU', 'Datacenter Asunción — RFC 1918'),
  ('LAN-CORP', 'Red corporativa interna')
ON CONFLICT (name) DO NOTHING;
