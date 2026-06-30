-- 115_inventory_collector.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Feature "Collector": lado RECEPTOR del agente de inventario de hardware/software
-- (scripts en /opt/legacyhunt/scripts/collector/). El agente reporta el estado
-- completo de cada equipo (Linux/macOS/Windows) a:
--   POST /api/auth/token       (email+password → JWT HS256 propio, aislado del OIDC)
--   POST /api/inventory/report (Bearer agent-jwt → payload schema_version "3")
-- y el SOC lo visualiza en Activos → tab "Collector".
--
-- Modelo NORMALIZADO: inventory_hosts (1 fila/host, resumen + identidad),
-- inventory_reports (histórico + payload crudo JSONB para auditoría/detalle), y
-- tablas hijas de "snapshot actual" que se REEMPLAZAN por host en cada reporte
-- (DELETE+INSERT dentro de una transacción) → siempre el último estado, consultable
-- y acotado. El histórico vive en inventory_reports.
--
-- Convención de esquema: SIN prefijo (mismo search_path que asset_registry, mig 010).
-- ip_address es TEXT (no inet): el agente puede mandar vacío/no-canónico (evita 22P02).
--
-- NO auto-aplicada (ver memoria pg_migrations_manual). Aplicar manualmente:
--   docker exec -i postgres psql -U huntdb -d huntdb < migrations/115_inventory_collector.sql
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Credenciales de agentes (email + password hash scrypt) ───────────────────
CREATE TABLE IF NOT EXISTS agent_credentials (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT         NOT NULL UNIQUE,
  pass_hash     TEXT         NOT NULL,                 -- scrypt: base64(salt).base64(dk)
  display_name  TEXT,
  role          TEXT         NOT NULL DEFAULT 'infraestructura',
  enabled       BOOLEAN      NOT NULL DEFAULT true,
  last_auth_at  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ── Hosts (1 fila por equipo; resumen + última identidad) ────────────────────
CREATE TABLE IF NOT EXISTS inventory_hosts (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_key    TEXT         NOT NULL UNIQUE,        -- uuid | serial | name+'|'+primary_mac
  hostname        TEXT,
  uuid            TEXT,
  serial_number   TEXT,
  primary_mac     TEXT,
  os_name         TEXT,
  os_version      TEXT,
  os_arch         TEXT,
  kernel          TEXT,
  ip_address      TEXT,
  domain          TEXT,
  virtualization  TEXT,
  timezone        TEXT,
  agent_type      TEXT,
  agent_version   TEXT,
  template_name   TEXT,                                -- asignación stub por os_name
  -- resumen de hardware
  cpu_model       TEXT,
  cpu_cores       INTEGER,
  ram_mb          INTEGER,
  manufacturer    TEXT,
  model           TEXT,
  -- resumen de seguridad / updates (para filtrar)
  firewall        TEXT,
  disk_encryption TEXT,
  antivirus       TEXT,
  pending_updates  INTEGER     NOT NULL DEFAULT 0,
  pending_security INTEGER     NOT NULL DEFAULT 0,
  software_count  INTEGER      NOT NULL DEFAULT 0,
  sections_failed JSONB        NOT NULL DEFAULT '[]',
  last_report_id  UUID,
  last_report_at  TIMESTAMPTZ,
  first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  report_count    INTEGER      NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_inv_hosts_lastseen ON inventory_hosts (last_report_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_hosts_os       ON inventory_hosts (os_name);
CREATE INDEX IF NOT EXISTS idx_inv_hosts_hostname ON inventory_hosts (lower(hostname));

-- ── Reportes (histórico; payload completo para auditoría y secciones long-tail) ──
CREATE TABLE IF NOT EXISTS inventory_reports (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id            UUID         NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  schema_version     TEXT,
  payload            JSONB        NOT NULL,
  payload_hash       TEXT         NOT NULL,            -- sha256(payload estable) — dedupe "sin cambios"
  payload_bytes      INTEGER,
  software_count     INTEGER,
  collection_seconds INTEGER,
  sections_failed    JSONB        NOT NULL DEFAULT '[]',
  template_name      TEXT,
  extraction_total   INTEGER      NOT NULL DEFAULT 0,
  extraction_success INTEGER      NOT NULL DEFAULT 0,
  source_ip          TEXT,
  received_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_reports_host ON inventory_reports (host_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_reports_hash ON inventory_reports (host_id, payload_hash);

-- ── Tablas hijas (snapshot actual; reemplazadas por host en cada reporte) ─────
CREATE TABLE IF NOT EXISTS inventory_software (
  host_id      UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  version      TEXT,
  install_date TEXT,
  publisher    TEXT
);
CREATE INDEX IF NOT EXISTS idx_inv_sw_host ON inventory_software (host_id);
CREATE INDEX IF NOT EXISTS idx_inv_sw_name ON inventory_software (lower(name));   -- "¿qué hosts tienen X?"

CREATE TABLE IF NOT EXISTS inventory_ports (
  host_id    UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  proto      TEXT,
  local_addr TEXT,
  port       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_inv_ports_host ON inventory_ports (host_id);
CREATE INDEX IF NOT EXISTS idx_inv_ports_port ON inventory_ports (port);

CREATE TABLE IF NOT EXISTS inventory_services (
  host_id UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  name    TEXT NOT NULL,
  state   TEXT
);
CREATE INDEX IF NOT EXISTS idx_inv_svc_host ON inventory_services (host_id);

CREATE TABLE IF NOT EXISTS inventory_users (
  host_id  UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  uid      TEXT,
  home     TEXT,
  shell    TEXT,
  is_admin BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_inv_users_host ON inventory_users (host_id);

CREATE TABLE IF NOT EXISTS inventory_partitions (
  host_id    UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  device     TEXT,
  fstype     TEXT,
  mountpoint TEXT,
  size_bytes BIGINT,
  used_bytes BIGINT
);
CREATE INDEX IF NOT EXISTS idx_inv_part_host ON inventory_partitions (host_id);

CREATE TABLE IF NOT EXISTS inventory_nics (
  host_id UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  name    TEXT,
  mac     TEXT,
  state   TEXT,
  ips     JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_inv_nics_host ON inventory_nics (host_id);

CREATE TABLE IF NOT EXISTS inventory_containers (
  host_id UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  name    TEXT,
  image   TEXT,
  status  TEXT
);
CREATE INDEX IF NOT EXISTS idx_inv_cont_host ON inventory_containers (host_id);
