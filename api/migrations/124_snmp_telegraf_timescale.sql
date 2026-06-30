-- 124_snmp_telegraf_timescale.sql
-- Hypertables para métricas SNMP vía Telegraf (HOST-RESOURCES-MIB + IF-MIB).
-- Complementa 122_noc_timescale_observability.sql (agentes push heartbeat).

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- ── Registro de targets SNMP (opcional; Telegraf puede usar solo tags) ────────
CREATE TABLE IF NOT EXISTS snmp_targets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_ip       INET NOT NULL UNIQUE,
  hostname        TEXT,
  site            TEXT,
  region          TEXT DEFAULT 'global',
  community       TEXT NOT NULL DEFAULT 'public',
  snmp_version    TEXT NOT NULL DEFAULT '2c',
  port            INTEGER NOT NULL DEFAULT 161,
  noc_device_id   UUID REFERENCES noc_devices(id) ON DELETE SET NULL,
  enabled         BOOLEAN NOT NULL DEFAULT true,
  sys_descr       TEXT,
  sys_object_id   TEXT,
  last_poll_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_snmp_targets_noc_device
  ON snmp_targets (noc_device_id) WHERE noc_device_id IS NOT NULL;

-- ── Keepalive / disponibilidad (sysUpTime, sysDescr) ─────────────────────────
CREATE TABLE IF NOT EXISTS snmp_availability (
  time            TIMESTAMPTZ      NOT NULL,
  agent_host      TEXT             NOT NULL,
  device_ip       INET             NOT NULL,
  device_id       UUID             REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname        TEXT,
  site            TEXT,
  region          TEXT,
  sys_uptime      BIGINT,
  sys_uptime_cs   BIGINT,
  sys_descr       TEXT,
  sys_name        TEXT,
  sys_location    TEXT,
  source          TEXT             NOT NULL DEFAULT 'telegraf-snmp'
);

SELECT create_hypertable('snmp_availability', 'time',
  chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_snmp_avail_device_ip_time
  ON snmp_availability (device_ip, time DESC);

CREATE INDEX IF NOT EXISTS idx_snmp_avail_device_id_time
  ON snmp_availability (device_id, time DESC)
  WHERE device_id IS NOT NULL;

-- ── CPU (HOST-RESOURCES-MIB) ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS snmp_cpu (
  time                TIMESTAMPTZ  NOT NULL,
  agent_host          TEXT         NOT NULL,
  device_ip           INET         NOT NULL,
  device_id           UUID         REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname            TEXT,
  site                TEXT,
  region              TEXT,
  hr_processor_index  INTEGER,
  ss_cpu_user         NUMERIC(8,3),
  ss_cpu_system       NUMERIC(8,3),
  ss_cpu_idle         NUMERIC(8,3),
  hr_processor_load   NUMERIC(8,3),
  source              TEXT         NOT NULL DEFAULT 'telegraf-snmp'
);

SELECT create_hypertable('snmp_cpu', 'time',
  chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_snmp_cpu_device_ip_time
  ON snmp_cpu (device_ip, time DESC);

CREATE INDEX IF NOT EXISTS idx_snmp_cpu_device_id_time
  ON snmp_cpu (device_id, time DESC) WHERE device_id IS NOT NULL;

-- ── Memoria / almacenamiento (hrStorage*) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS snmp_memory (
  time                TIMESTAMPTZ  NOT NULL,
  agent_host          TEXT         NOT NULL,
  device_ip           INET         NOT NULL,
  device_id           UUID         REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname            TEXT,
  site                TEXT,
  region              TEXT,
  hr_storage_index    INTEGER,
  hr_storage_descr    TEXT,
  hr_storage_type     TEXT,
  hr_storage_alloc_units BIGINT,
  hr_storage_size     BIGINT,
  hr_storage_used     BIGINT,
  usage_pct           NUMERIC(6,3),
  source              TEXT         NOT NULL DEFAULT 'telegraf-snmp'
);

SELECT create_hypertable('snmp_memory', 'time',
  chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_snmp_memory_device_ip_time
  ON snmp_memory (device_ip, time DESC);

CREATE INDEX IF NOT EXISTS idx_snmp_memory_device_id_time
  ON snmp_memory (device_id, time DESC) WHERE device_id IS NOT NULL;

-- ── Tráfico por interfaz (IF-MIB) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS snmp_interface_traffic (
  time                TIMESTAMPTZ  NOT NULL,
  agent_host          TEXT         NOT NULL,
  device_ip           INET         NOT NULL,
  device_id           UUID         REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname            TEXT,
  site                TEXT,
  region              TEXT,
  interface_name      TEXT         NOT NULL,
  if_index            INTEGER,
  if_descr            TEXT,
  if_oper_status      INTEGER,
  if_admin_status     INTEGER,
  if_speed            BIGINT,
  if_hc_in_octets     BIGINT,
  if_hc_out_octets    BIGINT,
  if_in_errors        BIGINT,
  if_out_errors       BIGINT,
  if_in_discards      BIGINT,
  if_out_discards     BIGINT,
  rx_bps              BIGINT,
  tx_bps              BIGINT,
  source              TEXT         NOT NULL DEFAULT 'telegraf-snmp'
);

SELECT create_hypertable('snmp_interface_traffic', 'time',
  chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_snmp_iface_device_ip_name_time
  ON snmp_interface_traffic (device_ip, interface_name, time DESC);

CREATE INDEX IF NOT EXISTS idx_snmp_iface_device_id_time
  ON snmp_interface_traffic (device_id, time DESC) WHERE device_id IS NOT NULL;

-- ── Inventario software SNMP (hrSWInstalledTable) ────────────────────────────
CREATE TABLE IF NOT EXISTS snmp_software_inventory (
  collected_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  agent_host          TEXT         NOT NULL,
  device_ip           INET         NOT NULL,
  device_id           UUID         REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname            TEXT,
  site                TEXT,
  region              TEXT,
  sw_index            INTEGER,
  sw_name             TEXT         NOT NULL,
  sw_installed_date   TEXT,
  sw_path             TEXT,
  source              TEXT         NOT NULL DEFAULT 'telegraf-snmp'
);

CREATE INDEX IF NOT EXISTS idx_snmp_sw_device_ip_collected
  ON snmp_software_inventory (device_ip, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_snmp_sw_name
  ON snmp_software_inventory (lower(sw_name));

CREATE INDEX IF NOT EXISTS idx_snmp_sw_device_id
  ON snmp_software_inventory (device_id, collected_at DESC)
  WHERE device_id IS NOT NULL;

-- ── Retención 30 días ────────────────────────────────────────────────────────
SELECT add_retention_policy('snmp_availability',       INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('snmp_cpu',                INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('snmp_memory',             INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('snmp_interface_traffic',  INTERVAL '30 days', if_not_exists => TRUE);

-- Compresión
ALTER TABLE snmp_availability SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_ip,agent_host');
ALTER TABLE snmp_cpu SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_ip,agent_host');
ALTER TABLE snmp_memory SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_ip,agent_host');
ALTER TABLE snmp_interface_traffic SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_ip,interface_name');

SELECT add_compression_policy('snmp_availability',      INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('snmp_cpu',               INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('snmp_memory',            INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('snmp_interface_traffic', INTERVAL '7 days', if_not_exists => TRUE);

-- ── Sync software SNMP → server_software (gobernanza) ────────────────────────
CREATE OR REPLACE FUNCTION sync_snmp_software_to_governance(
  p_device_ip INET,
  p_hostname  TEXT DEFAULT NULL
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_host_id UUID;
  v_node_id UUID;
  v_hostname TEXT;
  v_count INTEGER := 0;
  r RECORD;
BEGIN
  SELECT id INTO v_node_id FROM noc_devices
   WHERE ip_address = p_device_ip OR host(ip_address) = host(p_device_ip)
   LIMIT 1;

  v_hostname := COALESCE(p_hostname, (SELECT hostname FROM noc_devices WHERE id = v_node_id), host(p_device_ip));

  SELECT id INTO v_host_id FROM inventory_hosts
   WHERE lower(hostname) = lower(v_hostname)
      OR ip_address = host(p_device_ip)
   LIMIT 1;

  IF v_host_id IS NULL THEN
    INSERT INTO inventory_hosts (identity_key, hostname, ip_address, agent_type, last_report_at, report_count)
    VALUES ('snmp:' || host(p_device_ip), v_hostname, host(p_device_ip), 'snmp-telegraf', NOW(), 1)
    RETURNING id INTO v_host_id;
  END IF;

  DELETE FROM server_software WHERE server_id = v_host_id;

  FOR r IN
    SELECT DISTINCT ON (lower(sw_name))
      sw_name, sw_installed_date, sw_path
    FROM snmp_software_inventory
    WHERE device_ip = p_device_ip
      AND collected_at >= NOW() - INTERVAL '2 hours'
    ORDER BY lower(sw_name), collected_at DESC
  LOOP
    INSERT INTO server_software (
      server_id, node_id, hostname, name, version, publisher, install_date, package_manager
    ) VALUES (
      v_host_id, v_node_id, v_hostname, r.sw_name, NULL, NULL,
      r.sw_installed_date, 'snmp-hrSWInstalledTable'
    );
    v_count := v_count + 1;
  END LOOP;

  UPDATE inventory_hosts SET software_count = v_count, last_report_at = NOW() WHERE id = v_host_id;

  RETURN v_count;
END;
$$;

COMMENT ON FUNCTION sync_snmp_software_to_governance IS
  'Cruza hrSWInstalledTable (snmp_software_inventory) con server_software; dispara trigger blacklist.';
