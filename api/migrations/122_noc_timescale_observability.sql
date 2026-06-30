-- 122_noc_timescale_observability.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Capa de observabilidad NOC: TimescaleDB (métricas + logs) + inventario
-- software + blacklist/whitelist + cola de incidentes.
--
-- Requisitos: PostgreSQL 16+ con extensión TimescaleDB 2.x
--   CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
--
-- Integración obserLGCR:
--   - node_id → noc_devices(id)           (keepalive, métricas, logs)
--   - server_id → inventory_hosts(id)     (inventario HW/SW, gobernanza)
--   - incidents_queue → worker API → incident_cases_pg (Gestión)
--
-- Aplicar:
--   docker exec -i obserlgcr-postgres psql -U obserlgcr -d obserlgcr \
--     < api/migrations/122_noc_timescale_observability.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Esquema lógico (opcional; comentarios referencian tablas en public) ─────

-- ============================================================================
-- 1. KEEPALIVE — estado de servidores activos / caídos (serie temporal)
-- ============================================================================

CREATE TABLE IF NOT EXISTS keepalive_status (
  time            TIMESTAMPTZ      NOT NULL,
  node_id         UUID             NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  hostname        TEXT             NOT NULL,
  site            TEXT,
  region          TEXT,
  status          TEXT             NOT NULL
                    CHECK (status IN ('online', 'offline', 'degraded', 'unknown')),
  rtt_ms          NUMERIC(8,2),
  agent_version   TEXT,
  source          TEXT             NOT NULL DEFAULT 'heartbeat'
                    CHECK (source IN ('heartbeat', 'watcher', 'manual', 'synthetic')),
  details         JSONB            NOT NULL DEFAULT '{}'
);

SELECT create_hypertable(
  'keepalive_status',
  'time',
  chunk_time_interval => INTERVAL '1 day',
  if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_keepalive_node_time
  ON keepalive_status (node_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_keepalive_hostname_time
  ON keepalive_status (hostname, time DESC);

CREATE INDEX IF NOT EXISTS idx_keepalive_status_time
  ON keepalive_status (status, time DESC)
  WHERE status IN ('offline', 'degraded');

-- Vista materializada de estado actual (último evento por nodo)
CREATE OR REPLACE VIEW v_keepalive_current AS
SELECT DISTINCT ON (node_id)
  node_id,
  hostname,
  site,
  region,
  status,
  rtt_ms,
  agent_version,
  time AS last_event_at
FROM keepalive_status
ORDER BY node_id, time DESC;

-- ============================================================================
-- 2. MÉTRICAS DE RENDIMIENTO — hypertables
-- ============================================================================

-- CPU
CREATE TABLE IF NOT EXISTS cpu_usage (
  time            TIMESTAMPTZ      NOT NULL,
  node_id         UUID             NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  hostname        TEXT             NOT NULL,
  site            TEXT,
  region          TEXT,
  usage_pct       NUMERIC(6,3)     NOT NULL CHECK (usage_pct >= 0 AND usage_pct <= 100),
  load_1m         NUMERIC(8,4),
  load_5m         NUMERIC(8,4),
  cores           INTEGER,
  agent_id        TEXT
);

SELECT create_hypertable(
  'cpu_usage',
  'time',
  chunk_time_interval => INTERVAL '1 day',
  if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_cpu_usage_node_time
  ON cpu_usage (node_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_cpu_usage_hostname_time
  ON cpu_usage (hostname, time DESC);

-- Memoria
CREATE TABLE IF NOT EXISTS memory_usage (
  time            TIMESTAMPTZ      NOT NULL,
  node_id         UUID             NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  hostname        TEXT             NOT NULL,
  site            TEXT,
  region          TEXT,
  usage_pct       NUMERIC(6,3)     NOT NULL CHECK (usage_pct >= 0 AND usage_pct <= 100),
  used_bytes      BIGINT,
  total_bytes     BIGINT,
  swap_usage_pct  NUMERIC(6,3),
  agent_id        TEXT
);

SELECT create_hypertable(
  'memory_usage',
  'time',
  chunk_time_interval => INTERVAL '1 day',
  if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_memory_usage_node_time
  ON memory_usage (node_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_memory_usage_hostname_time
  ON memory_usage (hostname, time DESC);

-- Disco (complemento requerido: uso de disco)
CREATE TABLE IF NOT EXISTS disk_usage (
  time            TIMESTAMPTZ      NOT NULL,
  node_id         UUID             NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  hostname        TEXT             NOT NULL,
  site            TEXT,
  region          TEXT,
  mountpoint      TEXT             NOT NULL DEFAULT '/',
  device          TEXT,
  fstype          TEXT,
  usage_pct       NUMERIC(6,3)     NOT NULL CHECK (usage_pct >= 0 AND usage_pct <= 100),
  used_bytes      BIGINT,
  total_bytes     BIGINT
);

SELECT create_hypertable(
  'disk_usage',
  'time',
  chunk_time_interval => INTERVAL '1 day',
  if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_disk_usage_node_mount_time
  ON disk_usage (node_id, mountpoint, time DESC);

-- Tráfico de red (modelo wide: alineado al agente obserLGCR bw_in/out_bps)
CREATE TABLE IF NOT EXISTS network_traffic (
  time            TIMESTAMPTZ      NOT NULL,
  node_id         UUID             NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  hostname        TEXT             NOT NULL,
  site            TEXT,
  region          TEXT,
  iface           TEXT             NOT NULL DEFAULT 'default',
  rx_bps          BIGINT           NOT NULL DEFAULT 0,
  tx_bps          BIGINT           NOT NULL DEFAULT 0,
  rx_packets_ps   BIGINT,
  tx_packets_ps   BIGINT,
  rtt_ms          NUMERIC(8,2),
  agent_id        TEXT
);

SELECT create_hypertable(
  'network_traffic',
  'time',
  chunk_time_interval => INTERVAL '1 day',
  if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_network_traffic_node_time
  ON network_traffic (node_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_network_traffic_hostname_iface_time
  ON network_traffic (hostname, iface, time DESC);

-- ============================================================================
-- 3. LOGS ESTRUCTURADOS
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_logs (
  time            TIMESTAMPTZ      NOT NULL,
  node_id         UUID             NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  hostname        TEXT             NOT NULL,
  site            TEXT,
  region          TEXT,
  severity        TEXT             NOT NULL
                    CHECK (severity IN ('debug', 'info', 'warn', 'error', 'critical')),
  source          TEXT,
  log_type        TEXT             NOT NULL DEFAULT 'agent'
                    CHECK (log_type IN ('agent', 'kernel', 'service', 'watcher', 'action', 'audit')),
  message         TEXT             NOT NULL,
  raw             JSONB            NOT NULL DEFAULT '{}',
  trace_id        TEXT,
  ingestion_id    UUID             DEFAULT gen_random_uuid()
);

SELECT create_hypertable(
  'system_logs',
  'time',
  chunk_time_interval => INTERVAL '1 day',
  if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_system_logs_node_time
  ON system_logs (node_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_system_logs_hostname_time
  ON system_logs (hostname, time DESC);

CREATE INDEX IF NOT EXISTS idx_system_logs_severity_time
  ON system_logs (severity, time DESC)
  WHERE severity IN ('error', 'critical');

-- GIN para búsqueda en payload estructurado
CREATE INDEX IF NOT EXISTS idx_system_logs_raw_gin
  ON system_logs USING GIN (raw jsonb_path_ops);

-- ============================================================================
-- 4. POLÍTICAS DE RETENCIÓN (30 días métricas/logs detallados)
-- ============================================================================

SELECT add_retention_policy('keepalive_status',  INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('cpu_usage',         INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('memory_usage',    INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('disk_usage',      INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('network_traffic', INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('system_logs',     INTERVAL '30 days', if_not_exists => TRUE);

-- Compresión automática en chunks > 7 días (TimescaleDB 2.x)
ALTER TABLE keepalive_status  SET (timescaledb.compress, timescaledb.compress_segmentby = 'node_id,hostname');
ALTER TABLE cpu_usage         SET (timescaledb.compress, timescaledb.compress_segmentby = 'node_id,hostname');
ALTER TABLE memory_usage      SET (timescaledb.compress, timescaledb.compress_segmentby = 'node_id,hostname');
ALTER TABLE disk_usage        SET (timescaledb.compress, timescaledb.compress_segmentby = 'node_id,hostname,mountpoint');
ALTER TABLE network_traffic   SET (timescaledb.compress, timescaledb.compress_segmentby = 'node_id,hostname,iface');
ALTER TABLE system_logs       SET (timescaledb.compress, timescaledb.compress_segmentby = 'node_id,hostname,severity');

SELECT add_compression_policy('cpu_usage',         INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('memory_usage',      INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('disk_usage',        INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('network_traffic',   INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('system_logs',       INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('keepalive_status', INTERVAL '7 days', if_not_exists => TRUE);

-- ============================================================================
-- 5. INVENTARIO SOFTWARE + GOBERNANZA (PostgreSQL relacional)
-- ============================================================================

-- Hardware snapshot (complementa inventory_hosts de mig 115)
CREATE TABLE IF NOT EXISTS server_hardware (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id       UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  node_id         UUID REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname        TEXT NOT NULL,
  manufacturer    TEXT,
  model           TEXT,
  serial_number   TEXT,
  cpu_model       TEXT,
  cpu_cores       INTEGER,
  ram_mb          INTEGER,
  disk_total_gb   NUMERIC(12,2),
  virtualization  TEXT,
  collected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  raw             JSONB NOT NULL DEFAULT '{}',
  UNIQUE (server_id)
);

CREATE INDEX IF NOT EXISTS idx_server_hardware_hostname
  ON server_hardware (lower(hostname));

CREATE INDEX IF NOT EXISTS idx_server_hardware_node
  ON server_hardware (node_id)
  WHERE node_id IS NOT NULL;

-- Software instalado por servidor (snapshot actual + histórico por collected_at)
CREATE TABLE IF NOT EXISTS server_software (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id       UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  node_id         UUID REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname        TEXT NOT NULL,
  name            TEXT NOT NULL,
  version         TEXT,
  publisher       TEXT,
  install_date    TEXT,
  package_manager TEXT,
  cpe             TEXT,
  is_whitelisted  BOOLEAN,
  is_blacklisted  BOOLEAN NOT NULL DEFAULT false,
  collected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  report_id       UUID REFERENCES inventory_reports(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_server_software_server
  ON server_software (server_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_server_software_name
  ON server_software (lower(name));

CREATE INDEX IF NOT EXISTS idx_server_software_hostname_name
  ON server_software (lower(hostname), lower(name));

CREATE UNIQUE INDEX IF NOT EXISTS uq_server_software_snapshot
  ON server_software (server_id, lower(name), COALESCE(lower(version), ''), COALESCE(lower(publisher), ''));

-- Lista blanca
CREATE TABLE IF NOT EXISTS software_whitelist (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  software_name   TEXT NOT NULL,
  match_type      TEXT NOT NULL DEFAULT 'exact'
                    CHECK (match_type IN ('exact', 'prefix', 'suffix', 'regex', 'cpe')),
  pattern         TEXT NOT NULL,
  publisher       TEXT,
  min_version     TEXT,
  max_version     TEXT,
  enabled         BOOLEAN NOT NULL DEFAULT true,
  notes           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_software_whitelist_enabled
  ON software_whitelist (enabled)
  WHERE enabled = true;

-- Lista negra
CREATE TABLE IF NOT EXISTS software_blacklist (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  software_name   TEXT NOT NULL,
  match_type      TEXT NOT NULL DEFAULT 'exact'
                    CHECK (match_type IN ('exact', 'prefix', 'suffix', 'regex', 'cpe')),
  pattern         TEXT NOT NULL,
  publisher       TEXT,
  severity        TEXT NOT NULL DEFAULT 'HIGH'
                    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  mitre_technique TEXT,
  enabled         BOOLEAN NOT NULL DEFAULT true,
  auto_incident   BOOLEAN NOT NULL DEFAULT true,
  notes           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_software_blacklist_enabled
  ON software_blacklist (enabled)
  WHERE enabled = true;

CREATE INDEX IF NOT EXISTS idx_software_blacklist_pattern
  ON software_blacklist (lower(pattern));

-- Cola de incidentes (desacoplada del worker que crea incident_cases_pg)
CREATE TABLE IF NOT EXISTS incidents_queue (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  incident_type   TEXT NOT NULL
                    CHECK (incident_type IN (
                      'forbidden_software', 'unapproved_software',
                      'keepalive_down', 'high_cpu', 'high_memory', 'high_rtt', 'custom'
                    )),
  severity        TEXT NOT NULL
                    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE')),
  server_id       UUID REFERENCES inventory_hosts(id) ON DELETE SET NULL,
  node_id         UUID REFERENCES noc_devices(id) ON DELETE SET NULL,
  hostname        TEXT NOT NULL,
  dedup_key       TEXT NOT NULL,
  payload         JSONB NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'done', 'failed', 'suppressed')),
  case_id         VARCHAR(64),
  error_message   TEXT,
  processed_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_queue_pending_dedup
  ON incidents_queue (dedup_key)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_incidents_queue_pending
  ON incidents_queue (created_at ASC)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_incidents_queue_hostname
  ON incidents_queue (hostname, created_at DESC);

-- ============================================================================
-- 6. FUNCIÓN DE MATCHING + TRIGGER BLACKLIST
-- ============================================================================

CREATE OR REPLACE FUNCTION noc_match_software_rule(
  p_name      TEXT,
  p_version   TEXT,
  p_publisher TEXT,
  p_match_type TEXT,
  p_pattern   TEXT,
  p_rule_publisher TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_name TEXT := lower(COALESCE(p_name, ''));
  v_pat  TEXT := lower(COALESCE(p_pattern, ''));
BEGIN
  IF p_rule_publisher IS NOT NULL AND p_rule_publisher <> ''
     AND lower(COALESCE(p_publisher, '')) <> lower(p_rule_publisher) THEN
    RETURN false;
  END IF;

  CASE p_match_type
    WHEN 'exact'  THEN RETURN v_name = v_pat;
    WHEN 'prefix' THEN RETURN v_name LIKE v_pat || '%';
    WHEN 'suffix' THEN RETURN v_name LIKE '%' || v_pat;
    WHEN 'regex'  THEN RETURN v_name ~* p_pattern;
    WHEN 'cpe'    THEN RETURN COALESCE(p_version, '') ILIKE p_pattern || '%';
    ELSE RETURN false;
  END CASE;
END;
$$;

CREATE OR REPLACE FUNCTION trg_server_software_governance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  bl RECORD;
  wl_found BOOLEAN := false;
  v_dedup TEXT;
BEGIN
  -- Evaluar whitelist
  SELECT EXISTS (
    SELECT 1 FROM software_whitelist w
    WHERE w.enabled
      AND noc_match_software_rule(NEW.name, NEW.version, NEW.publisher,
                                  w.match_type, w.pattern, w.publisher)
  ) INTO wl_found;

  NEW.is_whitelisted := wl_found;

  -- Evaluar blacklist
  FOR bl IN
    SELECT id, software_name, match_type, pattern, publisher, severity, auto_incident, mitre_technique
    FROM software_blacklist
    WHERE enabled
  LOOP
    IF noc_match_software_rule(NEW.name, NEW.version, NEW.publisher,
                               bl.match_type, bl.pattern, bl.publisher) THEN
      NEW.is_blacklisted := true;

      IF bl.auto_incident THEN
        v_dedup := encode(
          digest(
            lower(NEW.hostname) || '|forbidden_software|' ||
            lower(bl.pattern) || '|' || lower(COALESCE(NEW.version, '')),
            'sha256'
          ),
          'hex'
        );

        INSERT INTO incidents_queue (
          incident_type, severity, server_id, node_id, hostname,
          dedup_key, payload, status
        )
        VALUES (
          'forbidden_software',
          bl.severity,
          NEW.server_id,
          NEW.node_id,
          NEW.hostname,
          v_dedup,
          jsonb_build_object(
            'rule_id',          bl.id,
            'rule_name',        bl.software_name,
            'match_type',       bl.match_type,
            'pattern',          bl.pattern,
            'software_name',    NEW.name,
            'software_version', NEW.version,
            'publisher',        NEW.publisher,
            'mitre_technique',  bl.mitre_technique,
            'server_software_id', NEW.id,
            'collected_at',     NEW.collected_at
          ),
          'pending'
        )
        ON CONFLICT (dedup_key) WHERE (status = 'pending') DO NOTHING;
      END IF;

      EXIT; -- primera regla negra que coincide
    END IF;
  END LOOP;

  -- Software no listado en whitelist (política estricta opcional)
  IF NOT wl_found AND NOT NEW.is_blacklisted THEN
    IF EXISTS (SELECT 1 FROM software_whitelist WHERE enabled LIMIT 1) THEN
      v_dedup := encode(
        digest(lower(NEW.hostname) || '|unapproved|' || lower(NEW.name), 'sha256'),
        'hex'
      );
      INSERT INTO incidents_queue (
        incident_type, severity, server_id, node_id, hostname,
        dedup_key, payload, status
      )
      VALUES (
        'unapproved_software',
        'MEDIUM',
        NEW.server_id,
        NEW.node_id,
        NEW.hostname,
        v_dedup,
        jsonb_build_object(
          'software_name',    NEW.name,
          'software_version', NEW.version,
          'publisher',        NEW.publisher,
          'policy',           'whitelist_enforced'
        ),
        'pending'
      )
      ON CONFLICT (dedup_key) WHERE (status = 'pending') DO NOTHING;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_server_software_governance ON server_software;
CREATE TRIGGER trg_server_software_governance
  BEFORE INSERT OR UPDATE OF name, version, publisher
  ON server_software
  FOR EACH ROW
  EXECUTE FUNCTION trg_server_software_governance();

-- ============================================================================
-- 7. FUNCIÓN AUXILIAR: ingestar heartbeat del agente → TimescaleDB
--    (llamar desde api/routes/noc.mjs tras validar JWT)
-- ============================================================================

CREATE OR REPLACE FUNCTION noc_ingest_heartbeat_ts(
  p_node_id       UUID,
  p_hostname      TEXT,
  p_site          TEXT,
  p_region        TEXT,
  p_status        TEXT,
  p_cpu_pct       NUMERIC,
  p_mem_pct       NUMERIC,
  p_rtt_ms        NUMERIC,
  p_rx_bps        BIGINT,
  p_tx_bps        BIGINT,
  p_iface         TEXT DEFAULT 'default',
  p_agent_version TEXT DEFAULT NULL,
  p_agent_id      TEXT DEFAULT NULL,
  p_disk_mounts   JSONB DEFAULT '[]'::jsonb
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  d     JSONB;
BEGIN
  INSERT INTO keepalive_status (time, node_id, hostname, site, region, status, rtt_ms, agent_version, source)
  VALUES (v_now, p_node_id, p_hostname, p_site, p_region, p_status, p_rtt_ms, p_agent_version, 'heartbeat');

  IF p_cpu_pct IS NOT NULL THEN
    INSERT INTO cpu_usage (time, node_id, hostname, site, region, usage_pct, agent_id)
    VALUES (v_now, p_node_id, p_hostname, p_site, p_region, p_cpu_pct, p_agent_id);
  END IF;

  IF p_mem_pct IS NOT NULL THEN
    INSERT INTO memory_usage (time, node_id, hostname, site, region, usage_pct, agent_id)
    VALUES (v_now, p_node_id, p_hostname, p_site, p_region, p_mem_pct, p_agent_id);
  END IF;

  INSERT INTO network_traffic (time, node_id, hostname, site, region, iface, rx_bps, tx_bps, rtt_ms, agent_id)
  VALUES (v_now, p_node_id, p_hostname, p_site, p_region, COALESCE(p_iface, 'default'),
          COALESCE(p_rx_bps, 0), COALESCE(p_tx_bps, 0), p_rtt_ms, p_agent_id);

  FOR d IN SELECT * FROM jsonb_array_elements(COALESCE(p_disk_mounts, '[]'::jsonb))
  LOOP
    INSERT INTO disk_usage (
      time, node_id, hostname, site, region,
      mountpoint, device, fstype, usage_pct, used_bytes, total_bytes
    )
    VALUES (
      v_now, p_node_id, p_hostname, p_site, p_region,
      COALESCE(d->>'mountpoint', '/'),
      d->>'device',
      d->>'fstype',
      (d->>'usage_pct')::NUMERIC,
      (d->>'used_bytes')::BIGINT,
      (d->>'total_bytes')::BIGINT
    );
  END LOOP;
END;
$$;

COMMENT ON FUNCTION noc_ingest_heartbeat_ts IS
  'Dual-write: invocar desde POST /api/noc/heartbeat para poblar hypertables TimescaleDB.';

-- ============================================================================
-- 8. SEED EJEMPLO — reglas de gobernanza lab
-- ============================================================================

INSERT INTO software_blacklist (software_name, match_type, pattern, severity, notes)
SELECT * FROM (VALUES
  ('TeamViewer', 'prefix', 'teamviewer', 'HIGH', 'RMM no autorizado'),
  ('AnyDesk',    'exact',  'anydesk',    'HIGH', 'RMM no autorizado'),
  ('Cobian Reflector', 'prefix', 'cobian', 'CRITICAL', 'Backup no aprobado')
) AS v(software_name, match_type, pattern, severity, notes)
WHERE NOT EXISTS (
  SELECT 1 FROM software_blacklist b
  WHERE lower(b.pattern) = lower(v.pattern) AND b.match_type = v.match_type
);
