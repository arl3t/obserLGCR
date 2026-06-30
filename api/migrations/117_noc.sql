-- NOC module: dispositivos, métricas, logs, alertas y acciones remotas.
-- Portado desde lgcrTI (database/migrations/010_noc.sql).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE OR REPLACE FUNCTION noc_update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS noc_devices (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname               VARCHAR(255) NOT NULL UNIQUE,
  ip_address             INET,
  mac_address            VARCHAR(17),
  device_type            VARCHAR(50) NOT NULL DEFAULT 'server',
  site                   VARCHAR(100),
  tags                   TEXT[],
  description            TEXT,
  heartbeat_timeout_secs INTEGER NOT NULL DEFAULT 120,
  cpu_threshold_pct      NUMERIC(5,2) NOT NULL DEFAULT 90,
  mem_threshold_pct      NUMERIC(5,2) NOT NULL DEFAULT 90,
  rtt_threshold_ms       NUMERIC(8,2) NOT NULL DEFAULT 500,
  status                 VARCHAR(20) NOT NULL DEFAULT 'unknown',
  last_seen_at           TIMESTAMPTZ,
  ssh_host               VARCHAR(255),
  ssh_port               INTEGER NOT NULL DEFAULT 22,
  ssh_user               VARCHAR(100),
  agent_version          VARCHAR(50),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_noc_devices_updated_at ON noc_devices;
CREATE TRIGGER trg_noc_devices_updated_at
  BEFORE UPDATE ON noc_devices
  FOR EACH ROW EXECUTE FUNCTION noc_update_updated_at_column();

CREATE TABLE IF NOT EXISTS noc_metrics (
  id          BIGSERIAL PRIMARY KEY,
  device_id   UUID NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  metric_name VARCHAR(50) NOT NULL,
  value       NUMERIC(15,4) NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_noc_metrics_device_metric_time
  ON noc_metrics (device_id, metric_name, recorded_at DESC);

CREATE TABLE IF NOT EXISTS noc_logs (
  id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  ts        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  severity  VARCHAR(10) NOT NULL DEFAULT 'info',
  source    VARCHAR(100),
  message   TEXT,
  raw       JSONB
);

CREATE INDEX IF NOT EXISTS idx_noc_logs_device_ts
  ON noc_logs (device_id, ts DESC);

CREATE TABLE IF NOT EXISTS noc_alerts (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id    UUID NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  alert_type   VARCHAR(50) NOT NULL,
  status       VARCHAR(20) NOT NULL DEFAULT 'open',
  triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at  TIMESTAMPTZ,
  ack_by       VARCHAR(255),
  ack_at       TIMESTAMPTZ,
  notified     BOOLEAN NOT NULL DEFAULT false,
  details      JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_noc_alerts_device_status_time
  ON noc_alerts (device_id, status, triggered_at DESC);

CREATE INDEX IF NOT EXISTS idx_noc_alerts_status_time
  ON noc_alerts (status, triggered_at DESC);

CREATE TABLE IF NOT EXISTS noc_remote_actions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id    UUID NOT NULL REFERENCES noc_devices(id) ON DELETE CASCADE,
  action_type  VARCHAR(50) NOT NULL,
  payload      JSONB NOT NULL DEFAULT '{}',
  status       VARCHAR(20) NOT NULL DEFAULT 'pending',
  output       TEXT,
  requested_by VARCHAR(255),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at   TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_noc_remote_actions_device_time
  ON noc_remote_actions (device_id, requested_at DESC);
