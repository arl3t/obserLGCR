-- 120_detection_events.sql
-- Eventos de detección ingeridos por scripts/agentes (obserLGCR demo sin Trino).
-- Los tipos de log se validan contra legacyhunt_soc.source_log_catalog.

CREATE TABLE IF NOT EXISTS detection_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_log    VARCHAR(64) NOT NULL,
  sensor_family VARCHAR(32),
  severity      VARCHAR(16) NOT NULL DEFAULT 'info',
  hostname      VARCHAR(255),
  source        VARCHAR(128),
  message       TEXT NOT NULL,
  raw           JSONB,
  src_ip        INET,
  dst_ip        INET,
  rule_id       VARCHAR(64),
  event_time    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ingested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  agent_id      VARCHAR(128),
  CONSTRAINT chk_detection_severity CHECK (
    severity IN ('debug', 'info', 'warn', 'error', 'critical')
  )
);

CREATE INDEX IF NOT EXISTS idx_detection_events_source_time
  ON detection_events (source_log, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_detection_events_family_time
  ON detection_events (sensor_family, event_time DESC)
  WHERE sensor_family IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_detection_events_ingested
  ON detection_events (ingested_at DESC);

CREATE INDEX IF NOT EXISTS idx_detection_events_severity_time
  ON detection_events (severity, event_time DESC)
  WHERE severity IN ('error', 'critical', 'warn');

COMMENT ON TABLE detection_events IS
  'Logs de seguridad ingeridos vía POST /api/detection/ingest. '
  'source_log debe existir en legacyhunt_soc.source_log_catalog (familias manual excluidas).';
