-- Reconocimiento de inventario (ACK) en activos NOC + incidentes por activo desconocido.

ALTER TABLE noc_devices
  ADD COLUMN IF NOT EXISTS inventory_ack       BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS inventory_ack_at    TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS inventory_ack_by      VARCHAR(255),
  ADD COLUMN IF NOT EXISTS inventory_ack_notes   TEXT,
  ADD COLUMN IF NOT EXISTS discovered_via        VARCHAR(32) NOT NULL DEFAULT 'manual';

CREATE INDEX IF NOT EXISTS idx_noc_devices_unacked
  ON noc_devices (created_at ASC)
  WHERE inventory_ack IS FALSE;

-- Activos con agente/heartbeat previo al go-live de ACK se consideran conocidos.
UPDATE noc_devices
   SET inventory_ack = TRUE,
       inventory_ack_at = COALESCE(last_seen_at, created_at, NOW()),
       inventory_ack_by = 'migration',
       inventory_ack_notes = 'Activo con heartbeat previo a política de ACK'
 WHERE inventory_ack IS FALSE
   AND last_seen_at IS NOT NULL
   AND status IN ('online', 'offline', 'degraded');

-- Ampliar tipos de incidente en cola de gobernanza.
ALTER TABLE incidents_queue DROP CONSTRAINT IF EXISTS incidents_queue_incident_type_check;
ALTER TABLE incidents_queue ADD CONSTRAINT incidents_queue_incident_type_check
  CHECK (incident_type IN (
    'forbidden_software', 'unapproved_software',
    'keepalive_down', 'high_cpu', 'high_memory', 'high_rtt',
    'unknown_asset', 'undocumented_host', 'custom'
  ));

INSERT INTO legacyhunt_soc.source_log_catalog
  (source_log, sensor_name, sensor_family, source_category, network_zone, iceberg_table, notes)
VALUES
  ('noc_inventory_governance', 'Gobernanza Inventario NOC', 'manual', 'other', 'internal', NULL,
   'Activos descubiertos sin reconocimiento (ACK) de inventario.')
ON CONFLICT (source_log) DO UPDATE SET
  sensor_name     = EXCLUDED.sensor_name,
  sensor_family   = EXCLUDED.sensor_family,
  source_category = EXCLUDED.source_category,
  network_zone    = EXCLUDED.network_zone,
  notes           = EXCLUDED.notes,
  updated_at      = NOW();
