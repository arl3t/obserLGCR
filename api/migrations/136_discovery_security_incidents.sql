-- Incidentes automáticos por hallazgos de seguridad en discovery nmap.

ALTER TABLE incidents_queue DROP CONSTRAINT IF EXISTS incidents_queue_incident_type_check;
ALTER TABLE incidents_queue ADD CONSTRAINT incidents_queue_incident_type_check
  CHECK (incident_type IN (
    'forbidden_software', 'unapproved_software',
    'keepalive_down', 'high_cpu', 'high_memory', 'high_rtt',
    'unknown_asset', 'undocumented_host',
    'critical_port_exposure', 'cve_detected',
    'custom'
  ));

INSERT INTO legacyhunt_soc.source_log_catalog
  (source_log, sensor_name, sensor_family, source_category, network_zone, iceberg_table, notes)
VALUES
  ('discovery_security', 'Discovery nmap - seguridad', 'nmap', 'network', 'internal', NULL,
   'Hallazgos de seguridad generados por descubrimiento nmap: CVE y puertos críticos expuestos.')
ON CONFLICT (source_log) DO UPDATE SET
  sensor_name     = EXCLUDED.sensor_name,
  sensor_family   = EXCLUDED.sensor_family,
  source_category = EXCLUDED.source_category,
  network_zone    = EXCLUDED.network_zone,
  notes           = EXCLUDED.notes,
  updated_at      = NOW();
