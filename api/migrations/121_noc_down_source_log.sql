-- 121_noc_down_source_log.sql
-- Tipo de log para incidentes generados desde alertas NOC (caída de dispositivo).

INSERT INTO legacyhunt_soc.source_log_catalog
  (source_log, sensor_name, sensor_family, source_category, network_zone, iceberg_table, notes)
VALUES
  ('noc_down', 'NOC Infraestructura', 'syslog', 'other', 'internal', NULL,
   'Dispositivo sin heartbeat — alerta down del módulo NOC. Genera caso en Gestión.')
ON CONFLICT (source_log) DO UPDATE SET
  sensor_name     = EXCLUDED.sensor_name,
  sensor_family   = EXCLUDED.sensor_family,
  source_category = EXCLUDED.source_category,
  network_zone    = EXCLUDED.network_zone,
  notes           = EXCLUDED.notes,
  updated_at      = NOW();
