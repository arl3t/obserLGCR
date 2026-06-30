-- =============================================================================
-- 016 — Añadir sensor_key y network_zone a incident_cases_pg
--
-- sensor_key  : hostname/IP del sensor que generó el IOC (OPNsense, Fortigate,
--               Suricata, Wazuh agent…). Permite filtrar y agrupar incidentes
--               por dispositivo físico de detección.
-- network_zone: zona de red inferida desde source_log (perimeter / endpoint /
--               email / internal). Permite clasificar incidentes por segmento.
--
-- Idempotente: ADD COLUMN IF NOT EXISTS
-- =============================================================================

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS sensor_key   VARCHAR(100),
  ADD COLUMN IF NOT EXISTS network_zone VARCHAR(40);

CREATE INDEX IF NOT EXISTS idx_cases_sensor_key
  ON incident_cases_pg(sensor_key)
  WHERE sensor_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_network_zone
  ON incident_cases_pg(network_zone)
  WHERE network_zone IS NOT NULL;
