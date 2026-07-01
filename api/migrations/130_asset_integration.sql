-- Integración de activos: metadatos de descubrimiento en NOC + base para vista unificada.

ALTER TABLE noc_devices
  ADD COLUMN IF NOT EXISTS discovery_meta JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_noc_devices_discovery_meta
  ON noc_devices USING gin (discovery_meta);

COMMENT ON COLUMN noc_devices.discovery_meta IS
  'Puertos/OS/enriquecimiento desde nmap (network discovery o subnet scan). JSON: os_guess, open_ports, last_run_id, updated_at.';
