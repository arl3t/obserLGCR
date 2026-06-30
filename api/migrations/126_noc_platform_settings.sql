-- 126_noc_platform_settings.sql — configuración NOC editable desde UI

CREATE TABLE IF NOT EXISTS noc_platform_settings (
  key         TEXT PRIMARY KEY,
  value       JSONB NOT NULL DEFAULT '{}',
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO noc_platform_settings (key, value)
VALUES (
  'snmp',
  '{"default_community":"public","default_port":161,"default_version":"2c","poll_interval_sec":60,"discovery_communities":[]}'::jsonb
)
ON CONFLICT (key) DO NOTHING;
