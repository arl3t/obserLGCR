CREATE TABLE IF NOT EXISTS scoring_profiles (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            VARCHAR(128) NOT NULL,
  required_sources JSONB        NOT NULL DEFAULT '[]',
  base_score      INT          NOT NULL DEFAULT 50 CHECK (base_score BETWEEN 0 AND 100),
  critical_mult   FLOAT        NOT NULL DEFAULT 1.0 CHECK (critical_mult >= 1.0),
  active          BOOLEAN      NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Perfiles predefinidos
INSERT INTO scoring_profiles (name, required_sources, base_score, critical_mult) VALUES
  ('Wazuh Crítico',   '["wazuh"]',                         75, 1.5),
  ('Wazuh + Suricata','["wazuh","suricata"]',               80, 1.8),
  ('W + S + Logs',    '["wazuh","suricata","syslog"]',      85, 2.0),
  ('Intel Externa',   '["wazuh","threat_intel"]',           90, 2.2)
ON CONFLICT DO NOTHING;
