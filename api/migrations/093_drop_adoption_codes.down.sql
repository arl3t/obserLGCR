-- 093_drop_adoption_codes.down.sql — recrea adoption_codes (esquema original).
CREATE TABLE IF NOT EXISTS adoption_codes (
  incident_id  VARCHAR(64)  NOT NULL PRIMARY KEY,
  code         VARCHAR(9)   NOT NULL,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ  NOT NULL,
  adopted      BOOLEAN      NOT NULL DEFAULT false,
  adopted_at   TIMESTAMPTZ,
  operator_id  VARCHAR(64),
  used_at      TIMESTAMPTZ,
  used_by_ci   VARCHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_adoption_codes_exp    ON adoption_codes (expires_at)        WHERE adopted = false;
CREATE INDEX IF NOT EXISTS idx_adoption_codes_lookup ON adoption_codes (incident_id, code) WHERE adopted = false;
