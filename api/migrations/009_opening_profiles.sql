-- =============================================================================
-- 009_opening_profiles.sql
-- Tabla para perfiles de apertura de casos SOC compartidos entre operadores.
-- Los perfiles definen criterios (severidad, score mínimo) para que el sistema
-- valide si un IOC puede convertirse en caso al ser reclamado manualmente.
--
-- Sustituye el localStorage-only de scoringProfiles.ts con persistencia real.
-- =============================================================================

CREATE TABLE IF NOT EXISTS opening_profiles (
  id           TEXT         PRIMARY KEY,
  name         VARCHAR(128) NOT NULL,
  description  TEXT,
  enabled      BOOLEAN      NOT NULL DEFAULT true,
  severities   JSONB        NOT NULL DEFAULT '[]',
  min_score    INT          NOT NULL DEFAULT 50 CHECK (min_score BETWEEN 0 AND 100),
  skip_adopted BOOLEAN      NOT NULL DEFAULT true,
  created_by   TEXT,
  updated_by   TEXT,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Perfiles por defecto — espejo de DEFAULT_PROFILES en scoringProfiles.ts
INSERT INTO opening_profiles
  (id, name, description, enabled, severities, min_score, skip_adopted)
VALUES
  ('critical-auto', 'CRITICAL automático',
   'Abre todos los casos CRITICAL con score ≥ 70',
   true, '["CRITICAL"]', 70, true),
  ('high-urlhaus', 'HIGH con feeds activos',
   'Abre HIGH si está en URLhaus u OpenPhish',
   true, '["HIGH"]', 50, true)
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- Extiende scoring_formula_config (Iceberg) tracking mediante tabla PG liviana.
-- Guarda qué perfil canónico de fórmula está activo para poder recuperarlo
-- rápidamente sin consultar Trino (que puede tardar segundos en frío).
-- =============================================================================

CREATE TABLE IF NOT EXISTS active_formula_profile (
  id           SERIAL       PRIMARY KEY,
  profile_id   TEXT         NOT NULL,   -- id canónico de scoringEngine.mjs
  profile_name TEXT         NOT NULL,
  applied_by   TEXT         NOT NULL DEFAULT 'dashboard',
  thresholds   JSONB        NOT NULL DEFAULT '{}',
  weights      JSONB        NOT NULL DEFAULT '{}',
  applied_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Índice para recuperar el perfil activo (último aplicado)
CREATE INDEX IF NOT EXISTS idx_active_formula_profile_at
  ON active_formula_profile(applied_at DESC);

-- Registro inicial (fórmula por defecto — wazuh-suricata)
INSERT INTO active_formula_profile
  (profile_id, profile_name, applied_by, thresholds, weights)
VALUES (
  'wazuh-suricata',
  'Wazuh + Suricata',
  'system-default',
  '{"critical":75,"high":55,"medium":28,"low":12}',
  '{"wMitre":1.0,"wEvidence":1.0,"wWazuh":1.8,"wContext":2.5,"wTor":1.0,"wMisp":1.0}'
)
ON CONFLICT DO NOTHING;
