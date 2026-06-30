-- =============================================================================
-- Migration 025 — InfraGOVPY watchlist con ventana deslizante de 7 días
-- =============================================================================
-- Tabla única que unifica la lista outbound automática (derivada de
-- incident_cases_pg cada 10 min) con los IOCs de inclusión manual. Cada IP
-- permanece en la lista por 7 días tras su último reporte; si re-aparece, su
-- expiración se reinicia a now() + 7 días y `report_count` se incrementa
-- (penalización efectiva).
--
-- Reemplaza la consulta Trino `lh.infragovpy.malicious_24h` (impactada por
-- metadata bloat en hunting.incident_cases) como fuente de verdad.
--
-- Reglas:
--   · Autoritativa para /api/intel/infragovpy/*
--   · Filtrado default: expires_at > NOW() (no purga física; conserva historial)
--   · `origin='manual'` migra desde legacyhunt_soc.infragovpy_manual_include
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS legacyhunt_soc;

CREATE TABLE IF NOT EXISTS legacyhunt_soc.infragovpy_watchlist (
  ip                       VARCHAR(64)  PRIMARY KEY,
  first_seen               TIMESTAMPTZ  NOT NULL DEFAULT now(),
  last_seen                TIMESTAMPTZ  NOT NULL DEFAULT now(),
  expires_at               TIMESTAMPTZ  NOT NULL,
  report_count             INTEGER      NOT NULL DEFAULT 1 CHECK (report_count >= 1),
  first_score              INTEGER      NOT NULL DEFAULT 0,
  last_score               INTEGER      NOT NULL DEFAULT 0,
  max_score                INTEGER      NOT NULL DEFAULT 0,
  last_severity            VARCHAR(16),
  last_source_log          VARCHAR(128),
  last_mitre_tactic_id     VARCHAR(32),
  last_mitre_tactic_name   VARCHAR(128),
  last_mitre_technique_id  VARCHAR(32),
  last_case_id             VARCHAR(64),
  origin                   VARCHAR(16)  NOT NULL DEFAULT 'auto'
                           CHECK (origin IN ('auto', 'manual')),
  added_by                 VARCHAR(64),
  reason                   TEXT,
  updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_infragovpy_wl_expires_at
  ON legacyhunt_soc.infragovpy_watchlist (expires_at);

CREATE INDEX IF NOT EXISTS idx_infragovpy_wl_last_seen
  ON legacyhunt_soc.infragovpy_watchlist (last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_infragovpy_wl_origin
  ON legacyhunt_soc.infragovpy_watchlist (origin);

CREATE INDEX IF NOT EXISTS idx_infragovpy_wl_active
  ON legacyhunt_soc.infragovpy_watchlist (expires_at)
  WHERE expires_at > now();

-- ── Migración de legacyhunt_soc.infragovpy_manual_include (origin='manual') ─
-- Idempotente: ON CONFLICT no sobreescribe filas ya presentes en watchlist.
INSERT INTO legacyhunt_soc.infragovpy_watchlist (
  ip, first_seen, last_seen, expires_at,
  report_count, first_score, last_score, max_score,
  last_severity, origin, added_by, reason
)
SELECT
  ioc_value,
  added_at,
  added_at,
  expires_at,
  1, 100, 100, 100,
  'MANUAL',
  'manual',
  added_by,
  reason
FROM legacyhunt_soc.infragovpy_manual_include
WHERE expires_at > NOW()
ON CONFLICT (ip) DO NOTHING;
