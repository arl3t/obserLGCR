-- 054_sla_config.sql
-- M5 (audit Gestión de Incidentes 2026-05-13, P4): SLA mutable en runtime.
--
-- Antes vivía duplicado en 3 fuentes inconsistentes:
--   · services/casePlaybookService.mjs SLA_MIN = {15, 60, 240, 1440, 4320} min
--   · routes/incidents.mjs SLA_SEC      = {900, 3600, 14400, 86400, 259200} s
--   · services/schedulerService.mjs CASE WHEN CRITICAL THEN 60 ... = 60/240/480 min
--   · routes/incidents.mjs query /me INTERVAL '15 minutes' / '1 hour' / ...
--   · server.mjs SLA_SEC = {900, 3600, 14400} (sin LOW/NEGLIGIBLE)
--
-- Esta migración crea la tabla single-row que services/slaConfig.mjs cachea
-- (TTL 30s) y propaga a todos los call sites. Audit completo en sla_config_audit.
--
-- Decisión 2026-05-13: defaults se alinean a casePlaybook (15/60/240/1440/4320
-- min). El scheduler — que hoy usa 60/240/480 — pasa a respetar el mismo
-- contrato; si genera ruido de notificaciones, el manager sube los valores
-- desde el endpoint PUT /api/incidents/sla.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.sla_config (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  sla_critical_sec   INT NOT NULL DEFAULT 900     CHECK (sla_critical_sec   BETWEEN 60 AND 31536000),
  sla_high_sec       INT NOT NULL DEFAULT 3600    CHECK (sla_high_sec       BETWEEN 60 AND 31536000),
  sla_medium_sec     INT NOT NULL DEFAULT 14400   CHECK (sla_medium_sec     BETWEEN 60 AND 31536000),
  sla_low_sec        INT NOT NULL DEFAULT 86400   CHECK (sla_low_sec        BETWEEN 60 AND 31536000),
  sla_negligible_sec INT NOT NULL DEFAULT 259200  CHECK (sla_negligible_sec BETWEEN 60 AND 31536000),
  updated_by  TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Orden estricto ascendente: critical < high < medium < low < negligible.
  -- Sin esto un cambio mal hecho podría darle 5h al CRITICAL y 30s al MEDIUM.
  CONSTRAINT chk_sla_order CHECK (
    sla_critical_sec < sla_high_sec   AND
    sla_high_sec     < sla_medium_sec AND
    sla_medium_sec   < sla_low_sec    AND
    sla_low_sec      < sla_negligible_sec
  )
);

-- Seed single row con defaults históricos (15/60/240/1440/4320 min).
INSERT INTO legacyhunt_soc.sla_config (id, updated_by)
  VALUES (1, 'migration:054')
  ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE legacyhunt_soc.sla_config IS
  'SLA por severidad (segundos) mutable en runtime. Single-row (id=1). '
  'Cacheado por services/slaConfig.mjs (TTL 30s). M5 audit 2026-05-13 — '
  'reemplaza constantes hardcoded en casePlaybook/incidents/scheduler.';

-- Audit trail: cada PUT inserta una fila con before/after en JSONB.
CREATE TABLE IF NOT EXISTS legacyhunt_soc.sla_config_audit (
  id          BIGSERIAL    PRIMARY KEY,
  changed_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  changed_by  TEXT         NOT NULL,
  before      JSONB        NOT NULL,
  after       JSONB        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sla_config_audit_recent
  ON legacyhunt_soc.sla_config_audit (changed_at DESC);

COMMENT ON TABLE legacyhunt_soc.sla_config_audit IS
  'Historial de cambios a sla_config. Inserción manual desde el handler '
  'PUT /api/incidents/sla. before/after = snapshot completo del row.';
