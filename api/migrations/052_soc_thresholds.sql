-- 052_soc_thresholds.sql
-- R15 (audit 2026-05-13, P3): umbrales R11 mutables en runtime.
--
-- R11 (P2) externalizó los umbrales a env vars (SOC_AUTO_ESCALATE_SCORE,
-- SOC_SEVERITY_{CRITICAL,HIGH,MEDIUM}_MIN) consumidos como `config.soc*` en:
--   - services/workflowEngine.shouldAutoEscalate (escalación automática)
--   - routes/incidents.mjs ~4202 (bucketing severity en leaks)
--
-- Limitación: ajustar un umbral requería editar .env del contenedor + restart
-- del API. Sin path para que un manager los tunee desde el UI. Esta migration
-- crea la tabla `soc_thresholds` (single-row) que el servicio
-- `services/socThresholds.mjs` cachea y refresca cada 30s; el endpoint
-- `PUT /api/incidents/thresholds` (manager+) actualiza el row y bumpea la
-- versión para invalidar caches del worker.
--
-- Audit completo (quién/cuándo/qué cambió) en `soc_thresholds_audit` —
-- consultable desde el mismo endpoint para mostrar last_changed en la UI.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.soc_thresholds (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  auto_escalate_score   INT NOT NULL DEFAULT 70 CHECK (auto_escalate_score   BETWEEN 1 AND 200),
  severity_critical_min INT NOT NULL DEFAULT 80 CHECK (severity_critical_min BETWEEN 1 AND 200),
  severity_high_min     INT NOT NULL DEFAULT 60 CHECK (severity_high_min     BETWEEN 1 AND 200),
  severity_medium_min   INT NOT NULL DEFAULT 35 CHECK (severity_medium_min   BETWEEN 1 AND 200),
  updated_by  TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Orden estricto: critical > high > medium. Si alguien intenta colapsar
  -- dos buckets, el CHECK rechaza el UPDATE → 23514 → handler devuelve 400.
  CONSTRAINT chk_threshold_order CHECK (
    severity_critical_min > severity_high_min AND
    severity_high_min     > severity_medium_min
  )
);

-- Seed la única fila con defaults históricos (coinciden con los defaults env).
-- Si ya existía un override por env, NO se migra automáticamente — el manager
-- puede re-aplicar el ajuste desde el UI cuando quiera.
INSERT INTO legacyhunt_soc.soc_thresholds (id, updated_by)
  VALUES (1, 'migration:052')
  ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE legacyhunt_soc.soc_thresholds IS
  'Umbrales de scoring (escalación + buckets de severidad) mutables en runtime. '
  'Single-row (id=1). Cacheado por services/socThresholds.mjs (TTL 30s). '
  'R15 audit 2026-05-13 — reemplaza env vars SOC_* para edición sin restart.';

-- Audit trail: cada PUT inserta una fila con before/after en JSONB. Útil
-- para responder "¿quién subió el CRITICAL a 85 ayer?" sin grep de logs.
CREATE TABLE IF NOT EXISTS legacyhunt_soc.soc_thresholds_audit (
  id          BIGSERIAL    PRIMARY KEY,
  changed_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  changed_by  TEXT         NOT NULL,
  before      JSONB        NOT NULL,
  after       JSONB        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_soc_thresholds_audit_recent
  ON legacyhunt_soc.soc_thresholds_audit (changed_at DESC);

COMMENT ON TABLE legacyhunt_soc.soc_thresholds_audit IS
  'Historial de cambios a soc_thresholds. Inserción manual desde el handler '
  'PUT /api/incidents/thresholds. before/after = snapshot completo del row.';
