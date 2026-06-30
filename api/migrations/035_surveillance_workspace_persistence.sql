-- =============================================================================
-- 035 — Persistencia del Workspace de Vigilancia Digital (Ola B del rediseño)
--
-- Tres tablas operativas en Postgres (no Iceberg) — el lake del proyecto
-- queda libre para volúmenes grandes; este storage es app-state transaccional
-- de bajo volumen.
--
--   1. surveillance_analyses             — histórico de análisis por dominio
--                                          con snapshot reproducible (#1).
--   2. surveillance_finding_annotations — triaged / false-positive / resolved
--                                          + nota + autor por finding (#3).
--   3. surveillance_audit_events         — log de auditoría con retención
--                                          a 30 días (#9).
--
-- Idempotente: CREATE … IF NOT EXISTS. Reaplicable con:
--   psql -U legacyhunt -d legacyhunt -f migrations/035_surveillance_workspace_persistence.sql
-- =============================================================================

-- ── 1. Histórico de análisis ──────────────────────────────────────────────────
--
-- Snapshot por (dominio, queriedAt). `data_snapshot` guarda el JSON crudo del
-- response de /api/surveillance/domain para reproducir vistas históricas.
-- `findings_summary` es un agregado pre-computado para diff rápido sin tener
-- que re-correr los builders.

CREATE TABLE IF NOT EXISTS surveillance_analyses (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  domain          VARCHAR(253)    NOT NULL,
  queried_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
  operator_ci     VARCHAR(64),
  risk_score      INT             NOT NULL,
  risk_band       VARCHAR(8)      NOT NULL CHECK (risk_band IN ('low', 'medium', 'high')),
  findings_summary JSONB          NOT NULL DEFAULT '{}'::jsonb,
  findings_critical INT           NOT NULL DEFAULT 0,
  findings_high     INT           NOT NULL DEFAULT 0,
  findings_total    INT           NOT NULL DEFAULT 0,
  data_snapshot   JSONB           NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_analyses_score CHECK (risk_score >= 0 AND risk_score <= 100)
);

-- Índice principal — listado por dominio descendiente en tiempo (vista
-- "histórico" en TabEjecutivo, pre-fill de comparación diff).
CREATE INDEX IF NOT EXISTS idx_surveillance_analyses_domain_time
  ON surveillance_analyses(domain, queried_at DESC);

-- BRIN sobre queried_at — barridos cronológicos cross-domain (auditoría,
-- reportes mensuales). BRIN es chico y barato; el set "muestreo de un mes"
-- comprende suficientes filas para amortizar el bloque.
CREATE INDEX IF NOT EXISTS brin_surveillance_analyses_time
  ON surveillance_analyses USING BRIN (queried_at);

COMMENT ON TABLE surveillance_analyses IS
  'Snapshot reproducible de cada análisis de Vigilancia. Sin retención fija — '
  'el cliente puede limpiar manualmente si el JSONB crece demasiado.';


-- ── 2. Anotaciones por finding ────────────────────────────────────────────────
--
-- Estado de triage del analista. UNIQUE (domain, finding_id) — un finding solo
-- tiene una anotación viva; ediciones bumpean updated_at + sobreescriben note.
-- Si el analista quiere mantener historial, se hace en tabla aparte (no se
-- modela hoy — agregar finding_annotation_history si surge la necesidad).

CREATE TABLE IF NOT EXISTS surveillance_finding_annotations (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id      VARCHAR(255)    NOT NULL,
  domain          VARCHAR(253)    NOT NULL,
  state           VARCHAR(16)     NOT NULL CHECK (state IN ('triaged', 'false-positive', 'resolved')),
  note            TEXT,
  operator_ci     VARCHAR(64)     NOT NULL,
  operator_label  VARCHAR(255),
  created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
  CONSTRAINT uq_finding_annotation_per_domain UNIQUE (domain, finding_id)
);

-- Lookup principal: "todas las anotaciones de este dominio" para overlay
-- en FindingsFeed. UNIQUE (domain, finding_id) ya cubre puntual pero no
-- el listado completo.
CREATE INDEX IF NOT EXISTS idx_finding_annotations_domain
  ON surveillance_finding_annotations(domain);

COMMENT ON TABLE surveillance_finding_annotations IS
  'Triage state por finding del Workspace Analista. UNIQUE evita anotaciones '
  'duplicadas — UPDATE bumpea updated_at + sobreescribe state/note.';


-- ── 3. Audit log con retención 30 días ───────────────────────────────────────
--
-- Eventos: search / open-case / add-watchlist / remove-watchlist / enrich /
-- annotate / export. Insert-only desde la API; NO updates — la integridad
-- temporal es parte del modelo de auditoría.
--
-- Retención: 30 días. Cleanup mediante cron en server.mjs (no pg_cron para
-- no agregar dependencia). El cron corre 1×/día y borra > 30d.

CREATE TABLE IF NOT EXISTS surveillance_audit_events (
  id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  action          VARCHAR(32)     NOT NULL,
  actor_ci        VARCHAR(64),
  target_domain   VARCHAR(253),
  target_ref      VARCHAR(255),
  metadata        JSONB           NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
  CONSTRAINT chk_audit_action CHECK (action IN (
    'search',
    'open-case',
    'add-watchlist',
    'remove-watchlist',
    'enrich',
    'annotate',
    'export',
    'notify-sent'
  ))
);

-- Lookup por tiempo (página /vigilancia/auditoria — listado descendente).
CREATE INDEX IF NOT EXISTS idx_audit_events_time
  ON surveillance_audit_events(created_at DESC);

-- Lookup por actor (auditoría individual del analista).
CREATE INDEX IF NOT EXISTS idx_audit_events_actor
  ON surveillance_audit_events(actor_ci, created_at DESC)
  WHERE actor_ci IS NOT NULL;

-- Lookup por dominio (forense de un dominio específico).
CREATE INDEX IF NOT EXISTS idx_audit_events_domain
  ON surveillance_audit_events(target_domain, created_at DESC)
  WHERE target_domain IS NOT NULL;

COMMENT ON TABLE surveillance_audit_events IS
  'Audit log del módulo Vigilancia. Retención 30 días vía cron en server.mjs '
  '(DELETE WHERE created_at < NOW() - INTERVAL ''30 days'').';
