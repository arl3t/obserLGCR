-- =============================================================================
-- LegacyHunt SOC — índice operativo de casos + auditoría
-- Esquema: legacyhunt_soc (separado del metastore Hive en DB metastore)
-- Ejecuta en initdb solo en volumen nuevo; reaplicar manualmente con:
--   psql -U $POSTGRES_USER -d $POSTGRES_DB -f scripts/sql/postgres/01_incident_cases_index.sql
-- Para instancias ya existentes (volumen no vacío) aplicar la migración:
--   psql -U $POSTGRES_USER -d $POSTGRES_DB -f scripts/sql/postgres/02_migrate_status_v2.sql
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS legacyhunt_soc;

-- Índice rápido: dedup en 15d contra casos abiertos (FOR UPDATE en el DAG)
CREATE TABLE IF NOT EXISTS legacyhunt_soc.incident_case_index (
    case_id           UUID PRIMARY KEY,
    dedup_key         VARCHAR(64) NOT NULL,
    ioc_value         VARCHAR(512) NOT NULL,
    ioc_type          VARCHAR(32),
    source_log        VARCHAR(128),
    mitre_tactic_id   VARCHAR(32),
    source_category   VARCHAR(256),
    severity_text     VARCHAR(32) NOT NULL,
    severity_rank     SMALLINT NOT NULL,
    severity_score    INTEGER NOT NULL,
    confidence_level  VARCHAR(16),
    status            VARCHAR(32) NOT NULL
        CHECK (status IN (
            -- Estados v2 (máquina de estados actual)
            'NUEVO', 'EN_ANALISIS', 'CONFIRMADO', 'MONITOREADO',
            'FALSO_POSITIVO', 'CERRADO',
            -- Estados v1 legacy (backward compat)
            'OPEN', 'IN_PROGRESS', 'UNDER_REVIEW',
            'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'
        )),
    occurrence_count  INTEGER NOT NULL DEFAULT 1,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closure_reason    VARCHAR(256),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE legacyhunt_soc.incident_case_index IS
  'Puntero operativo a incident_cases en Iceberg; dedup_key + estados abiertos + ventana 15d en el job.';

-- Como máximo un caso abierto por dedup_key (nuevo caso tras cierre/FALSE_POSITIVE)
-- Incluye estados abiertos v2 + v1 legacy
CREATE UNIQUE INDEX IF NOT EXISTS uq_incident_open_dedup
    ON legacyhunt_soc.incident_case_index (dedup_key)
    WHERE status IN (
        'NUEVO', 'EN_ANALISIS', 'CONFIRMADO',         -- v2
        'OPEN', 'IN_PROGRESS', 'UNDER_REVIEW'          -- v1 legacy
    );

CREATE INDEX IF NOT EXISTS idx_incident_index_ioc
    ON legacyhunt_soc.incident_case_index (ioc_value);

CREATE INDEX IF NOT EXISTS idx_incident_index_last_seen
    ON legacyhunt_soc.incident_case_index (last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_incident_index_status
    ON legacyhunt_soc.incident_case_index (status);

-- Auditoría append-only
CREATE TABLE IF NOT EXISTS legacyhunt_soc.incident_case_audit (
    id          BIGSERIAL PRIMARY KEY,
    case_id     UUID,
    dedup_key   VARCHAR(64),
    action      VARCHAR(64) NOT NULL,
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incident_audit_case
    ON legacyhunt_soc.incident_case_audit (case_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_incident_audit_dedup
    ON legacyhunt_soc.incident_case_audit (dedup_key, created_at DESC);
