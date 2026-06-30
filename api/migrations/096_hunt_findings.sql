-- 096_hunt_findings.sql
-- Centro de Inteligencia de Caza de Amenazas Externas — F1a.
-- Tabla núcleo: un "finding" = una instancia de una CLASE de amenaza detectada
-- sobre un par interno↔externo (no un IOC suelto, no un caso). El motor de
-- patrones (services/threatPatternScan.mjs) hace UPSERT por dedup_key; el
-- analista LLM (F2) rellena los campos llm_*; el Panel del Manager la lee.
-- Ver docs/CENTRO-INTELIGENCIA-CAZA-EXTERNA-F1.md

CREATE TABLE IF NOT EXISTS hunt_findings (
  finding_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  pattern_key             varchar(64)  NOT NULL,        -- ot_egress_foreign_cloud | beaconing_cadence | ...
  dedup_key               varchar(160) NOT NULL,        -- estable entre corridas (src|dst|port)
  severity                varchar(16)  NOT NULL DEFAULT 'LOW',
  title                   text         NOT NULL,
  internal_asset          varchar(64),                  -- host interno real (recalculado, no del caso)
  external_entity         varchar(128),                 -- IP/dominio/ASN externo
  evidence                jsonb        NOT NULL DEFAULT '{}'::jsonb,
  event_count             bigint       NOT NULL DEFAULT 0,   -- volumen real del lago
  first_seen              timestamptz,
  last_seen               timestamptz,
  status                  varchar(24)  NOT NULL DEFAULT 'NEW', -- NEW|ANALYZED|TRIAGED|ACTIONED|SUPPRESSED
  -- Capa analista LLM (F2)
  llm_verdict             varchar(24),                  -- benign|suspicious|malicious|inconclusive
  llm_confidence          int,
  llm_narrative           text,
  llm_recommended_action  varchar(32),                  -- open_case|create_rule|suppress_class|monitor|fp
  llm_evidence_cited      jsonb,
  llm_analyzed_at         timestamptz,
  -- Decisión humana (F3)
  operator_disposition    varchar(32),
  operator_ci             varchar(64),
  linked_case_id          varchar(64),
  created_at              timestamptz  NOT NULL DEFAULT now(),
  updated_at              timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT hunt_findings_dedup_uq UNIQUE (dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_hunt_findings_pattern_status ON hunt_findings (pattern_key, status);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_sev_lastseen   ON hunt_findings (severity, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_status_created  ON hunt_findings (status, created_at DESC);
