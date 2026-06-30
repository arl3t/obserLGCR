-- =============================================================================
-- 004_nist_escalation.sql
-- Extiende incident_cases_pg con:
--   · Campos NIST SP 800-61: incident_category, functional_impact, etc.
--   · Flujo de escalación: ESCALADO status + campos de escalación
--   · Contexto adicional: asset, red, usuario, evidencias, timeline
-- =============================================================================

-- ── Estado ESCALADO: ampliar el constraint ────────────────────────────────────
ALTER TABLE incident_cases_pg DROP CONSTRAINT IF EXISTS chk_status;
ALTER TABLE incident_cases_pg ADD CONSTRAINT chk_status CHECK (status IN (
  'NUEVO','EN_ANALISIS','CONFIRMADO','MONITOREADO',
  'ESCALADO','FALSO_POSITIVO','CERRADO'
));

-- ── Campos NIST SP 800-61 ─────────────────────────────────────────────────────
-- Phase: Detection and Analysis
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS incident_category    VARCHAR(50)
  CHECK (incident_category IN (
    'UNAUTHORIZED_ACCESS','DENIAL_OF_SERVICE','MALICIOUS_CODE',
    'IMPROPER_USAGE','SCANS_PROBES','INVESTIGATION','OTHER'
  ));

-- Phase: Containment, Eradication, Recovery
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS functional_impact    VARCHAR(30)
  CHECK (functional_impact IN ('NONE','MINIMAL','SIGNIFICANT','SEVERE'));
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS information_impact   VARCHAR(30)
  CHECK (information_impact IN ('NONE','SUSPECTED_BREACH','CONFIRMED_LOSS','CONFIRMED_CHANGE','NOT_APPLICABLE'));
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS recoverability       VARCHAR(30)
  CHECK (recoverability IN ('REGULAR','SUPPLEMENTED','EXTENDED','NOT_RECOVERABLE'));
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS containment_status   VARCHAR(30)
  CHECK (containment_status IN ('NOT_STARTED','IN_PROGRESS','CONTAINED','ERADICATED','RECOVERED'));

-- Phase: Post-Incident Activity
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS root_cause           TEXT;
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS lessons_learned      TEXT;

-- ── Contexto de activo y red ──────────────────────────────────────────────────
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS hostname             VARCHAR(255);
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS asset_id             VARCHAR(128);
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS asset_type           VARCHAR(50)
  CHECK (asset_type IN ('SERVER','WORKSTATION','NETWORK_DEVICE','CLOUD','IOT','UNKNOWN'));
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS source_ip            INET;
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS destination_ip       INET;
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS destination_port     INT CHECK (destination_port BETWEEN 0 AND 65535);
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS affected_user        VARCHAR(255);
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS business_impact      TEXT;

-- ── Evidencias y timeline ──────────────────────────────────────────────────────
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS evidence_links       TEXT[]        DEFAULT '{}';
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS timeline             JSONB         DEFAULT '[]';
  -- Formato de cada entrada en timeline:
  -- {"ts": "2026-01-01T00:00:00Z", "action": "...", "operator": "...", "detail": "..."}

-- ── Escalación ────────────────────────────────────────────────────────────────
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS escalation_level     VARCHAR(20)
  CHECK (escalation_level IN ('TIER1','TIER2','IR','EXECUTIVE','EXTERNAL'));
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS escalated_to         VARCHAR(255);
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS escalated_at         TIMESTAMPTZ;
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS escalation_reason    TEXT;

-- ── Índices adicionales ────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_category  ON incident_cases_pg(incident_category) WHERE incident_category IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cases_escalated ON incident_cases_pg(escalated_at)       WHERE escalated_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cases_status    ON incident_cases_pg(status);
CREATE INDEX IF NOT EXISTS idx_cases_hostname  ON incident_cases_pg(hostname)            WHERE hostname IS NOT NULL;
