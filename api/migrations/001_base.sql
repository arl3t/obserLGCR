-- Tabla operacional de casos (complementa Iceberg para mutaciones rápidas)
CREATE TABLE IF NOT EXISTS incident_cases_pg (
  id              VARCHAR(64)  PRIMARY KEY,
  anchor_dt       DATE         NOT NULL DEFAULT CURRENT_DATE,
  severity        VARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
  status          VARCHAR(30)  NOT NULL DEFAULT 'NUEVO',
  score           INT          NOT NULL DEFAULT 50 CHECK (score BETWEEN 0 AND 100),
  operator_id     VARCHAR(64),
  adopted_at      TIMESTAMPTZ,
  resolved_at     TIMESTAMPTZ,
  is_false_positive BOOLEAN    NOT NULL DEFAULT false,
  classification  VARCHAR(20),
  enrichment_data JSONB        DEFAULT '{}',
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),

  CONSTRAINT chk_status CHECK (status IN (
    'NUEVO','EN_ANALISIS','CONFIRMADO','MONITOREADO','FALSO_POSITIVO','CERRADO'
  )),
  CONSTRAINT chk_severity CHECK (severity IN (
    'CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE'
  ))
);

-- Códigos de adopción forzada (reemplaza Map en memoria de dynamicCodeService.mjs)
CREATE TABLE IF NOT EXISTS adoption_codes (
  incident_id  VARCHAR(64)  PRIMARY KEY,
  code         VARCHAR(9)   NOT NULL,              -- formato XXXX-XXXX
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ  NOT NULL,
  adopted      BOOLEAN      NOT NULL DEFAULT false,
  adopted_at   TIMESTAMPTZ,
  operator_id  VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_adoption_codes_exp
  ON adoption_codes(expires_at) WHERE adopted = false;
