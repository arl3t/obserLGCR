-- Tabla de supresiones por dedup_key (faltaba en instalaciones demo del fork).
-- El trigger trg_suppress_on_close (mig 078/079) y los cierres manuales la requieren.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.case_suppressions (
  dedup_key         VARCHAR(128) PRIMARY KEY,
  reason            VARCHAR(32)  NOT NULL,
  severity          VARCHAR(20),
  suppressed_until  TIMESTAMPTZ  NOT NULL,
  suppressed_by     VARCHAR(255),
  original_case_id  UUID,
  original_ioc      VARCHAR(512),
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_suppressions_until
  ON legacyhunt_soc.case_suppressions (suppressed_until DESC);

COMMENT ON TABLE legacyhunt_soc.case_suppressions IS
  'Ventanas de supresión por dedup_key tras cierre/FP. Consultada por DAG y API antes de reabrir casos.';

-- Vista operativa (mig 027) — recrear ahora que la tabla existe.
DROP VIEW IF EXISTS legacyhunt_soc.v_active_suppressions;

CREATE VIEW legacyhunt_soc.v_active_suppressions AS
SELECT
  s.dedup_key,
  s.reason,
  s.severity,
  s.suppressed_until,
  s.suppressed_by,
  s.original_case_id,
  COALESCE(s.original_ioc, c.ioc_value)            AS ioc_value,
  c.ioc_type,
  c.mitre_tactic_id,
  c.mitre_tactic_name,
  s.created_at,
  s.updated_at,
  ROUND(EXTRACT(EPOCH FROM (s.suppressed_until - now())) / 60.0)::int AS minutes_remaining,
  ROUND(EXTRACT(EPOCH FROM (s.suppressed_until - s.created_at)) / 86400.0, 1)::numeric AS window_days
FROM legacyhunt_soc.case_suppressions s
LEFT JOIN incident_cases_pg c
  ON c.id::text = s.original_case_id::text
WHERE s.suppressed_until > now()
ORDER BY s.suppressed_until ASC;
