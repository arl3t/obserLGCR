-- 095_bulk_close_operations.sql
-- M3 — Reversibilidad del cierre masivo: registro de cada operación (close/drain)
-- para poder reabrir el lote y expirar las supresiones que creó. Sin esto un
-- cierre masivo equivocado deja 200 casos cerrados + 200 supresiones (hasta 365d)
-- sin un "deshacer" atómico (ver incidente case_suppressions poisoning).
CREATE TABLE IF NOT EXISTS legacyhunt_soc.bulk_close_operations (
  op_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind             varchar(20)  NOT NULL,              -- 'close' | 'drain'
  operator_ci      varchar(64)  NOT NULL,
  to_status        varchar(30)  NOT NULL,              -- FALSO_POSITIVO | CERRADO
  classification   varchar(40),
  reason           text,
  criteria         jsonb        NOT NULL DEFAULT '{}'::jsonb,
  -- Por caso cerrado: { id, prevStatus } para poder restaurar el estado previo.
  closed_cases     jsonb        NOT NULL DEFAULT '[]'::jsonb,
  -- dedup_keys de las supresiones creadas por esta operación (para expirarlas).
  suppression_keys text[]       NOT NULL DEFAULT '{}'::text[],
  closed_count     integer      NOT NULL DEFAULT 0,
  created_at       timestamptz  NOT NULL DEFAULT now(),
  undone_at        timestamptz,
  undone_by        varchar(64),
  reopened_count   integer
);

CREATE INDEX IF NOT EXISTS idx_bulk_close_ops_created ON legacyhunt_soc.bulk_close_operations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bulk_close_ops_operator ON legacyhunt_soc.bulk_close_operations (operator_ci, created_at DESC);
