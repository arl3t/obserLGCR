-- Métricas periódicas de efectividad por operador
CREATE TABLE IF NOT EXISTS operator_metrics (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id     VARCHAR(64)  NOT NULL,
  period_start    TIMESTAMPTZ  NOT NULL,
  period_end      TIMESTAMPTZ  NOT NULL,
  cases_total     INT          NOT NULL DEFAULT 0,
  cases_sla_ok    INT          NOT NULL DEFAULT 0,
  ttd_avg_sec     FLOAT,           -- Time-to-detect promedio
  ttr_avg_sec     FLOAT,           -- Time-to-resolve promedio
  fp_count        INT          NOT NULL DEFAULT 0,
  oes_score       FLOAT,           -- 0.0 a 1.0
  oes_band        VARCHAR(20),     -- ELITE | COMPETENTE | EN_DESARROLLO | CRITICO
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),

  CONSTRAINT chk_oes_score  CHECK (oes_score  IS NULL OR (oes_score  >= 0 AND oes_score  <= 1)),
  CONSTRAINT chk_period     CHECK (period_end > period_start)
);

CREATE INDEX IF NOT EXISTS idx_op_metrics_operator ON operator_metrics(operator_id);
CREATE INDEX IF NOT EXISTS idx_op_metrics_period   ON operator_metrics(period_start DESC);

-- Progreso de acciones de playbook por caso
CREATE TABLE IF NOT EXISTS playbook_progress (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      VARCHAR(64) NOT NULL,
  action_id    VARCHAR(64) NOT NULL,
  phase        VARCHAR(20) NOT NULL
                 CHECK (phase IN ('TRIAGE','CONTAINMENT','INVESTIGATION','RECOVERY','CLOSURE')),
  status       VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                 CHECK (status IN ('PENDING','IN_PROGRESS','DONE','SKIPPED')),
  operator_id  VARCHAR(64),
  started_at   TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  notes        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pb_progress_case ON playbook_progress(case_id);
