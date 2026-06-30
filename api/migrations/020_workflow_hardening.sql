-- =============================================================================
-- 020_workflow_hardening.sql
--
-- Hardening del motor de workflow SOC (sprint de mejoras R1–R9).
-- Idempotente: todas las operaciones son IF NOT EXISTS / CREATE OR REPLACE.
--
-- Cambios:
--   R1. Backfill de `assigned_role` en incident_cases_pg desde soc_operators
--       cuando operator_id está seteado pero assigned_role es NULL.
--       + Trigger BEFORE UPDATE que propaga role_id automáticamente.
--
--   R2. adoption_codes:
--       - used_at / used_by_ci para audit (además del boolean `adopted`)
--       - constraint: no reutilizar un código ya usado o expirado
--
--   R3. Sin cambios de schema (la lógica va en workflowEngine.mjs).
--
--   R4. Consolidación dedup: case_suppressions ya es PG (ver scripts/sql/postgres/
--       04_case_suppressions.sql). Añadimos índice por dedup_key + active_until
--       para acelerar el check en scoringBonus.mjs.
--
--   R5. incident_cases_pg.detected_at (timestamp del evento original).
--       + v_soc_kpis se recrea con MTTD real (detected_at → adopted_at).
--
--   R6. Sin cambios de schema (advisory locks en runtime).
--
--   R7. Sin cambios de schema (validación 4-eyes en transitionCase).
--
--   R8. operator_metrics_daily — tabla de snapshot diario.
--
--   R9. GIN index en enrichment_data JSONB (para queries sobre claves internas
--       como sla_alert_sent_at, scoring_bonus_log, etc.)
-- =============================================================================

-- ─── R1. assigned_role backfill + trigger ──────────────────────────────────────

UPDATE incident_cases_pg c
SET    assigned_role = o.role_id
FROM   soc_operators o
WHERE  c.operator_id = o.id
  AND  c.assigned_role IS NULL;

CREATE OR REPLACE FUNCTION trg_cases_sync_assigned_role() RETURNS TRIGGER AS $$
BEGIN
  -- Cuando operator_id cambia a un valor, popular assigned_role desde
  -- soc_operators.role_id. Si operator_id vuelve a NULL, limpiar también
  -- assigned_role (caso sin owner = sin rol asignado).
  IF NEW.operator_id IS DISTINCT FROM OLD.operator_id THEN
    IF NEW.operator_id IS NOT NULL THEN
      NEW.assigned_role := (
        SELECT role_id FROM soc_operators WHERE id = NEW.operator_id
      );
    ELSE
      NEW.assigned_role := NULL;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cases_sync_assigned_role ON incident_cases_pg;
CREATE TRIGGER trg_cases_sync_assigned_role
  BEFORE UPDATE OF operator_id ON incident_cases_pg
  FOR EACH ROW EXECUTE FUNCTION trg_cases_sync_assigned_role();

-- También aplicar en INSERT (caso creado con operator_id ya asignado)
CREATE OR REPLACE FUNCTION trg_cases_sync_assigned_role_ins() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.operator_id IS NOT NULL AND NEW.assigned_role IS NULL THEN
    NEW.assigned_role := (
      SELECT role_id FROM soc_operators WHERE id = NEW.operator_id
    );
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cases_sync_assigned_role_ins ON incident_cases_pg;
CREATE TRIGGER trg_cases_sync_assigned_role_ins
  BEFORE INSERT ON incident_cases_pg
  FOR EACH ROW EXECUTE FUNCTION trg_cases_sync_assigned_role_ins();

-- ─── R2. adoption_codes: columnas de audit y constraint ────────────────────────

ALTER TABLE adoption_codes
  ADD COLUMN IF NOT EXISTS used_at      TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS used_by_ci   VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_adoption_codes_lookup
  ON adoption_codes(incident_id, code)
  WHERE adopted = false;

-- ─── R4. case_suppressions: índice de rendimiento ──────────────────────────────
-- Solo si la tabla existe (se crea vía scripts/sql/postgres/04_case_suppressions.sql).

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'case_suppressions'
      AND n.nspname = 'public'
      AND c.relkind = 'r'
  ) THEN
    EXECUTE $sql$
      CREATE INDEX IF NOT EXISTS idx_suppressions_dedup_active
        ON case_suppressions(dedup_key, active_until)
        WHERE active_until > now()
    $sql$;
  END IF;
END $$;

-- ─── R5. detected_at para MTTD ─────────────────────────────────────────────────

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS detected_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN incident_cases_pg.detected_at IS
  'Timestamp del evento origen (Wazuh alert, Suricata alert, OPNsense filterlog, etc.) '
  'utilizado como anchor para MTTD (Mean Time To Detect) en v_soc_kpis.';

-- Backfill: para casos existentes sin detected_at, usar created_at como proxy.
UPDATE incident_cases_pg
SET    detected_at = created_at
WHERE  detected_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cases_detected_at
  ON incident_cases_pg(detected_at)
  WHERE detected_at IS NOT NULL;

-- Recrear v_soc_kpis incluyendo MTTD real (detected_at → adopted_at).
DROP VIEW IF EXISTS v_soc_kpis CASCADE;
CREATE VIEW v_soc_kpis AS
SELECT
  -- Volumen
  COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO'))          AS open_cases,
  COUNT(*) FILTER (WHERE status = 'CERRADO')                                  AS closed_cases,
  COUNT(*) FILTER (WHERE status = 'FALSO_POSITIVO')                           AS fp_cases,
  COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND status NOT IN ('CERRADO','FALSO_POSITIVO')) AS critical_open,
  -- MTTD: tiempo desde detected_at (evento real) hasta created_at (apertura del caso)
  ROUND(AVG(EXTRACT(EPOCH FROM (created_at - detected_at))/60)
    FILTER (WHERE detected_at IS NOT NULL AND created_at >= now() - INTERVAL '7 days'), 1) AS mttd_min,
  -- MTTA: tiempo desde creación hasta adopción
  ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at - created_at))/60)
    FILTER (WHERE adopted_at IS NOT NULL AND created_at >= now() - INTERVAL '7 days'), 1) AS mtta_min,
  -- MTTR: tiempo desde creación hasta cierre
  ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/60)
    FILTER (WHERE resolved_at IS NOT NULL AND created_at >= now() - INTERVAL '7 days'), 1) AS mttr_min,
  -- MTTC: tiempo desde adopción hasta cierre (contención efectiva por analista)
  ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at - adopted_at))/60)
    FILTER (WHERE resolved_at IS NOT NULL AND adopted_at IS NOT NULL
            AND created_at >= now() - INTERVAL '7 days'), 1) AS mttc_min,
  -- FPR: tasa de falsos positivos (%)
  ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'FALSO_POSITIVO' AND created_at >= now() - INTERVAL '7 days')
    / NULLIF(COUNT(*) FILTER (WHERE created_at >= now() - INTERVAL '7 days'), 0), 2) AS fp_rate_7d,
  -- Escalación (% de casos que llegan a ESCALADO)
  ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'ESCALADO' AND created_at >= now() - INTERVAL '7 days')
    / NULLIF(COUNT(*) FILTER (WHERE created_at >= now() - INTERVAL '7 days'), 0), 2) AS escalation_rate_7d,
  -- Ventana
  now() AS computed_at
FROM incident_cases_pg;

-- ─── R8. operator_metrics_daily — snapshot diario ─────────────────────────────

CREATE TABLE IF NOT EXISTS operator_metrics_daily (
  snapshot_date     DATE                       NOT NULL,
  operator_id       VARCHAR(64)                NOT NULL,
  cases_adopted     INTEGER                    NOT NULL DEFAULT 0,
  cases_closed      INTEGER                    NOT NULL DEFAULT 0,
  cases_fp          INTEGER                    NOT NULL DEFAULT 0,
  cases_escalated   INTEGER                    NOT NULL DEFAULT 0,
  avg_mtta_min      NUMERIC(10,2),
  avg_mttr_min      NUMERIC(10,2),
  fp_rate_pct       NUMERIC(5,2),
  score_avg         NUMERIC(5,2),
  computed_at       TIMESTAMP WITH TIME ZONE   NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot_date, operator_id)
);

CREATE INDEX IF NOT EXISTS idx_operator_metrics_daily_op
  ON operator_metrics_daily(operator_id, snapshot_date DESC);

COMMENT ON TABLE operator_metrics_daily IS
  'Snapshot diario de métricas por operador. Alimentado por el scheduler SOC '
  '(tarea operatorMetricsRollup, ~00:10 UTC). Retención recomendada: 365 días.';

-- ─── R9. GIN index en enrichment_data ─────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_cases_enrichment_data_gin
  ON incident_cases_pg USING GIN (enrichment_data jsonb_path_ops);
