-- Revertir mig 079 → estado de mig 072 (vista) + mig 078 (trigger).

-- ── 1) Vista sin gate de internas y sin columnas extra (= mig 072) ───────────
CREATE OR REPLACE VIEW v_auto_close_candidates AS
  SELECT id,
         severity,
         status,
         lifecycle_stage,
         score,
         created_at,
         ioc_value,
         operator_id,
         dedup_key
    FROM incident_cases_pg
   WHERE severity::text = ANY (ARRAY['LOW'::varchar, 'NEGLIGIBLE'::varchar]::text[])
     AND status::text   = ANY (ARRAY['NUEVO'::varchar, 'EN_ANALISIS'::varchar]::text[])
     AND auto_closed_at IS NULL
     AND created_at >= (now() - '7 days'::interval);

-- ── 2) Trigger sin el skip de internas (= mig 078) ───────────────────────────
CREATE OR REPLACE FUNCTION legacyhunt_soc.trg_suppress_on_close()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  v_reason   VARCHAR(32);
  v_ioc      VARCHAR(512);
BEGIN
  IF NEW.dedup_key IS NULL OR btrim(NEW.dedup_key) = '' THEN
    RETURN NEW;
  END IF;
  IF NEW.status NOT IN ('CERRADO', 'FALSO_POSITIVO') THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NEW;
  END IF;

  IF NEW.status = 'FALSO_POSITIVO' THEN
    v_reason := 'FALSO_POSITIVO';
  ELSIF NEW.auto_closed_at IS NOT NULL THEN
    v_reason := 'AUTO_CLOSED';
  ELSE
    v_reason := 'CERRADO';
  END IF;

  v_ioc := NULLIF(NEW.ioc_value, '');

  INSERT INTO legacyhunt_soc.case_suppressions
      (dedup_key, reason, severity, suppressed_until, suppressed_by, original_case_id, original_ioc)
  VALUES (
      NEW.dedup_key,
      v_reason,
      upper(NEW.severity),
      NOW() + (legacyhunt_soc.suppression_days(v_reason, NEW.severity) || ' days')::interval,
      'trigger-close',
      CASE WHEN NEW.id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           THEN NEW.id::uuid ELSE NULL END,
      v_ioc
  )
  ON CONFLICT (dedup_key) DO UPDATE SET
      reason           = EXCLUDED.reason,
      severity         = COALESCE(EXCLUDED.severity, case_suppressions.severity),
      suppressed_until = CASE
        WHEN case_suppressions.reason = EXCLUDED.reason
          THEN GREATEST(case_suppressions.suppressed_until, EXCLUDED.suppressed_until)
        ELSE EXCLUDED.suppressed_until
      END,
      original_case_id = COALESCE(EXCLUDED.original_case_id, case_suppressions.original_case_id),
      original_ioc     = COALESCE(EXCLUDED.original_ioc, case_suppressions.original_ioc),
      updated_at       = NOW();

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_suppress_on_close ON incident_cases_pg;
CREATE TRIGGER trg_suppress_on_close
  AFTER INSERT OR UPDATE OF status ON incident_cases_pg
  FOR EACH ROW
  EXECUTE FUNCTION legacyhunt_soc.trg_suppress_on_close();
