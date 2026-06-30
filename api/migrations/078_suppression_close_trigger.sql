-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 078 — P0 (audit flujo 2026-06-06): supresión TRANSACCIONAL al cerrar.
--
-- Problema (dedup churn residual): la supresión post-cierre se hacía a nivel app
-- (autoClassifyController / workflowEngine / open-from-flow) de forma best-effort
-- y FAIL-OPEN. Si el UPDATE de cierre se commiteaba pero el upsert de supresión
-- fallaba (PG presionado, excepción, path que olvidó suprimir), el caso quedaba
-- CERRADO pero NO suprimido → la próxima recurrencia del mismo dedup_key volvía a
-- crear+cerrar el caso = churn (≈414k LOW/90d, ver memoria dedup_churn_diagnosis).
--
-- Fix: trigger AFTER INSERT/UPDATE sobre incident_cases_pg que, cuando un caso
-- pasa a estado terminal (CERRADO / FALSO_POSITIVO) con dedup_key NOT NULL,
-- inserta/extiende la supresión EN LA MISMA TRANSACCIÓN que el cierre. Así la
-- supresión es atómica con el cierre: si el cierre commitea, la supresión existe.
--
-- Semántica idéntica al upsert de la app (caseSuppression.mjs):
--   · reason: FALSO_POSITIVO | AUTO_CLOSED (auto_closed_at NOT NULL) | CERRADO
--   · ventana: legacyhunt_soc.suppression_days(reason, severity)
--   · severity-aware: guarda la severidad del caso; los readers comparan rangos
--     (un LOW suprimido NO tapa un MEDIUM real — la decisión vive en el check).
--   · ON CONFLICT: nunca acorta la ventana ni baja la severidad (idempotente y
--     compatible con que la app también haga su upsert más rico después).
--
-- El upsert app-level se mantiene (audit trail SUPPRESSION_SET, original_ioc/case
-- más ricos); el trigger es la red de seguridad que garantiza atomicidad.
--
-- Idempotente: CREATE OR REPLACE FUNCTION + DROP/CREATE TRIGGER.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION legacyhunt_soc.trg_suppress_on_close()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  v_reason   VARCHAR(32);
  v_ioc      VARCHAR(512);
BEGIN
  -- Solo estados terminales con dedup_key presente.
  IF NEW.dedup_key IS NULL OR btrim(NEW.dedup_key) = '' THEN
    RETURN NEW;
  END IF;
  IF NEW.status NOT IN ('CERRADO', 'FALSO_POSITIVO') THEN
    RETURN NEW;
  END IF;
  -- En UPDATE, actuar solo cuando el estado realmente cambió a terminal (evita
  -- re-extender la ventana en cada UPDATE de un caso ya cerrado).
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

  -- ioc_value puede no existir como columna en instalaciones viejas; protegido
  -- por el COALESCE sobre NEW (la columna se pobló en el backfill P1).
  v_ioc := NULLIF(NEW.ioc_value, '');

  -- incident_cases_pg.id es VARCHAR (no UUID nativo); original_case_id es UUID.
  -- Casteo guardado: solo si NEW.id tiene forma de UUID, sino NULL.
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

COMMENT ON FUNCTION legacyhunt_soc.trg_suppress_on_close() IS
  'P0 2026-06-06: inserta/extiende case_suppressions en la misma transacción que el cierre del caso (red de seguridad transaccional contra el dedup churn). Ver mig 078.';
