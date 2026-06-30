-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 079 — P3 (audit RFC1918 2026-06-06): preservar señales internas.
--
-- Contexto: las IPs internas RFC1918 (10/8, 172.16-31/12, 192.168/16) son señal
-- de movimiento lateral este-oeste. Hoy se drenan por el pipeline de auto-cierre
-- + supresión que se diseñó para el ruido LOW EXTERNO (414k LOW/90d, ver memoria
-- dedup_churn_diagnosis). Resultado: 873/925 casos internos cerrados se auto-
-- cerraron como LOW sin que ningún analista los viera, y 0 se marcaron FP.
--
-- Cambios (coordinados con incident_cases_sync_daily.py y caseSuppression.mjs):
--
--   1) v_auto_close_candidates: excluye internas RECURRENTES (occurrence_count>1)
--      del auto-cierre de la API. La 1ª ocurrencia se sigue auto-cerrando (acota
--      volumen); la recurrencia queda NUEVA para revisión del analista. Expone
--      además is_internal y occurrence_count para observabilidad/calleres.
--
--   2) trg_suppress_on_close: NO crea/extiende supresión para AUTO_CLOSED de IPs
--      internas. Sin supresión, la recurrencia interna vuelve a entrar (el DAG la
--      reabre y la deja NUEVA). El FP/CERRADO explícito de una interna SÍ suprime
--      (determinación deliberada). Espeja el skip app-level de caseSuppression.mjs.
--
-- is_internal se lee de enrichment_data->'iocEnrichment'->>'isInternal' (lo escribe
-- el DAG en _enrichment_jsonb; path verificado contra datos 2026-06-06).
-- Idempotente: CREATE OR REPLACE.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── 1) Vista de candidatos a auto-cierre ────────────────────────────────────
CREATE OR REPLACE VIEW v_auto_close_candidates AS
  SELECT id,
         severity,
         status,
         lifecycle_stage,
         score,
         created_at,
         ioc_value,
         operator_id,
         dedup_key,
         occurrence_count,
         COALESCE((enrichment_data->'iocEnrichment'->>'isInternal')::boolean, false) AS is_internal
    FROM incident_cases_pg
   WHERE severity::text = ANY (ARRAY['LOW'::varchar, 'NEGLIGIBLE'::varchar]::text[])
     AND status::text   = ANY (ARRAY['NUEVO'::varchar, 'EN_ANALISIS'::varchar]::text[])
     AND auto_closed_at IS NULL
     AND created_at >= (now() - '7 days'::interval)
     -- P3: no auto-cerrar internas recurrentes (movimiento lateral a revisar)
     AND NOT (
       COALESCE((enrichment_data->'iocEnrichment'->>'isInternal')::boolean, false)
       AND COALESCE(occurrence_count, 1) > 1
     );

-- ── 2) Trigger transaccional de supresión al cerrar (espejo mig 078 + skip P3) ──
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

  -- P3 audit 2026-06-06: NO suprimir AUTO_CLOSED de IPs internas RFC1918. Sus
  -- recurrencias deben reaparecer para revisión (movimiento lateral este-oeste).
  -- Espejo de caseSuppression.mjs::upsertSuppressionsBatch.
  IF v_reason = 'AUTO_CLOSED'
     AND COALESCE((NEW.enrichment_data->'iocEnrichment'->>'isInternal')::boolean, false) THEN
    RETURN NEW;
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

-- El trigger ya existe (mig 078); CREATE OR REPLACE FUNCTION basta. Reafirmamos
-- por idempotencia ante instalaciones donde 078 no llegó a crear el trigger.
DROP TRIGGER IF EXISTS trg_suppress_on_close ON incident_cases_pg;
CREATE TRIGGER trg_suppress_on_close
  AFTER INSERT OR UPDATE OF status ON incident_cases_pg
  FOR EACH ROW
  EXECUTE FUNCTION legacyhunt_soc.trg_suppress_on_close();

COMMENT ON FUNCTION legacyhunt_soc.trg_suppress_on_close() IS
  'P3 2026-06-06 (mig 079): igual que mig 078 pero NO suprime AUTO_CLOSED de IPs internas RFC1918 (sus recurrencias deben reaparecer para revisión). Coordinado con v_auto_close_candidates y caseSuppression.mjs.';
