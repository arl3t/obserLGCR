-- 062_fix_orphan_escalations.sql
-- Audit 2026-05-26: corrige los 46 casos en status='ESCALADO' que quedaron
-- huérfanos (escalation_level=NULL, operator_id=NULL) por el bug en
-- scheduler.checkSlaBreaches → transitionCase, que sólo escribía `status`
-- y nunca poblaba la metadata de escalación.
--
-- El path está fixeado adelante (mismo commit que agrega esta migración)
-- + se agregó reconcileOrphanEscalations() como guardrail.
--
-- Heurística:
--   - Sólo toca casos con `shift_manager_ci IS NOT NULL` — sin él no
--     sabemos a quién asignar.
--   - Setea escalation_level='AUTO_SLA_BACKFILL' (sentinel para distinguir
--     de auto-escalations futuras 'AUTO_SLA' o manuales 'TIER1'/'TIER2'/...).
--   - Asigna operator_id=shift_manager_ci y marca adopted_at=NOW para que
--     el caso tenga owner.
--   - escalated_at = updated_at (mejor proxy disponible).
--
-- Idempotente: WHERE escalation_level IS NULL deja inmunes los ya recuperados.
--
-- Constraint ampliado para incluir los valores system-only:
--   AUTO_SLA            — runtime auto-escalation (path fixeado del scheduler)
--   AUTO_SLA_BACKFILL   — backfill one-time del histórico (esta migración)
--   AUTO_SLA_RECOVERED  — runtime reconciler (guardrail defensivo del scheduler)

BEGIN;

-- Ampliar CHECK constraint para aceptar los nuevos valores system-only.
ALTER TABLE incident_cases_pg
  DROP CONSTRAINT IF EXISTS incident_cases_pg_escalation_level_check;
ALTER TABLE incident_cases_pg
  ADD CONSTRAINT incident_cases_pg_escalation_level_check
  CHECK (escalation_level IN (
    -- Niveles manuales (UI dropdown):
    'TIER1', 'TIER2', 'IR', 'EXECUTIVE', 'EXTERNAL',
    -- Sistema (no aparecen en UI, sólo en datos):
    'AUTO_SLA', 'AUTO_SLA_BACKFILL', 'AUTO_SLA_RECOVERED'
  ));

UPDATE incident_cases_pg
   SET escalation_level  = 'AUTO_SLA_BACKFILL',
       escalated_to      = shift_manager_ci,
       escalated_at      = COALESCE(escalated_at, updated_at, NOW()),
       escalation_reason = COALESCE(
         escalation_reason,
         'Backfill 2026-05-26: SLA auto-escalation completada retroactivamente'),
       operator_id       = COALESCE(operator_id, shift_manager_ci),
       adopted_at        = COALESCE(adopted_at, NOW()),
       updated_at        = NOW()
 WHERE status = 'ESCALADO'
   AND escalation_level IS NULL
   AND shift_manager_ci IS NOT NULL;

-- Reportar restantes (los que quedaron sin shift_manager_ci no son
-- backfilleables automáticamente — requieren intervención manual del
-- manager actual).
DO $$
DECLARE
  remaining INTEGER;
BEGIN
  SELECT COUNT(*) INTO remaining
    FROM incident_cases_pg
   WHERE status = 'ESCALADO'
     AND escalation_level IS NULL;
  RAISE NOTICE 'orphan ESCALADO sin shift_manager_ci tras backfill: %', remaining;
END
$$;

COMMIT;
