-- =============================================================================
-- 044 — Policy de auto-apertura de casos SOC desde el cron de Vigilancia.
--
-- Hasta hoy el cron auto-abre un incident_case_pg cuando `score >= 60`,
-- valor hardcoded. Esto agrega una columna `auto_open_severity` por
-- subscripción para que cada owner decida el umbral:
--
--   'never'    → no abrir caso automáticamente.
--   'medium'   → abrir si score ≥ 60   (comportamiento previo).
--   'high'     → abrir si score ≥ 70.
--   'critical' → abrir si score ≥ 80.
--
-- Backfill: subs preexistentes se setean en 'medium' para preservar la
-- conducta actual. El UI propone 'high' a subs nuevas (más conservador).
--
-- Idempotente.
-- =============================================================================

ALTER TABLE surveillance_watchlist_subs
  ADD COLUMN IF NOT EXISTS auto_open_severity VARCHAR(10)
  NOT NULL DEFAULT 'medium'
  CHECK (auto_open_severity IN ('never', 'medium', 'high', 'critical'));

COMMENT ON COLUMN surveillance_watchlist_subs.auto_open_severity IS
  'Umbral para auto-apertura de incident_case_pg desde el cron de Vigilancia. '
  'Valores: never|medium|high|critical correspondientes a score >=60/70/80. '
  'Default medium = score≥60 (comportamiento histórico). Operador puede pasar '
  'a never para silenciar.';

-- ── Audit log: agregar `case-auto-opened` al CHECK constraint. ───────────────
-- (Si ya está, este DDL es no-op pero tira error; lo envolvemos con DO block.)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_audit_action'
      AND pg_get_constraintdef(oid) LIKE '%case-auto-opened%'
  ) THEN
    ALTER TABLE surveillance_audit_events DROP CONSTRAINT IF EXISTS chk_audit_action;
    ALTER TABLE surveillance_audit_events ADD CONSTRAINT chk_audit_action
      CHECK (action IN (
        'search',
        'open-case',
        'add-watchlist',
        'remove-watchlist',
        'enrich',
        'annotate',
        'export',
        'notify-sent',
        'case-auto-opened'
      ));
  END IF;
END $$;
