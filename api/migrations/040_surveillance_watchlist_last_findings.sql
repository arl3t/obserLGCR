-- =============================================================================
-- 040 — Columna last_finding_ids para delta-detection del cron.
--
-- Item 7 del plan docs/MEJORA-VIGILANCIA-DETECCION-TEMPRANA.md.
--
-- El cron compara el set actual de findingIds vs el guardado aquí y skip-ea
-- cuando el set actual es subset del previo (= "no apareció nada nuevo desde
-- el último ciclo"). Esto evita alertar ciclo tras ciclo sobre un dominio
-- con findings estables (caso típico: dominio bajo vigilancia con varios
-- IOC MISP de hace meses; sin esto el cron alertaba cada slot).
--
-- Idempotente. Sin backfill — los subs existentes arrancan con array vacío;
-- en el primer ciclo, cualquier finding pasa como "nuevo" y luego ya se compara
-- contra ese set.
-- =============================================================================

ALTER TABLE surveillance_watchlist_subs
  ADD COLUMN IF NOT EXISTS last_finding_ids TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN surveillance_watchlist_subs.last_finding_ids IS
  'Set de finding-IDs detectados en el último ciclo del notifier. Usado para '
  'delta-detection: si el ciclo actual computa el mismo set o un subset, se '
  'skip-ea la notificación con detail="delta: sin nuevos findings".';
