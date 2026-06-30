-- =============================================================================
-- 038 — Slot-aligned analysis para watchlist de Vigilancia Digital
--
-- Hasta 037 el cron usaba `last_notified_at` para decidir qué subs estaban
-- "due", lo que mezclaba dos eventos distintos:
--   (a) cuándo corrió el último análisis (debería seguir el countdown del UI:
--       addedAt + N×interval)
--   (b) cuándo se envió la última notificación Slack (solo en casos urgentes)
--
-- Como `last_notified_at` se bumpeaba a now() en cada ciclo (incluso cuando
-- el sub se saltaba por no-urgente), la cadencia del cron se desfasaba del
-- countdown que muestra el frontend (`Próximo análisis en …`).
--
-- Este split agrega `last_analyzed_at` para que el cron alinee el análisis
-- al slot exacto (`addedAt + N×interval`). `last_notified_at` queda solo
-- como dedup de envíos Slack.
--
-- Backfill: copiamos `last_notified_at` para no re-disparar análisis viejos
-- en el primer tick post-migration. Subs nuevas arrancan con NULL.
--
-- Idempotente: ADD COLUMN IF NOT EXISTS / index IF NOT EXISTS.
-- =============================================================================

ALTER TABLE surveillance_watchlist_subs
  ADD COLUMN IF NOT EXISTS last_analyzed_at TIMESTAMPTZ;

UPDATE surveillance_watchlist_subs
   SET last_analyzed_at = last_notified_at
 WHERE last_analyzed_at IS NULL
   AND last_notified_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_watchlist_subs_analysis_freq
  ON surveillance_watchlist_subs(frequency, last_analyzed_at NULLS FIRST);

COMMENT ON COLUMN surveillance_watchlist_subs.last_analyzed_at IS
  'Timestamp del último slot procesado por el cron. Se bumpea al timestamp '
  'del slot (addedAt + N×interval), no a now(), para que la cadencia coincida '
  'exactamente con el countdown del UI.';
