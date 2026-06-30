-- =============================================================================
-- Migration 011 — Score Decay: índice de soporte + audit constraint
-- =============================================================================
-- La función calcScoreDecay() en scoringBonus.mjs consulta incident_cases_pg
-- filtrando por ioc_value. Sin índice la query hace seq-scan en tablas grandes.
--
-- También registramos 'score_decay' como bonus_type válido en el COMMENT de
-- scoring_bonus_log para documentar el enum esperado (no hay CHECK constraint
-- porque preferimos flexibilidad en bonus_type para nuevas extensiones futuras).
-- =============================================================================

-- ── Índice para lookups de decay por IOC ───────────────────────────────────────
-- Cubre el WHERE ioc_value = $1 AND is_false_positive = false AND status != 'FALSO_POSITIVO'
-- ORDER BY created_at DESC — el índice parcial filtra FP de forma eficiente.

CREATE INDEX IF NOT EXISTS idx_incpg_ioc_decay
  ON incident_cases_pg (ioc_value, created_at DESC)
  WHERE is_false_positive = false AND status != 'FALSO_POSITIVO';

-- ── Comentario de documentación ─────────────────────────────────────────────────
COMMENT ON TABLE scoring_bonus_log IS
  'Auditoría de bonos/penalizaciones aplicados al score de un caso.
   bonus_type esperados: kill_chain_depth | temporal_fresh | fp_penalty |
                         score_decay | geo_risk | asset_criticality';
