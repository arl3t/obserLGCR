-- =============================================================================
-- Migration 024 — Ampliar el check de score de 0–100 a 0–200
-- =============================================================================
-- Contexto: el pipeline de scoring acumula bonuses (geo risk, reincidencia,
-- intel feeds) que pueden empujar el score más allá de 100. La constraint
-- original `score BETWEEN 0 AND 100` rompía el INSERT de adopt para cualquier
-- caso con bonuses altos (ej. CRITICAL con 111).
--
-- Máximo teórico del scoring v4 es ~130. Dejamos 200 para dar headroom
-- a futuras reglas / multiplicadores sin re-migrar.
-- =============================================================================

ALTER TABLE incident_cases_pg
  DROP CONSTRAINT IF EXISTS incident_cases_pg_score_check;

ALTER TABLE incident_cases_pg
  ADD CONSTRAINT incident_cases_pg_score_check
  CHECK (score >= 0 AND score <= 200);
