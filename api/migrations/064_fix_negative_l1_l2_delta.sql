-- =============================================================================
-- Migration 064 — Backfill: casos con escalated_at < adopted_at
-- =============================================================================
-- Audit 2026-05-27: l1_l2_esc_min en soc_kpis_window dio -117.9 min sobre
-- 4 muestras CRITICAL/HIGH. Causa: el path de transferencia en
-- routes/incidents.mjs:3806 hacía `adopted_at = $3` sin COALESCE, sobreescribiendo
-- el adopted_at original cuando el caso era transferido a otro operador después
-- de la auto-escalación SLA. Resultado: adopted_at posterior a escalated_at.
--
-- Fix en código: routes/incidents.mjs ahora usa COALESCE(adopted_at, $3) en
-- transferencias — el adopted_at queda inmutable después del primer set.
--
-- Backfill: para casos con escalated_at < adopted_at, restaurar
-- adopted_at = escalated_at. Es la interpretación correcta: cuando el caso
-- fue auto-escalado, escalated_at y adopted_at fueron seteados simultáneamente
-- por el scheduler (línea 303 + 306). La transferencia posterior corrompió
-- adopted_at. escalated_at es el timestamp confiable.
-- =============================================================================

UPDATE incident_cases_pg
   SET adopted_at = escalated_at,
       updated_at = now()
 WHERE escalated_at IS NOT NULL
   AND adopted_at  IS NOT NULL
   AND escalated_at < adopted_at;
