-- =============================================================================
-- Migration 029 — Índices adicionales para range scans y scheduler de notificaciones
-- =============================================================================
-- Dos índices orientados a dos patrones de consulta que el stack actual no cubre
-- óptimamente:
--
-- 1) BRIN sobre created_at — range scans de ventanas temporales (7d/30d/90d)
--    que hace v_soc_kpis. idx_cases_created_status_severity (mig. 022) ya
--    ayuda, pero es btree completo y crece linealmente con la tabla.
--    BRIN (Block Range INdex) es ~100× más pequeño para series temporales
--    (datos físicamente ordenados por inserción) y permite bitmap scans
--    casi libres sobre ventanas grandes.
--    Coexiste con los btree: el planner elige según selectividad.
--
-- 2) Índice parcial para notifyCriticalCases() — schedulerService.mjs:258-327
--    consulta cada 1 minuto:
--      SELECT ... FROM incident_cases_pg
--      WHERE severity='CRITICAL' AND status='NUEVO'
--        AND slack_notified_at IS NULL
--        AND created_at BETWEEN now()-6h AND now()-60s
--    Sin índice el planner escanea toda la franja no-cerrada. Un parcial
--    con el predicado inmutable (severity+status+slack_notified_at IS NULL)
--    colapsa el set a decenas de filas como máximo en cualquier momento.
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. BRIN index sobre created_at (range scans)
--    pages_per_range default (128) es correcto para 90-365d de datos.
--    Si la tabla supera ~100M filas, considerar pages_per_range=32 para más
--    granularidad.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_created_brin
  ON incident_cases_pg
  USING BRIN (created_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Parcial para scheduler de notificaciones CRITICAL
--    Todos los predicados son inmutables (no usa now()/CURRENT_DATE).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_critical_slack_unnotified
  ON incident_cases_pg (created_at DESC)
  WHERE severity = 'CRITICAL'
    AND status   = 'NUEVO'
    AND slack_notified_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- Refrescar estadísticas para que el planner use los nuevos índices.
-- ─────────────────────────────────────────────────────────────────────────────
ANALYZE incident_cases_pg;
