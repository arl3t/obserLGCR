-- =============================================================================
-- 031 — last_status en infragovpy_watchlist
--
-- Añade visibilidad del estado operativo del caso que generó la entrada
-- del feed outbound. Se usa para:
--   - TTL dinámico (ESCALADO 21d, CONFIRMADO 14d, resto 7d).
--   - Ordenamiento UI (ESCALADO > CONFIRMADO > NUEVO > CERRADO).
--   - Columna adicional en el CSV outbound para que consumidores externos
--     puedan filtrar por nivel de confianza.
--
-- Idempotente: ADD COLUMN IF NOT EXISTS.
-- =============================================================================

ALTER TABLE legacyhunt_soc.infragovpy_watchlist
  ADD COLUMN IF NOT EXISTS last_status VARCHAR(32);

COMMENT ON COLUMN legacyhunt_soc.infragovpy_watchlist.last_status IS
  'Estado del último incident_cases_pg que reportó esta IP: NUEVO / EN_ANALISIS / CONFIRMADO / ESCALADO / MONITOREADO / CERRADO. Usado para TTL dinámico y clasificación de confianza del feed outbound.';
