-- =============================================================================
-- 030 — Paridad de soc_operators con la tabla Trino en vía de deprecación
--
-- La tabla Iceberg `minio_iceberg.hunting.soc_operators` tiene dos columnas
-- que PG no tenía: `team` (varchar, libre, típicamente "SOC") y `ci_hash`
-- (varchar, actualmente siempre NULL — legado del flujo previo).
--
-- Fase 1 del plan de unificación (ver PR perf/seguridad de creación de
-- operadores): durante la transición, el endpoint /api/workflow/operators/
-- register escribe en PG y replica a Trino. Para que los campos migren sin
-- pérdida, PG necesita recibirlos.
--
-- Idempotente: ALTER ... IF NOT EXISTS.
-- =============================================================================

ALTER TABLE soc_operators
  ADD COLUMN IF NOT EXISTS team    VARCHAR(64),
  ADD COLUMN IF NOT EXISTS ci_hash VARCHAR(64);

COMMENT ON COLUMN soc_operators.team IS
  'Equipo al que pertenece el operador (legado de la tabla Trino). Default "SOC".';

COMMENT ON COLUMN soc_operators.ci_hash IS
  'Hash de la CI (legado Trino). Actualmente siempre NULL; reservado para PII-hashing futuro.';
