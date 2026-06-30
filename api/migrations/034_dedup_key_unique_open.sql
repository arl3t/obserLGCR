-- 034_dedup_key_unique_open.sql
-- Convierte el lookup-only `idx_cases_dedup_key_open` (migration 023) en una
-- restricción UNIQUE PARCIAL sobre `dedup_key` para casos abiertos. Cierra
-- una race silenciosa: dos POST /api/incidents/open-from-flow simultáneos al
-- mismo IOC ambos pasaban el check de supresión + dedup_ioc en paralelo y
-- terminaban con 2 filas para el mismo dedup_key.
--
-- Postgres garantiza atomicidad con UNIQUE → el segundo INSERT falla con
-- código 23505 (unique_violation) y la API responde 409 con el id del caso
-- existente. Sin transacciones explícitas ni advisory locks.
--
-- Pre-condición verificada (2026-04-25): 0 duplicados de dedup_key entre casos
-- abiertos. La creación CONCURRENTLY no se puede correr en bloque transaccional
-- — la herramienta de migrations corre cada archivo dentro de una sesión que
-- ya está en BEGIN/COMMIT, así que usamos CREATE INDEX normal (toma lock breve
-- pero la tabla son 61K filas → < 100 ms).

-- 1. Drop del índice no-único viejo (migration 023). El reemplazo cubre el
--    mismo predicate y además garantiza unicidad.
DROP INDEX IF EXISTS idx_cases_dedup_key_open;

-- 2. UNIQUE PARCIAL: solo casos abiertos. Casos cerrados/FP pueden compartir
--    dedup_key con casos nuevos abiertos (es exactamente cómo se reabren).
CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_dedup_key_open_unique
  ON incident_cases_pg (dedup_key)
  WHERE dedup_key IS NOT NULL
    AND status NOT IN ('CERRADO','FALSO_POSITIVO');

COMMENT ON INDEX idx_cases_dedup_key_open_unique IS
  'UNIQUE parcial sobre dedup_key para casos abiertos. Reemplaza el índice '
  'lookup-only de migration 023 para cerrar la race en POST /open-from-flow.';

ANALYZE incident_cases_pg;
