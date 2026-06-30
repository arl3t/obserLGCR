-- 023_dedup_key_pg.sql
-- Mueve el lookup de dedup_key desde Iceberg (Trino, full scan) a Postgres
-- (B-tree, sub-ms). Diagnostico: incidents.mjs:926-957 ejecutaba SELECT contra
-- minio_iceberg.hunting.incident_cases por cada POST /api/incidents/open-from-flow,
-- lo que congestionaba el cluster Trino con 100+ casos/min.
--
-- Tras esta migration:
--   * incident_cases_pg gana columna dedup_key (NULLable, hasta 256 chars).
--   * Indice parcial cubre solo casos NO cerrados (~30% del volumen, mas selectivo).
--   * Backfill desde Iceberg para casos abiertos historicos:
--       scripts/023_backfill_dedup_key.mjs (ejecutar UNA vez tras aplicar SQL).
--   * El codigo (incidents.mjs) consulta PG en vez de Trino → -2s en POST.

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Columna dedup_key
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS dedup_key VARCHAR(256);

COMMENT ON COLUMN incident_cases_pg.dedup_key IS
  'Clave de deduplicacion estable (ej: leak|<dom>|<slug>). NULL = caso pre-023 o sin dedup_key explicito. Indexado parcialmente para casos abiertos.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Indice parcial: solo casos abiertos (excluye CERRADO/FALSO_POSITIVO).
--    El check de dedup en incidents.mjs ya filtra por status NOT IN cerrados,
--    asi que no necesitamos indexar los casos viejos resueltos.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_dedup_key_open
  ON incident_cases_pg(dedup_key)
  WHERE dedup_key IS NOT NULL
    AND status NOT IN ('CERRADO','FALSO_POSITIVO');

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Indice complementario sobre ioc_value para casos ABIERTOS.
--    El indice idx_cases_ioc_closed (migration 015) solo cubre cerrados/FP, asi
--    que el segundo dedup check (por ioc_value, incidents.mjs:894-907) tambien
--    iba a Iceberg sin necesidad. Este indice lo redirige a PG.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_ioc_open
  ON incident_cases_pg(ioc_value)
  WHERE ioc_value IS NOT NULL
    AND status NOT IN ('CERRADO','FALSO_POSITIVO');

ANALYZE incident_cases_pg;
