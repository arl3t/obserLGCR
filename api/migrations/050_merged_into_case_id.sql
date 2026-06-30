-- 050_merged_into_case_id.sql
-- Trazabilidad explícita de fusión de casos duplicados.
--
-- Hoy `POST /api/incidents/merge` (routes/incidents.mjs:2226) marca los casos
-- duplicados con `status='CERRADO'` y deposita el texto 'MERGEADO → {canonId}'
-- en la columna `recommended_action` (pgUpsertCase mapea `closureReason` →
-- `recommended_action`; no existe columna `closure_reason` en PG — solo en el
-- SELECT alias de incidents.mjs:882 sobre `auto_closed_reason`).
--
-- La relación duplicado→canónico vive dentro de un string → consultas requieren
-- parsing por regex, la UI no puede mostrar links, y los KPIs de deduplicación
-- no se pueden indexar.
--
-- Esta migration eleva la relación a columna de primera clase:
--   - `merged_into_case_id UUID` (NULL si el caso no fue fusionado)
--   - Índice parcial para casos fusionados (la mayoría son NULL → idx pequeño)
--   - Backfill idempotente desde `recommended_action`
--   - Verificado pre-migration (2026-05-13): 178 filas con 'MERGEADO → X'

-- 1. Columna nueva. NULL-able → no rompe inserts existentes.
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS merged_into_case_id UUID NULL;

-- 2. Índice parcial: solo casos fusionados (mayoría NULL). Cubre el caso de
--    uso típico "dame los duplicados de este canónico" en O(log n).
CREATE INDEX IF NOT EXISTS idx_cases_merged_into
  ON incident_cases_pg (merged_into_case_id)
  WHERE merged_into_case_id IS NOT NULL;

COMMENT ON COLUMN incident_cases_pg.merged_into_case_id IS
  'Si NOT NULL, este caso fue fusionado en el caso canónico indicado. Lo setea '
  'POST /api/incidents/merge. Reemplaza el parseo de closure_reason LIKE '
  'MERGEADO → X que se usaba antes de migration 050.';

-- 3. Backfill idempotente. Extrae el UUID del `recommended_action` con el
--    patrón 'MERGEADO → <uuid>' que escribe routes/incidents.mjs:2297. El
--    regex busca 8+ chars hex/guión y se valida con el formato UUID v4 (36
--    chars). Filas con texto malformado quedan NULL.
UPDATE incident_cases_pg
SET    merged_into_case_id = (
         CASE
           WHEN substring(recommended_action FROM 'MERGEADO\s*→\s*([0-9a-f-]{8,})')
                ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           THEN substring(recommended_action FROM 'MERGEADO\s*→\s*([0-9a-f-]{8,})')::uuid
           ELSE NULL
         END
       )
WHERE  merged_into_case_id IS NULL
  AND  recommended_action ~ 'MERGEADO\s*→\s*[0-9a-f-]{8,}';

ANALYZE incident_cases_pg;
