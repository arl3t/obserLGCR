-- 091_case_number.sql
-- Número de caso corto y legible (INC-000123) separado de la PK técnica (UUID).
--
-- Motivo: el id del caso (UUID 36-char / hex 32-char) es largo e incómodo de
-- leer y comunicar. NO se puede migrar la PK a numérico (espacio de 6 dígitos
-- se agota: ~447k casos y ~150k/mes; rompería FKs/uuid, Iceberg, dedup). En su
-- lugar añadimos un identificador secuencial corto SOLO para los casos que un
-- humano referencia (no-LOW o adoptados): ~3.5k/mes → 6 dígitos duran décadas.
--
-- El id UUID sigue siendo la PK (joins, FKs, lakehouse Iceberg, dedup intactos).
-- La asignación se hace por TRIGGER para cubrir todos los paths de creación
-- (API manual, autoClassify hex, y el DAG de Airflow en Python) sin tocarlos.

-- 1) Secuencia del número de caso.
CREATE SEQUENCE IF NOT EXISTS incident_case_number_seq AS BIGINT START 1;

-- 2) Columna (NULL para casos LOW/NEGLIGIBLE no adoptados — no consumen número).
ALTER TABLE incident_cases_pg ADD COLUMN IF NOT EXISTS case_number BIGINT;

-- 3) Unicidad (parcial: solo cuando hay número).
CREATE UNIQUE INDEX IF NOT EXISTS uq_incident_cases_case_number
  ON incident_cases_pg (case_number) WHERE case_number IS NOT NULL;
-- Índice para búsqueda/orden por número.
CREATE INDEX IF NOT EXISTS idx_incident_cases_case_number
  ON incident_cases_pg (case_number DESC NULLS LAST);

-- 4) Backfill cronológico de los casos "humanos" históricos (no-LOW o adoptados),
--    ordenados por created_at para que el número refleje el orden temporal.
--    Se ejecuta ANTES de crear el trigger → no dispara doble asignación.
WITH ranked AS (
  SELECT id, row_number() OVER (ORDER BY created_at, id) AS rn
    FROM incident_cases_pg
   WHERE case_number IS NULL
     AND (severity NOT IN ('LOW','NEGLIGIBLE') OR operator_id IS NOT NULL)
)
UPDATE incident_cases_pg c
   SET case_number = r.rn
  FROM ranked r
 WHERE c.id = r.id;

-- 5) Avanzar la secuencia más allá del máximo backfilleado.
SELECT setval(
  'incident_case_number_seq',
  COALESCE((SELECT MAX(case_number) FROM incident_cases_pg), 0) + 1,
  false
);

-- 6) Trigger: asigna número la primera vez que un caso "importa" (no-LOW o
--    adoptado) y aún no tiene número. Cubre INSERT (alta directa no-LOW) y
--    UPDATE (un LOW que se escala a MEDIUM/HIGH o se adopta).
CREATE OR REPLACE FUNCTION assign_case_number() RETURNS trigger AS $$
BEGIN
  IF NEW.case_number IS NULL
     AND (NEW.severity NOT IN ('LOW','NEGLIGIBLE') OR NEW.operator_id IS NOT NULL)
  THEN
    NEW.case_number := nextval('incident_case_number_seq');
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assign_case_number ON incident_cases_pg;
CREATE TRIGGER trg_assign_case_number
  BEFORE INSERT OR UPDATE ON incident_cases_pg
  FOR EACH ROW EXECUTE FUNCTION assign_case_number();
