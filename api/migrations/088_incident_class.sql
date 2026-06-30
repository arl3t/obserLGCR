-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 088 — clasificación eCSIRT/MISP persistida (taxonomía estándar CSIRT).
--
-- Hasta ahora la clase eCSIRT se derivaba SOLO en lectura (services/ecsirtClassify
-- en mapCaseRow / GET de caso). Eso cubre el chip de la UI pero NO permite filtrar
-- ni reportar por clase en SQL (la cola se sirve paginada desde incident_cases_pg).
--
-- Esta columna materializa la clave eCSIRT (MALICIOUS_CODE, INTRUSION, FRAUD, …)
-- al escribir el caso, derivada determinísticamente de MITRE + tipo de IOC +
-- fuente + enrichment con la MISMA función classifyEcsirt() que usa la lectura.
--   • Escritura: pgUpsertCase (open-from-flow, PATCH, merge) y autoClassifyController
--     (mirror del scoring) la recomputan cuando viaja la identidad del caso.
--   • Backfill in-place de los casos existentes: migrations/088_backfill_incident_class.mjs
--     (reusa classifyEcsirt → cero drift con el chip de la cola).
--
-- nullable (los casos pre-backfill quedan NULL → la lectura sigue derivando la
-- clase en vivo). Idempotente (ADD COLUMN IF NOT EXISTS).
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS incident_class VARCHAR(24);  -- clave eCSIRT.net/ENISA (taxonomía `ecsirt` MISP)

-- Índice para el filtro de la cola (WHERE incident_class = $) y reporting por clase.
-- Parcial sobre casos abiertos: el filtro vive en la cola operativa; los cerrados
-- se consultan por reporting batch (sin presión de latencia).
CREATE INDEX IF NOT EXISTS idx_cases_incident_class
  ON incident_cases_pg (incident_class)
  WHERE status NOT IN ('CERRADO', 'FALSO_POSITIVO');
