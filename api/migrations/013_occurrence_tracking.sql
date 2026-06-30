-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 013 — Occurrence tracking en incident_cases_pg
--
-- Añade dos columnas para rastrear re-ocurrencias del mismo IOC sin abrir
-- un caso duplicado:
--
--   occurrence_count  — cuántas veces se detectó el IOC mientras el caso estaba abierto
--   last_seen         — timestamp de la última re-ocurrencia registrada
--
-- Estas columnas son actualizadas por el endpoint POST /api/incidents/:id/add-occurrence
-- cuando el operador elige "Añadir como re-ocurrencia" en el modal 409.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS occurrence_count INT         NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS last_seen        TIMESTAMPTZ;

-- Índice para consultas de re-ocurrencias recientes
CREATE INDEX IF NOT EXISTS idx_cases_last_seen
  ON incident_cases_pg(last_seen DESC)
  WHERE last_seen IS NOT NULL;
