-- 058_case_viewers.sql
-- C3 audit UX 2026-05-21 — Presencia en tiempo real ("viewed by") en la
-- vista de investigación. Resuelve el rework cuando dos operadores trabajan
-- el mismo caso sin saberlo: avatar stack en el header + aviso al abrir.
--
-- Modelo:
--   - 1 fila por (case_id, operator_id). Upsert en cada heartbeat (cada 30s
--     desde el frontend mientras la pestaña está visible).
--   - last_seen_at se actualiza en cada heartbeat; viewers cuyo last_seen
--     es más viejo que 2 minutos se consideran "ausentes" y se excluyen del
--     listado activo (filtro a nivel query, no requiere DELETE inmediato).
--   - active_tab es informativo para tooltips ("Juan está en Assets").
--
-- Limpieza: un job ligero o el propio endpoint pueden DELETE las filas con
-- last_seen_at < now() - INTERVAL '1 day' para no acumular indefinidamente.
-- A escala SOC (≤50 operadores × ≤100 casos visitados por día) el upsert
-- mantiene la tabla naturalmente acotada incluso sin GC.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.case_viewers (
  case_id        VARCHAR(64)  NOT NULL,
  operator_id    VARCHAR(64)  NOT NULL,
  operator_name  VARCHAR(128),                          -- snapshot del display name
  active_tab     VARCHAR(32),                           -- "summary" | "assets" | "iocs" | …
  last_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  first_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, operator_id)
);

-- Índice para el listado por caso (endpoint GET /api/cases/:id/viewers).
-- Recurrente: 50 ops × 30s heartbeat = ~1.7 inserts/s; el listado se sirve
-- desde aquí en sub-ms.
CREATE INDEX IF NOT EXISTS idx_case_viewers_case_last_seen
  ON legacyhunt_soc.case_viewers (case_id, last_seen_at DESC);

-- Índice para limpieza eventual (DELETE viewers >24h) y para queries de
-- "qué casos miró X operador hoy" (auditoría futura).
CREATE INDEX IF NOT EXISTS idx_case_viewers_operator_last_seen
  ON legacyhunt_soc.case_viewers (operator_id, last_seen_at DESC);
