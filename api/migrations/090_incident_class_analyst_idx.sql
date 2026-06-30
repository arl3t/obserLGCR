-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 090 — índice para ejemplos "trabajados por analista" por clase eCSIRT.
--
-- La tarjeta "Casos similares" se reorientó a mostrar SÓLO casos que un humano
-- cerró (operator_id IS NOT NULL): en clases ruidosas (INFO_GATHERING, 400k
-- auto-cerrados) los ~500 trabajados por analistas son la señal útil ("qué hizo
-- un analista en un caso así"). Sin este índice, filtrar operator_id NOT NULL
-- dentro de la clase obliga a escanear cientos de miles de filas para hallar las
-- pocas con operador.
--
-- Índice parcial: sólo terminales con operador (≈1.5k filas en total) → diminuto.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_cases_class_analyst
  ON incident_cases_pg (incident_class, resolved_at DESC)
  WHERE operator_id IS NOT NULL
    AND status IN ('CERRADO', 'FALSO_POSITIVO');
