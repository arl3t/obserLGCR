-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 084 — P1 #7 (backlog GESTION-OPTIMIZACION-2026-06-07):
-- auto-asignación INMEDIATA para CRITICAL.
--
-- Antes: v_timeout_cases usaba un umbral fijo de 30 min para TODAS las severidades
-- → un CRITICAL sin adoptar esperaba hasta 30 min antes de auto-asignarse, lo que
-- infla el MTTA de los casos más urgentes.
--
-- Ahora: umbral por severidad —
--   · CRITICAL → 2 min  (gracia mínima para que un analista activo lo adopte solo;
--                        el tick de auto-assign corre cada 5 min, así que en la
--                        práctica un CRITICAL queda asignado en ≤5-7 min).
--   · HIGH     → 10 min
--   · resto    → 30 min  (comportamiento previo)
--
-- Resto de la lógica idéntica (NUEVO/EN_ANALISIS, sin adoptar, sin SM asignado,
-- excluye LOW/NEGLIGIBLE, ventana 7d). Idempotente (CREATE OR REPLACE VIEW).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE VIEW v_timeout_cases AS
SELECT id,
       severity,
       status,
       score,
       created_at,
       ioc_value,
       mitre_tactic_name,
       round(EXTRACT(epoch FROM now() - created_at) / 60::numeric) AS minutes_unadopted
  FROM incident_cases_pg c
 WHERE (status::text = ANY (ARRAY['NUEVO','EN_ANALISIS']::text[]))
   AND adopted_at IS NULL
   AND shift_manager_assigned_at IS NULL
   AND (severity::text <> ALL (ARRAY['LOW','NEGLIGIBLE']::text[]))
   AND created_at >= (now() - '7 days'::interval)
   AND (EXTRACT(epoch FROM now() - created_at) / 60::numeric) >=
       (CASE c.severity
          WHEN 'CRITICAL' THEN 2
          WHEN 'HIGH'     THEN 10
          ELSE 30
        END)::numeric;
