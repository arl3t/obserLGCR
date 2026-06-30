-- 106_ticket_templates.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F6 del Sistema de Tickets Público — Plantillas de respuesta.
-- Respuestas predefinidas que el analista inserta en el hilo (espejo del patrón
-- case_templates). docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#9).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ticket_templates (
  id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  title       TEXT         NOT NULL,
  body        TEXT         NOT NULL,
  category    VARCHAR(40),                  -- ack | investigacion | info | cierre | otro
  created_by  VARCHAR(64),
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ticket_templates_title ON ticket_templates (title);

-- Seeds iniciales (es). El analista puede editar/borrar/añadir desde la UI.
INSERT INTO ticket_templates (title, body, category, created_by) VALUES
  ('Recibido',
   'Hola, recibimos tu solicitud y ya la estamos revisando. Te contactamos a la brevedad con novedades.',
   'ack', 'migration:106'),
  ('En investigación',
   'Estamos investigando el incidente reportado. Te mantendremos al tanto a medida que avancemos.',
   'investigacion', 'migration:106'),
  ('Necesitamos información',
   'Para poder avanzar necesitamos que nos confirmes lo siguiente:' || chr(10) || '- ' || chr(10) || 'Quedamos a la espera de tu respuesta.',
   'info', 'migration:106'),
  ('Incidente resuelto',
   'El incidente fue resuelto. Si volvés a notar algo inusual, respondé este mismo ticket y lo reabrimos. ¡Gracias!',
   'cierre', 'migration:106')
ON CONFLICT DO NOTHING;
