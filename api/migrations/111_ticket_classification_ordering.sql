-- 111_ticket_classification_ordering.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Bloque "ordenar y clasificar tickets" (20 mejoras).
-- docs/PROPUESTA-TICKETING-PUBLICO.md §§26,27,30 + roadmap de clasificación.
--
-- Extiende el núcleo (mig 100/105) con taxonomía, orden/priorización y workflow:
--   · Clasificación: ticket_type, technical_severity (≠ priority), service_id,
--     tags[], sentiment + sugerencia de IA (ai_suggested), merge de duplicados.
--   · Orden: pinned, snoozed_until (posponer), score de cola (calculado en API).
--   · Workflow: watchers internos, cc del cliente, vistas guardadas, prefs de
--     orden por usuario, reglas de negocio configurables.
--
-- Todo idempotente (IF NOT EXISTS); el plano comunicacional sigue separado del
-- operacional (incident_cases_pg). NO se auto-aplica (ver memoria pg_migrations).
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Columnas de clasificación / orden sobre tickets ──────────────────────────
ALTER TABLE tickets
  -- (#1) Tipo de ticket → auto-ruteo de cola por tipo (ticketAssignment).
  ADD COLUMN IF NOT EXISTS ticket_type VARCHAR(20) NOT NULL DEFAULT 'CONSULTA'
    CHECK (ticket_type IN ('INCIDENTE','CONSULTA','CAMBIO','REPORTE_FP','ACEPTACION_RIESGO')),
  -- (#4) Severidad TÉCNICA (impacto real), separada de la prioridad del cliente
  -- (percepción). NULL = sin evaluar todavía.
  ADD COLUMN IF NOT EXISTS technical_severity VARCHAR(10)
    CHECK (technical_severity IS NULL OR technical_severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  -- (#5) Servicio/producto afectado (catálogo ticket_services). FK lógica.
  ADD COLUMN IF NOT EXISTS service_id UUID,
  -- (#2) Etiquetas libres + sugeridas.
  ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}',
  -- (#7) Sentimiento detectado del texto del cliente (señal para subir prioridad).
  ADD COLUMN IF NOT EXISTS sentiment VARCHAR(12)
    CHECK (sentiment IS NULL OR sentiment IN ('POSITIVO','NEUTRAL','FRUSTRADO','ENOJADO')),
  -- (#3/#7) Última sugerencia de la IA (categoría/prioridad/sentimiento/confianza),
  -- gate humano: es sugerencia, NO se aplica sola.
  ADD COLUMN IF NOT EXISTS ai_suggested JSONB,
  -- (#14) Fijar arriba de la cola.
  ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT false,
  -- (#18) Posponer: oculto de la cola activa hasta esta fecha.
  ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ,
  -- (#6) Merge de duplicados: el ticket absorbido apunta al canónico y se cierra.
  ADD COLUMN IF NOT EXISTS merged_into UUID REFERENCES tickets(id) ON DELETE SET NULL,
  -- (#20) CC múltiples del cliente (emails extra que reciben las notificaciones).
  ADD COLUMN IF NOT EXISTS cc_contacts JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Índices para los filtros/orden nuevos (parciales y baratos).
CREATE INDEX IF NOT EXISTS idx_tickets_type      ON tickets (ticket_type);
CREATE INDEX IF NOT EXISTS idx_tickets_service   ON tickets (service_id) WHERE service_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tickets_tags      ON tickets USING gin (tags);
CREATE INDEX IF NOT EXISTS idx_tickets_pinned    ON tickets (pinned) WHERE pinned = true;
CREATE INDEX IF NOT EXISTS idx_tickets_snoozed   ON tickets (snoozed_until) WHERE snoozed_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tickets_merged    ON tickets (merged_into) WHERE merged_into IS NOT NULL;

-- ── (#5) Catálogo de servicios / productos ───────────────────────────────────
CREATE TABLE IF NOT EXISTS ticket_services (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT        NOT NULL,
  slug        TEXT        NOT NULL UNIQUE,
  description TEXT,
  color       VARCHAR(16),
  active      BOOLEAN     NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ticket_services (name, slug, description) VALUES
  ('SOC / Detección',       'soc',        'Monitoreo, detección y respuesta a incidentes'),
  ('Firewall / Perímetro',  'firewall',   'FortiGate, VPN, perímetro de red'),
  ('Endpoint / EDR',        'endpoint',   'Wazuh, antivirus, hosts'),
  ('Correo / Anti-phishing','correo',     'Filtrado de correo, phishing'),
  ('Infraestructura',       'infra',      'Servidores, red, conectividad'),
  ('Otro',                  'otro',       'Sin servicio específico')
ON CONFLICT (slug) DO NOTHING;

-- ── (#20) Watchers internos (operadores que siguen el ticket) ────────────────
CREATE TABLE IF NOT EXISTS ticket_watchers (
  ticket_id    UUID        NOT NULL REFERENCES tickets (id) ON DELETE CASCADE,
  operator_ci  VARCHAR(64) NOT NULL,
  added_by     VARCHAR(64),
  added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (ticket_id, operator_ci)
);
CREATE INDEX IF NOT EXISTS idx_ticket_watchers_op ON ticket_watchers (operator_ci);

-- ── (#10) Vistas / filtros guardados (por operador, o compartidas) ───────────
CREATE TABLE IF NOT EXISTS ticket_saved_views (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_ci VARCHAR(64) NOT NULL,
  name        TEXT        NOT NULL,
  filters     JSONB       NOT NULL DEFAULT '{}'::jsonb,   -- {status,type,tag,service,waitingOn,mine,bucket}
  sort        JSONB       NOT NULL DEFAULT '[]'::jsonb,   -- (#12) [{col,dir}, …]
  is_shared   BOOLEAN     NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ticket_views_op ON ticket_saved_views (operator_ci);

-- ── (#12) Preferencias de orden persistidas por usuario ──────────────────────
CREATE TABLE IF NOT EXISTS ticket_user_prefs (
  operator_ci   VARCHAR(64) PRIMARY KEY,
  sort          JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- multi-columna
  default_view  UUID,                                      -- vista guardada por defecto
  layout        VARCHAR(12) NOT NULL DEFAULT 'table'       -- (#16) 'table' | 'kanban'
                  CHECK (layout IN ('table','kanban')),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── (#19) Reglas de negocio configurables (if cond → actions) ─────────────────
-- conditions y actions son JSON declarativos evaluados por ticketRules.mjs:
--   conditions: {type?, priority?, channel?, service_slug?, tag?, subject_contains?}
--   actions:    {assign_tier?, assign_ci?, set_priority?, add_tag?, notify_sm?, set_type?}
CREATE TABLE IF NOT EXISTS ticket_rules (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT        NOT NULL,
  enabled     BOOLEAN     NOT NULL DEFAULT true,
  ordering    INT         NOT NULL DEFAULT 100,   -- menor = se evalúa antes
  conditions  JSONB       NOT NULL DEFAULT '{}'::jsonb,
  actions     JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_by  VARCHAR(64),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ticket_rules_enabled ON ticket_rules (enabled, ordering) WHERE enabled = true;
