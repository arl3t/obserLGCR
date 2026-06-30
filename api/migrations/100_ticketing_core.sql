-- 100_ticketing_core.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F1 del Sistema de Tickets Público (docs/PROPUESTA-TICKETING-PUBLICO.md §3).
--
-- Núcleo del plano COMUNICACIONAL, separado del plano OPERACIONAL (incident_cases_pg).
-- Un ticket es la PROYECCIÓN PÚBLICA filtrada de la comunicación con el cliente;
-- nunca expone el caso interno crudo (scoring/IOCs/nombres de tablas). La relación
-- es 1 caso ↔ N tickets ↔ 0..1 caso, resuelta por la tabla puente ticket_case_links.
--
-- Estas tablas NO modifican el núcleo de detección: solo se VINCULAN a casos.
-- Diseño tenant-ready (org_id presente) aunque arranque mono-cliente.
--
-- Refinamiento sobre la propuesta §3.1: el `linked_case_id` denormalizado se OMITE
-- a propósito para no tener dos fuentes de verdad (este repo penaliza los espejos
-- que se desincronizan). El vínculo vive SOLO en ticket_case_links; el caso
-- "primario" es la fila con link_type='PRIMARY' (única por ticket).
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Ticket público ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tickets (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Referencia legible para el cliente. NO secuencial-adivinable (anti-enumeración).
  public_ref         TEXT         NOT NULL UNIQUE,
  org_id             UUID,                       -- tenant-ready (una sola org por ahora; sin FK)
  subject            TEXT         NOT NULL,
  -- Máquina de estados del ticket (SEPARADA de la del caso). Transiciones válidas
  -- gobernadas en API (routes/tickets.mjs VALID_TRANSITIONS), espejo del patrón
  -- de incidents.mjs:
  --   ABIERTO           -> EN_ATENCION | RESUELTO | CERRADO
  --   EN_ATENCION       -> ESPERANDO_CLIENTE | RESUELTO | CERRADO
  --   ESPERANDO_CLIENTE -> EN_ATENCION | CERRADO
  --   RESUELTO          -> CERRADO | REABIERTO
  --   REABIERTO         -> EN_ATENCION
  --   CERRADO           -> REABIERTO
  status             VARCHAR(20)  NOT NULL DEFAULT 'ABIERTO'
                       CHECK (status IN ('ABIERTO','EN_ATENCION','ESPERANDO_CLIENTE',
                                         'RESUELTO','REABIERTO','CERRADO')),
  -- Prioridad VISIBLE al cliente. Independiente del score/severity interno
  -- (no filtrar scoring) — decisión §12.7.
  priority           VARCHAR(10)  NOT NULL DEFAULT 'MEDIUM'
                       CHECK (priority IN ('LOW','MEDIUM','HIGH','URGENT')),
  channel            VARCHAR(20)  NOT NULL DEFAULT 'PORTAL'
                       CHECK (channel IN ('PORTAL','EMAIL','API','SOC_INITIATED')),
  requester_contact  JSONB        NOT NULL DEFAULT '{}'::jsonb,   -- nombre/email del cliente
  assigned_operator  VARCHAR(64),                                 -- CI del analista dueño de la comunicación
  -- Ball-in-court (§5.1): de quién es la pelota. Recalculado al insertar cada
  -- mensaje PUBLIC. El tiempo en 'CLIENT' NO cuenta contra el SLA del SOC.
  waiting_on         VARCHAR(8)   NOT NULL DEFAULT 'SOC'
                       CHECK (waiting_on IN ('SOC','CLIENT','NONE')),
  reopened_count     INT          NOT NULL DEFAULT 0 CHECK (reopened_count >= 0),
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
  first_response_at  TIMESTAMPTZ,                                 -- primer mensaje PUBLIC del SOC (FRT)
  resolved_at        TIMESTAMPTZ,
  closed_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tickets_status        ON tickets (status);
CREATE INDEX IF NOT EXISTS idx_tickets_waiting_on    ON tickets (waiting_on, status);
CREATE INDEX IF NOT EXISTS idx_tickets_assigned      ON tickets (assigned_operator) WHERE assigned_operator IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tickets_org           ON tickets (org_id) WHERE org_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tickets_created       ON tickets (created_at DESC);

-- ── Hilo del ticket (ping-pong) — fuente de las métricas de cadencia §5 ───────
CREATE TABLE IF NOT EXISTS ticket_messages (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id          UUID         NOT NULL REFERENCES tickets (id) ON DELETE CASCADE,
  author_type        VARCHAR(8)   NOT NULL CHECK (author_type IN ('CLIENT','SOC','SYSTEM')),
  author_ref         VARCHAR(128),                                -- CI del operador o contacto del cliente
  -- PUBLIC la ve el cliente; INTERNAL es nota privada del SOC y NO para el reloj
  -- de comunicación ni cuenta como respuesta al cliente.
  visibility         VARCHAR(8)   NOT NULL DEFAULT 'PUBLIC'
                       CHECK (visibility IN ('PUBLIC','INTERNAL')),
  body               TEXT         NOT NULL,
  attachments        JSONB        NOT NULL DEFAULT '[]'::jsonb,
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
  -- Métricas denormalizadas al insertar (evita recálculo sobre el hilo):
  is_first_response  BOOLEAN      NOT NULL DEFAULT false,         -- primer mensaje SOC tras apertura
  turnaround_seconds INT          CHECK (turnaround_seconds IS NULL OR turnaround_seconds >= 0)
);

CREATE INDEX IF NOT EXISTS idx_ticket_messages_thread ON ticket_messages (ticket_id, created_at);
-- Para métricas de cadencia por lado, ignorando notas internas:
CREATE INDEX IF NOT EXISTS idx_ticket_messages_public ON ticket_messages (ticket_id, author_type, created_at)
  WHERE visibility = 'PUBLIC';

-- ── Puente caso ↔ ticket ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ticket_case_links (
  ticket_id   UUID         NOT NULL REFERENCES tickets (id) ON DELETE CASCADE,
  case_id     VARCHAR(64)  NOT NULL,                             -- FK lógica a incident_cases_pg(id)
  link_type   VARCHAR(8)   NOT NULL DEFAULT 'PRIMARY'
                CHECK (link_type IN ('PRIMARY','RELATED')),
  linked_by   VARCHAR(64),
  linked_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  PRIMARY KEY (ticket_id, case_id)
);

-- Un ticket tiene como máximo UN caso primario.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ticket_primary_case
  ON ticket_case_links (ticket_id) WHERE link_type = 'PRIMARY';
-- Lookup inverso: todos los tickets de un caso (broadcast multi-afectados §28).
CREATE INDEX IF NOT EXISTS idx_ticket_case_links_case ON ticket_case_links (case_id);
