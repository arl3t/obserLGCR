-- 102_ticket_comm_sla.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F1 del Sistema de Tickets Público — SLA de COMUNICACIÓN
-- (docs/PROPUESTA-TICKETING-PUBLICO.md §3.5).
--
-- Paralelo a sla_config (mig 054), pero mide algo DISTINTO: no "¿cuándo se contuvo
-- el ataque?" (SLA operacional) sino "¿cuándo se le RESPONDIÓ al cliente?". Se
-- incumplen por razones distintas, por eso son tablas separadas.
--
-- Tres relojes por prioridad VISIBLE del ticket (URGENT < HIGH < MEDIUM < LOW):
--   · FRT  — First Response Time:  apertura del cliente → 1er mensaje PUBLIC del SOC
--   · NRT  — Next Response Time:   mensaje del cliente → siguiente respuesta del SOC
--   · RES  — Resolución comunicada: apertura → ticket en estado RESUELTO
--
-- El tiempo en waiting_on='CLIENT' NO cuenta contra estos relojes (ball-in-court).
-- Si business_hours_aware=true, el reloj respeta el horario laboral/zona del
-- cliente (reutiliza el concepto de mig 099_business_hours_scoring) y se pausa
-- fuera de la franja contratada.
--
-- Singleton id=1 cacheado por services/ticketCommSla.mjs (espejo de slaConfig.mjs).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ticket_comm_sla_config (
  id                  INT          PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  -- FRT por prioridad (segundos). Defaults §3.5: 30m / 2h / 8h / 24h.
  frt_urgent_sec      INT          NOT NULL DEFAULT 1800    CHECK (frt_urgent_sec   BETWEEN 60 AND 31536000),
  frt_high_sec        INT          NOT NULL DEFAULT 7200    CHECK (frt_high_sec     BETWEEN 60 AND 31536000),
  frt_medium_sec      INT          NOT NULL DEFAULT 28800   CHECK (frt_medium_sec   BETWEEN 60 AND 31536000),
  frt_low_sec         INT          NOT NULL DEFAULT 86400   CHECK (frt_low_sec      BETWEEN 60 AND 31536000),
  -- NRT por prioridad (segundos). Defaults §3.5: 1h / 4h / 1d / 2d.
  nrt_urgent_sec      INT          NOT NULL DEFAULT 3600    CHECK (nrt_urgent_sec   BETWEEN 60 AND 31536000),
  nrt_high_sec        INT          NOT NULL DEFAULT 14400   CHECK (nrt_high_sec     BETWEEN 60 AND 31536000),
  nrt_medium_sec      INT          NOT NULL DEFAULT 86400   CHECK (nrt_medium_sec   BETWEEN 60 AND 31536000),
  nrt_low_sec         INT          NOT NULL DEFAULT 172800  CHECK (nrt_low_sec      BETWEEN 60 AND 31536000),
  -- Resolución comunicada por prioridad (segundos). Defaults §3.5: 4h / 1d / 3d / 5d.
  res_urgent_sec      INT          NOT NULL DEFAULT 14400   CHECK (res_urgent_sec   BETWEEN 60 AND 31536000),
  res_high_sec        INT          NOT NULL DEFAULT 86400   CHECK (res_high_sec     BETWEEN 60 AND 31536000),
  res_medium_sec      INT          NOT NULL DEFAULT 259200  CHECK (res_medium_sec   BETWEEN 60 AND 31536000),
  res_low_sec         INT          NOT NULL DEFAULT 432000  CHECK (res_low_sec      BETWEEN 60 AND 31536000),
  -- El reloj respeta el horario laboral del cliente (mig 099) y se pausa fuera.
  business_hours_aware BOOLEAN     NOT NULL DEFAULT false,
  enabled             BOOLEAN      NOT NULL DEFAULT true,
  updated_by          TEXT,
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),

  -- Orden estricto: URGENT < HIGH < MEDIUM < LOW en cada métrica (evita que un
  -- cambio mal hecho le dé más tiempo al URGENT que al LOW).
  CONSTRAINT chk_frt_order CHECK (frt_urgent_sec < frt_high_sec AND frt_high_sec < frt_medium_sec AND frt_medium_sec < frt_low_sec),
  CONSTRAINT chk_nrt_order CHECK (nrt_urgent_sec < nrt_high_sec AND nrt_high_sec < nrt_medium_sec AND nrt_medium_sec < nrt_low_sec),
  CONSTRAINT chk_res_order CHECK (res_urgent_sec < res_high_sec AND res_high_sec < res_medium_sec AND res_medium_sec < res_low_sec)
);

INSERT INTO ticket_comm_sla_config (id, updated_by)
  VALUES (1, 'migration:102')
ON CONFLICT (id) DO NOTHING;

-- ── Auditoría de cambios (espejo de sla_config_audit) ────────────────────────
CREATE TABLE IF NOT EXISTS ticket_comm_sla_audit (
  id          BIGSERIAL    PRIMARY KEY,
  changed_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  changed_by  TEXT         NOT NULL,
  before      JSONB        NOT NULL,
  after       JSONB        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ticket_comm_sla_audit_recent
  ON ticket_comm_sla_audit (changed_at DESC);

COMMENT ON TABLE ticket_comm_sla_audit IS
  'Historial de cambios a ticket_comm_sla_config. Inserción manual desde el handler '
  'PUT /api/tickets/sla-com. before/after = snapshot completo del row.';
