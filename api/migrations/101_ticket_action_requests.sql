-- 101_ticket_action_requests.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- F1 del Sistema de Tickets Público — Solicitudes accionables y aceptación de
-- riesgo (docs/PROPUESTA-TICKETING-PUBLICO.md §3.6 y §6).
--
-- Caso de uso: un analista, DESDE un caso, necesita que el cliente HAGA algo sobre
-- SU PROPIA infraestructura (aplicar una contención en su firewall, aislar un host,
-- rotar credenciales…) o que ASUMA FORMALMENTE el riesgo de no hacerlo. El SOC no
-- ejecuta la acción — la SOLICITA y RASTREA su disposición.
--
-- Distinto de las acciones que el SOC ejecuta sobre su propia infra (Estación de
-- Respuesta: bloquear IP / aislar host): misma taxonomía, distinto EJECUTOR.
--
-- `RIESGO_ACEPTADO` es el entregable de cumplimiento: registro trazable de QUIÉN
-- (con cargo) declina la recomendación, QUÉ riesgo residual asume y HASTA CUÁNDO
-- (revisión/expiración). Es la cobertura de responsabilidad del equipo.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ticket_action_requests (
  id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id             UUID         NOT NULL REFERENCES tickets (id) ON DELETE CASCADE,
  case_id               VARCHAR(64),                              -- caso origen (FK lógica a incident_cases_pg)
  requested_by          VARCHAR(64)  NOT NULL,                    -- CI del operador
  action_type           VARCHAR(24)  NOT NULL
                          CHECK (action_type IN ('CONTENCION_FIREWALL','AISLAR_HOST','BLOQUEO_IOC',
                                                 'RESET_CREDENCIALES','APLICAR_PARCHE','DESHABILITAR_CUENTA',
                                                 'DESHABILITAR_SERVICIO','OTRO')),
  title                 TEXT         NOT NULL,                    -- "Bloquear 203.0.113.40 en el FW perimetral"
  rationale             TEXT         NOT NULL,                    -- por qué (lenguaje claro, sin telemetría cruda)
  recommended_steps     TEXT,                                    -- guía concreta opcional
  urgency               VARCHAR(10)  NOT NULL DEFAULT 'MEDIUM'
                          CHECK (urgency IN ('LOW','MEDIUM','HIGH','URGENT')),
  due_at                TIMESTAMPTZ,                             -- fecha límite de decisión
  status                VARCHAR(16)  NOT NULL DEFAULT 'PENDIENTE'
                          CHECK (status IN ('PENDIENTE','EJECUTADA','RECHAZADA',
                                            'RIESGO_ACEPTADO','DIFERIDA','CANCELADA')),
  -- ── Disposición del cliente ──
  decided_by            VARCHAR(128),                            -- contacto del cliente que decide
  decided_at            TIMESTAMPTZ,
  decision_note         TEXT,                                    -- evidencia de ejecución o justificación
  deferred_until        TIMESTAMPTZ,                             -- compromiso de fecha si DIFERIDA
  -- ── Bloque de aceptación de riesgo (sólo si status='RIESGO_ACEPTADO') ──
  risk_accepted_by      VARCHAR(160),                            -- nombre + cargo de quien asume
  risk_acceptance_scope TEXT,                                    -- riesgo residual que se asume
  risk_review_at        TIMESTAMPTZ,                             -- caducidad / fecha de revisión
  created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

  -- Integridad de la disposición: si está decidida, debe constar quién y cuándo.
  CONSTRAINT chk_action_decided CHECK (
    status = 'PENDIENTE'
    OR status = 'CANCELADA'
    OR (decided_by IS NOT NULL AND decided_at IS NOT NULL)
  ),
  -- Una aceptación de riesgo SIN quién la asume no es trazable → se prohíbe.
  CONSTRAINT chk_risk_acceptance CHECK (
    status <> 'RIESGO_ACEPTADO'
    OR (risk_accepted_by IS NOT NULL AND risk_acceptance_scope IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_action_req_ticket  ON ticket_action_requests (ticket_id, created_at);
CREATE INDEX IF NOT EXISTS idx_action_req_case    ON ticket_action_requests (case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_action_req_pending ON ticket_action_requests (due_at)
  WHERE status = 'PENDIENTE';

-- ── Registro de riesgos aceptados VIGENTES (para revisión periódica §6.3) ─────
-- Riesgos asumidos por el cliente cuya revisión no ha vencido o no está marcada.
CREATE OR REPLACE VIEW v_open_risk_acceptances AS
  SELECT ar.id,
         ar.ticket_id,
         ar.case_id,
         ar.action_type,
         ar.title,
         ar.risk_accepted_by,
         ar.risk_acceptance_scope,
         ar.risk_review_at,
         ar.decided_at,
         (ar.risk_review_at IS NOT NULL AND ar.risk_review_at < now()) AS review_overdue
    FROM ticket_action_requests ar
   WHERE ar.status = 'RIESGO_ACEPTADO';
