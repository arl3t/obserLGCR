-- 008_soc_workflow.sql
-- Implementación completa del flujo de trabajo del analista SOC.
-- NIST SP 800-61 Rev. 3 — 5 etapas del ciclo de vida del incidente.
--
-- Nuevas tablas:
--   soc_roles              — definición de roles (L1/L2/L3/LEADER/ADMIN)
--   soc_operators          — operadores con rol, turno, y si es shift manager
--   soc_notifications      — cola de notificaciones in-app
--   incident_auto_actions  — audit trail de acciones automáticas
--   soc_handover_reports   — reportes de handover entre turnos
--
-- Extensiones a incident_cases_pg:
--   lifecycle_stage        — etapa NIST del incidente
--   assigned_role          — rol propietario actual del caso
--   auto_closed_at         — timestamp si fue auto-cerrado
--   auto_closed_reason     — justificación del cierre automático
--   shift_manager_assigned_at — timestamp de asignación automática al líder

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ROLES SOC
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_roles (
  id                      VARCHAR(20)  PRIMARY KEY,
  name                    VARCHAR(64)  NOT NULL,
  description             TEXT,
  -- Permisos granulares
  can_adopt               BOOLEAN NOT NULL DEFAULT false,
  can_escalate_to_l2      BOOLEAN NOT NULL DEFAULT false,
  can_escalate_to_l3      BOOLEAN NOT NULL DEFAULT false,
  can_close_fp            BOOLEAN NOT NULL DEFAULT false,
  can_close_case          BOOLEAN NOT NULL DEFAULT false,
  can_assign_cases        BOOLEAN NOT NULL DEFAULT false,
  can_review_kpis         BOOLEAN NOT NULL DEFAULT false,
  can_post_mortem         BOOLEAN NOT NULL DEFAULT false,
  can_create_handover     BOOLEAN NOT NULL DEFAULT false,
  -- Receptor de auto-asignaciones por timeout
  receives_auto_assign    BOOLEAN NOT NULL DEFAULT false,
  -- Escalada automática sugerida para score ≥ umbral
  escalation_score_threshold INT,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO soc_roles (id, name, description,
  can_adopt, can_escalate_to_l2, can_escalate_to_l3,
  can_close_fp, can_close_case, can_assign_cases,
  can_review_kpis, can_post_mortem, can_create_handover,
  receives_auto_assign, escalation_score_threshold)
VALUES
  ('L1',     'Analista L1 — Triaje',
   'Revisión de cola NUEVO cada 30 min. Apertura inmediata de críticos. Escalada a L2 si score ≥ 70.',
   true, true, false, true, false, false, false, false, false, false, 70),
  ('L2',     'Analista L2 — Investigación',
   'Correlación Wazuh/Trino, línea de tiempo, informe técnico MITRE ATT&CK, coordinación L3.',
   true, false, true, true, true, false, true, true, false, false, 90),
  ('L3',     'Analista L3 — Respuesta y Hunting',
   'Threat hunting, DAGs Airflow, ajuste scoring v2, TI interna (IOC/YARA/Sigma/STIX), post-mortem.',
   true, false, false, true, true, false, true, true, false, false, null),
  ('LEADER', 'Líder SOC / Shift Manager',
   'KPIs al inicio de turno, asignación de carga, escalada P1 ≥ 90, reporte de turno, handover.',
   true, true, true, true, true, true, true, true, true, true, null),
  ('ADMIN',  'Administrador del Sistema',
   'Acceso total. Gestión de roles, operadores y configuración del motor de scoring.',
   true, true, true, true, true, true, true, true, true, false, null)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  can_adopt = EXCLUDED.can_adopt,
  can_escalate_to_l2 = EXCLUDED.can_escalate_to_l2,
  can_escalate_to_l3 = EXCLUDED.can_escalate_to_l3,
  can_close_fp = EXCLUDED.can_close_fp,
  can_close_case = EXCLUDED.can_close_case,
  can_assign_cases = EXCLUDED.can_assign_cases,
  can_review_kpis = EXCLUDED.can_review_kpis,
  can_post_mortem = EXCLUDED.can_post_mortem,
  can_create_handover = EXCLUDED.can_create_handover,
  receives_auto_assign = EXCLUDED.receives_auto_assign,
  escalation_score_threshold = EXCLUDED.escalation_score_threshold;

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. OPERADORES SOC
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_operators (
  id                VARCHAR(64)  PRIMARY KEY,  -- CI del operador
  name              VARCHAR(128) NOT NULL,
  email             VARCHAR(255),
  role_id           VARCHAR(20)  NOT NULL DEFAULT 'L1' REFERENCES soc_roles(id),
  is_active         BOOLEAN      NOT NULL DEFAULT true,
  -- Turno actual
  shift             VARCHAR(20)  DEFAULT 'MORNING'
                    CHECK (shift IN ('MORNING','AFTERNOON','NIGHT','ON_CALL')),
  -- Si es el Shift Manager activo (solo 1 por turno)
  is_shift_manager  BOOLEAN      NOT NULL DEFAULT false,
  -- KPIs del operador (acumulado 30 días)
  cases_adopted     INT          NOT NULL DEFAULT 0,
  cases_closed      INT          NOT NULL DEFAULT 0,
  fp_count          INT          NOT NULL DEFAULT 0,
  avg_mtta_min      NUMERIC(8,1),
  avg_mttr_min      NUMERIC(8,1),
  -- Metadatos
  registered_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  last_active_at    TIMESTAMPTZ,
  notes             TEXT
);

CREATE INDEX IF NOT EXISTS idx_soc_operators_role
  ON soc_operators(role_id);
CREATE INDEX IF NOT EXISTS idx_soc_operators_shift_mgr
  ON soc_operators(is_shift_manager) WHERE is_shift_manager = true;
CREATE INDEX IF NOT EXISTS idx_soc_operators_active
  ON soc_operators(is_active) WHERE is_active = true;

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. EXTENSIÓN DE incident_cases_pg PARA EL FLUJO DE VIDA
-- ─────────────────────────────────────────────────────────────────────────────

-- Etapa del ciclo de vida NIST SP 800-61
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS lifecycle_stage VARCHAR(20) DEFAULT 'DETECTION'
  CHECK (lifecycle_stage IN ('DETECTION','TRIAGE_L1','INVESTIGATION_L2','RESPONSE_L3','CLOSURE'));

-- Rol propietario actual del caso
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS assigned_role VARCHAR(20) REFERENCES soc_roles(id);

-- Cierre automático
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS auto_closed_at TIMESTAMPTZ;
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS auto_closed_reason TEXT;

-- Auto-asignación al Shift Manager por timeout 30 min
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS shift_manager_assigned_at TIMESTAMPTZ;
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS shift_manager_ci VARCHAR(64);

-- Score de escalada sugerida (auto-calculado al crear)
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS escalation_suggested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS escalation_reason_auto TEXT;

-- Índice para el scheduler de timeouts
CREATE INDEX IF NOT EXISTS idx_cases_lifecycle
  ON incident_cases_pg(lifecycle_stage, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_auto_close
  ON incident_cases_pg(severity, status, auto_closed_at)
  WHERE status NOT IN ('CERRADO','FALSO_POSITIVO') AND auto_closed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_cases_timeout_check
  ON incident_cases_pg(status, adopted_at, created_at)
  WHERE status IN ('NUEVO','EN_ANALISIS') AND adopted_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. AUDIT TRAIL DE ACCIONES AUTOMÁTICAS
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incident_auto_actions (
  id              VARCHAR(64)  PRIMARY KEY,
  case_id         VARCHAR(64)  NOT NULL REFERENCES incident_cases_pg(id) ON DELETE CASCADE,
  action_type     VARCHAR(30)  NOT NULL
                  CHECK (action_type IN (
                    'AUTO_CLOSE_LOW',       -- cierre automático LOW/NEGLIGIBLE
                    'AUTO_CLOSE_NEGLIGIBLE',
                    'AUTO_ASSIGN_TIMEOUT',  -- auto-asignación 30 min
                    'AUTO_ESCALATE_SCORE',  -- escalada por score ≥ umbral
                    'AUTO_ESCALATE_TACTIC', -- escalada por táctica crítica
                    'SLA_BREACH_ALERT',     -- alerta SLA vencido
                    'HANDOVER_CREATED'      -- se creó reporte de handover
                  )),
  performed_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  target_operator VARCHAR(64), -- CI del operador afectado (ej: shift manager)
  before_status   VARCHAR(30),
  after_status    VARCHAR(30),
  before_stage    VARCHAR(20),
  after_stage     VARCHAR(20),
  reason          TEXT,
  details         JSONB        NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_auto_actions_case
  ON incident_auto_actions(case_id, performed_at DESC);
CREATE INDEX IF NOT EXISTS idx_auto_actions_type
  ON incident_auto_actions(action_type, performed_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. NOTIFICACIONES IN-APP
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_notifications (
  id              VARCHAR(64)  PRIMARY KEY,
  operator_id     VARCHAR(64)  NOT NULL,  -- CI del destinatario
  case_id         VARCHAR(64)  REFERENCES incident_cases_pg(id) ON DELETE SET NULL,
  type            VARCHAR(30)  NOT NULL
                  CHECK (type IN (
                    'AUTO_ASSIGN',       -- te asignaron un caso por timeout
                    'P1_ESCALATION',     -- caso P1 requiere atención inmediata
                    'SLA_BREACH',        -- SLA vencido en tu caso
                    'SHIFT_HANDOVER',    -- nuevo reporte de handover disponible
                    'CASE_ESCALATED',    -- caso escalado desde L1/L2
                    'AUTO_CLOSE',        -- caso cerrado automáticamente
                    'MENTION',           -- fuiste mencionado en un caso
                    'SYSTEM'             -- notificación de sistema
                  )),
  priority        VARCHAR(10)  NOT NULL DEFAULT 'NORMAL'
                  CHECK (priority IN ('LOW','NORMAL','HIGH','CRITICAL')),
  title           VARCHAR(256) NOT NULL,
  body            TEXT,
  action_url      TEXT,        -- ruta del dashboard (ej: /cases/{id})
  read_at         TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notif_operator
  ON soc_notifications(operator_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_unread
  ON soc_notifications(operator_id, read_at)
  WHERE read_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. REPORTES DE HANDOVER
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_handover_reports (
  id                    VARCHAR(64)  PRIMARY KEY,
  outgoing_manager_ci   VARCHAR(64)  NOT NULL,
  incoming_manager_ci   VARCHAR(64),
  shift                 VARCHAR(20)  NOT NULL,
  -- Snapshot del estado al momento del handover
  open_cases_count      INT          NOT NULL DEFAULT 0,
  critical_open_count   INT          NOT NULL DEFAULT 0,
  pending_escalation    INT          NOT NULL DEFAULT 0,
  sla_breached_count    INT          NOT NULL DEFAULT 0,
  -- KPIs del turno saliente
  cases_closed_shift    INT          NOT NULL DEFAULT 0,
  cases_opened_shift    INT          NOT NULL DEFAULT 0,
  mtta_shift_min        NUMERIC(8,1),
  mttr_shift_min        NUMERIC(8,1),
  fp_rate_shift         NUMERIC(5,1),
  -- Contexto narrativo
  notes                 TEXT,
  pending_actions       TEXT,        -- acciones pendientes para el próximo turno
  critical_case_ids     TEXT[],      -- IDs de casos críticos a atender
  -- Firma temporal
  created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
  acknowledged_at       TIMESTAMPTZ  -- cuando incoming lo confirma
);

CREATE INDEX IF NOT EXISTS idx_handover_created
  ON soc_handover_reports(created_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- 7. VISTA: COLA DE TRABAJO POR ROL
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_workflow_queue AS
SELECT
  c.id,
  c.severity,
  c.status,
  c.lifecycle_stage,
  c.assigned_role,
  c.score,
  c.ioc_value,
  c.ioc_type,
  c.source_log,
  c.mitre_tactic_name,
  c.mitre_technique_id,
  c.operator_id,
  c.adopted_at,
  c.created_at,
  c.escalation_suggested,
  c.escalation_reason_auto,
  c.shift_manager_assigned_at,
  c.shift_manager_ci,
  -- SLA: % consumido (umbral por severidad en minutos)
  EXTRACT(EPOCH FROM (now() - c.created_at)) / 60 AS elapsed_min,
  CASE c.severity
    WHEN 'CRITICAL'   THEN 60
    WHEN 'HIGH'       THEN 240
    WHEN 'MEDIUM'     THEN 480
    ELSE 1440
  END AS sla_min,
  ROUND(
    EXTRACT(EPOCH FROM (now() - c.created_at)) / 60
    / CASE c.severity
        WHEN 'CRITICAL' THEN 60
        WHEN 'HIGH'     THEN 240
        WHEN 'MEDIUM'   THEN 480
        ELSE 1440
      END * 100
  ) AS sla_pct_consumed,
  -- Tiempo sin adopción
  CASE WHEN c.adopted_at IS NULL
    THEN ROUND(EXTRACT(EPOCH FROM (now() - c.created_at)) / 60)
    ELSE NULL
  END AS unacknowledged_min
FROM incident_cases_pg c
WHERE c.status NOT IN ('CERRADO','FALSO_POSITIVO')
  AND c.created_at >= now() - INTERVAL '90 days'
ORDER BY
  CASE c.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
  c.score DESC,
  c.created_at ASC;

-- ─────────────────────────────────────────────────────────────────────────────
-- 8. VISTA: CASOS CANDIDATOS A CIERRE AUTOMÁTICO (LOW/NEGLIGIBLE)
-- Solo aplica a casos en triaje inicial (NUEVO / EN_ANALISIS).
-- CONFIRMADO, ESCALADO y MONITOREADO quedan excluidos: puede que un analista L2
-- los esté trabajando aunque sean de baja severidad (ej. parte de un incidente mayor).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_auto_close_candidates AS
SELECT id, severity, status, lifecycle_stage, score, created_at, ioc_value, operator_id
FROM incident_cases_pg
WHERE severity IN ('LOW','NEGLIGIBLE')
  AND status IN ('NUEVO','EN_ANALISIS')
  AND auto_closed_at IS NULL
  AND created_at >= now() - INTERVAL '7 days';

-- ─────────────────────────────────────────────────────────────────────────────
-- 9. VISTA: CASOS CANDIDATOS A AUTO-ASIGNACIÓN (30 min sin adoptar)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_timeout_cases AS
SELECT
  c.id, c.severity, c.status, c.score, c.created_at,
  c.ioc_value, c.mitre_tactic_name,
  ROUND(EXTRACT(EPOCH FROM (now() - c.created_at)) / 60) AS minutes_unadopted
FROM incident_cases_pg c
WHERE c.status IN ('NUEVO','EN_ANALISIS')
  AND c.adopted_at IS NULL
  AND c.shift_manager_assigned_at IS NULL
  AND EXTRACT(EPOCH FROM (now() - c.created_at)) / 60 >= 30
  AND c.severity NOT IN ('LOW','NEGLIGIBLE')  -- LOW/NEGLIGIBLE se auto-cierran, no se asignan
  AND c.created_at >= now() - INTERVAL '7 days';
