-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 006 — DFIR-IRIS inspired tables
-- Case Templates, Tasks, Assets, IOCs, Evidences, Timeline (dedicated)
-- ─────────────────────────────────────────────────────────────────────────────

-- Ampliar incident_cases_pg con campos DFIR/NIST
ALTER TABLE incident_cases_pg
  ADD COLUMN IF NOT EXISTS template_id        VARCHAR(64),
  ADD COLUMN IF NOT EXISTS incident_category  VARCHAR(40),
  ADD COLUMN IF NOT EXISTS functional_impact  VARCHAR(30),
  ADD COLUMN IF NOT EXISTS information_impact VARCHAR(40),
  ADD COLUMN IF NOT EXISTS recoverability     VARCHAR(30),
  ADD COLUMN IF NOT EXISTS root_cause         TEXT,
  ADD COLUMN IF NOT EXISTS lessons_learned    TEXT,
  ADD COLUMN IF NOT EXISTS containment_status VARCHAR(40),
  ADD COLUMN IF NOT EXISTS ioc_value          VARCHAR(512),
  ADD COLUMN IF NOT EXISTS ioc_type           VARCHAR(40),
  ADD COLUMN IF NOT EXISTS source_log         VARCHAR(128),
  ADD COLUMN IF NOT EXISTS mitre_tactic_id    VARCHAR(20),
  ADD COLUMN IF NOT EXISTS mitre_tactic_name  VARCHAR(128),
  ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(20);

-- ── Case Templates ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_templates (
  id           VARCHAR(64)   PRIMARY KEY,
  name         VARCHAR(128)  NOT NULL,
  description  TEXT,
  -- Tipo de incidente que activa esta plantilla
  trigger_categories TEXT[]   DEFAULT '{}',
  trigger_severities TEXT[]   DEFAULT '{}',
  -- Metadatos
  mitre_tactics  TEXT[]       DEFAULT '{}',
  default_tags   TEXT[]       DEFAULT '{}',
  -- Checklist de tareas (JSONB array de {title, description, phase})
  tasks_template JSONB        NOT NULL DEFAULT '[]',
  -- Campos de reporte pre-llenados
  report_fields  JSONB        NOT NULL DEFAULT '{}',
  is_builtin     BOOLEAN      NOT NULL DEFAULT false,
  created_by     VARCHAR(64),
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ── Case Tasks ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_tasks (
  id           VARCHAR(64)   PRIMARY KEY,
  case_id      VARCHAR(64)   NOT NULL REFERENCES incident_cases_pg(id) ON DELETE CASCADE,
  title        VARCHAR(256)  NOT NULL,
  description  TEXT,
  phase        VARCHAR(30)   NOT NULL DEFAULT 'DETECTION',  -- DETECTION | CONTAINMENT | ERADICATION | RECOVERY | POST_INCIDENT
  status       VARCHAR(20)   NOT NULL DEFAULT 'OPEN',       -- OPEN | IN_PROGRESS | DONE | SKIPPED
  assignee     VARCHAR(64),
  due_at       TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  sort_order   INTEGER       NOT NULL DEFAULT 0,
  created_by   VARCHAR(64),
  created_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
  CONSTRAINT chk_task_phase   CHECK (phase  IN ('DETECTION','CONTAINMENT','ERADICATION','RECOVERY','POST_INCIDENT')),
  CONSTRAINT chk_task_status  CHECK (status IN ('OPEN','IN_PROGRESS','DONE','SKIPPED'))
);

CREATE INDEX IF NOT EXISTS idx_case_tasks_case ON case_tasks(case_id);
CREATE INDEX IF NOT EXISTS idx_case_tasks_status ON case_tasks(status);

-- ── Case Assets ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_assets (
  id              VARCHAR(64)   PRIMARY KEY,
  case_id         VARCHAR(64)   NOT NULL REFERENCES incident_cases_pg(id) ON DELETE CASCADE,
  asset_type      VARCHAR(30)   NOT NULL DEFAULT 'HOST',  -- HOST | USER | ACCOUNT | ENDPOINT | NETWORK | OTHER
  asset_value     VARCHAR(512)  NOT NULL,
  hostname        VARCHAR(256),
  ip_address      VARCHAR(64),
  domain          VARCHAR(256),
  os              VARCHAR(128),
  description     TEXT,
  compromised     BOOLEAN       NOT NULL DEFAULT false,
  containment_status VARCHAR(30) DEFAULT 'ACTIVE',  -- ACTIVE | ISOLATED | REIMAGED | DECOMMISSIONED
  enrichment_data JSONB         DEFAULT '{}',
  added_by        VARCHAR(64),
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
  CONSTRAINT chk_asset_type CHECK (asset_type IN ('HOST','USER','ACCOUNT','ENDPOINT','NETWORK','OTHER'))
);

CREATE INDEX IF NOT EXISTS idx_case_assets_case ON case_assets(case_id);

-- ── Case IOCs (per-case IOC registry) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_iocs (
  id          VARCHAR(64)   PRIMARY KEY,
  case_id     VARCHAR(64)   NOT NULL REFERENCES incident_cases_pg(id) ON DELETE CASCADE,
  ioc_type    VARCHAR(30)   NOT NULL,  -- ip | domain | hash_md5 | hash_sha256 | url | email | filename
  ioc_value   VARCHAR(512)  NOT NULL,
  tlp         VARCHAR(10)   NOT NULL DEFAULT 'AMBER',  -- WHITE | GREEN | AMBER | RED
  description TEXT,
  tags        TEXT[]        DEFAULT '{}',
  is_primary  BOOLEAN       NOT NULL DEFAULT false,
  -- Enriquecimiento snapshot
  vt_malicious    INTEGER,
  vt_permalink    VARCHAR(512),
  abuse_score     INTEGER,
  in_misp         BOOLEAN,
  shodan_summary  TEXT,
  enriched_at     TIMESTAMPTZ,
  added_by    VARCHAR(64),
  created_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_iocs_case  ON case_iocs(case_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_case_iocs_uniq ON case_iocs(case_id, ioc_type, ioc_value);

-- ── Case Evidences ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_evidences (
  id             VARCHAR(64)   PRIMARY KEY,
  case_id        VARCHAR(64)   NOT NULL REFERENCES incident_cases_pg(id) ON DELETE CASCADE,
  evidence_type  VARCHAR(30)   NOT NULL DEFAULT 'LOG',  -- LOG | PCAP | SCREENSHOT | DUMP | ARTIFACT | OTHER
  name           VARCHAR(256)  NOT NULL,
  description    TEXT,
  -- Chain of custody
  collected_by   VARCHAR(64)   NOT NULL,
  collected_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
  hash_sha256    VARCHAR(64),
  size_bytes     BIGINT,
  -- Storage (MinIO path or external URL)
  storage_path   VARCHAR(512),
  -- Tags para clasificación
  tags           TEXT[]        DEFAULT '{}',
  created_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
  CONSTRAINT chk_evidence_type CHECK (evidence_type IN ('LOG','PCAP','SCREENSHOT','DUMP','ARTIFACT','OTHER'))
);

CREATE INDEX IF NOT EXISTS idx_case_evidences_case ON case_evidences(case_id);

-- ── Case Timeline Events (dedicated table, replaces JSONB timeline) ──────────
CREATE TABLE IF NOT EXISTS case_timeline_events (
  id            VARCHAR(64)   PRIMARY KEY,
  case_id       VARCHAR(64)   NOT NULL REFERENCES incident_cases_pg(id) ON DELETE CASCADE,
  event_ts      TIMESTAMPTZ   NOT NULL DEFAULT now(),
  event_type    VARCHAR(30)   NOT NULL DEFAULT 'NOTE',
  -- DETECTION | CONTAINMENT | ERADICATION | RECOVERY | POST_INCIDENT
  -- ADOPT | STATUS_CHANGE | ESCALATE | SLACK_NOTIFY | NOTE | EVIDENCE | IOC | ASSET
  phase         VARCHAR(30),
  title         VARCHAR(256),
  description   TEXT,
  -- Links to related objects
  related_asset_id    VARCHAR(64),
  related_ioc_id      VARCHAR(64),
  related_evidence_id VARCHAR(64),
  operator_ci   VARCHAR(64),
  source        VARCHAR(30)   NOT NULL DEFAULT 'MANUAL',  -- MANUAL | SYSTEM | ALERT | ENRICHMENT
  metadata      JSONB         DEFAULT '{}',
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_timeline_case ON case_timeline_events(case_id);
CREATE INDEX IF NOT EXISTS idx_case_timeline_ts   ON case_timeline_events(event_ts DESC);

-- ── KPI materialized view (PostgreSQL) — replaces slow Trino queries ─────────
CREATE OR REPLACE VIEW v_soc_kpis AS
SELECT
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status NOT IN ('CERRADO','FALSO_POSITIVO') AND created_at >= now() - INTERVAL '90 days')
    AS open_cases,
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL AND created_at >= now() - INTERVAL '7 days')
    AS critical_sla_ok,
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE severity = 'CRITICAL' AND created_at >= now() - INTERVAL '7 days')
    AS critical_sla_total,
  (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (adopted_at - created_at)) / 60))
   FROM incident_cases_pg
   WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL AND created_at >= now() - INTERVAL '7 days')
    AS critical_avg_ack_min,
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status IN ('CERRADO') AND updated_at >= CURRENT_DATE)
    AS resolved_today,
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status = 'MONITOREADO' AND created_at >= now() - INTERVAL '90 days')
    AS monitoring,
  (SELECT COUNT(*) FROM incident_cases_pg
   WHERE status = 'FALSO_POSITIVO' AND created_at >= now() - INTERVAL '7 days')
    AS auto_fp;

-- ── Status distribution view ─────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_case_status_dist AS
SELECT
  status,
  COUNT(*) AS cnt,
  severity
FROM incident_cases_pg
WHERE created_at >= now() - INTERVAL '90 days'
GROUP BY status, severity;

-- ── Seed built-in templates ─────────────────────────────────────────────────
INSERT INTO case_templates (id, name, description, trigger_categories, trigger_severities, mitre_tactics, default_tags, tasks_template, is_builtin, created_by)
VALUES
(
  'tpl_phishing',
  'Phishing / Email Attack',
  'Plantilla para incidentes de phishing, spear-phishing y ataques por correo.',
  ARRAY['UNAUTHORIZED_ACCESS','MALICIOUS_CODE'],
  ARRAY['HIGH','CRITICAL'],
  ARRAY['TA0001','TA0009'],
  ARRAY['phishing','email','initial-access'],
  '[
    {"title":"Confirmar destinatarios afectados","description":"Identificar todos los usuarios que recibieron el email malicioso.","phase":"DETECTION"},
    {"title":"Aislar cuentas comprometidas","description":"Resetear contraseñas y revocar tokens de las cuentas afectadas.","phase":"CONTAINMENT"},
    {"title":"Bloquear dominio/URL del remitente","description":"Añadir el dominio malicioso a las listas de bloqueo del gateway de correo.","phase":"CONTAINMENT"},
    {"title":"Analizar payload adjunto/enlace","description":"Extraer y analizar el payload en entorno sandbox. Documentar IOCs.","phase":"ERADICATION"},
    {"title":"Limpiar artefactos en endpoints afectados","description":"Buscar y eliminar archivos descargados, entradas de registro, tareas programadas.","phase":"ERADICATION"},
    {"title":"Restaurar acceso a cuentas","description":"Habilitar cuentas limpias y verificar integridad de datos.","phase":"RECOVERY"},
    {"title":"Generar informe de lecciones aprendidas","description":"Documentar vector de entrada, controles fallidos y mejoras recomendadas.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  true, 'system'
),
(
  'tpl_malware',
  'Malware / Ransomware',
  'Plantilla para infecciones de malware incluyendo ransomware, troyanos y backdoors.',
  ARRAY['MALICIOUS_CODE'],
  ARRAY['CRITICAL','HIGH'],
  ARRAY['TA0002','TA0003','TA0011'],
  ARRAY['malware','ransomware','endpoint'],
  '[
    {"title":"Identificar proceso/hash malicioso","description":"Capturar el hash SHA-256 del ejecutable y buscar en VT/MISP.","phase":"DETECTION"},
    {"title":"Aislar el endpoint infectado","description":"Desconectar de la red inmediatamente (VLAN de cuarentena o apagado físico de NIC).","phase":"CONTAINMENT"},
    {"title":"Preservar imagen forense","description":"Capturar imagen de disco y memoria RAM antes de cualquier intervención.","phase":"CONTAINMENT"},
    {"title":"Identificar alcance de la propagación","description":"Revisar logs de red para detectar movimiento lateral o C2.","phase":"CONTAINMENT"},
    {"title":"Eliminar malware y artefactos","description":"Ejecutar herramientas de limpieza o reimaginar el sistema si no es recuperable.","phase":"ERADICATION"},
    {"title":"Actualizar defensas","description":"Agregar firmas/IOCs a EDR, IDS/IPS y listas de bloqueo.","phase":"ERADICATION"},
    {"title":"Restaurar desde backup verificado","description":"Restaurar datos desde backup previo a la infección, verificar integridad.","phase":"RECOVERY"},
    {"title":"Monitoreo post-incidente 30 días","description":"Aumentar nivel de monitoreo sobre el host y cuentas relacionadas.","phase":"RECOVERY"},
    {"title":"Lecciones aprendidas + reporte ejecutivo","description":"Documentar línea de tiempo, impacto y recomendaciones de mejora.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  true, 'system'
),
(
  'tpl_cred_compromise',
  'Credential Compromise',
  'Acceso no autorizado por credenciales comprometidas, credential stuffing o brute-force.',
  ARRAY['UNAUTHORIZED_ACCESS'],
  ARRAY['HIGH','CRITICAL'],
  ARRAY['TA0006','TA0008'],
  ARRAY['credentials','brute-force','lateral-movement'],
  '[
    {"title":"Identificar cuentas comprometidas","description":"Revisar logs de autenticación, detectar IPs anómalas y horarios inusuales.","phase":"DETECTION"},
    {"title":"Revocar sesiones activas y tokens","description":"Invalidar todos los tokens activos de las cuentas afectadas.","phase":"CONTAINMENT"},
    {"title":"Bloquear IPs de origen del ataque","description":"Añadir las IPs atacantes a las listas de bloqueo del firewall.","phase":"CONTAINMENT"},
    {"title":"Resetear credenciales afectadas","description":"Forzar cambio de contraseña y habilitar MFA en todas las cuentas comprometidas.","phase":"ERADICATION"},
    {"title":"Auditar accesos durante el período comprometido","description":"Revisar qué datos o sistemas accedió la cuenta comprometida.","phase":"ERADICATION"},
    {"title":"Verificar persistencia (backdoors/tokens)","description":"Buscar tokens de API, SSH keys o scripts de persistencia instalados.","phase":"ERADICATION"},
    {"title":"Restaurar acceso controlado","description":"Re-habilitar acceso con MFA y monitoreo elevado.","phase":"RECOVERY"},
    {"title":"Informe de impacto en datos","description":"Documentar qué información fue expuesta y si aplica notificación regulatoria.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  true, 'system'
),
(
  'tpl_data_breach',
  'Data Breach / Exfiltración',
  'Exfiltración de datos sensibles o acceso no autorizado a información confidencial.',
  ARRAY['UNAUTHORIZED_ACCESS'],
  ARRAY['CRITICAL'],
  ARRAY['TA0010','TA0009'],
  ARRAY['data-breach','exfiltration','dlp'],
  '[
    {"title":"Confirmar y cuantificar la exfiltración","description":"Determinar volumen, tipo y clasificación de datos exfiltrados.","phase":"DETECTION"},
    {"title":"Identificar el canal de exfiltración","description":"Analizar logs de red, DNS, HTTP/S para determinar el método usado.","phase":"DETECTION"},
    {"title":"Contener el acceso del actor de amenaza","description":"Revocar accesos, bloquear IPs/dominios C2, cerrar sesiones activas.","phase":"CONTAINMENT"},
    {"title":"Notificar al equipo legal y DPO","description":"Iniciar proceso de notificación regulatoria si aplica (GDPR, LOPDGDD).","phase":"CONTAINMENT"},
    {"title":"Preservar evidencias forenses","description":"Capturar logs, capturas de red y estados del sistema sin modificarlos.","phase":"CONTAINMENT"},
    {"title":"Cerrar el vector de exfiltración","description":"Eliminar el canal o vulnerabilidad utilizada para la exfiltración.","phase":"ERADICATION"},
    {"title":"Implementar controles DLP adicionales","description":"Revisar y reforzar las reglas DLP en endpoints y gateways.","phase":"RECOVERY"},
    {"title":"Notificación regulatoria (si aplica)","description":"Preparar y enviar notificación a autoridades de protección de datos.","phase":"POST_INCIDENT"},
    {"title":"Informe forense completo","description":"Generar informe técnico y ejecutivo con cadena de custodia documentada.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  true, 'system'
),
(
  'tpl_generic',
  'Investigación Genérica',
  'Plantilla base para cualquier tipo de incidente de seguridad.',
  ARRAY['OTHER','INVESTIGATION','SCANS_PROBES'],
  ARRAY['MEDIUM','HIGH','CRITICAL'],
  ARRAY[]::TEXT[],
  ARRAY['investigation'],
  '[
    {"title":"Confirmar el incidente","description":"Verificar que el alerta no es un falso positivo y documentar evidencia inicial.","phase":"DETECTION"},
    {"title":"Determinar el alcance","description":"Identificar todos los sistemas, usuarios e IOCs afectados.","phase":"DETECTION"},
    {"title":"Aplicar medidas de contención","description":"Aislar sistemas comprometidos para evitar propagación.","phase":"CONTAINMENT"},
    {"title":"Eliminar la amenaza","description":"Remover malware, accesos no autorizados y artefactos maliciosos.","phase":"ERADICATION"},
    {"title":"Restaurar la operación normal","description":"Verificar la integridad de los sistemas y restaurar servicios.","phase":"RECOVERY"},
    {"title":"Documentar lecciones aprendidas","description":"Registrar causa raíz, timeline e impacto. Identificar mejoras.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  true, 'system'
)
ON CONFLICT (id) DO NOTHING;
