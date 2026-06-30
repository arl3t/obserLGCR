-- 056_source_log_catalog.sql
-- Frente A (audit Scoring 2026-05-21): catálogo canónico de `source_log`.
--
-- Hasta esta migration, el mapping `source_log → sensor_name / category /
-- network_zone / iceberg_table` vivía duplicado en 6+ archivos:
--   - scripts/sql/threat-hunt/21_v2_view_incident_score.sql:475-487   (CASE WHEN)
--   - scripts/sql/threat-hunt/42_v_incident_score_v3.sql:513-530      (CASE WHEN)
--   - legacyhunt-api/services/dedupKey.mjs:46-66                       (sourceCategoryOf)
--   - legacyhunt-api/routes/incidents.mjs:4827                         (resolveNetworkZone)
--   - legacyhunt-api/routes/incidents.mjs:4838                         (labelOrigenSistema)
--   - legacyhunt-api/trino/incident-scoring-sql.mjs:1488-1502          (ip_scope)
--   - legacyhunt-api/services/scoringEngine.mjs:24-78                  (requiredSources por perfil)
--
-- Costo de drift: agregar un sensor nuevo (CrowdStrike, Velociraptor) requería
-- editar 6+ archivos en sincronía y un olvido se manifestaba como
-- `origen_sistema=NULL` o `network_zone='internal'` silenciosos. Drift
-- observado: `wazuh_fluent_alerts` y `pmg_phishing` solo aparecían desde v3 →
-- casos con `scoring_version='v2'` y esos source_log devolvían NULL.
--
-- Esta tabla centraliza el mapping. `services/sourceLogCatalog.mjs` la cachea
-- 5min y expone getters sync para los hot paths.
--
-- NOTA: `sourceCategoryOf` (services/dedupKey.mjs) NO se migra a esta tabla
-- en este paso. La fórmula de dedup_key es byte-sensitive y tiene una contra-
-- parte Python (data/airflow/plugins/dedup_key_canon.py) que debe mantenerse
-- alineada. Cambiar ese mapping requiere migrar ambos lados + backfill de
-- dedup_keys históricos. La tabla incluye `source_category` para cuando esa
-- migración se haga, pero por ahora solo se consume para
-- resolveNetworkZone / labelOrigenSistema.
--
-- Idempotente: CREATE IF NOT EXISTS + ON CONFLICT DO UPDATE en seed.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.source_log_catalog (
  source_log       VARCHAR(64) PRIMARY KEY,
  sensor_name      VARCHAR(64) NOT NULL,                              -- label legible para UI
  sensor_family    VARCHAR(32) NOT NULL,                              -- agrupador estable (wazuh, fortigate, opnsense, suricata, pmg, syslog)
  source_category  VARCHAR(32) NOT NULL,                              -- siem, firewall, ids, ips, email, edr, dns, proxy, auth, other
  network_zone     VARCHAR(32) NOT NULL,                              -- endpoint, perimeter, email, internal
  iceberg_table    VARCHAR(128),                                      -- tabla cruda Iceberg/MinIO (opcional, informacional)
  enabled          BOOLEAN NOT NULL DEFAULT true,                     -- catálogo conserva sensores deshabilitados para histórico
  notes            TEXT,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_source_category CHECK (
    source_category IN ('siem','firewall','ids','ips','email','edr','dns','proxy','auth','other')
  ),
  CONSTRAINT chk_network_zone CHECK (
    network_zone IN ('endpoint','perimeter','email','internal','dmz','unknown')
  )
);

CREATE INDEX IF NOT EXISTS idx_source_log_catalog_family   ON legacyhunt_soc.source_log_catalog (sensor_family) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_source_log_catalog_category ON legacyhunt_soc.source_log_catalog (source_category) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_source_log_catalog_zone     ON legacyhunt_soc.source_log_catalog (network_zone) WHERE enabled = true;

COMMENT ON TABLE legacyhunt_soc.source_log_catalog IS
  'Catálogo canónico source_log → sensor/categoría/zona/tabla cruda. '
  'Consumido por services/sourceLogCatalog.mjs (cache 5min). '
  'Para agregar un sensor nuevo: INSERT aquí + actualizar el seed de esta migration. '
  'Las CASE WHEN duplicadas en 21_/42_/43_ siguen hardcoded — test '
  'sourceLogCatalog.test.mjs verifica que matchen.';

-- ── Seed ─────────────────────────────────────────────────────────────────────
-- Valores derivados de las CASE WHEN actuales en v2 (21) y v3 (42), de
-- sourceCategoryOf (dedupKey.mjs) y de resolveNetworkZone (incidents.mjs).
-- Cualquier modificación aquí debe sincronizarse con esas 3 fuentes.

INSERT INTO legacyhunt_soc.source_log_catalog
  (source_log, sensor_name, sensor_family, source_category, network_zone, iceberg_table, notes)
VALUES
  ('wazuh_alerts',          'Wazuh SIEM',             'wazuh',     'siem',     'endpoint',  'minio.hunting.wazuh_alerts',         'Wazuh agent → manager. Aporta source_severity vía wazuh_level CTE.'),
  ('wazuh',                 'Wazuh SIEM',             'wazuh',     'siem',     'endpoint',  'minio.hunting.wazuh_alerts',         'Alias legacy de wazuh_alerts.'),
  ('wazuh_fluent_alerts',   'Wazuh Fluent',           'wazuh',     'siem',     'endpoint',  'minio.hunting.wazuh_fluent',         'Pipeline alterno Wazuh + Fluent Bit. Solo materializado en v3+.'),
  ('opnsense_filterlog',    'OPNsense Firewall',      'opnsense',  'firewall', 'perimeter', 'minio.hunting.syslog',               'pf/filterlog de OPNsense vía syslog.'),
  ('filterlog',             'OPNsense Firewall',      'opnsense',  'firewall', 'perimeter', 'minio.hunting.syslog',               'Alias corto de opnsense_filterlog.'),
  ('opnsense',              'OPNsense Firewall',      'opnsense',  'firewall', 'perimeter', 'minio.hunting.syslog',               'Alias genérico.'),
  ('suricata',              'Suricata IDS',           'suricata',  'ids',      'perimeter', 'minio.hunting.syslog',               'Eve.json vía syslog. Tabla cruda compartida con filterlog.'),
  ('fortigate',             'FortiGate FW',           'fortigate', 'firewall', 'perimeter', 'minio.hunting.fortigate',            'FortiGate UTM logs vía syslog estructurado.'),
  ('fortigate_webfilter',   'FortiGate WebFilter',    'fortigate', 'firewall', 'perimeter', 'minio.hunting.fortigate',            'Subconjunto de fortigate filtrado a categoría webfilter.'),
  ('pmg_phishing',          'Proxmox Mail Gateway',   'pmg',       'email',    'email',     'minio.hunting.pmg_phishing',         'PMG email gateway. Solo materializado en v3+.'),
  ('syslog',                'Syslog Genérico',        'syslog',    'other',    'internal',  'minio.hunting.syslog',               'Fuente sin clasificar — score_evidence cae a piso 5pts si no aporta source_severity.'),
  -- Pseudo-sources (apertura manual / force-ack): se incluyen para que el
  -- lookup nunca devuelva NULL y los reportes por sensor agrupen estos casos.
  ('manual-flow',           'Apertura Manual',        'manual',    'other',    'internal',  NULL,                                 'POST /api/incidents/open-from-flow sin source_log original.'),
  ('manual',                'Apertura Manual',        'manual',    'other',    'internal',  NULL,                                 'Alias corto.'),
  ('dashboard_open',        'Dashboard Open',         'manual',    'other',    'internal',  NULL,                                 'controllers/forcedAckController.processForcedAck (no enriched).'),
  ('dashboard_voluntary',   'Adopción Voluntaria',    'manual',    'other',    'internal',  NULL,                                 'controllers/forcedAckController.voluntaryAdoptIncident.'),
  ('force_ack',             'Force-Ack',              'manual',    'other',    'internal',  NULL,                                 'controllers/forcedAckController.persistAdoptionToTrino default.')
ON CONFLICT (source_log) DO UPDATE SET
  sensor_name     = EXCLUDED.sensor_name,
  sensor_family   = EXCLUDED.sensor_family,
  source_category = EXCLUDED.source_category,
  network_zone    = EXCLUDED.network_zone,
  iceberg_table   = EXCLUDED.iceberg_table,
  notes           = EXCLUDED.notes,
  updated_at      = NOW();
