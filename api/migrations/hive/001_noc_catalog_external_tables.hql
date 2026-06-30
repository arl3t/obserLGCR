-- 001_noc_catalog_external_tables.hql
-- ─────────────────────────────────────────────────────────────────────────────
-- Hive Metastore (HMS) — catálogo analítico NOC obserLGCR
--
-- Prerequisitos:
--   - HMS apuntando a PostgreSQL/MySQL como metastore DB
--   - Object store S3/MinIO: s3a://obserlgcr-lake/noc/
--   - Spark/Flink/Airflow job ETL: PG TimescaleDB + inventory → Parquet diario
--
-- Particionado: dt (fecha ingestión) + region (site/DC)
-- Formato: Parquet + Snappy (lectura columnar eficiente)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS obserlgcr_noc
  COMMENT 'Catálogo NOC — inventario, métricas históricas, gobernanza software'
  LOCATION 's3a://obserlgcr-lake/noc/';

USE obserlgcr_noc;

-- ── Gobernanza: reglas activas (dimensión lenta, snapshot diario) ───────────

CREATE EXTERNAL TABLE IF NOT EXISTS dim_software_blacklist (
  rule_id         STRING      COMMENT 'UUID de software_blacklist',
  software_name   STRING,
  match_type      STRING      COMMENT 'exact|prefix|suffix|regex|cpe',
  pattern         STRING,
  publisher       STRING,
  severity        STRING,
  mitre_technique STRING,
  enabled         BOOLEAN,
  snapshot_ts     TIMESTAMP
)
PARTITIONED BY (dt STRING COMMENT 'YYYY-MM-DD', region STRING COMMENT 'site/DC o global')
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/dim_software_blacklist/'
TBLPROPERTIES (
  'parquet.compress' = 'SNAPPY',
  'projection.enabled' = 'true',
  'projection.dt.type' = 'date',
  'projection.dt.range' = '2026-01-01,2030-12-31',
  'projection.dt.format' = 'yyyy-MM-dd',
  'projection.region.type' = 'enum',
  'projection.region.values' = 'global,lgcr-dc1,lgcr-dc2,lgcr-edge',
  'storage.location.template' = 's3a://obserlgcr-lake/noc/dim_software_blacklist/dt=${dt}/region=${region}'
);

CREATE EXTERNAL TABLE IF NOT EXISTS dim_software_whitelist (
  rule_id         STRING,
  software_name   STRING,
  match_type      STRING,
  pattern         STRING,
  publisher       STRING,
  enabled         BOOLEAN,
  snapshot_ts     TIMESTAMP
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/dim_software_whitelist/'
TBLPROPERTIES ('parquet.compress' = 'SNAPPY');

-- ── Inventario hardware (snapshot por host, consolidado ETL) ─────────────────

CREATE EXTERNAL TABLE IF NOT EXISTS fact_server_hardware (
  server_id       STRING      COMMENT 'inventory_hosts.id',
  node_id         STRING      COMMENT 'noc_devices.id (nullable)',
  hostname        STRING,
  site            STRING,
  manufacturer    STRING,
  model           STRING,
  serial_number   STRING,
  cpu_model       STRING,
  cpu_cores       INT,
  ram_mb          INT,
  disk_total_gb   DOUBLE,
  virtualization  STRING,
  os_name         STRING,
  os_version      STRING,
  os_arch         STRING,
  collected_at    TIMESTAMP
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_server_hardware/'
TBLPROPERTIES (
  'parquet.compress' = 'SNAPPY',
  'obserlgcr.source_table' = 'server_hardware,inventory_hosts'
);

-- ── Inventario software (histórico masivo — una fila por paquete/host/día) ───

CREATE EXTERNAL TABLE IF NOT EXISTS fact_server_software (
  server_id         STRING,
  node_id           STRING,
  hostname          STRING,
  site              STRING,
  name              STRING,
  version           STRING,
  publisher         STRING,
  install_date      STRING,
  package_manager   STRING,
  cpe               STRING,
  is_whitelisted    BOOLEAN,
  is_blacklisted    BOOLEAN,
  collected_at      TIMESTAMP,
  governance_status STRING      COMMENT 'approved|forbidden|unapproved|unknown'
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_server_software/'
TBLPROPERTIES (
  'parquet.compress' = 'SNAPPY',
  'obserlgcr.source_table' = 'server_software'
);

-- ── Métricas agregadas (roll-up horario desde TimescaleDB → lake) ─────────────

CREATE EXTERNAL TABLE IF NOT EXISTS fact_cpu_usage_hourly (
  node_id       STRING,
  hostname      STRING,
  site          STRING,
  hour_ts       TIMESTAMP,
  avg_usage_pct DOUBLE,
  max_usage_pct DOUBLE,
  p95_usage_pct DOUBLE,
  sample_count  BIGINT
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_cpu_usage_hourly/';

CREATE EXTERNAL TABLE IF NOT EXISTS fact_memory_usage_hourly (
  node_id         STRING,
  hostname        STRING,
  site            STRING,
  hour_ts         TIMESTAMP,
  avg_usage_pct   DOUBLE,
  max_usage_pct   DOUBLE,
  sample_count    BIGINT
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_memory_usage_hourly/';

CREATE EXTERNAL TABLE IF NOT EXISTS fact_network_traffic_hourly (
  node_id       STRING,
  hostname      STRING,
  site          STRING,
  iface         STRING,
  hour_ts       TIMESTAMP,
  avg_rx_bps    DOUBLE,
  avg_tx_bps    DOUBLE,
  max_rx_bps    DOUBLE,
  max_tx_bps    DOUBLE,
  avg_rtt_ms    DOUBLE
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_network_traffic_hourly/';

-- ── Keepalive / disponibilidad ───────────────────────────────────────────────

CREATE EXTERNAL TABLE IF NOT EXISTS fact_keepalive_events (
  node_id         STRING,
  hostname        STRING,
  site            STRING,
  event_ts        TIMESTAMP,
  status          STRING      COMMENT 'online|offline|degraded|unknown',
  rtt_ms          DOUBLE,
  agent_version   STRING,
  source          STRING,
  downtime_secs   BIGINT      COMMENT 'calculado en ETL si transición offline'
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_keepalive_events/';

-- ── Logs estructurados (ORC alternativo para texto largo — descomentar si prefieres)
-- CREATE EXTERNAL TABLE fact_system_logs (...)
-- STORED AS ORC LOCATION 's3a://obserlgcr-lake/noc/fact_system_logs/'
-- TBLPROPERTIES ('orc.compress' = 'SNAPPY');

CREATE EXTERNAL TABLE IF NOT EXISTS fact_system_logs (
  log_id          STRING,
  node_id         STRING,
  hostname        STRING,
  site            STRING,
  event_ts        TIMESTAMP,
  severity        STRING,
  source          STRING,
  log_type        STRING,
  message         STRING,
  raw_json        STRING      COMMENT 'JSON serializado del campo raw'
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_system_logs/'
TBLPROPERTIES ('parquet.compress' = 'SNAPPY');

-- ── Incidentes de gobernanza (cola procesada + histórico) ───────────────────

CREATE EXTERNAL TABLE IF NOT EXISTS fact_governance_incidents (
  queue_id        STRING,
  case_id         STRING,
  incident_type   STRING,
  severity        STRING,
  hostname        STRING,
  server_id       STRING,
  software_name   STRING,
  software_version STRING,
  rule_pattern    STRING,
  created_at      TIMESTAMP,
  processed_at    TIMESTAMP,
  status          STRING
)
PARTITIONED BY (dt STRING, region STRING)
STORED AS PARQUET
LOCATION 's3a://obserlgcr-lake/noc/fact_governance_incidents/';

-- ── Vista lógica de catálogo unificado (para Trino/Presto si aplica) ──────────
-- En Hive 3+: CREATE VIEW ...

-- MSCK REPAIR TABLE obserlgcr_noc.fact_server_software;
-- MSCK REPAIR TABLE obserlgcr_noc.fact_keepalive_events;
