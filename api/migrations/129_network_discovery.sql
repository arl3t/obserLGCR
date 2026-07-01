-- Módulo de descubrimiento de red (nmap completo): jobs, runs, hosts, puertos, documentación.

CREATE TABLE IF NOT EXISTS network_discovery_jobs (
  id               SERIAL PRIMARY KEY,
  name             VARCHAR(128) NOT NULL,
  description      TEXT,
  targets          TEXT NOT NULL,
  scan_profile     VARCHAR(32) NOT NULL DEFAULT 'discovery',
  custom_args      TEXT,
  schedule_cron    VARCHAR(64),
  schedule_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  auto_sync_ipam   BOOLEAN NOT NULL DEFAULT FALSE,
  ipam_subnet_id   INTEGER REFERENCES ipam_subnets(id) ON DELETE SET NULL,
  last_run_at      TIMESTAMPTZ,
  last_run_id      BIGINT,
  created_by       VARCHAR(255),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nd_jobs_schedule ON network_discovery_jobs (schedule_enabled) WHERE schedule_enabled IS TRUE;

CREATE TABLE IF NOT EXISTS network_discovery_runs (
  id             BIGSERIAL PRIMARY KEY,
  job_id         INTEGER REFERENCES network_discovery_jobs(id) ON DELETE SET NULL,
  name           VARCHAR(128),
  targets        TEXT NOT NULL,
  scan_profile   VARCHAR(32) NOT NULL,
  nmap_command   TEXT,
  status         VARCHAR(16) NOT NULL DEFAULT 'pending',
  started_at     TIMESTAMPTZ,
  finished_at    TIMESTAMPTZ,
  duration_ms    INTEGER,
  hosts_up       INTEGER NOT NULL DEFAULT 0,
  hosts_total    INTEGER NOT NULL DEFAULT 0,
  ports_open     INTEGER NOT NULL DEFAULT 0,
  nmap_summary   TEXT,
  raw_xml        TEXT,
  stats_json     JSONB,
  error_message  TEXT,
  triggered_by   VARCHAR(255),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nd_runs_job ON network_discovery_runs (job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_nd_runs_status ON network_discovery_runs (status, created_at DESC);

CREATE TABLE IF NOT EXISTS network_discovery_hosts (
  id              BIGSERIAL PRIMARY KEY,
  run_id          BIGINT NOT NULL REFERENCES network_discovery_runs(id) ON DELETE CASCADE,
  ip_address      INET NOT NULL,
  hostname        VARCHAR(255),
  mac_address     MACADDR,
  status          VARCHAR(16) NOT NULL DEFAULT 'up',
  os_guess        VARCHAR(255),
  notes           TEXT,
  documented      BOOLEAN NOT NULL DEFAULT FALSE,
  documented_at   TIMESTAMPTZ,
  documented_by   VARCHAR(255),
  tags            TEXT[],
  UNIQUE (run_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_nd_hosts_run ON network_discovery_hosts (run_id);
CREATE INDEX IF NOT EXISTS idx_nd_hosts_doc ON network_discovery_hosts (run_id, documented);

CREATE TABLE IF NOT EXISTS network_discovery_ports (
  id          BIGSERIAL PRIMARY KEY,
  host_id     BIGINT NOT NULL REFERENCES network_discovery_hosts(id) ON DELETE CASCADE,
  port        INTEGER NOT NULL,
  protocol    VARCHAR(8) NOT NULL DEFAULT 'tcp',
  state       VARCHAR(16) NOT NULL,
  service     VARCHAR(64),
  product     VARCHAR(128),
  version     VARCHAR(128),
  extra_info  TEXT,
  UNIQUE (host_id, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_nd_ports_host ON network_discovery_ports (host_id);
CREATE INDEX IF NOT EXISTS idx_nd_ports_service ON network_discovery_ports (service);
