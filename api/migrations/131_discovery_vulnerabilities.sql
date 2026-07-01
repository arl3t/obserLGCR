-- CVE / vulnerabilidades detectadas por scripts NSE (nmap --script vuln).

ALTER TABLE network_discovery_jobs
  ADD COLUMN IF NOT EXISTS scan_cves BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE network_discovery_runs
  ADD COLUMN IF NOT EXISTS scan_cves BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS network_discovery_vulnerabilities (
  id          BIGSERIAL PRIMARY KEY,
  host_id     BIGINT NOT NULL REFERENCES network_discovery_hosts(id) ON DELETE CASCADE,
  cve_id      VARCHAR(32) NOT NULL,
  severity    VARCHAR(16),
  cvss_score  NUMERIC(4, 1),
  title       TEXT,
  port        INTEGER,
  protocol    VARCHAR(8),
  script_id   VARCHAR(128),
  details     TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nd_vulns_host ON network_discovery_vulnerabilities (host_id);
CREATE INDEX IF NOT EXISTS idx_nd_vulns_cve ON network_discovery_vulnerabilities (cve_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nd_vulns_host_cve_port_script
  ON network_discovery_vulnerabilities (host_id, cve_id, COALESCE(port, -1), COALESCE(script_id, ''));
