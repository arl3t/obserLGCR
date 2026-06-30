-- 057_cve_enrichment.sql
-- B1 audit Casos 2026-05-21 — enriquecimiento de CVEs con NVD + CISA KEV.
--
-- Dos tablas independientes:
--
--   1. cve_cache — cache local de metadata NVD (CVSS v3, CWE, descripción)
--      para evitar pegarle a services.nvd.nist.gov en cada request del panel
--      del caso. TTL 30 días; CVEs nuevos sin CVSS asignado ("AWAITING_ANALYSIS")
--      se reintentan más seguido (TTL 1 día) por si NVD los completa.
--
--   2. cve_kev — catálogo CISA Known Exploited Vulnerabilities. ~1200 entries
--      al 2026-05; pulled como bulk desde
--      https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
--      y refrescado por job/cron. La columna `known_ransomware_use` permite
--      escalar la criticidad del caso cuando aplica.
--
-- Ambas son self-bootstrap (services/nvdEnrichment.mjs y services/kevCatalog.mjs
-- llaman a ensureCveCacheTable / ensureKevTable al cargar), pero el .sql se
-- conserva para reproducibilidad histórica y rollback.

CREATE SCHEMA IF NOT EXISTS legacyhunt_soc;

-- ── cve_cache ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS legacyhunt_soc.cve_cache (
  cve_id              VARCHAR(32)  PRIMARY KEY,
  cvss_v3_score       NUMERIC(3,1),                   -- 0.0–10.0
  cvss_v3_severity    VARCHAR(16),                    -- LOW/MEDIUM/HIGH/CRITICAL
  cvss_v3_vector      VARCHAR(64),                    -- e.g. CVSS:3.1/AV:N/AC:L/...
  cvss_v2_score       NUMERIC(3,1),                   -- fallback cuando v3 = null
  cwe_ids             TEXT[],                         -- e.g. {CWE-502, CWE-94}
  description         TEXT,                           -- english NVD description
  reference_urls      TEXT[],                         -- top 10 refs
  published_at        TIMESTAMPTZ,
  last_modified       TIMESTAMPTZ,
  vuln_status         VARCHAR(32),                    -- ANALYZED / AWAITING_ANALYSIS / MODIFIED / REJECTED
  fetched_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  ttl_until           TIMESTAMPTZ  NOT NULL DEFAULT now() + INTERVAL '30 days'
);

CREATE INDEX IF NOT EXISTS idx_cve_cache_ttl_until    ON legacyhunt_soc.cve_cache (ttl_until);
CREATE INDEX IF NOT EXISTS idx_cve_cache_vuln_status  ON legacyhunt_soc.cve_cache (vuln_status);

-- ── cve_kev (CISA Known Exploited Vulnerabilities) ───────────────────────────
CREATE TABLE IF NOT EXISTS legacyhunt_soc.cve_kev (
  cve_id                 VARCHAR(32)  PRIMARY KEY,
  vendor_project         VARCHAR(128),
  product                VARCHAR(256),
  vulnerability_name     TEXT,
  date_added             DATE,
  short_description      TEXT,
  required_action        TEXT,
  due_date               DATE,
  known_ransomware_use   BOOLEAN      NOT NULL DEFAULT false,
  notes                  TEXT,
  cwes                   TEXT[],
  refreshed_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cve_kev_date_added     ON legacyhunt_soc.cve_kev (date_added DESC);
CREATE INDEX IF NOT EXISTS idx_cve_kev_ransomware     ON legacyhunt_soc.cve_kev (known_ransomware_use);
