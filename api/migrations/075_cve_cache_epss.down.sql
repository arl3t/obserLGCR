-- Rollback 075 — quita las columnas EPSS del cache de CVEs.
ALTER TABLE legacyhunt_soc.cve_cache DROP COLUMN IF EXISTS epss_score;
ALTER TABLE legacyhunt_soc.cve_cache DROP COLUMN IF EXISTS epss_percentile;
ALTER TABLE legacyhunt_soc.cve_cache DROP COLUMN IF EXISTS epss_fetched_at;
