-- 057_cve_enrichment.down.sql — rollback de 057_cve_enrichment.sql

DROP INDEX IF EXISTS legacyhunt_soc.idx_cve_kev_ransomware;
DROP INDEX IF EXISTS legacyhunt_soc.idx_cve_kev_date_added;
DROP TABLE IF EXISTS legacyhunt_soc.cve_kev;

DROP INDEX IF EXISTS legacyhunt_soc.idx_cve_cache_vuln_status;
DROP INDEX IF EXISTS legacyhunt_soc.idx_cve_cache_ttl_until;
DROP TABLE IF EXISTS legacyhunt_soc.cve_cache;
