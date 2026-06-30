-- 056_source_log_catalog.down.sql — rollback de 056_source_log_catalog.sql

DROP INDEX IF EXISTS legacyhunt_soc.idx_source_log_catalog_zone;
DROP INDEX IF EXISTS legacyhunt_soc.idx_source_log_catalog_category;
DROP INDEX IF EXISTS legacyhunt_soc.idx_source_log_catalog_family;

DROP TABLE IF EXISTS legacyhunt_soc.source_log_catalog;
