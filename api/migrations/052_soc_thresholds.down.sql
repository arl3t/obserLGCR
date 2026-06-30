-- Rollback de 052_soc_thresholds.sql (P4 M3, audit 2026-05-13).
--
-- Antes de aplicar: el código (services/socThresholds.mjs) caerá a los
-- DEFAULTS de config.mjs cuando la tabla no exista. Confirmá que esos
-- defaults son aceptables para el SOC en producción.
--
-- Uso (manual, no automático):
--   psql -U huntdb -d huntdb -f migrations/052_soc_thresholds.down.sql

DROP INDEX IF EXISTS legacyhunt_soc.idx_soc_thresholds_audit_recent;
DROP TABLE IF EXISTS legacyhunt_soc.soc_thresholds_audit;
DROP TABLE IF EXISTS legacyhunt_soc.soc_thresholds;
