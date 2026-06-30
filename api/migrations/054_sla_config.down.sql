-- Rollback de 054_sla_config.sql
-- Solo drop si los call sites volvieron a usar constantes hardcoded.
-- Si la tabla está en uso, el rollback debe ir acompañado de revertir
-- el código que importa services/slaConfig.mjs.

DROP TABLE IF EXISTS legacyhunt_soc.sla_config_audit;
DROP TABLE IF EXISTS legacyhunt_soc.sla_config;
