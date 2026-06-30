-- 082_integration_credentials.down.sql — rollback de 082.
-- Las keys vuelven a resolverse sólo desde .env (process.env).
DROP TABLE IF EXISTS legacyhunt_soc.integration_credentials;
