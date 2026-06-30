-- Rollback de 051_iceberg_merge_queue.sql (P4 M3, audit 2026-05-13).
--
-- Si necesitás revertir, primero asegurate de que la cola esté vacía o que
-- el drift PG↔Iceberg de jobs pending/failed sea aceptable — la tabla NO se
-- recupera tras el DROP.
--
-- Uso (manual, no automático):
--   psql -U huntdb -d huntdb -f migrations/051_iceberg_merge_queue.down.sql

DROP INDEX IF EXISTS legacyhunt_soc.idx_imq_failed;
DROP INDEX IF EXISTS legacyhunt_soc.idx_imq_pending_due;
DROP TABLE IF EXISTS legacyhunt_soc.iceberg_merge_queue;
