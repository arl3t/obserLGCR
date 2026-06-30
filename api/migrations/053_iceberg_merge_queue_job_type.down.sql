-- Rollback de 053 (P4 C3, audit 2026-05-13).
-- Antes de aplicar: detener el worker; jobs `status_sync` pendientes
-- quedarán sin procesar (volverán a tomarse como 'merge' por el
-- worker viejo y fallarán por shape de payload incompatible).

DROP INDEX IF EXISTS legacyhunt_soc.idx_imq_job_type_status;

ALTER TABLE legacyhunt_soc.iceberg_merge_queue
  DROP CONSTRAINT IF EXISTS chk_imq_job_type;

ALTER TABLE legacyhunt_soc.iceberg_merge_queue
  DROP COLUMN IF EXISTS job_type;
