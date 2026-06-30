-- 059_sync_runs.sql
-- Métricas de las corridas del DAG s3_to_minio_unified_sync (1 fila por
-- (dag_run, fuente)). Permite consultar "última sync OK por fuente",
-- "throughput de copiado por hora", y alertar si una fuente lleva > N min
-- sin sync exitoso.
--
-- Llena: data/airflow/dags/s3_to_minio_unified_sync.py (insert al final
-- de cada task, en bloque único para evitar parcialidad si la conexión cae).
-- Consume (futuro): endpoint /api/sync-runs/health + widget en /leader.
--
-- Tamaño esperado: 6 fuentes × 96 corridas/día × 30 días = ~17k rows/mes.
-- Despreciable; igualmente se agregan índices para mantener queries en sub-ms.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.sync_runs (
  id                BIGSERIAL    PRIMARY KEY,
  dag_id            VARCHAR(64)  NOT NULL,
  dag_run_id        VARCHAR(250) NOT NULL,                   -- AIRFLOW dag_run.run_id
  source            VARCHAR(64)  NOT NULL,                   -- ej "syslog", "wazuh_fluent"
  run_started_at    TIMESTAMPTZ  NOT NULL,
  run_ended_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  duration_ms       INTEGER      NOT NULL,
  copied            INTEGER      NOT NULL DEFAULT 0,         -- objetos copiados S3→MinIO
  skipped           INTEGER      NOT NULL DEFAULT 0,         -- objetos saltados (size match)
  errors            INTEGER      NOT NULL DEFAULT 0,         -- copy errors (no fatal)
  partition_refresh_ok BOOLEAN   NOT NULL DEFAULT false,     -- sync_partition_metadata ok
  partition_refresh_msg TEXT,                                -- mensaje si !ok
  lookback_hours    INTEGER      NOT NULL DEFAULT 25,
  bytes_copied      BIGINT       NOT NULL DEFAULT 0          -- sum de obj.Size copiados
);

-- "Última corrida por fuente" — query típica del dashboard de salud.
CREATE INDEX IF NOT EXISTS idx_sync_runs_source_ended
  ON legacyhunt_soc.sync_runs (source, run_ended_at DESC);

-- "Histórico por dag_run_id" — debug cuando una corrida falla parcialmente.
CREATE INDEX IF NOT EXISTS idx_sync_runs_dag_run
  ON legacyhunt_soc.sync_runs (dag_run_id);
