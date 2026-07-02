-- 133_noc_heartbeat_timeout_agent.sql
-- El agente NOC corre cada 5 min (cron) + jitter hasta 120 s.
-- Timeout 120 s provoca alertas down/up en cada ciclo (falso positivo).
-- Default seguro: 480 s (8 min) = intervalo + jitter + margen watcher.

ALTER TABLE noc_devices
  ALTER COLUMN heartbeat_timeout_secs SET DEFAULT 480;

UPDATE noc_devices
SET heartbeat_timeout_secs = 480
WHERE heartbeat_timeout_secs <= 120;
