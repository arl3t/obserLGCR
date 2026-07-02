-- Programación por intervalo y gobernanza de activos nuevos en descubrimiento.

ALTER TABLE network_discovery_jobs
  ADD COLUMN IF NOT EXISTS schedule_interval_minutes INTEGER,
  ADD COLUMN IF NOT EXISTS detect_new_assets BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS open_incidents_on_unacked BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE network_discovery_jobs
  DROP CONSTRAINT IF EXISTS chk_nd_jobs_interval_min;

ALTER TABLE network_discovery_jobs
  ADD CONSTRAINT chk_nd_jobs_interval_min
  CHECK (schedule_interval_minutes IS NULL OR schedule_interval_minutes >= 15);
