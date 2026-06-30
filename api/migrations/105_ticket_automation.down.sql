-- 105_ticket_automation.down.sql
DROP INDEX IF EXISTS idx_tickets_resolved_open;
DROP INDEX IF EXISTS idx_tickets_waiting_client;
DROP TABLE IF EXISTS ticket_automation_config;
ALTER TABLE tickets
  DROP COLUMN IF EXISTS last_reminder_at,
  DROP COLUMN IF EXISTS csat_score,
  DROP COLUMN IF EXISTS csat_comment,
  DROP COLUMN IF EXISTS csat_at;
