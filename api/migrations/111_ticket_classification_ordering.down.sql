-- 111_ticket_classification_ordering.down.sql
DROP TABLE IF EXISTS ticket_rules;
DROP TABLE IF EXISTS ticket_user_prefs;
DROP TABLE IF EXISTS ticket_saved_views;
DROP TABLE IF EXISTS ticket_watchers;
DROP TABLE IF EXISTS ticket_services;

DROP INDEX IF EXISTS idx_tickets_merged;
DROP INDEX IF EXISTS idx_tickets_snoozed;
DROP INDEX IF EXISTS idx_tickets_pinned;
DROP INDEX IF EXISTS idx_tickets_tags;
DROP INDEX IF EXISTS idx_tickets_service;
DROP INDEX IF EXISTS idx_tickets_type;

ALTER TABLE tickets
  DROP COLUMN IF EXISTS cc_contacts,
  DROP COLUMN IF EXISTS merged_into,
  DROP COLUMN IF EXISTS snoozed_until,
  DROP COLUMN IF EXISTS pinned,
  DROP COLUMN IF EXISTS ai_suggested,
  DROP COLUMN IF EXISTS sentiment,
  DROP COLUMN IF EXISTS tags,
  DROP COLUMN IF EXISTS service_id,
  DROP COLUMN IF EXISTS technical_severity,
  DROP COLUMN IF EXISTS ticket_type;
