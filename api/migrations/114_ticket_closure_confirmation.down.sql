-- 114_ticket_closure_confirmation.down.sql — revierte 114_ticket_closure_confirmation.sql
ALTER TABLE tickets DROP COLUMN IF EXISTS closure_requested_at;
DROP TABLE IF EXISTS ticket_closure_confirmations;
