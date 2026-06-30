-- 113_case_playbooks.down.sql — revierte 113_case_playbooks.sql
ALTER TABLE tickets         DROP COLUMN IF EXISTS soc_last_read_at;
ALTER TABLE ticket_messages DROP COLUMN IF EXISTS playbook_html;
DROP TABLE IF EXISTS case_playbooks;
