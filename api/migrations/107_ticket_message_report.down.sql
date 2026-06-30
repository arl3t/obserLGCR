-- 107_ticket_message_report.down.sql
ALTER TABLE ticket_messages DROP COLUMN IF EXISTS report_html;
