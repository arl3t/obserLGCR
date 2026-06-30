-- 107_ticket_message_report.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Permite adjuntar el INFORME del caso (HTML) a un mensaje del ticket, para que
-- el analista pueda enviárselo al cliente desde la Investigación y el cliente lo
-- abra en un modal (iframe sandboxed) desde el portal.
-- docs/PROPUESTA-TICKETING-PUBLICO.md §6 / §9.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE ticket_messages
  ADD COLUMN IF NOT EXISTS report_html TEXT;
