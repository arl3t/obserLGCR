-- 108_ticket_webhooks_api.down.sql — revierte F7 (webhooks + API pública).
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;
DROP TABLE IF EXISTS api_tokens;
