-- 093_drop_adoption_codes.sql
-- Elimina el mecanismo de adopción forzada por código (2026-06-08).
-- La tabla adoption_codes era write-only: el endpoint que validaba el código
-- (force-ack/adopt) se removió en mayo 2026, dejando la tabla sin lectores.
-- Tras retirar el popup (ForcedAcknowledgmentModal), las rutas force-ack y el
-- bloque de código en Slack, la tabla queda sin referencias → se dropea.
-- La adopción real fluye por POST /api/incidents/:caseId/adopt (gestión).
DROP TABLE IF EXISTS adoption_codes;
