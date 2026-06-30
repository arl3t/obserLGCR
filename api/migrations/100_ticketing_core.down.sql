-- 100_ticketing_core.down.sql — revierte el núcleo de ticketing.
-- Orden inverso por dependencias FK (ON DELETE CASCADE cae con la tabla padre,
-- pero se dropean explícitas para claridad).
DROP TABLE IF EXISTS ticket_case_links;
DROP TABLE IF EXISTS ticket_messages;
DROP TABLE IF EXISTS tickets;
