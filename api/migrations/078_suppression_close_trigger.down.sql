-- Down de mig 078 — quita el trigger de supresión transaccional al cerrar.
-- No revierte las supresiones ya escritas (son datos válidos); solo el mecanismo.
DROP TRIGGER IF EXISTS trg_suppress_on_close ON incident_cases_pg;
DROP FUNCTION IF EXISTS legacyhunt_soc.trg_suppress_on_close();
