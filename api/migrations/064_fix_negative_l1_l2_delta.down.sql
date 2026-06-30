-- Down 064: no-op — el backfill no es reversible (no guardamos el adopted_at
-- "corrupto" anterior, porque conceptualmente era el valor incorrecto).
-- Para reproducir el bug, revertir el cambio de routes/incidents.mjs.
SELECT 1;
