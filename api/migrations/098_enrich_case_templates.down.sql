-- Down de 098 — sólo elimina la plantilla nueva. El contenido enriquecido de
-- las built-in (UPDATE) no se revierte automáticamente; re-aplicar 006 lo
-- restauraría al seed original si hiciera falta.
DELETE FROM case_templates WHERE id = 'tpl_ransomware' AND is_builtin;
