-- Down 067 — revertir el marcador del backfill. Solo afecta filas con la
-- reason específica que esta migration usó (no toca cierres legítimos).
UPDATE incident_cases_pg
   SET auto_closed_at = NULL,
       auto_closed_reason = NULL,
       resolved_at = NULL
 WHERE auto_closed_reason = 'AUTO-CERRADO: severidad LOW — backfill 067 (DAG sync histórico)';
