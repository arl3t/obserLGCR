-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 076 — R5 (audit 2026-06-05): alinear ventana de supresión AUTO_CLOSED
-- con la ventana de reapertura del DAG.
--
-- Problema: `suppression_days('AUTO_CLOSED', …)` devolvía 30 días, pero el DAG
-- incident_cases_sync_daily.py reabre un caso CERRADO cuyo dedup_key reaparece
-- dentro de `last_seen >= NOW() - INTERVAL '60 days'`. Entre el día 30 y el 60,
-- la supresión ya expiró pero el caso aún es reabrible → una recurrencia LOW
-- de bajo valor REABRE el caso en vez de seguir suprimida = re-churn parcial.
--
-- Fix: AUTO_CLOSED pasa de 30 → 60 días, cubriendo toda la ventana de reapertura.
-- La supresión sigue siendo severity-aware (si la severidad escala por encima de
-- la suprimida, el DAG la overridea igual), así que extenderla no enmascara
-- escaladas reales — sólo corta el churn de lo que de verdad es ruido.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION legacyhunt_soc.suppression_days(
    p_reason   VARCHAR,
    p_severity VARCHAR
) RETURNS INTEGER LANGUAGE plpgsql AS $$
BEGIN
    IF p_reason = 'FALSO_POSITIVO' THEN
        RETURN CASE upper(p_severity)
            WHEN 'CRITICAL'    THEN 60
            WHEN 'HIGH'        THEN 60
            WHEN 'MEDIUM'      THEN 30
            ELSE 14  -- LOW / NEGLIGIBLE
        END;
    ELSIF p_reason = 'AUTO_CLOSED' THEN
        RETURN 60;  -- R5: alineado con la ventana de reapertura del DAG (60d)
    ELSE  -- CERRADO / OPERATOR
        RETURN CASE upper(p_severity)
            WHEN 'CRITICAL'    THEN 30
            WHEN 'HIGH'        THEN 30
            WHEN 'MEDIUM'      THEN 14
            ELSE 30  -- LOW / NEGLIGIBLE
        END;
    END IF;
END;
$$;
