-- Revierte 076: AUTO_CLOSED vuelve a 30 días.
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
            ELSE 14
        END;
    ELSIF p_reason = 'AUTO_CLOSED' THEN
        RETURN 30;
    ELSE
        RETURN CASE upper(p_severity)
            WHEN 'CRITICAL'    THEN 30
            WHEN 'HIGH'        THEN 30
            WHEN 'MEDIUM'      THEN 14
            ELSE 30
        END;
    END IF;
END;
$$;
