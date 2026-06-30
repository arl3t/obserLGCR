-- 123_software_governance_source_log.sql
-- source_log para incidentes de gobernanza de software + config whitelist estricta.

INSERT INTO legacyhunt_soc.source_log_catalog
  (source_log, sensor_name, sensor_family, source_category, network_zone, iceberg_table, notes)
VALUES
  ('software_governance', 'Gobernanza Software', 'manual', 'other', 'internal', NULL,
   'Software prohibido o no aprobado detectado en inventario de hosts.'),
  ('noc_metrics', 'NOC Métricas', 'syslog', 'other', 'internal', NULL,
   'Umbrales de CPU/memoria/latencia superados en agente NOC.')
ON CONFLICT (source_log) DO UPDATE SET
  sensor_name     = EXCLUDED.sensor_name,
  sensor_family   = EXCLUDED.sensor_family,
  source_category = EXCLUDED.source_category,
  network_zone    = EXCLUDED.network_zone,
  notes           = EXCLUDED.notes,
  updated_at      = NOW();

CREATE TABLE IF NOT EXISTS software_governance_config (
  id                BOOLEAN PRIMARY KEY DEFAULT true CHECK (id = true),
  strict_whitelist  BOOLEAN NOT NULL DEFAULT false,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO software_governance_config (id, strict_whitelist)
VALUES (true, false)
ON CONFLICT (id) DO NOTHING;

-- Actualizar trigger: unapproved solo si strict_whitelist = true
CREATE OR REPLACE FUNCTION trg_server_software_governance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  bl RECORD;
  wl_found BOOLEAN := false;
  strict_wl BOOLEAN := false;
  v_dedup TEXT;
BEGIN
  SELECT strict_whitelist INTO strict_wl FROM software_governance_config WHERE id = true;

  SELECT EXISTS (
    SELECT 1 FROM software_whitelist w
    WHERE w.enabled
      AND noc_match_software_rule(NEW.name, NEW.version, NEW.publisher,
                                  w.match_type, w.pattern, w.publisher)
  ) INTO wl_found;

  NEW.is_whitelisted := wl_found;
  NEW.is_blacklisted := false;

  FOR bl IN
    SELECT id, software_name, match_type, pattern, publisher, severity, auto_incident, mitre_technique
    FROM software_blacklist
    WHERE enabled
  LOOP
    IF noc_match_software_rule(NEW.name, NEW.version, NEW.publisher,
                               bl.match_type, bl.pattern, bl.publisher) THEN
      NEW.is_blacklisted := true;

      IF bl.auto_incident THEN
        v_dedup := encode(
          digest(
            lower(NEW.hostname) || '|forbidden_software|' ||
            lower(bl.pattern) || '|' || lower(COALESCE(NEW.version, '')),
            'sha256'
          ),
          'hex'
        );

        INSERT INTO incidents_queue (
          incident_type, severity, server_id, node_id, hostname,
          dedup_key, payload, status
        )
        VALUES (
          'forbidden_software',
          bl.severity,
          NEW.server_id,
          NEW.node_id,
          NEW.hostname,
          v_dedup,
          jsonb_build_object(
            'rule_id', bl.id,
            'rule_name', bl.software_name,
            'match_type', bl.match_type,
            'pattern', bl.pattern,
            'software_name', NEW.name,
            'software_version', NEW.version,
            'publisher', NEW.publisher,
            'mitre_technique', bl.mitre_technique,
            'server_software_id', NEW.id,
            'collected_at', NEW.collected_at
          ),
          'pending'
        )
        ON CONFLICT (dedup_key) WHERE (status = 'pending') DO NOTHING;
      END IF;

      EXIT;
    END IF;
  END LOOP;

  IF strict_wl AND NOT wl_found AND NOT NEW.is_blacklisted THEN
    v_dedup := encode(
      digest(lower(NEW.hostname) || '|unapproved|' || lower(NEW.name), 'sha256'),
      'hex'
    );
    INSERT INTO incidents_queue (
      incident_type, severity, server_id, node_id, hostname,
      dedup_key, payload, status
    )
    VALUES (
      'unapproved_software',
      'MEDIUM',
      NEW.server_id,
      NEW.node_id,
      NEW.hostname,
      v_dedup,
      jsonb_build_object(
        'software_name', NEW.name,
        'software_version', NEW.version,
        'publisher', NEW.publisher,
        'policy', 'whitelist_enforced'
      ),
      'pending'
    )
    ON CONFLICT (dedup_key) WHERE (status = 'pending') DO NOTHING;
  END IF;

  RETURN NEW;
END;
$$;
