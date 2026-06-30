-- 125_snmp_sync_window_fix.sql
-- Sync gobernanza: usar último snapshot SNMP (no ventana 2h estricta).

CREATE OR REPLACE FUNCTION sync_snmp_software_to_governance(
  p_device_ip INET,
  p_hostname  TEXT DEFAULT NULL
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_host_id UUID;
  v_node_id UUID;
  v_hostname TEXT;
  v_count INTEGER := 0;
  v_last_poll TIMESTAMPTZ;
  r RECORD;
BEGIN
  SELECT MAX(collected_at) INTO v_last_poll
    FROM snmp_software_inventory WHERE device_ip = p_device_ip;

  IF v_last_poll IS NULL THEN
    RETURN 0;
  END IF;

  SELECT id INTO v_node_id FROM noc_devices
   WHERE ip_address = p_device_ip OR host(ip_address) = host(p_device_ip)
   LIMIT 1;

  v_hostname := COALESCE(
    p_hostname,
    (SELECT hostname FROM noc_devices WHERE id = v_node_id),
    (SELECT sys_name FROM snmp_availability WHERE device_ip = p_device_ip ORDER BY time DESC LIMIT 1),
    host(p_device_ip)
  );

  SELECT id INTO v_host_id FROM inventory_hosts
   WHERE lower(hostname) = lower(v_hostname)
      OR ip_address = host(p_device_ip)
   LIMIT 1;

  IF v_host_id IS NULL THEN
    INSERT INTO inventory_hosts (identity_key, hostname, ip_address, agent_type, last_report_at, report_count)
    VALUES ('snmp:' || host(p_device_ip), v_hostname, host(p_device_ip), 'snmp-telegraf', v_last_poll, 1)
    RETURNING id INTO v_host_id;
  END IF;

  DELETE FROM server_software WHERE server_id = v_host_id;

  FOR r IN
    SELECT DISTINCT ON (lower(sw_name))
      sw_name, sw_installed_date, sw_path
    FROM snmp_software_inventory
    WHERE device_ip = p_device_ip
      AND collected_at >= v_last_poll - INTERVAL '10 minutes'
    ORDER BY lower(sw_name), collected_at DESC
  LOOP
    INSERT INTO server_software (
      server_id, node_id, hostname, name, version, publisher, install_date, package_manager
    ) VALUES (
      v_host_id, v_node_id, v_hostname, r.sw_name, NULL, NULL,
      r.sw_installed_date, 'snmp-hrSWInstalledTable'
    );
    v_count := v_count + 1;
  END LOOP;

  UPDATE inventory_hosts
     SET software_count = v_count, last_report_at = v_last_poll
   WHERE id = v_host_id;

  RETURN v_count;
END;
$$;
