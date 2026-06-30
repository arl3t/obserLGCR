/**
 * Configuración NOC persistida en PostgreSQL (SNMP, etc.).
 */
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const SNMP_DEFAULTS = {
  default_community: (process.env.SNMP_COMMUNITY ?? "public").trim() || "public",
  default_port: 161,
  default_version: "2c",
  poll_interval_sec: 60,
  discovery_communities: [],
};

export async function getSnmpSettings() {
  try {
    const [row] = await pgQuery(`SELECT value FROM noc_platform_settings WHERE key = 'snmp'`);
    if (!row?.value) return { ...SNMP_DEFAULTS };
    return { ...SNMP_DEFAULTS, ...row.value };
  } catch (err) {
    if (err.code === "42P01") return { ...SNMP_DEFAULTS };
    throw err;
  }
}

export async function updateSnmpSettings(patch) {
  const current = await getSnmpSettings();
  const next = {
    ...current,
    ...patch,
    default_community: String(patch.default_community ?? current.default_community).trim() || "public",
    default_port: Number(patch.default_port ?? current.default_port) || 161,
    default_version: String(patch.default_version ?? current.default_version) || "2c",
    poll_interval_sec: Number(patch.poll_interval_sec ?? current.poll_interval_sec) || 60,
    discovery_communities: Array.isArray(patch.discovery_communities)
      ? patch.discovery_communities.map((c) => String(c).trim()).filter(Boolean)
      : current.discovery_communities ?? [],
  };

  await pgQuery(
    `INSERT INTO noc_platform_settings (key, value, updated_at)
     VALUES ('snmp', $1::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [JSON.stringify(next)],
  );

  return next;
}

/** Vincula IP del activo NOC con snmp_targets usando community por defecto. */
export async function syncSnmpTargetForDevice(device) {
  if (!device?.ip_address) return null;
  try {
    const cfg = await getSnmpSettings();
    const [row] = await pgQuery(
      `INSERT INTO snmp_targets (device_ip, hostname, site, community, noc_device_id, enabled)
       VALUES ($1::inet, $2, $3, $4, $5, true)
       ON CONFLICT (device_ip) DO UPDATE SET
         hostname = COALESCE(EXCLUDED.hostname, snmp_targets.hostname),
         site = COALESCE(EXCLUDED.site, snmp_targets.site),
         noc_device_id = EXCLUDED.noc_device_id,
         community = CASE
           WHEN snmp_targets.community = 'public' THEN EXCLUDED.community
           ELSE snmp_targets.community
         END
       RETURNING id, device_ip::text AS device_ip, community`,
      [device.ip_address, device.hostname, device.site ?? null, cfg.default_community, device.id],
    );
    return row ?? null;
  } catch (err) {
    if (err.code !== "42P01") {
      logger.warn("snmp_target_sync_failed", { deviceId: device.id, msg: err.message });
    }
    return null;
  }
}
