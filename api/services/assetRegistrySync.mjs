/**
 * Sincroniza asset_registry desde noc_devices (scoring SOC).
 * Invocado tras alta/heartbeat/actualización de dispositivos NOC.
 */
import { pgQuery } from "../db/postgres.mjs";
import { invalidateAssetCache } from "./scoringBonus.mjs";
import { logger } from "../logger.mjs";

/**
 * @param {string | null} [ipAddress]
 * @returns {Promise<number>}
 */
export async function syncAssetRegistryFromNoc(ipAddress = null) {
  const params = [];
  let ipFilter = "";
  if (ipAddress) {
    params.push(ipAddress);
    ipFilter = "AND d.ip_address = $1::inet";
  }

  try {
    const result = await pgQuery(
      `INSERT INTO asset_registry (
         sensor_key, hostname, ip_address, asset_type, criticality,
         location, os_platform, description, updated_by
       )
       SELECT
         COALESCE(NULLIF(trim(d.hostname), ''), host(d.ip_address)::text),
         d.hostname,
         d.ip_address,
         CASE
           WHEN lower(d.device_type) IN ('router','switch','firewall','network','gateway')
             THEN 'network-device'
           WHEN lower(d.device_type) = 'printer' THEN 'printer'
           WHEN lower(d.device_type) IN ('iot','sensor') THEN 'iot'
           ELSE 'server'
         END,
         CASE
           WHEN lower(d.device_type) IN ('router','switch','firewall','network','gateway') THEN 'tier1'
           WHEN lower(d.device_type) = 'server' THEN 'tier2'
           WHEN d.site ILIKE '%dc%' OR d.site ILIKE '%datacenter%' THEN 'tier1'
           ELSE 'tier3'
         END,
         d.site,
         NULLIF(d.discovery_meta->>'os_guess', ''),
         COALESCE(NULLIF(trim(d.description), ''), 'Sincronizado desde NOC'),
         'asset-integration'
       FROM noc_devices d
       WHERE d.ip_address IS NOT NULL
         ${ipFilter}
       ON CONFLICT (sensor_key) DO UPDATE SET
         hostname = EXCLUDED.hostname,
         ip_address = EXCLUDED.ip_address,
         asset_type = EXCLUDED.asset_type,
         criticality = EXCLUDED.criticality,
         location = COALESCE(EXCLUDED.location, asset_registry.location),
         os_platform = COALESCE(EXCLUDED.os_platform, asset_registry.os_platform),
         description = CASE
           WHEN asset_registry.description LIKE 'Sincronizado%' THEN EXCLUDED.description
           ELSE asset_registry.description
         END,
         is_active = true,
         updated_at = NOW(),
         updated_by = 'asset-integration'`,
      params,
    );
    invalidateAssetCache();
    return result.rowCount ?? 0;
  } catch (err) {
    logger.warn({ err: err.message, ipAddress }, "asset_registry_sync_failed");
    return 0;
  }
}
