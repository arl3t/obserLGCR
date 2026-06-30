/**
 * Evalúa dispositivos sin heartbeat reciente y crea alertas de caída.
 * Portado desde lgcrTI cron/noc/heartbeat-watcher.
 */
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { syncNocDownIncidents } from "./nocIncidentBridge.mjs";

export async function runNocHeartbeatWatcher() {
  const stale = await pgQuery(`
    SELECT id, hostname, last_seen_at, heartbeat_timeout_secs
    FROM noc_devices
    WHERE status NOT IN ('offline', 'unknown')
      AND last_seen_at IS NOT NULL
      AND last_seen_at < NOW() - (heartbeat_timeout_secs || ' seconds')::INTERVAL
  `);

  let wentOffline = 0;
  let alertsCreated = 0;

  for (const device of stale) {
    await pgQuery("UPDATE noc_devices SET status = 'offline' WHERE id = $1", [device.id]);
    wentOffline++;

    const existing = await pgQuery(
      `SELECT id FROM noc_alerts
       WHERE device_id = $1 AND alert_type = 'down' AND status = 'open'
       LIMIT 1`,
      [device.id],
    );

    if (existing.length === 0) {
      await pgQuery(
        `INSERT INTO noc_alerts (device_id, alert_type, details)
         VALUES ($1, 'down', $2)`,
        [
          device.id,
          JSON.stringify({
            down_since: new Date().toISOString(),
            last_seen_at: device.last_seen_at,
          }),
        ],
      );
      alertsCreated++;

      await pgQuery(
        `INSERT INTO noc_logs (device_id, severity, source, message)
         VALUES ($1, 'error', 'heartbeat-watcher', $2)`,
        [
          device.id,
          `Device offline: no heartbeat recibido en ${device.heartbeat_timeout_secs} segundos`,
        ],
      );
    }
  }

  let incidentSync = { created: 0 };
  try {
    incidentSync = await syncNocDownIncidents();
  } catch (err) {
    logger.error("noc_incident_sync_after_watcher", { msg: err.message });
  }

  if (wentOffline > 0 || alertsCreated > 0) {
    logger.info("noc_heartbeat_watcher", {
      wentOffline,
      alertsCreated,
      incidentsCreated: incidentSync.created ?? 0,
      checked: stale.length,
    });
  }

  return {
    checked: stale.length,
    went_offline: wentOffline,
    alerts_created: alertsCreated,
    incidents_created: incidentSync.created ?? 0,
  };
}
