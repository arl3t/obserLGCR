/**
 * Evalúa dispositivos sin heartbeat reciente y crea alertas de caída.
 * Dual-write: keepalive_status (TimescaleDB) + incidents_queue.
 */
import { createHash } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { syncNocDownIncidents } from "./nocIncidentBridge.mjs";
import { ingestKeepaliveOffline } from "./nocTimescale.mjs";

function dedupKeyKeepalive(hostname) {
  return createHash("sha256").update(`${hostname.toLowerCase()}|keepalive_down`).digest("hex");
}

export async function runNocHeartbeatWatcher() {
  const stale = await pgQuery(`
    SELECT d.id, d.hostname, d.site, d.last_seen_at, d.heartbeat_timeout_secs
    FROM noc_devices d
    WHERE d.status NOT IN ('offline', 'unknown')
      AND d.last_seen_at IS NOT NULL
      AND d.last_seen_at < NOW() - (d.heartbeat_timeout_secs || ' seconds')::INTERVAL
  `);

  let wentOffline = 0;
  let alertsCreated = 0;
  let queuedIncidents = 0;

  for (const device of stale) {
    await pgQuery("UPDATE noc_devices SET status = 'offline' WHERE id = $1", [device.id]);
    wentOffline++;

    await ingestKeepaliveOffline({
      nodeId: device.id,
      hostname: device.hostname,
      site: device.site,
      region: device.site ?? "global",
      lastSeenAt: device.last_seen_at,
      timeoutSecs: device.heartbeat_timeout_secs,
    }).catch(() => {});

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

      try {
        await pgQuery(
          `INSERT INTO incidents_queue (
             incident_type, severity, node_id, hostname, dedup_key, payload, status
           ) VALUES ('keepalive_down', 'HIGH', $1, $2, $3, $4::jsonb, 'pending')
           ON CONFLICT (dedup_key) WHERE (status = 'pending') DO NOTHING`,
          [
            device.id,
            device.hostname,
            dedupKeyKeepalive(device.hostname),
            JSON.stringify({
              last_seen_at: device.last_seen_at,
              timeout_secs: device.heartbeat_timeout_secs,
              site: device.site,
            }),
          ],
        );
        queuedIncidents++;
      } catch (err) {
        if (err.code !== "42P01") {
          logger.warn("keepalive_incidents_queue_failed", { msg: err.message });
        }
      }
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
      queuedIncidents,
      incidentsCreated: incidentSync.created ?? 0,
      checked: stale.length,
    });
  }

  return {
    checked: stale.length,
    went_offline: wentOffline,
    alerts_created: alertsCreated,
    queued_incidents: queuedIncidents,
    incidents_created: incidentSync.created ?? 0,
  };
}
