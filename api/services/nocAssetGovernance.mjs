/**
 * Gobernanza de inventario NOC: activos sin ACK → incidents_queue → Gestión.
 */
import { createHash } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const ENABLED = process.env.NOC_INVENTORY_GOVERNANCE?.trim() !== "false";
const SCAN_INTERVAL_MS = parseInt(process.env.NOC_INVENTORY_GOVERNANCE_INTERVAL_MS ?? "60000", 10);

function dedupKey(deviceId, incidentType = "unknown_asset") {
  return createHash("sha256")
    .update(`${deviceId}|${incidentType}`)
    .digest("hex");
}

/**
 * Encola incidente por activo no reconocido (idempotente mientras pending).
 */
export async function enqueueUnknownAssetIncident(device, source = "discovery") {
  if (!ENABLED || !device?.id) return { enqueued: false };

  const [row] = await pgQuery(
    `SELECT id, hostname, ip_address::text AS ip_address, inventory_ack, discovered_via
       FROM noc_devices WHERE id = $1`,
    [device.id],
  );
  if (!row || row.inventory_ack) return { enqueued: false, reason: "already_acknowledged" };

  const payload = {
    noc_device_id: row.id,
    ip_address: row.ip_address,
    hostname: row.hostname,
    discovered_via: source || row.discovered_via || "discovery",
    policy: "inventory_ack_required",
    ...(device.payload ?? {}),
  };

  const dk = dedupKey(row.id);
  const inserted = await pgQuery(
    `INSERT INTO incidents_queue (
       incident_type, severity, node_id, hostname, dedup_key, payload, status
     ) VALUES (
       'unknown_asset', 'HIGH', $1, $2, $3, $4::jsonb, 'pending'
     )
     ON CONFLICT (dedup_key) WHERE (status = 'pending') DO NOTHING
     RETURNING id`,
    [row.id, row.hostname, dk, JSON.stringify(payload)],
  );

  if (inserted.length) {
    logger.info({
      msg: "unknown_asset_enqueued",
      deviceId: row.id,
      hostname: row.hostname,
      source,
    });
    return { enqueued: true, queueId: inserted[0].id };
  }
  return { enqueued: false, reason: "duplicate_pending" };
}

/**
 * Reconoce un activo (ACK inventario) y suprime cola pendiente.
 */
export async function acknowledgeInventoryDevice(deviceId, actor, notes = null) {
  const [dev] = await pgQuery(
    `UPDATE noc_devices
        SET inventory_ack = TRUE,
            inventory_ack_at = NOW(),
            inventory_ack_by = $2,
            inventory_ack_notes = COALESCE($3, inventory_ack_notes),
            updated_at = NOW()
      WHERE id = $1
      RETURNING id, hostname, ip_address::text AS ip_address, inventory_ack_at`,
    [deviceId, actor, notes],
  );
  if (!dev) return null;

  try {
    await pgQuery(
      `UPDATE incidents_queue
          SET status = 'suppressed', processed_at = NOW(),
              error_message = 'Activo reconocido (inventory ACK)'
        WHERE node_id = $1
          AND incident_type IN ('unknown_asset', 'undocumented_host')
          AND status = 'pending'`,
      [deviceId],
    );
  } catch (err) {
    logger.warn({ msg: "inventory_ack_queue_suppress_failed", deviceId, error: err.message });
  }

  try {
    await pgQuery(
      `UPDATE incident_cases_pg c
          SET timeline = COALESCE(timeline, '[]'::jsonb) || jsonb_build_array(
                jsonb_build_object(
                  'ts', to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                  'action', 'INVENTORY_ACK',
                  'operator', $2::text,
                  'detail', 'Activo reconocido en inventario NOC'
                )
              ),
              updated_at = NOW()
        WHERE c.status NOT IN ('CERRADO', 'FALSO_POSITIVO')
          AND c.source_log = 'noc_inventory_governance'
          AND (
            c.enrichment_data->>'noc_device_id' = $1::text
            OR c.enrichment_data->'payload'->>'noc_device_id' = $1::text
            OR c.hostname = $3::text
          )`,
      [deviceId, actor, dev.hostname],
    );
  } catch (err) {
    logger.warn({ msg: "inventory_ack_case_timeline_failed", deviceId, error: err.message });
  }

  if (dev.ip_address) {
    try {
      await pgQuery(
        `UPDATE network_discovery_hosts h
            SET documented = TRUE,
                documented_at = NOW(),
                documented_by = $2::text
          WHERE h.ip_address = $1::inet
            AND h.run_id = (
              SELECT MAX(run_id) FROM network_discovery_hosts WHERE ip_address = $1::inet
            )`,
        [dev.ip_address, actor],
      );
    } catch (err) {
      logger.warn({ msg: "inventory_ack_discovery_document_failed", deviceId, error: err.message });
    }
  }

  logger.info({ msg: "inventory_ack", deviceId, hostname: dev.hostname, actor });
  return dev;
}

/**
 * Al cerrar un caso de gobernanza (inventario/descubrimiento), suprime cola pendiente.
 */
export async function onGovernanceCaseClosed(caseId, actor = "operator") {
  const [row] = await pgQuery(
    `SELECT source_log, enrichment_data FROM incident_cases_pg WHERE id = $1`,
    [caseId],
  );
  if (!row || !["noc_inventory_governance", "software_governance"].includes(row.source_log)) {
    return { updated: false };
  }

  const ed = typeof row.enrichment_data === "string"
    ? (() => { try { return JSON.parse(row.enrichment_data); } catch { return {}; } })()
    : (row.enrichment_data ?? {});
  const payload = ed.payload ?? {};
  const deviceId = ed.noc_device_id ?? ed.node_id ?? payload.noc_device_id ?? null;
  const queueId = ed.incidents_queue_id ?? null;

  try {
    if (deviceId) {
      await pgQuery(
        `UPDATE incidents_queue
            SET status = 'suppressed', processed_at = NOW(),
                error_message = 'Caso cerrado en gestión'
          WHERE node_id = $1
            AND status = 'pending'`,
        [deviceId],
      );
    }
    if (queueId) {
      await pgQuery(
        `UPDATE incidents_queue
            SET status = 'done', processed_at = COALESCE(processed_at, NOW()),
                error_message = NULL
          WHERE id = $1
            AND status IN ('pending', 'processing')`,
        [queueId],
      );
    }
    logger.info({ msg: "governance_case_closed", caseId, deviceId, queueId, actor });
    return { updated: true, deviceId, queueId };
  } catch (err) {
    logger.warn({ msg: "governance_case_closed_failed", caseId, error: err.message });
    return { updated: false, error: err.message };
  }
}

/**
 * Escaneo periódico: activos sin ACK → cola de incidentes.
 */
export async function scanUnacknowledgedAssets(limit = 50) {
  if (!ENABLED) return { enabled: false, scanned: 0, enqueued: 0 };

  const rows = await pgQuery(
    `SELECT id, hostname, ip_address::text AS ip_address, discovered_via
       FROM noc_devices
      WHERE inventory_ack IS FALSE
      ORDER BY created_at ASC
      LIMIT $1`,
    [limit],
  );

  let enqueued = 0;
  for (const row of rows) {
    const r = await enqueueUnknownAssetIncident(row, row.discovered_via ?? "scan");
    if (r.enqueued) enqueued++;
  }

  if (enqueued > 0) {
    logger.info({ msg: "inventory_governance_scan", scanned: rows.length, enqueued });
  }
  return { enabled: true, scanned: rows.length, enqueued };
}

let _timer = null;

export function startInventoryGovernanceWatcher() {
  if (!ENABLED || SCAN_INTERVAL_MS <= 0) {
    logger.info("noc_inventory_governance_disabled");
    return;
  }
  if (_timer) return;

  const tick = () => {
    scanUnacknowledgedAssets().catch((err) =>
      logger.error("inventory_governance_tick", { msg: err.message }),
    );
  };

  tick();
  _timer = setInterval(tick, SCAN_INTERVAL_MS);
  logger.info("noc_inventory_governance_started", { intervalMs: SCAN_INTERVAL_MS });
}

export function stopInventoryGovernanceWatcher() {
  if (_timer) clearInterval(_timer);
  _timer = null;
}
