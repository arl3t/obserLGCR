/**
 * Puente NOC → Gestión de incidentes.
 * Convierte alertas `down` abiertas en casos PostgreSQL (incident_cases_pg).
 */
import { randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { dedupKey as canonDedupKey, normalizeIoc as canonNormalizeIoc } from "../services/dedupKey.mjs";
import { getNetworkZone, getSensorLabel } from "../services/sourceLogCatalog.mjs";

const SOURCE_LOG = "noc_down";
const SEVERITY = "HIGH";
const SCORE = 72;
const ENABLED = process.env.NOC_AUTO_INCIDENT?.trim() !== "false";

function normalizeIpFromPg(ipText) {
  const s = String(ipText ?? "").trim();
  if (!s) return "";
  const slash = s.indexOf("/");
  return slash > 0 ? s.slice(0, slash) : s;
}

function isIp(v) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(v ?? "").trim());
}

function buildTimelineEntry(hostname, alertType, lastSeen) {
  return {
    ts: new Date().toISOString(),
    action: "noc_auto_open",
    operator: "system:noc-watcher",
    detail: `Incidente auto-abierto por alerta NOC (${alertType}) en ${hostname}. Último heartbeat: ${lastSeen ?? "desconocido"}`,
  };
}

/**
 * Abre (o enlaza) un caso de gestión para una alerta NOC down.
 * @returns {Promise<{ outcome: string, caseId?: string, alertId: string }>}
 */
export async function openCaseFromNocAlert(alertId, { operatorCi = "system:noc-watcher" } = {}) {
  const [row] = await pgQuery(
    `SELECT a.id AS alert_id, a.alert_type, a.status, a.details, a.triggered_at,
            d.id AS device_id, d.hostname, d.ip_address::text AS ip_address,
            d.device_type, d.site, d.last_seen_at
       FROM noc_alerts a
       JOIN noc_devices d ON d.id = a.device_id
      WHERE a.id = $1`,
    [alertId],
  );
  if (!row) return { outcome: "not_found", alertId };
  if (row.alert_type !== "down") return { outcome: "not_down", alertId };
  if (row.status !== "open" && row.status !== "ack") {
    return { outcome: "not_open", alertId };
  }

  const existingCaseId = row.details?.case_id ?? null;
  if (existingCaseId) {
    const [active] = await pgQuery(
      `SELECT id FROM incident_cases_pg
        WHERE id = $1 AND status NOT IN ('CERRADO','FALSO_POSITIVO') LIMIT 1`,
      [String(existingCaseId)],
    );
    if (active) return { outcome: "already_linked", alertId, caseId: active.id };
  }

  const hostname = String(row.hostname ?? "unknown").trim();
  const ipRaw = normalizeIpFromPg(row.ip_address);
  const iocRaw = ipRaw || hostname;
  const iocType = isIp(iocRaw) ? "ip" : "hostname";
  const iocValue = canonNormalizeIoc(iocRaw, iocType);
  const dedupKeyFinal = canonDedupKey({
    iocValue,
    iocType,
    severity: SEVERITY,
    mitreTacticId: "TA0008",
    sourceLog: SOURCE_LOG,
  });

  const [dupe] = await pgQuery(
    `SELECT id FROM incident_cases_pg
      WHERE (dedup_key = $1 OR ioc_value = $2 OR sensor_key = $3)
        AND status NOT IN ('CERRADO','FALSO_POSITIVO')
        AND updated_at >= now() - INTERVAL '30 days'
      ORDER BY updated_at DESC LIMIT 1`,
    [dedupKeyFinal, iocValue, hostname],
  );
  if (dupe) {
    await pgQuery(
      `UPDATE noc_alerts SET details = COALESCE(details, '{}'::jsonb) || jsonb_build_object('case_id', $2::text)
        WHERE id = $1`,
      [alertId, dupe.id],
    );
    return { outcome: "linked_existing", alertId, caseId: dupe.id };
  }

  const caseId = randomUUID();
  const now = new Date().toISOString();
  const enrichment = {
    noc_alert_id: alertId,
    noc_device_id: row.device_id,
    device_type: row.device_type,
    site: row.site,
    alert_type: row.alert_type,
    triggered_at: row.triggered_at,
    last_seen_at: row.last_seen_at,
    auto_opened: true,
  };
  const recommended = `Verificar conectividad y agente NOC en ${hostname}. Revisar logs y ejecutar ping/traceroute remoto si aplica.`;

  await pgQuery(
    `INSERT INTO incident_cases_pg (
       id, severity, status, score, operator_id, hostname, sensor_key, network_zone,
       ioc_value, ioc_type, source_log, dedup_key, detected_at,
       enrichment_data, recommended_action, timeline
     ) VALUES (
       $1, $2, 'NUEVO', $3, NULL, $4, $4, $5,
       $6, $7, $8, $9, $10,
       $11::jsonb, $12, jsonb_build_array($13::jsonb)
     )`,
    [
      caseId,
      SEVERITY,
      SCORE,
      hostname,
      getNetworkZone(SOURCE_LOG),
      iocValue,
      iocType,
      SOURCE_LOG,
      dedupKeyFinal,
      row.last_seen_at ?? row.triggered_at ?? now,
      JSON.stringify(enrichment),
      recommended,
      JSON.stringify(buildTimelineEntry(hostname, row.alert_type, row.last_seen_at)),
    ],
  );

  await pgQuery(
    `UPDATE noc_alerts SET details = COALESCE(details, '{}'::jsonb) || jsonb_build_object('case_id', $2::text)
      WHERE id = $1`,
    [alertId, caseId],
  );

  logger.info({
    msg: "noc_incident_opened",
    alertId,
    caseId,
    hostname,
    iocValue,
    operator: operatorCi,
    sensor: getSensorLabel(SOURCE_LOG),
  });

  return { outcome: "created", alertId, caseId, hostname, severity: SEVERITY, score: SCORE };
}

/**
 * Procesa todas las alertas down abiertas sin caso vinculado.
 */
export async function syncNocDownIncidents() {
  if (!ENABLED) {
    return { enabled: false, processed: 0, results: [] };
  }

  const alerts = await pgQuery(
    `SELECT a.id
       FROM noc_alerts a
      WHERE a.alert_type = 'down'
        AND a.status IN ('open', 'ack')
        AND COALESCE(a.details->>'case_id', '') = ''`,
  );

  const results = [];
  for (const { id } of alerts) {
    try {
      results.push(await openCaseFromNocAlert(id));
    } catch (err) {
      logger.error("noc_incident_sync_failed", { alertId: id, msg: err.message });
      results.push({ outcome: "error", alertId: id, error: err.message });
    }
  }

  const created = results.filter((r) => r.outcome === "created").length;
  if (created > 0 || results.some((r) => r.outcome === "error")) {
    logger.info("noc_incident_sync", { processed: alerts.length, created, results });
  }

  return { enabled: true, processed: alerts.length, created, results };
}
