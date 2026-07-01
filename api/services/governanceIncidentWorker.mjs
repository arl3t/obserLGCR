/**
 * Worker: drena incidents_queue → incident_cases_pg (Gestión).
 */
import { randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { dedupKey as canonDedupKey, normalizeIoc as canonNormalizeIoc } from "./dedupKey.mjs";
import { getNetworkZone, getSensorLabel } from "./sourceLogCatalog.mjs";

const ENABLED = process.env.GOVERNANCE_INCIDENT_WORKER?.trim() !== "false";
const INTERVAL_MS = parseInt(process.env.GOVERNANCE_INCIDENT_INTERVAL_MS ?? "15000", 10);
const BATCH_SIZE = parseInt(process.env.GOVERNANCE_INCIDENT_BATCH ?? "20", 10);

const TYPE_CONFIG = {
  forbidden_software: {
    sourceLog: "software_governance",
    mitreTacticId: "TA0005",
    scoreMap: { CRITICAL: 88, HIGH: 82, MEDIUM: 72, LOW: 60, NEGLIGIBLE: 50 },
    defaultScore: 82,
  },
  unapproved_software: {
    sourceLog: "software_governance",
    mitreTacticId: "TA0005",
    scoreMap: { CRITICAL: 75, HIGH: 70, MEDIUM: 65, LOW: 55, NEGLIGIBLE: 45 },
    defaultScore: 65,
  },
  keepalive_down: {
    sourceLog: "noc_down",
    mitreTacticId: "TA0008",
    scoreMap: { CRITICAL: 85, HIGH: 72, MEDIUM: 65, LOW: 55, NEGLIGIBLE: 45 },
    defaultScore: 72,
  },
  high_cpu: {
    sourceLog: "noc_metrics",
    mitreTacticId: "TA0008",
    defaultScore: 68,
  },
  high_memory: {
    sourceLog: "noc_metrics",
    mitreTacticId: "TA0008",
    defaultScore: 68,
  },
  high_rtt: {
    sourceLog: "noc_metrics",
    mitreTacticId: "TA0008",
    defaultScore: 65,
  },
  unknown_asset: {
    sourceLog: "noc_inventory_governance",
    mitreTacticId: "TA0007",
    scoreMap: { CRITICAL: 78, HIGH: 72, MEDIUM: 65, LOW: 55, NEGLIGIBLE: 45 },
    defaultScore: 72,
    incidentCategory: "UNAUTHORIZED_ACCESS",
  },
  undocumented_host: {
    sourceLog: "noc_inventory_governance",
    mitreTacticId: "TA0007",
    defaultScore: 68,
    incidentCategory: "INVESTIGATION",
  },
};

function isIp(v) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(v ?? "").trim());
}

function scoreFor(type, severity) {
  const cfg = TYPE_CONFIG[type] ?? TYPE_CONFIG.forbidden_software;
  return cfg.scoreMap?.[severity] ?? cfg.defaultScore ?? 70;
}

function buildRecommendedAction(row) {
  const p = row.payload ?? {};
  switch (row.incident_type) {
    case "forbidden_software":
      return `Software prohibido detectado: ${p.software_name ?? "?"} ${p.software_version ?? ""}. Desinstalar o solicitar excepción en whitelist.`;
    case "unapproved_software":
      return `Software no aprobado: ${p.software_name ?? "?"}. Verificar política de software autorizado.`;
    case "keepalive_down":
      return `Verificar conectividad y agente NOC en ${row.hostname}.`;
    case "unknown_asset":
      return `Activo no reconocido: ${row.hostname}. Verificar origen, documentar en inventario (ACK) o aislar si es rogue.`;
    case "undocumented_host":
      return `Host descubierto sin documentar: ${row.hostname}. Confirmar legitimidad y marcar como activo conocido.`;
    default:
      return `Revisar alerta NOC: ${row.incident_type} en ${row.hostname}.`;
  }
}

async function openCaseFromQueue(row) {
  const cfg = TYPE_CONFIG[row.incident_type] ?? TYPE_CONFIG.forbidden_software;
  const hostname = String(row.hostname ?? "unknown").trim();
  const iocRaw = hostname;
  const iocType = isIp(iocRaw) ? "ip" : "hostname";
  const iocValue = canonNormalizeIoc(iocRaw, iocType);
  const dedupKeyFinal = canonDedupKey({
    iocValue,
    iocType,
    severity: row.severity,
    mitreTacticId: cfg.mitreTacticId,
    sourceLog: cfg.sourceLog,
  });

  const [dupe] = await pgQuery(
    `SELECT id FROM incident_cases_pg
      WHERE dedup_key = $1
        AND status NOT IN ('CERRADO','FALSO_POSITIVO')
        AND updated_at >= now() - INTERVAL '30 days'
      ORDER BY updated_at DESC LIMIT 1`,
    [dedupKeyFinal],
  );
  if (dupe) {
    return { outcome: "linked_existing", caseId: dupe.id };
  }

  const caseId = randomUUID();
  const now = new Date().toISOString();
  const score = scoreFor(row.incident_type, row.severity);
  const payload = row.payload ?? {};
  const enrichment = {
    incidents_queue_id: row.id,
    incident_type: row.incident_type,
    server_id: row.server_id,
    node_id: row.node_id,
    noc_device_id: row.node_id ?? payload.noc_device_id ?? null,
    payload,
    auto_opened: true,
  };
  const timeline = {
    ts: now,
    action: "governance_auto_open",
    operator: "system:governance-worker",
    detail: `Incidente auto-abierto (${row.incident_type}) en ${hostname}.`,
  };

  await pgQuery(
    `INSERT INTO incident_cases_pg (
       id, severity, status, score, operator_id, hostname, sensor_key, network_zone,
       ioc_value, ioc_type, source_log, dedup_key, detected_at,
       enrichment_data, recommended_action, timeline, incident_category
     ) VALUES (
       $1, $2, 'NUEVO', $3, NULL, $4, $4, $5,
       $6, $7, $8, $9, $10,
       $11::jsonb, $12, jsonb_build_array($13::jsonb), $14
     )`,
    [
      caseId,
      row.severity,
      score,
      hostname,
      getNetworkZone(cfg.sourceLog),
      iocValue,
      iocType,
      cfg.sourceLog,
      dedupKeyFinal,
      now,
      JSON.stringify(enrichment),
      buildRecommendedAction(row),
      JSON.stringify(timeline),
      cfg.incidentCategory ?? null,
    ],
  );

  logger.info({
    msg: "governance_incident_opened",
    queueId: row.id,
    caseId,
    hostname,
    incidentType: row.incident_type,
    sensor: getSensorLabel(cfg.sourceLog),
  });

  return { outcome: "created", caseId };
}

export async function processIncidentsQueueBatch(limit = BATCH_SIZE) {
  if (!ENABLED) return { enabled: false, processed: 0 };

  const pending = await pgQuery(
    `UPDATE incidents_queue q
        SET status = 'processing'
      WHERE q.id IN (
        SELECT id FROM incidents_queue
         WHERE status = 'pending'
         ORDER BY created_at ASC
         LIMIT $1
         FOR UPDATE SKIP LOCKED
      )
      RETURNING *`,
    [limit],
  );

  let created = 0;
  let linked = 0;
  let failed = 0;

  for (const row of pending) {
    try {
      const result = await openCaseFromQueue(row);
      await pgQuery(
        `UPDATE incidents_queue
            SET status = 'done', case_id = $2, processed_at = NOW(), error_message = NULL
          WHERE id = $1`,
        [row.id, result.caseId ?? null],
      );
      if (result.outcome === "created") created++;
      else linked++;
    } catch (err) {
      failed++;
      await pgQuery(
        `UPDATE incidents_queue
            SET status = 'failed', processed_at = NOW(), error_message = $2
          WHERE id = $1`,
        [row.id, err.message?.slice(0, 500)],
      );
      logger.error("governance_incident_failed", { queueId: row.id, msg: err.message });
    }
  }

  if (pending.length > 0) {
    logger.info("governance_incident_batch", {
      processed: pending.length,
      created,
      linked,
      failed,
    });
  }

  return { enabled: true, processed: pending.length, created, linked, failed };
}

let _timer = null;

export function startGovernanceIncidentWorker() {
  if (!ENABLED || INTERVAL_MS <= 0) {
    logger.info("governance_incident_worker_disabled");
    return;
  }
  if (_timer) return;

  const tick = () => {
    processIncidentsQueueBatch().catch((err) =>
      logger.error("governance_incident_worker_tick", { msg: err.message }),
    );
  };

  tick();
  _timer = setInterval(tick, INTERVAL_MS);
  logger.info("governance_incident_worker_started", { intervalMs: INTERVAL_MS });
}

export function stopGovernanceIncidentWorker() {
  if (_timer) clearInterval(_timer);
  _timer = null;
}
