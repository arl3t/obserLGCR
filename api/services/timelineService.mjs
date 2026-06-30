/**
 * timelineService.mjs
 * DFIR-IRIS inspired Timeline service.
 * Dedicated timeline_events table with phases, related objects and metadata.
 */

import { pgQuery } from "../db/postgres.mjs";
import { randomUUID } from "node:crypto";

export const EVENT_TYPES = new Set([
  "DETECTION","CONTAINMENT","ERADICATION","RECOVERY","POST_INCIDENT",
  "ADOPT","STATUS_CHANGE","ESCALATE","SLACK_NOTIFY","CLIENT_NOTIFY","NOTE",
  "EVIDENCE","IOC","ASSET",
  // Sistema de tickets público (docs/PROPUESTA-TICKETING-PUBLICO.md §4):
  // la conversación cliente↔SOC y las solicitudes accionables se espejan al
  // timeline del caso vinculado para que el analista las vea en la investigación.
  "TICKET_MSG","TICKET_STATUS","TICKET_ACTION_REQUEST","TICKET_ACTION_DECISION",
]);

export const PHASES = new Set([
  "DETECTION","CONTAINMENT","ERADICATION","RECOVERY","POST_INCIDENT",
]);

// ── Add event ─────────────────────────────────────────────────────────────────

export async function addTimelineEvent(caseId, {
  eventType = "NOTE",
  phase,
  title,
  description,
  operatorCi,
  source = "MANUAL",
  relatedAssetId,
  relatedIocId,
  relatedEvidenceId,
  metadata = {},
  eventTs,
}) {
  const id = randomUUID();
  await pgQuery(
    `INSERT INTO case_timeline_events
       (id, case_id, event_ts, event_type, phase, title, description,
        related_asset_id, related_ioc_id, related_evidence_id,
        operator_ci, source, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [
      id, caseId,
      eventTs ? new Date(eventTs).toISOString() : new Date().toISOString(),
      eventType,
      phase ?? null,
      title ?? null,
      description ?? null,
      relatedAssetId ?? null,
      relatedIocId ?? null,
      relatedEvidenceId ?? null,
      operatorCi ?? "system",
      source,
      JSON.stringify(metadata),
    ]
  );
  return id;
}

// ── List timeline for a case ──────────────────────────────────────────────────

export async function getTimeline(caseId) {
  return pgQuery(
    `SELECT
       te.id, te.event_ts, te.event_type, te.phase, te.title, te.description,
       te.operator_ci, te.source, te.metadata,
       a.asset_value  AS related_asset,
       ioc.ioc_value  AS related_ioc,
       ev.name        AS related_evidence
     FROM case_timeline_events te
     LEFT JOIN case_assets    a   ON a.id   = te.related_asset_id
     LEFT JOIN case_iocs      ioc ON ioc.id = te.related_ioc_id
     LEFT JOIN case_evidences ev  ON ev.id  = te.related_evidence_id
     WHERE te.case_id = $1
     ORDER BY te.event_ts ASC`,
    [caseId]
  );
}

// ── Sync legacy JSONB timeline to events table ────────────────────────────────
// Called once when opening a case that has an existing JSONB timeline.

export async function syncLegacyTimeline(caseId, jsonbTimeline) {
  if (!Array.isArray(jsonbTimeline) || jsonbTimeline.length === 0) return;

  // Only sync if no events exist yet for this case
  const existing = await pgQuery(
    `SELECT 1 FROM case_timeline_events WHERE case_id=$1 LIMIT 1`,
    [caseId]
  );
  if (existing.length > 0) return;

  const vals = [];
  const rows = jsonbTimeline.map((entry, i) => {
    const base = i * 8;
    const type = mapLegacyAction(entry.action);
    vals.push(
      randomUUID(), caseId,
      entry.ts ? new Date(entry.ts).toISOString() : new Date().toISOString(),
      type, null,
      entry.action ?? "Evento",
      entry.detail ?? null,
      entry.operator ?? "system",
      "SYSTEM",
    );
    return `($${base+1},$${base+2},$${base+3},$${base+4},$${base+5},$${base+6},$${base+7},$${base+8},$${base+9})`;
  });

  await pgQuery(
    `INSERT INTO case_timeline_events
       (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source)
     VALUES ${rows.join(",")}
     ON CONFLICT DO NOTHING`,
    vals
  );
}

function mapLegacyAction(action) {
  const a = (action ?? "").toUpperCase();
  if (a === "ADOPT")          return "ADOPT";
  if (a === "STATUS_CHANGE")  return "STATUS_CHANGE";
  if (a === "ESCALATE")       return "ESCALATE";
  if (a === "SLACK")          return "SLACK_NOTIFY";
  return "NOTE";
}
