/**
 * routes/caseInvestigation.mjs
 * DFIR-IRIS inspired Case Investigation API.
 *
 * Mounted at /api/cases in server.mjs.
 * Handles: templates, tasks, assets, IOCs, evidences, timeline, reports.
 * All data is PostgreSQL-backed for speed and ACID compliance.
 */

import { Router } from "express";
import rateLimit from "express-rate-limit";
import { randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import {
  listTemplates, getTemplate, createTemplate, updateTemplate,
  deleteTemplate, suggestTemplate, applyTemplateToCase,
} from "../services/caseTemplateService.mjs";
import {
  addTimelineEvent, getTimeline, syncLegacyTimeline,
} from "../services/timelineService.mjs";
import { enrichIoc } from "../services/enrichmentService.mjs";
import { computeIocVerdict } from "../services/iocVerdict.mjs";
import { classifyEcsirt, ECSIRT_CLASSES } from "../services/ecsirtClassify.mjs";
import { parseCaseNumber } from "../services/caseNumber.mjs";
import { generatePlaybook, generateRecommendedAction } from "../services/casePlaybookService.mjs";
import { generateCasePlaybookDoc, contextKeyFor } from "../services/casePlaybookDoc.mjs";
import { findReusablePlaybook, savePlaybook } from "../services/casePlaybookStore.mjs";
import { getSlaMin } from "../services/slaConfig.mjs";
import { resolveJwtOperatorCi } from "../services/operatorResolver.mjs";
import { detectCvesInText, maxCveTone } from "../services/cveDetection.mjs";
import { getEnrichmentBatch as getNvdEnrichmentBatch } from "../services/nvdEnrichment.mjs";
import { getKevByIds } from "../services/kevCatalog.mjs";
import { resolveNamedTrinoQuery } from "../trino/registry.mjs";
import { config } from "../config.mjs";
import { logger } from "../logger.mjs";

const TCASES  = "minio_iceberg.hunting.incident_cases";
const SESSION = { catalog: "minio_iceberg", schema: "hunting" };

// Acepta UUID canónico (con guiones) y también el formato sin guiones de 32 hex
// (incident_key estilo md5 que usan los casos auto-importados desde Trino: ~34k
// casos en PG tienen este id). Sólo hex → sigue siendo seguro para concatenar en
// queries Trino (no hay vector de inyección). Antes sólo aceptaba la forma con
// guiones → abrir la investigación de un caso sin guiones devolvía 400.
const UUID_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

function isCaseManager(req) {
  const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
  return roles.includes("manager") || roles.includes("admin");
}

/**
 * ACL para acceso a un caso específico.
 *
 *  · READ (mode="read"):  manager+/admin → todo; analyst → casos propios o
 *    sin adoptar (preserva el flujo "previsualizar → adoptar"). Caso ghost
 *    (no en PG) → permite pasar al handler para auto-import desde Trino.
 *  · WRITE (mode="write"): solo owner (operator_id) o manager+/admin.
 *
 * Devuelve { ok:true, pgRow } cuando autoriza, o { ok:false } tras emitir
 * la respuesta (404 en read denegada para no leakear existencia, 403 en
 * write). Valida formato UUID — protege contra inyección al concatenar
 * `case_id` en queries Trino.
 *
 * Why: el audit P4 (2026-05-13) encontró IDOR de lectura/mutación y un
 * vector de inyección Trino vía req.params.id sin validar.
 */
async function checkCaseAccess(req, res, caseId, mode = "read") {
  if (!caseId || !UUID_RE.test(caseId)) {
    res.status(400).json({ error: "ID inválido (UUID requerido)" });
    return { ok: false };
  }
  let pgRow = null;
  try {
    const rows = await pgQuery(
      `SELECT * FROM incident_cases_pg WHERE id=$1 LIMIT 1`,
      [caseId],
    );
    pgRow = rows[0] ?? null;
  } catch (err) {
    res.status(500).json({ error: err.message });
    return { ok: false };
  }
  if (isCaseManager(req)) return { ok: true, pgRow };

  const jwtCi = await resolveJwtOperatorCi(req);

  if (mode === "read") {
    if (!pgRow) return { ok: true, pgRow: null }; // ghost: handler decide
    if (!pgRow.operator_id) return { ok: true, pgRow }; // cola sin adoptar
    if (jwtCi && pgRow.operator_id === jwtCi) return { ok: true, pgRow };
    res.status(404).json({ error: "Caso no encontrado" });
    return { ok: false };
  }

  // write
  if (!pgRow) {
    res.status(404).json({ error: "Caso no encontrado" });
    return { ok: false };
  }
  if (jwtCi && pgRow.operator_id === jwtCi) return { ok: true, pgRow };
  res.status(403).json({
    error: "No autorizado: el caso pertenece a otro operador",
  });
  return { ok: false };
}

// Cache de /api/cases/kpis con bucket por ventana temporal (?hours=N).
// La función SQL soc_kpis_window(p_hours) aplica la ventana del selector a las
// métricas operacionales; las de cobertura quedan fijas a 30d (gestión interna).
// TTL 30s, dedupe de queries concurrentes por bucket.
const KPIS_TTL_MS = 30_000;
const _kpisBuckets = new Map(); // hours → { value, expiresAt, pending }

function _normalizeHours(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 168;            // default: 7d
  return Math.min(8760, Math.max(1, Math.round(n)));        // clamp [1h, 365d]
}

async function _computeCasesKpis(hours) {
  const [rows, autoClosedRows, unassignedRows] = await Promise.all([
    pgQuery(`SELECT * FROM soc_kpis_window($1) LIMIT 1`, [hours]),
    pgQuery(`
      -- Auto-cerrados LOW/NEG en 7 días. Filtramos por auto_closed_at (el campo
      -- canónico que setea autoClassifyController) en vez de operator_id: el
      -- inserter no escribe operator_id en los espejos auto-clasificados,
      -- por lo que el filtro 'auto%' devolvía 0 (audit 2026-05-13 — bug 2).
      SELECT COUNT(*) AS cnt FROM incident_cases_pg
      WHERE status = 'CERRADO'
        AND severity IN ('LOW','NEGLIGIBLE')
        AND auto_closed_at IS NOT NULL
        AND auto_closed_at >= now() - INTERVAL '7 days'
    `).catch(() => [{ cnt: 0 }]),
    pgQuery(`
      SELECT COUNT(*) AS cnt FROM incident_cases_pg
      WHERE operator_id IS NULL
        AND status NOT IN ('CERRADO','FALSO_POSITIVO')
    `).catch(() => [{ cnt: 0 }]),
  ]);
  const k = rows[0] ?? {};
  const num = (col) => k[col] != null ? Number(k[col]) : null;
  const slaOk  = Number(k.critical_sla_ok  ?? 0);
  const slaAll = Number(k.critical_sla_total ?? 0);

  // coverage_by_source: jsonb del SQL. pg ya lo devuelve como array JS.
  // Garantizamos forma estable: omitimos filas null y normalizamos números.
  const rawCoverage = Array.isArray(k.coverage_by_source) ? k.coverage_by_source : [];
  const coverageBySource = rawCoverage
    .filter((r) => r && typeof r === "object")
    .map((r) => ({
      sourceLog: String(r.source_log ?? "(sin fuente)"),
      total:     Number(r.total  ?? 0),
      mapped:    Number(r.mapped ?? 0),
      pct:       r.pct != null ? Number(r.pct) : null,
    }));

  return {
    windowHours:        hours,
    openCases:          Number(k.open_cases      ?? 0),
    closedCases:        Number(k.closed_cases    ?? 0),
    criticalSlaOk:      slaOk,
    criticalSlaTotal:   slaAll,
    criticalAvgAckMin:  num("critical_avg_ack_min"),
    resolvedToday:      Number(k.resolved_today  ?? 0),
    monitoring:         Number(k.monitoring      ?? 0),
    autoFp:             Number(k.auto_fp         ?? 0),
    autoClosedLow:      Number(autoClosedRows[0]?.cnt ?? 0),
    unassignedOpen:     Number(unassignedRows[0]?.cnt ?? 0),
    mttdMin:            num("mttd_min"),
    mttaMin:            num("mtta_min"),
    mttrMin:            num("mttr_min"),
    mttcMin:            num("mttc_min"),
    // first_action_min: tiempo a la 1ra acción de un analista (humano O LLM). KPI
    // separado de mttaMin (adopción humana) — da crédito al analista LLM sin tocar MTTC.
    firstActionMin:     num("first_action_min"),
    fpRate:             num("fp_rate"),
    mitreCoveragePct:   num("mitre_coverage_pct"),
    autoDeduPct:        num("auto_dedup_pct"),
    l1L2EscMin:         num("l1_l2_esc_min"),
    wazuhFallbackPct:   num("wazuh_fallback_pct"),
    postmortemRate:     num("postmortem_rate"),
    slaCriticalPct:     num("sla_critical_pct"),
    escalationRate:     num("escalation_rate"),
    coverageBySource,
    nMttd:              num("n_mttd"),
    nMtta:              num("n_mtta"),
    nMttr:              num("n_mttr"),
    nMttc:              num("n_mttc"),
  };
}

async function _getCasesKpisCached(hours) {
  const now = Date.now();
  let bucket = _kpisBuckets.get(hours);
  if (!bucket) {
    bucket = { value: null, expiresAt: 0, pending: null };
    _kpisBuckets.set(hours, bucket);
  }
  // Fresco → instantáneo.
  if (bucket.value && bucket.expiresAt > now) return bucket.value;

  // Refresh-ahead / stale-while-revalidate (opt 2026-06-06): el cálculo hace un
  // Seq Scan inherente de incident_cases_pg (el 100% de las filas cae en la
  // ventana de 90d → ningún índice lo evita). Si ya hay un valor viejo, lo
  // servimos YA y recalculamos en segundo plano: el scan de ~1s nunca queda en
  // el camino de la request. Single-flight vía bucket.pending.
  if (!bucket.pending) {
    bucket.pending = _computeCasesKpis(hours)
      .then((v) => {
        bucket.value     = v;
        bucket.expiresAt = Date.now() + KPIS_TTL_MS;
        bucket.pending   = null;
        return v;
      })
      .catch((err) => {
        bucket.pending = null;
        if (!bucket.value) throw err;          // cold start: propagá el error
        logger.warn("cases.kpis.bg_refresh_failed", { hours, err: err?.message ?? String(err) });
        return bucket.value;                   // hay valor viejo: seguí sirviéndolo
      });
  }
  // Con valor viejo → servilo sin esperar. Cold start → esperá el primer cálculo.
  return bucket.value ?? bucket.pending;
}

/** Invalida todos los buckets — llamado desde mutaciones. */
export function invalidateCasesKpisCache() {
  _kpisBuckets.clear();
}

// Rate limit per-user para enriquecimiento manual (P4 A6, 2026-05-13).
// enrichIoc fan-outs a VT, Shodan, AbuseIPDB, MISP, URLhaus — un loop
// autenticado puede vaciar la cuota free de VT (500/día) en minutos.
// keyGenerator usa req.user.sub para que el límite sea por user, no por IP
// (varios analistas detrás del mismo NAT corporativo no se penalizan
// entre sí). 3 enriquecimientos/min/user es generoso para uso real y
// agresivo contra abuso programático.
const enrichLimiter = rateLimit({
  windowMs: 60_000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.sub || req.ip,
  message: { error: "Demasiados enriquecimientos manuales — esperá 1 minuto" },
});

/**
 * Serializa el resultado de enrichIoc para persistir en enrichment_data JSONB.
 * Capea arrays voluminosos (MISP events, OTX pulses) y guarda summary + sources
 * detalladas + status por-fuente + veredicto agregado (audit intel 2026-06-05).
 * Fuente única usada por el enriquecimiento al abrir caso y por enrich-now.
 */
function buildEnrichmentJsonb(enr) {
  const sources = { ...(enr.sources ?? {}) };
  if (sources.misp?.events?.length > 10) {
    sources.misp = { ...sources.misp, events: sources.misp.events.slice(0, 10) };
  }
  if (sources.otx?.pulses?.length > 5) {
    sources.otx = { ...sources.otx, pulses: sources.otx.pulses.slice(0, 5) };
  }
  return JSON.stringify({
    iocEnrichment: enr.summary ?? {},
    iocSources:    sources,
    iocStatus:     enr.status  ?? {},
    iocVerdict:    enr.verdict ?? null,
    enrichedAt:    enr.enrichedAt,
  });
}

export default function caseInvestigationRouter(runQuery) {
  const r = Router();

  // ── GET /api/cases/kpis — NIST SP 800-61 Rev. 3 + CSF 2.0 KPIs ─────────────
  // Acepta ?hours=N para alinear las métricas operacionales con el selector de
  // ventana del UI (24/168/720/8760). Default 168 (7d) por compatibilidad.
  r.get("/kpis", async (req, res) => {
    try {
      const hours = _normalizeHours(req.query?.hours);
      const result = await _getCasesKpisCached(hours);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/cases/status-dist — Status + severity distribution ───────────
  r.get("/status-dist", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT status, severity, COUNT(*) AS cnt
         FROM incident_cases_pg
         WHERE created_at >= now() - INTERVAL '90 days'
         GROUP BY status, severity
         ORDER BY status, severity`
      );
      res.json(rows);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/cases/list — PostgreSQL paginated case list ─────────────────
  r.get("/list", async (req, res) => {
    const {
      severity = "ALL",
      status   = "ALL",
      search,
      page     = "1",
      pageSize = "25",
    } = req.query;

    const pg = Math.max(1, Number(page));
    const ps = Math.min(100, Math.max(1, Number(pageSize)));
    const offset = (pg - 1) * ps;

    const conds = [];
    const vals  = [];
    let   i     = 1;

    // Date window: 90 days for active, 365 for closed
    conds.push(`created_at >= now() - INTERVAL '365 days'`);

    if (severity !== "ALL") {
      conds.push(`severity = $${i++}`);
      vals.push(severity);
    }
    if (status !== "ALL") {
      conds.push(`status = $${i++}`);
      vals.push(status);
    } else {
      // Default: exclude nothing — show all statuses
    }
    if (search) {
      // Búsqueda por número de caso (INC-000123 / #123 / 123) además de texto libre.
      const caseNum = parseCaseNumber(search);
      if (caseNum != null) {
        conds.push(`(ioc_value ILIKE $${i} OR source_log ILIKE $${i} OR mitre_tactic_name ILIKE $${i} OR id ILIKE $${i} OR case_number = $${i + 1})`);
        vals.push(`%${search}%`, caseNum);
        i += 2;
      } else {
        conds.push(`(ioc_value ILIKE $${i} OR source_log ILIKE $${i} OR mitre_tactic_name ILIKE $${i} OR id ILIKE $${i})`);
        vals.push(`%${search}%`);
        i++;
      }
    }

    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";

    try {
      const [countRows, caseRows] = await Promise.all([
        pgQuery(`SELECT COUNT(*) AS cnt FROM incident_cases_pg ${where}`, vals),
        pgQuery(
          `SELECT id, case_number, severity, status, score, operator_id,
                  adopted_at, created_at, updated_at,
                  ioc_value, ioc_type, source_log,
                  mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
                  escalation_level, escalated_to, escalated_at, escalation_reason,
                  template_id, incident_category, functional_impact,
                  information_impact, recoverability, root_cause, lessons_learned,
                  recommended_action, enrichment_data,
                  containment_status, slack_notified_at
           FROM incident_cases_pg
           ${where}
           ORDER BY
             CASE status
               WHEN 'NUEVO'          THEN 1
               WHEN 'EN_ANALISIS'    THEN 2
               WHEN 'CONFIRMADO'     THEN 3
               WHEN 'ESCALADO'       THEN 4
               WHEN 'MONITOREADO'    THEN 5
               WHEN 'FALSO_POSITIVO' THEN 6
               WHEN 'CERRADO'        THEN 7
               ELSE 8 END,
             CASE severity
               WHEN 'CRITICAL'   THEN 1
               WHEN 'HIGH'       THEN 2
               WHEN 'MEDIUM'     THEN 3
               WHEN 'LOW'        THEN 4
               ELSE 5 END,
             updated_at DESC
           LIMIT $${i} OFFSET $${i+1}`,
          [...vals, ps, offset]
        ),
      ]);

      const total = Number(countRows[0]?.cnt ?? 0);
      res.json({ cases: caseRows, total, page: pg, pageSize: ps });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/cases/:id — Full case detail ─────────────────────────────────
  // If the case doesn't exist in PG yet (DAG-created cases), auto-import from Trino.
  r.get("/:id", async (req, res) => {
    const { id } = req.params;
    const acl = await checkCaseAccess(req, res, id, "read");
    if (!acl.ok) return;
    try {
      let pgRow = acl.pgRow;

      // ── Auto-import + enrich from Trino if not in PG ──────────────────────
      if (!pgRow && runQuery) {
        let trinoRows = [];
        try {
          trinoRows = await runQuery(
            `SELECT case_id, ioc_value, ioc_type, source_log, source_category,
                    severity_text, severity_score, confidence_level, status,
                    mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
                    adopted_at, first_seen, last_seen, assigned_to,
                    score_breakdown, notes, occurrence_count
             FROM ${TCASES}
             WHERE case_id = '${id.replace(/'/g, "''")}'
             LIMIT 1`,
            SESSION
          );
        } catch { /* Trino unavailable — fall through to 404 */ }

        if (trinoRows.length) {
          const t = trinoRows[0];
          const VALID_SEV    = ["CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE"];
          const VALID_STATUS = ["NUEVO","EN_ANALISIS","CONFIRMADO","MONITOREADO","ESCALADO","FALSO_POSITIVO","CERRADO"];
          const sev    = VALID_SEV.includes(String(t.severity_text ?? "").toUpperCase())
            ? String(t.severity_text).toUpperCase() : "MEDIUM";
          const status = VALID_STATUS.includes(String(t.status ?? "").toUpperCase())
            ? String(t.status).toUpperCase() : "NUEVO";

          // 1. Upsert base case record into PG
          // R4 (migration 055): scoring_version='iceberg-import' — el score viene
          // de Iceberg sin saber qué vista lo produjo (sync DAG previo a la columna
          // scoring_version). El valor distingue este path del flujo normal sync.
          const inserted = await pgQuery(
            `INSERT INTO incident_cases_pg
               (id, severity, status, score, operator_id, adopted_at,
                ioc_value, ioc_type, source_log,
                mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
                scoring_version, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                     'iceberg-import',
                     COALESCE($13::timestamptz, now()), now())
             ON CONFLICT (id) DO NOTHING
             RETURNING id`,
            [
              id, sev, status,
              Number(t.severity_score ?? 50),
              t.assigned_to ?? null,
              t.adopted_at  ?? null,
              t.ioc_value   ?? null,
              t.ioc_type    ?? null,
              t.source_log  ?? null,
              t.mitre_tactic_id   ?? null,
              t.mitre_tactic_name ?? null,
              t.mitre_technique_id ?? null,
              t.first_seen ?? null,
            ]
          );
          const isNew = inserted.length > 0; // true only on first import

          pgRow = (await pgQuery(`SELECT * FROM incident_cases_pg WHERE id=$1 LIMIT 1`, [id]))[0];

          if (isNew && pgRow) {
            const iocValue  = t.ioc_value  ? String(t.ioc_value).trim()  : null;
            const iocType   = t.ioc_type   ? String(t.ioc_type).toLowerCase() : "ip";
            const firstSeen = t.first_seen ? String(t.first_seen) : new Date().toISOString();
            const category  = t.source_category ? String(t.source_category) : null;

            // 2. Auto-create primary IOC
            if (iocValue) {
              const iocId = randomUUID();
              await pgQuery(
                `INSERT INTO case_iocs
                   (id, case_id, ioc_type, ioc_value, tlp, description, is_primary, added_by)
                 VALUES ($1,$2,$3,$4,'AMBER',$5,true,'system')
                 ON CONFLICT DO NOTHING`,
                [iocId, id, iocType, iocValue,
                 `IOC detectado vía ${t.source_log ?? "DAG"}` +
                 (t.mitre_tactic_name ? ` · ${t.mitre_tactic_name}` : "")]
              );
            }

            // 3. Auto-create asset if IOC is an IP/host
            if (iocValue && ["ip","host","endpoint"].includes(iocType)) {
              const assetId = randomUUID();
              await pgQuery(
                `INSERT INTO case_assets
                   (id, case_id, asset_type, asset_value, ip_address, description, compromised, added_by)
                 VALUES ($1,$2,'HOST',$3,$4,$5,true,'system')
                 ON CONFLICT DO NOTHING`,
                [assetId, id, iocValue, iocValue,
                 `Host detectado en ${t.source_log ?? "telemetría"} · sev ${sev}`]
              );
            }

            // 4. Initial DETECTION timeline event
            await pgQuery(
              `INSERT INTO case_timeline_events
                 (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source)
               VALUES ($1,$2,$3::timestamptz,'DETECTION','DETECTION',$4,$5,'system','auto')`,
              [
                randomUUID(), id, firstSeen,
                `Detección inicial · ${sev}`,
                `IOC ${iocValue ?? id} detectado por ${t.source_log ?? "DAG"}` +
                (t.mitre_tactic_name ? ` · MITRE: ${t.mitre_tactic_name}` : "") +
                (t.occurrence_count  ? ` · ${t.occurrence_count} ocurrencias` : ""),
              ]
            );

            // 5. Auto-apply best matching template
            //    Fix #12: pasamos mitre_tactic_id para que las playbooks con
            //    `trigger_mitre_tactics` matcheado se prioricen sobre las
            //    genéricas (ej. una "Credential Access" para TA0006).
            try {
              const tacticId = t.mitre_tactic_id ?? null;
              let suggestions = await suggestTemplate(sev, category ?? "INVESTIGATION", tacticId);
              // Fallback: category didn't match — try generic INVESTIGATION
              if (!suggestions.length) suggestions = await suggestTemplate(sev, "INVESTIGATION", tacticId);
              // Last resort: any template matching severity
              if (!suggestions.length) suggestions = await suggestTemplate(sev, "OTHER", tacticId);
              if (suggestions.length > 0) {
                await applyTemplateToCase(id, suggestions[0].id, "system");
              }
            } catch (tplErr) {
              logger.warn("cases.auto_template_failed", { caseId: id, err: tplErr.message });
            }

            // 6. Background IOC enrichment (VT, Shodan, AbuseIPDB, MISP — non-blocking)
            if (iocValue) {
              enrichIoc(iocValue, iocType)
                .then(async (enr) => {
                  if (!enr) return;
                  const s = enr.summary ?? {};
                  // Update IOC record with enrichment data
                  await pgQuery(
                    `UPDATE case_iocs
                        SET vt_malicious = $1,
                            vt_permalink = $2,
                            abuse_score  = $3,
                            in_misp      = $4,
                            shodan_summary = $5,
                            enriched_at  = now()
                      WHERE case_id = $6 AND is_primary = true`,
                    [
                      s.vtMalicious       ?? null,
                      enr.sources?.virustotal?.permalink ?? null,
                      s.abuseConfidence   ?? null,
                      s.inMisp            ?? false,
                      enr.sources?.shodan
                        ? JSON.stringify({ country: enr.sources.shodan.country, ports: enr.sources.shodan.ports?.slice(0,10), vulns: enr.sources.shodan.vulns?.slice(0,5) })
                        : null,
                      id,
                    ]
                  );
                  // Persist enrichment (summary + sources + status + verdict) en JSONB
                  await pgQuery(
                    `UPDATE incident_cases_pg
                        SET enrichment_data = enrichment_data || $1::jsonb, updated_at = now()
                      WHERE id = $2`,
                    [buildEnrichmentJsonb(enr), id]
                  );
                })
                .catch(() => { /* enrichment errors are non-fatal */ });
            }
          }
        }
      }

      if (!pgRow) return res.status(404).json({ error: "Caso no encontrado" });

      const [tasks, assets, iocs, evidences, timeline] = await Promise.all([
        pgQuery(`SELECT * FROM case_tasks WHERE case_id=$1 ORDER BY sort_order, created_at`, [id]),
        pgQuery(`SELECT * FROM case_assets WHERE case_id=$1 ORDER BY created_at`, [id]),
        pgQuery(`SELECT * FROM case_iocs WHERE case_id=$1 ORDER BY is_primary DESC, created_at`, [id]),
        pgQuery(`SELECT * FROM case_evidences WHERE case_id=$1 ORDER BY collected_at DESC`, [id]),
        getTimeline(id),
      ]);

      // Sync legacy JSONB timeline if needed
      if (pgRow.timeline && Array.isArray(pgRow.timeline) && pgRow.timeline.length > 0) {
        syncLegacyTimeline(id, pgRow.timeline).catch(() => {});
      }

      // ── Plantilla recomendada por táctica (2026-06-16) ──────────────────
      // El selector de Tareas mostraba todas las plantillas iguales y ninguna
      // marcada como recomendada ("el check no se marca"). Exponemos cuál es la
      // recomendada (match severidad/categoría/táctica MITRE, misma heurística
      // que el auto-apply de import). Además, si el caso sigue ABIERTO y llegó
      // sin tareas ni plantilla (p.ej. importado del DAG sin bootstrap), la
      // auto-aplicamos acá — lazy, idempotente (applyTemplateToCase no duplica).
      let recommendedTemplateId = null;
      let effectiveTasks = tasks;
      try {
        const tacticId = pgRow.mitre_tactic_id ?? null;
        const cat = pgRow.incident_category ?? "INVESTIGATION";
        let sugg = await suggestTemplate(pgRow.severity, cat, tacticId);
        if (!sugg.length) sugg = await suggestTemplate(pgRow.severity, "INVESTIGATION", tacticId);
        if (!sugg.length) sugg = await suggestTemplate(pgRow.severity, "OTHER", tacticId);
        if (sugg.length) {
          recommendedTemplateId = sugg[0].id;
          const TERMINAL = ["CERRADO", "FALSO_POSITIVO"];
          if (effectiveTasks.length === 0 && !pgRow.template_id && !TERMINAL.includes(String(pgRow.status))) {
            await applyTemplateToCase(id, recommendedTemplateId, "system");
            effectiveTasks = await pgQuery(
              `SELECT * FROM case_tasks WHERE case_id=$1 ORDER BY sort_order, created_at`, [id],
            );
            pgRow.template_id = recommendedTemplateId;
          }
        }
      } catch (e) {
        logger.warn("cases.recommend_template_failed", { caseId: id, err: e.message });
      }

      // ── Generar playbook MITRE + enrichment ─────────────────────────────
      const enrichmentData = pgRow.enrichment_data ?? {};
      const caseForPlaybook = {
        severity_text:     pgRow.severity,
        severity_score:    pgRow.score,
        mitre_tactic_id:   pgRow.mitre_tactic_id,
        mitre_tactic_name: pgRow.mitre_tactic_name,
        ioc_value:         pgRow.ioc_value,
        ioc_type:          pgRow.ioc_type,
        source_log:        pgRow.source_log,
        score_breakdown:   pgRow.score_breakdown,
      };
      const playbook = generatePlaybook(caseForPlaybook, enrichmentData.iocEnrichment ?? enrichmentData);

      // Persistir recommended_action si aún no está generado
      if (!pgRow.recommended_action && playbook.title) {
        const txt = generateRecommendedAction(caseForPlaybook, enrichmentData.iocEnrichment ?? enrichmentData);
        pgQuery(
          `UPDATE incident_cases_pg SET recommended_action=$1, updated_at=now() WHERE id=$2`,
          [txt, id]
        ).catch(() => {});
      }

      res.json({
        ...pgRow,
        enrichmentData,
        // Clasificación eCSIRT/MISP derivada (taxonomía estándar CSIRT).
        incidentClass: classifyEcsirt({
          mitreTacticId: pgRow.mitre_tactic_id,
          iocType:       pgRow.ioc_type,
          sourceLog:     pgRow.source_log,
          enrichment:    enrichmentData.iocEnrichment ?? enrichmentData,
        }),
        tasks: effectiveTasks,
        assets,
        iocs,
        evidences,
        timeline,
        playbook,
        recommended_template_id: recommendedTemplateId,
        sla_min:   getSlaMin(pgRow.severity),
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── PATCH /api/cases/:id — Update case metadata ───────────────────────────
  r.patch("/:id", async (req, res) => {
    const acl = await checkCaseAccess(req, res, req.params.id, "write");
    if (!acl.ok) return;
    const allowed = [
      "incident_category","functional_impact","information_impact",
      "recoverability","root_cause","lessons_learned","containment_status",
    ];
    const sets = [];
    const vals = [req.params.id];
    let i = 2;
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        sets.push(`${key}=$${i++}`);
        vals.push(req.body[key]);
      }
    }
    if (!sets.length) return res.status(400).json({ error: "Nada que actualizar" });
    sets.push("updated_at=now()");
    try {
      await pgQuery(
        `UPDATE incident_cases_pg SET ${sets.join(",")} WHERE id=$1`,
        vals
      );
      // Timeline event
      if (req.body.operatorCi) {
        await addTimelineEvent(req.params.id, {
          eventType: "NOTE",
          title: "Metadatos actualizados",
          description: `Campos actualizados: ${sets.filter(s => !s.startsWith("updated")).join(", ")}`,
          operatorCi: req.body.operatorCi,
          source: "MANUAL",
        });
      }
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // TEMPLATES
  // ══════════════════════════════════════════════════════════════════════════

  r.get("/templates/all", async (_req, res) => {
    try { res.json(await listTemplates()); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.get("/templates/suggest", async (req, res) => {
    try {
      // Fix #12: aceptamos mitreTacticId vía querystring para sumar al ranking.
      const tactic = req.query.mitreTacticId ?? req.query.mitre_tactic_id ?? null;
      res.json(await suggestTemplate(req.query.severity, req.query.category, tactic));
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.get("/templates/:id", async (req, res) => {
    try {
      const tpl = await getTemplate(req.params.id);
      if (!tpl) return res.status(404).json({ error: "Template no encontrado" });
      res.json(tpl);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.post("/templates", async (req, res) => {
    if (!req.body.name) return res.status(400).json({ error: "name requerido" });
    try {
      const id = await createTemplate(req.body, req.body.createdBy);
      res.status(201).json({ id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.put("/templates/:id", async (req, res) => {
    try {
      await updateTemplate(req.params.id, req.body);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.delete("/templates/:id", async (req, res) => {
    try {
      await deleteTemplate(req.params.id);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Apply template to existing case
  r.post("/:id/apply-template", async (req, res) => {
    const { templateId, operatorCi } = req.body ?? {};
    if (!templateId) return res.status(400).json({ error: "templateId requerido" });
    try {
      const result = await applyTemplateToCase(req.params.id, templateId, operatorCi);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(err.message.includes("no encontrado") ? 404 : 500).json({ error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // TASKS
  // ══════════════════════════════════════════════════════════════════════════

  r.get("/:id/tasks", async (req, res) => {
    try {
      res.json(await pgQuery(
        `SELECT * FROM case_tasks WHERE case_id=$1 ORDER BY sort_order, created_at`,
        [req.params.id]
      ));
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.post("/:id/tasks", async (req, res) => {
    const { title, description, phase, assignee, dueAt, operatorCi } = req.body ?? {};
    if (!title) return res.status(400).json({ error: "title requerido" });
    try {
      const id = randomUUID();
      await pgQuery(
        `INSERT INTO case_tasks
           (id, case_id, title, description, phase, assignee, due_at, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [id, req.params.id, title, description ?? null, phase ?? "DETECTION",
         assignee ?? null, dueAt ?? null, operatorCi ?? "system"]
      );
      await addTimelineEvent(req.params.id, {
        eventType: "NOTE", phase: phase ?? "DETECTION",
        title: `Tarea añadida: ${title}`, operatorCi, source: "MANUAL",
      });
      res.status(201).json({ id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.patch("/:id/tasks/:taskId", async (req, res) => {
    const acl = await checkCaseAccess(req, res, req.params.id, "write");
    if (!acl.ok) return;
    const { status, assignee, completedAt, operatorCi } = req.body ?? {};
    const sets = ["updated_at=now()"];
    // El UPDATE filtra por (id, case_id) para impedir mutar tareas de otro
    // caso pasando un taskId arbitrario.
    const vals = [req.params.taskId, req.params.id];
    let i = 3;
    if (status     !== undefined) {
      sets.push(`status=$${i++}`); vals.push(status);
      // A3 audit 2026-06-05: autollenar/limpiar completed_at según el status si el
      // caller no lo manda explícito (el front solo envía {status:"DONE"}). Sin
      // esto, completed_at quedaba NULL y las métricas de cierre de tarea eran
      // incalculables.
      if (completedAt === undefined) {
        if (status === "DONE" || status === "SKIPPED") {
          sets.push("completed_at=COALESCE(completed_at, now())");
        } else if (status === "OPEN" || status === "IN_PROGRESS") {
          sets.push("completed_at=NULL");
        }
      }
    }
    if (assignee   !== undefined) { sets.push(`assignee=$${i++}`);      vals.push(assignee); }
    if (completedAt !== undefined){ sets.push(`completed_at=$${i++}`);  vals.push(completedAt); }
    try {
      const result = await pgQuery(
        `UPDATE case_tasks SET ${sets.join(",")} WHERE id=$1 AND case_id=$2 RETURNING id`,
        vals,
      );
      if (result.length === 0) {
        return res.status(404).json({ error: "Tarea no encontrada en este caso" });
      }
      // KPI/actividad (2026-06-16): CUALQUIER acción del operador sobre una tarea
      // cuenta como actividad manual del caso — no sólo completarla. Antes sólo
      // `DONE` dejaba rastro, así que avanzar una tarea (IN_PROGRESS), reabrirla,
      // saltarla o reasignarla era invisible al seguimiento (followup digest) y a
      // "última actividad manual". Registramos un evento MANUAL describiendo el
      // cambio para que toda interacción del operador alimente el KPI de actividad.
      const taskShort = `Task #${req.params.taskId.slice(0, 6)}`;
      const STATUS_VERB = {
        DONE: "completó", SKIPPED: "saltó", IN_PROGRESS: "avanzó", OPEN: "reabrió",
      };
      if (status !== undefined) {
        await addTimelineEvent(req.params.id, {
          eventType: "NOTE",
          title: `Tarea ${STATUS_VERB[status] ?? "actualizó"}: ${taskShort}`,
          description: taskShort,
          operatorCi, source: "MANUAL",
        });
      } else if (assignee !== undefined) {
        await addTimelineEvent(req.params.id, {
          eventType: "NOTE",
          title: `Tarea reasignada: ${taskShort}`,
          description: assignee ? `→ @${assignee}` : "sin asignar",
          operatorCi, source: "MANUAL",
        });
      }
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.delete("/:id/tasks/:taskId", async (req, res) => {
    try {
      await pgQuery(`DELETE FROM case_tasks WHERE id=$1 AND case_id=$2`,
        [req.params.taskId, req.params.id]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ASSETS
  // ══════════════════════════════════════════════════════════════════════════

  r.get("/:id/assets", async (req, res) => {
    try {
      res.json(await pgQuery(`SELECT * FROM case_assets WHERE case_id=$1 ORDER BY created_at`, [req.params.id]));
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.post("/:id/assets", async (req, res) => {
    const { assetType, assetValue, hostname, ipAddress, domain, os, description, compromised, addedBy } = req.body ?? {};
    if (!assetValue) return res.status(400).json({ error: "assetValue requerido" });
    try {
      const id = randomUUID();
      await pgQuery(
        `INSERT INTO case_assets
           (id, case_id, asset_type, asset_value, hostname, ip_address, domain, os, description, compromised, added_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [id, req.params.id, assetType ?? "HOST", assetValue,
         hostname ?? null, ipAddress ?? null, domain ?? null, os ?? null,
         description ?? null, compromised ?? false, addedBy ?? "system"]
      );
      await addTimelineEvent(req.params.id, {
        eventType: "ASSET",
        title: `Asset añadido: ${assetValue}`,
        description: `Tipo: ${assetType ?? "HOST"}`,
        operatorCi: addedBy,
        relatedAssetId: id,
        source: "MANUAL",
      });
      res.status(201).json({ id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.patch("/:id/assets/:assetId", async (req, res) => {
    const allowed = ["compromised","containment_status","description","hostname","ip_address","os"];
    const sets = ["updated_at=now()"];
    const vals = [req.params.assetId];
    let i = 2;
    for (const k of allowed) {
      const v = req.body[k] ?? req.body[toCamel(k)];
      if (v !== undefined) { sets.push(`${k}=$${i++}`); vals.push(v); }
    }
    try {
      await pgQuery(`UPDATE case_assets SET ${sets.join(",")} WHERE id=$1`, vals);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.delete("/:id/assets/:assetId", async (req, res) => {
    try {
      await pgQuery(`DELETE FROM case_assets WHERE id=$1 AND case_id=$2`, [req.params.assetId, req.params.id]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // CVEs (B1 audit Casos 2026-05-21)
  // ══════════════════════════════════════════════════════════════════════════
  //
  // GET /api/cases/:id/cves?days=7
  //
  // Devuelve dos vistas consolidadas del riesgo CVE del caso:
  //   · `wazuhCves`  — CVEs reportadas por Wazuh vulnerability-detector para
  //     los hosts/IPs registrados en `case_assets` (última ventana de N días).
  //   · `patterns`   — Heurísticas client-side migradas a backend
  //     (Log4Shell, ProxyLogon, FortiGate auth bypass, etc.) aplicadas sobre
  //     los `case_iocs` del caso.
  //
  // Estos dos canales se complementan: el primero detecta vulnerabilidades
  // *instaladas* (paquete vulnerable presente); el segundo detecta intentos
  // *de explotación* (firma del payload). Un caso puede tener uno, otro o
  // ambos.
  //
  // Respuesta: { caseId, windowDays, wazuhCves[], patterns[], maxTone,
  //              counts, errors? }
  r.get("/:id/cves", async (req, res) => {
    const acl = await checkCaseAccess(req, res, req.params.id, "read");
    if (!acl.ok) return;

    const days = Math.max(1, Math.min(90, Number(req.query.days) || 7));
    const caseId = req.params.id;

    try {
      const [assets, iocs] = await Promise.all([
        pgQuery(
          `SELECT hostname, ip_address, asset_value, asset_type
             FROM case_assets WHERE case_id=$1`,
          [caseId],
        ),
        pgQuery(
          `SELECT ioc_value, ioc_type, description
             FROM case_iocs WHERE case_id=$1`,
          [caseId],
        ),
      ]);

      // ── 1. Wazuh vulnerability-detector ──────────────────────────────────
      // Construimos tuplas (host, ip) únicas a partir de los assets del caso.
      // Para asset_type=HOST sin hostname explícito, usamos asset_value.
      // Para asset_type=IP sin ip_address, idem. Esto cubre los casos donde
      // el analista cargó el asset "rápido" con solo asset_value.
      const tuples = new Map();
      for (const a of assets) {
        const host = (a.hostname
          ?? (a.asset_type === "HOST" ? a.asset_value : null))?.trim() || null;
        const ip = (a.ip_address
          ?? (a.asset_type === "IP" ? a.asset_value : null))?.trim() || null;
        if (!host && !ip) continue;
        const key = `${host ?? ""}|${ip ?? ""}`;
        if (!tuples.has(key)) tuples.set(key, { host, ip });
      }

      const wazuhRows = [];
      const errors = [];
      if (runQuery && tuples.size) {
        const results = await Promise.all(
          [...tuples.values()].map(async ({ host, ip }) => {
            const resolved = resolveNamedTrinoQuery(
              "lh.wazuh.cves_for_host",
              { host_name: host, host_ip: ip, days, limit: 100 },
              config,
            );
            if (!resolved.ok) {
              return { rows: [], host, ip, error: resolved.error };
            }
            try {
              const rows = await runQuery(resolved.sql, SESSION);
              return { rows, host, ip };
            } catch (err) {
              return { rows: [], host, ip, error: err?.message ?? String(err) };
            }
          }),
        );
        for (const r of results) {
          if (r.error) errors.push(`Wazuh ${r.host ?? ""}|${r.ip ?? ""}: ${r.error}`);
          for (const row of r.rows) wazuhRows.push(row);
        }
      }

      // Dedup por cve_id: si el mismo CVE apareció para varios hosts del
      // caso, nos quedamos con el cvss_score mayor pero sumamos alert_count.
      const wazuhMap = new Map();
      for (const row of wazuhRows) {
        if (!row?.cve_id) continue;
        const cur = wazuhMap.get(row.cve_id);
        const score = Number(row.cvss_score) || 0;
        if (!cur) {
          wazuhMap.set(row.cve_id, { ...row, cvss_score: score });
        } else {
          cur.alert_count = Number(cur.alert_count ?? 0) + Number(row.alert_count ?? 0);
          if (score > Number(cur.cvss_score)) {
            cur.cvss_score = score;
            cur.cvss_source = row.cvss_source ?? cur.cvss_source;
            cur.severity    = row.severity    ?? cur.severity;
          }
        }
      }
      const wazuhCves = [...wazuhMap.values()].sort((a, b) =>
        Number(b.cvss_score) - Number(a.cvss_score)
      );

      // ── 2. Pattern matching sobre IOCs y descripciones ───────────────────
      const patterns = [];
      const seen = new Set();
      for (const ioc of iocs) {
        const text = [ioc.ioc_value, ioc.description].filter(Boolean).join("\n");
        const hits = detectCvesInText(text);
        for (const h of hits) {
          const key = (h.name ?? "") + (h.cve ?? "") + (ioc.ioc_value ?? "");
          if (seen.has(key)) continue;
          seen.add(key);
          patterns.push({
            ...h,
            sourceIocValue: ioc.ioc_value,
            sourceIocType:  ioc.ioc_type,
          });
        }
      }

      // ── 3. NVD enrichment + CISA KEV ─────────────────────────────────────
      // Recolectamos todos los cve_id únicos (Wazuh + patterns) y consultamos
      // los caches locales. Los faltantes se hidratan async (no bloquea).
      // El cliente verá `nvd: null` para los aún no hidratados y refresh los
      // revela en el próximo poll.
      const allCveIds = new Set();
      for (const w of wazuhCves) if (w.cve_id) allCveIds.add(w.cve_id);
      for (const p of patterns)  if (p.cve)    allCveIds.add(p.cve);

      const [nvdMap, kevMap] = await Promise.all([
        getNvdEnrichmentBatch([...allCveIds]).catch((e) => {
          errors.push(`NVD: ${e?.message ?? String(e)}`);
          return new Map();
        }),
        getKevByIds([...allCveIds]).catch((e) => {
          errors.push(`KEV: ${e?.message ?? String(e)}`);
          return new Map();
        }),
      ]);

      function decorateNvdKev(cveId) {
        const nvd = nvdMap.get(cveId) ?? null;
        const kev = kevMap.get(cveId) ?? null;
        return {
          nvd: nvd ? {
            cvssV3Score:    nvd.cvss_v3_score != null ? Number(nvd.cvss_v3_score) : null,
            cvssV3Severity: nvd.cvss_v3_severity,
            cvssV3Vector:   nvd.cvss_v3_vector,
            cvssV2Score:    nvd.cvss_v2_score != null ? Number(nvd.cvss_v2_score) : null,
            cweIds:         nvd.cwe_ids ?? [],
            description:    nvd.description,
            references:     nvd.reference_urls ?? [],
            vulnStatus:     nvd.vuln_status,
            publishedAt:    nvd.published_at,
            // EPSS (I1): probabilidad de explotación a 30 días + percentil.
            epssScore:      nvd.epss_score != null ? Number(nvd.epss_score) : null,
            epssPercentile: nvd.epss_percentile != null ? Number(nvd.epss_percentile) : null,
          } : null,
          kev: kev ? {
            vendorProject:      kev.vendor_project,
            product:            kev.product,
            vulnerabilityName:  kev.vulnerability_name,
            dateAdded:          kev.date_added,
            shortDescription:   kev.short_description,
            requiredAction:     kev.required_action,
            dueDate:            kev.due_date,
            knownRansomwareUse: kev.known_ransomware_use === true,
          } : null,
        };
      }

      // Decoramos cada CVE con su nvd/kev. Si Wazuh trajo CVSSv2 y NVD aporta
      // CVSSv3, preferimos el v3 para el cálculo de tono (es el oficial).
      const wazuhDecorated = wazuhCves.map((w) => {
        const { nvd, kev } = decorateNvdKev(w.cve_id);
        const officialScore = nvd?.cvssV3Score ?? (Number(w.cvss_score) || 0);
        return { ...w, nvd, kev, officialScore };
      });
      const patternsDecorated = patterns.map((p) => {
        const dec = p.cve ? decorateNvdKev(p.cve) : { nvd: null, kev: null };
        return { ...p, ...dec };
      });

      // Severidad consolidada — KEV eleva siempre a "crit"; sin KEV usamos
      // CVSS v3 oficial (NVD) o el de Wazuh como fallback.
      const wazuhTones = wazuhDecorated.map((w) => {
        if (w.kev) return { tone: "crit" };
        const s = w.officialScore;
        return { tone: s >= 9 ? "crit" : s >= 7 ? "high" : "warn" };
      });
      const patternTones = patternsDecorated.map((p) => {
        if (p.kev) return { tone: "crit" };
        return { tone: p.tone };
      });

      // ── 4. R7 (audit 2026-06-05): auto-sugerir escalación por KEV / EPSS alto ──
      // Un CVE en CISA KEV (explotación activa conocida) o con EPSS alto en un
      // asset del caso es señal fuerte de respuesta urgente, pero el scoring SQL
      // (nocturno, IOC-level) no la ve — los CVEs se descubren acá, lazy, vía
      // Wazuh per-asset. Reusamos el mecanismo `escalation_suggested` (que ya
      // gatea el cierre FP 4-ojos y lo surfacea la UI) en vez de tocar el motor
      // de scoring. Best-effort, idempotente, sólo en casos abiertos. Soft: NO
      // cambia el estado, sólo sugiere. Desactivable con CASE_KEV_AUTO_SUGGEST=off.
      const allDecorated = [...wazuhDecorated, ...patternsDecorated];
      const kevCveIds = [...new Set(allDecorated.filter((c) => c.kev).map((c) => c.cve_id ?? c.cve).filter(Boolean))];
      const maxEpss = allDecorated.reduce(
        (m, c) => Math.max(m, Number(c.nvd?.epssScore ?? 0) || 0), 0);
      const epssMin = Math.max(0, Math.min(1, Number(process.env.CASE_ESCALATE_EPSS_MIN ?? 0.5) || 0.5));
      const kevSuggestOn = (process.env.CASE_KEV_AUTO_SUGGEST ?? "on").toLowerCase() !== "off";
      let escalationSuggested = false;
      if (kevSuggestOn && (kevCveIds.length > 0 || maxEpss >= epssMin)) {
        const bits = [];
        if (kevCveIds.length) bits.push(`CISA KEV: ${kevCveIds.slice(0, 5).join(", ")}${kevCveIds.length > 5 ? "…" : ""} (explotación activa)`);
        if (maxEpss >= epssMin) bits.push(`EPSS ${(maxEpss * 100).toFixed(0)}%`);
        const reason = `Escalación sugerida por vulnerabilidad — ${bits.join(" · ")}`;
        try {
          const [row] = await pgQuery(
            `UPDATE incident_cases_pg
                SET escalation_suggested   = true,
                    escalation_reason_auto = $2,
                    updated_at             = now()
              WHERE id = $1
                AND status NOT IN ('CERRADO','FALSO_POSITIVO','ESCALADO')
                AND COALESCE(escalation_suggested, false) = false
              RETURNING id`,
            [caseId, reason],
          );
          escalationSuggested = Boolean(row);
          if (escalationSuggested) {
            invalidateCasesKpisCache();
            logger.info({ caseId, kevCveIds, maxEpss }, "[cves] R7: escalación sugerida por KEV/EPSS");
          }
        } catch (e) {
          logger.warn({ caseId, err: e?.message }, "[cves] R7: no se pudo sugerir escalación");
        }
      }

      res.json({
        caseId,
        windowDays: days,
        wazuhCves: wazuhDecorated,
        patterns:  patternsDecorated,
        maxTone:   maxCveTone([...patternTones, ...wazuhTones]),
        escalationSuggested,
        kevEpss:   { kevCveIds, maxEpss, epssMin },
        counts: {
          wazuh:     wazuhDecorated.length,
          patterns:  patternsDecorated.length,
          assets:    assets.length,
          iocs:      iocs.length,
          nvdHits:   nvdMap.size,
          kevHits:   kevMap.size,
        },
        ...(errors.length ? { errors } : {}),
      });
    } catch (err) {
      res.status(500).json({ error: err?.message ?? String(err) });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // IOCs
  // ══════════════════════════════════════════════════════════════════════════

  r.get("/:id/iocs", async (req, res) => {
    try {
      res.json(await pgQuery(
        `SELECT * FROM case_iocs WHERE case_id=$1 ORDER BY is_primary DESC, created_at`,
        [req.params.id]
      ));
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.post("/:id/iocs", async (req, res) => {
    const { iocType, iocValue, tlp, description, tags, isPrimary, addedBy } = req.body ?? {};
    if (!iocType || !iocValue) return res.status(400).json({ error: "iocType e iocValue requeridos" });
    try {
      const id = randomUUID();
      await pgQuery(
        `INSERT INTO case_iocs
           (id, case_id, ioc_type, ioc_value, tlp, description, tags, is_primary, added_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (case_id, ioc_type, ioc_value) DO NOTHING`,
        [id, req.params.id, iocType, iocValue, tlp ?? "AMBER",
         description ?? null, tags ?? [], isPrimary ?? false, addedBy ?? "system"]
      );
      await addTimelineEvent(req.params.id, {
        eventType: "IOC",
        title: `IOC añadido: ${iocValue}`,
        description: `Tipo: ${iocType} | TLP: ${tlp ?? "AMBER"}`,
        operatorCi: addedBy,
        relatedIocId: id,
        source: "MANUAL",
      });
      res.status(201).json({ id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.delete("/:id/iocs/:iocId", async (req, res) => {
    try {
      await pgQuery(`DELETE FROM case_iocs WHERE id=$1 AND case_id=$2`, [req.params.iocId, req.params.id]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // EVIDENCES
  // ══════════════════════════════════════════════════════════════════════════

  r.get("/:id/evidences", async (req, res) => {
    try {
      res.json(await pgQuery(
        `SELECT * FROM case_evidences WHERE case_id=$1 ORDER BY collected_at DESC`,
        [req.params.id]
      ));
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.post("/:id/evidences", async (req, res) => {
    const {
      evidenceType, name, description, collectedBy,
      hashSha256, sizeBytes, storagePath, tags,
    } = req.body ?? {};
    if (!name || !collectedBy) return res.status(400).json({ error: "name y collectedBy requeridos" });
    try {
      const id = randomUUID();
      await pgQuery(
        `INSERT INTO case_evidences
           (id, case_id, evidence_type, name, description, collected_by, hash_sha256, size_bytes, storage_path, tags)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [id, req.params.id, evidenceType ?? "LOG", name, description ?? null,
         collectedBy, hashSha256 ?? null, sizeBytes ?? null, storagePath ?? null, tags ?? []]
      );
      await addTimelineEvent(req.params.id, {
        eventType: "EVIDENCE",
        title: `Evidencia registrada: ${name}`,
        description: `Tipo: ${evidenceType ?? "LOG"} | Hash: ${hashSha256 ?? "N/A"}`,
        operatorCi: collectedBy,
        relatedEvidenceId: id,
        source: "MANUAL",
      });
      res.status(201).json({ id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.delete("/:id/evidences/:evId", async (req, res) => {
    try {
      await pgQuery(`DELETE FROM case_evidences WHERE id=$1 AND case_id=$2`, [req.params.evId, req.params.id]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // TIMELINE
  // ══════════════════════════════════════════════════════════════════════════

  r.get("/:id/timeline", async (req, res) => {
    try {
      res.json(await getTimeline(req.params.id));
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  r.post("/:id/timeline", async (req, res) => {
    const { eventType, phase, title, description, operatorCi, eventTs, metadata } = req.body ?? {};
    if (!title && !description) return res.status(400).json({ error: "title o description requerido" });
    try {
      const id = await addTimelineEvent(req.params.id, {
        eventType: eventType ?? "NOTE",
        phase, title, description, operatorCi,
        source: "MANUAL",
        eventTs, metadata,
      });
      res.status(201).json({ id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // REPORT
  // ══════════════════════════════════════════════════════════════════════════

  r.get("/:id/report", async (req, res) => {
    try {
      const [caseRows, tasks, assets, iocs, evidences, timeline] = await Promise.all([
        pgQuery(`SELECT * FROM incident_cases_pg WHERE id=$1 LIMIT 1`, [req.params.id]),
        pgQuery(`SELECT * FROM case_tasks     WHERE case_id=$1 ORDER BY sort_order`, [req.params.id]),
        pgQuery(`SELECT * FROM case_assets    WHERE case_id=$1 ORDER BY created_at`, [req.params.id]),
        pgQuery(`SELECT * FROM case_iocs      WHERE case_id=$1 ORDER BY is_primary DESC`, [req.params.id]),
        pgQuery(`SELECT * FROM case_evidences WHERE case_id=$1 ORDER BY collected_at`, [req.params.id]),
        getTimeline(req.params.id),
      ]);
      if (!caseRows.length) return res.status(404).json({ error: "Caso no encontrado" });
      const c = caseRows[0];

      const parts = { tasks, assets, iocs, evidences, timeline };
      if (String(req.query.format).toLowerCase() === "html") {
        // Vista previa HTML (inline) — usada por el modal "Enviar informe al cliente".
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.send(generateHtmlReport(c, parts));
      }
      const report = generateMarkdownReport(c, parts);
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="case-${c.id.slice(0,8)}-report.md"`);
      res.send(report);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── Helper: arma el documento playbook (consulta KB → reutiliza o genera) ─────
  // forceNew=true ignora la base de conocimiento y siempre genera + persiste uno
  // nuevo. Devuelve { html, md, title, source, reused, kbSlug }.
  async function resolvePlaybookDoc(caseId, { forceNew = false, operatorCi = "system" } = {}) {
    const caseRows = await pgQuery(`SELECT * FROM incident_cases_pg WHERE id=$1 LIMIT 1`, [caseId]);
    if (!caseRows.length) { const e = new Error("Caso no encontrado"); e.status = 404; throw e; }
    const c = caseRows[0];

    // 1. Consultar la base de conocimiento: ¿ya hay un playbook reutilizable?
    if (!forceNew) {
      const existing = await findReusablePlaybook(contextKeyFor(c));
      if (existing) {
        return { html: existing.body_html, md: existing.body_md, title: existing.title,
                 source: existing.generated_by, reused: true, kbSlug: existing.kb_slug ?? null };
      }
    }
    // 2. Generar (LLM con fallback rule-based) y persistir + publicar en KB.
    const doc = await generateCasePlaybookDoc(c, {});
    const saved = await savePlaybook({ caseId, doc, createdBy: operatorCi });
    return { html: doc.bodyHtml, md: doc.bodyMd, title: doc.title,
             source: doc.source, reused: false, kbSlug: saved.kb_slug ?? null };
  }

  // ── GET /:id/playbook.html — vista previa (genera/reutiliza, NO envía) ────────
  r.get("/:id/playbook.html", async (req, res) => {
    try {
      const operatorCi = (await resolveJwtOperatorCi(req)) || req.user?.preferred_username || "system";
      const doc = await resolvePlaybookDoc(req.params.id, {
        forceNew: req.query.forceNew === "true", operatorCi,
      });
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(doc.html);
    } catch (err) { res.status(err.status || 500).json({ ok: false, error: err.message }); }
  });

  // ── POST /:id/enrich-now — Manual IOC enrichment refresh ──────────────────
  // Calls VT, Shodan, AbuseIPDB, MISP, URLhaus in parallel and persists results.
  // Rate-limited a 3/min/user (P4 A6) — ver enrichLimiter arriba.
  r.post("/:id/enrich-now", enrichLimiter, async (req, res) => {
    try {
      const row = (await pgQuery(
        `SELECT id, ioc_value, ioc_type FROM incident_cases_pg WHERE id=$1 LIMIT 1`,
        [req.params.id],
      ))[0];
      if (!row) return res.status(404).json({ error: "Caso no encontrado" });
      if (!row.ioc_value) return res.status(400).json({ error: "Sin IOC para enriquecer" });

      // force: el refresh manual siempre re-consulta (omite la caché TTL).
      const enr = await enrichIoc(row.ioc_value, row.ioc_type ?? "ip", { force: true });
      if (!enr) return res.status(500).json({ error: "Fallo en enriquecimiento" });

      // Cruce de las CVEs expuestas por Shodan con CISA KEV (explotación activa).
      // Lookup barato contra cve_kev (sin fetch por-CVE); recalcula el veredicto
      // si hay KEV para reflejar el riesgo real de exposición.
      const shodanVulns = enr.sources?.shodan?.vulns ?? [];
      if (shodanVulns.length > 0) {
        try {
          const kevMap = await getKevByIds(shodanVulns);
          if (kevMap.size > 0) {
            const kevIds = shodanVulns.filter((v) => kevMap.has(v));
            enr.summary.shodanKevVulns = kevIds;
            enr.summary.shodanKevCount = kevIds.length;
            if (enr.sources.shodan) enr.sources.shodan.kevVulns = kevIds;
            enr.verdict = computeIocVerdict({ summary: enr.summary, sources: enr.sources });
          }
        } catch { /* KEV no-fatal */ }
      }

      const s = enr.summary;

      // Update primary IOC record with enrichment fields
      await pgQuery(
        `UPDATE case_iocs
            SET vt_malicious   = $1,
                vt_permalink   = $2,
                abuse_score    = $3,
                in_misp        = $4,
                shodan_summary = $5,
                enriched_at    = now()
          WHERE case_id = $6 AND is_primary = true`,
        [
          s.vtMalicious     ?? null,
          enr.sources?.virustotal?.permalink ?? null,
          s.abuseConfidence ?? null,
          s.inMisp          ?? false,
          enr.sources?.shodan
            ? JSON.stringify({
                country:  enr.sources.shodan.country,
                org:      enr.sources.shodan.org,
                ports:    enr.sources.shodan.ports?.slice(0, 10),
                vulns:    enr.sources.shodan.vulns?.slice(0, 5),
                services: enr.sources.shodan.services?.slice(0, 5),
              })
            : null,
          req.params.id,
        ],
      );

      // Persist full enrichment (summary + sources detalladas + status + veredicto).
      await pgQuery(
        `UPDATE incident_cases_pg
            SET enrichment_data = enrichment_data || $1::jsonb,
                updated_at      = now()
          WHERE id = $2`,
        [buildEnrichmentJsonb(enr), req.params.id],
      );

      // KPI/actividad (2026-06-16): la quick action "Re-enriquecer IOC" es una
      // acción del operador → deja rastro MANUAL para alimentar actividad/followup.
      try {
        const opCi = await resolveJwtOperatorCi(req);
        await addTimelineEvent(req.params.id, {
          eventType: "NOTE",
          title: "Re-enriquecimiento manual del IOC",
          description: `${row.ioc_value} · veredicto ${enr.verdict?.label ?? enr.verdict ?? "—"}`,
          operatorCi: opCi, source: "MANUAL",
        });
      } catch { /* registro best-effort */ }

      res.json({
        ok:         true,
        enrichedAt: enr.enrichedAt,
        summary:    s,
        status:     enr.status,
        verdict:    enr.verdict,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/cases/:id/suppression ────────────────────────────────────────
  // Devuelve la supresión actual del caso (si la hay), el dedup_key resuelto
  // y los TTL esperados según severidad/motivo. Si el caso aún está abierto,
  // `suppression` viene null y `expected_ttl_days` informa cuánto duraría
  // la supresión si el operador cerrara o marcara FP ahora.
  //
  // Resiliencia: si la columna `dedup_key`, la tabla `case_suppressions` o la
  // función `suppression_days` no existen (entorno sin migrations 023/027/
  // 04_case_suppressions), devolvemos null/empty + `infra_missing` para que
  // la UI lo señale al operador en vez de mostrar 500.
  r.get("/:id/suppression", async (req, res) => {
    const { id } = req.params;
    const MISSING_CODES = new Set(["42703", "42P01", "42883"]); // column/relation/function
    const infraMissing = [];

    try {
      // Caso base (sin dedup_key — opcional)
      let caseRow;
      try {
        caseRow = (await pgQuery(
          `SELECT id, severity, status, dedup_key, ioc_value
             FROM incident_cases_pg WHERE id=$1 LIMIT 1`,
          [id],
        ))[0];
      } catch (err) {
        if (MISSING_CODES.has(err?.code)) {
          infraMissing.push("incident_cases_pg.dedup_key");
          caseRow = (await pgQuery(
            `SELECT id, severity, status, ioc_value, NULL::text AS dedup_key
               FROM incident_cases_pg WHERE id=$1 LIMIT 1`,
            [id],
          ))[0];
        } else {
          throw err;
        }
      }
      if (!caseRow) return res.status(404).json({ error: "case not found" });

      // TTL esperados por severidad — depende de legacyhunt_soc.suppression_days()
      let ttls = { fp_days: null, closed_days: null, auto_closed_days: null };
      try {
        const r2 = (await pgQuery(
          `SELECT
             legacyhunt_soc.suppression_days('FALSO_POSITIVO', $1::varchar)::int AS fp_days,
             legacyhunt_soc.suppression_days('CERRADO',        $1::varchar)::int AS closed_days,
             legacyhunt_soc.suppression_days('AUTO_CLOSED',    $1::varchar)::int AS auto_closed_days`,
          [String(caseRow.severity ?? "MEDIUM")],
        ))[0];
        if (r2) {
          ttls = {
            fp_days:          r2.fp_days          != null ? Number(r2.fp_days)          : null,
            closed_days:      r2.closed_days      != null ? Number(r2.closed_days)      : null,
            auto_closed_days: r2.auto_closed_days != null ? Number(r2.auto_closed_days) : null,
          };
        }
      } catch (err) {
        if (MISSING_CODES.has(err?.code)) {
          infraMissing.push("legacyhunt_soc.suppression_days");
        } else {
          throw err;
        }
      }

      // Supresión vigente — depende de legacyhunt_soc.case_suppressions
      let suppression = null;
      if (caseRow.dedup_key) {
        try {
          const sRows = await pgQuery(
            `SELECT
               dedup_key, reason, severity, suppressed_until, suppressed_by,
               original_case_id, original_ioc, created_at, updated_at,
               suppressed_until > now() AS active,
               ROUND(EXTRACT(EPOCH FROM (suppressed_until - now())) / 60.0)::int AS minutes_remaining,
               ROUND(EXTRACT(EPOCH FROM (suppressed_until - created_at)) / 86400.0, 1)::numeric AS window_days
             FROM legacyhunt_soc.case_suppressions
             WHERE dedup_key = $1
             LIMIT 1`,
            [caseRow.dedup_key],
          );
          if (sRows.length) {
            const s = sRows[0];
            suppression = {
              dedup_key:         s.dedup_key,
              reason:            s.reason,
              severity:          s.severity,
              suppressed_until:  s.suppressed_until,
              suppressed_by:     s.suppressed_by,
              minutes_remaining: s.minutes_remaining != null ? Number(s.minutes_remaining) : null,
              window_days:       s.window_days       != null ? Number(s.window_days)       : null,
              original_case_id:  s.original_case_id,
              original_ioc:      s.original_ioc,
              created_at:        s.created_at,
              updated_at:        s.updated_at,
              active:            !!s.active,
            };
          }
        } catch (err) {
          if (MISSING_CODES.has(err?.code)) {
            infraMissing.push("legacyhunt_soc.case_suppressions");
          } else {
            throw err;
          }
        }
      }

      res.json({
        case_id:   id,
        dedup_key: caseRow.dedup_key ?? null,
        severity:  caseRow.severity  ?? null,
        status:    caseRow.status    ?? null,
        ioc_value: caseRow.ioc_value ?? null,
        suppression,
        expected_ttl_days: ttls,
        infra_missing: infraMissing.length > 0 ? infraMissing : null,
      });
    } catch (err) {
      res.status(500).json({ error: err?.message ?? "internal" });
    }
  });

  // ── I2 (audit 2026-06-05) — Correlación por IOC ──────────────────────────
  // GET /api/cases/:id/related → otros casos que comparten el ioc_value de
  // este caso. Pivote de investigación: "¿este IOC aparece en otros casos
  // activos?". Devolvemos los ABIERTOS en detalle (accionables, ordenados por
  // recencia) y sólo un conteo de los terminales (la mayoría son recurrencias
  // auto-cerradas — ruido si se listan, señal útil como número).
  //
  // Index-friendly: el filtro de abiertos usa idx_cases_ioc_open (parcial
  // sobre ioc_value WHERE status no-terminal); el conteo de cerrados usa
  // idx_cases_ioc_closed. Cap 50 abiertos.
  r.get("/:id/related", async (req, res) => {
    const { id } = req.params;
    try {
      const [base] = await pgQuery(
        `SELECT ioc_value, ioc_type FROM incident_cases_pg WHERE id = $1 LIMIT 1`,
        [id],
      );
      if (!base) return res.status(404).json({ error: "case not found" });
      const iocValue = base.ioc_value ? String(base.ioc_value).trim() : null;
      if (!iocValue) {
        return res.json({
          case_id: id, ioc_value: null, ioc_type: base.ioc_type ?? null,
          open: [], open_count: 0, closed_count: 0, total: 0,
        });
      }

      const TERMINAL = `('CERRADO','FALSO_POSITIVO')`;
      const [openRows, closedAgg] = await Promise.all([
        pgQuery(
          `SELECT id, severity, status, operator_id, created_at, dedup_key,
                  ROUND(EXTRACT(EPOCH FROM (now() - created_at)) / 86400.0, 1)::numeric AS age_days
             FROM incident_cases_pg
            WHERE ioc_value = $1
              AND id <> $2
              AND status NOT IN ${TERMINAL}
            ORDER BY created_at DESC
            LIMIT 50`,
          [iocValue, id],
        ),
        pgQuery(
          `SELECT count(*)::int AS n
             FROM incident_cases_pg
            WHERE ioc_value = $1
              AND id <> $2
              AND status IN ${TERMINAL}`,
          [iocValue, id],
        ),
      ]);

      const open = openRows.map((c) => ({
        id:          c.id,
        severity:    c.severity ?? null,
        status:      c.status ?? null,
        operator_id: c.operator_id ?? null,
        created_at:  c.created_at,
        age_days:    c.age_days != null ? Number(c.age_days) : null,
        dedup_key:   c.dedup_key ?? null,
      }));
      const closed_count = closedAgg[0]?.n ?? 0;

      res.json({
        case_id:      id,
        ioc_value:    iocValue,
        ioc_type:     base.ioc_type ?? null,
        open,
        open_count:   open.length,
        closed_count: closed_count,
        total:        open.length + closed_count,
      });
    } catch (err) {
      res.status(500).json({ error: err?.message ?? "internal" });
    }
  });

  // GET /api/cases/:id/similar → "cómo se trabajaron casos como éste". Enfocado
  // en EJEMPLOS accionables para el analista: casos de la MISMA clase eCSIRT que
  // un humano cerró (operator_id IS NOT NULL), con la disposición y la ACCIÓN que
  // registró. En clases ruidosas (INFO_GATHERING tiene 400k auto-cerrados) los
  // ~500 trabajados por analistas son la única señal útil; los auto-cierres no
  // enseñan nada. Devuelve: abiertos ahora, agregado sobre trabajados-por-analista
  // (disposición, MTTR, % escalado, top operadores) y una lista de ejemplos con
  // link al caso para que el analista vea cómo se resolvió.
  //
  // "Similar" = misma incident_class (materializada por mig 088). Index-friendly:
  // abiertos → idx_cases_incident_class; trabajados → idx_cases_class_analyst
  // (mig 090, parcial sobre terminales con operador).
  r.get("/:id/similar", async (req, res) => {
    const { id } = req.params;
    const windowDays = Math.min(365, Math.max(7, Number(req.query.days ?? 90)));
    try {
      const [base] = await pgQuery(
        `SELECT incident_class, source_log, ioc_type FROM incident_cases_pg WHERE id = $1 LIMIT 1`,
        [id],
      );
      if (!base) return res.status(404).json({ error: "case not found" });

      const cls = base.incident_class ? String(base.incident_class) : null;
      const clsMeta = cls && ECSIRT_CLASSES[cls] ? ECSIRT_CLASSES[cls] : null;
      const basis = {
        incidentClass: cls,
        label:         clsMeta?.label ?? "Sin clasificar",
        short:         clsMeta?.short ?? "Otro",
        sourceLog:     base.source_log ?? null,
        iocType:       base.ioc_type ?? null,
        windowDays,
      };
      // Sin clase persistida (caso pre-backfill) → no podemos agrupar. La UI lo
      // trata como "sin datos" en lugar de un error.
      if (!cls) {
        return res.json({ case_id: id, basis, openCount: 0, handled: null, examples: [], recommendation: null });
      }

      const TERMINAL = `('CERRADO','FALSO_POSITIVO')`;
      const HANDLED_CAP = 500;   // analyst-handled por clase ≤ ~550; cap holgado
      const [openAgg, handledRows] = await Promise.all([
        // Abiertos de la misma clase (excluye el caso actual).
        pgQuery(
          `SELECT count(*)::int AS n
             FROM incident_cases_pg
            WHERE incident_class = $1 AND id <> $2 AND status NOT IN ${TERMINAL}`,
          [cls, id],
        ),
        // Casos de la clase cerrados POR UN ANALISTA en la ventana. Traemos las
        // filas crudas (≤500) y agregamos en JS — barato y evita N queries.
        pgQuery(
          `SELECT id, severity, classification, operator_id, recommended_action,
                  escalation_level, resolved_at, created_at,
                  ROUND(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0, 1)::numeric AS mttr_h,
                  ROUND(EXTRACT(EPOCH FROM (now() - resolved_at)) / 86400.0, 1)::numeric AS age_days
             FROM incident_cases_pg
            WHERE incident_class = $1
              AND id <> $2
              AND status IN ${TERMINAL}
              AND operator_id IS NOT NULL
              AND resolved_at >= now() - ($3 || ' days')::interval
            ORDER BY resolved_at DESC
            LIMIT ${HANDLED_CAP}`,
          [cls, id, String(windowDays)],
        ),
      ]);

      const openCount = openAgg[0]?.n ?? 0;

      const DISP_LABEL = {
        TRUE_POSITIVE:  "Verdadero positivo",
        FALSE_POSITIVE: "Falso positivo",
        DUPLICATE:      "Duplicado",
        NO_ACTIONABLE:  "No accionable",
        OTHER:          "Otro",
      };
      const bucketOf = (c) => {
        const v = String(c ?? "").toUpperCase();
        if (["TRUE_POSITIVE", "AUTO_TP"].includes(v)) return "TRUE_POSITIVE";
        if (["FALSE_POSITIVE", "FALSO_POSITIVO", "AUTO_FP"].includes(v)) return "FALSE_POSITIVE";
        if (["DUPLICATE", "AUTO_DUPLICATE"].includes(v)) return "DUPLICATE";
        if (["NO_ACTIONABLE", "AUTO_NO_ACTIONABLE"].includes(v)) return "NO_ACTIONABLE";
        return "OTHER";
      };
      // Humaniza el texto de acción registrado (recommended_action): los códigos
      // internos más frecuentes a algo legible; el resto se pasa truncado.
      const humanizeAction = (raw) => {
        const t = String(raw ?? "").replace(/\s+/g, " ").trim();
        if (!t) return null;
        if (/^MERGEADO\s*→/i.test(t)) return "Fusionado con el caso canónico (duplicado)";
        const m = t.match(/^CLOSED_([A-Z_]+):([A-Z_]+)/);
        if (m) {
          const reason = m[1].toLowerCase().replace(/_/g, " ");
          return `Cerrado — ${reason}`;
        }
        return t.length > 120 ? `${t.slice(0, 120)}…` : t;
      };

      // Agregado sobre trabajados-por-analista.
      const handledTotal = handledRows.length;
      const dispCount = new Map();
      const opCount   = new Map();
      const mttrVals  = [];
      let escalated   = 0;
      for (const r of handledRows) {
        const b = bucketOf(r.classification);
        dispCount.set(b, (dispCount.get(b) ?? 0) + 1);
        if (r.operator_id) opCount.set(r.operator_id, (opCount.get(r.operator_id) ?? 0) + 1);
        if (r.escalation_level != null) escalated++;
        if (r.mttr_h != null) mttrVals.push(Number(r.mttr_h));
      }
      const dispositions = [...dispCount.entries()]
        .map(([key, count]) => ({
          key, label: DISP_LABEL[key] ?? key, count,
          pct: handledTotal ? Math.round((count / handledTotal) * 100) : 0,
        }))
        .sort((a, b) => b.count - a.count);
      const topOperators = [...opCount.entries()]
        .map(([operatorId, count]) => ({ operatorId, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 3);
      const median = (xs) => {
        if (!xs.length) return null;
        const s = [...xs].sort((a, b) => a - b);
        const m = Math.floor(s.length / 2);
        return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
      };
      const mttrMed = median(mttrVals);

      const handled = handledTotal > 0 ? {
        total:        handledTotal,
        mttrHours:    mttrMed != null ? Math.round(mttrMed * 10) / 10 : null,
        escalatedPct: handledTotal ? Math.round((escalated / handledTotal) * 100) : 0,
        dispositions,
        topOperators,
      } : null;

      // Ejemplos: 1 por disposición (variedad de "qué se hizo"), los más recientes
      // primero. Da al analista 3-4 precedentes distintos para abrir y replicar.
      const examples = [];
      const seenBucket = new Set();
      for (const r of handledRows) {
        if (examples.length >= 4) break;
        const b = bucketOf(r.classification);
        if (seenBucket.has(b)) continue;
        seenBucket.add(b);
        examples.push({
          id:           r.id,
          severity:     r.severity ?? null,
          dispositionKey:   b,
          dispositionLabel: DISP_LABEL[b] ?? b,
          action:       humanizeAction(r.recommended_action),
          operatorId:   r.operator_id ?? null,
          ageDays:      r.age_days != null ? Number(r.age_days) : null,
        });
      }

      // Recomendación textual: desenlace dominante entre trabajados-por-analista.
      let recommendation = null;
      if (handled && dispositions.length && handledTotal >= 3) {
        const top = dispositions[0];
        recommendation =
          `Analistas resolvieron ${handledTotal} caso${handledTotal !== 1 ? "s" : ""} de clase ` +
          `«${basis.label}»; lo más común fue ${top.label.toLowerCase()} (${top.pct}%).`;
      }

      res.json({ case_id: id, basis, openCount, handled, examples, recommendation });
    } catch (err) {
      res.status(500).json({ error: err?.message ?? "internal" });
    }
  });

  // ── C3 — Presencia en tiempo real ("viewed by") ─────────────────────────
  // Modelo: upsert por (case_id, operator_id). Heartbeat cada 30s desde el
  // frontend mientras la pestaña está visible. Viewers con last_seen_at
  // > 2min se consideran ausentes y NO se devuelven en el GET ni participan
  // en eventos de presencia.
  //
  // Socket: el cliente además llama a `socket.emit("case:subscribe", caseId)`
  // para joinear la room; el heartbeat HTTP es independiente y persiste el
  // estado en PG (sobrevive a reconexiones de socket, page reloads, etc).

  const VIEWER_STALE_MIN = 2;   // viewers más viejos que esto = ausentes

  /** GET /api/cases/:id/viewers — snapshot de quién está mirando ahora. */
  r.get("/:id/viewers", async (req, res) => {
    const { id } = req.params;
    try {
      const rows = await pgQuery(
        `SELECT operator_id, operator_name, active_tab, last_seen_at, first_seen_at
         FROM legacyhunt_soc.case_viewers
         WHERE case_id = $1
           AND last_seen_at > now() - INTERVAL '${VIEWER_STALE_MIN} minutes'
         ORDER BY last_seen_at DESC`,
        [id],
      );
      res.json({
        case_id: id,
        viewers: rows.map((row) => ({
          operatorId:   row.operator_id,
          operatorName: row.operator_name,
          activeTab:    row.active_tab,
          lastSeenAt:   row.last_seen_at,
          firstSeenAt:  row.first_seen_at,
        })),
      });
    } catch (err) {
      res.status(500).json({ error: err?.message ?? "internal" });
    }
  });

  /** POST /api/cases/:id/viewers/heartbeat — upsert mi presencia.
   *  Body opcional: { activeTab: string } */
  r.post("/:id/viewers/heartbeat", async (req, res) => {
    const { id } = req.params;
    const operatorId = String(req.user?.preferred_username ?? "").trim();
    if (!operatorId) {
      return res.status(401).json({ error: "no_operator" });
    }
    const operatorName = req.user?.name ?? null;
    const activeTab    = typeof req.body?.activeTab === "string"
      ? req.body.activeTab.slice(0, 32)
      : null;
    try {
      // INSERT...ON CONFLICT permite el primer-visto + subsiguientes upserts.
      // first_seen_at se preserva en updates (sólo se setea en INSERT).
      const rows = await pgQuery(
        `INSERT INTO legacyhunt_soc.case_viewers
           (case_id, operator_id, operator_name, active_tab, last_seen_at, first_seen_at)
         VALUES ($1, $2, $3, $4, now(), now())
         ON CONFLICT (case_id, operator_id) DO UPDATE
           SET operator_name = COALESCE(EXCLUDED.operator_name, case_viewers.operator_name),
               active_tab    = EXCLUDED.active_tab,
               last_seen_at  = now()
         RETURNING first_seen_at, (xmax = 0) AS is_first`,
        [id, operatorId, operatorName, activeTab],
      );
      const isFirst = rows[0]?.is_first === true;
      // Broadcast a la room solo en transiciones: el primer heartbeat (join)
      // y los cambios de tab. No queremos spamear viewer_joined cada 30s.
      if (isFirst) {
        const { emitToCase } = await import("../services/socketService.mjs");
        emitToCase(id, "case:viewer_joined", {
          caseId: id,
          operatorId,
          operatorName,
          activeTab,
          firstSeenAt: rows[0]?.first_seen_at,
        });
      }
      res.json({ ok: true, isFirst });
    } catch (err) {
      res.status(500).json({ error: err?.message ?? "internal" });
    }
  });

  /** DELETE /api/cases/:id/viewers — quitar mi presencia (al cerrar el caso).
   *  Best-effort: el TTL de 2min ya invalida si esto falla. */
  r.delete("/:id/viewers", async (req, res) => {
    const { id } = req.params;
    const operatorId = String(req.user?.preferred_username ?? "").trim();
    if (!operatorId) return res.status(401).json({ error: "no_operator" });
    try {
      await pgQuery(
        `DELETE FROM legacyhunt_soc.case_viewers
         WHERE case_id = $1 AND operator_id = $2`,
        [id, operatorId],
      );
      const { emitToCase } = await import("../services/socketService.mjs");
      emitToCase(id, "case:viewer_left", { caseId: id, operatorId });
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err?.message ?? "internal" });
    }
  });

  return r;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function toCamel(s) {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

function generateMarkdownReport(c, { tasks, assets, iocs, evidences, timeline }) {
  const now = new Date().toISOString();
  const sev = c.severity ?? "UNKNOWN";
  const status = c.status ?? "UNKNOWN";

  const tasksByPhase = {};
  for (const t of tasks) {
    if (!tasksByPhase[t.phase]) tasksByPhase[t.phase] = [];
    tasksByPhase[t.phase].push(t);
  }

  const phases = ["DETECTION","CONTAINMENT","ERADICATION","RECOVERY","POST_INCIDENT"];

  return `# Informe de Incidente — ${c.id?.slice(0,8) ?? "N/A"}

**Generado:** ${now}
**Clasificación:** TLP:AMBER — Uso interno SOC

---

## Resumen Ejecutivo

| Campo | Valor |
|-------|-------|
| ID | \`${c.id}\` |
| IOC Principal | \`${c.ioc_value ?? "N/A"}\` |
| Tipo IOC | ${c.ioc_type ?? "N/A"} |
| Severidad | **${sev}** |
| Estado | ${status} |
| Score | ${c.score ?? "N/A"} |
| Fuente | ${c.source_log ?? "N/A"} |
| MITRE Tactic | ${c.mitre_tactic_name ?? "N/A"} (${c.mitre_tactic_id ?? "N/A"}) |
| Técnica | ${c.mitre_technique_id ?? "N/A"} |
| Operador | ${c.operator_id ?? "Sin asignar"} |
| Apertura | ${c.created_at ?? "N/A"} |
| Adopción | ${c.adopted_at ?? "N/A"} |
| Última actualización | ${c.updated_at ?? "N/A"} |

---

## Clasificación NIST SP 800-61

| Campo | Valor |
|-------|-------|
| Categoría | ${c.incident_category ?? "N/A"} |
| Impacto Funcional | ${c.functional_impact ?? "N/A"} |
| Impacto en Información | ${c.information_impact ?? "N/A"} |
| Recuperabilidad | ${c.recoverability ?? "N/A"} |
| Estado Contención | ${c.containment_status ?? "N/A"} |

---

## IOCs Identificados

${iocs.length === 0 ? "_Sin IOCs registrados_" : iocs.map(i =>
  `- **${i.ioc_type}** \`${i.ioc_value}\` | TLP: ${i.tlp} | ${i.description ?? ""}${i.vt_malicious ? ` | VT: ${i.vt_malicious}` : ""}${i.in_misp ? " | ⚠️ En MISP" : ""}`
).join("\n")}

---

## Assets Involucrados

${assets.length === 0 ? "_Sin assets registrados_" : assets.map(a =>
  `- **${a.asset_type}** \`${a.asset_value}\`${a.ip_address ? ` (${a.ip_address})` : ""}${a.compromised ? " — ⚠️ COMPROMETIDO" : ""} | Contención: ${a.containment_status ?? "ACTIVE"}`
).join("\n")}

---

## Tareas por Fase (NIST)

${phases.map(phase => {
  const phaseTasks = tasksByPhase[phase];
  if (!phaseTasks?.length) return "";
  return `### ${phase}\n\n${phaseTasks.map(t =>
    `- [${t.status === "DONE" ? "x" : " "}] **${t.title}** (${t.status})${t.assignee ? ` — @${t.assignee}` : ""}${t.description ? `\n  ${t.description}` : ""}`
  ).join("\n")}\n`;
}).filter(Boolean).join("\n")}

---

## Evidencias (Chain of Custody)

${evidences.length === 0 ? "_Sin evidencias registradas_" : evidences.map(e =>
  `- **${e.evidence_type}** ${e.name} | Recolectado por: ${e.collected_by} | ${e.collected_at}${e.hash_sha256 ? `\n  SHA-256: \`${e.hash_sha256}\`` : ""}`
).join("\n")}

---

## Timeline del Incidente

${timeline.length === 0 ? "_Sin eventos en timeline_" : timeline.map(t =>
  `| ${t.event_ts} | **${t.event_type}** | ${t.title ?? ""} | ${t.operator_ci ?? "system"} |`
).join("\n") === "" ? "" : `| Timestamp | Tipo | Descripción | Operador |\n|-----------|------|-------------|----------|\n${timeline.map(t =>
  `| ${new Date(t.event_ts).toLocaleString("es-ES")} | ${t.event_type} | ${t.title ?? t.description ?? ""} | ${t.operator_ci ?? "system"} |`
).join("\n")}`}

---

## Causa Raíz

${c.root_cause ?? "_No documentada_"}

## Recomendaciones / Acción Recomendada

${c.recommended_action ?? c.lessons_learned ?? "_Sin recomendaciones documentadas_"}

## Lecciones Aprendidas

${c.lessons_learned ?? "_No documentadas_"}

---

*Informe generado automáticamente por LegacyHunt SOC Platform — ${now}*
`;
}

// ── Markdown → HTML SEGURO (escape-first → sin XSS aunque el caso traiga datos
//    controlados por el atacante). Cubre los constructos del informe: headings,
//    tablas, **negrita**, `code`, --- y listas. ─────────────────────────────────
function _escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function _inlineMd(s) {
  // se aplica sobre texto YA escapado (los marcadores ** y ` no son HTML-especiales)
  return s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
}
function _mdTable(rows) {
  const cells = (r) => r.replace(/^\|/, "").replace(/\|\s*$/, "").split("|").map((x) => x.trim());
  if (rows.length < 2) return "";
  const head = cells(rows[0]);
  const body = rows.slice(2).map(cells); // rows[1] es el separador |---|
  return `<table><thead><tr>${head.map((h) => `<th>${_inlineMd(h)}</th>`).join("")}</tr></thead>`
    + `<tbody>${body.map((r) => `<tr>${r.map((c) => `<td>${_inlineMd(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}
function markdownToSafeHtml(md) {
  const lines = _escHtml(md).split("\n");
  let html = ""; let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^### /.test(line)) { html += `<h3>${_inlineMd(line.slice(4))}</h3>`; i++; continue; }
    if (/^## /.test(line))  { html += `<h2>${_inlineMd(line.slice(3))}</h2>`; i++; continue; }
    if (/^# /.test(line))   { html += `<h1>${_inlineMd(line.slice(2))}</h1>`; i++; continue; }
    if (/^---+\s*$/.test(line)) { html += "<hr>"; i++; continue; }
    if (/^\|/.test(line)) {
      const rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) { rows.push(lines[i]); i++; }
      html += _mdTable(rows); continue;
    }
    if (/^- /.test(line)) {
      html += "<ul>";
      while (i < lines.length && /^- /.test(lines[i])) { html += `<li>${_inlineMd(lines[i].slice(2))}</li>`; i++; }
      html += "</ul>"; continue;
    }
    if (line.trim() === "") { i++; continue; }
    html += `<p>${_inlineMd(line)}</p>`; i++;
  }
  return html;
}
export function generateHtmlReport(c, parts) {
  const body = markdownToSafeHtml(generateMarkdownReport(c, parts));
  return `<!doctype html><html lang="es"><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<style>`
    + `body{font-family:system-ui,-apple-system,sans-serif;color:#1e293b;max-width:840px;margin:0 auto;padding:24px;line-height:1.55}`
    + `h1{font-size:1.5rem;margin:.2rem 0} h2{font-size:1.15rem;border-bottom:1px solid #e2e8f0;padding-bottom:4px;margin-top:1.6rem} h3{font-size:1rem}`
    + `table{border-collapse:collapse;width:100%;margin:8px 0;font-size:.9rem} th,td{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top} th{background:#f8fafc}`
    + `code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:.85em} hr{border:none;border-top:1px solid #e2e8f0;margin:16px 0} ul{padding-left:20px} p{margin:.4rem 0}`
    + `</style></head><body>${body}</body></html>`;
}
