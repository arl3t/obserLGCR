/**
 * forcedAckController.mjs
 * Controladores HTTP de adopción y apertura de casos.
 *
 * Endpoints montados en /api/incidents:
 *
 *   POST /voluntary-adopt
 *     Adopción manual desde el panel de scoring (sin código). Persiste la
 *     adopción en incident_classifications + incident_cases(_pg).
 *
 *   POST /open
 *     Abre un caso inmediatamente desde el enriquecimiento en tiempo real,
 *     sin esperar al DAG diario (misma dedup_key → no duplica).
 *
 * NOTA: el flujo de "adopción forzada por código" (force-ack/initiate, retry
 * loop, popup ForcedAcknowledgmentModal, tabla adoption_codes) fue eliminado
 * el 2026-06-08. La adopción operativa fluye por POST /api/incidents/:caseId/adopt.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { emitIncidentAdopted } from "../services/socketService.mjs";
import { isRfc1918 } from "../services/netClass.mjs";
import {
  trinoExec,
  migrateIncidentClassifications,
  migrateIncidentResolutionColumns,
} from "../services/trinoWriter.mjs";
import { inferRuleFamily } from "../config/case-taxonomy.mjs";
import { resolveJwtOperatorCi } from "../services/operatorResolver.mjs";
import { calcScoreEvidenceRfc1918 } from "../services/scoringBonus.mjs";
import { dedupKey as canonDedupKey } from "../services/dedupKey.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

/**
 * Stub para `fetchEnrichmentFromTrino` — la implementación nunca existió en
 * este archivo, pero el call-site la invocaba dentro de un `.catch(() => null)`
 * que enmascaraba el ReferenceError → `openCaseFromEnrichment` siempre se
 * comportaba como `enriched=false`. Mantenemos ese comportamiento explícito
 * hasta tener una versión Trino-backed.
 *
 * TODO(R1 audit): implementar query a `v_incident_score_v4` (o `v3` como
 * fallback) por `ioc_value` y devolver fila completa con severity, score,
 * mitre tactic/technique, source_log, source_category y los 4 sub-scores +
 * enrichment_data. Cuando exista, evaluar si reemplazar el `severityToScore`
 * fallback de processForcedAck.
 */
async function fetchEnrichmentFromTrino(_iocValue) {
  return null;
}

// Migraciones de esquema al cargar el módulo (idempotentes)
migrateIncidentClassifications().catch((err) =>
  logger.error("migration.incident_classifications_failed", { err: err?.message ?? String(err) }),
);
migrateIncidentResolutionColumns().catch((err) =>
  logger.error("migration.incident_resolution_columns_failed", { err: err?.message ?? String(err) }),
);

const __dirname = dirname(fileURLToPath(import.meta.url));
const AUDIT_DIR  = join(__dirname, "..", "data");
const AUDIT_FILE = join(AUDIT_DIR, "force-ack-audit.jsonl");

const SEVERITY_RANK_MAP = { NEGLIGIBLE: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };

// ── Auditoría ──────────────────────────────────────────────────────────────────

async function writeAudit(event) {
  try {
    await mkdir(AUDIT_DIR, { recursive: true });
    await appendFile(AUDIT_FILE, JSON.stringify({ ...event, ts: new Date().toISOString() }) + "\n");
  } catch {
    // Fallo de escritura no debe interrumpir el flujo principal
  }
}

// ── Persistencia Trino ────────────────────────────────────────────────────────

/** Score aproximado basado en severidad (sin datos VT/Shodan disponibles en force-ack). */
function severityToScore(sev) {
  return { CRITICAL: 80, HIGH: 60, MEDIUM: 35, LOW: 15, NEGLIGIBLE: 5 }[sev] ?? 50;
}

/** Parsea el campo mitre string "TA0001 - Initial Access / T1110 - Brute Force". */
function parseMitre(mitre) {
  if (!mitre) return { tacticId: null, tacticName: null, techniqueId: null };
  const tacticId    = mitre.match(/TA\d{4}/)?.[0] ?? null;
  const techniqueId = mitre.match(/T\d{4}/)?.[0] ?? null;
  const tacticName  = mitre.split(" - ")[1]?.split(" / ")[0]?.trim() ?? null;
  return { tacticId, tacticName, techniqueId };
}

function sq(s) { return `'${String(s ?? "").replace(/'/g, "''")}'`; }
function tsz(ms) { return `TIMESTAMP '${new Date(ms).toISOString().replace("T", " ").replace("Z", " UTC")}'`; }

/** Normaliza CI a solo dígitos para validar y persistir. */
function normalizeOperatorCi(raw) {
  return String(raw ?? "").replace(/\D/g, "");
}

/**
 * Inserta una fila en `incident_classifications` registrando la adopción.
 * Fire-and-forget: los errores de Trino no afectan al flujo HTTP.
 */
/**
 * @param {object} [opts]
 * @param {number} [opts.scoreOverride] — puntuación v2 real (adopción manual desde scoring)
 * @param {string} [opts.sourceLog] — columna source_log (p. ej. dashboard_voluntary)
 * @param {string} [opts.detectionType] — detection_type (p. ej. voluntary_adopt)
 */
async function persistAdoptionToTrino(alertId, alertData, analystId, adoptedAt, opts = {}) {
  const {
    severity = "CRITICAL",
    srcip = "",
    mitre = null,
    level = null,
    rule = null,
    ioc_type: iocTypeRaw = "ip",
  } = alertData;
  const iocType = String(iocTypeRaw ?? "ip").slice(0, 64) || "ip";
  const { tacticId, tacticName, techniqueId } = parseMitre(mitre);
  const override = opts.scoreOverride;
  const score =
    override != null && Number.isFinite(Number(override))
      ? Math.min(100, Math.max(0, Math.round(Number(override))))
      : severityToScore(severity);
  const now = adoptedAt ?? Date.now();
  const dt = new Date(now).toISOString().slice(0, 10);
  const sourceLogCol = opts.sourceLog ?? "force_ack";
  const detectionTypeCol = opts.detectionType ?? "force_ack";
  const ruleFamily = inferRuleFamily(detectionTypeCol, tacticName, rule);

  const sql = `
INSERT INTO minio_iceberg.hunting.incident_classifications (
  incident_key, ioc_value, ioc_type, source_log,
  score, score_mitre, score_evidence, score_wazuh, severity,
  mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
  vt_malicious, vt_suspicious, vt_permalink,
  shodan_ports, shodan_vulns, abuse_confidence,
  in_urlhaus, in_openphish,
  recommended_action, classified_at, dt,
  adopted_by, adopted_at,
  detection_type, rule_family
) VALUES (
  ${sq(alertId)}, ${sq(srcip)}, ${sq(iocType)}, ${sq(sourceLogCol)},
  ${score}, 0, 0, ${level != null ? Math.min(25, Math.round(Number(level) * 1.5)) : 0}, ${sq(severity)},
  ${sq(techniqueId)}, ${sq(tacticId)}, ${sq(tacticName)},
  NULL, NULL, NULL,
  NULL, NULL, NULL,
  false, false,
  'ADOPTADO', ${tsz(now)}, DATE '${dt}',
  ${sq(analystId)}, ${tsz(now)},
  ${sq(detectionTypeCol)}, ${sq(ruleFamily)}
)`.trim();

  const result = await trinoExec(sql, { catalog: "minio_iceberg", schema: "hunting" });
  if (!result.ok) {
    await writeAudit({ event: "trino_write_failed", alertId, error: result.error });
  }

  // También insertar en incident_cases para que el caso aparezca en Gestión de Incidentes.
  // El DAG deduplicará por dedup_key si el mismo IOC aparece luego en el scoring diario.
  const SEVERITY_RANK = { NEGLIGIBLE: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
  const sevUpper = (severity || "CRITICAL").toUpperCase();
  const rank = SEVERITY_RANK[sevUpper] ?? 5;
  const scoreBreakdownJson = JSON.stringify({
    score_mitre: 0,
    score_evidence: 0,
    score_wazuh: level != null ? Math.min(25, Math.round(Number(level) * 1.5)) : 0,
    score_context: 0,
    score,
  });
  const evJson = JSON.stringify([{ ioc_key: alertId, dt, source_log: sourceLogCol }]);
  // dedup_key: misma fórmula SHA256 que incident_cases_sync_daily.py
  // → el DAG encontrará el caso existente y solo incrementará occurrence_count.
  // Usamos el helper canónico en services/dedupKey.mjs (R5 audit 2026-05-21:
  // antes invocaba `buildDedupKey` que nunca estuvo importado → ReferenceError).
  // ALTA-6 (audit 2026-06-05): usar el source_log real (sourceLogCol), igual que
  // open-from-flow y autoClassify. Antes pasaba detectionTypeCol → divergencia de
  // dedup_key entre caminos de creación para el mismo IOC en severidades MEDIUM/LOW.
  const dedup_key = canonDedupKey({
    iocValue:      srcip,
    iocType:       iocType,
    severity:      sevUpper,
    mitreTacticId: tacticId,
    sourceLog:     sourceLogCol,
  });

  const sqlCase = `
INSERT INTO minio_iceberg.hunting.incident_cases (
  case_id, dedup_key, ioc_value, ioc_type, source_log,
  mitre_technique_id, mitre_tactic_id, mitre_tactic_name, source_category,
  severity_text, severity_rank, severity_score, confidence_level, status,
  occurrence_count, first_seen, last_seen, anchor_dt,
  linked_evidence, score_breakdown, notes, assigned_to, closure_reason,
  created_at, updated_at
) VALUES (
  ${sq(alertId)}, ${sq(dedup_key)}, ${sq(srcip)},
  ${sq(iocType)}, ${sq(sourceLogCol)},
  ${sq(techniqueId)}, ${sq(tacticId)}, ${sq(tacticName)}, ${sq(detectionTypeCol)},
  ${sq(sevUpper)}, ${rank}, ${score}, NULL,
  'CONFIRMADO', 1, ${tsz(now)}, ${tsz(now)}, DATE '${dt}',
  ${sq(evJson)}, ${sq(scoreBreakdownJson)},
  ${sq(`Adoptado por ${analystId} vía force-ack`)}, ${sq(analystId)}, NULL,
  ${tsz(now)}, ${tsz(now)}
)`.trim();

  const resultCase = await trinoExec(sqlCase, { catalog: "minio_iceberg", schema: "hunting" });
  if (!resultCase.ok) {
    await writeAudit({ event: "trino_incident_cases_write_failed", alertId, error: resultCase.error });
  }

  // ── ALTA-6 (audit 2026-06-05): espejo a incident_cases_pg ────────────────────
  // PG es la fuente de verdad operacional (PATCH /status, /adopt, auto-assign,
  // KPIs leen PG primero). Antes este path solo escribía Iceberg → el caso
  // CONFIRMADO quedaba invisible para el SOC hasta que el DAG diario lo
  // reconciliara (horas). Mirroreamos sincrónicamente. Best-effort: si PG falla
  // el caso sigue en Iceberg y el DAG lo recupera.
  try {
    await pgQuery(
      `INSERT INTO incident_cases_pg
         (id, severity, status, score, recommended_action, dedup_key, ioc_value,
          ioc_type, source_log, mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
          operator_id, adopted_at, detected_at, occurrence_count, anchor_dt,
          created_at, updated_at)
       VALUES ($1,$2,'CONFIRMADO',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
               now(), now(), 1, CURRENT_DATE, now(), now())
       ON CONFLICT (id) DO UPDATE SET
         -- No degradar un caso que ya avanzó a estado terminal/escalado.
         status      = CASE WHEN incident_cases_pg.status IN ('CERRADO','FALSO_POSITIVO','ESCALADO')
                            THEN incident_cases_pg.status ELSE EXCLUDED.status END,
         operator_id = COALESCE(incident_cases_pg.operator_id, EXCLUDED.operator_id),
         adopted_at  = COALESCE(incident_cases_pg.adopted_at, now()),
         dedup_key   = COALESCE(incident_cases_pg.dedup_key, EXCLUDED.dedup_key),
         ioc_value   = COALESCE(incident_cases_pg.ioc_value, EXCLUDED.ioc_value),
         updated_at  = now()`,
      [
        alertId, sevUpper, score, `Adoptado por ${analystId} vía force-ack`,
        dedup_key, srcip, iocType, sourceLogCol,
        tacticId ?? null, tacticName ?? null, techniqueId ?? null, analystId,
      ],
    );
  } catch (pgErr) {
    if (pgErr?.code === "23505") {
      // Índice único parcial: ya hay un caso ABIERTO para este dedup_key.
      // El IOC ya tiene caso vivo — la adopción no necesita crear otro.
      logger.debug("forceack.pg_mirror_dedup_collision", { alertId, dedupKey: dedup_key });
    } else {
      logger.warn("forceack.pg_mirror_failed", { alertId, err: pgErr.message });
    }
  }
}

// ── Controladores ──────────────────────────────────────────────────────────────

/**
 * POST /api/incidents/voluntary-adopt
 * Adopción manual desde el panel de scoring (sin código Slack ni umbral mínimo).
 * Persiste en incident_classifications con detection_type voluntary_adopt.
 */
export async function voluntaryAdoptIncident(req, res) {
  const body = req.body ?? {};
  const ioc_value = String(body.ioc_value ?? "").trim();
  if (!ioc_value) {
    res.status(400).json({ ok: false, error: "ioc_value es obligatorio" });
    return;
  }

  const bodyCi = normalizeOperatorCi(body.operatorCi);

  // Identidad autoritativa = JWT. Body sólo se acepta si JWT no resuelve.
  const jwtCi = await resolveJwtOperatorCi(req);
  if (jwtCi && bodyCi && bodyCi !== jwtCi) {
    logger.warn("force_ack.voluntary_adopt.body_ci_mismatch_use_jwt", {
      jwtCi, bodyCi, ioc_value, user: req.user?.preferred_username,
    });
  }
  const ciDigits = jwtCi ?? bodyCi;

  if (ciDigits.length < 5 || ciDigits.length > 14) {
    res.status(400).json({
      ok: false,
      error: "Número de CI obligatorio: entre 5 y 14 dígitos (sin letras).",
      reason: "invalid_ci",
    });
    return;
  }

  const analystId = String(body.analystId ?? "operador").slice(0, 64).trim() || "operador";
  const adoptedByLabel = `${analystId} · CI ${ciDigits}`;
  const severity = String(body.severity ?? "LOW").toUpperCase().slice(0, 20);
  const scoreNum = Number(body.score);
  const source_log = String(body.source_log ?? "dashboard_voluntary").slice(0, 128);
  const ioc_type = String(body.ioc_type ?? "ip").trim().slice(0, 32) || "ip";

  const mitreStr =
    body.mitre != null && String(body.mitre).trim()
      ? String(body.mitre).trim().slice(0, 512)
      : (() => {
          const tid = body.mitre_tactic_id != null ? String(body.mitre_tactic_id).trim() : "";
          const tname = body.mitre_tactic_name != null ? String(body.mitre_tactic_name).trim() : "";
          const tech = body.mitre_technique_id != null ? String(body.mitre_technique_id).trim() : "";
          if (!tid && !tech) return null;
          return `${tid}${tname ? ` - ${tname}` : ""}${tech ? ` / ${tech}` : ""}`.slice(0, 512);
        })();

  const alertId = `voluntary-${randomUUID()}`.slice(0, 128);
  const alertData = {
    alertId,
    severity,
    rule: `voluntary_adopt · ${source_log}`,
    agent: "(dashboard)",
    srcip: ioc_value,
    ioc_type,
    message: String(body.note ?? "").slice(0, 2000),
    mitre: mitreStr,
    level: null,
  };

  const adoptedAt = Date.now();
  await persistAdoptionToTrino(alertId, alertData, adoptedByLabel, adoptedAt, {
    scoreOverride: Number.isFinite(scoreNum) ? scoreNum : undefined,
    sourceLog: "dashboard_voluntary",
    detectionType: "voluntary_adopt",
  }).catch(() => {});

  emitIncidentAdopted({ alertId, adoptedBy: adoptedByLabel, adoptedAt });

  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ??
    req.socket?.remoteAddress ??
    "unknown";
  await writeAudit({
    event: "voluntary_adopted",
    alertId,
    ioc_value,
    analystId,
    operatorCi: ciDigits,
    clientIp,
    severity,
    score: Number.isFinite(scoreNum) ? scoreNum : null,
  });

  res.json({
    ok: true,
    alertId,
    adoptedBy: adoptedByLabel,
    adoptedAt: new Date(adoptedAt).toISOString(),
    message: `Caso adoptado manualmente por ${adoptedByLabel}`,
  });
}

/**
 * POST /api/incidents/open
 *
 * Abre un caso de forma INMEDIATA desde el dashboard, sin esperar al DAG diario.
 * Consulta v_incident_score_v2 + enriched_ioc para obtener el enriquecimiento real
 * (VT, Shodan, MITRE, scores) y crea el caso en incident_cases con la dedup_key
 * canónica, de modo que el DAG del día siguiente solo incrementará occurrence_count
 * en lugar de crear un duplicado.
 *
 * Body:
 *   ioc_value     {string}  — IOC a abrir (requerido)
 *   ioc_type      {string}  — "ip" | "domain" | "hash" (opcional, default "ip")
 *   severity      {string}  — sobrescritura de severidad (opcional; si hay dato real en Trino, se usa ese)
 *   analystId     {string}  — nombre del analista
 *   operatorCi    {string}  — CI del operador (5-14 dígitos)
 *   note          {string}  — nota inicial opcional
 *   forceOpen     {boolean} — si true, abre incluso cuando ya existe caso activo (default false)
 *
 * Response: { ok, caseId, incident_key, enriched, dedup_key, message }
 *   enriched: true  → datos tomados de v_incident_score_v2 (tiempo real)
 *   enriched: false → datos estimados por severidad (Trino sin datos para ese IOC)
 */
export async function openCaseFromEnrichment(req, res) {
  const body = req.body ?? {};
  const ioc_value = String(body.ioc_value ?? "").trim();
  if (!ioc_value) {
    res.status(400).json({ ok: false, error: "ioc_value es obligatorio" });
    return;
  }

  const ciDigits = normalizeOperatorCi(body.operatorCi);
  if (ciDigits.length < 5 || ciDigits.length > 14) {
    res.status(400).json({
      ok: false,
      error: "Número de CI obligatorio: entre 5 y 14 dígitos.",
      reason: "invalid_ci",
    });
    return;
  }

  const analystId      = String(body.analystId ?? "operador").slice(0, 64).trim() || "operador";
  const adoptedByLabel = `${analystId} · CI ${ciDigits}`;
  const ioc_type       = String(body.ioc_type ?? "ip").trim().slice(0, 32) || "ip";
  const noteRaw        = String(body.note ?? "").slice(0, 2000);
  const forceOpen      = body.forceOpen === true || body.forceOpen === "true";
  const now            = Date.now();
  const nowTs          = tsz(now);

  // ── 1. Buscar enriquecimiento real en Trino ──────────────────────────────────
  const enrichRow = await fetchEnrichmentFromTrino(ioc_value).catch(() => null);
  const enriched  = enrichRow != null;

  // Parámetros resueltos (datos reales o fallback por severidad)
  const bodySev      = String(body.severity ?? "MEDIUM").toUpperCase().slice(0, 20);
  const severity     = enriched ? String(enrichRow.severity ?? bodySev).toUpperCase() : bodySev;
  const score        = enriched ? Number(enrichRow.score ?? 30) : severityToScore(severity);
  const rank         = SEVERITY_RANK_MAP[severity] ?? 3;
  const mitreId      = enriched ? (enrichRow.mitre_technique_id ?? null) : null;
  const tacticId     = enriched ? (enrichRow.mitre_tactic_id ?? null) : null;
  const tacticName   = enriched ? (enrichRow.mitre_tactic_name ?? null) : null;
  const sourceLog    = enriched ? String(enrichRow.source_log ?? "dashboard_open") : "dashboard_open";
  const sourceCat    = enriched ? (enrichRow.source_category ?? null) : null;
  const confLevel    = enriched ? (enrichRow.confidence_level ?? null) : null;
  const dtStr        = enriched ? String(enrichRow.dt ?? new Date(now).toISOString().slice(0, 10)) : new Date(now).toISOString().slice(0, 10);

  // R5 audit 2026-05-21: si el IOC es RFC1918 y Trino no enriqueció todavía,
  // replicamos la fórmula de la vista v_incident_score_v2 para score_evidence
  // — así el DAG (que sí pasa por la vista) y el dashboard ven el mismo valor
  // hasta que el ciclo de enrichment lo recalcule contra eventos reales.
  const evidenceFallback = (!enriched && isRfc1918(ioc_value))
    ? calcScoreEvidenceRfc1918({ severity })
    : 0;

  const scoreBreakdown = JSON.stringify({
    score_mitre:    enriched ? Number(enrichRow.score_mitre    ?? 0) : 0,
    score_evidence: enriched ? Number(enrichRow.score_evidence ?? 0) : evidenceFallback,
    score_wazuh:    enriched ? Number(enrichRow.score_wazuh    ?? 0) : 0,
    score_context:  enriched ? Number(enrichRow.score_context  ?? 0) : 0,
    score,
    enriched_from_trino: enriched,
  });

  const rawEvent  = enriched ? String(enrichRow.raw_event ?? "") : "";
  const iocKeyRef = enriched ? (enrichRow.ioc_key ?? null) : null;

  // ── 2. Calcular dedup_key canónica (misma fórmula que el DAG) ───────────────
  // Vía services/dedupKey.mjs (single source). Antes referenciaba un
  // `buildDedupKey` que nunca existió en este módulo → ReferenceError uncaught.
  const dedup_key = canonDedupKey({
    iocValue:       ioc_value,
    iocType:        ioc_type,
    severity,
    mitreTacticId:  tacticId,
    sourceCategory: sourceCat,
  });
  const caseId    = randomUUID();

  // ── 3. Verificar duplicado activo + supresión (audit 2026-06-05, ALTA-6/M5) ──
  //    Antes este bloque estaba VACÍO (el check "atómico en el insert" prometido
  //    nunca se implementó) → casos duplicados para el mismo IOC. Replicamos la
  //    defensa de POST /open-from-flow contra incident_cases_pg (fuente operacional).
  if (!forceOpen && dedup_key) {
    try {
      // 3a. Caso abierto existente (mismo dedup_key o IOC) → no duplicar.
      const [dup] = await pgQuery(
        `SELECT id, status FROM incident_cases_pg
          WHERE (dedup_key = $1 OR ioc_value = $2)
            AND status NOT IN ('CERRADO','FALSO_POSITIVO')
          ORDER BY updated_at DESC LIMIT 1`,
        [dedup_key, ioc_value],
      );
      if (dup) {
        res.status(409).json({
          ok: false, error: "Ya existe un caso activo para este IOC",
          caseId: dup.id, status: dup.status,
          hint: "Usa forceOpen=true para abrir igualmente.",
        });
        return;
      }
      // 3b. Supresión vigente — severity-aware (ALTA-3): solo bloquea si la
      //     severidad actual NO supera la suprimida.
      const [sup] = await pgQuery(
        `SELECT reason, suppressed_until, severity FROM legacyhunt_soc.case_suppressions
          WHERE dedup_key = $1 AND suppressed_until > NOW()
          ORDER BY suppressed_until DESC LIMIT 1`,
        [dedup_key],
      );
      const curRank = SEVERITY_RANK_MAP[severity] ?? 3;
      const supRank = SEVERITY_RANK_MAP[String(sup?.severity ?? "").toUpperCase()] ?? 0;
      if (sup && curRank <= supRank) {
        res.status(403).json({
          ok: false, error: "IOC suprimido — caso cerrado recientemente",
          reason: sup.reason, suppressedUntil: sup.suppressed_until,
          hint: "Usa forceOpen=true para forzar la apertura.",
        });
        return;
      }
    } catch (chkErr) {
      // Fail-open: si el check falla, seguimos con la creación (no bloquear).
      logger.warn("open_case.dup_check_failed", { ioc_value, err: chkErr.message });
    }
  }

  // ── 4. Insertar en incident_cases (Iceberg) ──────────────────────────────────
  const evJson = JSON.stringify([
    { ioc_key: iocKeyRef ?? caseId, dt: dtStr, source_log: sourceLog },
  ]);

  const insertCaseNote = noteRaw
    ? `Abierto manualmente por ${adoptedByLabel}. ${noteRaw}`
    : `Abierto manualmente por ${adoptedByLabel} (enriquecimiento tiempo real: ${enriched ? "sí" : "no"})`;

  const sqlCase = `
INSERT INTO minio_iceberg.hunting.incident_cases (
  case_id, dedup_key, ioc_value, ioc_type, source_log,
  mitre_technique_id, mitre_tactic_id, mitre_tactic_name, source_category,
  severity_text, severity_rank, severity_score, confidence_level, status,
  occurrence_count, first_seen, last_seen, anchor_dt,
  linked_evidence, score_breakdown, notes, assigned_to, closure_reason,
  created_at, updated_at
) VALUES (
  ${sq(caseId)}, ${sq(dedup_key)}, ${sq(ioc_value)},
  ${sq(ioc_type)}, ${sq(sourceLog)},
  ${sq(mitreId)}, ${sq(tacticId)}, ${sq(tacticName)}, ${sq(sourceCat)},
  ${sq(severity)}, ${rank}, ${score}, ${sq(confLevel)},
  'NUEVO', 1, ${nowTs}, ${nowTs}, DATE '${dtStr}',
  ${sq(evJson)}, ${sq(scoreBreakdown)},
  ${sq(insertCaseNote)}, ${sq(analystId)}, NULL,
  ${nowTs}, ${nowTs}
)`.trim();

  const resCase = await trinoExec(sqlCase, { catalog: "minio_iceberg", schema: "hunting" });
  if (!resCase.ok) {
    await writeAudit({ event: "open_case_trino_failed", caseId, ioc_value, error: resCase.error });
    res.status(500).json({ ok: false, error: `Error al crear caso en Iceberg: ${resCase.error}` });
    return;
  }

  // ── 4b. Espejo a incident_cases_pg (ALTA-6: fuente operacional) ──────────────
  // Sin esto el caso quedaba solo en Iceberg, invisible para el SOC hasta el DAG.
  try {
    await pgQuery(
      `INSERT INTO incident_cases_pg
         (id, severity, status, score, recommended_action, dedup_key, ioc_value,
          ioc_type, source_log, mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
          detected_at, occurrence_count, anchor_dt, created_at, updated_at)
       VALUES ($1,$2,'NUEVO',$3,$4,$5,$6,$7,$8,$9,$10,$11,now(),1,CURRENT_DATE,now(),now())
       ON CONFLICT (id) DO NOTHING`,
      [
        caseId, severity, score, insertCaseNote, dedup_key, ioc_value, ioc_type,
        sourceLog, tacticId ?? null, tacticName ?? null, mitreId ?? null,
      ],
    );
  } catch (pgErr) {
    if (pgErr?.code === "23505") {
      logger.debug("open_case.pg_mirror_dedup_collision", { caseId, dedupKey: dedup_key });
    } else {
      logger.warn("open_case.pg_mirror_failed", { caseId, err: pgErr.message });
    }
  }

  // ── 5. Insertar en incident_classifications (v1 — compatibilidad) ────────────
  const ruleFamily = inferRuleFamily("dashboard_open", tacticName, null);
  const sqlClassif = `
INSERT INTO minio_iceberg.hunting.incident_classifications (
  incident_key, ioc_value, ioc_type, source_log,
  score, score_mitre, score_evidence, score_wazuh, severity,
  mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
  vt_malicious, vt_suspicious, vt_permalink,
  shodan_ports, shodan_vulns, abuse_confidence,
  in_urlhaus, in_openphish,
  recommended_action, classified_at, dt,
  adopted_by, adopted_at,
  detection_type, rule_family
) VALUES (
  ${sq(caseId)}, ${sq(ioc_value)}, ${sq(ioc_type)}, ${sq(sourceLog)},
  ${score},
  ${enriched ? Number(enrichRow.score_mitre ?? 0) : 0},
  ${enriched ? Number(enrichRow.score_evidence ?? 0) : evidenceFallback},
  ${enriched ? Number(enrichRow.score_wazuh ?? 0) : 0},
  ${sq(severity)},
  ${sq(mitreId)}, ${sq(tacticId)}, ${sq(tacticName)},
  ${enriched ? Number(enrichRow.vt_malicious ?? 0) : "NULL"},
  ${enriched ? Number(enrichRow.vt_suspicious ?? 0) : "NULL"},
  ${enriched && enrichRow.vt_permalink ? sq(enrichRow.vt_permalink) : "NULL"},
  ${enriched && enrichRow.shodan_ports ? sq(enrichRow.shodan_ports) : "NULL"},
  ${enriched && enrichRow.shodan_vulns ? sq(enrichRow.shodan_vulns) : "NULL"},
  ${enriched ? Number(enrichRow.abuse_confidence ?? 0) : "NULL"},
  ${enriched ? String(enrichRow.in_urlhaus) : "false"},
  ${enriched ? String(enrichRow.in_openphish) : "false"},
  ${enriched && enrichRow.recommended_action ? sq(enrichRow.recommended_action) : "NULL"},
  ${nowTs}, DATE '${dtStr}',
  ${sq(adoptedByLabel)}, ${nowTs},
  'dashboard_open', ${sq(ruleFamily)}
)`.trim();

  await trinoExec(sqlClassif, { catalog: "minio_iceberg", schema: "hunting" }).catch((err) =>
    writeAudit({ event: "open_case_classif_failed", caseId, error: err?.message }),
  );

  // ── 6. Auditoría ─────────────────────────────────────────────────────────────
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ??
    req.socket?.remoteAddress ??
    "unknown";

  await writeAudit({
    event:      "case_opened_from_enrichment",
    caseId,
    ioc_value,
    severity,
    score,
    enriched,
    dedup_key,
    analystId,
    operatorCi: ciDigits,
    clientIp,
  });

  res.json({
    ok:           true,
    caseId,
    incident_key: caseId,
    dedup_key,
    severity,
    score,
    enriched,
    status:       "NUEVO",
    message: enriched
      ? `Caso creado con enriquecimiento en tiempo real (score ${score}, ${severity}).`
      : `Caso creado con estimación por severidad (sin datos de scoring para este IOC en los últimos 7 días).`,
  });
}
