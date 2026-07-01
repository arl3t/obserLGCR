/**
 * routes/incidents.mjs — Gestión de Casos SOC
 *
 * Lectura:  incident_cases (tabla Iceberg — partición anchor_dt)
 * Escritura dual:
 *   · incident_cases (Trino/Iceberg) — fuente analítica, DELETE+INSERT
 *   · incident_cases_pg (PostgreSQL)  — fuente operacional rápida (adopt, escalation,
 *     enrichment, timeline, slack_notified_at). PG escribe primero; Iceberg asíncrono.
 *
 * La respuesta al cliente NO espera la escritura en Iceberg salvo en adopt (bloquea
 * para garantizar consistencia en la primera vista del caso).
 *
 * Montado en server.mjs:
 *   app.use("/api/incidents", incidentsRouter(runTrinoQueryWithInitRetries, getIo));
 */

import { createHash, randomUUID, randomBytes } from "node:crypto";
import { Router } from "express";
import {
  getThresholds,
  setThresholds,
  getThresholdsAudit,
  severityFromScore,
} from "../services/socThresholds.mjs";
import { trinoExec } from "../services/trinoWriter.mjs";
import { isRfc1918 } from "../services/netClass.mjs";
import { lookupCountry } from "../services/geoipService.mjs";
import { _topCountries } from "../services/technicalReportService.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { dedupKey as canonDedupKey, normalizeIoc as canonNormalizeIoc, severityRank as sevRank } from "../services/dedupKey.mjs";
import { isSourceEnabled, getSensorLabel } from "../services/sourceLogCatalog.mjs";
import { formatCaseNumber, parseCaseNumber } from "../services/caseNumber.mjs";
import { mapChunked } from "../services/asyncBatch.mjs";
import { getSlaMin } from "../services/slaConfig.mjs";
import { logger } from "../logger.mjs";
import { resolveJwtOperatorCi } from "../services/operatorResolver.mjs";
import {
  sendSlackAlert,
  isSlackEnabled,
  buildSocCaseAdoptionBlock,
} from "../slack-notify.mjs";
import { generatePlaybook, generateRecommendedAction, buildLeakIntelTasks, bootstrapCaseTasks } from "../services/casePlaybookService.mjs";
import { enrichIoc, screenIocMalice } from "../services/enrichmentService.mjs";
import { sendMail } from "../services/mailTransport.mjs";
import { addTimelineEvent } from "../services/timelineService.mjs";
import { classifyEcsirt, ECSIRT_CLASSES } from "../services/ecsirtClassify.mjs";
import {
  applyAllBonuses,
  applyNodeOnlyBonuses,
  BONUSES_IN_SQL_V4,
  persistBonusLog,
  calcGeoRiskMultiplier,
  calcScoreEvidenceRfc1918,
} from "../services/scoringBonus.mjs";
import {
  getNetworkZone as catalogNetworkZone,
  getSensorLabel as catalogSensorLabel,
} from "../services/sourceLogCatalog.mjs";
import {
  getActiveShiftManager,
  getFallbackLeader,
  createNotification,
  shouldAutoEscalate,
  mirrorCasesToIndex,
  mirrorCasesToIceberg,
  transitionCase,
  STATUS_TO_STAGE,
} from "../services/workflowEngine.mjs";
import { decideClosureClassification } from "../services/closureClassification.mjs";
import { parseBulkCloseCriteria } from "../services/bulkCloseCriteria.mjs";
import { isTrustedOriginWithScanners, loadBenignScannerIps } from "../services/trustedOriginMatcher.mjs";
import {
  recommendFromClusters, scoreCaseConfidence, suppressionPlan, clusterAction,
  THREAT_TECHNIQUES, RECON_TECHNIQUES, TRIAGE_BUCKETS, triageDisposition,
} from "../services/bulkCloseConfidence.mjs";
import { manualInclude as watchlistManualInclude } from "../services/infragovpyWatchlistService.mjs";
import {
  enqueueMergeJob, enqueueStatusSyncJob,
  getQueueStats, retryFailedJob, deleteQueueJob,
} from "../services/icebergMergeQueue.mjs";
import { TRANSITION_CAP, decideTransitionRbac } from "../services/transitionRbac.mjs";
import {
  getSla,
  getCachedSla,
  getSlaSec,
  setSla,
  getSlaAudit,
} from "../services/slaConfig.mjs";
import { invalidateCasesKpisCache } from "../services/casesKpisCache.mjs";

// Resolución JWT→CI vive en services/operatorResolver.mjs (compartida con
// routes/outliers.mjs y cualquier handler nuevo que necesite la identidad
// autoritativa del operador).

// ── RBAC por transición de estado ─────────────────────────────────────────────
//
// Complementa la validación "es transición válida?" (VALID_TRANSITIONS) con
// "¿tiene el operador el cap granular para ejecutarla?". Hasta el hotfix del
// audit, un L1 podía CERRAR casos aunque soc_roles.can_close_case=false para
// su rol — el backend sólo miraba la pertenencia a VALID_TRANSITIONS.
//
// Mapa target_status → capability(ies) requerida(s). "any-of" = cualquiera
// alcanza; transiciones no mapeadas no exigen cap extra (asumen can_adopt,
// ya chequeado al adoptar).
//
// Auditado 2026-05-13 (R10):
//   Estados terminales/de compromiso requieren cap explícito:
//     FALSO_POSITIVO  → can_close_fp     (descartar evidencia formalmente)
//     CERRADO         → can_close_case   (cerrar el caso de raíz)
//     ESCALADO        → can_escalate_*   (mover responsabilidad de tier)
//     CONFIRMADO      → can_close_case   (commitir que es incidente real;
//                                          afecta escalation_rate y KPIs
//                                          regulatorios — debe ser hunter+)
//   Estados de "trabajo normal" sólo exigen can_adopt (que ya se valida en
//   POST /:id/adopt; el operador no puede transicionar lo que no adoptó):
//     NUEVO        — sólo inicial, no se transiciona hacia este estado
//     EN_ANALISIS  — resumir trabajo (incluso desde MONITOREADO)
//     MONITOREADO  — parking reversible; L1 puede parquear su caso
//
// Caveat para tests futuros: si soc_roles agrega un can_confirm específico,
// CONFIRMADO debería migrar a ese cap más fino (hoy lo mapeo a can_close_case
// porque es el cap más alto que ya tiene L1L2+ y bloquea a L1 puro).
// TRANSITION_CAP + decideTransitionRbac viven en services/transitionRbac.mjs
// (aislados para tests sin DB — ver legacyhunt-api/tests/transitionRbac.test.mjs).

/**
 * Verifica que el operador con CI `ci` tenga el cap granular de soc_roles
 * necesario para transicionar a `targetStatus`.
 *
 * Devuelve:
 *   { ok: true }                        — permitido o target sin cap mapeado
 *   { ok: false, status, body }         — envía res.status(status).json(body)
 *
 * Fallbacks conservadores (no bloquear sin evidencia):
 *   - Si no hay CI (jwt no resolvió y no vino body)          → 400
 *   - Si la query a soc_operators/soc_roles tira             → permite (lab/legacy)
 *   - Si el operador no está en soc_operators                → permite (legacy seed)
 */
async function checkTransitionRbac(ci, targetStatus) {
  if (!TRANSITION_CAP[targetStatus]) return { ok: true };
  if (!ci) {
    return { ok: false, status: 400, body: { error: "CI del operador no resuelto; no se puede validar permiso de transición." } };
  }
  let role;
  try {
    const rows = await pgQuery(
      `SELECT o.role_id, o.is_active,
              r.can_close_fp, r.can_close_case,
              r.can_escalate_to_l2, r.can_escalate_to_l3
         FROM soc_operators o
         LEFT JOIN soc_roles r ON r.id = o.role_id
        WHERE o.id = $1 LIMIT 1`,
      [ci],
    );
    role = rows[0];
  } catch {
    return { ok: true };
  }
  return decideTransitionRbac(role, targetStatus);
}

// ── Opening-profile gate ───────────────────────────────────────────────────────

/** Caché de perfiles de apertura — 30 s TTL (se invalida en cada cambio manual) */
let _openingProfilesCache    = null;
let _openingProfilesCachedAt = 0;
const OPENING_PROFILES_TTL_MS = 30_000;

/**
 * Carga los perfiles de apertura desde Postgres (con caché de 30 s).
 * Fallback a perfil permisivo si la tabla aún no existe.
 * @returns {Promise<Array<{id,enabled,severities,minScore,skipAdopted}>>}
 */
async function loadOpeningProfiles() {
  const now = Date.now();
  if (_openingProfilesCache && (now - _openingProfilesCachedAt) < OPENING_PROFILES_TTL_MS) {
    return _openingProfilesCache;
  }
  try {
    const rows = await pgQuery(
      `SELECT id, enabled, severities, min_score AS "minScore", skip_adopted AS "skipAdopted"
       FROM opening_profiles
       WHERE enabled = true`,
    );
    _openingProfilesCache    = rows.map((r) => ({
      id:          r.id,
      enabled:     r.enabled,
      severities:  Array.isArray(r.severities) ? r.severities : [],
      minScore:    Number(r.minScore  ?? 10),
      skipAdopted: Boolean(r.skipAdopted ?? true),
    }));
    _openingProfilesCachedAt = now;
    return _openingProfilesCache;
  } catch {
    // Tabla no lista: devolver perfil permisivo para no bloquear operaciones
    return [{ id: "fallback", enabled: true, severities: ["CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE"], minScore: 10, skipAdopted: false }];
  }
}

/**
 * Evalúa si un caso pasa al menos un perfil de apertura activo.
 * @param {{ severity: string, score: number, adoptedAt?: string|null }} caseData
 * @param {Array} profiles
 * @returns {{ ok: boolean, matchedProfile?: string, reason?: string }}
 */
function checkOpeningProfiles(caseData, profiles) {
  if (!profiles.length) return { ok: true, matchedProfile: "no-profiles-configured" };

  const sev   = String(caseData.severity ?? "").toUpperCase();
  const score = Number(caseData.score    ?? 0);

  for (const p of profiles) {
    if (!p.enabled) continue;
    if (p.skipAdopted && caseData.adoptedAt) continue;
    if (p.severities.length && !p.severities.includes(sev)) continue;
    if (score < p.minScore) continue;
    return { ok: true, matchedProfile: p.id };
  }

  // Construir mensaje de rechazo con los criterios activos
  const criteria = profiles
    .filter((p) => p.enabled)
    .map((p) => `[${p.id}] severidades: ${p.severities.join(",")} score≥${p.minScore}`)
    .join(" | ");
  return {
    ok:     false,
    reason: `El caso (${sev} score=${score}) no cumple ningún perfil de apertura activo. Criterios: ${criteria || "ninguno habilitado"}`,
  };
}

// ── Pesos del perfil de scoring activo (A2 — paridad con el DAG) ──────────────
// El DAG (_load_active_weights / _weighted_score_v4) reponderá los candidatos
// con los pesos del perfil publicado antes del gate de apertura. Para que la
// apertura manual (open-from-flow) decida igual, espejamos esa lógica acá.
const _WEIGHT_KEYS = ["wMitre", "wEvidence", "wWazuh", "wContext", "wTor", "wMisp"];
const _IDENTITY_WEIGHTS = { wMitre: 1, wEvidence: 1, wWazuh: 1, wContext: 1, wTor: 1, wMisp: 1 };
let _activeWeightsCache = null;
let _activeWeightsCachedAt = 0;
const ACTIVE_WEIGHTS_TTL_MS = 30_000;

/**
 * Carga los pesos del perfil de scoring activo desde active_formula_profile
 * (con caché de 30 s). Acepta claves camelCase (FE) o snake_case (back).
 * Fallback a pesos 1.0 si no hay perfil — score sin reponderar.
 * @returns {Promise<Record<string, number>>}
 */
async function loadActiveProfileWeights() {
  const now = Date.now();
  if (_activeWeightsCache && (now - _activeWeightsCachedAt) < ACTIVE_WEIGHTS_TTL_MS) {
    return _activeWeightsCache;
  }
  try {
    const [row] = await pgQuery(
      `SELECT weights FROM active_formula_profile ORDER BY applied_at DESC LIMIT 1`,
    );
    const w = row?.weights
      ? (typeof row.weights === "string" ? JSON.parse(row.weights) : row.weights)
      : null;
    const pick = (...keys) => {
      for (const k of keys) if (w && w[k] != null) return Number(w[k]);
      return 1;
    };
    _activeWeightsCache = w
      ? {
          wMitre:   pick("wMitre", "w_mitre"),   wEvidence: pick("wEvidence", "w_evidence"),
          wWazuh:   pick("wWazuh", "w_wazuh"),   wContext:  pick("wContext", "w_context"),
          wTor:     pick("wTor", "w_tor"),       wMisp:     pick("wMisp", "w_misp"),
        }
      : { ..._IDENTITY_WEIGHTS };
    _activeWeightsCachedAt = now;
    return _activeWeightsCache;
  } catch {
    return { ..._IDENTITY_WEIGHTS };
  }
}

function isIdentityWeights(w) {
  return _WEIGHT_KEYS.every((k) => Math.abs(Number(w?.[k] ?? 1) - 1) < 1e-9);
}

/**
 * Reweight de un score v4 con los pesos del perfil activo, vía la razón de bases
 * ponderada/cruda sobre el desglose de componentes. Espejo (aproximado) de
 * _weighted_score_v4 del DAG: el front sólo trae 5 componentes (sin tor/email ni
 * los factores v4), así que escalamos el score por baseW/baseRaw — exacto sin
 * bonos v4, aproximado cuando los hay. Pesos 1.0 o sin desglose → sin cambio.
 * @returns {number}
 */
function reweightScoreForActiveProfile(scoreParsed, scoreBreakdown, weights) {
  if (!Number.isFinite(scoreParsed) || isIdentityWeights(weights)) return scoreParsed;
  const sb = (scoreBreakdown && typeof scoreBreakdown === "object") ? scoreBreakdown : null;
  if (!sb) return scoreParsed;
  const c = {
    mitre:    Number(sb.score_mitre    ?? 0), evidence: Number(sb.score_evidence ?? 0),
    wazuh:    Number(sb.score_wazuh    ?? 0), context:  Number(sb.score_context  ?? 0),
    tor:      Number(sb.score_tor      ?? 0), misp:     Number(sb.score_misp     ?? 0),
  };
  const baseRaw = c.mitre + c.evidence + c.wazuh + c.context + c.tor + c.misp;
  if (baseRaw <= 0) return scoreParsed;
  const baseW = c.mitre * weights.wMitre + c.evidence * weights.wEvidence
              + c.wazuh * weights.wWazuh + c.context * weights.wContext
              + c.tor   * weights.wTor   + c.misp    * weights.wMisp;
  return Math.max(0, Math.round(scoreParsed * (baseW / baseRaw)));
}

// ── P3/P5: piso UTM FortiGate + boost por activo interno (paridad con el DAG) ──
// Espejo de _utm_threat_floor / _asset_target_boost de incident_cases_sync_daily.
// El sync automatizado aplica estos ajustes a TODOS los candidatos ANTES del gate
// de apertura (en _fetch_candidates); acá los replicamos para que el open-from-flow
// manual decida y persista igual que el bulk. Si no, un IPS/AV crítico abierto a
// mano quedaría con score crudo (~LOW) mientras el sync lo abre CRITICAL.
const UTM_FLOOR_CRITICAL = 90;  // > umbral CRITICAL (74)
const UTM_FLOOR_HIGH     = 60;  // entre HIGH (48) y CRITICAL (74)

/**
 * +8 si el IOC ataca un activo interno conocido (affected_asset_ip RFC1918).
 * Espejo de _asset_target_boost del DAG. Acota a 100.
 * @returns {number}
 */
function assetTargetBoost(affectedAssetIp, score) {
  if (affectedAssetIp && isRfc1918(String(affectedAssetIp))) {
    return Math.min(100, (Number(score) || 0) + 8);
  }
  return score;
}

/**
 * Piso de severidad para detecciones UTM (IPS/antivirus) de FortiGate. Espejo de
 * _utm_threat_floor del DAG: source_category de ips/virus + source_severity del
 * crlevel del motor (1=crítico → piso 90, 2=alto → piso 60). El resto del tráfico
 * FortiGate no se toca. Sin estos campos (no es FortiGate / no es UTM) → no-op.
 * @returns {number}
 */
function utmThreatFloor({ sourceLog, sourceCategory, sourceSeverity }, score) {
  if (String(sourceLog || "").toLowerCase() !== "fortigate") return score;
  const cat = String(sourceCategory || "").toLowerCase();
  if (!cat.includes("ips") && !cat.includes("virus")) return score;
  let sev = Number.parseInt(sourceSeverity, 10);
  if (!Number.isFinite(sev)) sev = 4;
  const cur = Number(score) || 0;
  if (sev <= 1) return Math.max(cur, UTM_FLOOR_CRITICAL);
  if (sev === 2) return Math.max(cur, UTM_FLOOR_HIGH);
  return score;
}

const TC      = "minio_iceberg.hunting.incident_classifications";
const TCASES  = "minio_iceberg.hunting.incident_cases";
const SESSION = { catalog: "minio_iceberg", schema: "hunting" };

// SLA_SEC ahora vive en legacyhunt_soc.sla_config (mutable runtime, M5
// 2026-05-13). Consumir vía getSlaSec(severity) o getCachedSla() del módulo
// services/slaConfig.mjs.

/**
 * Obtiene contexto básico de un caso existente desde PostgreSQL.
 * Usado para enriquecer respuestas 409 con información accionable.
 * @param {string} caseId
 * @returns {Promise<{status,severity,score,operatorId,occurrenceCount}|null>}
 */
async function fetchExistingCaseCtx(caseId) {
  try {
    const rows = await pgQuery(
      `SELECT status, severity, score, operator_id AS "operatorId",
              COALESCE(occurrence_count, 1) AS "occurrenceCount"
         FROM incident_cases_pg
        WHERE id = $1`,
      [caseId],
    );
    return rows[0] ?? null;
  } catch { return null; }
}

const OPEN_STATUSES_EXCL = `('CERRADO','FALSO_POSITIVO','CLOSED','FALSE_POSITIVE','RESOLVED','RESUELTO')`;

// Estados terminales canónicos (módulo). Reusado por el path de reapertura.
const TERMINAL = new Set(["CERRADO", "FALSO_POSITIVO"]);

// Transiciones válidas — espejadas en el frontend para UX coherente.
// Autoridad de aristas del path HUMANO (PATCH /:id/status). La autorización del
// destino la decide el cap RBAC (checkTransitionRbac), NO el rol per se.
//
// RELACIÓN con `TRANSITIONS` (services/workflowEngine.mjs, role-aware): esta
// tabla es el SUPERCONJUNTO de aristas-existentes; el cap RBAC restringe el
// "quién". No la derivamos en runtime porque TRANSITIONS no modela el rol
// combinado `L1L2` (validateTransition lo bloquearía). Regla de oro: nunca
// permitir acá una arista que el engine rechazaría para TODOS los roles.
//
// F1 (audit 2026-06-05): CERRADO ya NO es terminal-duro — LEADER/ADMIN pueden
// reabrir (paridad con TRANSITIONS.CERRADO). La reapertura de un terminal está
// gateada por `assertReopenAllowed` (rol + reopenReason), porque el destino
// EN_ANALISIS no tiene cap RBAC propio que restrinja el "quién".
const VALID_TRANSITIONS = {
  NUEVO:          new Set(["EN_ANALISIS", "FALSO_POSITIVO", "MONITOREADO", "CERRADO"]),
  EN_ANALISIS:    new Set(["CONFIRMADO", "ESCALADO", "FALSO_POSITIVO", "MONITOREADO", "CERRADO"]),
  CONFIRMADO:     new Set(["ESCALADO", "CERRADO", "MONITOREADO"]),
  MONITOREADO:    new Set(["EN_ANALISIS", "ESCALADO", "FALSO_POSITIVO", "CERRADO"]),
  // Un caso escalado que tras revisión L3 resulta benigno debe poder cerrarse
  // como FALSO_POSITIVO (no sólo CERRADO) para no sesgar el FPR. El gate 4-eyes
  // por escalation_suggested (M1, más abajo) sigue protegiendo los casos
  // auto-marcados para escalación.
  ESCALADO:       new Set(["CONFIRMADO", "CERRADO", "FALSO_POSITIVO"]),
  FALSO_POSITIVO: new Set(["CERRADO", "EN_ANALISIS"]),
  CERRADO:        new Set(["EN_ANALISIS"]),  // F1: reapertura excepcional (LEADER/ADMIN)
};

// Roles autorizados a reabrir un caso terminal (CERRADO/FALSO_POSITIVO →
// estado abierto). Paridad con TRANSITIONS: sólo LEADER/ADMIN reabren CERRADO.
const REOPEN_ROLES = new Set(["LEADER", "ADMIN"]);
const REOPEN_REASON_MIN = 20;

// ── SQL helpers ────────────────────────────────────────────────────────────────

function sq(s)      { return `'${String(s ?? "").replace(/'/g, "''")}'`; }
function nullOrSq(v){ return (v != null && v !== "") ? sq(v) : "NULL"; }
function tsz(iso)   {
  const d = iso ? new Date(iso) : new Date();
  return `TIMESTAMP '${d.toISOString().replace("T", " ").replace("Z", " UTC")}'`;
}

// ── PostgreSQL helpers ─────────────────────────────────────────────────────────

/**
 * Añade una entrada al array JSONB timeline de incident_cases_pg.
 * Devuelve el timeline actualizado como array JS.
 */
function buildTimelineEntry(action, operatorCi, detail) {
  return JSON.stringify({ ts: new Date().toISOString(), action, operator: operatorCi ?? "system", detail: detail ?? null });
}

/**
 * Upsert en incident_cases_pg con los campos que correspondan a la operación.
 * Sólo escribe las columnas indicadas; el resto conservan el valor anterior.
 */
async function pgUpsertCase(id, fields) {
  const {
    severity, status, score, operatorId, adoptedAt,
    escalationLevel, escalatedTo, escalatedAt, escalationReason,
    enrichmentData, timelineEntry, slackNotifiedAt, closureReason,
    recommendedAction, sensorKey, networkZone,
    detectedAt,   // R5: timestamp del evento origen (Wazuh/Suricata/etc.) → MTTD
    // Contexto de red (editable por operador)
    hostname, sourceIp, destinationIp, destinationPort, sourcePort,
    protocol, firewallAction, srcCountry,
    affectedUser, assetId, assetType, businessImpact,
    // NIST SP 800-61
    incidentCategory, functionalImpact, informationImpact,
    recoverability, containmentStatus, rootCause, lessonsLearned,
    // Origen del evento (sin estos campos, "Sensor de origen" en UI queda vacío)
    iocValue, iocType, sourceLog,
    mitreTacticId, mitreTacticName, mitreTechniqueId,
    // Dedup key estable (migration 023): habilita lookup en PG en vez de Iceberg
    dedupKey,
    // Trazabilidad de fusión (migration 050): si NOT NULL, este caso fue fusionado
    // en el canónico indicado por POST /api/incidents/merge. Reemplaza el parseo
    // del texto 'MERGEADO → X' en recommended_action.
    mergedIntoCaseId,
    // R4 (migration 055): versión de fórmula que produjo severity_score.
    // Valores: v2|v3|v4 (sync DAG según vista usada) | manual (open-from-flow).
    scoringVersion,
    // P2-9 audit 2026-05-26: outcome del cierre. Valores:
    //   TRUE_POSITIVE | FALSE_POSITIVE | DUPLICATE | NO_ACTIONABLE
    //   AUTO_TP | AUTO_FP | AUTO_DUPLICATE (sistema)
    classification,
  } = fields;

  // closureReason y recommendedAction comparten columna; recommendedAction gana
  // si ambos vienen; closureReason es alias retro-compat de los flujos de cierre.
  const recommendedActionResolved = recommendedAction !== undefined
    ? recommendedAction
    : closureReason;

  // F3 (audit 2026-06-05): un cierre terminal SIEMPRE debe llevar classification.
  // Los callers de alto nivel (PATCH /status, transitionCase, /merge) ya la
  // setean; este default + telemetría cubre cualquier path que cierre vía
  // pgUpsertCase sin clasificar — evita classification NULL en estados
  // terminales (sesga KPIs de outcome) sin re-implementar los gates acá.
  const _isTerminalClose = status !== undefined
    && (String(status) === "CERRADO" || String(status) === "FALSO_POSITIVO");
  let classificationResolved = classification;
  if (_isTerminalClose && (classificationResolved === undefined || classificationResolved === null)) {
    classificationResolved = "AUTO_NO_ACTIONABLE";
    logger.warn("pgUpsertCase.terminal_without_classification", {
      caseId: id, status, defaulted: classificationResolved,
    });
  }

  // Clasificación eCSIRT/MISP persistida (mig 088): materializamos la clave para
  // poder FILTRAR/reportar por clase en SQL (el chip de la cola la deriva en vivo
  // con la misma classifyEcsirt). Sólo (re)computamos cuando el caller trae la
  // identidad del caso (IOC/MITRE/fuente) — así un update parcial (PATCH /status,
  // enrich-now sin esos campos) NO la pisa con OTHER. enrichment_data suma señales
  // de intel si vienen en este mismo upsert.
  let incidentClassResolved;
  if (iocType !== undefined || mitreTacticId !== undefined || sourceLog !== undefined) {
    const enr = enrichmentData?.iocEnrichment ?? enrichmentData ?? null;
    incidentClassResolved = classifyEcsirt({
      mitreTacticId, iocType, sourceLog, enrichment: enr,
    }).class;
  }

  // Geo de origen (mig 017): el upsert sólo persistía src_country si el caller lo
  // pasaba — y ningún path lo hacía (0/37k casos lo traían → el informe técnico
  // debía recalcular el país en caliente). Lo derivamos UNA vez aquí, offline, vía
  // MaxMind, cuando este upsert trae una IP pública de origen y no llega país.
  // No pisamos en updates parciales (si no hay IP en este upsert, queda undefined
  // → el .filter de `optional` lo descarta y conserva el valor previo). IPs
  // privadas devuelven null (lookupCountry filtra RFC1918) → src_country queda
  // NULL, que es lo correcto para tráfico interno.
  let srcCountryResolved = srcCountry;
  if (srcCountryResolved === undefined || srcCountryResolved === null) {
    const geoIpCandidate = sourceIp ?? (iocType === "ip" ? iocValue : undefined);
    if (geoIpCandidate) {
      try {
        const cc = await lookupCountry(String(geoIpCandidate));
        if (cc) srcCountryResolved = cc;
      } catch { /* geo no disponible → src_country queda como vino */ }
    }
  }

  // Lista canónica de columnas opcionales que viajan en INSERT y UPDATE.
  // Solo se incluyen las que el caller pasó (no undefined). Esto garantiza que
  // los datos de origen y red se persistan también al crear el caso, no solo
  // al actualizarlo (bug histórico: ON CONFLICT ... DO UPDATE solo aplicaba al
  // path de update, dejando casos nuevos con sensor_key/source_log/ioc_value en NULL).
  const optional = [
    ["operator_id",         operatorId],
    ["adopted_at",          adoptedAt],
    ["detected_at",         detectedAt],   // R5: MTTD anchor (timestamp del evento original)
    ["escalation_level",    escalationLevel],
    ["escalated_to",        escalatedTo],
    ["escalated_at",        escalatedAt],
    ["escalation_reason",   escalationReason],
    ["enrichment_data",     enrichmentData !== undefined ? JSON.stringify(enrichmentData) : undefined],
    ["slack_notified_at",   slackNotifiedAt],
    ["recommended_action",  recommendedActionResolved],
    ["sensor_key",          sensorKey],
    ["network_zone",        networkZone],
    ["hostname",            hostname],
    ["source_ip",           sourceIp],
    ["destination_ip",      destinationIp],
    ["destination_port",    destinationPort],
    ["source_port",         sourcePort],
    ["protocol",            protocol],
    ["firewall_action",     firewallAction],
    ["src_country",         srcCountryResolved],
    ["affected_user",       affectedUser],
    ["asset_id",            assetId],
    ["asset_type",          assetType],
    ["business_impact",     businessImpact],
    ["incident_category",   incidentCategory],
    ["functional_impact",   functionalImpact],
    ["information_impact",  informationImpact],
    ["recoverability",      recoverability],
    ["containment_status",  containmentStatus],
    ["root_cause",          rootCause],
    ["lessons_learned",     lessonsLearned],
    ["ioc_value",           iocValue],
    ["ioc_type",            iocType],
    ["source_log",          sourceLog],
    ["mitre_tactic_id",     mitreTacticId],
    ["mitre_tactic_name",   mitreTacticName],
    ["mitre_technique_id",  mitreTechniqueId],
    ["dedup_key",           dedupKey],
    ["merged_into_case_id", mergedIntoCaseId],
    ["scoring_version",     scoringVersion],
    ["classification",      classificationResolved],
    ["incident_class",      incidentClassResolved],
    ["is_false_positive",   classificationResolved && /FALSE|FP/i.test(String(classificationResolved)) ? true : undefined],
  ].filter(([, v]) => v !== undefined);

  const values = [id];
  let idx = 2;

  // Defaults obligatorios del INSERT (severity NO se actualiza en UPDATE para
  // no permitir downgrades automáticos, igual que el comportamiento previo).
  const insertCols = ["id", "severity", "status", "score", "anchor_dt", "updated_at"];
  const insertVals = [
    `$1`,
    `$${idx++}`,
    `$${idx++}`,
    `$${idx++}`,
    "CURRENT_DATE",
    "now()",
  ];
  values.push(severity ?? "MEDIUM", status ?? "NUEVO", score ?? 50);

  const setClauses = [];
  // status/score sí se actualizan si vienen explícitos.
  if (status !== undefined) { setClauses.push(`status = $${idx}`); values.push(status); idx++; }
  if (score  !== undefined) { setClauses.push(`score = $${idx}`);  values.push(score);  idx++; }

  for (const [colName, val] of optional) {
    insertCols.push(colName);
    insertVals.push(`$${idx}`);
    setClauses.push(`${colName} = $${idx}`);
    values.push(val);
    idx++;
  }

  // resolved_at: sella el momento de cierre cuando el status entra en un estado
  // terminal. Audit 2026-05-27: este helper no lo persistía → 308 casos cerrados
  // vía PATCH /status, merge, etc. quedaron con resolved_at NULL y MTTR a cero.
  // workflowEngine.transitionCase lo hace por su cuenta; replicamos acá con
  // COALESCE para que sea idempotente (no resetea cierres previos si el caller
  // re-aplica la misma transición).
  const TERMINAL_STATUSES = new Set(["CERRADO", "FALSO_POSITIVO"]);
  if (status !== undefined && TERMINAL_STATUSES.has(String(status))) {
    insertCols.push("resolved_at");
    insertVals.push("now()");
    setClauses.push("resolved_at = COALESCE(incident_cases_pg.resolved_at, now())");
  }

  // Timeline: append atómico (sin read-modify-write, evita race condition).
  // INSERT crea el array; UPDATE appendea preservando el existente.
  if (timelineEntry) {
    insertCols.push("timeline");
    insertVals.push(`jsonb_build_array($${idx}::jsonb)`);
    setClauses.push(
      `timeline = COALESCE(incident_cases_pg.timeline, '[]'::jsonb) || jsonb_build_array($${idx}::jsonb)`
    );
    values.push(timelineEntry);
    idx++;
  }

  setClauses.push("updated_at = now()");

  // RETURNING captura el status previo (via CTE de pre-select) y el actual,
  // para detectar transiciones reales. Si status no vino, prev=new=NULL y no
  // hay que escribir audit.
  const rows = await pgQuery(
    `WITH prev AS (
       SELECT status AS prev_status FROM incident_cases_pg WHERE id = $1
     )
     INSERT INTO incident_cases_pg (${insertCols.join(", ")})
     VALUES (${insertVals.join(", ")})
     ON CONFLICT (id) DO UPDATE SET ${setClauses.join(", ")}
     RETURNING (SELECT prev_status FROM prev) AS prev_status, status AS new_status`,
    values
  );

  // Audit trail: paralelo a workflowEngine.transitionCase. Sin esto los
  // cierres vía PATCH /status, merge, etc. no dejaban rastro en
  // case_timeline_events — sólo en el JSONB inline (audit gap 2026-05-27).
  // Sólo emite cuando hay transición real: prevStatus=null marca INSERT puro
  // (creación de caso) y NO se considera una transición.
  if (status !== undefined) {
    const prevStatus = rows[0]?.prev_status ?? null;
    const newStatus  = rows[0]?.new_status ?? status;
    if (prevStatus !== null && prevStatus !== newStatus) {
      try {
        await pgQuery(
          `INSERT INTO case_timeline_events
             (id, case_id, event_type, phase, title, description, operator_ci, source, metadata)
           VALUES ($1, $2, 'STATUS_CHANGE', $3, $4, $5, $6, 'MANUAL', $7)`,
          [
            randomUUID(),
            id,
            STATUS_TO_STAGE[newStatus] ?? null,
            `${prevStatus ?? "NEW"} → ${newStatus}`,
            closureReason ?? null,
            operatorId ?? "system",
            JSON.stringify({ fromStatus: prevStatus, toStatus: newStatus, via: "pgUpsertCase" }),
          ]
        );
      } catch (auditErr) {
        // No bloquear el upsert si la fila de audit falla — el cambio ya
        // está commit en incident_cases_pg + JSONB timeline (fuente primaria).
        logger.warn("pgUpsertCase.timeline_event_failed", {
          caseId: id, prevStatus, newStatus, err: auditErr.message,
        });
      }
    }
    // KPI cache invalidation: cualquier cambio de status afecta open_cases,
    // closed_cases, unassignedOpen, MTTR, MTTA, etc. Sin esto el dashboard
    // queda hasta 30s desincronizado tras una acción del operador (bulk-escalate,
    // bulk-assign, PATCH /status) — el LEADER lo lee como "no se aplicó" y
    // re-dispara la acción (audit P0.2 2026-05-27).
    invalidateCasesKpisCache();
  } else if (operatorId !== undefined || adoptedAt !== undefined) {
    // G1 (audit 2026-06-05): una reasignación pura de owner (sin cambio de
    // status) igual mueve KPIs por-operador (assigned_open, carga, MTTA). Antes
    // sólo se invalidaba en cambio de status → el panel del LEADER quedaba 30s
    // mostrando la asignación vieja.
    invalidateCasesKpisCache();
  }
}

/**
 * Batch lookup en PostgreSQL para un conjunto de case_ids.
 * Devuelve un Map { case_id → row }.
 */
async function pgBatchLookup(caseIds) {
  if (!caseIds.length) return new Map();
  try {
    const [rows, iocRows] = await Promise.all([
      pgQuery(
        `SELECT id, case_number, adopted_at, operator_id, created_at,
                escalation_level, escalated_to, escalated_at, escalation_reason,
                enrichment_data, timeline, slack_notified_at, recommended_action,
                resolved_at, status AS pg_status,
                merged_into_case_id,
                -- Contexto de red (columnas estructuradas)
                source_ip::text   AS source_ip,
                destination_ip::text AS destination_ip,
                destination_port, source_port,
                protocol, firewall_action, src_country,
                network_zone, sensor_key,
                hostname, asset_id, asset_type,
                affected_user, business_impact, evidence_links,
                -- NIST SP 800-61 (completado por operador)
                incident_category, functional_impact, information_impact,
                recoverability, containment_status, root_cause, lessons_learned,
                -- Escalación automática
                escalation_suggested, escalation_reason_auto
         FROM incident_cases_pg
         WHERE id = ANY($1)`,
        [caseIds]
      ),
      // IOC primario enriquecido (VT permalink, Shodan, MISP)
      pgQuery(
        `SELECT case_id, vt_permalink, abuse_score, in_misp, shodan_summary, enriched_at
         FROM case_iocs
         WHERE case_id = ANY($1) AND is_primary = true`,
        [caseIds]
      ).catch(() => []),
    ]);
    const iocMap = new Map(iocRows.map((r) => [r.case_id, r]));
    return new Map(rows.map((r) => [r.id, { ...r, _ioc: iocMap.get(r.id) ?? null }]));
  } catch {
    return new Map(); // PG no disponible → degradar silenciosamente
  }
}

// ── Sort helper ────────────────────────────────────────────────────────────────

/**
 * Builds a safe ORDER BY clause for incident_cases listing.
 * Only allows known column names to prevent SQL injection.
 */
function buildOrderBy(sort, sortDir) {
  const dir = String(sortDir).toUpperCase() === "DESC" ? "DESC" : "ASC";
  const SEVERITY_CASE = `
    CASE ic.severity_text
      WHEN 'CRITICAL'   THEN 1
      WHEN 'HIGH'       THEN 2
      WHEN 'MEDIUM'     THEN 3
      WHEN 'LOW'        THEN 4
      WHEN 'NEGLIGIBLE' THEN 5
      ELSE 6
    END ${dir}`;

  switch (String(sort).toLowerCase()) {
    case "id":
    case "caso":       return `ic.case_id ${dir}`;
    case "ioc":
    case "source":     return `ic.ioc_value ${dir}, ic.source_log ${dir}`;
    case "severity":   return `${SEVERITY_CASE}, ic.first_seen DESC NULLS LAST`;
    case "status":     return `COALESCE(ic.status,'NUEVO') ${dir}, ic.first_seen DESC NULLS LAST`;
    case "stage":
    case "etapa":      return `ic.source_category ${dir} NULLS LAST, ic.first_seen DESC NULLS LAST`;
    case "score":      return `ic.severity_score ${dir} NULLS LAST, ic.first_seen DESC NULLS LAST`;
    case "detected":
    case "detectado":  return `ic.first_seen ${dir} NULLS LAST`;
    case "creado":
    case "created":    return `ic.first_seen ${dir} NULLS LAST`;
    case "sla":        return `${SEVERITY_CASE}, ic.first_seen ASC NULLS LAST`;
    default:           return `${SEVERITY_CASE}, ic.first_seen DESC NULLS LAST`;
  }
}

// ── Narrative helpers (scoring-detail) ────────────────────────────────────────

/**
 * Fuente → etiqueta legible en español para el brief del analista.
 */
const SOURCE_LABEL = {
  wazuh_alerts:       "Wazuh SIEM",
  wazuh_fluent:       "Wazuh Fluent (syslog)",
  opnsense_filterlog: "OPNsense Filterlog",
  suricata_ids:       "Suricata IDS",
  fortigate_utm:      "Fortigate UTM",
  pmg_mail:           "Email / Phishing (PMG)",
};

/**
 * MITRE tactic ID → fase de kill-chain legible.
 */
const TACTIC_LABEL = {
  TA0043: "Reconocimiento",       TA0042: "Desarrollo de recursos",
  TA0001: "Acceso inicial",       TA0002: "Ejecución",
  TA0003: "Persistencia",         TA0004: "Escalada de privilegios",
  TA0005: "Evasión de defensas",  TA0006: "Acceso a credenciales",
  TA0007: "Descubrimiento",       TA0008: "Movimiento lateral",
  TA0009: "Recolección",          TA0011: "Comando y control (C2)",
  TA0010: "Exfiltración",         TA0040: "Impacto",
};

/**
 * Genera un resumen textual del incidente orientado al analista.
 * Construido 100% a partir de los metadatos del caso — sin LLM.
 */
function buildAnalystBrief(c) {
  const sev    = String(c.severity ?? "MEDIUM").toUpperCase();
  const src    = SOURCE_LABEL[c.source_log] ?? String(c.source_log ?? "sensor desconocido");
  const ioc    = String(c.ioc_value ?? "desconocido");
  const score  = Number(c.score  ?? 0);
  const tactic = c.mitre_tactic_id
    ? `${TACTIC_LABEL[c.mitre_tactic_id] ?? c.mitre_tactic_name ?? c.mitre_tactic_id} (${c.mitre_tactic_id})`
    : null;

  // Enriquecimiento — leer de enrichment_data JSONB
  const enrich = c.enrichment_data ?? {};
  const vtMal  = enrich.vt_malicious ?? enrich.vtMalicious ?? null;
  const abuse  = enrich.abuse_confidence ?? enrich.abuseConfidence ?? null;
  const inFeed = enrich.in_urlhaus || enrich.inUrlhaus || enrich.in_openphish || enrich.inOpenphish;

  // Párrafo 1 — tipo y origen
  const sevLabel = { CRITICAL: "Amenaza CRÍTICA", HIGH: "Amenaza ALTA", MEDIUM: "Actividad MEDIA",
                     LOW: "Actividad BAJA", NEGLIGIBLE: "Actividad NEGLIGIBLE" }[sev] ?? `Severidad ${sev}`;
  let brief = `${sevLabel} detectada por ${src}. IOC identificado: ${ioc}.`;

  // Párrafo 2 — evidencia de inteligencia
  const parts = [];
  if (vtMal != null && Number(vtMal) > 0)
    parts.push(`${vtMal} motores de VirusTotal lo clasifican como malicioso`);
  if (abuse != null && Number(abuse) > 0)
    parts.push(`AbuseIPDB reporta confianza de ${abuse}%`);
  if (inFeed)
    parts.push(`presencia en feeds de IOCs (URLhaus / OpenPhish)`);
  if (parts.length)
    brief += ` Inteligencia externa: ${parts.join("; ")}.`;

  // Párrafo 3 — MITRE
  if (tactic)
    brief += ` Táctica MITRE ATT&CK identificada: ${tactic}.`;

  // Párrafo 4 — score
  const scoreLabel = score >= 90 ? "extremadamente alto" : score >= 70 ? "alto" : score >= 45 ? "moderado" : "bajo";
  brief += ` Score de riesgo calculado: ${score} puntos (nivel ${scoreLabel}).`;

  // Párrafo 5 — acción recomendada
  if (c.recommended_action)
    brief += ` Acción recomendada: ${c.recommended_action}`;
  else {
    const defaultActions = {
      CRITICAL: "Contener inmediatamente — bloquear IOC en todos los controles perimetrales y aislar activos afectados.",
      HIGH:     "Investigar en < 1 hora — confirmar si el IOC tiene conectividad activa y revisar logs relacionados.",
      MEDIUM:   "Analizar contexto — verificar si existe correlación con otros eventos y enriquecer el caso.",
      LOW:      "Monitorear — agregar a lista de observación y revisar en próximo ciclo de análisis.",
    };
    brief += ` ${defaultActions[sev] ?? "Revisar el caso y determinar plan de acción."}`;
  }

  return brief.trim();
}

/**
 * Infiere la taxonomía NIST SP 800-61 y la categoría de ataque a partir del
 * source_log y el tactic_id MITRE.
 *
 * @returns {{ nistCategory, nistLabel, attackCategory, confidence, rationale }}
 */
function inferTaxonomy(c) {
  const src    = String(c.source_log ?? "").toLowerCase();
  const tactic = String(c.mitre_tactic_id ?? "").toUpperCase();
  const enrich = c.enrichment_data ?? {};
  const score  = Number(c.score ?? 0);
  const sev    = String(c.severity ?? "MEDIUM").toUpperCase();

  let nistCategory  = "OTHER";
  let attackCategory = "Actividad sospechosa";
  let rationale      = [];
  let confidence     = 0.35; // base

  // ── Clasificación por fuente + táctica ──────────────────────────────────────
  if (src.includes("pmg") || src.includes("mail") || src.includes("phish")) {
    nistCategory   = "MALICIOUS_CODE";
    attackCategory = "Phishing / Correo malicioso";
    rationale.push("Fuente PMG Email");
    confidence += 0.30;
  } else if (src.includes("filterlog") || src.includes("opnsense")) {
    nistCategory   = "SCANS_PROBES";
    attackCategory = "Escaneo / Sondeo perimetral";
    rationale.push("OPNsense Filterlog — tráfico bloqueado perimetral");
    confidence += 0.20;
  } else if (src.includes("fortigate")) {
    nistCategory   = "SCANS_PROBES";
    attackCategory = "Intento de intrusión bloqueado (UTM)";
    rationale.push("Fortigate UTM — política de bloqueo activada");
    confidence += 0.20;
  } else if (src.includes("suricata")) {
    if (["TA0001","TA0006","TA0003"].includes(tactic)) {
      nistCategory   = "UNAUTHORIZED_ACCESS";
      attackCategory = "Intento de acceso no autorizado (IDS)";
    } else if (tactic === "TA0011") {
      nistCategory   = "MALICIOUS_CODE";
      attackCategory = "Comunicación C2 detectada por IDS";
    } else {
      nistCategory   = "SCANS_PROBES";
      attackCategory = "Alerta IDS — tráfico anómalo";
    }
    rationale.push("Suricata IDS");
    confidence += 0.15;
  } else if (src.includes("wazuh")) {
    if (tactic === "TA0006") {
      nistCategory   = "UNAUTHORIZED_ACCESS";
      attackCategory = "Ataque de credenciales (fuerza bruta / spraying)";
    } else if (tactic === "TA0001") {
      nistCategory   = "UNAUTHORIZED_ACCESS";
      attackCategory = "Acceso inicial detectado por SIEM";
    } else if (tactic === "TA0011" || tactic === "TA0010") {
      nistCategory   = "MALICIOUS_CODE";
      attackCategory = "C2 / Exfiltración detectada";
    } else if (["TA0043","TA0042","TA0007"].includes(tactic)) {
      nistCategory   = "SCANS_PROBES";
      attackCategory = "Reconocimiento interno / sondeo";
    } else {
      nistCategory   = "INVESTIGATION";
      attackCategory = "Evento de seguridad bajo análisis";
    }
    rationale.push("Wazuh SIEM");
    confidence += 0.15;
  }

  // ── Ajuste de confianza por calidad de datos ─────────────────────────────────
  if (tactic && tactic !== "") {
    confidence += 0.20;
    rationale.push(`Táctica MITRE confirmada: ${tactic}`);
  }
  const hasEnrich = (enrich.vt_malicious ?? enrich.vtMalicious) != null
    || (enrich.abuse_confidence ?? enrich.abuseConfidence) != null;
  if (hasEnrich) {
    confidence += 0.15;
    rationale.push("Enriquecimiento externo disponible (VT/AbuseIPDB)");
  }
  if (score >= 70) {
    confidence += 0.10;
    rationale.push(`Score alto (${score} pts)`);
  }
  if (sev === "CRITICAL" || sev === "HIGH") {
    confidence += 0.05;
    rationale.push(`Severidad ${sev}`);
  }

  // Normalizar a [0, 0.99]
  confidence = Math.min(0.99, confidence);

  // NIST → etiqueta legible
  const NIST_LABEL = {
    UNAUTHORIZED_ACCESS: "Acceso no autorizado",
    DENIAL_OF_SERVICE:   "Denegación de servicio",
    MALICIOUS_CODE:      "Código malicioso",
    IMPROPER_USAGE:      "Uso indebido",
    SCANS_PROBES:        "Escaneos / Sondeo",
    INVESTIGATION:       "En investigación",
    OTHER:               "Otro",
  };

  return {
    nistCategory,
    nistLabel:      NIST_LABEL[nistCategory] ?? nistCategory,
    attackCategory,
    confidence:     +confidence.toFixed(2),
    rationale,
  };
}

// ── Caza Externa → Gestión: mapeo hunt_finding → caso (sync Fase 1) ──────────
// Un hunt_finding describe una CLASE de amenaza sobre un par interno↔externo.
// hunt_findings NO almacena MITRE ni score numérico, así que lo derivamos del
// pattern_key y de la severidad del finding para construir un caso canónico.
const HUNT_PATTERN_MITRE = {
  ot_egress_foreign_cloud:  { techniqueId: "T1071",     tacticId: "TA0011", tacticName: "Command and Control" },
  egress_foreign:           { techniqueId: "T1071",     tacticId: "TA0011", tacticName: "Command and Control" },
  beaconing_cadence:        { techniqueId: "T1071.001", tacticId: "TA0011", tacticName: "Command and Control" },
  beaconing:                { techniqueId: "T1071.001", tacticId: "TA0011", tacticName: "Command and Control" },
  permitido_intel_negativa: { techniqueId: "T1071",     tacticId: "TA0011", tacticName: "Command and Control" },
  auth_bruteforce:          { techniqueId: "T1110",     tacticId: "TA0006", tacticName: "Credential Access" },
  dns_tunneling:            { techniqueId: "T1071.004", tacticId: "TA0011", tacticName: "Command and Control" },
};
const HUNT_MITRE_DEFAULT = { techniqueId: "T1071", tacticId: "TA0011", tacticName: "Command and Control" };
function mitreFromHuntPattern(patternKey) {
  const k = String(patternKey ?? "").toLowerCase();
  if (HUNT_PATTERN_MITRE[k]) return HUNT_PATTERN_MITRE[k];
  for (const [key, val] of Object.entries(HUNT_PATTERN_MITRE)) {
    if (k.includes(key)) return val;
  }
  return HUNT_MITRE_DEFAULT;
}
function inferIocTypeFromValue(v) {
  const s = String(v ?? "").trim();
  if (/^https?:\/\//i.test(s) || s.includes("/")) return "url";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ip";
  if (s.includes(":") && /^[0-9a-f:]+$/i.test(s)) return "ip";        // IPv6
  if (/^[a-f0-9]{32,64}$/i.test(s)) return "hash";
  if (s.includes(".") && /[a-z]/i.test(s)) return "domain";
  return "ip";
}
// Piso de score por severidad — por encima del umbral canónico (soc_thresholds:
// CRIT 74 / HIGH 48 / MED 27) para que el caso nazca en la severidad del finding.
const HUNT_SEV_SCORE = { CRITICAL: 85, HIGH: 62, MEDIUM: 40, LOW: 15, NEGLIGIBLE: 5 };
const HUNT_SEV_RANK  = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NEGLIGIBLE: 5 };

/**
 * Sincroniza un hallazgo de Caza Externa (hunt_findings) a Gestión de Casos.
 * Núcleo compartido por el endpoint manual (POST /findings/:id/open-case) y el
 * auto-open gated (Fase 3, schedulerService). Mapea server-side el contexto rico
 * del finding (activo interno, evidencia, veredicto+narrativa LLM) a un caso
 * canónico, con dedup por IOC y enlace bidireccional.
 *
 * Devuelve { outcome, caseId, ... }. outcome ∈
 *   not_found | no_ioc | already_linked | linked_existing | created | raced | error
 * NO lanza por casos de negocio; solo propaga errores inesperados al caller.
 *
 * @param {string} findingId
 * @param {{ operatorCi: string, getIo?: () => any }} opts
 */
export async function openCaseFromHuntFinding(findingId, { operatorCi, getIo = null } = {}) {
  const ci = String(operatorCi ?? "").trim() || "caza-externa";

  const [f] = await pgQuery(
    `SELECT finding_id, pattern_key, severity, title, internal_asset, external_entity,
            evidence, event_count, first_seen, last_seen, status,
            llm_verdict, llm_confidence, llm_narrative, llm_recommended_action,
            llm_evidence_cited, linked_case_id
       FROM hunt_findings WHERE finding_id = $1`,
    [findingId],
  );
  if (!f) return { outcome: "not_found" };

  const ioc = String(f.external_entity ?? "").trim();
  if (!ioc) return { outcome: "no_ioc" };

  const iocType = inferIocTypeFromValue(ioc);
  const sev     = String(f.severity ?? "MEDIUM").toUpperCase();
  const mitre   = mitreFromHuntPattern(f.pattern_key);
  const ev      = (f.evidence && typeof f.evidence === "object") ? f.evidence : {};

  const verdictLine = f.llm_verdict
    ? `Veredicto LLM: ${f.llm_verdict} (confianza ${f.llm_confidence ?? "N/D"}%). Acción recomendada: ${f.llm_recommended_action ?? "N/D"}.`
    : "Sin veredicto del analista LLM.";
  const timelineDesc =
    (f.llm_narrative || f.title || "Hallazgo de Caza Externa.") +
    `\n${verdictLine}\nPatrón: ${f.pattern_key} · Activo interno: ${f.internal_asset ?? "N/D"} · Eventos: ${Number(f.event_count) || 0}.`;

  // Siembra el veredicto de caza en el timeline (idempotente por finding+verdict).
  const seedTimeline = async (cid) => {
    const [dup] = await pgQuery(
      `SELECT 1 FROM case_timeline_events
        WHERE case_id = $1 AND metadata->>'finding_id' = $2
          AND COALESCE(metadata->>'verdict','') = $3 LIMIT 1`,
      [cid, f.finding_id, f.llm_verdict ?? ""],
    );
    if (dup) return;
    await addTimelineEvent(cid, {
      eventType: "DETECTION", phase: "DETECTION",
      title: `Caza Externa: ${f.pattern_key}${f.llm_verdict ? ` (${f.llm_verdict})` : ""}`,
      description: timelineDesc, operatorCi: ci, source: "MANUAL",
      metadata: { finding_id: f.finding_id, verdict: f.llm_verdict ?? null, pattern_key: f.pattern_key, source: "caza_externa" },
    });
  };

  const linkFinding = async (cid) => pgQuery(
    `UPDATE hunt_findings
        SET linked_case_id = $2, operator_disposition = 'confirmed',
            operator_ci = COALESCE($3, operator_ci), status = 'ACTIONED', updated_at = now()
      WHERE finding_id = $1`,
    [findingId, cid, ci],
  );

  // 1) Idempotencia: finding ya enlazado a un caso activo.
  if (f.linked_case_id) {
    const [active] = await pgQuery(
      `SELECT id, case_number FROM incident_cases_pg
        WHERE id = $1 AND status NOT IN ('CERRADO','FALSO_POSITIVO') LIMIT 1`,
      [f.linked_case_id],
    );
    if (active) {
      await seedTimeline(active.id);
      return { outcome: "already_linked", caseId: active.id, caseNumber: active.case_number ?? null };
    }
  }

  // 2) Dedup por IOC: enlazar a caso activo existente en vez de duplicar.
  const [dupe] = await pgQuery(
    `SELECT id, case_number FROM incident_cases_pg
      WHERE (ioc_value = $1 OR EXISTS (SELECT 1 FROM case_iocs ci WHERE ci.case_id = id AND ci.ioc_value = $1))
        AND status NOT IN ('CERRADO','FALSO_POSITIVO')
        AND updated_at >= now() - INTERVAL '30 days'
      ORDER BY updated_at DESC LIMIT 1`,
    [ioc],
  );
  if (dupe) {
    await linkFinding(dupe.id);
    await seedTimeline(dupe.id);
    return { outcome: "linked_existing", caseId: dupe.id, caseNumber: dupe.case_number ?? null };
  }

  // 3) Crear caso nuevo.
  const caseId = randomUUID();
  const now    = new Date().toISOString();
  const score  = HUNT_SEV_SCORE[sev] ?? 40;
  const dedupKeyFinal = canonDedupKey({ iocValue: ioc, iocType, severity: sev, mitreTacticId: mitre.tacticId, sourceLog: "caza_externa" });
  const dstIp    = iocType === "ip" ? ioc : (ev.dst_ip ?? ev.dstip ?? null);
  const dstPortN = ev.dst_port != null ? Number(ev.dst_port) : (ev.dstport != null ? Number(ev.dstport) : NaN);
  const proto    = (ev.proto ?? ev.protocol ?? null)?.toString().toLowerCase() ?? null;

  // Iceberg (fuente analítica) — misma primitiva/columnas que open-from-flow.
  await trinoExec(buildCasesInsert({
    case_id: caseId, dedup_key: dedupKeyFinal,
    ioc_value: canonNormalizeIoc(ioc, iocType), ioc_type: iocType,
    source_log: "caza_externa",
    mitre_technique_id: mitre.techniqueId, mitre_tactic_id: mitre.tacticId, mitre_tactic_name: mitre.tacticName,
    source_category: "caza_externa",
    severity_text: sev, severity_rank: HUNT_SEV_RANK[sev] ?? 3, severity_score: score,
    confidence_level: null, status: "EN_ANALISIS", occurrence_count: 1,
    first_seen: f.first_seen ?? now, last_seen: f.last_seen ?? now, anchor_dt: now.slice(0, 10),
    linked_evidence: f.finding_id,
    score_breakdown: JSON.stringify({ score_mitre: 0, score_evidence: 0, score_wazuh: 0, score_misp: 0, score_context: 0 }),
    notes: `Caso abierto desde Caza Externa (patrón ${f.pattern_key}) por ${ci}`,
    assigned_to: ci, created_at: now, updated_at: now, adopted_at: now,
  }), SESSION);

  // Espejo PG (fuente operacional).
  const enrichmentSeed = {
    _status: "pending",
    hunt_finding: {
      finding_id: f.finding_id, pattern_key: f.pattern_key,
      internal_asset: f.internal_asset ?? null, event_count: Number(f.event_count) || 0,
      llm_verdict: f.llm_verdict ?? null, llm_confidence: f.llm_confidence ?? null,
      llm_recommended_action: f.llm_recommended_action ?? null, evidence: ev,
    },
  };
  // El CI puede ser sintético del automatismo (p.ej. "caza-externa-auto"), que NO
  // existe en soc_operators → violaría fk_cases_operator (operator_id REFERENCES
  // soc_operators(id)). Si no es un operador real, el caso queda SIN ASIGNAR
  // (operator_id NULL, válido); la procedencia se conserva en notes/timeline y en
  // assigned_to del espejo Iceberg. (Bug latente: el auto-open nunca estuvo on.)
  const [opRow] = await pgQuery(`SELECT id FROM soc_operators WHERE id = $1 LIMIT 1`, [ci]);
  const caseOperatorId = opRow ? ci : null;

  try {
    await pgUpsertCase(caseId, {
      severity: sev, status: "EN_ANALISIS", score, operatorId: caseOperatorId, adoptedAt: now,
      detectedAt: f.first_seen ?? null, enrichmentData: enrichmentSeed,
      sensorKey: f.internal_asset ?? null,
      iocValue: ioc, iocType, sourceLog: "caza_externa",
      mitreTacticId: mitre.tacticId, mitreTacticName: mitre.tacticName, mitreTechniqueId: mitre.techniqueId,
      dedupKey: dedupKeyFinal, scoringVersion: "caza_externa",
      hostname: f.internal_asset ?? null, assetId: f.internal_asset ?? null,
      destinationIp: dstIp, destinationPort: Number.isFinite(dstPortN) ? dstPortN : null, protocol: proto,
    });
  } catch (err) {
    // Race del UNIQUE PARCIAL por dedup_key (mig 034): enlazar al ganador.
    if (err?.code === "23505") {
      const [r] = await pgQuery(
        `SELECT id FROM incident_cases_pg WHERE dedup_key = $1 AND status NOT IN ('CERRADO','FALSO_POSITIVO') ORDER BY updated_at DESC LIMIT 1`,
        [dedupKeyFinal],
      ).catch(() => [null]);
      if (r?.id) {
        await linkFinding(r.id);
        await seedTimeline(r.id);
        return { outcome: "raced", caseId: r.id };
      }
    }
    throw err;
  }

  await seedTimeline(caseId);
  await linkFinding(caseId);

  // Bootstrap de tareas (idempotente, best-effort).
  try {
    await bootstrapCaseTasks(caseId, {
      severity: sev, score, source_log: "caza_externa",
      ioc_value: ioc, ioc_type: iocType,
      mitre_tactic_id: mitre.tacticId, mitre_tactic_name: mitre.tacticName, operator_id: ci,
    }, {}, "caza-externa", pgQuery, { randomUUIDFn: randomUUID });
  } catch (e) { logger.warn("incidents.hunt_open_case.tasks_bootstrap_failed", { caseId, err: e?.message }); }

  // Enriquecimiento async (VT/Shodan/AbuseIPDB) — best-effort, no bloquea.
  enrichIoc(ioc, iocType)
    .then(async (enr) => {
      const enrData = {
        ...enrichmentSeed, _status: "done",
        ...(enr?.summary ? { iocEnrichment: enr.summary, iocSources: enr.sources, iocStatus: enr.status, iocVerdict: enr.verdict, enrichedAt: enr.enrichedAt } : {}),
      };
      await pgQuery(`UPDATE incident_cases_pg SET enrichment_data = $1::jsonb, updated_at = now() WHERE id = $2`, [JSON.stringify(enrData), caseId]);
    })
    .catch((e) => logger.warn("incidents.hunt_open_case.enrich_failed", { caseId, err: e?.message }));

  getIo?.()?.emit("incident:opened_from_flow", { id: caseId, operatorCi: ci, iocValue: ioc, source: "caza_externa" });

  return { outcome: "created", caseId, status: "EN_ANALISIS", severity: sev, score };
}

// ── Factory ────────────────────────────────────────────────────────────────────

export default function incidentsRouter(runQuery, getIo, ensureFreshCtiSnapshot = null) {
  const router = Router();

  // ── GET /api/incidents/open ──────────────────────────────────────────────────
  router.get("/open", async (req, res) => {
    const {
      severity = "ALL",
      status   = "ALL",
      page     = "1",
      pageSize = "25",
      search,
      sort    = "severity",
      sortDir = "asc",
      dateFrom,
      dateTo,
      // Filtros por operador asignado (resuelto contra PG, fuente de verdad
      // operacional). assignedTo admite valores especiales:
      //   __unassigned__  → operator_id IS NULL
      //   <CI>            → operator_id = <CI>
      // assignedRole filtra por role_id en soc_operators (LEADER/L1/L2/L1L2/L3).
      assignedTo,
      assignedRole,
      // Por defecto se ocultan CERRADO y FALSO_POSITIVO. Se respetan si el
      // operador los selecciona explícitamente vía status= o si pasa
      // includeClosed=true.
      includeClosed = "false",
      // C5 — DSL search params: rangos de score (0-200) y ventana de
      // created_at (timestamp ISO). El parser frontend resuelve `score:>N`,
      // `score:N-M`, `age:<7d`, `createdAt:>2026-05-15` a estos 4 valores
      // antes de enviar. Backend solo valida y aplica.
      scoreMin,
      scoreMax,
      createdAtMin,
      createdAtMax,
      // Clase eCSIRT/MISP (mig 088): clave persistida en incident_cases_pg.
      // "ALL" / vacío → sin filtrar. Valores: claves de ECSIRT_CLASSES.
      incidentClass = "ALL",
    } = req.query;

    // Validación tolerante: descartamos valores no-parseables sin tirar 400 —
    // un input malformado en el DSL del frontend simplemente no debe filtrar.
    const isIntStr = (s) => /^-?\d+$/.test(String(s ?? ""));
    const isIsoTs  = (s) => {
      const v = String(s ?? "");
      if (!/^\d{4}-\d{2}-\d{2}([T ].+)?$/.test(v)) return false;
      return Number.isFinite(Date.parse(v));
    };
    const scoreMinNum = isIntStr(scoreMin) ? Number(scoreMin) : null;
    const scoreMaxNum = isIntStr(scoreMax) ? Number(scoreMax) : null;
    const createdAtMinIso = isIsoTs(createdAtMin) ? String(createdAtMin) : null;
    const createdAtMaxIso = isIsoTs(createdAtMax) ? String(createdAtMax) : null;
    // Clase eCSIRT: sólo aceptamos claves conocidas (descarta valores arbitrarios).
    const classKey = String(incidentClass ?? "").toUpperCase();
    const incidentClassFilter =
      classKey && classKey !== "ALL" && Object.hasOwn(ECSIRT_CLASSES, classKey)
        ? classKey : null;

    const pg   = Math.max(1, Number(page));
    const ps   = Math.min(200, Math.max(1, Number(pageSize)));
    const skip = (pg - 1) * ps;

    // Rango de fecha para anchor_dt (validado contra inyección SQL).
    // Default 30 d: cubre todos los casos operativamente relevantes (NUEVO,
    // EN_ANALISIS, CONFIRMADO, ESCALADO) y permite a Trino hacer partition
    // pruning agresivo sobre incident_cases — sin esto el planner recorre
    // manifests de 365 días y supera TRINO_QUERY_TOTAL_TIMEOUT_MS. Para ver
    // casos más antiguos se usa dateFrom explícito.
    const isValidDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(String(s ?? ""));
    const anchorFrom = isValidDate(dateFrom)
      ? `DATE '${dateFrom}'`
      : `current_date - INTERVAL '30' DAY`;
    const anchorToClause = isValidDate(dateTo)
      ? ` AND anchor_dt <= DATE '${dateTo}'`
      : "";

    const filters = [];
    if (severity !== "ALL") {
      filters.push(`severity_text = ${sq(severity)}`);
    }
    if (status !== "ALL") {
      // Specific status selected — include it regardless of whether it's "open" or "closed"
      filters.push(`COALESCE(ic.status, 'NUEVO') = ${sq(status)}`);
    } else if (String(includeClosed).toLowerCase() !== "true") {
      // status=ALL + includeClosed=false → ocultamos automáticamente CERRADO y
      // FALSO_POSITIVO. El operador puede activar el toggle "Incluir cerrados"
      // o seleccionar uno de esos estados explícitamente.
      filters.push(`COALESCE(ic.status, 'NUEVO') NOT IN ('CERRADO','FALSO_POSITIVO')`);
    }
    if (search) {
      const s = sq(`%${search}%`);
      filters.push(`(
        ic.case_id    LIKE ${s} OR
        ic.ioc_value  LIKE ${s} OR
        ic.ioc_type   LIKE ${s} OR
        ic.source_log LIKE ${s} OR
        ic.mitre_tactic_name LIKE ${s}
      )`);
    }

    // ── Pre-filtro por operador / rol (vía PG) ─────────────────────────────
    // Cuando se solicita filtrar por owner, PG es la fuente de verdad (Trino
    // assigned_to puede estar desincronizado tras transferencias). Resolvemos
    // los case_ids candidatos en PG y los inyectamos como IN (...) en Trino.
    //
    // BUG fix 2026-05-13: antes la subquery solo aplicaba operator_id+role,
    // sin status ni anchor_dt. Como incident_cases_pg tiene ~160k casos sin
    // asignar (mayoría CERRADO/FP antiguos), el LIMIT 5000 se llenaba con
    // cerrados y al pasar por la query principal sólo sobrevivían ~3-7 abiertos
    // — facets decía 1444 sin asignar pero el listado se veía vacío. Replicamos
    // los filtros de status/severity/anchor_dt acá para que la subquery
    // entregue solo candidatos que la query principal va a aceptar.
    if (assignedTo || assignedRole) {
      const pgFilters = [];
      const pgParams  = [];
      let pgIdx = 1;

      if (assignedTo === "__unassigned__") {
        pgFilters.push(`c.operator_id IS NULL`);
      } else if (assignedTo) {
        pgFilters.push(`c.operator_id = $${pgIdx++}`);
        pgParams.push(String(assignedTo));
      }

      // Para assignedRole admitimos lista separada por coma (multi-perfil):
      //   ?assignedRole=L1,L1L2  → o.role_id IN ('L1','L1L2')
      //
      // Nota: si además se pidió `__unassigned__`, el filtro de rol es
      // contradictorio (un caso sin operador no tiene role_id) y se ignora —
      // de lo contrario el INNER JOIN excluía los 55 casos huérfanos y la
      // tabla aparecía vacía aunque el contador de facetas mostrase "55".
      const roles = String(assignedRole ?? "")
        .split(",")
        .map((s) => s.trim().toUpperCase())
        .filter(Boolean);
      const useJoin = roles.length > 0 && assignedTo !== "__unassigned__";
      if (useJoin) {
        const placeholders = roles.map(() => `$${pgIdx++}`).join(",");
        pgFilters.push(`o.role_id IN (${placeholders})`);
        pgParams.push(...roles);
      }

      // Espejar status/severity/anchor_dt: la query principal ya los aplica,
      // pero acotar acá evita que el LIMIT 5000 se llene de cerrados antiguos.
      if (status !== "ALL") {
        pgFilters.push(`c.status = $${pgIdx++}`);
        pgParams.push(String(status));
      } else if (String(includeClosed).toLowerCase() !== "true") {
        pgFilters.push(`c.status NOT IN ('CERRADO','FALSO_POSITIVO')`);
      }
      if (severity !== "ALL") {
        pgFilters.push(`c.severity = $${pgIdx++}`);
        pgParams.push(String(severity));
      }
      if (isValidDate(dateFrom)) {
        pgFilters.push(`c.anchor_dt >= $${pgIdx++}::date`);
        pgParams.push(dateFrom);
      } else {
        // Mismo default que la query principal (30 d).
        pgFilters.push(`c.anchor_dt >= current_date - INTERVAL '30 days'`);
      }
      if (isValidDate(dateTo)) {
        pgFilters.push(`c.anchor_dt <= $${pgIdx++}::date`);
        pgParams.push(dateTo);
      }
      // C5 — Espejar filtros DSL acá también, sino LIMIT 5000 puede llenarse
      // de candidatos que la query principal rechaza después.
      if (scoreMinNum != null) {
        pgFilters.push(`c.score >= $${pgIdx++}`);
        pgParams.push(scoreMinNum);
      }
      if (scoreMaxNum != null) {
        pgFilters.push(`c.score <= $${pgIdx++}`);
        pgParams.push(scoreMaxNum);
      }
      if (createdAtMinIso) {
        pgFilters.push(`c.created_at >= $${pgIdx++}::timestamptz`);
        pgParams.push(createdAtMinIso);
      }
      if (createdAtMaxIso) {
        pgFilters.push(`c.created_at <= $${pgIdx++}::timestamptz`);
        pgParams.push(createdAtMaxIso);
      }

      const sqlPg = `
        SELECT c.id
        FROM incident_cases_pg c
        ${useJoin ? "JOIN soc_operators o ON o.id = c.operator_id" : ""}
        WHERE ${pgFilters.join(" AND ")}
        LIMIT 5000`;

      let pgIds = [];
      try {
        const rows = await pgQuery(sqlPg, pgParams);
        pgIds = rows.map((r) => String(r.id));
      } catch (err) {
        return res.status(500).json({ error: `Error al filtrar por operador: ${err.message}` });
      }

      if (pgIds.length === 0) {
        // Sin coincidencias: respuesta vacía sin tocar Trino
        return res.json({ cases: [], total: 0, page: pg, pageSize: ps });
      }
      // IN list cap a 5000 (Trino acepta IN grandes pero pasamos algunos miles
      // ya es un caso de uso atípico — mostramos lo que cabe).
      const inList = pgIds.map((id) => sq(id)).join(",");
      filters.push(`ic.case_id IN (${inList})`);
    }

    // ── PG-first: servimos el listado desde incident_cases_pg (source-of-truth
    // operacional). El backend Trino/Iceberg sobre incident_cases acumula
    // metadata explotada (miles de commits/día por auto-close) y el planner
    // supera TRINO_QUERY_TOTAL_TIMEOUT_MS incluso con partition filter.
    // Los campos Trino-only (raw_context, confidence_level, source_category,
    // score_breakdown) se retornan null aquí; mapCaseRow los tolera.
    // Traducimos los filtros Trino-shaped a columnas PG equivalentes.
    const pgFilters = [];
    const pgParams  = [];
    let pgIdx = 1;

    // Ventana anchor_dt
    if (isValidDate(dateFrom)) {
      pgFilters.push(`anchor_dt >= $${pgIdx++}::date`);
      pgParams.push(dateFrom);
    } else {
      // Default 30 d (cubre casos operacionalmente relevantes)
      pgFilters.push(`anchor_dt >= current_date - INTERVAL '30 days'`);
    }
    if (isValidDate(dateTo)) {
      pgFilters.push(`anchor_dt <= $${pgIdx++}::date`);
      pgParams.push(dateTo);
    }

    // Severity / status (ya validados arriba vs filters[] de Trino)
    if (severity !== "ALL") {
      pgFilters.push(`severity = $${pgIdx++}`);
      pgParams.push(String(severity));
    }
    if (status !== "ALL") {
      pgFilters.push(`status = $${pgIdx++}`);
      pgParams.push(String(status));
    } else if (String(includeClosed).toLowerCase() !== "true") {
      pgFilters.push(`status NOT IN ('CERRADO','FALSO_POSITIVO')`);
    }

    // Búsqueda libre (incluye número de caso: INC-000123 / #123 / 123)
    if (search) {
      const sidx = pgIdx++;
      const caseNum = parseCaseNumber(search);
      let numClause = "";
      if (caseNum != null) {
        const nidx = pgIdx++;
        numClause = ` OR case_number = $${nidx}`;
      }
      pgFilters.push(`(
        id ILIKE $${sidx} OR
        ioc_value ILIKE $${sidx} OR
        ioc_type ILIKE $${sidx} OR
        source_log ILIKE $${sidx} OR
        mitre_tactic_name ILIKE $${sidx}${numClause}
      )`);
      pgParams.push(`%${search}%`);
      if (caseNum != null) pgParams.push(caseNum);
    }

    // C5 — Rango de score (inclusivo) y ventana de created_at. Ambos son
    // opcionales e independientes; min sin max (o vice-versa) es válido.
    if (scoreMinNum != null) {
      pgFilters.push(`score >= $${pgIdx++}`);
      pgParams.push(scoreMinNum);
    }
    if (scoreMaxNum != null) {
      pgFilters.push(`score <= $${pgIdx++}`);
      pgParams.push(scoreMaxNum);
    }
    if (createdAtMinIso) {
      pgFilters.push(`created_at >= $${pgIdx++}::timestamptz`);
      pgParams.push(createdAtMinIso);
    }
    if (createdAtMaxIso) {
      pgFilters.push(`created_at <= $${pgIdx++}::timestamptz`);
      pgParams.push(createdAtMaxIso);
    }

    // Clase eCSIRT/MISP (mig 088, columna materializada). Los casos pre-backfill
    // con incident_class NULL no matchean ninguna clase concreta — esperado: el
    // filtro es opt-in y la lectura sigue mostrando la clase derivada en vivo.
    if (incidentClassFilter) {
      pgFilters.push(`incident_class = $${pgIdx++}`);
      pgParams.push(incidentClassFilter);
    }

    // Filtro por assignedTo/assignedRole ya resuelto arriba a una IN list de
    // case_ids (filters.push(`ic.case_id IN (${inList})`)). Reconvertir a PG.
    const iceIn = filters.find((f) => /^ic\.case_id IN/.test(f));
    if (iceIn) {
      const ids = iceIn.match(/'([^']+)'/g)?.map((s) => s.slice(1, -1)) ?? [];
      if (ids.length > 0) {
        pgFilters.push(`id = ANY($${pgIdx++}::varchar[])`);
        pgParams.push(ids);
      } else {
        return res.json({ cases: [], total: 0, page: pg, pageSize: ps });
      }
    }

    // ORDER BY — traducimos las opciones de Trino a columnas PG
    const dir = String(sortDir).toUpperCase() === "DESC" ? "DESC" : "ASC";
    const SEV_CASE_PG = `CASE severity
        WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4 WHEN 'NEGLIGIBLE' THEN 5 ELSE 6 END ${dir}`;
    let orderBy;
    switch (String(sort).toLowerCase()) {
      case "id":   case "caso":      orderBy = `id ${dir}`; break;
      case "ioc":  case "source":    orderBy = `ioc_value ${dir}, source_log ${dir}`; break;
      case "severity":               orderBy = SEV_CASE_PG; break;
      case "status":                 orderBy = `status ${dir}`; break;
      case "score":                  orderBy = `score ${dir} NULLS LAST`; break;
      case "detected": case "detectado":
      case "creado":   case "created": orderBy = `created_at ${dir} NULLS LAST`; break;
      case "sla":                    orderBy = `${SEV_CASE_PG}, created_at ASC NULLS LAST`; break;
      // "prioridad" (default de la cola SOC): abiertos antes que cerrados, dentro
      // de eso NO adoptados primero, y dentro de eso los más nuevos primero.
      // Composición fija (ignora dir) para que la cola sea estable y paginable.
      case "prioridad":
      default:
        orderBy = `(status IN ('CERRADO','FALSO_POSITIVO')) ASC, `
                + `(adopted_at IS NULL) DESC, created_at DESC NULLS LAST`;
    }

    const whereSql = pgFilters.length ? `WHERE ${pgFilters.join(" AND ")}` : "";

    const sqlCount = `SELECT COUNT(*)::int AS cnt FROM incident_cases_pg ${whereSql}`;

    // Trino-shape aliases para que mapCaseRow consuma estas filas sin cambios.
    // score_breakdown se rellena desde enrichment_data (PG) — antes iba '{}' y
    // CaseDetailSheet mostraba MITRE/Evidencia/Wazuh/MISP/Contexto en 0/X.
    const sqlCases = `
      SELECT
        id                AS case_id,
        ioc_value, ioc_type, source_log,
        severity          AS severity_text,
        score             AS severity_score,
        NULL::text        AS confidence_level,
        status,
        NULL::text        AS source_category,
        mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
        operator_id       AS assigned_to,
        auto_closed_reason AS closure_reason,
        root_cause        AS notes,
        -- Re-construye score_breakdown JSON desde enrichment_data para que
        -- el front pinte las 5 barras del Score breakdown.
        COALESCE(
          jsonb_build_object(
            'score_mitre',    COALESCE((enrichment_data->>'score_mitre')::int,    0),
            'score_evidence', COALESCE((enrichment_data->>'score_evidence')::int, 0),
            'score_wazuh',    COALESCE((enrichment_data->>'score_wazuh')::int,    0),
            'score_misp',     COALESCE((enrichment_data->>'score_misp')::int,     0),
            'score_context',  COALESCE((enrichment_data->>'score_context')::int,  0)
          )::text,
          '{}'
        )                 AS score_breakdown,
        created_at        AS first_seen,
        last_seen,
        stage_entered_at,
        occurrence_count,
        adopted_at,
        escalation_level, escalated_to, escalated_at, escalation_reason,
        recommended_action,
        -- Conteo de assets asociados al caso (case_assets.case_id FK). Alimenta
        -- el badge "N hosts" en la lista — permite al operador ver el blast
        -- radius sin entrar al caso (evita cierre FP apresurado que ignora
        -- múltiples endpoints comprometidos). El subquery usa el índice FK
        -- implícito sobre case_assets(case_id); coste ~0.1ms por fila × 25
        -- filas típicas = ~2.5ms total, aceptable para el caché de 60s.
        (SELECT COUNT(*)::int FROM case_assets WHERE case_id = incident_cases_pg.id) AS assets_count,
        '{}'::text        AS raw_context
      FROM incident_cases_pg
      ${whereSql}
      ORDER BY ${orderBy}
      OFFSET $${pgIdx++} LIMIT $${pgIdx++}`;

    const paramsCases = pgParams.concat([skip, ps]);

    try {
      const [countRows, caseRows] = await Promise.all([
        pgQuery(sqlCount, pgParams),
        pgQuery(sqlCases, paramsCases),
      ]);

      const total   = Number(countRows[0]?.cnt ?? 0);
      const caseIds = caseRows.map((r) => String(r.case_id));
      const pgMap   = await pgBatchLookup(caseIds);

      const cases = caseRows.map((r) => mapCaseRow(r, pgMap.get(String(r.case_id)) ?? null));
      res.json({ cases, total, page: pg, pageSize: ps });
    } catch (err) {
      res.status(500).json({ error: err.message ?? "Error consultando PostgreSQL" });
    }
  });

  // ── Cache en memoria del flow completo (per-days) ───────────────────────────
  // Evita recomputar el merge (~5 s) en cada cambio de página/filtro.
  // TTL 60 s: lo suficiente para que pagination rápida sea instantánea y lo
  // suficientemente corto para que cambios recientes se reflejen al refrescar.
  /** @type {Map<string, { expiresAt: number; rows: any[]; pending?: Promise<any[]> }>} */
  const _flowCache = new Map();
  const FLOW_CACHE_TTL_MS = 60_000;

  function _flowCacheKey(days, maxCls) { return `${days}:${maxCls}`; }

  async function _getFlowRows(days, maxCls) {
    const key = _flowCacheKey(days, maxCls);
    const cached = _flowCache.get(key);
    if (cached) {
      if (cached.expiresAt > Date.now()) {
        if (cached.pending) return cached.pending;
        return cached.rows;
      }
      _flowCache.delete(key);
    }
    const pending = _buildFlowRows(days, maxCls).then((rows) => {
      _flowCache.set(key, { expiresAt: Date.now() + FLOW_CACHE_TTL_MS, rows });
      return rows;
    }).catch((err) => {
      _flowCache.delete(key);
      throw err;
    });
    _flowCache.set(key, { expiresAt: Date.now() + FLOW_CACHE_TTL_MS, rows: [], pending });
    return pending;
  }

  async function _buildFlowRows(d, maxCls) {
    // Delegamos al módulo canónico (services/dedupKey.mjs) — antes este
    // cálculo usaba `source_log` directo mientras que el DAG Airflow y
    // forcedAckController usaban `source_category`. Eso producía hashes
    // distintos para el mismo caso y rompía la dedup silenciosamente.
    const dedupKey = (iocValue, severity, mitreTacticId, sourceLog, iocType) =>
      canonDedupKey({ iocValue, iocType, severity, mitreTacticId, sourceLog });

    const [pgCases, trinoCls, pgDedup] = await Promise.all([
      pgQuery(
        `SELECT id, ioc_value, ioc_type,
                COALESCE(created_at, last_seen) AS ts,
                source_log, severity, score, status, operator_id,
                mitre_tactic_id, mitre_tactic_name
           FROM incident_cases_pg
          WHERE anchor_dt >= current_date - INTERVAL '${d} days'`,
        [],
      ),
      runQuery(`
        SELECT
          ic.incident_key                                           AS ioc_id,
          ic.ioc_value, ic.ioc_type,
          CAST(COALESCE(ic.classified_at,
               CAST(ic.dt AS TIMESTAMP(6) WITH TIME ZONE)) AS varchar) AS timestamp_evento,
          ic.source_log,
          CAST(COALESCE(ic.score, 0) AS INTEGER)                    AS score,
          UPPER(COALESCE(ic.severity, ''))                          AS severidad,
          ic.mitre_tactic_id, ic.mitre_tactic_name,
          ic.detection_type, ic.confidence_level,
          ic.status                                                 AS case_status,
          ic.adopted_by                                             AS assigned_to
        FROM minio_iceberg.hunting.incident_classifications ic
        WHERE ic.dt >= current_date - INTERVAL '${d}' DAY
          AND ic.dt IS NOT NULL
        LIMIT ${maxCls}
      `, SESSION),
      pgQuery(
        `SELECT id, ioc_value, severity, source_log, status,
                mitre_tactic_id, last_seen
           FROM incident_cases_pg
          WHERE status IN ('NUEVO','EN_ANALISIS','CONFIRMADO','MONITOREADO','ESCALADO')
            AND last_seen >= NOW() - INTERVAL '15 days'`,
        [],
      ),
    ]);

    const dedupMap = new Map();
    for (const c of pgDedup) {
      const k = dedupKey(c.ioc_value, c.severity, c.mitre_tactic_id, c.source_log, c.ioc_type);
      const prev = dedupMap.get(k);
      const ts = new Date(c.last_seen ?? 0).getTime();
      if (!prev || ts > prev.ts) {
        dedupMap.set(k, {
          ts,
          incident_case_id:  c.id,
          incident_status:   c.status,
          incident_severity: c.severity,
        });
      }
    }

    const merged = [];
    const seenIocIds = new Set();
    for (const c of pgCases) {
      const k = dedupKey(c.ioc_value, c.severity, c.mitre_tactic_id, c.source_log, c.ioc_type);
      seenIocIds.add(c.id);
      merged.push({
        ioc_id: c.id, ioc_value: c.ioc_value, ioc_type: c.ioc_type,
        timestamp_evento: c.ts instanceof Date ? c.ts.toISOString() : String(c.ts ?? ""),
        source_log: c.source_log, dedup_key: k,
        score: Number(c.score ?? 0), severidad: String(c.severity ?? "").toUpperCase(),
        mitre_tactic_id: c.mitre_tactic_id, mitre_tactic_name: c.mitre_tactic_name,
        detection_type: null, confidence_level: null,
        _es_caso_abierto: true, _case_status: c.status, _assigned_to: c.operator_id,
        _self_case_id: c.id,
      });
    }
    for (const t of trinoCls) {
      if (seenIocIds.has(t.ioc_id)) continue;
      const sev = String(t.severidad ?? "").toUpperCase();
      const k = dedupKey(t.ioc_value, sev, t.mitre_tactic_id, t.source_log, t.ioc_type);
      merged.push({
        ioc_id: t.ioc_id, ioc_value: t.ioc_value, ioc_type: t.ioc_type,
        timestamp_evento: t.timestamp_evento, source_log: t.source_log, dedup_key: k,
        score: Number(t.score ?? 0), severidad: sev,
        mitre_tactic_id: t.mitre_tactic_id, mitre_tactic_name: t.mitre_tactic_name,
        detection_type: t.detection_type, confidence_level: t.confidence_level,
        _es_caso_abierto: false, _case_status: t.case_status, _assigned_to: t.assigned_to,
        _self_case_id: null,
      });
    }

    const SEV_ORDER = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
    const result = merged.map((b) => {
      const dup = dedupMap.get(b.dedup_key) ?? null;
      const cumpleScore     = b.score != null && b.score >= 30;
      const cumpleSeveridad = ["MEDIUM", "HIGH", "CRITICAL"].includes(b.severidad);
      const existeDuplicado = b._es_caso_abierto || Boolean(dup);

      let criterio;
      if (b._es_caso_abierto) {
        criterio = `Caso activo — estado: ${b._case_status || "NUEVO"}` +
                   (b._assigned_to ? ` · adoptado por: ${b._assigned_to}` : " · sin adoptar");
      } else if (b.score == null || b.severidad === "") {
        criterio = "Datos insuficientes (sin score o severidad)";
      } else if (b.score < 30) {
        criterio = `NO cumple score mínimo (${b.score} < 30)`;
      } else if (!cumpleSeveridad) {
        criterio = `NO cumple severidad requerida (es ${b.severidad})`;
      } else if (dup) {
        criterio = `Score y severidad OK — caso duplicado activo: ${dup.incident_case_id || "ventana 15 días"}`;
      } else {
        criterio = "TODOS los criterios OK → Caso debería abrirse";
      }

      let flujo;
      if (b._es_caso_abierto)                                                           flujo = "ABIERTO";
      else if (b.score == null || b.severidad === "")                                   flujo = "NO_ABIERTO";
      else if (cumpleScore && cumpleSeveridad && !dup)                                  flujo = "ABIERTO";
      else if (cumpleScore && cumpleSeveridad && dup)                                   flujo = "DEDUPLICADO";
      else                                                                              flujo = "NO_ABIERTO";

      return {
        ioc_id: b.ioc_id, ioc_value: b.ioc_value, ioc_type: b.ioc_type,
        timestamp_evento: b.timestamp_evento, source_log: b.source_log, dedup_key: b.dedup_key,
        score: b.score, severidad: b.severidad,
        mitre_tactic_id: b.mitre_tactic_id, mitre_tactic_name: b.mitre_tactic_name,
        detection_type: b.detection_type, confidence_level: b.confidence_level,
        es_caso_abierto: b._es_caso_abierto, self_case_id: b._self_case_id,
        cumple_score: cumpleScore, cumple_severidad: cumpleSeveridad,
        existe_caso_duplicado: existeDuplicado,
        criterio_fallido: criterio, flujo_estado: flujo,
        incident_case_id:  b._self_case_id ?? (dup?.incident_case_id ?? null),
        incident_status:   b._case_status  ?? (dup?.incident_status  ?? null),
        incident_severity: dup?.incident_severity ?? null,
      };
    });

    result.sort((a, b) => {
      if (a.es_caso_abierto !== b.es_caso_abierto) return a.es_caso_abierto ? -1 : 1;
      const sa = SEV_ORDER[a.severidad] ?? 5;
      const sb = SEV_ORDER[b.severidad] ?? 5;
      if (sa !== sb) return sa - sb;
      return String(b.timestamp_evento).localeCompare(String(a.timestamp_evento));
    });

    return result;
  }

  // ── GET /api/incidents/analysis-flow ────────────────────────────────────────
  // Flujo explicable de apertura de casos con paginación + filtros server-side.
  // Cache en memoria por `days` (TTL 60 s) hace que pagination/filter sea ~0 ms.
  //
  // Query params:
  //   days        1-90 (default 30)
  //   limit       500-50000 (cap para classifications scan, default 5000)
  //   page        >=1 (default 1)
  //   pageSize    10-500 (default 25)
  //   search      texto libre (case-insensitive, coincidencia parcial)
  //   flowState   ALL | ABIERTO | NO_ABIERTO | DEDUPLICADO
  //   reason      ALL | score | severidad | dedup | ok | insuficiente
  //
  // Response:
  //   { rows, total, page, pageSize, stats: { total, abiertos, dedup, descartados } }
  router.get("/analysis-flow", async (req, res) => {
    const d        = Math.min(90,  Math.max(1,  Number(req.query.days     ?? 30)));
    const maxCls   = Math.min(50000, Math.max(500, Number(req.query.limit    ?? 5000)));
    const page     = Math.max(1, Number(req.query.page ?? 1));
    const pageSize = Math.min(500, Math.max(10, Number(req.query.pageSize ?? 25)));
    const search   = String(req.query.search    ?? "").trim().toLowerCase();
    const flowSt   = String(req.query.flowState ?? "ALL").toUpperCase();
    const reason   = String(req.query.reason    ?? "ALL").toLowerCase();

    try {
      const all = await _getFlowRows(d, maxCls);

      // Stats sobre el conjunto completo (no filtrado)
      const stats = { total: all.length, abiertos: 0, dedup: 0, descartados: 0 };
      for (const r of all) {
        if (r.flujo_estado === "ABIERTO")           stats.abiertos++;
        else if (r.flujo_estado === "DEDUPLICADO")  stats.dedup++;
        else                                         stats.descartados++;
      }

      // Filtros
      const filtered = all.filter((r) => {
        if (flowSt !== "ALL" && r.flujo_estado !== flowSt) return false;
        const crit = String(r.criterio_fallido ?? "").toLowerCase();
        if (reason === "score"        && !crit.includes("score"))               return false;
        if (reason === "severidad"    && !crit.includes("severidad"))           return false;
        if (reason === "dedup"        && !crit.includes("duplicado"))           return false;
        if (reason === "ok"           && !crit.includes("todos los criterios")) return false;
        if (reason === "insuficiente" && !crit.includes("insuficientes"))       return false;
        if (!search) return true;
        return (
          String(r.ioc_id).toLowerCase().includes(search)           ||
          String(r.ioc_value).toLowerCase().includes(search)        ||
          String(r.dedup_key).toLowerCase().includes(search)        ||
          String(r.criterio_fallido).toLowerCase().includes(search) ||
          String(r.flujo_estado).toLowerCase().includes(search)     ||
          String(r.source_log).toLowerCase().includes(search)
        );
      });

      const total = filtered.length;
      const skip  = (page - 1) * pageSize;
      const rows  = filtered.slice(skip, skip + pageSize);

      res.json({ rows, total, page, pageSize, stats });
    } catch (err) {
      res.status(500).json({ error: err.message ?? "Error consultando flujo de incidentes" });
    }
  });


  // ── POST /api/incidents/open-from-flow ──────────────────────────────────────
  // Apertura manual de caso desde el flujo de análisis.
  // Solo permite abrir si el IOC cumple score >= 30, severity OK, y no hay caso
  // duplicado activo en la ventana de 15 días (misma lógica que el DAG).
  router.post("/open-from-flow", async (req, res) => {
    const {
      iocId,            // incident_key de incident_classifications
      iocValue,         // valor del IOC (IP, dominio, hash…)
      iocType,          // ip | domain | hash | url
      sourceLog,        // fuente del evento
      score,            // score numérico
      severidad,        // MEDIUM | HIGH | CRITICAL (analysis-flow field name)
      severity,         // MEDIUM | HIGH | CRITICAL (scoring-v2 / top-incidents field name)
      dedupKey,         // clave de deduplicación pre-calculada por el frontend
      mitreTacticId,
      mitreTacticName,
      mitreTacticIds,   // array de tactic IDs para kill-chain bonus (opcional)
      sensorKey,        // hostname/IP del activo afectado (para asset criticality)
      firstSeenTs,      // timestamp del primer evento (para temporal freshness)
      scoreBreakdown,   // { score_mitre, score_evidence, score_wazuh, score_misp, score_context } — frontend lo trae del live scoring
      rawContext,       // JSON serializado del evento origen — usado abajo para extraer detected_at + src/dst ip/port/proto
      operatorCi,
    } = req.body ?? {};

    // ── Validaciones ──────────────────────────────────────────────────────────
    if (!iocValue || !iocValue.trim())
      return res.status(400).json({ error: "iocValue requerido" });
    if (!operatorCi || String(operatorCi).trim().length < 5)
      return res.status(400).json({ error: "CI inválido (mínimo 5 caracteres)" });

    let scoreParsed = Number(score);
    // Allow manual force-open regardless of score (operator override)
    const forceOpen = req.body?.force === true;

    // A2: reponderar el score con los pesos del perfil de scoring activo, igual
    // que el DAG reponderá los candidatos del sync (cierra la brecha donde el
    // perfil publicado no afectaba la apertura). Sin perfil / pesos 1.0 → sin
    // cambio. Mantiene coherente la decisión entre el camino manual y el bulk.
    const activeWeights = await loadActiveProfileWeights();
    const scoreRaw = scoreParsed;
    scoreParsed = reweightScoreForActiveProfile(scoreParsed, scoreBreakdown, activeWeights);
    const wasReweighted = scoreParsed !== scoreRaw;
    if (wasReweighted) {
      logger.info("open-from-flow/reweight", {
        iocValue: String(iocValue ?? "").trim(), raw: scoreRaw,
        weighted: scoreParsed, weights: activeWeights,
      });
    }

    // ── P3/P5: piso UTM FortiGate + boost por activo interno (paridad DAG) ────
    // El sync aplica estos ajustes ANTES de decidir apertura. Acá los espejamos
    // para que un IPS/AV crítico de FortiGate (RCE, web shell, botnet) abra
    // CRITICAL a mano igual que en bulk, en vez de caer a LOW y auto-cerrarse.
    // Los callers no envían source_category/source_severity, así que para
    // FortiGate los leemos de enriched_ioc (misma tabla que alimenta la vista
    // del DAG). El boost por activo aplica a cualquier fuente vía sensorKey.
    let utmCat = null, utmSev = null, utmAsset = null;
    if (String(sourceLog ?? "").toLowerCase() === "fortigate") {
      try {
        const er = await runQuery(
          `SELECT source_category, source_severity, affected_asset_ip
             FROM minio_iceberg.hunting.enriched_ioc
            WHERE source_log = 'fortigate'
              AND ioc_value = ${sq(String(iocValue).trim())}
            ORDER BY dt DESC
            LIMIT 1`,
          SESSION,
        );
        if (er.length) {
          utmCat   = er[0].source_category   ?? null;
          utmSev   = er[0].source_severity   ?? null;
          utmAsset = er[0].affected_asset_ip ?? null;
        }
      } catch (lookupErr) {
        logger.warn({ err: lookupErr.message }, "[open-from-flow] enriched_ioc UTM lookup failed (non-fatal)");
      }
    }
    const assetIp = utmAsset || sensorKey || null;
    const scoreBeforeFloor = scoreParsed;
    scoreParsed = utmThreatFloor(
      { sourceLog, sourceCategory: utmCat, sourceSeverity: utmSev },
      assetTargetBoost(assetIp, scoreParsed),
    );
    const wasFloored = scoreParsed !== scoreBeforeFloor;
    if (wasFloored) {
      logger.info("open-from-flow/utm-floor", {
        iocValue: String(iocValue ?? "").trim(), before: scoreBeforeFloor,
        after: scoreParsed, source_category: utmCat, source_severity: utmSev,
        asset: assetIp,
      });
    }

    // ── RFC1918 detection — umbrales relajados para IPs internas ──────────────
    // Las IPs RFC1918 no pueden ser enriquecidas externamente (VT, AbuseIPDB → 0 pts).
    // Los perfiles de apertura estándar están calibrados para IPs públicas (score >55).
    // Para IPs internas, sólo contribuyen score_wazuh (0-25) + score_mitre (0-40)
    // → max ≈75. Usamos umbral mínimo reducido y saltamos el gate de perfiles externos.
    const iocIsInternal = isRfc1918(String(iocValue ?? "").trim());
    const HARD_MIN = iocIsInternal ? 5 : 10;

    if (!forceOpen && (isNaN(scoreParsed) || scoreParsed < HARD_MIN)) {
      return res.status(400).json({
        error: `Score demasiado bajo para abrir caso (${scoreParsed} < ${HARD_MIN})`,
        ...(iocIsInternal
          ? { hint: "IP interna RFC1918 — umbral reducido a 5 pts. Sin enriquecimiento externo posible." }
          : {}),
      });
    }

    let sev = String(severidad ?? severity ?? "LOW").toUpperCase();
    const VALID_SEVS = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]);
    if (!VALID_SEVS.has(sev))
      return res.status(400).json({ error: `Severidad '${sev}' inválida` });
    // A2: si el score fue reponderado por el perfil activo, derivar la severidad
    // del score ponderado (canónico — espeja _severity_from_score del DAG).
    // P3/P5: idem si el piso UTM / boost por activo modificó el score (un IPS
    // crítico floored a 90 debe persistir como CRITICAL, no como la sev del body).
    if (wasReweighted || wasFloored) sev = severityFromScore(scoreParsed);

    // ── Validación contra perfiles de apertura activos ────────────────────────
    // Si force=true el operador asume responsabilidad y saltea los perfiles.
    if (!forceOpen) {
      if (iocIsInternal) {
        // IPs internas: no aplicar perfiles externos. Criterios propios:
        //   CRITICAL / HIGH  → score >= 5  (hard min ya pasó)
        //   MEDIUM           → score >= 10
        //   LOW / NEGLIGIBLE → score >= 20 (amenazas internas LOW requieren más evidencia)
        const rfc1918Min = sev === "LOW" || sev === "NEGLIGIBLE" ? 20
                         : sev === "MEDIUM"                      ? 10
                         :                                          5;
        if (scoreParsed < rfc1918Min) {
          return res.status(403).json({
            error:       `IP interna RFC1918 — ${sev} requiere score ≥ ${rfc1918Min}`,
            hint:        "Los perfiles de apertura externos no aplican a IPs RFC1918. Usa force=true para override.",
            isInternal:  true,
            rfc1918:     true,
            threshold:   rfc1918Min,
          });
        }
      } else {
        const openingProfiles = await loadOpeningProfiles();
        const gate = checkOpeningProfiles({ severity: sev, score: scoreParsed }, openingProfiles);
        if (!gate.ok) {
          return res.status(403).json({
            error:    gate.reason,
            hint:     "Usa force=true para forzar la apertura como override de operador, o ajusta los perfiles en /api/scoring-profiles/opening.",
            profiles: openingProfiles.filter((p) => p.enabled).map((p) => ({ id: p.id, severities: p.severities, minScore: p.minScore })),
          });
        }
      }
    }

    const ci  = String(operatorCi).trim();
    const now = new Date().toISOString();

    // Recalcular dedup_key server-side con la fórmula canónica. El front puede
    // haber enviado un hash con la fórmula vieja (pre services/dedupKey.mjs);
    // confiar en el canónico garantiza que supresiones y dedup funcionen igual
    // acá y en el DAG. El hash recibido del body se conserva como shadow para
    // auditar mismatches hasta que el front adopte la nueva fórmula.
    const dedupKeyCanon = canonDedupKey({
      iocValue,
      iocType,
      severity:       sev,
      mitreTacticId,
      sourceLog,
    });
    if (dedupKey && dedupKey !== dedupKeyCanon) {
      logger.info("open-from-flow/dedupkey_mismatch", {
        fromClient: String(dedupKey).slice(0, 16),
        canonical:  dedupKeyCanon.slice(0, 16),
        iocValue, sev,
      });
    }
    // A partir de aquí usamos siempre el canónico. Hacemos shadow al nombre
    // existente para minimizar cambios downstream.
    // eslint-disable-next-line no-param-reassign
    // (la reasignación intencional la hacemos con let shadow abajo)
    const dedupKeyFinal = dedupKeyCanon;

    // ── Toggle de detección (2026-06-08): fuente deshabilitada ⇒ no alimenta casos.
    // Gate espejo del DAG y de autoClassify. Apertura manual: el operador puede
    // forzar con force=true (override auditable). Fail-open para fuentes unknown.
    if (!forceOpen && !isSourceEnabled(sourceLog)) {
      return res.status(403).json({
        error:      `Fuente de detección deshabilitada: ${getSensorLabel(sourceLog)}`,
        source_log: sourceLog,
        reason:     "source_disabled",
        hint:       "La fuente está apagada en Ajustes → Fuentes de detección. Usa force=true para abrir como override de operador.",
      });
    }

    // ── Verificar supresión activa por dedup_key ─────────────────────────────
    // El DAG también la verifica; aquí la aplicamos para que la API sea
    // consistente y no cree casos que el DAG igualmente suprimiría.
    if (dedupKeyFinal && !forceOpen) {
      let suppRows;
      try {
        suppRows = await pgQuery(
          `SELECT reason, suppressed_until, severity
           FROM legacyhunt_soc.case_suppressions
           WHERE dedup_key = $1
             AND suppressed_until > NOW()
           ORDER BY suppressed_until DESC
           LIMIT 1`,
          [dedupKeyFinal],
        );
      } catch (err) { return res.status(500).json({ error: err.message }); }

      // ALTA-3 (audit 2026-06-05): supresión severity-aware. MEDIUM/LOW/NEGLIGIBLE
      // comparten bucket de dedup_key, así que un LOW suprimido bloqueaba un MEDIUM
      // posterior del mismo IOC. Solo bloqueamos si la severidad actual NO supera
      // la suprimida; si escala, dejamos abrir el caso (posible escalación real).
      if (suppRows.length > 0 && sevRank(sev) <= sevRank(suppRows[0].severity)) {
        return res.status(403).json({
          error:           "IOC suprimido — caso cerrado recientemente",
          reason:          suppRows[0].reason,
          suppressedUntil: suppRows[0].suppressed_until,
          hint:            "Usa force=true para forzar la apertura como override de operador.",
        });
      }
    }

    // ── Verificar deduplicación por ioc_value (siempre) ─────────────────────
    // Evita casos duplicados para el mismo IOC activo en los últimos 30 días.
    // Migration 023: lookup en PG (idx_cases_ioc_open) en vez de Iceberg.
    {
      let iocDupRows;
      try {
        iocDupRows = await pgQuery(
          `SELECT id AS case_id, status
           FROM incident_cases_pg
           WHERE ioc_value = $1
             AND status NOT IN ('CERRADO','FALSO_POSITIVO')
             AND updated_at >= now() - INTERVAL '30 days'
           ORDER BY updated_at DESC
           LIMIT 1`,
          [String(iocValue).trim()]
        );
      } catch (err) { return res.status(500).json({ error: err.message }); }

      if (iocDupRows.length > 0) {
        const existingId = String(iocDupRows[0].case_id);
        const ctx = await fetchExistingCaseCtx(existingId);
        return res.status(409).json({
          error:          "Ya existe un caso activo para este IOC",
          existingCaseId: existingId,
          existingStatus: ctx?.status ?? String(iocDupRows[0].status),
          existingSeverity: ctx?.severity ?? null,
          existingScore:    ctx?.score    ?? null,
          existingOperator: ctx?.operatorId ?? null,
          existingOccurrences: ctx?.occurrenceCount ?? null,
          iocValue:       String(iocValue).trim(),
        });
      }
    }

    // ── P1/P3 triage por intel (2026-06-16): no abrir ruido benigno conocido ──
    // Criba keyless barata (GreyNoise RIOT/benign + ThreatFox/URLhaus/OpenPhish/
    // Spamhaus/OTX) corrida SINCRÓNICA en el punto de decisión (P3), SOLO para IP
    // pública no-CRITICAL (GreyNoise no aplica a RFC1918; nunca frenamos un
    // CRITICAL). Si la intel la marca benigna y SIN señal de amenaza, no se abre
    // caso (el escáner/servicio es inofensivo conocido). VT/Shodan NO se tocan
    // acá (P2: las caras quedan para enrich-now). force=true override del operador.
    // Best-effort: una falla de la criba nunca bloquea la apertura.
    if (!forceOpen && !iocIsInternal && sev !== "CRITICAL"
        && /^ip$/i.test(String(iocType ?? "ip"))) {
      try {
        const screen = await screenIocMalice(String(iocValue).trim(), "ip");
        if (screen.benign && !screen.malicious) {
          logger.info("open-from-flow/triage_benign_skip", {
            iocValue: String(iocValue).trim(), reasons: screen.benignReasons,
          });
          return res.status(403).json({
            error:  "No abierto: IOC benigno conocido (GreyNoise/feeds)",
            reason: "triage_benign",
            benign: screen.benignReasons,
            hint:   "Marcado como escáner/servicio benigno conocido. Usa force=true para abrir igual.",
          });
        }
      } catch (e) {
        logger.warn("open-from-flow/triage_failed", { err: e?.message });
      }
    }

    // ── Verificar deduplicación por dedup_key (canónico) ─────────────────────
    // Migration 023: lookup en PG (idx_cases_dedup_key_open) en vez de Iceberg.
    // Casos pre-023 sin dedup_key en PG son inertes para este check (aceptable:
    // el dedup por ioc_value de arriba ya cubre el solapamiento).
    //
    // Ventana 30d (R2 audit 2026-05-13): alineada con dedup por ioc_value.
    // Antes era 15d sin rationale documentado, creando una banda 15-30d donde
    // este check no detectaba duplicados pero la UNIQUE PARCIAL (migration 034)
    // sí los bloqueaba con 23505 → 409 sin explicación operacional. Unificar a
    // 30d hace explícito el contrato "caso activo del mismo dedup_key en 30d
    // no abre uno nuevo". La UNIQUE PARCIAL no tiene filtro temporal, así que
    // este lookup pre-INSERT existe sólo para devolver un 409 limpio con el
    // ID del caso existente (vs el 23505 que requiere fallback handler).
    if (dedupKeyFinal) {
      let dupRows;
      try {
        dupRows = await pgQuery(
          `SELECT id AS case_id, status
           FROM incident_cases_pg
           WHERE dedup_key = $1
             AND status NOT IN ('CERRADO','FALSO_POSITIVO')
             AND updated_at >= now() - INTERVAL '30 days'
           LIMIT 1`,
          [String(dedupKeyFinal).slice(0, 256)]
        );
      } catch (err) { return res.status(500).json({ error: err.message }); }

      if (dupRows.length > 0) {
        const existingId = String(dupRows[0].case_id);
        const ctx = await fetchExistingCaseCtx(existingId);
        return res.status(409).json({
          error:          "Ya existe un caso activo (dedup_key)",
          existingCaseId: existingId,
          existingStatus: ctx?.status ?? String(dupRows[0].status),
          existingSeverity: ctx?.severity ?? null,
          existingScore:    ctx?.score    ?? null,
          existingOperator: ctx?.operatorId ?? null,
          existingOccurrences: ctx?.occurrenceCount ?? null,
          iocValue:       String(iocValue).trim(),
        });
      }
    }

    // ── Crear caso en Iceberg ────────────────────────────────────────────────
    const caseId = randomUUID();
    const SEV_RANK = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NEGLIGIBLE: 5 };

    try {
      await trinoExec(buildCasesInsert({
        case_id:           caseId,
        dedup_key:         dedupKeyFinal,
        ioc_value:         canonNormalizeIoc(iocValue, iocType),
        ioc_type:          String(iocType ?? "ip").toLowerCase(),
        source_log:        String(sourceLog ?? "manual-flow"),
        mitre_tactic_id:   mitreTacticId  ?? null,
        mitre_tactic_name: mitreTacticName ?? null,
        source_category:   "manual_flow",
        severity_text:     sev,
        severity_rank:     SEV_RANK[sev] ?? 3,
        severity_score:    scoreParsed,
        confidence_level:  null,
        status:            "EN_ANALISIS",
        occurrence_count:  1,
        first_seen:        now,
        last_seen:         now,
        anchor_dt:         now.slice(0, 10),
        linked_evidence:   iocId ? String(iocId) : null,
        // R14 audit 2026-05-13: persistir el desglose de 5 dimensiones al INSERT
        // inicial de Iceberg (antes iba NULL, dashboard mostraba 0/X en las
        // barras al consultar histórico). Serializado como string JSON porque
        // buildCasesInsert usa nullOrSq → necesita literal SQL.
        // R5 audit 2026-05-21: si el IOC es RFC1918 y no hay score_evidence
        // (v2 no materializó todavía), aplicar fórmula SQL en Node — ver más
        // abajo en enrichmentSeed.
        score_breakdown: (scoreBreakdown && typeof scoreBreakdown === "object")
          ? (() => {
              const rawEv = Number(scoreBreakdown.score_evidence ?? 0);
              const ev = (iocIsInternal && rawEv === 0)
                ? calcScoreEvidenceRfc1918({ severity: sev })
                : rawEv;
              return JSON.stringify({
                score_mitre:    Number(scoreBreakdown.score_mitre    ?? 0),
                score_evidence: ev,
                score_wazuh:    Number(scoreBreakdown.score_wazuh    ?? 0),
                score_misp:     Number(scoreBreakdown.score_misp     ?? 0),
                score_context:  Number(scoreBreakdown.score_context  ?? 0),
              });
            })()
          : null,
        notes:             `Caso abierto manualmente desde flujo de análisis por ${ci}`,
        assigned_to:       ci,
        closure_reason:    null,
        created_at:        now,
        updated_at:        now,
        adopted_at:        now,
        escalation_level:  null,
        escalated_to:      null,
        escalated_at:      null,
        escalation_reason: null,
        recommended_action: null,
      }), SESSION);
    } catch (err) {
      return res.status(500).json({ error: `Error al crear caso en Iceberg: ${err.message}` });
    }

    // ── Detección de reincidencia (best-effort, no bloquea la respuesta) ────────
    // Busca casos cerrados/FP con el mismo ioc_value en los últimos 90 días.
    // Si existe, registra el vínculo en parent_case_id e is_recurrence=true.
    let parentCaseId = null;
    try {
      const recRows = await pgQuery(
        `SELECT id, severity, score, created_at
         FROM incident_cases_pg
         WHERE ioc_value = $1
           AND status IN ('CERRADO','FALSO_POSITIVO')
           AND created_at >= now() - INTERVAL '90 days'
         ORDER BY created_at DESC
         LIMIT 1`,
        [String(iocValue).trim()]
      );
      if (recRows.length > 0) {
        parentCaseId = recRows[0].id;
      }
    } catch (recErr) {
      logger.warn({ err: recErr.message }, "[incidents][open-from-flow] recurrence check failed (non-fatal)");
    }

    // ── Registrar en PostgreSQL (timeline + operador) ────────────────────────
    try {
      // Extraer contexto de red del rawContext recibido al abrir el caso
      let openCtx = {};
      try { openCtx = JSON.parse(rawContext ?? "{}"); } catch { /* vacío */ }
      const openSrcIp  = openCtx.src_ip  || openCtx.srcip  || (iocType === "ip" ? String(iocValue) : null) || null;
      const openDstIp  = openCtx.dst_ip  || openCtx.dstip  || openCtx.data?.dstip  || null;
      const openDstPort = openCtx.dst_port != null ? Number(openCtx.dst_port) : null;
      const openSrcPort = openCtx.src_port != null ? Number(openCtx.src_port)
                        : openCtx.srcport  != null ? Number(openCtx.srcport)  : null;
      const openProto  = (openCtx.proto || openCtx.protocol || openCtx.ip_protocol
                       || openCtx.data?.proto || null)?.toString().toLowerCase() ?? null;
      const openFwAction = (openCtx.action || openCtx.data?.action || null)?.toString().toUpperCase() ?? null;
      const openHostname = openCtx.agent?.name || openCtx.agent?.hostname
                         || openCtx.hostname   || openCtx.host || null;
      const openUser   = openCtx.user || openCtx.srcuser || openCtx.data?.srcuser || null;

      // R5: detected_at = timestamp del evento origen extraído del rawContext.
      // F4 #1: ampliamos la búsqueda para cubrir todas las formas conocidas por
      // sensor + normalizamos epoch numérico (FortiGate emite microsegundos o
      // segundos según versión). Si queda NULL emitimos un warn estructurado
      // para diagnosticar qué fuentes no instrumentan timestamp.
      const detectedAtIso = (() => {
        // Candidatos por sensor (orden de preferencia):
        //   Wazuh:    data.timestamp (ISO), timestamp (ISO)
        //   Suricata: timestamp (ISO), @timestamp
        //   Fortigate: eventtime (epoch ns/μs/ms/s), itime (epoch)
        //   filterlog/OPNsense: @timestamp, timestamp
        //   PMG: time, ts, @timestamp
        const candidates = [
          openCtx?.data?.timestamp,
          openCtx?.timestamp,
          openCtx?.["@timestamp"],
          openCtx?.eventtime,
          openCtx?.event_ts,
          openCtx?.itime,
          openCtx?.time,
          openCtx?.ts,
        ];
        for (const raw of candidates) {
          if (raw == null || raw === "") continue;
          // String ISO o "yyyy-MM-dd HH:mm:ss" — se acepta tal cual; PG lo parsea.
          if (typeof raw === "string") return raw;
          // Numérico: detectar escala (ns / μs / ms / s) y convertir a ISO.
          if (typeof raw === "number" && Number.isFinite(raw)) {
            let ms = raw;
            if (raw > 1e18) ms = raw / 1e6;          // nanosegundos
            else if (raw > 1e15) ms = raw / 1e3;     // microsegundos
            else if (raw > 1e12) ms = raw;           // milisegundos
            else if (raw > 1e9)  ms = raw * 1000;    // segundos
            else continue;                           // valor sospechoso, descartar
            try { return new Date(ms).toISOString(); }
            catch { continue; }
          }
        }
        return null;
      })();

      // Log estructurado para diagnosticar la cobertura de detected_at por
      // fuente. Útil para tracking F4: cuántos sensores instrumentan correcto.
      if (detectedAtIso == null) {
        logger.warn({
          msg: "case_detected_at_missing",
          source_log: sourceLog ?? "unknown",
          ioc_type: iocType,
          raw_context_keys: Object.keys(openCtx ?? {}).slice(0, 12),
        });
      }

      // Persistir el desglose del score en enrichment_data para que el panel
      // de gestión de casos muestre las 5 barras (MITRE/Evidencia/Wazuh/MISP/
      // Contexto). Sin esto se quedaba todo en 0/X.
      const sb = (scoreBreakdown && typeof scoreBreakdown === "object") ? scoreBreakdown : {};
      // R5: si el IOC es RFC1918 y el frontend no pudo traer score_evidence
      // (v_incident_score_v2 todavía sin materializar el IOC), aplicamos la
      // misma fórmula que la vista para que el DAG no recalcule un valor
      // distinto al sincronizar. Solo rellena cuando viene 0/null — un valor
      // explícito >0 del live-scoring panel se respeta.
      const rawEvidence = Number(sb.score_evidence ?? 0);
      const finalEvidence = (iocIsInternal && rawEvidence === 0)
        ? calcScoreEvidenceRfc1918({ severity: sev })
        : rawEvidence;
      const enrichmentSeed = {
        _status:        "pending",
        score_mitre:    Number(sb.score_mitre    ?? 0),
        score_evidence: finalEvidence,
        score_wazuh:    Number(sb.score_wazuh    ?? 0),
        score_misp:     Number(sb.score_misp     ?? 0),
        score_context:  Number(sb.score_context  ?? 0),
      };

      try {
        await pgUpsertCase(caseId, {
          severity:        sev,
          status:          "EN_ANALISIS",
          score:           scoreParsed,
          operatorId:      ci,
          adoptedAt:       now,
          detectedAt:      detectedAtIso,
          enrichmentData:  enrichmentSeed,
          sensorKey:       sensorKey ?? null,
          networkZone:     resolveNetworkZone(sourceLog),
          // Origen del evento (clave para que la UI muestre "Sensor de origen")
          iocValue:        String(iocValue).trim(),
          iocType:         String(iocType ?? "ip").toLowerCase(),
          sourceLog:       sourceLog ? String(sourceLog) : "manual-flow",
          mitreTacticId,
          mitreTacticName,
          // Migration 023: persistir dedup_key en PG para acelerar futuros lookups
          dedupKey:        dedupKeyFinal,
          // R4 (migration 055): score calculado en backend Node + scoringBonus.mjs,
          // no por las vistas v2/v3/v4 del lakehouse.
          scoringVersion:  "manual",
          // Contexto de red extraído del evento original
          sourceIp:        openSrcIp,
          destinationIp:   openDstIp,
          destinationPort: openDstPort,
          sourcePort:      openSrcPort,
          protocol:        openProto,
          firewallAction:  openFwAction,
          hostname:        openHostname,
          affectedUser:    openUser,
        });
      } catch (err) {
        // Migration 034: idx_cases_dedup_key_open_unique cierra la race entre
        // dos POST simultáneos al mismo dedup_key (los checks pre-INSERT pueden
        // ambos pasar si llegan en paralelo; el UNIQUE PARCIAL serializa).
        if (err?.code === "23505" && /dedup_key_open_unique/.test(err?.constraint ?? "")) {
          let existingId = null;
          try {
            const [r] = await pgQuery(
              `SELECT id FROM incident_cases_pg
                WHERE dedup_key = $1
                  AND status NOT IN ('CERRADO','FALSO_POSITIVO')
                ORDER BY updated_at DESC LIMIT 1`,
              [dedupKeyFinal],
            );
            existingId = r?.id ?? null;
          } catch { /* lookup secundario no es crítico */ }
          return res.status(409).json({
            error: "Race detectada — otro request abrió un caso para el mismo dedup_key",
            existingCaseId: existingId,
            dedupKey: dedupKeyFinal,
          });
        }
        throw err;
      }

      // Vincular reincidencia si se detectó un caso padre
      if (parentCaseId) {
        pgQuery(
          `UPDATE incident_cases_pg
           SET parent_case_id = $2, is_recurrence = true, updated_at = now()
           WHERE id = $1`,
          [caseId, parentCaseId]
        ).catch((e) => logger.warn("incidents.open_from_flow.parent_link_failed", { caseId, parentCaseId, err: e?.message }));
      }

      // Evento DETECTION inicial (fase NIST correcta)
      await pgQuery(
        `INSERT INTO case_timeline_events
           (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source, metadata)
         VALUES ($1,$2,$3::timestamptz,'DETECTION','DETECTION',$4,$5,$6,'MANUAL',$7)
         ON CONFLICT DO NOTHING`,
        [
          randomUUID(), caseId, now,
          `Detección manual · ${sev}`,
          `IOC ${String(iocValue).trim()} (${iocType}) abierto por ${ci}` +
            (mitreTacticName ? ` · MITRE: ${mitreTacticName}` : ""),
          ci,
          JSON.stringify({ score: scoreParsed, severity: sev,
            mitre_tactic_id: mitreTacticId, source_log: sourceLog }),
        ]
      );

      // ── Bootstrap del playbook (A5 audit 2026-06-05) ─────────────────────────
      // Antes los casos abiertos manualmente sólo recibían tareas vía el job
      // bootstrapMissingTasks (≤5 min). Para un caso que el operador ya está
      // trabajando las generamos de inmediato. bootstrapCaseTasks es idempotente.
      try {
        await bootstrapCaseTasks(
          caseId,
          {
            severity: sev, score: scoreParsed, source_log: sourceLog,
            ioc_value: String(iocValue).trim(), ioc_type: iocType,
            mitre_tactic_id: mitreTacticId ?? null, mitre_tactic_name: mitreTacticName ?? null,
            operator_id: ci ?? null,
          },
          {},
          "open-from-flow",
          pgQuery,
          { randomUUIDFn: randomUUID },
        );
      } catch (e) {
        logger.warn("incidents.open_from_flow.tasks_bootstrap_failed", { caseId, err: e?.message });
      }

      // ── Auto-escalación sugerida por score/táctica ───────────────────────────
      const autoEsc = shouldAutoEscalate(scoreParsed, mitreTacticId);
      if (autoEsc.suggest) {
        pgQuery(
          `UPDATE incident_cases_pg
           SET escalation_suggested=true, escalation_reason_auto=$2, updated_at=now()
           WHERE id=$1`,
          [caseId, autoEsc.reason],
        ).catch((e) => logger.warn("incidents.open_from_flow.auto_escalation_flag_failed", { caseId, reason: autoEsc.reason, err: e?.message }));
      }

      // ── Notificación P1 al Shift Manager para casos CRITICAL ─────────────────
      if (sev === "CRITICAL") {
        setImmediate(async () => {
          try {
            const manager = await getActiveShiftManager();
            if (manager) {
              await createNotification({
                operatorId: manager.id,
                caseId,
                type:     "P1_ESCALATION",
                priority: "CRITICAL",
                title:    `[P1] Caso CRITICAL abierto — ${String(iocValue).trim()}`,
                body:     `Score: ${scoreParsed} | MITRE: ${mitreTacticName ?? "—"} | Op: ${ci}`,
                io:       getIo(),
              });
            }
          } catch { /* best-effort */ }
        });
      }

      // ── Bonos de scoring v2 (async best-effort, no bloquea la respuesta) ────
      // Se calculan después de que el caso está creado en PG para poder loguear.
      // R1 audit 2026-05-21: el `scoreParsed` viene del live-scoring panel del
      // frontend, que lee `v_incident_score_v4`. Esa vista ya aplica:
      //   - kill-chain bonus (+5 si ≥3 fases / +2 si ≥2 fases)
      //   - novelty multiplier diario (×1.10 today / ×1.05 ayer)
      //   - geo-risk multiplier (×1.25/×1.10)
      // Antes Node re-aplicaba los 3 → doble counting. Ahora usamos
      // `applyNodeOnlyBonuses` que solo aplica los bonos PG-backed que v4 NO
      // calcula: fpPenalty, scoreDecay, assetTier.
      setImmediate(async () => {
        try {
          const tacticIds = Array.isArray(mitreTacticIds)
            ? mitreTacticIds
            : (mitreTacticId ? [mitreTacticId] : []);

          const bonusResult = await applyNodeOnlyBonuses(scoreParsed, {
            tacticIds,
            firstSeenTs: firstSeenTs ?? now,
            iocValue:    String(iocValue).trim(),
            dedupKey:    dedupKeyFinal,
            countryCode: null,          // se actualiza tras enrichment (ver abajo)
            sensorKey:   sensorKey ?? null,
            isInternal:  iocIsInternal,
          });

          // Actualizar score ajustado en PG si difiere del base
          if (bonusResult.finalScore !== scoreParsed) {
            await pgQuery(
              `UPDATE incident_cases_pg
                  SET score      = GREATEST(score, $1),
                      updated_at = now()
                WHERE id = $2`,
              [bonusResult.finalScore, caseId],
            ).catch((e) => logger.warn("incidents.open_from_flow.bonus_score_update_failed", { caseId, finalScore: bonusResult.finalScore, err: e?.message }));
          }

          // Persistir log de bonos para trazabilidad
          await persistBonusLog(caseId, bonusResult);
        } catch (e) {
          logger.warn("incidents.open_from_flow.bonus_apply_failed", { caseId, err: e?.message });
        }
      });

      // Enriquecimiento asíncrono no bloqueante: VT + Shodan + AbuseIPDB → playbook
      enrichIoc(String(iocValue).trim(), String(iocType ?? "ip").toLowerCase())
        .then(async (enr) => {
          // Forma canónica consumida por el IntelTab: iocEnrichment/iocSources/
          // iocStatus/iocVerdict (audit intel 2026-06-05). Antes escribía `sources`,
          // clave que la UI no leía → las fuentes detalladas quedaban invisibles.
          const enrData = {
            _status: "done",
            ...(enr?.summary ? {
              iocEnrichment: enr.summary,
              iocSources:    enr.sources,
              iocStatus:     enr.status,
              iocVerdict:    enr.verdict,
              enrichedAt:    enr.enrichedAt,
            } : {}),
          };
          const caseForPb = {
            severity_text: sev, severity_score: scoreParsed,
            mitre_tactic_id: mitreTacticId, mitre_tactic_name: mitreTacticName,
            ioc_value: String(iocValue).trim(), ioc_type: iocType, source_log: sourceLog,
          };
          const rec = generateRecommendedAction(caseForPb, enr?.summary ?? {});

          await pgQuery(
            `UPDATE incident_cases_pg
                SET enrichment_data   = $1::jsonb,
                    recommended_action = $2,
                    updated_at         = now()
              WHERE id = $3`,
            [JSON.stringify(enrData), rec, caseId]
          );

          // Evento ENRICH en timeline
          await pgQuery(
            `INSERT INTO case_timeline_events
               (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source, metadata)
             VALUES ($1,$2,now(),'NOTE','DETECTION',$3,$4,'system','auto',$5)`,
            [
              randomUUID(), caseId,
              "Enrichment automático completado",
              enr?.summary
                ? `VT: ${enr.summary.vtMalicious ?? 0} maliciosos · AbuseIPDB: ${enr.summary.abuseConfidence ?? "N/A"}% · Shodan: ${enr.summary.openPorts?.length ?? 0} puertos`
                : "Sin datos de enrichment disponibles",
              JSON.stringify({ enrichedAt: enr?.enrichedAt, sources: Object.keys(enr?.sources ?? {}) }),
            ]
          );

          // ── Registrar geo-risk bonus con country_code resuelto por VT/Shodan ──
          // Solo se inserta el bono geo-risk (evita duplicar todos los bonos ya
          // persistidos en el bloque setImmediate anterior).
          const resolvedCountry = enr?.sources?.virustotal?.country
                               ?? enr?.sources?.shodan?.country
                               ?? null;
          if (resolvedCountry && !iocIsInternal) {
            calcGeoRiskMultiplier(resolvedCountry)
              .then(async (geoRisk) => {
                if (geoRisk.multiplier !== 1.0) {
                  await pgQuery(
                    `INSERT INTO scoring_bonus_log
                       (case_id, bonus_type, bonus_value, multiplier, detail)
                     VALUES ($1, 'geo_risk', 0, $2, $3::jsonb)
                     ON CONFLICT DO NOTHING`,
                    [caseId, geoRisk.multiplier, JSON.stringify(geoRisk.detail)],
                  );
                }
              })
              .catch((e) => logger.warn("incidents.open_from_flow.geo_risk_bonus_failed", { caseId, country: resolvedCountry, err: e?.message }));
          }

          // Actualizar IOC principal en case_iocs si fue importado
          if (enr?.sources?.virustotal || enr?.sources?.shodan || enr?.sources?.abuseipdb) {
            await pgQuery(
              `UPDATE case_iocs
                  SET vt_malicious    = $1,
                      vt_permalink    = $2,
                      abuse_score     = $3,
                      in_misp         = $4,
                      shodan_summary  = $5,
                      enriched_at     = now()
                WHERE case_id = $6 AND is_primary = true`,
              [
                enr.summary?.vtMalicious ?? null,
                enr.sources?.virustotal?.permalink ?? null,
                enr.summary?.abuseConfidence ?? null,
                enr.summary?.inMisp ?? false,
                enr.sources?.shodan
                  ? JSON.stringify({ ports: enr.sources.shodan.ports?.slice(0, 10), org: enr.sources.shodan.org, country: enr.sources.shodan.country })
                  : null,
                caseId,
              ]
            );
          }
        })
        .catch((e) => {
          logger.warn("incidents.open_from_flow.enrich_failed", { caseId, err: e.message });
          pgQuery(
            `UPDATE incident_cases_pg
                SET enrichment_data = jsonb_set(
                      COALESCE(enrichment_data, '{}'::jsonb),
                      '{_status}', '"failed"'::jsonb
                    ),
                    updated_at = now()
              WHERE id = $1`,
            [caseId],
          ).catch((e) => logger.warn("incidents.open_from_flow.enrich_failed_flag_update_failed", { caseId, err: e?.message }));
        });
    } catch (pgErr) {
      logger.error("incidents.open_from_flow.pg_error", { caseId, err: pgErr.message });
    }

    getIo()?.emit("incident:opened_from_flow", { id: caseId, operatorCi: ci, iocValue });

    res.status(201).json({
      ok:            true,
      caseId,
      status:        "EN_ANALISIS",
      isRecurrence:  parentCaseId !== null,
      parentCaseId:  parentCaseId ?? undefined,
    });
  });

  // ── POST /api/incidents/findings/:id/open-case ──────────────────────────────
  // Sincroniza un hallazgo de Caza Externa (hunt_findings) a Gestión de Casos,
  // mapeando server-side su contexto rico (activo interno, evidencia, veredicto +
  // narrativa LLM) al caso — a diferencia del puente UI previo (OpenCaseModal →
  // open-from-flow) que solo cargaba external_entity/severity/score plano.
  //
  //   1) Idempotente: si el finding ya está enlazado a un caso activo → lo devuelve.
  //   2) Dedup por IOC: si existe un caso activo (30d) para la entidad externa →
  //      ENLAZA el finding a ese caso (no duplica) + siembra el veredicto en timeline.
  //   3) Si no: crea el caso (Iceberg + espejo PG, mismas primitivas que
  //      open-from-flow), siembra timeline con la narrativa LLM, enlaza bidireccional,
  //      bootstrapea tareas y dispara enriquecimiento async (VT/Shodan/AbuseIPDB).
  //
  // No aplica los perfiles de apertura IOC-céntricos (calibrados para el pipeline
  // bulk): un finding ya pasó por el motor de patrones + analista LLM + decisión
  // del manager, así que la apertura es un override con contexto de caza.
  router.post("/findings/:id/open-case", async (req, res) => {
    const findingId = String(req.params.id);
    try {
      const jwtCi = await resolveJwtOperatorCi(req).catch(() => null);
      const ci = String(req.body?.operatorCi || jwtCi || "").trim();
      if (ci.length < 5) return res.status(400).json({ error: "CI inválido (mínimo 5 caracteres)" });

      const r = await openCaseFromHuntFinding(findingId, { operatorCi: ci, getIo });
      switch (r.outcome) {
        case "not_found":      return res.status(404).json({ error: "Finding no encontrado." });
        case "no_ioc":         return res.status(400).json({ error: "El finding no tiene entidad externa para abrir caso." });
        case "already_linked": return res.json({ ok: true, alreadyLinked: true,  caseId: r.caseId, caseNumber: r.caseNumber });
        case "linked_existing":return res.json({ ok: true, linkedExisting: true, caseId: r.caseId, caseNumber: r.caseNumber });
        case "raced":          return res.json({ ok: true, linkedExisting: true, caseId: r.caseId, raced: true });
        case "created":        return res.status(201).json({ ok: true, created: true, caseId: r.caseId, status: r.status, severity: r.severity, score: r.score });
        default:               return res.status(500).json({ error: "Resultado de apertura desconocido." });
      }
    } catch (err) {
      logger.error({ err: err.message, findingId }, "[incidents] hunt finding open-case failed");
      return res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/incidents/:id/timeline ─────────────────────────────────────────
  // Fuente canónica: case_timeline_events (tabla estructurada con fase NIST).
  // ── GET /api/incidents/facets ──────────────────────────────────────────────
  // Conteos por owner, por rol y unassigned para anotar selectores con
  // counts sin múltiples round-trips. NOTE: debe estar antes de /:id para
  // evitar route shadowing — Express matchea por orden.
  router.get("/facets", async (req, res) => {
    const includeClosed = String(req.query.includeClosed ?? "false").toLowerCase() === "true";
    const closedClause  = includeClosed ? "" : `AND status NOT IN ('CERRADO','FALSO_POSITIVO')`;
    try {
      const [byOperator, byRole, unassigned] = await Promise.all([
        pgQuery(`
          SELECT operator_id AS id, COUNT(*)::int AS cnt
          FROM incident_cases_pg
          WHERE operator_id IS NOT NULL ${closedClause}
          GROUP BY operator_id
          ORDER BY cnt DESC
        `),
        pgQuery(`
          SELECT o.role_id AS role, COUNT(*)::int AS cnt
          FROM incident_cases_pg c
          JOIN soc_operators o ON o.id = c.operator_id
          WHERE 1=1 ${closedClause.replace(/status/g, "c.status")}
          GROUP BY o.role_id
          ORDER BY cnt DESC
        `),
        pgQuery(`
          SELECT COUNT(*)::int AS cnt FROM incident_cases_pg
          WHERE operator_id IS NULL ${closedClause}
        `),
      ]);
      res.json({
        byOperator: Object.fromEntries(byOperator.map((r) => [r.id, r.cnt])),
        byRole:     Object.fromEntries(byRole.map((r) => [r.role, r.cnt])),
        unassigned: unassigned[0]?.cnt ?? 0,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Reemplaza la lectura de incident_cases_pg.timeline JSONB (deprecado en 015).
  // Incluye fallback al JSONB legacy para casos anteriores a Abril 2026.
  // NOTE: debe estar antes de /:id para evitar route shadowing.
  router.get("/:id/timeline", async (req, res) => {
    const { id } = req.params;
    try {
      // Fuente 1: case_timeline_events (canónica)
      const events = await pgQuery(
        `SELECT
           id, event_ts AS ts, event_type AS action, phase,
           title, description AS detail, operator_ci AS operator,
           source, metadata
         FROM case_timeline_events
         WHERE case_id = $1
         ORDER BY event_ts ASC`,
        [id]
      );

      // Fuente 2: timeline JSONB legacy (casos anteriores a migration 015)
      // Solo se usa si case_timeline_events está vacío para este caso.
      let legacyTimeline = [];
      if (events.length === 0) {
        const pgRows = await pgQuery(
          `SELECT timeline FROM incident_cases_pg WHERE id = $1`,
          [id]
        );
        if (pgRows.length && Array.isArray(pgRows[0]?.timeline)) {
          legacyTimeline = pgRows[0].timeline.map((e) => ({
            ...e,
            phase:   null,
            source:  "legacy_jsonb",
            metadata: null,
          }));
        }
      }

      const timeline = events.length > 0 ? events : legacyTimeline;
      res.json({
        caseId:   id,
        count:    timeline.length,
        source:   events.length > 0 ? "case_timeline_events" : "legacy_jsonb",
        timeline,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/incidents/kpis ──────────────────────────────────────────────────
  // Fast path: PostgreSQL view v_soc_kpis (sub-ms) — no Trino dependency.
  // Fallback to Trino if PG is unavailable.
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  // Cache mini-struct compartido con /api/cases/kpis (mismo origen: v_soc_kpis).
  // El handler abajo usa un cache propio para no acoplar routers; ambos TTL 30 s.
  const _incidentsKpiCache = { value: null, expiresAt: 0, pending: null };
  const INCIDENTS_KPI_TTL_MS = 30_000;
  async function _computeIncidentsKpisPg() {
    const [pgRows, pgCritUnadopted] = await Promise.all([
      pgQuery(`SELECT * FROM v_soc_kpis LIMIT 1`),
      pgQuery(`SELECT COUNT(*) AS cnt FROM incident_cases_pg
                WHERE severity = 'CRITICAL'
                  AND adopted_at IS NULL
                  AND status NOT IN ('CERRADO','FALSO_POSITIVO')`),
    ]);
    const k = pgRows[0];
    if (!k) return null;
    return {
      openCases:          Number(k.open_cases          ?? 0),
      criticalSlaOk:      Number(k.critical_sla_ok     ?? 0),
      criticalSlaTotal:   Number(k.critical_sla_total  ?? 0),
      criticalAvgAckMin:  k.critical_avg_ack_min != null
        ? Number(k.critical_avg_ack_min) : null,
      resolvedToday:      Number(k.resolved_today      ?? 0),
      monitoring:         Number(k.monitoring          ?? 0),
      autoFp:             Number(k.auto_fp             ?? 0),
      criticalUnadopted:  Number(pgCritUnadopted[0]?.cnt ?? 0),
    };
  }

  router.get("/kpis", async (_req, res) => {
    // Try PostgreSQL first (fast, ACID, no Trino timeout risk) con cache TTL 30s
    try {
      const now = Date.now();
      const c = _incidentsKpiCache;
      // Fresco → instantáneo.
      if (c.value && c.expiresAt > now) return res.json(c.value);

      // Refresh-ahead / stale-while-revalidate (opt 2026-06-06): v_soc_kpis hace
      // un Seq Scan inherente (100% de las filas en la ventana de 90d). Si hay
      // valor viejo lo servimos YA y recalculamos en 2º plano; el scan nunca
      // queda en el camino de la request. Single-flight vía c.pending.
      if (!c.pending) {
        c.pending = _computeIncidentsKpisPg()
          .then((v) => {
            if (v) { c.value = v; c.expiresAt = Date.now() + INCIDENTS_KPI_TTL_MS; }
            c.pending = null;
            return v;
          })
          .catch((e) => {
            c.pending = null;
            if (!c.value) throw e;             // cold start: propagá (→ fallback Trino)
            logger.warn("incidents.kpis.bg_refresh_failed", { err: e?.message ?? String(e) });
            return c.value;
          });
      }
      if (c.value) return res.json(c.value);   // valor viejo → sin esperar
      const val = await c.pending;             // cold start → esperá el primer cálculo
      if (val) return res.json(val);
      // pgRows vacío → fall-through al Trino fallback abajo
    } catch (pgErr) {
      // PG unavailable — fall through to Trino
      logger.warn("incidents.kpis.pg_unavailable_fallback_trino", { err: pgErr.message });
    }

    // Fallback: Trino queries (slower — may timeout on cold Trino)
    const DAYS = 7;
    const sqlOpen = `
      SELECT COUNT(DISTINCT case_id) AS cnt
      FROM ${TCASES}
      WHERE COALESCE(status, 'NUEVO') NOT IN ${OPEN_STATUSES_EXCL}
        AND anchor_dt >= current_date - INTERVAL '90' DAY`;
    const sqlCritical = `
      SELECT
        COUNT(*) AS total,
        COUNT(CASE WHEN adopted_at IS NOT NULL THEN 1 END) AS adopted,
        AVG(CASE WHEN adopted_at IS NOT NULL
              THEN date_diff('second', first_seen, adopted_at) / 60.0 END) AS avg_ack_min
      FROM ${TCASES}
      WHERE severity_text = 'CRITICAL'
        AND anchor_dt >= current_date - INTERVAL '${DAYS}' DAY`;
    const sqlResolved = `
      SELECT COUNT(*) AS cnt FROM ${TCASES}
      WHERE status IN ('CERRADO','CLOSED','RESOLVED','RESUELTO')
        AND anchor_dt >= current_date - INTERVAL '1' DAY`;
    const sqlMonitor = `
      SELECT COUNT(*) AS cnt FROM ${TCASES}
      WHERE status = 'MONITOREADO'
        AND anchor_dt >= current_date - INTERVAL '90' DAY`;
    const sqlFp = `
      SELECT COUNT(*) AS cnt FROM ${TCASES}
      WHERE status IN ('FALSO_POSITIVO','FALSE_POSITIVE')
        AND anchor_dt >= current_date - INTERVAL '${DAYS}' DAY`;
    const sqlCritUnadopted = `
      SELECT COUNT(*) AS cnt FROM ${TCASES}
      WHERE severity_text = 'CRITICAL'
        AND adopted_at IS NULL
        AND COALESCE(status, 'NUEVO') NOT IN ${OPEN_STATUSES_EXCL}
        AND anchor_dt >= current_date - INTERVAL '90' DAY`;

    try {
      const [open, crit, res7d, mon, fp, critUnadopted] = await Promise.all([
        runQuery(sqlOpen, SESSION), runQuery(sqlCritical, SESSION),
        runQuery(sqlResolved, SESSION), runQuery(sqlMonitor, SESSION),
        runQuery(sqlFp, SESSION), runQuery(sqlCritUnadopted, SESSION),
      ]);
      const critRow = crit[0] ?? {};
      res.json({
        openCases:          Number(open[0]?.cnt  ?? 0),
        criticalSlaOk:      Number(critRow.adopted ?? 0),
        criticalSlaTotal:   Number(critRow.total   ?? 0),
        criticalAvgAckMin:  critRow.avg_ack_min != null
          ? Math.round(Number(critRow.avg_ack_min)) : null,
        resolvedToday:      Number(res7d[0]?.cnt ?? 0),
        monitoring:         Number(mon[0]?.cnt   ?? 0),
        autoFp:             Number(fp[0]?.cnt    ?? 0),
        criticalUnadopted:  Number(critUnadopted[0]?.cnt ?? 0),
      });
    } catch (err) {
      res.status(500).json({ error: err.message ?? "Error consultando KPIs" });
    }
  });

  // ── GET /api/incidents/transitions ──────────────────────────────────────────
  // Expone el mapa VALID_TRANSITIONS + caps requeridos por target status para
  // que el frontend tenga una fuente única y no duplique las reglas. Config
  // estática → caché HTTP fuerte vía Cache-Control.
  //
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  router.get("/transitions", (_req, res) => {
    const transitions = {};
    for (const [from, toSet] of Object.entries(VALID_TRANSITIONS)) {
      transitions[from] = [...toSet];
    }
    // Max-age largo pero con stale-while-revalidate para que no haya drift
    // grande si un deploy cambia el mapa. 10 min hot + 1h stale es razonable.
    res.set("Cache-Control", "public, max-age=600, stale-while-revalidate=3600");
    res.json({
      ok: true,
      transitions,
      requiredCaps: TRANSITION_CAP,
    });
  });

  // ── GET /api/incidents/thresholds ────────────────────────────────────────────
  // R15 (audit 2026-05-13, P3): umbrales mutables consumidos por
  // shouldAutoEscalate y la auto-clasificación de severidad. Lee del cache TTL
  // 30s con fallback a defaults. Cualquier rol autenticado puede leerlos
  // (es información operacional, no secreto).
  router.get("/thresholds", async (_req, res) => {
    try {
      const t = await getThresholds();
      res.set("Cache-Control", "private, max-age=30");
      res.json({ ok: true, thresholds: t });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/incidents/thresholds/audit ──────────────────────────────────────
  // Últimos N cambios (default 20) — quien, cuándo, before→after. Manager+
  // para evitar exponer patrones de tuning a analystas curiosos.
  router.get("/thresholds/audit", async (req, res) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (!roles.includes("manager") && !roles.includes("admin")) {
      return res.status(403).json({ ok: false, error: "Requiere rol manager o admin" });
    }
    try {
      const limit = Number(req.query?.limit ?? 20);
      const rows = await getThresholdsAudit(limit);
      res.json({ ok: true, audit: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── PUT /api/incidents/thresholds ────────────────────────────────────────────
  // Actualiza los umbrales mutables. Manager+. El servicio valida orden
  // crítico>alto>medio y rango [1,200]; el CHECK constraint de la tabla es
  // una segunda barrera.
  router.put("/thresholds", async (req, res) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (!roles.includes("manager") && !roles.includes("admin")) {
      return res.status(403).json({ ok: false, error: "Requiere rol manager o admin" });
    }
    const ci = await resolveJwtOperatorCi(req);
    // OCC opcional (P4 A5): si el cliente envía expectedUpdatedAt (del GET
    // previo), el servicio rechaza con 409 si otro manager cambió los
    // thresholds en el ínterin. Compatible hacia atrás: si no se envía, no
    // hay check.
    const expectedUpdatedAt = req.body?.expectedUpdatedAt ?? null;
    try {
      const result = await setThresholds({
        values:     req.body?.thresholds ?? req.body ?? {},
        operatorCi: ci || req.user?.preferred_username || null,
        expectedUpdatedAt,
      });
      res.json(result);
    } catch (err) {
      const code = err.code || "INTERNAL";
      if (code === "CONFLICT") {
        return res.status(409).json({
          ok: false,
          error: err.message,
          code,
          currentUpdatedAt: err.currentUpdatedAt,
          currentUpdatedBy: err.currentUpdatedBy,
        });
      }
      const status = (code === "INVALID_PAYLOAD" || code === "OUT_OF_RANGE" || code === "BAD_ORDER") ? 400 : 500;
      // Bubble up el constraint check de PG con detalle legible
      if (err.code === "23514") {
        return res.status(400).json({ ok: false, error: "Constraint check falló — verifica orden y rangos", detail: err.detail });
      }
      res.status(status).json({ ok: false, error: err.message, code });
    }
  });

  // ── GET /api/incidents/sla ───────────────────────────────────────────────────
  // M5 (audit 2026-05-13): SLA por severidad mutable en runtime. Cualquier
  // rol autenticado puede leerlos (los espeja el frontend para mostrar
  // pulse-bars y countdowns). NOTE: must be defined BEFORE /:id.
  router.get("/sla", async (_req, res) => {
    try {
      const t = await getSla();
      res.set("Cache-Control", "private, max-age=30");
      res.json({ ok: true, sla: t });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/incidents/sla/audit ─────────────────────────────────────────────
  router.get("/sla/audit", async (req, res) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (!roles.includes("manager") && !roles.includes("admin")) {
      return res.status(403).json({ ok: false, error: "Requiere rol manager o admin" });
    }
    try {
      const limit = Number(req.query?.limit ?? 20);
      const rows = await getSlaAudit(limit);
      res.json({ ok: true, audit: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── PUT /api/incidents/sla ───────────────────────────────────────────────────
  // Actualiza los SLAs mutables. Manager+. Orden ascendente estricto y rango
  // [60, 31536000] segundos. El CHECK constraint de la tabla es la segunda
  // barrera.
  router.put("/sla", async (req, res) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (!roles.includes("manager") && !roles.includes("admin")) {
      return res.status(403).json({ ok: false, error: "Requiere rol manager o admin" });
    }
    const ci = await resolveJwtOperatorCi(req);
    const expectedUpdatedAt = req.body?.expectedUpdatedAt ?? null;
    try {
      const result = await setSla({
        values:     req.body?.sla ?? req.body ?? {},
        operatorCi: ci || req.user?.preferred_username || null,
        expectedUpdatedAt,
      });
      res.json(result);
    } catch (err) {
      const code = err.code || "INTERNAL";
      if (code === "CONFLICT") {
        return res.status(409).json({
          ok: false,
          error: err.message,
          code,
          currentUpdatedAt: err.currentUpdatedAt,
          currentUpdatedBy: err.currentUpdatedBy,
        });
      }
      const status = (code === "INVALID_PAYLOAD" || code === "OUT_OF_RANGE" || code === "BAD_ORDER") ? 400 : 500;
      if (err.code === "23514") {
        return res.status(400).json({ ok: false, error: "Constraint check falló — verifica orden y rangos", detail: err.detail });
      }
      res.status(status).json({ ok: false, error: err.message, code });
    }
  });

  // ── GET /api/incidents/me ────────────────────────────────────────────────────
  // R12 (audit 2026-05-13): KPIs operador-globales contra todo el universo.
  // Reemplaza el useMemo myLoad de CaseManagementDashboard que iteraba sólo la
  // página actual (bug donde `Mis activos == Tu carga == En riesgo SLA` por
  // clonado de variable). El CI sale del JWT; sin JWT devuelve ceros.
  //
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  router.get("/me", async (req, res) => {
    const ci = await resolveJwtOperatorCi(req);
    if (!ci) {
      // Sin operador resuelto → todos los counts a 0 (el frontend no muestra
      // nada). Evita filtrar por NULL en pgQuery accidentalmente.
      return res.json({
        ok: true, ci: null,
        mineOpen: 0, mineAtRisk: 0, mineBreached: 0,
        criticalUnadopted: 0, newUnassigned24h: 0,
      });
    }
    try {
      // SLA-at-risk threshold: 70% del SLA por severidad. M5 (2026-05-13):
      // SLA viene del cache (sla_config); pasamos los 5 valores en segundos
      // como params para que el CASE los use en vez de un INTERVAL hardcoded.
      const sla = getCachedSla();
      const rows = await pgQuery(
        `WITH mine AS (
           SELECT severity, created_at, detected_at
             FROM incident_cases_pg
            WHERE operator_id = $1
              AND status NOT IN ('CERRADO','FALSO_POSITIVO')
         ),
         sla AS (
           SELECT severity, created_at,
             (CASE severity
               WHEN 'CRITICAL'   THEN $2::int
               WHEN 'HIGH'       THEN $3::int
               WHEN 'MEDIUM'     THEN $4::int
               WHEN 'LOW'        THEN $5::int
               WHEN 'NEGLIGIBLE' THEN $6::int
             END) * INTERVAL '1 second' AS sla_dur
           FROM mine
         )
         SELECT
           (SELECT COUNT(*) FROM mine)                                          AS mine_open,
           -- P4 (audit 2026-06-04): "En riesgo SLA 778/778" estaba saturado
           -- porque contaba TODO lo que pasó el 70% del SLA — incluido el
           -- backlog ya vencido. Separamos "por vencer" (70%–100%, accionable:
           -- todavía se puede salvar) de "vencido" (>100%, ya incumplido).
           (SELECT COUNT(*) FROM sla
             WHERE COALESCE(created_at, now()) <= now() - (sla_dur * 0.7)
               AND COALESCE(created_at, now()) >  now() - sla_dur)              AS mine_at_risk,
           (SELECT COUNT(*) FROM sla
             WHERE COALESCE(created_at, now()) <= now() - sla_dur)              AS mine_breached,
           (SELECT COUNT(*) FROM incident_cases_pg
             WHERE severity = 'CRITICAL'
               AND operator_id IS NULL
               AND status NOT IN ('CERRADO','FALSO_POSITIVO'))                   AS critical_unadopted,
           (SELECT COUNT(*) FROM incident_cases_pg
             WHERE operator_id IS NULL
               AND status NOT IN ('CERRADO','FALSO_POSITIVO')
               AND created_at >= now() - INTERVAL '24 hours')                    AS new_unassigned_24h`,
        [ci,
         sla.sla_critical_sec, sla.sla_high_sec, sla.sla_medium_sec,
         sla.sla_low_sec, sla.sla_negligible_sec],
      );
      const r = rows[0] ?? {};
      res.set("Cache-Control", "private, max-age=30");
      res.json({
        ok:                true,
        ci,
        mineOpen:          Number(r.mine_open          ?? 0),
        mineAtRisk:        Number(r.mine_at_risk       ?? 0),
        mineBreached:      Number(r.mine_breached      ?? 0),
        criticalUnadopted: Number(r.critical_unadopted ?? 0),
        newUnassigned24h:  Number(r.new_unassigned_24h ?? 0),
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Iceberg merge queue: inspección + DLQ (P4 M1, 2026-05-13) ────────────
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  //
  // Antes los jobs `failed` quedaban olvidados en la tabla y sólo eran
  // visibles vía consulta SQL manual. Estos endpoints exponen la cola al
  // shift manager: ver fallos, reintentar tras resolver causa raíz, o
  // purgar si el payload está corrupto.
  router.get("/merge-queue/stats", async (req, res) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (!roles.includes("manager") && !roles.includes("admin")) {
      return res.status(403).json({ ok: false, error: "Requiere rol manager o admin" });
    }
    try {
      const stats = await getQueueStats({ limit: Number(req.query.limit) || 50 });
      res.json({ ok: true, ...stats });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.post("/merge-queue/:id/retry", async (req, res) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (!roles.includes("manager") && !roles.includes("admin")) {
      return res.status(403).json({ ok: false, error: "Requiere rol manager o admin" });
    }
    try {
      const row = await retryFailedJob(req.params.id);
      res.json({ ok: true, ...row });
    } catch (err) {
      const status = err.code === "NOT_RETRIABLE" ? 404 : 500;
      res.status(status).json({ ok: false, error: err.message, code: err.code });
    }
  });

  router.delete("/merge-queue/:id", async (req, res) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (!roles.includes("manager") && !roles.includes("admin")) {
      return res.status(403).json({ ok: false, error: "Requiere rol manager o admin" });
    }
    try {
      const row = await deleteQueueJob(req.params.id);
      res.json({ ok: true, ...row });
    } catch (err) {
      const status = err.code === "NOT_DELETABLE" ? 404 : 500;
      res.status(status).json({ ok: false, error: err.message, code: err.code });
    }
  });

  // ── GET /api/incidents/suppressions ─────────────────────────────────────────
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  // ?onlyActive=true filtra a las vigentes (default: false → incluye expiradas
  // para auditoría histórica).
  router.get("/suppressions", async (req, res) => {
    const onlyActive = String(req.query.onlyActive ?? "").toLowerCase() === "true";
    try {
      // Para vigentes: usa v_active_suppressions (incluye ioc_value resuelto
      // desde incident_cases_pg + minutos restantes). Para histórico completo:
      // tabla cruda con flag `active` calculado.
      const rows = onlyActive
        ? await pgQuery(
            `SELECT dedup_key, reason, severity, suppressed_until, suppressed_by,
                    original_case_id, ioc_value, ioc_type,
                    mitre_tactic_id, mitre_tactic_name,
                    created_at, updated_at, minutes_remaining, window_days,
                    true AS active
               FROM legacyhunt_soc.v_active_suppressions
              LIMIT 500`,
          )
        : await pgQuery(
            `SELECT s.dedup_key, s.reason, s.severity, s.suppressed_until, s.suppressed_by,
                    s.original_case_id, COALESCE(s.original_ioc, c.ioc_value) AS ioc_value,
                    c.ioc_type, c.mitre_tactic_id, c.mitre_tactic_name,
                    s.created_at, s.updated_at,
                    s.suppressed_until > NOW() AS active
               FROM legacyhunt_soc.case_suppressions s
               LEFT JOIN incident_cases_pg c ON c.id::text = s.original_case_id::text
              ORDER BY s.updated_at DESC
              LIMIT 200`,
          );
      res.json({ ok: true, rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/incidents/suppressions/export.csv ──────────────────────────────
  // Export operativo en CSV de las supresiones vigentes (panel SOC + auditoría).
  // NOTE: must be defined BEFORE /:id (y antes de /:dk) para evitar shadowing.
  router.get("/suppressions/export.csv", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT dedup_key, reason, severity, suppressed_until, suppressed_by,
                original_case_id, ioc_value, ioc_type,
                mitre_tactic_id, mitre_tactic_name,
                created_at, minutes_remaining, window_days
           FROM legacyhunt_soc.v_active_suppressions`,
      );

      const header = [
        "dedup_key","reason","severity","suppressed_until","suppressed_by",
        "original_case_id","ioc_value","ioc_type",
        "mitre_tactic_id","mitre_tactic_name",
        "created_at","minutes_remaining","window_days",
      ];
      const escape = (v) => {
        if (v == null) return "";
        const s = String(v);
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const csv = [
        header.join(","),
        ...rows.map((r) => header.map((k) => escape(r[k])).join(",")),
      ].join("\n");

      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition",
        `attachment; filename="suppressions-active-${stamp}.csv"`);
      res.send(csv);
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/incidents/duplicates/count ────────────────────────────────────
  // R8 (audit 2026-05-13): KPI ligero del badge "duplicados pendientes" en el
  // header del dashboard. PG-only (sin Trino) para que la consulta tarde <50ms
  // y pueda hot-pollearse. Cuenta grupos de ≥2 casos abiertos con el mismo
  // ioc_value — alineado con la lógica del DuplicatePanel (groupBy=ioc_value).
  //
  // Filtros activos:
  //   - status NOT IN (CERRADO, FALSO_POSITIVO)        — sólo abiertos
  //   - ioc_value NOT NULL AND NOT '' AND NOT '0.0.0.0' — descarta basura
  //   - HAVING count(*) >= 2                            — al menos 2 casos
  //
  // NOTE: must be defined BEFORE /:id y antes de /duplicates (más larga).
  router.get("/duplicates/count", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT
           COUNT(*)               AS groups_count,
           COALESCE(SUM(cases), 0) AS total_duplicates
         FROM (
           SELECT ioc_value, COUNT(*) AS cases
             FROM incident_cases_pg
            WHERE ioc_value IS NOT NULL
              AND ioc_value <> ''
              AND ioc_value <> '0.0.0.0'
              AND status NOT IN ('CERRADO','FALSO_POSITIVO')
            GROUP BY ioc_value
           HAVING COUNT(*) >= 2
         ) g`,
      );
      res.set("Cache-Control", "private, max-age=30");
      res.json({
        ok:              true,
        groupsCount:     Number(rows[0]?.groups_count     ?? 0),
        totalDuplicates: Number(rows[0]?.total_duplicates ?? 0),
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/incidents/duplicates ───────────────────────────────────────────
  // Detecta grupos de casos activos con el mismo ioc_value (posibles duplicados).
  // Usa Trino/Iceberg para la búsqueda; agrupa en Node antes de responder.
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  router.get("/duplicates", async (req, res) => {
    // Dos modos de agrupación:
    //   · groupBy=ioc_value (default): muestra el radio de impacto — útil
    //     para "un IP aparece en 5 tacticas distintas".
    //   · groupBy=dedup_key: solo los casos que el sistema considera
    //     duplicados "verdaderos" según la fórmula canónica. Más estricto,
    //     alineado con la política del DAG (ver services/dedupKey.mjs).
    const groupBy = req.query.groupBy === "dedup_key" ? "dedup_key" : "ioc_value";
    // Ventana configurable (P4 M4, 2026-05-13). Antes era fija a 90 días lo
    // que escaneaba toda la tabla cuando el dashboard hacía polling cada
    // 30s × N usuarios. Default 30d (cubre el caso típico de duplicados
    // operacionales) con cap 90d para mantener el uso histórico.
    const daysRaw = Number(req.query.days);
    const days = Number.isFinite(daysRaw)
      ? Math.min(90, Math.max(1, Math.round(daysRaw)))
      : 30;
    // Cota dura sobre la CTE para prevenir full scan si la ventana captura
    // > N casos activos. 5000 cubre el SOC típico; por encima de eso, la
    // visualización en el frontend no es usable de todas formas.
    const ACTIVE_LIMIT = 5000;
    // P3-13 audit 2026-05-26: paginación. Antes había un `LIMIT 300` fijo —
    // por encima de eso se perdían grupos sin feedback al cliente. Ahora
    // page/pageSize controlan offset y la respuesta incluye paginación.
    const pageRaw = Number(req.query.page);
    const pageSizeRaw = Number(req.query.pageSize);
    const page = Number.isFinite(pageRaw) ? Math.max(1, Math.round(pageRaw)) : 1;
    const pageSize = Number.isFinite(pageSizeRaw)
      ? Math.min(500, Math.max(10, Math.round(pageSizeRaw)))
      : 100;
    // PG-first: misma lógica contra incident_cases_pg para evitar planning
    // Iceberg explotado. `dedup_key` no existe en PG → se computa en Node
    // (misma fórmula canónica que el DAG vía services/dedupKey.mjs).
    //
    // Anti-JOIN con `ioc_dedup_blocklist` (migración 033) para filtrar IOCs
    // genéricos (8.8.8.8, loopback, RFC1918, etc.) que hoy inflan la tabla
    // del DuplicatePanel con agrupaciones falsas de >50 casos sin relación
    // real. Dos kinds soportados:
    //   · exact  → ioc_value = pattern
    //   · prefix → ioc_value LIKE pattern || '%'
    const sqlDups = `
      WITH active AS (
        SELECT id AS case_id, ioc_value, ioc_type, source_log,
               severity AS severity_text, score AS severity_score,
               status, operator_id AS assigned_to,
               created_at AS first_seen, last_seen,
               COALESCE(occurrence_count, 1) AS occurrence_count,
               mitre_tactic_id
          FROM incident_cases_pg
         WHERE anchor_dt >= current_date - ($1 || ' days')::interval
           AND status NOT IN ('CERRADO','FALSO_POSITIVO')
           -- Blocklist de IOCs genéricos (migration 033).
           AND NOT EXISTS (
             SELECT 1 FROM ioc_dedup_blocklist b
              WHERE (b.kind = 'exact'  AND incident_cases_pg.ioc_value = b.pattern)
                 OR (b.kind = 'prefix' AND incident_cases_pg.ioc_value LIKE b.pattern || '%')
           )
         ORDER BY last_seen DESC NULLS LAST
         LIMIT $2
      ),
      dup_iocs AS (
        SELECT ioc_value, COUNT(*)::int AS cnt,
               SUM(occurrence_count)::bigint AS total_occ
          FROM active
         GROUP BY ioc_value
        HAVING COUNT(*) > 1
      )
      SELECT a.case_id, a.ioc_value, a.ioc_type, a.source_log,
             a.severity_text, a.severity_score, a.status,
             a.assigned_to, a.first_seen::text AS first_seen,
             a.last_seen::text  AS last_seen,
             a.occurrence_count, a.mitre_tactic_id,
             d.cnt AS group_count, d.total_occ AS total_occurrences
        FROM active a
        JOIN dup_iocs d USING (ioc_value)
       ORDER BY d.cnt DESC,
                CASE a.severity_text
                  WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                  WHEN 'MEDIUM'   THEN 3 ELSE 4 END ASC,
                a.first_seen ASC
       LIMIT 5000`;

    try {
      const rows = await pgQuery(sqlDups, [String(days), ACTIVE_LIMIT]);
      // dedup_key canónico — mismo hash que usan el DAG y forcedAckController.
      // Antes se recalculaba aquí con `source_log` crudo y sin normalizar el
      // IOC → hashes distintos al del DAG para casos MEDIUM/LOW.
      for (const r of rows) {
        r.dedup_key = canonDedupKey({
          iocValue:       r.ioc_value,
          iocType:        r.ioc_type,
          severity:       r.severity_text,
          mitreTacticId:  r.mitre_tactic_id,
          sourceLog:      r.source_log,
        });
      }

      // Agrupar en Node según modo elegido. Cuando groupBy=dedup_key el set
      // puede quedar más pequeño que por ioc_value — filtramos al final los
      // grupos que perdieron el "duplicado" tras el recálculo.
      const groupMap = new Map();
      for (const r of rows) {
        const key = groupBy === "dedup_key"
          ? String(r.dedup_key ?? "")
          : String(r.ioc_value ?? "");
        if (!groupMap.has(key)) {
          groupMap.set(key, {
            ioc_value:          String(r.ioc_value ?? ""),
            ioc_type:           String(r.ioc_type  ?? "ip"),
            dedup_key:          String(r.dedup_key ?? ""),
            group_by:           groupBy,
            group_count:        Number(r.group_count ?? 1),
            total_occurrences:  Number(r.total_occurrences ?? 1),
            is_internal:        isRfc1918(String(r.ioc_value ?? "")),
            cases: [],
          });
        }
        groupMap.get(key).cases.push({
          case_id:          String(r.case_id          ?? ""),
          source_log:       String(r.source_log       ?? ""),
          severity_text:    String(r.severity_text    ?? "MEDIUM"),
          severity_score:   Number(r.severity_score   ?? 0),
          status:           normalizeStatus(r.status),
          assigned_to:      r.assigned_to ?? null,
          first_seen:       r.first_seen  ?? null,
          last_seen:        r.last_seen   ?? null,
          occurrence_count: Number(r.occurrence_count ?? 1),
          dedup_key:        String(r.dedup_key        ?? ""),
        });
      }

      // En modo dedup_key recalculamos group_count por grupo y filtramos los
      // que quedaron con una sola fila (perdieron el "duplicado" al cambiar
      // el eje de agrupación).
      let groups = Array.from(groupMap.values());
      if (groupBy === "dedup_key") {
        for (const g of groups) g.group_count = g.cases.length;
        groups = groups.filter((g) => g.cases.length > 1);
      }
      // Orden estable para que la paginación sea consistente entre llamadas:
      // primero por tamaño del grupo desc, luego por ioc_value para evitar
      // empates indeterministas.
      groups.sort((a, b) =>
        (b.group_count - a.group_count) || a.ioc_value.localeCompare(b.ioc_value));
      const total = groups.length;
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      const start = (page - 1) * pageSize;
      const pageGroups = groups.slice(start, start + pageSize);
      res.json({
        ok: true,
        total_groups: total,
        groups: pageGroups,
        group_by: groupBy,
        pagination: {
          page,
          pageSize,
          totalPages,
          totalItems: total,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message ?? "Error consultando duplicados" });
    }
  });

  // ── POST /api/incidents/merge ────────────────────────────────────────────────
  // Fusiona un grupo de casos duplicados en uno canónico.
  // El caso canónico mantiene la mayor severidad, absorbe los occurrence_counts
  // y recibe una entrada de timeline de merge.
  // Los duplicados se marcan CERRADO con closure_reason = "MERGEADO → {canonicalId}".
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  router.post("/merge", async (req, res) => {
    const { canonicalCaseId, duplicateCaseIds, operatorCi } = req.body ?? {};

    if (!canonicalCaseId?.trim())
      return res.status(400).json({ error: "canonicalCaseId requerido" });
    if (!Array.isArray(duplicateCaseIds) || duplicateCaseIds.length === 0)
      return res.status(400).json({ error: "duplicateCaseIds (array no vacío) requerido" });
    if (!operatorCi || String(operatorCi).trim().length < 5)
      return res.status(400).json({ error: "CI inválido (mínimo 5 caracteres)" });

    const ci  = String(operatorCi).trim();
    const now = new Date().toISOString();

    const allIds = [canonicalCaseId, ...duplicateCaseIds].map(String);

    // Fetch involved cases from PostgreSQL (fuente de verdad operacional, de
    // donde sale la lista de duplicados). Antes se leía de Iceberg incident_cases
    // con filtro anchor_dt≥90d → 404 cuando Iceberg estaba stale (p.ej. tras un
    // outage del sync) o los casos eran del path autoClassify (no mirroreados).
    // Aliaseamos a la forma Iceberg (severity_text/severity_score) que consume el
    // resto del handler. El enqueue Iceberg sigue siendo best-effort.
    let allRows;
    try {
      allRows = await pgQuery(
        `SELECT id AS case_id, ioc_value, ioc_type,
                severity AS severity_text, score AS severity_score,
                status, occurrence_count, anchor_dt,
                mitre_tactic_id, mitre_tactic_name, source_log
           FROM incident_cases_pg
          WHERE id = ANY($1::text[])`,
        [allIds],
      );
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }

    if (allRows.length === 0)
      return res.status(404).json({ error: "No se encontraron los casos indicados" });

    const byId = new Map(allRows.map((r) => [String(r.case_id), r]));
    const canon = byId.get(String(canonicalCaseId));
    if (!canon)
      return res.status(404).json({ error: `Caso canónico ${canonicalCaseId} no encontrado` });

    // Agrupación MANUAL (cross-IOC): el operador agrupa una selección
    // heterogénea (p.ej. una campaña que abarca varios IOCs) en un caso
    // canónico. Salta la validación de mismo-ioc pero exige LEADER/ADMIN +
    // motivo, ya que pierde la garantía "mismo indicador" del merge de
    // duplicados. El merge normal (DuplicatePanel) sigue exigiendo mismo IOC.
    const manual = Boolean(req.body?.manual);
    const reasonText = String(req.body?.reason ?? "").trim();
    if (manual) {
      const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
      const isLeader = roles.includes("manager") || roles.includes("admin");
      if (!isLeader)
        return res.status(403).json({ error: "Sólo LEADER/ADMIN puede agrupar casos de distinto IOC" });
      if (reasonText.length < 10)
        return res.status(400).json({ error: "motivo requerido (mín. 10 caracteres) para agrupación manual" });
    } else {
      // Validar que todos comparten el mismo ioc_value
      const canonIoc = String(canon.ioc_value ?? "");
      const mismatch = duplicateCaseIds.find((id) => {
        const r = byId.get(String(id));
        return !r || String(r.ioc_value ?? "") !== canonIoc;
      });
      if (mismatch)
        return res.status(422).json({
          error: `Caso ${mismatch} tiene ioc_value diferente al canónico (${canonIoc})`,
        });
    }
    const mergeVerb = manual ? "AGRUPADO" : "MERGEADO";

    // Calcular nuevo occurrence_count (suma de todos)
    const totalOcc = allRows.reduce((s, r) => s + Number(r.occurrence_count ?? 1), 0);

    // 1. PG — actualizar canónico + marcar duplicados CERRADO
    try {
      await pgUpsertCase(String(canonicalCaseId), {
        severity:      String(canon.severity_text ?? "MEDIUM").toUpperCase(),
        status:        normalizeStatus(canon.status),
        score:         Number(canon.severity_score ?? 50),
        operatorId:    ci,
        timelineEntry: buildTimelineEntry(
          "MERGE",
          ci,
          `${manual ? "Agrupación manual de" : "Merged"} ${duplicateCaseIds.length} caso(s): ${duplicateCaseIds.join(", ")} · total occ=${totalOcc}`
            + (manual && reasonText ? ` · motivo: ${reasonText}` : ""),
        ),
      });

      for (const dupId of duplicateCaseIds) {
        const dup = byId.get(String(dupId));
        if (!dup) continue;
        await pgUpsertCase(String(dupId), {
          severity:           String(dup.severity_text ?? "MEDIUM").toUpperCase(),
          status:             "CERRADO",
          score:              Number(dup.severity_score ?? 50),
          operatorId:         ci,
          // Mantenemos el texto 'MERGEADO/AGRUPADO → X' por retro-compat (UI
          // antigua, exports CSV). La trazabilidad real vive en merged_into_case_id.
          closureReason:      `${mergeVerb} → ${canonicalCaseId}`,
          mergedIntoCaseId:   String(canonicalCaseId),
          // F3 (audit 2026-06-05): clasificar el cierre por fusión como duplicado
          // del sistema. Antes quedaba classification NULL (bypass de la
          // clasificación obligatoria que sí aplican PATCH/status y transitionCase).
          classification:     "AUTO_DUPLICATE",
          timelineEntry:      buildTimelineEntry("STATUS_CHANGE", ci, `${mergeVerb} → ${canonicalCaseId}`),
        });
      }
    } catch (pgErr) {
      logger.error("incidents.merge.pg_error", { err: pgErr.message });
    }

    // 2. Iceberg — enqueue del trabajo en la cola persistente (R9 audit
    // 2026-05-13). El handler retorna 200 al cliente inmediatamente; el worker
    // de icebergMergeQueue.startIcebergMergeQueueWorker() drena con retry
    // exponencial. Si el proceso cae, los jobs pendientes sobreviven.
    try {
      const dupRows = duplicateCaseIds
        .map((id) => byId.get(String(id)))
        .filter(Boolean);
      await enqueueMergeJob({
        canonicalId:     String(canonicalCaseId),
        duplicateIds:    duplicateCaseIds.map(String),
        totalOccurrence: totalOcc,
        canonicalRow:    canon,
        duplicateRows:   dupRows,
        ci,
        now,
      });
    } catch (qErr) {
      // Si la cola PG falla, registramos pero NO bloqueamos la respuesta —
      // la mitad PG ya fue exitosa. Operador puede re-correr el merge.
      logger.error("incidents.merge.iceberg_merge_enqueue_failed", { canonicalCaseId, err: qErr.message });
    }

    getIo()?.emit("incident:merged", {
      canonicalCaseId,
      duplicateCaseIds,
      operatorCi: ci,
      mergedAt:   now,
    });

    res.json({
      ok: true,
      canonicalCaseId,
      merged:      duplicateCaseIds.length,
      newOccurrenceCount: totalOcc,
    });
  });

  // ── DELETE /api/incidents/suppressions/:dedup_key ────────────────────────────
  // NOTE: must be defined BEFORE /:id to avoid route shadowing.
  router.delete("/suppressions/:dk", async (req, res) => {
    const { dk } = req.params;
    if (!dk?.trim()) return res.status(400).json({ ok: false, error: "dedup_key requerido" });
    try {
      await pgQuery(
        `DELETE FROM legacyhunt_soc.case_suppressions WHERE dedup_key = $1`,
        [dk],
      );
      res.json({ ok: true, deleted: dk });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── POST /api/incidents/suppressions ────────────────────────────────────────
  // R6 (audit 2026-05-13): UI manager+ puede silenciar un IOC por dedup_key.
  // Body:
  //   { dedupKey, durationDays, reason?, severity?, iocValue?, suppressedBy? }
  // - dedupKey:      required (lookup key, 64 chars hex desde services/dedupKey.mjs)
  // - durationDays:  required (1..365) — calcula suppressed_until = now + N days
  // - reason:        default 'OPERATOR'; uno de FALSO_POSITIVO|CERRADO|AUTO_CLOSED|OPERATOR
  // - severity:      opcional (informativo; usado por suppression_days() en el path
  //                  automático del DAG, no influye aquí porque durationDays manda)
  // - iocValue:      opcional (original_ioc — útil para vista v_active_suppressions)
  // - suppressedBy:  default JWT.user → req.user.preferred_username o body
  //
  // ON CONFLICT (dedup_key): extiende la ventana si el motivo no cambia; si cambia,
  // sobreescribe (alineado con scripts/sql/postgres/04_case_suppressions.sql).
  //
  // RBAC: requiere capability manager+. Si no hay JWT (lab mode), pasa.
  router.post("/suppressions", async (req, res) => {
    const {
      dedupKey, durationDays, reason: rawReason,
      severity, iocValue, suppressedBy: rawCi,
    } = req.body ?? {};

    if (!dedupKey || typeof dedupKey !== "string" || dedupKey.trim().length < 8) {
      return res.status(400).json({ ok: false, error: "dedupKey inválido (mínimo 8 chars)" });
    }
    const days = Number(durationDays);
    if (!Number.isFinite(days) || days < 1 || days > 365) {
      return res.status(400).json({ ok: false, error: "durationDays debe estar entre 1 y 365" });
    }
    const reason = String(rawReason ?? "OPERATOR").toUpperCase();
    if (!["FALSO_POSITIVO", "CERRADO", "AUTO_CLOSED", "OPERATOR"].includes(reason)) {
      return res.status(400).json({
        ok: false,
        error: "reason debe ser FALSO_POSITIVO | CERRADO | AUTO_CLOSED | OPERATOR",
      });
    }

    const jwtCi = await resolveJwtOperatorCi(req);
    const ci    = jwtCi ?? (rawCi ? String(rawCi).trim() : null) ?? "system";

    try {
      const rows = await pgQuery(
        `INSERT INTO legacyhunt_soc.case_suppressions
           (dedup_key, reason, severity, suppressed_until, suppressed_by, original_ioc, created_at, updated_at)
         VALUES ($1, $2, $3, now() + ($4 || ' days')::interval, $5, $6, now(), now())
         ON CONFLICT (dedup_key) DO UPDATE SET
           reason           = EXCLUDED.reason,
           severity         = COALESCE(EXCLUDED.severity, legacyhunt_soc.case_suppressions.severity),
           suppressed_until = GREATEST(EXCLUDED.suppressed_until, legacyhunt_soc.case_suppressions.suppressed_until),
           suppressed_by    = EXCLUDED.suppressed_by,
           original_ioc     = COALESCE(EXCLUDED.original_ioc, legacyhunt_soc.case_suppressions.original_ioc),
           updated_at       = now()
         RETURNING dedup_key, reason, severity, suppressed_until, suppressed_by, original_ioc, created_at, updated_at`,
        [
          String(dedupKey).trim().slice(0, 64),
          reason,
          severity ? String(severity).toUpperCase() : null,
          String(days),
          ci,
          iocValue ? String(iocValue).slice(0, 512) : null,
        ],
      );
      res.json({ ok: true, suppression: rows[0] });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/incidents/:id/scoring-detail ────────────────────────────────────
  // Devuelve el proceso de scoring documentado para un caso: bonus log, brief
  // para el analista, taxonomía auto-clasificada y datos de enriquecimiento raw.
  router.get("/:id/scoring-detail", async (req, res) => {
    const { id } = req.params;

    try {
      // 1. Leer metadatos del caso desde PG (rápido, no Trino)
      const pgRows = await pgQuery(
        `SELECT id, status, severity, score, ioc_value, source_log,
                mitre_tactic_id, mitre_tactic_name, enrichment_data,
                recommended_action, is_false_positive, created_at
         FROM incident_cases_pg WHERE id = $1`,
        [id],
      );

      // Si no está en PG, consultar Trino (degraded path)
      let caseData = pgRows[0] ?? null;
      if (!caseData) {
        const trinoRows = await runQuery(
          `SELECT case_id AS id, status, severity_text AS severity,
                  severity_score AS score, ioc_value, source_log,
                  mitre_tactic_id, mitre_tactic_name, first_seen AS created_at
           FROM ${TCASES} WHERE case_id = ${sq(id)} LIMIT 1`,
          SESSION,
        );
        if (!trinoRows.length) return res.status(404).json({ error: "Caso no encontrado" });
        caseData = trinoRows[0];
      }

      // 2. Leer bonus log desde PostgreSQL
      let bonusLog = [];
      try {
        bonusLog = await pgQuery(
          `SELECT bonus_type, bonus_value, multiplier, detail, calculated_at
           FROM scoring_bonus_log
           WHERE case_id = $1
           ORDER BY calculated_at ASC`,
          [id],
        );
      } catch {
        // scoring_bonus_log puede no existir si la migración 010 no se aplicó
        bonusLog = [];
      }

      // 3. Generar resumen analítico (regla basada en campos del caso)
      const analystBrief = buildAnalystBrief(caseData);

      // 4. Auto-clasificar taxonomía
      const autoTaxonomy = inferTaxonomy(caseData);

      // 5. Raw enrichment data (ya en PG)
      const rawData = caseData.enrichment_data ?? null;

      res.json({ bonusLog, analystBrief, autoTaxonomy, rawData, caseId: id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/incidents/:id ───────────────────────────────────────────────────
  router.get("/:id", async (req, res) => {
    const { id } = req.params;

    const sqlCase = `
      SELECT
        ic.case_id, ic.ioc_value, ic.ioc_type, ic.source_log,
        ic.severity_text, ic.severity_score, ic.confidence_level,
        ic.status, ic.mitre_technique_id, ic.mitre_tactic_id, ic.mitre_tactic_name,
        ic.assigned_to, ic.closure_reason, ic.notes, ic.score_breakdown,
        ic.first_seen, ic.last_seen, ic.occurrence_count,
        ic.adopted_at, ic.escalation_level, ic.escalated_to,
        ic.escalated_at, ic.escalation_reason, ic.recommended_action
      FROM ${TCASES} ic
      WHERE ic.case_id = ${sq(id)}
      LIMIT 1`;

    try {
      const [rows, pgMap] = await Promise.all([
        runQuery(sqlCase, SESSION),
        pgBatchLookup([id]),
      ]);

      if (!rows.length) return res.status(404).json({ error: "Caso no encontrado" });
      res.json(mapCaseRow(rows[0], pgMap.get(id) ?? null));
    } catch (err) {
      res.status(500).json({ error: err.message ?? "Error consultando Trino" });
    }
  });

  // ── GET /api/incidents/:id/raw_event ────────────────────────────────────────
  // Fase 2A — busca el evento raw del caso en la tabla fuente (Hive/Iceberg).
  // Match: strpos(message, ioc_value) > 0 dentro de una ventana ±1 h alrededor
  // de case.created_at (partition pruning year/month/day/hour en Hive; dt en
  // Iceberg). Retorna el primer match; el cliente parsea JSON si corresponde.
  router.get("/:id/raw_event", async (req, res) => {
    const { id } = req.params;
    try {
      const rows = await pgQuery(
        `SELECT source_log, ioc_value, created_at
           FROM incident_cases_pg WHERE id = $1`,
        [id],
      );
      if (!rows.length) return res.status(404).json({ error: "Caso no encontrado" });
      const { source_log, ioc_value, created_at } = rows[0];
      if (!source_log || !ioc_value || !created_at) {
        return res.status(422).json({ error: "Caso sin source_log / ioc / timestamp para resolver raw_event" });
      }

      // source_log → { catalog.schema.table, kind: "hive-json" | "iceberg-row" }
      const SRC_MAP = {
        wazuh_alerts:        { table: "minio.hunting.wazuh_alerts",              kind: "hive-json" },
        wazuh_fluent_alerts: { table: "minio.hunting.wazuh_fluent",              kind: "hive-json" },
        wazuh_fluent:        { table: "minio.hunting.wazuh_fluent",              kind: "hive-json" },
        fortigate:           { table: "minio.hunting.fortigate",                 kind: "hive-json" },
        pmg:                 { table: "minio.hunting.pmg",                       kind: "hive-json" },
        opnsense_filterlog:  { table: "minio_iceberg.hunting.syslog_events",     kind: "iceberg-row" },
        syslog:              { table: "minio_iceberg.hunting.syslog_events",     kind: "iceberg-row" },
      };
      const src = SRC_MAP[source_log];
      if (!src) {
        return res.status(422).json({ error: `source_log no soportado: ${source_log}` });
      }

      // Ventana ±24 h: el `created_at` del caso suele ser posterior al primer
      // evento (ingest + accumulator lag). Enumeramos 3 días (D-1, D, D+1)
      // para partition pruning en Hive.
      const t = new Date(created_at);
      const dayKeys = [-1, 0, 1].map(offset => {
        const x = new Date(t.getTime() + offset * 86400_000);
        return {
          y:  String(x.getUTCFullYear()),
          mo: String(x.getUTCMonth() + 1).padStart(2, "0"),
          d:  String(x.getUTCDate()).padStart(2, "0"),
        };
      });
      const hivePart = dayKeys.map(k => `(year=${sq(k.y)} AND month=${sq(k.mo)} AND day=${sq(k.d)})`).join(" OR ");

      let sql;
      if (src.kind === "hive-json") {
        // Partition pruning por (y/m/d); strpos del IOC en message. El orden
        // por timestamp DESC prioriza el evento más cercano al created_at.
        sql = `
          SELECT message AS event_json, source_ip, hostname, "timestamp" AS ts,
                 year, month, day, hour
            FROM ${src.table}
           WHERE (${hivePart})
             AND (strpos(message, ${sq(ioc_value)}) > 0 OR source_ip = ${sq(ioc_value)})
           ORDER BY "timestamp" DESC
           LIMIT 1`;
      } else {
        // iceberg-row: no JSON — devolvemos columnas relevantes como objeto.
        sql = `
          SELECT
            CAST(event_ts AS varchar) AS ts,
            host, appname, facility, severity, message,
            fl_action, fl_interface, fl_protocol,
            fl_src_ip, fl_dst_ip, fl_src_port, fl_dst_port,
            fl_flags, fl_length, fl_is_filterlog
            FROM ${src.table}
           WHERE dt BETWEEN DATE ${sq(`${y}-${mo}-${d}`)} - INTERVAL '1' DAY
                        AND DATE ${sq(`${y}-${mo}-${d}`)} + INTERVAL '1' DAY
             AND (fl_src_ip = ${sq(ioc_value)} OR fl_dst_ip = ${sq(ioc_value)}
                  OR strpos(message, ${sq(ioc_value)}) > 0)
           ORDER BY event_ts DESC
           LIMIT 1`;
      }

      const result = await runQuery(sql, SESSION);
      if (!result.length) {
        return res.json({
          table:       src.table,
          kind:        src.kind,
          found:       false,
          queried_at:  new Date().toISOString(),
          query_window: { center_ts: t.toISOString(), days: dayKeys.map(k => `${k.y}-${k.mo}-${k.d}`).join(",") },
        });
      }

      const row = result[0];
      // Hive-json: intentar parsear message (JSON-as-string) para devolver un objeto.
      let event = row;
      if (src.kind === "hive-json" && typeof row.event_json === "string") {
        try { event = { ...row, parsed: JSON.parse(row.event_json) }; }
        catch { /* deja event_json como string */ }
      }

      return res.json({
        table:       src.table,
        kind:        src.kind,
        found:       true,
        matched_on:  src.kind === "hive-json" ? "message.strpos(ioc)" : "fl_src_ip|fl_dst_ip|message",
        queried_at:  new Date().toISOString(),
        event,
      });
    } catch (err) {
      logger.error("incidents.raw_event_failed", { err: err?.message ?? String(err) });
      return res.status(500).json({ error: err.message ?? "Error consultando raw_event" });
    }
  });

  // ── GET /api/incidents/:id/traceability ─────────────────────────────────────
  // Fase 2A — correlación 24 h sobre las tablas fuente del stack. Busca el
  // IOC del caso como src/dst/hostname/message en ventana centrada en
  // case.created_at. Cap 50 filas. Úsalo desde "Buscar más trazabilidad".
  router.get("/:id/traceability", async (req, res) => {
    const { id } = req.params;
    const hours  = Math.min(Math.max(Number(req.query.hours) || 24, 1), 72);

    try {
      const rows = await pgQuery(
        `SELECT source_log, ioc_value, created_at
           FROM incident_cases_pg WHERE id = $1`,
        [id],
      );
      if (!rows.length) return res.status(404).json({ error: "Caso no encontrado" });
      const { ioc_value, created_at } = rows[0];
      if (!ioc_value || !created_at) return res.status(422).json({ error: "Caso sin IOC o timestamp" });

      const t     = new Date(created_at);
      const from  = new Date(t.getTime() - hours * 3600_000);
      const to    = new Date(t.getTime() + hours * 3600_000);
      // enriched_ioc / syslog_events particionan por `dt` (DATE): el filtro de
      // partición es el rango de días [from, to]. Ya no se enumeran particiones
      // Hive (year/month/day) porque la query dejó de tocar las tablas raw.

      // Perf 2026-06-15: antes esta query hacía UNION sobre las tablas RAW
      // (minio.hunting.wazuh_alerts / fortigate) con strpos(message, IOC) — un
      // escaneo de substring sobre el blob `message` que tardaba >60s (fortigate
      // 12.5M filas/día, blobs Wazuh multi-KB) → timeout del front. El benchmark
      // mostró 6m37s incluso filtrando SÓLO por columnas tipadas en el raw fortigate.
      //
      // Ahora se correlaciona sobre `enriched_ioc` (la moneda de la detección, ya
      // parseada/tipada e indexada por dt): ~1s, all-history, con origen
      // (ioc_value) Y destino (affected_asset_ip) poblados para TODAS las fuentes
      // —incluido Wazuh, que antes fijaba dst_ip=NULL y perdía el host víctima—.
      // Es agregado por (ioc, día): para la trazabilidad origen→destino eso es más
      // legible que 50 filas raw casi idénticas (alert_count expone el volumen).
      // El detalle por-evento sigue en el tab "Eventos" (/events) y RawEventPanel.
      const fromDay = sq(from.toISOString().slice(0, 10));
      const toDay   = sq(to.toISOString().slice(0, 10));
      const sql = `
        WITH e AS (
          SELECT
            source_log AS src_table,
            CAST(dt AS timestamp) AS ts,
            sensor_host AS host,
            ioc_value AS src_ip,
            affected_asset_ip AS dst_ip,
            substr(concat(
              COALESCE(NULLIF(source_category, ''), source_log),
              ' · ', CAST(COALESCE(alert_count, 0) AS varchar), ' ev',
              COALESCE(' · dst_port ' || json_extract_scalar(raw_context, '$.dest_port'), ''),
              COALESCE(' · crlevel '  || NULLIF(json_extract_scalar(raw_context, '$.crlevel'), ''), ''),
              COALESCE(' · ' || NULLIF(mitre_technique_id, ''), ''),
              COALESCE(' · víctima ' || NULLIF(affected_asset_name, ''), '')
            ), 1, 300) AS msg_preview
          FROM minio_iceberg.hunting.enriched_ioc
          WHERE dt BETWEEN DATE ${fromDay} AND DATE ${toDay}
            AND (ioc_value = ${sq(ioc_value)} OR affected_asset_ip = ${sq(ioc_value)})
        ),
        s AS (
          SELECT 'syslog_events' AS src_table,
                 event_ts AS ts,
                 host,
                 fl_src_ip AS src_ip,
                 fl_dst_ip AS dst_ip,
                 substr(message, 1, 300) AS msg_preview
            FROM minio_iceberg.hunting.syslog_events
           WHERE dt BETWEEN DATE ${fromDay} AND DATE ${toDay}
             AND (fl_src_ip = ${sq(ioc_value)} OR fl_dst_ip = ${sq(ioc_value)})
        )
        SELECT * FROM e
        UNION ALL SELECT * FROM s
        ORDER BY ts DESC NULLS LAST
        LIMIT 100`;

      const events = await runQuery(sql, SESSION);
      return res.json({
        ioc:         ioc_value,
        hours,
        window:      { from: from.toISOString(), to: to.toISOString() },
        count:       events.length,
        events,
        queried_at:  new Date().toISOString(),
      });
    } catch (err) {
      logger.error("incidents.traceability_failed", { err: err?.message ?? String(err) });
      return res.status(500).json({ error: err.message ?? "Error consultando trazabilidad" });
    }
  });

  // ── GET /api/incidents/:id/events ──────────────────────────────────────────
  // Paginación de eventos crudos sobre la tabla fuente del caso. Útil cuando
  // el snapshot Hunt Pivots reportó N alertas (p.ej. 5,959) y el operador
  // quiere recorrerlas: RawEventPanel solo muestra 1, TraceabilityPanel cap 50
  // y une 3 fuentes — esto pagina dentro de UNA fuente (la del caso) y deja
  // que la UI scrollee con offset.
  //
  // Query params:
  //   hours    — ventana centrada en created_at (default 24, cap 168 = 7d)
  //   limit    — page size (default 50, cap 500)
  //   offset   — número de filas a saltar (default 0)
  //   severity — filtro opcional CRITICAL|HIGH|MEDIUM|LOW|NEGLIGIBLE
  //
  // `hasMore` se calcula pidiendo `limit+1` filas; si vinieron más de `limit`
  // hay siguiente página. El total absoluto NO se devuelve (count(*) sería
  // otra query igual de cara). Para el total agregado consultar el snapshot
  // que ya quedó en enrichment_data.huntPivotSnapshot.totalEvents24h.
  const VALID_SEV = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]);

  router.get("/:id/events", async (req, res) => {
    const { id } = req.params;
    const hours  = Math.min(Math.max(Number(req.query.hours)  || 24, 1), 168);
    const limit  = Math.min(Math.max(Number(req.query.limit)  || 50, 1), 500);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const sevFilter = typeof req.query.severity === "string" && VALID_SEV.has(req.query.severity.toUpperCase())
      ? req.query.severity.toUpperCase()
      : null;

    try {
      const rows = await pgQuery(
        `SELECT source_log, ioc_value, created_at
           FROM incident_cases_pg WHERE id = $1`,
        [id],
      );
      if (!rows.length) return res.status(404).json({ error: "Caso no encontrado" });
      const { source_log, ioc_value, created_at } = rows[0];
      if (!source_log || !ioc_value || !created_at) {
        return res.status(422).json({ error: "Caso sin source_log / ioc / timestamp" });
      }

      // Normalizamos source_log → 1 de 5 builders. Mismo mapping conceptual
      // que /raw_event pero unificado a 5 grupos para evitar duplicar el SQL.
      const sl = String(source_log).toLowerCase();
      const kind =
        sl === "wazuh_alerts"        ? "wazuh"     :
        sl === "wazuh_fluent"        ? "wazuh_fl"  :
        sl === "wazuh_fluent_alerts" ? "wazuh_fl"  :
        sl === "fortigate"           ? "fortigate" :
        sl === "pmg"                 ? "pmg"       :
        sl === "syslog"              ? "syslog"    :
        sl === "opnsense_filterlog"  ? "syslog"    :
        null;
      if (!kind) {
        return res.status(422).json({ error: `source_log no soportado: ${source_log}` });
      }

      const t    = new Date(created_at);
      const from = new Date(t.getTime() - hours * 3600_000);
      const to   = new Date(t.getTime() + hours * 3600_000);

      // Partition keys Hive — enumeramos cada día del rango.
      const dayKeys = [];
      for (let x = new Date(from); x <= to; x.setUTCDate(x.getUTCDate() + 1)) {
        dayKeys.push({
          y:  String(x.getUTCFullYear()),
          mo: String(x.getUTCMonth() + 1).padStart(2, "0"),
          d:  String(x.getUTCDate()).padStart(2, "0"),
        });
      }
      const hivePart = dayKeys.length
        ? dayKeys.map(k => `(year=${sq(k.y)} AND month=${sq(k.mo)} AND day=${sq(k.d)})`).join(" OR ")
        : "FALSE";

      // SQL CASE para mapear Wazuh level → severity bucket (mismo cutoff que
      // services/huntPivots.mjs:wazuhLevelToSev).
      const wazuhSevCase = (lvlExpr) => `
        CASE
          WHEN ${lvlExpr} >= 13 THEN 'CRITICAL'
          WHEN ${lvlExpr} >= 10 THEN 'HIGH'
          WHEN ${lvlExpr} >=  7 THEN 'MEDIUM'
          WHEN ${lvlExpr} >=  3 THEN 'LOW'
          ELSE 'NEGLIGIBLE'
        END`;

      // syslog (filterlog) severity ya viene 0-7 estilo RFC5424.
      const syslogSevCase = `
        CASE
          WHEN severity <= 1 THEN 'CRITICAL'
          WHEN severity <= 3 THEN 'HIGH'
          WHEN severity <= 4 THEN 'MEDIUM'
          WHEN severity <= 6 THEN 'LOW'
          ELSE 'NEGLIGIBLE'
        END`;

      let sql;
      if (kind === "wazuh") {
        // Perf 2026-06-15: antes scaneaba el raw wazuh_alerts con strpos(message,
        // IOC) sobre el blob multi-KB (2.84M filas/día) → >60s timeout. Repunta a
        // wazuh_events_slim (Iceberg tipado, parseado 1x por wazuh_summary_refresh_30min,
        // ~1s, 48h rolling). dst_ip = agent_ip (host monitorizado/víctima); antes era NULL.
        const fromTs = sq(from.toISOString());
        const toTs   = sq(to.toISOString());
        sql = `
          SELECT
            ev_ts                                       AS ts,
            'wazuh_alerts'                              AS src_table,
            agent_name                                  AS host,
            src_ip                                      AS src_ip,
            agent_ip                                    AS dst_ip,
            rule_level                                  AS lvl,
            ${wazuhSevCase("rule_level")}               AS severity,
            CAST(rule_id AS varchar)                    AS rule_id,
            rule_description                            AS rule_desc,
            substr(COALESCE(rule_description, ''), 1, 300) AS msg_preview
            FROM minio_iceberg.hunting.wazuh_events_slim
           WHERE ev_ts BETWEEN from_iso8601_timestamp(${fromTs})
                           AND from_iso8601_timestamp(${toTs})
             AND (src_ip = ${sq(ioc_value)} OR agent_ip = ${sq(ioc_value)}
                  OR agent_name = ${sq(ioc_value)})
        `;
      } else if (kind === "wazuh_fl") {
        const lvl = `CAST(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.level') AS INTEGER)`;
        sql = `
          SELECT
            try(from_iso8601_timestamp("timestamp"))                                            AS ts,
            'wazuh_fluent'                                                                       AS src_table,
            json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name')            AS host,
            json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip')            AS src_ip,
            json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.dstip')            AS dst_ip,
            ${lvl}                                                                               AS lvl,
            ${wazuhSevCase(lvl)}                                                                 AS severity,
            json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')               AS rule_id,
            json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description')      AS rule_desc,
            substr(CAST(message AS varchar), 1, 300)                                             AS msg_preview
            FROM minio.hunting.wazuh_fluent
           WHERE (${hivePart})
             AND strpos(CAST(message AS varchar), ${sq(ioc_value)}) > 0
        `;
      } else if (kind === "fortigate") {
        // Perf 2026-06-15: antes scaneaba el raw fortigate con OR strpos(message,
        // IOC) (12.5M filas/día) → >60s. Repunta a fortigate_events_slim (Iceberg
        // tipado POR-EVENTO, MV del DAG fortigate_events_slim_refresh_30min, ~2.7s,
        // 48h rolling). Mantiene el detalle por-paquete (ts al segundo, dst_ip/
        // dst_port/action/crlevel/attack tipados) que enriched_ioc agregaba.
        const fromTs = sq(from.toISOString());
        const toTs   = sq(to.toISOString());
        sql = `
          SELECT
            ev_ts                                                                                AS ts,
            'fortigate'                                                                          AS src_table,
            devname                                                                              AS host,
            src_ip                                                                               AS src_ip,
            dst_ip                                                                               AS dst_ip,
            CAST(NULL AS INTEGER)                                                                AS lvl,
            CASE
              WHEN crlevel = 'critical' THEN 'CRITICAL'
              WHEN crlevel = 'high'     THEN 'HIGH'
              WHEN crlevel = 'medium'   THEN 'MEDIUM'
              WHEN fw_level IN ('critical','alert','emergency') THEN 'CRITICAL'
              WHEN fw_level = 'error'   THEN 'HIGH'
              WHEN fw_level = 'warning' THEN 'MEDIUM'
              ELSE 'LOW'
            END                                                                                  AS severity,
            COALESCE(NULLIF(attack, ''), action)                                                 AS rule_id,
            COALESCE(NULLIF(utm_subtype, ''), log_family)                                        AS rule_desc,
            substr(concat(
              log_family,
              COALESCE(' · dst_port ' || CAST(dst_port AS varchar), ''),
              COALESCE(' · ' || NULLIF(crlevel, ''), ''),
              COALESCE(' · attack ' || NULLIF(attack, ''), ''),
              COALESCE(' · virus ' || NULLIF(virus_name, ''), '')
            ), 1, 300)                                                                           AS msg_preview
            FROM minio_iceberg.hunting.fortigate_events_slim
           WHERE ev_ts BETWEEN from_iso8601_timestamp(${fromTs})
                           AND from_iso8601_timestamp(${toTs})
             AND (src_ip = ${sq(ioc_value)} OR dst_ip = ${sq(ioc_value)})
        `;
      } else if (kind === "pmg") {
        // Schema real de minio.hunting.pmg: sender_email/sender_ip/sender_domain
        // + recipient_email + spam_score + action. No hay `sender`/`recipient`/
        // `score`/`qid`/`subject` directos.
        sql = `
          SELECT
            try(from_iso8601_timestamp("timestamp"))                                            AS ts,
            'pmg'                                                                                AS src_table,
            hostname                                                                             AS host,
            COALESCE(sender_email, sender_ip)                                                    AS src_ip,
            recipient_email                                                                      AS dst_ip,
            CAST(NULL AS INTEGER)                                                                AS lvl,
            CASE
              WHEN CAST(spam_score AS double) >= 9 THEN 'CRITICAL'
              WHEN CAST(spam_score AS double) >= 5 THEN 'HIGH'
              WHEN CAST(spam_score AS double) >= 3 THEN 'MEDIUM'
              WHEN CAST(spam_score AS double) >  0 THEN 'LOW'
              ELSE 'NEGLIGIBLE'
            END                                                                                  AS severity,
            action                                                                               AS rule_id,
            log_family                                                                           AS rule_desc,
            substr(CAST(message AS varchar), 1, 300)                                             AS msg_preview
            FROM minio.hunting.pmg
           WHERE (${hivePart})
             AND (sender_email = ${sq(ioc_value)} OR sender_ip = ${sq(ioc_value)}
                  OR sender_domain = ${sq(ioc_value)} OR recipient_email = ${sq(ioc_value)}
                  OR strpos(CAST(message AS varchar), ${sq(ioc_value)}) > 0)
        `;
      } else {
        // syslog (iceberg) — partition por dt (DATE). Sin rule_id/desc.
        sql = `
          SELECT
            CAST(event_ts AS varchar)                AS ts,
            'syslog_events'                          AS src_table,
            host                                     AS host,
            fl_src_ip                                AS src_ip,
            fl_dst_ip                                AS dst_ip,
            CAST(severity AS INTEGER)                AS lvl,
            ${syslogSevCase}                         AS severity,
            CAST(NULL AS varchar)                    AS rule_id,
            appname                                  AS rule_desc,
            substr(message, 1, 300)                  AS msg_preview
            FROM minio_iceberg.hunting.syslog_events
           WHERE dt BETWEEN DATE ${sq(from.toISOString().slice(0, 10))}
                        AND DATE ${sq(to.toISOString().slice(0, 10))}
             AND (fl_src_ip = ${sq(ioc_value)} OR fl_dst_ip = ${sq(ioc_value)}
                  OR strpos(message, ${sq(ioc_value)}) > 0)
        `;
      }

      // Filtro de severity al outer SELECT (no en el SELECT base) para que
      // los builders queden uniformes — el CASE deja `severity` accesible.
      const sevPredicate = sevFilter ? `WHERE severity = ${sq(sevFilter)}` : "";
      // Pedimos 1 row extra para detectar hasMore sin un count(*) separado.
      const pageSql = `
        SELECT *
          FROM (${sql})
        ${sevPredicate}
        ORDER BY ts DESC NULLS LAST
        OFFSET ${offset}
        LIMIT ${limit + 1}
      `;

      const result = await runQuery(pageSql, SESSION);
      const hasMore = result.length > limit;
      const events = hasMore ? result.slice(0, limit) : result;

      return res.json({
        ok:          true,
        ioc:         ioc_value,
        source:      source_log,
        kind,
        hours,
        window:      { from: from.toISOString(), to: to.toISOString() },
        count:       events.length,
        hasMore,
        offset,
        limit,
        severity:    sevFilter,
        events,
        queried_at:  new Date().toISOString(),
      });
    } catch (err) {
      logger.error("incidents.events_failed", { err: err?.message ?? String(err) });
      return res.status(500).json({ error: err.message ?? "Error consultando events" });
    }
  });

  // ── GET /api/incidents/:id/narrative ────────────────────────────────────────
  // Fase 2B — resumen LLM del incidente. Usa SOC_CHAT_LLM_* (OpenAI-compat).
  // Si SOC_CHAT_LLM_ENABLED=false responde { enabled:false } y el frontend
  // usa su headline auto-generado. Cache best-effort en enrichment_data.narrative.
  router.get("/:id/narrative", async (req, res) => {
    const { id } = req.params;
    const enabled = String(process.env.SOC_CHAT_LLM_ENABLED ?? "false").toLowerCase() === "true";
    const apiKey  = process.env.SOC_CHAT_LLM_API_KEY;
    const apiUrl  = process.env.SOC_CHAT_LLM_API_URL ?? "https://api.openai.com/v1/chat/completions";
    const model   = process.env.SOC_CHAT_LLM_MODEL    ?? "gpt-4o-mini";

    if (!enabled || !apiKey) {
      return res.json({ enabled: false, reason: !enabled ? "llm_disabled" : "missing_api_key" });
    }

    try {
      const rows = await pgQuery(
        `SELECT id, severity, score, ioc_value, ioc_type, source_log,
                mitre_tactic_name, mitre_technique_id, escalation_level,
                enrichment_data
           FROM incident_cases_pg WHERE id = $1`,
        [id],
      );
      if (!rows.length) return res.status(404).json({ error: "Caso no encontrado" });
      const c = rows[0];

      // Cache hit: evita re-llamar al LLM si ya hay narrative (<24 h).
      const cached = c.enrichment_data?.narrative;
      if (cached?.headline && cached.generated_at) {
        const ageMs = Date.now() - new Date(cached.generated_at).getTime();
        if (ageMs < 24 * 3600 * 1000) return res.json({ enabled: true, cached: true, ...cached });
      }

      const enr = c.enrichment_data?.iocEnrichment ?? {};
      const context = [
        `Caso ${c.id} — ${c.severity} — score ${c.score}.`,
        c.ioc_value ? `IOC ${c.ioc_type}: ${c.ioc_value}.` : "",
        c.mitre_tactic_name ? `MITRE ${c.mitre_tactic_name} (${c.mitre_technique_id ?? "n/a"}).` : "",
        c.source_log ? `Fuente: ${c.source_log}.` : "",
        enr.vtMalicious ? `VirusTotal ${enr.vtMalicious} maliciosos.` : "",
        enr.abuseConfidence ? `AbuseIPDB ${enr.abuseConfidence}% (${enr.abuseTotalReports ?? 0} reportes).` : "",
        c.escalation_level ? `Escalado a ${c.escalation_level}.` : "",
      ].filter(Boolean).join(" ");

      const prompt = [
        { role: "system", content: "Eres analista SOC. Responde SOLO con JSON válido: {\"headline\": string (1 oración, ≤160 caracteres, en español, sin adjetivos dramáticos), \"reasons\": string[] (2-5 chips, ≤40 chars cada uno)}." },
        { role: "user", content: `Sintetiza por qué este incidente importa:\n${context}` },
      ];

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      const llmRes = await fetch(apiUrl, {
        method:  "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ model, messages: prompt, temperature: 0.2, max_tokens: 400, response_format: { type: "json_object" } }),
        signal: controller.signal,
      }).finally(() => clearTimeout(timer));

      if (!llmRes.ok) {
        const txt = await llmRes.text().catch(() => "");
        return res.status(502).json({ enabled: true, error: `LLM ${llmRes.status}`, detail: txt.slice(0, 300) });
      }
      const payload = await llmRes.json();
      const content = payload?.choices?.[0]?.message?.content ?? "{}";
      let parsed = {};
      try { parsed = JSON.parse(content); } catch { /* parseo estricto */ }
      const headline = String(parsed.headline ?? "").slice(0, 200);
      const reasons  = Array.isArray(parsed.reasons)
        ? parsed.reasons.slice(0, 5).map((x) => String(x).slice(0, 60))
        : [];

      const narrative = { headline, reasons, generated_at: new Date().toISOString(), model };

      // Cache en enrichment_data.narrative (best-effort, no bloqueamos si falla).
      try {
        await pgQuery(
          `UPDATE incident_cases_pg
              SET enrichment_data = jsonb_set(COALESCE(enrichment_data, '{}'::jsonb), '{narrative}', $1::jsonb, true)
            WHERE id = $2`,
          [JSON.stringify(narrative), id],
        );
      } catch (cacheErr) {
        logger.warn("incidents.narrative_cache_failed", { caseId: id, err: cacheErr.message });
      }

      return res.json({ enabled: true, cached: false, ...narrative });
    } catch (err) {
      if (err.name === "AbortError") {
        return res.status(504).json({ enabled: true, error: "LLM timeout (15s)" });
      }
      logger.error("incidents.narrative_failed", { caseId: id, err: err?.message ?? String(err) });
      return res.status(500).json({ error: err.message ?? "Error generando narrative" });
    }
  });

  // ── POST /api/incidents/:id/add-occurrence ───────────────────────────────────
  // Registra una nueva ocurrencia del mismo IOC sobre un caso ya abierto.
  // Incrementa occurrence_count, actualiza last_seen, añade evento al timeline,
  // y actualiza el score si la nueva detección trae uno mayor.
  router.post("/:id/add-occurrence", async (req, res) => {
    const { id } = req.params;
    const {
      operatorCi,
      newScore,
      sourceLog,
      mitreTacticName,
      notes,
    } = req.body ?? {};

    if (!id || !operatorCi) {
      return res.status(400).json({ error: "id y operatorCi son requeridos" });
    }

    // Validar rango de score (0-130: máximo teórico con todos los bonos)
    if (newScore !== undefined && newScore !== null) {
      const parsedScore = Number(newScore);
      if (isNaN(parsedScore) || parsedScore < 0 || parsedScore > 130) {
        return res.status(400).json({ error: "newScore debe estar entre 0 y 130" });
      }
    }

    // Verificar que el caso existe y está abierto
    const existing = await pgQuery(
      `SELECT id, status, severity, score, occurrence_count
         FROM incident_cases_pg
        WHERE id = $1`,
      [id],
    );
    if (!existing.length) {
      return res.status(404).json({ error: "Caso no encontrado" });
    }
    const c = existing[0];
    if (["CERRADO", "FALSO_POSITIVO"].includes(c.status)) {
      return res.status(409).json({
        error: "El caso ya está cerrado — no se puede añadir re-ocurrencia",
        status: c.status,
      });
    }

    const newOccCount = Number(c.occurrence_count ?? 1) + 1;
    const scoreToUse  = newScore && Number(newScore) > Number(c.score)
      ? Number(newScore)
      : Number(c.score);

    await pgQuery(
      `UPDATE incident_cases_pg
          SET occurrence_count = $1,
              last_seen        = now(),
              score            = $2,
              updated_at       = now()
        WHERE id = $3`,
      [newOccCount, scoreToUse, id],
    );

    // Timeline event
    const eventDesc = [
      `Re-ocurrencia #${newOccCount} detectada por ${operatorCi}`,
      sourceLog     ? `· Fuente: ${sourceLog}` : "",
      mitreTacticName ? `· MITRE: ${mitreTacticName}` : "",
      notes         ? `· Nota: ${notes}` : "",
    ].filter(Boolean).join(" ");

    await pgQuery(
      `INSERT INTO case_timeline_events
         (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source, metadata)
       VALUES ($1, $2, now(), 'NOTE', 'DETECTION', $3, $4, $5, 'MANUAL', $6)`,
      [
        randomUUID(), id,
        `Re-ocurrencia #${newOccCount}`,
        eventDesc,
        String(operatorCi).trim(),
        JSON.stringify({ occurrenceCount: newOccCount, newScore: newScore ?? null }),
      ],
    );

    getIo()?.emit("incident:occurrence_added", { id, occurrenceCount: newOccCount, operatorCi });

    return res.json({
      ok:              true,
      caseId:          id,
      occurrenceCount: newOccCount,
      score:           scoreToUse,
    });
  });

  // ── POST /api/incidents/:id/adopt ────────────────────────────────────────────
  // Reglas de adopción:
  //  · Owner == solicitante  → idempotente (200)
  //  · Sin owner             → claim normal
  //  · Owner es LEADER       → transferencia automática (un líder abre, el
  //                            analista L1/L2 toma el caso)
  //  · Owner inactivo        → transferencia automática
  //  · Owner activo distinto → 409 salvo force=true (transferencia manual con
  //                            log en timeline)
  router.post("/:id/adopt", async (req, res) => {
    const { id } = req.params;
    const { operatorCi: bodyCi, force = false } = req.body ?? {};

    // Identidad autoritativa = JWT → soc_operators.kc_user_id (o .id en lab).
    // Si no resuelve (operador aún sin link a KC), caemos a bodyCi como
    // transición legacy — se loggea el descarte cuando difieren para auditar
    // intentos de suplantación. Hotfix del audit de gestión.
    const jwtCi = await resolveJwtOperatorCi(req);
    const rawBodyCi = bodyCi ? String(bodyCi).trim() : null;

    // Separar ACTOR (quien ejecuta, autoritativo vía JWT) del DESTINATARIO
    // (a quién se asigna el caso). El "claim" propio colapsa ambos; la
    // reasignación a un tercero los separa. Antes `const ci = jwtCi ?? rawBodyCi`
    // descartaba el destinatario y el JWT ganaba siempre → reasignar a otro
    // operador era un no-op (el caso se autoasignaba a quien clicaba, y si ya
    // era el owner caía en el guard idempotente `alreadyAdopted`). Fix de
    // reasignación 2026-06-18: cuando force=true y el body apunta a otro CI,
    // ese CI es el nuevo owner; el JWT queda como actor de auditoría.
    const actorCi = jwtCi ?? rawBodyCi;
    const isReassignToOther = force === true && !!rawBodyCi && !!jwtCi && rawBodyCi !== jwtCi;
    const ci = isReassignToOther ? rawBodyCi : actorCi;

    if (!ci || ci.length < 5) {
      return res.status(400).json({ error: "CI inválido (mínimo 5 caracteres)" });
    }

    // Anti-suplantación: asignar un caso a OTRO operador requiere can_assign_cases
    // (LEADER/ADMIN). Un analista sólo puede tomar el caso para sí mismo. Cuando
    // el body difiere del JWT pero NO se cumple esta vía sancionada, se descarta
    // el body y se usa el actor (comportamiento previo, log de posible suplantación).
    if (isReassignToOther) {
      try {
        const actorRows = await pgQuery(
          `SELECT r.can_assign_cases
             FROM soc_operators o
             LEFT JOIN soc_roles r ON r.id = o.role_id
            WHERE o.id = $1 LIMIT 1`,
          [actorCi],
        );
        if (actorRows[0] && actorRows[0].can_assign_cases === false) {
          return res.status(403).json({
            error: "Tu rol no puede asignar casos a otros operadores (requiere can_assign_cases).",
            hint: "Adoptá el caso para vos (sin elegir otro operador) o pedí a un Shift Manager que lo reasigne.",
          });
        }
      } catch { /* tabla puede no existir en labs mínimos */ }
    } else if (jwtCi && rawBodyCi && rawBodyCi !== jwtCi) {
      logger.warn("incidents.adopt.body_ci_mismatch_use_jwt", {
        jwtCi, bodyCi: rawBodyCi, caseId: id, force,
        user: req.user?.preferred_username,
      });
    }
    const now = new Date().toISOString();

    // Validación de rol: el operador debe tener can_adopt=true.
    try {
      const rows = await pgQuery(
        `SELECT o.role_id, r.can_adopt, o.is_active
           FROM soc_operators o
           LEFT JOIN soc_roles r ON r.id = o.role_id
          WHERE o.id = $1 LIMIT 1`,
        [ci],
      );
      if (rows[0]) {
        if (!rows[0].is_active) {
          return res.status(403).json({ error: "Operador inactivo: no puede adoptar casos" });
        }
        if (rows[0].can_adopt === false) {
          return res.status(403).json({
            error: `Rol ${rows[0].role_id} no tiene permiso para adoptar casos`,
          });
        }
      }
      // Si no existe en soc_operators, permitimos continuar (lab/legacy).
    } catch { /* tabla puede no existir en labs mínimos */ }

    // Estado actual del caso en PG (fuente de verdad operacional). Si Iceberg
    // está disponible, lo consultamos también para refrescar severity/score.
    const pgRows = await pgQuery(
      `SELECT id, severity, score, operator_id, adopted_at, status FROM incident_cases_pg WHERE id = $1`,
      [id],
    );
    let icebergRow = null;
    try {
      const t = await runQuery(`SELECT * FROM ${TCASES} WHERE case_id = ${sq(id)} LIMIT 1`, SESSION);
      icebergRow = t[0] ?? null;
    } catch { /* Iceberg roto o sin metadata: usamos sólo PG */ }

    if (!pgRows.length && !icebergRow) {
      return res.status(404).json({ error: "Caso no encontrado" });
    }

    const sev   = String(icebergRow?.severity_text ?? pgRows[0]?.severity ?? "MEDIUM").toUpperCase();
    const score = Number(icebergRow?.severity_score ?? pgRows[0]?.score ?? 50);
    const currentOwner = pgRows[0]?.operator_id ?? null;

    // Idempotente
    if (currentOwner === ci) {
      return res.json({ ok: true, alreadyAdopted: true, operatorId: ci });
    }

    // Resolver rol del owner actual y del solicitante (best-effort)
    let ownerRole = null, ownerActive = true;
    if (currentOwner) {
      try {
        const rows = await pgQuery(
          `SELECT role_id, is_active FROM soc_operators WHERE id = $1 LIMIT 1`,
          [currentOwner],
        );
        if (rows[0]) { ownerRole = rows[0].role_id; ownerActive = !!rows[0].is_active; }
      } catch { /* tabla puede no existir */ }
    }

    const isAutoTransfer = currentOwner && (ownerRole === "LEADER" || !ownerActive);
    const isForceTransfer = currentOwner && force === true;

    if (currentOwner && !isAutoTransfer && !isForceTransfer) {
      // adoptedAt en la respuesta para que la UI muestre "hace Nm" sin
      // pedir otro round-trip (G1 audit UX operador 2026-05-20).
      return res.status(409).json({
        error: "El caso ya fue adoptado por otro operador",
        adoptedBy: currentOwner,
        adoptedByRole: ownerRole,
        adoptedAt: pgRows[0]?.adopted_at ?? null,
        canForce: true,
        hint: "El caso pertenece a un operador activo. Reenvía con force=true para reasignarlo a tu CI (queda registrado en el timeline).",
      });
    }

    // Transferencia o claim — ambos usan CAS (compare-and-swap) atómico vía
    // RETURNING. Si el UPDATE no afecta filas (porque otro operador ya mutó
    // el owner entre el SELECT y este punto) devolvemos 409. Esto cierra la
    // ventana de race donde 2 operadores ven currentOwner=X y ambos creen
    // que su UPDATE tuvo efecto. Fix #1 del audit.
    let updated;
    try {
      if (currentOwner) {
        // Transferencia: sólo sobreescribe si el owner sigue siendo el que leímos.
        // Cubre tanto auto-transfer (ownerRole=LEADER/inactive) como force=true.
        // adopted_at preserva el PRIMER timestamp de adopción para que
        // L1→L2 (escalated_at - adopted_at) sea siempre ≥ 0. Una transferencia
        // posterior no es una "re-adopción": el campo correcto para
        // "cuándo el owner actual lo recibió" es updated_at + audit timeline.
        // Ver migration 064_*.sql para backfill de casos con adopted_at >
        // escalated_at (4 casos detectados 2026-05-27).
        updated = await pgQuery(
          `UPDATE incident_cases_pg
             SET operator_id = $2,
                 adopted_at  = COALESCE(adopted_at, $3),
                 status      = CASE WHEN status IN ('CERRADO','FALSO_POSITIVO') THEN status
                                    ELSE 'EN_ANALISIS' END,
                 updated_at  = now()
           WHERE id = $1
             AND operator_id IS NOT DISTINCT FROM $4
           RETURNING id, operator_id`,
          [id, ci, now, currentOwner],
        );
      } else {
        // Claim atómico: INSERT si no existe la fila, UPDATE sólo si operator_id
        // sigue NULL. La cláusula WHERE dentro del DO UPDATE es el CAS — si
        // otro operador ya seteó operator_id, RETURNING sale vacío.
        // R4 (migration 055): scoring_version='manual' — este path crea casos
        // como placeholder en adopt sin haber pasado por sync DAG (vistas v2/v3/v4).
        updated = await pgQuery(
          `INSERT INTO incident_cases_pg
             (id, severity, status, score, operator_id, adopted_at, anchor_dt, scoring_version, updated_at)
           VALUES ($1, $2, 'EN_ANALISIS', $3, $4, $5, CURRENT_DATE, 'manual', now())
           ON CONFLICT (id) DO UPDATE
             SET operator_id = EXCLUDED.operator_id,
                 adopted_at  = EXCLUDED.adopted_at,
                 status      = CASE WHEN incident_cases_pg.status IN ('CERRADO','FALSO_POSITIVO')
                                    THEN incident_cases_pg.status
                                    ELSE 'EN_ANALISIS' END,
                 updated_at  = now()
             WHERE incident_cases_pg.operator_id IS NULL
           RETURNING id, operator_id`,
          [id, sev, score, ci, now],
        );
      }
    } catch (pgErr) {
      // Caso típico: FK fk_cases_operator — el CI no está registrado.
      if (/fk_cases_operator/.test(pgErr.message)) {
        return res.status(400).json({
          error: `CI '${ci}' no está registrado como operador activo en soc_operators.`,
        });
      }
      return res.status(500).json({ error: `Error al adoptar: ${pgErr.message}` });
    }

    // CAS miss — otro operador ganó la carrera entre nuestro SELECT y UPDATE.
    // Leemos el estado fresco para devolver un 409 informativo.
    if (!updated.length) {
      const fresh = await pgQuery(
        `SELECT operator_id FROM incident_cases_pg WHERE id = $1 LIMIT 1`,
        [id],
      );
      const newOwner = fresh[0]?.operator_id ?? null;
      logger.warn("incidents.adopt.cas_race_lost", { id, requester: ci, currentOwner, newOwner });
      return res.status(409).json({
        error: "Otro operador adoptó el caso antes que vos",
        adoptedBy: newOwner,
        canForce: Boolean(newOwner),
        hint: "El listado se actualizará con el estado real. Reintentá con force=true si necesitás tomarlo.",
      });
    }

    // Timeline: ADOPT o TRANSFER según el caso
    try {
      const action = currentOwner ? "TRANSFER" : "ADOPT";
      const detail = currentOwner
        ? `Caso transferido de ${currentOwner}${ownerRole ? ` (${ownerRole})` : ""} → ${ci}` +
          (isForceTransfer ? " · force=true" : " · transferencia automática") +
          (isReassignToOther ? ` · asignado por ${actorCi}` : "")
        : `Caso adoptado por ${ci}`;
      await pgUpsertCase(id, {
        severity: sev, status: "EN_ANALISIS", score,
        operatorId: ci,
        timelineEntry: buildTimelineEntry(action, ci, detail),
      });
    } catch (pgErr) {
      logger.error("incidents.adopt.timeline_failed", { caseId: id, err: pgErr.message });
    }

    // 2. Iceberg — best-effort. Si la tabla está rota no bloqueamos al operador.
    if (icebergRow) {
      try {
        await trinoExec(`DELETE FROM ${TCASES} WHERE case_id = ${sq(id)}`, SESSION);
        await trinoExec(buildCasesInsert({
          ...icebergRow,
          status:      "EN_ANALISIS",
          assigned_to: ci,
          adopted_at:  now,
          updated_at:  now,
        }), SESSION);
      } catch (err) {
        logger.warn("incidents.adopt.iceberg_sync_failed", { caseId: id, err: err.message });
      }
    }

    getIo()?.emit("incident:adopted", { id, operatorCi: ci, transferredFrom: currentOwner ?? null });

    if (isSlackEnabled()) {
      try {
        await sendSlackAlert({
          text: currentOwner
            ? `🔄 *CASO TRANSFERIDO — ${sev}*\n*Caso:* ${id}\n*IOC:* ${icebergRow?.ioc_value ?? pgRows[0]?.ioc_value ?? "—"}\n*De:* ${currentOwner}${ownerRole ? ` (${ownerRole})` : ""}\n*A:* ${ci}`
            : `🔒 *CASO ADOPTADO — ${sev}*\n*Caso:* ${id}\n*IOC:* ${icebergRow?.ioc_value ?? "—"}\n*Operador:* ${ci}\n*Estado:* EN_ANALISIS`,
        });
      } catch { /* no interrumpir si Slack falla */ }
    }

    res.json({
      ok: true,
      operatorId: ci,
      transferredFrom: currentOwner ?? null,
      autoTransfer:  isAutoTransfer || false,
    });
  });

  // ── PATCH /api/incidents/:id — actualizar campos de contexto/NIST ──────────
  // Permite al operador completar o corregir campos de investigación.
  // Solo se actualizan los campos presentes en el body.
  router.patch("/:id", async (req, res) => {
    const { id } = req.params;
    const {
      hostname, sourceIp, destinationIp, destinationPort, sourcePort,
      protocol, firewallAction, srcCountry, affectedUser,
      assetId, assetType, businessImpact, networkZone, sensorKey,
      incidentCategory, functionalImpact, informationImpact,
      recoverability, containmentStatus, rootCause, lessonsLearned,
      // Clasificación del ataque (operador puede completarla manualmente
      // cuando el evento original llegó sin metadata MITRE).
      mitreTacticId, mitreTacticName, mitreTechniqueId,
      iocValue, iocType, sourceLog,
    } = req.body ?? {};

    const EDITABLE = {
      hostname, sourceIp, destinationIp, destinationPort, sourcePort,
      protocol, firewallAction, srcCountry, affectedUser,
      assetId, assetType, businessImpact, networkZone, sensorKey,
      incidentCategory, functionalImpact, informationImpact,
      recoverability, containmentStatus, rootCause, lessonsLearned,
      mitreTacticId, mitreTacticName, mitreTechniqueId,
      iocValue, iocType, sourceLog,
    };
    // Filtrar solo los campos definidos en el body
    const patch = Object.fromEntries(
      Object.entries(EDITABLE).filter(([, v]) => v !== undefined)
    );
    if (!Object.keys(patch).length) {
      return res.status(400).json({ error: "Sin campos a actualizar" });
    }
    try {
      await pgUpsertCase(id, patch);
      res.json({ ok: true, updated: Object.keys(patch) });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── PATCH /api/incidents/:id/status ─────────────────────────────────────────
  router.patch("/:id/status", async (req, res) => {
    const { id } = req.params;
    const { status, reason, operatorCi: bodyCi, classification, secondApproverCi, lessonsLearned,
            resolutionAction, rootCauseCategory } = req.body ?? {};

    // Identidad autoritativa = JWT (ver resolveJwtOperatorCi). Body sólo se
    // usa si JWT no resuelve, loggeando descartes para auditoría.
    const jwtCi = await resolveJwtOperatorCi(req);
    const rawBodyCi = bodyCi ? String(bodyCi).trim() : null;
    if (jwtCi && rawBodyCi && rawBodyCi !== jwtCi) {
      logger.warn("incidents.status.body_ci_mismatch_use_jwt", {
        jwtCi, bodyCi: rawBodyCi, caseId: id, user: req.user?.preferred_username,
      });
    }
    const operatorCi = jwtCi ?? rawBodyCi;

    const VALID = new Set(["EN_ANALISIS","CONFIRMADO","MONITOREADO","ESCALADO","FALSO_POSITIVO","CERRADO"]);
    if (!VALID.has(status)) return res.status(400).json({ error: "Estado inválido" });
    // La decisión de clasificación se evalúa más abajo, una vez leído el caso en
    // PG: así pasamos currentClassification (M3) y aplicamos el gate 4-eyes FP (M1).

    // Fuente de verdad del estado operacional = PostgreSQL. La tabla primaria
    // es public.incident_cases_pg (status/severity/score se actualizan allí
    // vía pgUpsertCase). legacyhunt_soc.incident_case_index es un dedup tracker
    // con first_seen/last_seen/occurrence_count y puede tener status stale
    // (ese índice NO se actualiza por el flujo de transiciones).
    // Hacemos LEFT JOIN al index solo para recuperar dedup_key (necesario para
    // el insert en case_suppressions).
    // Iceberg es el store de máxima fidelidad (todos los campos) pero puede
    // tener drift ante fallos silenciosos del sync (setImmediate fire-and-forget
    // del flujo de creación). Cuando el row de Iceberg está ausente lo tratamos
    // como "ghost case": se permite la transición contra PG y se salta el
    // re-insert Iceberg — si no, el operador quedaba bloqueado con un 404.
    let pgCase = null;
    try {
      const [row] = await pgQuery(
        `SELECT cp.id,
                cp.status,
                cp.severity      AS severity_text,
                cp.score         AS severity_score,
                cp.ioc_value,
                cp.classification,
                cp.escalation_suggested,
                idx.dedup_key
           FROM public.incident_cases_pg cp
           LEFT JOIN legacyhunt_soc.incident_case_index idx
             -- Cast del lado filtrado (no de la columna indexada) para usar el
             -- PK uuid de incident_case_index. El CASE corta el cast en ids
             -- hex32 (no-uuid), que nunca matchean igual → evita 22P02 y seq-scan.
             ON idx.case_id = (CASE WHEN cp.id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                                    THEN cp.id::uuid END)
          WHERE cp.id = $1`,
        [id],
      );
      pgCase = row ?? null;
    } catch (err) { return res.status(500).json({ error: err.message }); }

    let trinoRow = null;
    try {
      // No bloquear el cierre/transición si Trino está lento (metadata bloat de
      // incident_cases / carga): cap a 8 s. Si no responde a tiempo seguimos con
      // PG (primario para validar/persistir la transición); el sync a Iceberg lo
      // cubre el reconcile DAG. Antes el `await` colgaba ~115 s → Traefik 502.
      const rows = await Promise.race([
        runQuery(`SELECT * FROM ${TCASES} WHERE case_id = ${sq(id)} LIMIT 1`, SESSION),
        new Promise((resolve) => setTimeout(() => resolve(null), 8000)),
      ]);
      if (rows === null) {
        logger.warn("incidents.status.iceberg_fetch_timeout", { caseId: id, capMs: 8000 });
      }
      trinoRow = rows?.[0] ?? null;
    } catch (err) {
      logger.warn("incidents.status.iceberg_fetch_failed", { caseId: id, err: err.message });
    }

    if (!pgCase && !trinoRow) {
      return res.status(404).json({ error: "Caso no encontrado" });
    }

    // Validar transición contra el estado registrado en PG (primario) o Iceberg (fallback).
    const currentStatus = normalizeStatus(pgCase?.status ?? trinoRow?.status ?? "NUEVO");
    const allowed = VALID_TRANSITIONS[currentStatus] ?? new Set();
    if (!allowed.has(status)) {
      return res.status(422).json({
        error: `Transición inválida: ${currentStatus} → ${status}`,
        allowedTransitions: [...allowed],
      });
    }

    // RBAC granular: el rol del operador tiene que tener el cap del target.
    // Runs AFTER VALID_TRANSITIONS para dar el error más informativo primero.
    const rbac = await checkTransitionRbac(operatorCi, status);
    if (!rbac.ok) return res.status(rbac.status).json(rbac.body);

    // ── F1 (audit 2026-06-05): guard de REAPERTURA de un caso terminal ──────────
    // Reabrir (CERRADO/FALSO_POSITIVO → estado abierto) es sensible y el destino
    // EN_ANALISIS no tiene cap RBAC propio, así que el check anterior lo dejaría
    // pasar para cualquier rol. Exigimos rol LEADER/ADMIN + un reopenReason
    // explícito (campo `reason`, ≥ 20 chars) — paridad con TRANSITIONS y deja
    // rastro auditable de por qué se reabrió.
    if (TERMINAL.has(currentStatus) && !TERMINAL.has(status)) {
      const [opRow] = await pgQuery(
        `SELECT role_id FROM soc_operators WHERE id = $1 AND is_active = true`,
        [operatorCi],
      ).catch(() => []);
      const role = opRow?.role_id ?? null;
      if (!role || !REOPEN_ROLES.has(role)) {
        return res.status(403).json({
          error: "Reabrir un caso terminal requiere rol LEADER o ADMIN.",
          required_role: [...REOPEN_ROLES],
        });
      }
      if (String(reason ?? "").trim().length < REOPEN_REASON_MIN) {
        return res.status(422).json({
          error: `La reapertura requiere un motivo (campo reason) de al menos ${REOPEN_REASON_MIN} caracteres.`,
          field: "reason",
          minChars: REOPEN_REASON_MIN,
        });
      }
    }

    // ── M3 (audit 2026-06-05): classification preservando currentClassification ─
    // Antes pasaba currentClassification:null → podía pisar un outcome correcto
    // previo (p.ej. TRUE_POSITIVE) al re-cerrar. Fuente única decideClosureClassification,
    // misma que workflowEngine.transitionCase.
    const classDecision = decideClosureClassification({
      toStatus:    status,
      classification,
      currentClassification: pgCase?.classification ?? trinoRow?.classification ?? null,
      roleId: null,  // path humano manual; los flujos SYSTEM pasan por transitionCase
    });
    if (!classDecision.ok) {
      return res.status(400).json({ error: classDecision.message, ...classDecision.hint });
    }

    // ── M1 (audit 2026-06-05): gate 4-eyes para cerrar como FALSO_POSITIVO un caso
    //    marcado para escalación automática. Paridad con workflowEngine.transitionCase
    //    (R7): antes este endpoint NO lo aplicaba → un L1/L2 podía cerrar como FP un
    //    caso escalation_suggested usando el PATCH HTTP, evadiendo el control.
    //    Requiere: (a) justificación ≥ 80 chars, O (b) 2º aprobador LEADER/ADMIN.
    if (status === "FALSO_POSITIVO"
        && (pgCase?.escalation_suggested === true || trinoRow?.escalation_suggested === true)) {
      const justification = String(reason ?? "").trim();
      if (justification.length < 80) {
        const approver = String(secondApproverCi ?? "").trim();
        if (!approver) {
          return res.status(422).json({
            error: "Este caso fue marcado para escalación automática. Para cerrarlo como "
              + "FALSO_POSITIVO necesitás: (a) justificación de al menos 80 caracteres "
              + "(campo reason), O (b) aprobación de un segundo operador LEADER/ADMIN "
              + "(campo secondApproverCi).",
            field: "reason",
            minChars: 80,
          });
        }
        let approverRow;
        try {
          [approverRow] = await pgQuery(
            `SELECT id FROM soc_operators
              WHERE id = $1 AND is_active = true AND role_id IN ('LEADER','ADMIN')`,
            [approver],
          );
        } catch (err) { return res.status(500).json({ error: err.message }); }
        if (!approverRow) {
          return res.status(422).json({ error: `Segundo aprobador ${approver} inválido (no existe o no es LEADER/ADMIN).` });
        }
        if (String(approverRow.id) === String(operatorCi)) {
          return res.status(422).json({ error: "El segundo aprobador debe ser distinto del operador que cierra el caso." });
        }
      }
    }

    const now = new Date().toISOString();
    const sev = String((trinoRow?.severity_text ?? pgCase?.severity_text) ?? "MEDIUM").toUpperCase();
    const score = Number((trinoRow?.severity_score ?? pgCase?.severity_score) ?? 50);

    // Postmortem gate — paridad con workflowEngine.transitionCase (fix #8).
    // Audit 2026-05-27: postmortem_rate venía 0% porque este endpoint cerraba
    // sin pasar por transitionCase, bypaseando el gate. Para CRITICAL/HIGH/
    // MEDIUM exigimos que el caso ya tenga lessons_learned grabado (vía
    // PATCH /:id que sí acepta el campo). La UI debe popular el postmortem
    // ANTES de disparar el cierre.
    if (status === "CERRADO") {
      const SEV_REQUIRES_POSTMORTEM = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
      const POSTMORTEM_MIN_CHARS = 60;
      if (SEV_REQUIRES_POSTMORTEM.has(sev)) {
        // P2 #17: aceptar lessons_learned en el MISMO request. Si viene en el body
        // y cumple el mínimo, lo persistimos acá → cerrar deja de requerir 2 llamadas
        // (PATCH /:id para el postmortem + PATCH /:id/status). Si no viene, se exige
        // el que ya esté grabado (comportamiento previo).
        const incomingLl = String(lessonsLearned ?? "").trim();
        if (incomingLl.length >= POSTMORTEM_MIN_CHARS) {
          await pgQuery(
            `UPDATE incident_cases_pg SET lessons_learned = $2, updated_at = now() WHERE id = $1`,
            [id, incomingLl],
          ).catch((e) => logger.warn("incidents.status.ll_persist_failed", { caseId: id, err: e?.message }));
        }
        const [pmRow] = await pgQuery(
          `SELECT COALESCE(lessons_learned, '') AS ll FROM incident_cases_pg WHERE id = $1`,
          [id],
        );
        const existing = String(pmRow?.ll ?? "").trim();
        if (existing.length < POSTMORTEM_MIN_CHARS) {
          return res.status(422).json({
            error:
              `Postmortem requerido para cerrar casos ${sev} `
              + `(mínimo ${POSTMORTEM_MIN_CHARS} caracteres). `
              + `Envialo en el campo lessonsLearned de este request o grabalo vía PATCH /api/incidents/${id}.`,
            field: "lessons_learned",
            minChars: POSTMORTEM_MIN_CHARS,
            hint: "1) Causa raíz · 2) Prevención · 3) Mejora de proceso",
          });
        }
      }
    }

    // 1. PostgreSQL primero
    try {
      const detail = reason ? `${status}: ${reason}` : status;
      const tlEntry = buildTimelineEntry("STATUS_CHANGE", operatorCi, detail);
      // Normalizar classification: aceptamos FALSO_POSITIVO histórico y FALSE_POSITIVE.
      const classNormalized = classification
        ? String(classification).toUpperCase().replace(/FALSO_POSITIVO/, "FALSE_POSITIVE")
        : undefined;
      await pgUpsertCase(id, {
        severity:    sev,
        status,
        score,
        operatorId:  operatorCi ?? undefined,
        timelineEntry: tlEntry,
        ...(reason ? { closureReason: reason } : {}),
        ...(classNormalized ? { classification: classNormalized } : {}),
      });
      // P2 #18: outcome estructurado en el cierre (qué acción resolvió + causa raíz
      // categorizada) → habilita reporting "% por causa" y validar cierres reales.
      if ((status === "CERRADO" || status === "FALSO_POSITIVO") && (resolutionAction || rootCauseCategory)) {
        await pgQuery(
          `UPDATE incident_cases_pg
              SET resolution_action   = COALESCE($2, resolution_action),
                  root_cause_category = COALESCE($3, root_cause_category),
                  updated_at = now()
            WHERE id = $1`,
          [id, resolutionAction ?? null, rootCauseCategory ?? null],
        ).catch((e) => logger.warn("incidents.status.outcome_persist_failed", { caseId: id, err: e?.message }));
      }
    } catch (pgErr) {
      logger.error("incidents.status.pg_error", { caseId: id, err: pgErr.message });
    }

    // ── Reapertura: re-armar el SLA (audit 2026-06-05) ─────────────────────────
    // Cuando un caso terminal (FALSO_POSITIVO) se reabre a un estado abierto,
    // las marcas `sla_*_at` quedaban en enrichment_data y el scheduler
    // (checkSlaBreaches) las usa como idempotencia → el caso reabierto NUNCA
    // volvía a alertar por breach. Además el SLA está anclado a created_at, así
    // que un FP viejo reabierto leía como 400%+ vencido al instante.
    // Fix: al reabrir limpiamos las 4 marcas y sellamos `sla_reopened_at`. El
    // scheduler ancla elapsed/ventana a GREATEST(created_at, sla_reopened_at),
    // dándole al caso reabierto un reloj SLA fresco.
    if (TERMINAL.has(currentStatus) && !TERMINAL.has(status)) {
      void pgQuery(
        `UPDATE incident_cases_pg
            SET enrichment_data = jsonb_set(
                  COALESCE(enrichment_data,'{}'::jsonb)
                    - 'sla_warning_sent_at'
                    - 'sla_alert_sent_at'
                    - 'sla_alert_200_at'
                    - 'sla_alert_400_at',
                  '{sla_reopened_at}', to_jsonb(now()::text)),
                resolved_at = NULL,
                -- P2 #19: contador de reaperturas → detecta cierres prematuros / pingpong.
                reopened_count = COALESCE(reopened_count, 0) + 1,
                sla_breach_at = NULL
          WHERE id = $1`,
        [id],
      ).catch((e) => logger.warn("incidents.status.sla_rearm_failed", { caseId: id, err: e?.message }));
    }

    // 2. Iceberg vía cola persistente (P4 C3, audit 2026-05-13).
    //    Antes era setImmediate fire-and-forget; si Trino caía o el process
    //    moría, el row Iceberg quedaba viejo sin retry. Ahora encolamos un
    //    job 'status_sync' en iceberg_merge_queue — el worker drena con
    //    retry exponencial y el reaper de C2 cubre crashes del worker.
    //    Solo encolamos si tenemos el row Iceberg completo: el job re-usa
    //    todos los campos críticos (mitre_*, score_breakdown, etc.).
    if (trinoRow) {
      try {
        await enqueueStatusSyncJob({
          caseId: id,
          trinoRow: {
            ...trinoRow,
            status,
            updated_at: now,
            ...(reason     ? { closure_reason: reason }  : {}),
            ...(operatorCi ? { assigned_to: operatorCi } : {}),
          },
          ci: operatorCi ?? "system",
          now,
        });
      } catch (qErr) {
        // QUEUE_FULL u otro fallo del enqueue. PG ya commiteó: la respuesta
        // sigue siendo 200 (el operador ve el cambio en su cola operacional).
        // El log alerta para que el shift manager mire /merge-queue/stats.
        logger.error("incidents.iceberg_status_sync_enqueue_failed", { caseId: id, err: qErr.message });
      }
    } else {
      logger.warn("incidents.status.ghost_case_skip_iceberg_sync", { caseId: id });
    }

    // Sincronizar estado al índice canónico (audit 2026-05-26). El DAG
    // sync_daily lee este índice para dedup; sin esto se reabren casos
    // ya tomados como NUEVO. Best-effort: errores no bloquean la respuesta.
    void mirrorCasesToIndex([id]).catch(() => {});

    getIo()?.emit("incident:status_change", { id, status });

    // ── Cierre: marcar tareas abiertas como SKIPPED (A4 audit 2026-06-05) ──────
    if (status === "CERRADO" || status === "FALSO_POSITIVO") {
      void pgQuery(
        `UPDATE case_tasks
            SET status = 'SKIPPED',
                completed_at = COALESCE(completed_at, now()),
                updated_at = now()
          WHERE case_id = $1 AND status IN ('OPEN','IN_PROGRESS')`,
        [id],
      ).catch((e) => logger.warn("incidents.status.skip_tasks_failed", { caseId: id, err: e?.message }));
    }

    // ── Supresión automática al cerrar o marcar FP ─────────────────────────
    if (status === "CERRADO" || status === "FALSO_POSITIVO") {
      const suppressReason = status === "FALSO_POSITIVO" ? "FALSO_POSITIVO" : "CERRADO";
      setImmediate(async () => {
        try {
          const dk = String((trinoRow?.dedup_key ?? pgCase?.dedup_key) ?? "");
          if (!dk) return;
          await pgQuery(
            `INSERT INTO legacyhunt_soc.case_suppressions
               (dedup_key, reason, severity, suppressed_until, suppressed_by, original_case_id, original_ioc)
             VALUES (
               $1, $2, $3,
               NOW() + (legacyhunt_soc.suppression_days($2, $3) || ' days')::interval,
               $4, $5::uuid, $6
             )
             ON CONFLICT (dedup_key) DO UPDATE SET
               reason           = EXCLUDED.reason,
               severity         = EXCLUDED.severity,
               suppressed_until = CASE
                 WHEN case_suppressions.reason = EXCLUDED.reason
                   THEN GREATEST(case_suppressions.suppressed_until, EXCLUDED.suppressed_until)
                 ELSE EXCLUDED.suppressed_until
               END,
               suppressed_by    = EXCLUDED.suppressed_by,
               original_case_id = EXCLUDED.original_case_id,
               updated_at       = NOW()`,
            [dk, suppressReason, sev, operatorCi ?? "system", id, String((trinoRow?.ioc_value ?? pgCase?.ioc_value) ?? "")],
          );
          await pgQuery(
            `INSERT INTO legacyhunt_soc.incident_case_audit (case_id, dedup_key, action, detail)
             VALUES ($1::uuid, $2, 'SUPPRESSION_SET', $3::jsonb)`,
            [id, dk, JSON.stringify({ reason: suppressReason, severity: sev, by: operatorCi ?? "system" })],
          );
        } catch (sErr) {
          logger.error("incidents.status.suppression_insert_failed", { caseId: id, err: sErr.message });
        }
      });
    }

    if (isSlackEnabled() && status === "ESCALADO") {
      try {
        await sendSlackAlert({
          text: `⚠️ *CASO ESCALADO — ${sev}*\n*Caso:* ${id}\n*IOC:* ${(trinoRow?.ioc_value ?? pgCase?.ioc_value) ?? "—"}\n*Operador:* ${operatorCi ?? "—"}\n*Motivo:* ${reason ?? "—"}`,
        });
      } catch { /* no interrumpir si Slack falla */ }
    }

    res.json({ ok: true });
  });

  // ── POST /api/incidents/:id/contain ──────────────────────────────────────────
  // P1 #5 (backlog 2026-06-07) — "aplicar acción recomendada" (SOAR-lite).
  // Registra una CONTENCIÓN del caso: (a) evento CONTAINMENT en case_timeline_events
  // → alimenta el MTTC explícito (mttc_explicit en soc_kpis_window, hoy en 0); y
  // (b) si hay `SOAR_WEBHOOK_URL` configurado, dispara el webhook con la acción +
  // IOC para que un SOAR/automation (block IP en FortiGate/OPNsense, disable user)
  // la ejecute. Sin webhook → sólo deja el rastro de contención (el analista la
  // aplicó out-of-band). NO cambia el estado del caso (la transición la decide el
  // operador aparte). Identidad = JWT.
  router.post("/:id/contain", async (req, res) => {
    const { id } = req.params;
    const { action, note } = req.body ?? {};
    const UUID_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
    if (!UUID_RE.test(String(id))) return res.status(400).json({ error: "id inválido" });

    const operatorCi = await resolveJwtOperatorCi(req);

    let c;
    try {
      const [row] = await pgQuery(
        `SELECT id, ioc_value, severity, status, recommended_action FROM incident_cases_pg WHERE id = $1`,
        [id],
      );
      c = row;
    } catch (err) { return res.status(500).json({ error: err.message }); }
    if (!c) return res.status(404).json({ error: "Caso no encontrado" });

    const actionLabel = String(action ?? c.recommended_action ?? "Contención manual").slice(0, 300);

    // SOAR webhook opcional (best-effort, no bloquea el registro de contención).
    const hook = process.env.SOAR_WEBHOOK_URL;
    const soar = { configured: Boolean(hook), ok: false };
    if (hook) {
      try {
        const r = await fetch(hook, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            event: "contain", caseId: id, ioc: c.ioc_value,
            action: actionLabel, severity: c.severity, operator: operatorCi ?? "system",
          }),
          signal: AbortSignal.timeout(8000),
        });
        soar.ok = r.ok;
        if (!r.ok) logger.warn("incidents.contain.soar_non_ok", { caseId: id, status: r.status });
      } catch (e) {
        logger.warn("incidents.contain.soar_failed", { caseId: id, err: String(e?.message ?? e) });
      }
    }

    // Evento CONTAINMENT → MTTC explícito.
    try {
      await pgQuery(
        `INSERT INTO case_timeline_events
           (id, case_id, event_type, phase, title, description, operator_ci, source, metadata)
         VALUES ($1, $2, 'CONTAINMENT', 'RESPONSE_L3', $3, $4, $5, $6, $7)`,
        [
          randomUUID(), id, actionLabel, note ?? null, operatorCi ?? "system",
          soar.configured ? "SOAR" : "MANUAL",
          JSON.stringify({ action: actionLabel, ioc: c.ioc_value, soar }),
        ],
      );
    } catch (err) {
      return res.status(500).json({ error: `No se pudo registrar la contención: ${err.message}` });
    }

    getIo()?.emit("incident:contained", { id, action: actionLabel });
    res.json({ ok: true, contained: true, soar });
  });

  // ── POST /api/incidents/:id/severity ────────────────────────────────────────
  // Cambia la severidad de un caso existente. Operación auditada (timeline
  // event SEVERITY_CHANGE) y limitada a operadores activos en soc_operators.
  //
  // pgUpsertCase NO toca `severity` en UPDATE por diseño (evita downgrades
  // implícitos al re-upsert). Por eso este endpoint hace un UPDATE directo
  // de la columna, registrando la transición en el timeline para trazabilidad.
  router.post("/:id/severity", async (req, res) => {
    const { id } = req.params;
    const { severity: rawSev, reason, operatorCi: bodyCi } = req.body ?? {};

    const sev = String(rawSev ?? "").toUpperCase().trim();
    const VALID = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]);
    if (!VALID.has(sev)) {
      return res.status(400).json({ error: "Severity inválida. Valores: CRITICAL/HIGH/MEDIUM/LOW/NEGLIGIBLE." });
    }

    // Identidad: JWT primero, body fallback.
    const jwtCi = await resolveJwtOperatorCi(req);
    const operatorCi = jwtCi ?? (bodyCi ? String(bodyCi).trim() : null);
    if (!operatorCi) {
      return res.status(401).json({ error: "Operador no resuelto (JWT o body.operatorCi)." });
    }
    try {
      const opRows = await pgQuery(
        `SELECT id FROM soc_operators WHERE id = $1 AND is_active = true LIMIT 1`,
        [operatorCi],
      );
      if (!opRows.length) {
        return res.status(403).json({ error: `Operador ${operatorCi} no registrado o inactivo.` });
      }
    } catch (e) {
      logger.warn("incidents.severity.soc_operators_check_failed", { caseId: id, err: e.message });
    }

    // Lookup del estado previo (para el evento de timeline).
    let prevSev = null;
    try {
      const rows = await pgQuery(`SELECT severity FROM incident_cases_pg WHERE id = $1 LIMIT 1`, [id]);
      if (!rows.length) return res.status(404).json({ error: `Caso ${id} no encontrado.` });
      prevSev = String(rows[0].severity ?? "").toUpperCase();
    } catch (e) {
      return res.status(500).json({ error: `Error al consultar caso: ${e.message}` });
    }

    if (prevSev === sev) {
      return res.json({ ok: true, id, severity: sev, unchanged: true });
    }

    try {
      await pgQuery(
        `UPDATE incident_cases_pg
            SET severity   = $2,
                -- M3 audit 2026-06-05: el SLA del caso depende de severity, así que
                -- reseteamos las marcas de hito SLA para que el scheduler reevalúe
                -- preaviso/breach bajo el nuevo umbral (si subió, marcas viejas lo
                -- bloqueaban; si bajó, evitamos breaches espurios).
                enrichment_data = (COALESCE(enrichment_data, '{}'::jsonb)
                  - 'sla_warning_sent_at' - 'sla_alert_sent_at'
                  - 'sla_alert_200_at' - 'sla_alert_400_at'),
                updated_at = now()
          WHERE id = $1`,
        [id, sev],
      );

      // M3: rescalar due_at de las tareas abiertas en proporción al nuevo SLA y
      // limpiar sus marcas SLA. Sin esto, una subida LOW→CRITICAL dejaba las
      // tareas con due_at calculado al SLA viejo (laxo).
      try {
        const oldSla = getSlaMin(prevSev || "MEDIUM");
        const newSla = getSlaMin(sev);
        const ratio = oldSla > 0 ? newSla / oldSla : 1;
        if (ratio !== 1) {
          await pgQuery(
            `UPDATE case_tasks
                SET due_at = created_at + ((due_at - created_at) * $2::double precision),
                    sla_warned_at = NULL,
                    sla_breached_at = NULL,
                    updated_at = now()
              WHERE case_id = $1
                AND status IN ('OPEN','IN_PROGRESS')
                AND due_at IS NOT NULL`,
            [id, ratio],
          );
        }
      } catch (e) {
        logger.warn("incidents.severity.task_due_rescale_failed", { caseId: id, err: e.message });
      }

      // Audit en case_timeline_events — phase IDENTIFICATION para que aparezca
      // en la línea de tiempo del caso con el operador y la razón.
      const ts = new Date().toISOString();
      const reasonClean = reason ? String(reason).slice(0, 1000) : null;
      await pgQuery(
        `INSERT INTO case_timeline_events
           (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source, metadata)
         VALUES ($1,$2,$3::timestamptz,'SEVERITY_CHANGE','IDENTIFICATION',$4,$5,$6,'manual',$7)`,
        [
          randomUUID(), id, ts,
          `Cambio de severidad: ${prevSev || "—"} → ${sev}`,
          reasonClean ?? `Severidad ajustada manualmente por ${operatorCi}.`,
          operatorCi,
          JSON.stringify({ from: prevSev, to: sev, reason: reasonClean }),
        ],
      ).catch((e) => logger.warn("incidents.severity.timeline_insert_failed", { caseId: id, err: e.message }));

      try {
        getIo()?.emit("incident:severity_change", { id, from: prevSev, to: sev, operatorCi });
      } catch { /* */ }

      return res.json({ ok: true, id, severity: sev, prevSeverity: prevSev || null });
    } catch (err) {
      return res.status(500).json({ error: `Error al actualizar severidad: ${err.message}` });
    }
  });

  // ── POST /api/incidents/:id/escalate ────────────────────────────────────────
  router.post("/:id/escalate", async (req, res) => {
    const { id } = req.params;
    const {
      escalationLevel,
      escalatedTo,
      escalationReason,
      operatorCi: bodyCi,
    } = req.body ?? {};

    // Identidad autoritativa = JWT. Body es fallback; log si difiere.
    const jwtCi = await resolveJwtOperatorCi(req);
    const rawBodyCi = bodyCi ? String(bodyCi).trim() : null;
    if (jwtCi && rawBodyCi && rawBodyCi !== jwtCi) {
      logger.warn("incidents.escalate.body_ci_mismatch_use_jwt", {
        jwtCi, bodyCi: rawBodyCi, caseId: id, user: req.user?.preferred_username,
      });
    }
    const operatorCi = jwtCi ?? rawBodyCi;

    const VALID_LEVELS = new Set(["TIER1","TIER2","IR","EXECUTIVE","EXTERNAL"]);
    if (!VALID_LEVELS.has(escalationLevel))
      return res.status(400).json({ error: "escalationLevel inválido" });
    if (!escalationReason?.trim())
      return res.status(400).json({ error: "escalationReason requerido" });

    // RBAC: sólo roles con cap de escalar (cualquiera de los dos niveles)
    // pueden usar este endpoint. El mapeo fino TIER1→l2 / TIER2→l3 se deja
    // para una fase posterior si se necesita separación por tier.
    const rbac = await checkTransitionRbac(operatorCi, "ESCALADO");
    if (!rbac.ok) return res.status(rbac.status).json(rbac.body);

    let rows;
    try { rows = await runQuery(`SELECT * FROM ${TCASES} WHERE case_id = ${sq(id)} LIMIT 1`, SESSION); }
    catch (err) { return res.status(500).json({ error: err.message }); }

    if (!rows.length) return res.status(404).json({ error: "Caso no encontrado" });

    const currentStatus = normalizeStatus(rows[0].status);
    if (!VALID_TRANSITIONS[currentStatus]?.has("ESCALADO")) {
      return res.status(422).json({
        error: `No se puede escalar desde el estado ${currentStatus}`,
      });
    }

    const r   = rows[0];
    const now = new Date().toISOString();
    const sev = String(r.severity_text ?? "HIGH").toUpperCase();

    // 1. PostgreSQL: escalación estructurada + timeline
    try {
      const detail = `${escalationLevel} → ${escalatedTo ?? "—"}: ${escalationReason}`;
      const tlEntry = buildTimelineEntry("ESCALATE", operatorCi, detail);
      await pgUpsertCase(id, {
        severity:        sev,
        status:          "ESCALADO",
        score:           Number(r.severity_score ?? 50),
        operatorId:      operatorCi ?? undefined,
        escalationLevel,
        escalatedTo:     escalatedTo?.trim() ?? null,
        escalatedAt:     now,
        escalationReason: escalationReason.trim(),
        timelineEntry:   tlEntry,
      });
    } catch (pgErr) {
      logger.error("incidents.escalate.pg_error", { caseId: id, err: pgErr.message });
    }

    // 2. Iceberg vía cola persistente (P4 C3) — ver comentario en /:id/status.
    try {
      await enqueueStatusSyncJob({
        caseId: id,
        trinoRow: {
          ...r,
          status:            "ESCALADO",
          updated_at:        now,
          escalation_level:  escalationLevel,
          escalated_to:      escalatedTo?.trim() ?? null,
          escalated_at:      now,
          escalation_reason: escalationReason.trim(),
          ...(operatorCi ? { assigned_to: operatorCi } : {}),
        },
        ci: operatorCi ?? "system",
        now,
      });
    } catch (qErr) {
      logger.error({ msg: "iceberg_status_sync_enqueue_failed", caseId: id, error: qErr.message });
    }

    // Sincronizar estado al índice canónico (audit 2026-05-26).
    void mirrorCasesToIndex([id]).catch(() => {});

    const io = getIo();
    io?.emit("incident:escalated", {
      id,
      escalationLevel,
      escalatedTo:     escalatedTo ?? null,
      escalationReason,
      escalatedBy:     operatorCi  ?? "system",
      escalatedAt:     now,
    });

    // Notificar al operador que tenía asignado el caso (si es distinto al escalador)
    const prevOperator = r.assigned_to ?? null;
    if (prevOperator && prevOperator !== (operatorCi ?? "")) {
      setImmediate(async () => {
        try {
          await createNotification({
            operatorId: prevOperator,
            caseId:     id,
            type:       "CASE_ESCALATED",
            priority:   "HIGH",
            title:      `Caso ${id.slice(0,7).toUpperCase()} escalado — ${escalationLevel}`,
            body:       `Escalado por ${operatorCi ?? "sistema"} → ${escalatedTo ?? "—"}: ${escalationReason}`,
            io,
          });
        } catch { /* best-effort */ }
      });
    }

    if (isSlackEnabled()) {
      // P2-11 audit 2026-05-26: antes este catch tragaba todos los errores y
      // dejaba slack_notified_at en NULL (24% de cobertura en HIGH ESCALADO).
      // Ahora log explícito + persistencia de la marca solo si el envío fue OK.
      try {
        const slackR = await sendSlackAlert({
          text: `⚠️ *INCIDENTE ESCALADO — ${escalationLevel}*\n*Caso:* ${id}\n*IOC:* ${r.ioc_value ?? "—"}\n*Severidad:* ${sev}\n*Escalado a:* ${escalatedTo ?? "—"}\n*Motivo:* ${escalationReason}`,
        });
        if (slackR?.ok) {
          pgQuery(
            `UPDATE incident_cases_pg SET slack_notified_at = now() WHERE id = $1`, [id],
          ).catch((e) => logger.warn("incidents.escalate.slack_notified_at_update_failed", { caseId: id, err: e?.message }));
        } else {
          logger.warn("incidents.escalate.slack_failed", { caseId: id, slackError: slackR?.error, status: slackR?.status });
        }
      } catch (slackErr) {
        logger.warn("incidents.escalate.slack_exception", { caseId: id, err: slackErr?.message });
      }
    }

    res.json({ ok: true, status: "ESCALADO", escalationLevel });
  });

  // ── POST /api/incidents/:id/notify-slack ─────────────────────────────────────
  router.post("/:id/notify-slack", async (req, res) => {
    if (!isSlackEnabled()) return res.status(503).json({ error: "Slack no configurado" });

    const { id }     = req.params;
    const { reason } = req.body ?? {};

    // ── Lookups: PG primary (siempre disponible) + Trino best-effort para scores
    let pgRow;
    try {
      const pgRows = await pgQuery(
        `SELECT id, case_number, severity, status, score, ioc_value, ioc_type, source_log,
                mitre_tactic_id, mitre_tactic_name, mitre_technique_id,
                recommended_action, enrichment_data
         FROM incident_cases_pg WHERE id = $1 LIMIT 1`, [id]
      );
      pgRow = pgRows[0] ?? null;
    } catch { /* continúa — intentará Trino */ }

    // Trino fallback si PG no tiene el registro (caso muy raro)
    if (!pgRow) {
      let trinoRows = [];
      try { trinoRows = await runQuery(`SELECT * FROM ${TCASES} WHERE case_id = ${sq(id)} LIMIT 1`, SESSION); }
      catch { /* ignorar */ }
      if (!trinoRows.length) return res.status(404).json({ error: "Caso no encontrado" });
      // Normalizar campos Trino → formato PG esperado abajo
      const tr = trinoRows[0];
      pgRow = {
        id, severity: tr.severity_text, status: tr.status,
        score: Number(tr.severity_score ?? 50),
        ioc_value: tr.ioc_value, ioc_type: tr.ioc_type, source_log: tr.source_log,
        mitre_tactic_id: tr.mitre_tactic_id, mitre_tactic_name: tr.mitre_tactic_name,
        mitre_technique_id: tr.mitre_technique_id,
        recommended_action: tr.recommended_action ?? tr.notes,
        enrichment_data: {},
      };
    }

    // ── Score breakdown: PG enrichment_data → Trino best-effort
    const ed = typeof pgRow.enrichment_data === "string"
      ? JSON.parse(pgRow.enrichment_data || "{}")
      : (pgRow.enrichment_data ?? {});

    let sm = ed.score_mitre   != null ? Number(ed.score_mitre)   : null;
    let se = ed.score_evidence != null ? Number(ed.score_evidence) : null;
    let sw = ed.score_wazuh   != null ? Number(ed.score_wazuh)   : null;
    let smp = ed.score_misp   != null ? Number(ed.score_misp)    : null;
    let sc = ed.score_context  != null ? Number(ed.score_context)  : null;

    // Intentar Trino para scores si no están en PG (best-effort, no bloquea)
    if (sm == null || se == null || sw == null) {
      try {
        const sr = await runQuery(
          `SELECT score_mitre, score_evidence, score_wazuh, score_misp, score_context
           FROM ${TC} WHERE incident_key = ${sq(id)} LIMIT 1`, SESSION
        );
        if (sr.length) {
          if (sm  == null && sr[0].score_mitre    != null) sm  = Number(sr[0].score_mitre);
          if (se  == null && sr[0].score_evidence != null) se  = Number(sr[0].score_evidence);
          if (sw  == null && sr[0].score_wazuh    != null) sw  = Number(sr[0].score_wazuh);
          if (smp == null && sr[0].score_misp     != null) smp = Number(sr[0].score_misp);
          if (sc  == null && sr[0].score_context  != null) sc  = Number(sr[0].score_context);
        }
      } catch { /* Trino puede estar frío — no bloquear */ }
    }

    const severity = String(pgRow.severity ?? "MEDIUM").toUpperCase();
    const score    = Number(pgRow.score ?? 50);
    const agentName = ed.agent_name ?? ed.host_agente_log ?? "—";

    const mitreParts = [];
    if (pgRow.mitre_tactic_id && pgRow.mitre_tactic_name)
      mitreParts.push(`${pgRow.mitre_tactic_id} - ${pgRow.mitre_tactic_name}`);
    if (pgRow.mitre_technique_id)
      mitreParts.push(pgRow.mitre_technique_id);
    const mitre = mitreParts.length ? mitreParts.join(" / ") : null;

    const block = buildSocCaseAdoptionBlock({
      caseId:       id,
      caseNumber:   pgRow.case_number ?? null,
      severity,
      rule:         pgRow.source_log      ?? "—",
      agent:        agentName,
      srcIp:        pgRow.ioc_value       ?? "—",
      iocType:      pgRow.ioc_type        ?? "ip",
      mitre,
      eventExtract: pgRow.recommended_action ?? null,
      score,
      scoreBreakdown: { mitre: sm, evidence: se, wazuh: sw, misp: smp, context: sc },
      reason:       reason ?? "manual",
      dedupe:       false,
    });

    // block nunca es null aquí (dedupe: false) — enviar y verificar resultado
    const slackResult = await sendSlackAlert(block);
    if (!slackResult.ok) {
      logger.warn({ caseId: id, slackError: slackResult.error, status: slackResult.status },
        "[incidents][notify-slack] Slack rechazó el mensaje");
      return res.status(502).json({
        error: `Slack rechazó el mensaje: ${slackResult.error ?? slackResult.body ?? "respuesta no-OK"}`,
      });
    }

    // Registrar en PG para historial
    pgQuery(
      `UPDATE incident_cases_pg SET slack_notified_at = now() WHERE id = $1`, [id]
    ).catch((e) => logger.warn("[incidents][notify-slack] slack_notified_at_update_failed", { caseId: id, err: e?.message }));

    // KPI/actividad (2026-06-16): la quick action "Notificar Slack" es una acción
    // del operador → deja rastro MANUAL para alimentar actividad/followup.
    resolveJwtOperatorCi(req).then((opCi) =>
      addTimelineEvent(id, {
        eventType: "SLACK_NOTIFY",
        title: "Notificación SOC enviada por Slack",
        description: reason ? `motivo: ${reason}` : undefined,
        operatorCi: opCi, source: "MANUAL",
      }),
    ).catch((e) => logger.warn("[incidents][notify-slack] timeline_failed", { caseId: id, err: e?.message }));

    res.json({ ok: true });
  });

  // ── POST /api/incidents/:id/notify-client ──────────────────────────────────────
  // Envía un email al cliente con el veredicto/estado del incidente y lo registra
  // en el Timeline del caso. El cuerpo lo compone el frontend (NotifyClientModal).
  router.post("/:id/notify-client", async (req, res) => {
    const { id } = req.params;
    const { to, subject, body } = req.body ?? {};
    const operatorCi =
      resolveJwtOperatorCi(req) || req.body?.operatorCi || req.user?.preferred_username || "system";

    if (!to || !/\S+@\S+\.\S+/.test(String(to).trim()))
      return res.status(400).json({ error: "Destinatario (to) inválido" });
    if (!subject || !String(subject).trim())
      return res.status(400).json({ error: "Asunto requerido" });
    if (!body || !String(body).trim())
      return res.status(400).json({ error: "Cuerpo del mensaje requerido" });

    // El caso debe existir (PG es la fuente de verdad para casos gestionados).
    let exists = false;
    try {
      const rows = await pgQuery(`SELECT id FROM incident_cases_pg WHERE id = $1 LIMIT 1`, [id]);
      exists = rows.length > 0;
    } catch (e) {
      logger.warn("[incidents][notify-client] lookup_failed", { caseId: id, err: e?.message });
    }
    if (!exists) return res.status(404).json({ error: "Caso no encontrado" });

    const text = String(body);
    const html = `<pre style="font-family:inherit;white-space:pre-wrap;margin:0">${
      text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    }</pre>`;

    const result = await sendMail({ to: String(to).trim(), subject: String(subject).trim(), text, html });
    if (!result.ok) {
      const unconfigured = /SMTP no configurado/i.test(result.error ?? "");
      return res.status(unconfigured ? 503 : 502).json({ error: result.error ?? "No se pudo enviar el email" });
    }

    // Registrar en el timeline (best-effort, no bloquea la respuesta).
    addTimelineEvent(id, {
      eventType: "CLIENT_NOTIFY",
      title: `Notificación enviada al cliente`,
      description: `Email a ${String(to).trim()} — ${String(subject).trim()}`,
      operatorCi,
      source: "MANUAL",
      metadata: { to: String(to).trim(), subject: String(subject).trim() },
    }).catch((e) => logger.warn("[incidents][notify-client] timeline_failed", { caseId: id, err: e?.message }));

    res.json({ ok: true });
  });

  // ── POST /api/incidents/bulk-sync-pending ──────────────────────────────────────
  // Promueve clasificaciones con criterios OK (o force) que aún NO tienen caso en incident_cases.
  // Parámetros body: { operatorCi, force?, days?, minScore?, includeLowNegligible? }
  router.post("/bulk-sync-pending", async (req, res) => {
    const {
      operatorCi,
      force            = false,
      days             = 30,
      minScore         = 10,
      includeLowNegligible = true,
    } = req.body ?? {};

    if (!operatorCi || String(operatorCi).trim().length < 5)
      return res.status(400).json({ error: "CI inválido" });

    const ci  = String(operatorCi).trim();
    const now = new Date().toISOString();
    const anchor = now.slice(0, 10);
    const SEV_RANK = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NEGLIGIBLE: 5 };

    // Fast dedup: fetch active ioc_values from PostgreSQL (avoids slow Trino-Trino JOIN)
    let activeIocSet = new Set();
    try {
      const pgActive = await pgQuery(`
        SELECT DISTINCT ioc_value FROM incident_cases_pg
        WHERE status NOT IN ('CERRADO','FALSO_POSITIVO')
          AND last_seen >= now() - INTERVAL '30 days'
      `);
      activeIocSet = new Set(pgActive.map(r => String(r.ioc_value)));
    } catch { /* if PG fails, proceed without dedup filter */ }

    // Fetch classifications from Trino (simple scan, no JOIN)
    const sevFilter = includeLowNegligible
      ? `severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE')`
      : `severity IN ('CRITICAL','HIGH','MEDIUM')`;

    const sqlPending = `
      SELECT *
      FROM ${TC}
      WHERE dt >= current_date - INTERVAL '${Number(days)}' DAY
        AND dt IS NOT NULL
        AND ${sevFilter}
        AND CAST(COALESCE(score, 0) AS INTEGER) >= ${Number(minScore)}
      ORDER BY
        CASE UPPER(COALESCE(severity,''))
          WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
          ELSE 5 END ASC,
        score DESC NULLS LAST
      LIMIT 1000`;

    let allRows;
    try { allRows = await runQuery(sqlPending, SESSION); }
    catch (err) { return res.status(500).json({ error: err.message }); }

    // Filter in Node.js using the PostgreSQL active-ioc set
    const pending = activeIocSet.size > 0
      ? allRows.filter(r => !activeIocSet.has(String(r.ioc_value ?? ""))).slice(0, 500)
      : allRows.slice(0, 500);

    if (pending.length === 0) return res.json({ ok: true, synced: 0, skipped: 0, total: 0 });

    // Respond immediately — processing happens in background to avoid nginx timeout
    res.json({ ok: true, started: true, total: pending.length, synced: 0, skipped: 0 });

    setImmediate(async () => {
      let synced = 0, skipped = 0;
      for (const row of pending) {
        const sev = String(row.severity ?? "LOW").toUpperCase();
        const scoreParsed = Number(row.score ?? 0);
        const caseId = randomUUID();
        try {
          await trinoExec(buildCasesInsert({
            case_id:           caseId,
            dedup_key:         row.dedup_key ?? "",
            ioc_value:         String(row.ioc_value ?? "").trim(),
            ioc_type:          String(row.ioc_type ?? "ip").toLowerCase(),
            source_log:        String(row.source_log ?? "bulk-sync"),
            mitre_tactic_id:   row.mitre_tactic_id ?? null,
            mitre_tactic_name: row.mitre_tactic_name ?? null,
            source_category:   "bulk_sync",
            severity_text:     sev,
            severity_rank:     SEV_RANK[sev] ?? 4,
            severity_score:    scoreParsed,
            confidence_level:  row.confidence_level ?? null,
            status:            "NUEVO",
            occurrence_count:  1,
            first_seen:        now,
            last_seen:         now,
            anchor_dt:         anchor,
            linked_evidence:   String(row.incident_key ?? ""),
            score_breakdown:   null,
            notes:             `Sincronizado en lote por ${ci}`,
            assigned_to:       null,
            closure_reason:    null,
            created_at:        now,
            updated_at:        now,
            adopted_at:        null,
            escalation_level:  null,
            escalated_to:      null,
            escalated_at:      null,
            escalation_reason: null,
            recommended_action: null,
          }), SESSION);
          try {
            await pgUpsertCase(caseId, {
              severity:    sev,
              status:      "NUEVO",
              score:       scoreParsed,
              operatorId:  ci,
              // Origen del evento — sin esto la UI no puede resolver el sensor
              iocValue:        String(row.ioc_value ?? "").trim() || undefined,
              iocType:         String(row.ioc_type ?? "ip").toLowerCase(),
              sourceLog:       String(row.source_log ?? "bulk-sync"),
              mitreTacticId:   row.mitre_tactic_id   ?? undefined,
              mitreTacticName: row.mitre_tactic_name ?? undefined,
            });
          } catch { /* non-critical */ }
          synced++;
        } catch { skipped++; }
      }

      getIo()?.emit("incident:bulk-sync-done", { source: "bulk-sync", synced, skipped, total: pending.length });
    });
  });

  // ── POST /api/incidents/bulk-escalate-unadopted ────────────────────────────────
  // Escala a TIER1 todos los casos NUEVO sin adoptar que superen el umbral de tiempo.
  // Parámetros: { operatorCi, dryRun? }
  router.post("/bulk-escalate-unadopted", async (req, res) => {
    const { operatorCi: bodyCi, dryRun = false } = req.body ?? {};

    // Identidad autoritativa = JWT (ver resolveJwtOperatorCi).
    const jwtCi = await resolveJwtOperatorCi(req);
    const rawBodyCi = bodyCi ? String(bodyCi).trim() : null;
    if (jwtCi && rawBodyCi && rawBodyCi !== jwtCi) {
      logger.warn("incidents.bulk_escalate.body_ci_mismatch_use_jwt", {
        jwtCi, bodyCi: rawBodyCi, user: req.user?.preferred_username,
      });
    }
    const ci = jwtCi ?? rawBodyCi;
    if (!ci || ci.length < 5)
      return res.status(400).json({ error: "CI inválido" });

    // RBAC: acción de alto impacto — requiere cap de escalar.
    const rbac = await checkTransitionRbac(ci, "ESCALADO");
    if (!rbac.ok) return res.status(rbac.status).json(rbac.body);

    const now = new Date().toISOString();

    // PG-first: la fuente autoritativa para "qué casos están sin adoptar" es
    // `incident_cases_pg`. La query original iba contra Iceberg `incident_cases`
    // cuyo planning tarda 2-3 min por metadata explotada (Trino 435 no
    // auto-limpia). PG responde <100ms y no requiere el cruce posterior de
    // status porque ya es la fuente de verdad.
    //
    // Equivalencias de columnas: id=case_id, severity=severity_text,
    // score=severity_score, operator_id=assigned_to, created_at=first_seen.
    // Devolvemos los alias que el resto del handler espera para que el código
    // downstream (trinoExec + DELETE/INSERT Iceberg) no cambie.
    const sqlUnadopted = `
      SELECT id                 AS case_id,
             ioc_value,
             ioc_type,
             source_log,
             mitre_tactic_id,
             severity           AS severity_text,
             score              AS severity_score,
             created_at         AS first_seen,
             last_seen,
             status,
             occurrence_count,
             anchor_dt
        FROM incident_cases_pg
       WHERE anchor_dt >= current_date - INTERVAL '90 days'
         AND status IN ('NUEVO', 'EN_ANALISIS')
         AND (operator_id IS NULL OR operator_id = '')
       ORDER BY
         CASE severity
           WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
           WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5
         END ASC,
         created_at ASC
       LIMIT 500`;

    let unadopted;
    try { unadopted = await pgQuery(sqlUnadopted, []); }
    catch (err) { return res.status(500).json({ error: err.message }); }

    if (unadopted.length === 0) return res.json({ ok: true, escalated: 0, below_threshold: 0 });
    // PG ya es la verdad operacional — el filtro por `status IN (...)` sobre PG
    // reemplaza al cruce Iceberg↔PG que hacía la versión anterior.
    const skippedByPgStatus = 0;

    // Resolver destinatario real: SM activo → fallback LEADER → literal.
    let targetManager = await getActiveShiftManager();
    let targetSource  = targetManager ? "SHIFT_MANAGER" : null;
    if (!targetManager) {
      targetManager = await getFallbackLeader();
      if (targetManager) targetSource = "FALLBACK_LEADER";
    }
    const escalatedToLabel = targetManager
      ? `${targetManager.name} (${targetManager.id})`
      : "SOC_LEADER";
    const escalatedToCi   = targetManager?.id   ?? null;
    const escalatedToName = targetManager?.name ?? null;
    const escalatedToRole = targetManager?.role_id ?? null;

    // Umbrales de tiempo sin adopción antes de escalar (en minutos)
    const THRESHOLD_MIN = { CRITICAL: 30, HIGH: 60, MEDIUM: 120, LOW: 1440, NEGLIGIBLE: 4320 };

    const toEscalate = unadopted.filter((r) => {
      const sev = String(r.severity_text ?? "LOW").toUpperCase();
      const threshold = THRESHOLD_MIN[sev] ?? 1440;
      const ageMin = r.first_seen
        ? (Date.now() - new Date(String(r.first_seen)).getTime()) / 60_000
        : Infinity;
      return ageMin >= threshold;
    });

    if (dryRun) {
      return res.json({
        ok: true, dryRun: true,
        would_escalate:    toEscalate.length,
        below_threshold:   unadopted.length - toEscalate.length,
        skipped_by_status: skippedByPgStatus,
        cases: toEscalate.map((r) => ({
          case_id: r.case_id, severity: r.severity_text,
          first_seen: r.first_seen,
        })),
        escalated_to: {
          label:  escalatedToLabel,
          ci:     escalatedToCi,
          name:   escalatedToName,
          role:   escalatedToRole,
          source: targetSource,
        },
      });
    }

    // Perf (opt 2026-06-06): escalación por caso en paralelo acotado (chunks de 5,
    // pool PG=10). Cada caso es una fila distinta de incident_cases_pg → sin
    // contención; el sync a Iceberg va por COLA persistente (no INSERT inline),
    // así que NO hay riesgo de CommitFailedException (a diferencia de bulk-sync).
    // QUEUE_FULL sigue cortando el bulk vía stopWhen (con sobre-proceso ≤ 1 chunk).
    const ESCALATE_CONCURRENCY = 5;
    const results = await mapChunked(toEscalate, ESCALATE_CONCURRENCY, async (r) => {
      const id  = String(r.case_id);
      const sev = String(r.severity_text ?? "HIGH").toUpperCase();
      const reason = `Auto-escalado: caso NUEVO sin adoptar (${sev}) superó umbral de tiempo`;
      try {
        await pgUpsertCase(id, {
          severity:        sev,
          status:          "ESCALADO",
          score:           Number(r.severity_score ?? 50),
          operatorId:      ci,
          escalationLevel: "TIER1",
          escalatedTo:     escalatedToLabel,
          escalatedAt:     now,
          escalationReason: reason,
          timelineEntry:   buildTimelineEntry("ESCALATE", ci, reason),
        });
        // Iceberg vía cola persistente (P4 C3). Si la cola está saturada,
        // el enqueue tira QUEUE_FULL: paramos el bulk para no acumular.
        try {
          await enqueueStatusSyncJob({
            caseId: id,
            trinoRow: {
              ...r,
              status:            "ESCALADO",
              updated_at:        now,
              escalation_level:  "TIER1",
              escalated_to:      escalatedToLabel,
              escalated_at:      now,
              escalation_reason: reason,
            },
            ci,
            now,
          });
        } catch (qErr) {
          logger.error("incidents.iceberg_status_sync_enqueue_failed", { caseId: id, err: qErr.message });
          if (qErr.code === "QUEUE_FULL") return { id, queueFull: true };
        }
        return { id, ok: true };
      } catch { return { id, ok: false }; }
    }, { stopWhen: (v) => v?.queueFull === true });

    const escalatedIds = results.filter((v) => v?.ok).map((v) => v.id);
    const escalated = escalatedIds.length;

    // Sync índice canónico para los IDs efectivamente escalados (audit 2026-05-26).
    // Best-effort batch — no bloquea la respuesta del bulk.
    if (escalatedIds.length > 0) {
      void mirrorCasesToIndex(escalatedIds).catch(() => {});
    }

    if (isSlackEnabled() && escalated > 0) {
      try {
        const targetSuffix = targetManager
          ? targetSource === "FALLBACK_LEADER"
            ? " · LEADER fallback (sin Shift Manager designado)"
            : " · Shift Manager activo"
          : " · ⚠️ sin Shift Manager ni LEADER disponibles";
        await sendSlackAlert({
          text: `🚨 *ESCALADO MASIVO — ${escalated} casos sin adoptar*\n*Ejecutado por:* ${ci}\n*Criterio:* Casos NUEVO sin adoptar que superaron umbral por severidad\n*Escalados a:* ${escalatedToLabel} (TIER1)${targetSuffix}`,
        });
      } catch { /* no interrumpir */ }
    }

    if (escalated > 0 && escalatedToCi) {
      try {
        await createNotification({
          operatorId: escalatedToCi,
          type:       "CASE_ESCALATED",
          priority:   "HIGH",
          title:      `[TIER1] ${escalated} casos escalados a tu cola`,
          body:       `Escalado masivo ejecutado por ${ci} — casos NUEVO sin adoptar que superaron umbral por severidad. Origen: ${targetSource === "FALLBACK_LEADER" ? "LEADER fallback (sin SM designado)" : "Shift Manager activo"}.`,
          io:         getIo(),
        });
      } catch { /* best-effort */ }
    }

    // Emitimos con `caseIds` para que listeners downstream (telemetría, vistas
    // por owner) puedan reconciliar sin pegar al backend. El front consume el
    // evento vía invalidateAll() debounced — no necesita el detalle, pero
    // tenerlo evita pegar otro endpoint para enumerar qué cambió.
    getIo()?.emit("incident:status_change", {
      source: "bulk-escalate",
      count:  escalated,
      caseIds: escalatedIds,
    });
    res.json({
      ok: true,
      escalated,
      below_threshold:   unadopted.length - toEscalate.length,
      skipped_by_status: skippedByPgStatus,
      escalated_to: {
        label:  escalatedToLabel,
        ci:     escalatedToCi,
        name:   escalatedToName,
        role:   escalatedToRole,
        source: targetSource,
      },
    });
  });

  // ── POST /api/incidents/bulk-status ────────────────────────────────────────
  // P0 #12 (backlog GESTION-OPTIMIZACION-2026-06-07): cambio de estado en LOTE
  // (cerrar / FP / monitorear / escalar / confirmar varios casos a la vez). Antes
  // sólo existía bulk-escalate y bulk-assign → cerrar 20 FP era 20 acciones.
  //
  // Reutiliza el MOTOR canónico workflowEngine.transitionCase por caso, así que
  // hereda TODOS los gates sin duplicarlos: validación de transición role-aware,
  // 4-eyes en FP de escalation_suggested, postmortem ≥60 en cierres MEDIUM+,
  // clasificación obligatoria, supresión transaccional (trigger 078), mirror
  // Iceberg/índice e invalidación de KPIs. Identidad = JWT. Best-effort por caso:
  // un fallo de gate en un caso NO aborta el resto; se reporta en results[].
  router.post("/bulk-status", async (req, res) => {
    const { caseIds, status, reason, classification, secondApproverCi, lessonsLearned } = req.body ?? {};
    // Cierre forzado en lote: omite el postmortem (sólo ADMIN/LEADER, ver gate abajo).
    const force = req.body?.force === true;

    const operatorCi = await resolveJwtOperatorCi(req);
    if (!operatorCi) return res.status(400).json({ error: "CI del operador no resuelto" });

    const VALID = new Set(["EN_ANALISIS","CONFIRMADO","MONITOREADO","ESCALADO","FALSO_POSITIVO","CERRADO"]);
    if (!VALID.has(status)) return res.status(400).json({ error: "Estado inválido" });

    if (!Array.isArray(caseIds) || caseIds.length === 0) {
      return res.status(400).json({ error: "caseIds debe ser un array no vacío" });
    }
    if (caseIds.length > 100) {
      return res.status(400).json({ error: "Máximo 100 casos por batch" });
    }
    const UUID_RE2 = /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
    const badIds = caseIds.filter((id) => typeof id !== "string" || !UUID_RE2.test(id));
    if (badIds.length > 0) {
      return res.status(400).json({ error: "caseIds contiene UUIDs inválidos", invalid: badIds.slice(0, 5) });
    }

    // Rol del operador → transitionCase aplica RBAC vía validateTransition.
    let roleId = null;
    try {
      const [op] = await pgQuery(
        `SELECT role_id FROM soc_operators WHERE id = $1 AND is_active = true`, [operatorCi],
      );
      if (!op) return res.status(403).json({ error: `Operador ${operatorCi} no existe o no está activo` });
      roleId = op.role_id;
    } catch (err) { return res.status(500).json({ error: err.message }); }

    // Gate de cierre forzado: sólo ADMIN/LEADER pueden cerrar sin postmortem.
    // Falla rápido para todo el batch en vez de rechazar caso por caso.
    if (force && !["ADMIN", "LEADER"].includes(String(roleId ?? "").toUpperCase())) {
      return res.status(403).json({
        error: "Cierre forzado (sin postmortem) requiere rol ADMIN o LEADER.",
        required_role: ["ADMIN", "LEADER"],
        role: roleId,
      });
    }

    // Procesar en bloques de 8 para no saturar PG/Trino con 100 transiciones
    // concurrentes (cada una hace varios queries + mirror). Best-effort por caso.
    const io = getIo();
    const results = [];
    for (let i = 0; i < caseIds.length; i += 8) {
      const chunk = caseIds.slice(i, i + 8);
      const settled = await Promise.allSettled(chunk.map((id) =>
        // deferMirror: evitamos el mirror Iceberg/Trino por-caso (2 escrituras
        // awaited × N → timeout del cliente). Lo batcheamos UNA vez al final.
        transitionCase({
          caseId: id, toStatus: status, operatorCi, roleId,
          reason, classification, secondApproverCi, lessonsLearned, force,
          deferMirror: true,
        }, io),
      ));
      settled.forEach((r, j) => {
        if (r.status === "fulfilled") {
          results.push({ id: chunk[j], ok: true, fromStatus: r.value?.fromStatus, toStatus: r.value?.toStatus });
        } else {
          results.push({ id: chunk[j], ok: false, error: r.reason?.message ?? "error" });
        }
      });
    }

    // Mirror batcheado para TODOS los casos exitosos: una sola escritura
    // Iceberg + una al índice + una invalidación de KPI (en vez de N×). Es el
    // cambio que mantiene el bulk dentro del timeout. Best-effort.
    const okIds = results.filter((r) => r.ok).map((r) => r.id);
    if (okIds.length > 0) {
      await mirrorCasesToIceberg(okIds).catch((e) => logger.warn("incidents.bulk_status.mirror_iceberg_failed", { err: e?.message }));
      await mirrorCasesToIndex(okIds).catch((e) => logger.warn("incidents.bulk_status.mirror_index_failed", { err: e?.message }));
      invalidateCasesKpisCache();
      if (io) io.emit("incident:bulk_status_change", { caseIds: okIds, toStatus: status, operatorCi });
    }

    const succeeded = results.filter((r) => r.ok).length;
    logger.info("incidents.bulk_status", {
      operatorCi, status, total: caseIds.length, succeeded, failed: caseIds.length - succeeded,
    });
    res.json({
      ok: true, total: caseIds.length, succeeded, failed: caseIds.length - succeeded, results,
    });
  });

  // ── GET /geo-origins → ranking de países de origen de los casos recientes +
  // agregados globales + tipos de ataque (MITRE), para el radar táctico del
  // dashboard. Lectura general (no SM). Reusa la agregación híbrida del informe
  // (src_country PG + MaxMind para huérfanos). Cacheado en memoria (TTL 5 min).
  const _geoOriginsCache = new Map(); // days → { value, expiresAt }
  router.get("/geo/origins", async (req, res) => {
    const days = Math.max(1, Math.min(90, Number.parseInt(req.query?.days, 10) || 7));
    const now = Date.now();
    const cached = _geoOriginsCache.get(days);
    if (cached && cached.expiresAt > now) return res.json(cached.value);
    try {
      const to = new Date(now);
      const from = new Date(now - days * 24 * 60 * 60 * 1000);
      const fromIso = from.toISOString(), toIso = to.toISOString();
      // R2/R3: por país conservamos unique_ips + high_risk + risk (no se descartan).
      const ranked = await _topCountries(fromIso, toIso);
      const countries = ranked.map((c) => ({
        cc: c.cc, name: c.name, total: Number(c.total) || 0,
        unique_ips: Number(c.unique_ips) || 0, high_risk: Number(c.high_risk) || 0, risk: c.risk,
      }));
      // R2: agregados globales (% bloqueado desde firewall_action de los casos).
      const [agg] = await pgQuery(
        `SELECT COUNT(*)::int AS contacts,
                COUNT(*) FILTER (WHERE upper(coalesce(firewall_action,'')) IN ('BLOCK','DENY','DROP','BLOCKED','DROPPED'))::int AS blocked,
                COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH'))::int AS high_risk
           FROM incident_cases_pg
          WHERE created_at >= $1 AND created_at < $2`,
        [fromIso, toIso],
      );
      const contacts = agg?.contacts ?? 0;
      const totals = {
        contacts,
        uniqueIps: countries.reduce((s, c) => s + c.unique_ips, 0),
        countries: countries.length,
        highRiskCountries: countries.filter((c) => c.risk === "high").length,
        highRisk: agg?.high_risk ?? 0,
        blockedPct: contacts > 0 ? Math.round(((agg?.blocked ?? 0) / contacts) * 100) : 0,
      };
      // R4: tipos de ataque (táctica MITRE) — poblado en casos.
      const attackTypes = (await pgQuery(
        `SELECT COALESCE(NULLIF(mitre_tactic_name,''), mitre_tactic_id, 'Sin clasificar') AS label, COUNT(*)::int AS total
           FROM incident_cases_pg
          WHERE created_at >= $1 AND created_at < $2
          GROUP BY 1 ORDER BY 2 DESC LIMIT 8`,
        [fromIso, toIso],
      )).map((r) => ({ label: r.label, total: r.total }));

      const value = { ok: true, days, generatedAt: new Date(now).toISOString(), countries, totals, attackTypes };
      _geoOriginsCache.set(days, { value, expiresAt: now + 5 * 60 * 1000 });
      res.json(value);
    } catch (err) {
      res.status(500).json({ error: `Geo-origins falló: ${err.message}` });
    }
  });

  // ── GET /attacked-services → R4: top servicios destino del perímetro (puerto →
  // servicio) desde fortigate_events_slim (Trino). Query pesada (~8s) → cache
  // 10 min. Lectura general. Mapea puertos conocidos a nombre de servicio.
  const _PORT_SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    4443: "HTTPS-alt", 10443: "SSL-VPN", 27017: "MongoDB",
  };
  const _attackedServicesCache = new Map();
  router.get("/geo/attacked-services", async (req, res) => {
    const days = Math.max(1, Math.min(30, Number.parseInt(req.query?.days, 10) || 7));
    const now = Date.now();
    const cached = _attackedServicesCache.get(days);
    if (cached && cached.expiresAt > now) return res.json(cached.value);
    try {
      const rows = await runQuery(
        `SELECT dst_port AS port, count(*) AS c
           FROM minio_iceberg.hunting.fortigate_events_slim
          WHERE dt >= current_date - INTERVAL '${days}' DAY AND dst_port IS NOT NULL AND dst_port > 0
          GROUP BY dst_port ORDER BY c DESC LIMIT 10`,
      );
      const services = rows.map((r) => {
        const port = Number(r.port);
        return { port, name: _PORT_SERVICE[port] ?? `:${port}`, count: Number(r.c) || 0 };
      });
      const value = { ok: true, days, generatedAt: new Date(now).toISOString(), services };
      _attackedServicesCache.set(days, { value, expiresAt: now + 10 * 60 * 1000 });
      res.json(value);
    } catch (err) {
      res.status(500).json({ error: `Attacked-services falló: ${err.message}` });
    }
  });

  // ── Asistente de cierre masivo (sólo Shift Manager activo) ─────────────────
  // POST /bulk-close/preview  → dry-run: cuenta + muestra los casos que matchean
  //                             criterios y devuelve un confirmToken (TTL 5 min).
  // POST /bulk-close          → ejecuta el cierre del set tokenizado.
  //
  // Caso de uso: cerrar en lote reconocimiento (TA0043) hacia origen legítimo
  // (Microsoft, scanner autorizado, RFC1918). RBAC: SOLO el SM activo — un
  // LEADER/ADMIN que no sea el SM designado NO puede. Lab mode (OIDC off) bypass.
  const BULK_CLOSE_TOKEN_TTL_MS = 5 * 60 * 1000;
  const _bulkCloseTokens = new Map(); // token → { caseIds:Set<string>, expiresAt:number }

  function _pruneBulkCloseTokens() {
    const now = Date.now();
    for (const [t, v] of _bulkCloseTokens) if (v.expiresAt <= now) _bulkCloseTokens.delete(t);
  }

  // RBAC compartido por preview+execute. Identidad = JWT (no se confía en el body).
  async function requireActiveShiftManager(req) {
    const ci = await resolveJwtOperatorCi(req);
    // Lab mode (OIDC_ENABLED=false): bypass documentado, igual que otros endpoints
    // admin — el middleware marca isLabMode sólo cuando no hay OIDC.
    if (req.user?.isLabMode === true) return { ok: true, ci: ci ?? "lab-user" };
    if (!ci) return { ok: false, status: 400, body: { error: "CI del operador no resuelto" } };
    let mgr = null;
    try { mgr = await getActiveShiftManager(); } catch { /* sin SM → 403 abajo */ }
    if (!mgr?.id || String(mgr.id) !== String(ci)) {
      logger.warn("incidents.bulk_close.forbidden", { ci, smId: mgr?.id ?? null });
      return { ok: false, status: 403, body: { error: "Solo el Shift Manager activo puede ejecutar cierre masivo" } };
    }
    return { ok: true, ci };
  }

  // Arma WHERE + params a partir de criterios normalizados (severidad efectiva).
  function _bulkCloseWhere(c, severities) {
    const params = [];
    const where = ["c.status NOT IN ('CERRADO','FALSO_POSITIVO')"];
    params.push(severities); where.push(`c.severity = ANY($${params.length}::text[])`);
    params.push(c.statusIn);  where.push(`c.status = ANY($${params.length}::text[])`);
    if (c.mitreTacticId)    { params.push(c.mitreTacticId);    where.push(`c.mitre_tactic_id = $${params.length}`); }
    if (c.mitreTechniqueId) { params.push(c.mitreTechniqueId); where.push(`c.mitre_technique_id = $${params.length}`); }
    if (c.iocType)       { params.push(c.iocType);       where.push(`c.ioc_type = $${params.length}`); }
    if (c.iocPattern)    { params.push(c.iocPattern);    where.push(`c.ioc_value ILIKE $${params.length}`); }
    if (c.sourceLog)     { params.push(`${c.sourceLog}%`); where.push(`c.source_log ILIKE $${params.length}`); }
    // firewallAction: 'blocked' = ya mitigado por el FortiGate (la señal de
    // auto-cierre más limpia); 'none' = sin acción registrada.
    if (c.firewallAction === "blocked") {
      where.push(`upper(coalesce(c.firewall_action,'')) IN ('BLOCK','DENY','DROP','BLOCKED','DROPPED')`);
    } else if (c.firewallAction === "none") {
      where.push(`coalesce(nullif(trim(c.firewall_action),''), '') = ''`);
    } else if (c.firewallAction === "allowed") {
      where.push(`coalesce(nullif(trim(c.firewall_action),''), '') <> '' AND upper(c.firewall_action) NOT IN ('BLOCK','DENY','DROP','BLOCKED','DROPPED')`);
    }
    // netClass: internal = RFC1918 (espejo SQL canónico de netClass.isRfc1918);
    // public = IPv4 que no cae en rango privado/reservado.
    const RFC1918_RE = "^(127\\.|10\\.|192\\.168\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)";
    if (c.netClass === "internal") {
      where.push(`c.ioc_type = 'ip' AND c.ioc_value ~ '${RFC1918_RE}'`);
    } else if (c.netClass === "public") {
      where.push(`c.ioc_type = 'ip' AND c.ioc_value ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$' AND c.ioc_value !~ '${RFC1918_RE}'`);
    }
    // techClass: reproduce los buckets de triage (recon/threat/other). 'threat'
    // gana sobre 'recon' (mismo criterio que el clasificador JS).
    if (c.techClass) {
      const threat = `(upper(coalesce(c.mitre_technique_id,'')) IN (${_threatList}) OR upper(coalesce(c.mitre_tactic_id,'')) IN (${_threatList}))`;
      const recon = `(upper(coalesce(c.mitre_technique_id,'')) IN (${_reconList}) OR upper(coalesce(c.mitre_tactic_id,'')) IN (${_reconList})`
        + ` OR upper(coalesce(c.mitre_tactic_id,'')) IN ('TA0007','TA0043') OR (coalesce(c.mitre_technique_id,'')='' AND coalesce(c.mitre_tactic_id,'')=''))`;
      if (c.techClass === "threat") where.push(threat);
      else if (c.techClass === "recon") where.push(`NOT ${threat} AND ${recon}`);
      else where.push(`NOT ${threat} AND NOT ${recon}`);
    }
    params.push(c.maxAgeDays); where.push(`c.created_at >= now() - ($${params.length} || ' days')::interval`);
    return { where: where.join(" AND "), params };
  }

  // ── M1: conteo VERDADERO por cluster (sin cap). El preview limita filas a 200,
  // así que clusterizar la muestra subreporta (el cluster "interno bloqueado" real
  // = 558 se vería ≤200). Esta query agrupa TODA la población con las MISMAS
  // clases que el scoring JS (netclass·firewall·técnica) y devuelve el total real.
  const _RFC1918_SQL = "^(127\\.|10\\.|192\\.168\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)";
  const _threatList = [...THREAT_TECHNIQUES].map((t) => `'${t}'`).join(",");
  const _reconList = [...RECON_TECHNIQUES].map((t) => `'${t}'`).join(",");
  function _clusterKeyExpr() {
    const netclass = `CASE WHEN c.ioc_type='ip' AND c.ioc_value ~ '${_RFC1918_SQL}' THEN 'internal'
      WHEN c.ioc_type='ip' AND c.ioc_value ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$' THEN 'public' ELSE 'other' END`;
    const fwclass = `CASE WHEN upper(coalesce(c.firewall_action,'')) IN ('BLOCK','DENY','DROP','BLOCKED','DROPPED') THEN 'blocked'
      WHEN coalesce(nullif(trim(c.firewall_action),''),'')<>'' THEN 'allowed' ELSE 'none' END`;
    const techclass = `CASE
      WHEN upper(coalesce(c.mitre_technique_id,'')) IN (${_threatList}) OR upper(coalesce(c.mitre_tactic_id,'')) IN (${_threatList}) THEN 'threat'
      WHEN upper(coalesce(c.mitre_technique_id,'')) IN (${_reconList}) OR upper(coalesce(c.mitre_tactic_id,'')) IN (${_reconList})
        OR upper(coalesce(c.mitre_tactic_id,'')) IN ('TA0007','TA0043')
        OR (coalesce(c.mitre_technique_id,'')='' AND coalesce(c.mitre_tactic_id,'')='') THEN 'recon'
      ELSE 'other' END`;
    return { netclass, fwclass, techclass };
  }
  async function _clusterTotals(where, params) {
    const { netclass, fwclass, techclass } = _clusterKeyExpr();
    const sql = `SELECT ${netclass} AS netclass, ${fwclass} AS fwclass, ${techclass} AS techclass, COUNT(*)::int AS n
      FROM incident_cases_pg c WHERE ${where} GROUP BY 1,2,3`;
    const rows = await pgQuery(sql, params);
    const byKey = new Map();
    let total = 0;
    for (const r of rows) { byKey.set(`${r.netclass}|${r.fwclass}|${r.techclass}`, r.n); total += r.n; }
    return { byKey, total };
  }

  // ── M2/M4: cierre de UN caso reutilizable por execute y drain. Aplica el veto
  // de confianza (no cierra amenazas salvo forceVetoed) y el plan de supresión
  // cluster-aware. Devuelve el resultado para acumular en el batch.
  async function _closeOneCase(row, opts) {
    const { status, classificationIn, reason, operatorCi,
      includeHighSeverity, createSuppressions, suppressionDays, smartSuppressions, forceVetoed } = opts;
    const id = String(row.id);
    if (row.status === "CERRADO" || row.status === "FALSO_POSITIVO") {
      return { skipped: { caseId: id, reason: `ya está ${row.status}` } };
    }
    const sev = String(row.severity ?? "MEDIUM").toUpperCase();
    if (!includeHighSeverity && (sev === "CRITICAL" || sev === "HIGH")) {
      return { skipped: { caseId: id, reason: `severidad ${sev} bloqueada` } };
    }
    // M2: veto de confianza (técnica de amenaza / CRITICAL / veredicto malicioso).
    const conf = scoreCaseConfidence(row);
    if (conf.veto && !forceVetoed) {
      return { skipped: { caseId: id, reason: `vetado: ${conf.veto}` } };
    }
    const decision = decideClosureClassification({
      toStatus: status, classification: classificationIn,
      currentClassification: row.classification ?? null, roleId: null,
    });
    if (!decision.ok) return { error: { caseId: id, error: decision.message } };

    await pgUpsertCase(id, {
      severity: sev, status, score: Number(row.score ?? 50),
      classification: decision.value, closureReason: reason,
      timelineEntry: buildTimelineEntry("STATUS_CHANGE", operatorCi, `Cierre masivo → ${status} (${decision.value}): ${reason}`),
    });
    const out = { closedId: id, prevStatus: row.status, suppressionKey: null };

    if (createSuppressions && status === "FALSO_POSITIVO") {
      const plan = suppressionPlan(row, { suppressionDays, smart: smartSuppressions });
      const dk = String(row.dedup_key ?? "");
      if (plan.create && dk) {
        try {
          await pgQuery(
            `INSERT INTO legacyhunt_soc.case_suppressions
               (dedup_key, reason, severity, suppressed_until, suppressed_by, original_case_id, original_ioc)
             VALUES ($1, $2, $3, NOW() + ($7 || ' days')::interval, $4, $5::uuid, $6)
             ON CONFLICT (dedup_key) DO UPDATE SET
               reason='FALSO_POSITIVO', severity=EXCLUDED.severity,
               suppressed_until=GREATEST(case_suppressions.suppressed_until, EXCLUDED.suppressed_until),
               suppressed_by=EXCLUDED.suppressed_by, original_case_id=EXCLUDED.original_case_id, updated_at=NOW()`,
            [dk, "FALSO_POSITIVO", sev, operatorCi, id, String(row.ioc_value ?? ""), String(plan.days)],
          );
          out.suppressionKey = dk;
        } catch (sErr) { logger.warn("incidents.bulk_close.suppression_failed", { caseId: id, err: sErr.message }); }
      } else if (!plan.create) {
        out.suppressionSkipped = plan.skipReason;
      }
    }
    return out;
  }

  router.post("/bulk-close/preview", async (req, res) => {
    const gate = await requireActiveShiftManager(req);
    if (!gate.ok) return res.status(gate.status).json(gate.body);

    const parsed = parseBulkCloseCriteria(req.body?.criteria ?? {});
    if (!parsed.ok) return res.status(400).json({ error: "Criterios inválidos", details: parsed.errors });
    const c = parsed.criteria;

    const { where, params } = _bulkCloseWhere(c, c.effectiveSeverities);
    params.push(c.limit);
    const sql = `
      SELECT c.id, c.severity, c.status, c.ioc_value, c.ioc_type,
             c.mitre_tactic_id, c.mitre_technique_id, c.firewall_action,
             c.source_log, c.score,
             COALESCE(c.dedup_key, idx.dedup_key) AS dedup_key
        FROM incident_cases_pg c
        LEFT JOIN legacyhunt_soc.incident_case_index idx ON idx.case_id::varchar = c.id
       WHERE ${where}
       ORDER BY c.created_at DESC
       LIMIT $${params.length}`;
    let rows;
    try { rows = await pgQuery(sql, params); }
    catch (err) { return res.status(500).json({ error: `Query de criterios falló: ${err.message}` }); }

    // Post-filtro de orígenes confiables (Microsoft/RFC1918/scanner-benigno).
    if (c.matchTrustedOrigins) {
      let scannerSet = new Set();
      try { scannerSet = await loadBenignScannerIps((q) => runQuery(q)); } catch { /* best-effort */ }
      rows = rows.filter((r) =>
        isTrustedOriginWithScanners({ iocValue: r.ioc_value, iocType: r.ioc_type }, scannerSet).trusted);
    }

    const bySeverity = {}, byStatus = {};
    for (const r of rows) {
      bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
      byStatus[r.status]     = (byStatus[r.status] ?? 0) + 1;
    }
    const caseIds = rows.map((r) => String(r.id));

    // Conteo de CRITICAL/HIGH bloqueados (si el gate está apagado) — para que el
    // SM vea cuántos quedaron fuera por seguridad.
    let blockedHighSeverity = 0;
    if (!c.includeHighSeverity) {
      try {
        const b = _bulkCloseWhere(c, ["CRITICAL", "HIGH"]);
        const [bRow] = await pgQuery(`SELECT COUNT(*)::int AS n FROM incident_cases_pg c WHERE ${b.where}`, b.params);
        blockedHighSeverity = bRow?.n ?? 0;
      } catch { /* best-effort */ }
    }

    _pruneBulkCloseTokens();
    const expiresAt = Date.now() + BULK_CLOSE_TOKEN_TTL_MS;
    const confirmToken = createHash("sha256")
      .update(JSON.stringify({ ids: [...caseIds].sort(), ts: expiresAt, n: randomBytes(8).toString("hex") }))
      .digest("hex");
    _bulkCloseTokens.set(confirmToken, { caseIds: new Set(caseIds), expiresAt });

    // Recomendación + clusters semánticos (netclass·firewall·técnica) con confianza.
    const { clusters, ...recommendation } = recommendFromClusters(rows);

    // M1: totales VERDADEROS por cluster (sin cap). avgConfidence/action salen de
    // la muestra (representativa); el conteo se reemplaza por el real. Cuando hay
    // post-filtro JS (matchTrustedOrigins) el SQL no puede reflejarlo → se omite.
    let matchCountTotal = caseIds.length;
    if (!c.matchTrustedOrigins) {
      try {
        const cnt = _bulkCloseWhere(c, c.effectiveSeverities);
        const totals = await _clusterTotals(cnt.where, cnt.params);
        matchCountTotal = totals.total;
        for (const cl of clusters) {
          const real = totals.byKey.get(cl.key);
          if (real != null) { cl.sampledCount = cl.count; cl.count = real; }
        }
        // Clusters presentes en la población pero ausentes de la muestra capada.
        for (const [key, n] of totals.byKey) {
          if (clusters.some((x) => x.key === key)) continue;
          const [netclass, fwClass, techClass] = key.split("|");
          clusters.push({ key, netclass, fwClass, techClass, count: n, vetoed: techClass === "threat" ? n : 0,
            avgConfidence: null, action: clusterAction(netclass, techClass, 0), label: `${techClass} · ${netclass} · fw:${fwClass}`,
            caseIds: [], sampleIds: [] });
        }
        clusters.sort((a, b) => b.count - a.count);
      } catch (e) { logger.warn("incidents.bulk_close.cluster_totals_failed", { err: e?.message }); }
    }

    res.json({
      ok: true,
      matchCount: caseIds.length,
      matchCountTotal,
      cappedAt: c.limit,
      capped: matchCountTotal > caseIds.length,
      bySeverity,
      byStatus,
      blocked: { highSeverity: blockedHighSeverity },
      recommendation,
      clusters,
      sample: rows.slice(0, 10).map((r) => {
        const conf = scoreCaseConfidence(r);
        return {
          id: r.id, ioc_value: r.ioc_value, ioc_type: r.ioc_type,
          severity: r.severity, status: r.status, mitre_tactic_id: r.mitre_tactic_id,
          mitre_technique_id: r.mitre_technique_id, firewall_action: r.firewall_action,
          source_log: r.source_log, score: r.score,
          confidence: conf.confidence, veto: conf.veto,
        };
      }),
      caseIds,
      confirmToken,
      expiresAt: new Date(expiresAt).toISOString(),
    });
  });

  router.post("/bulk-close", async (req, res) => {
    const gate = await requireActiveShiftManager(req);
    if (!gate.ok) return res.status(gate.status).json(gate.body);
    const operatorCi = gate.ci;

    const { confirmToken, caseIds: rawCaseIds, closure } = req.body ?? {};
    if (typeof confirmToken !== "string" || !confirmToken) {
      return res.status(400).json({ error: "confirmToken requerido (previsualizá primero)" });
    }
    _pruneBulkCloseTokens();
    const tokenEntry = _bulkCloseTokens.get(confirmToken);
    if (!tokenEntry) {
      return res.status(409).json({ error: "Token de confirmación inválido o expirado. Volvé a previsualizar." });
    }

    if (!Array.isArray(rawCaseIds) || rawCaseIds.length === 0) {
      return res.status(400).json({ error: "caseIds debe ser un array no vacío" });
    }
    if (rawCaseIds.length > 200) {
      return res.status(400).json({ error: "Máximo 200 casos por batch" });
    }
    const caseIds = rawCaseIds.map(String);
    // Todos los ids deben provenir del preview tokenizado (anti-tampering).
    const foreign = caseIds.filter((id) => !tokenEntry.caseIds.has(id));
    if (foreign.length > 0) {
      return res.status(409).json({ error: "caseIds no coinciden con el preview", invalid: foreign.slice(0, 5) });
    }

    // ── Parámetros de cierre ────────────────────────────────────────────────
    const cl = closure ?? {};
    const status = cl.status === "CERRADO" ? "CERRADO" : "FALSO_POSITIVO";
    const reason = String(cl.reason ?? "").trim();
    if (reason.length < 5) {
      return res.status(422).json({ error: "reason requerido (mín. 5 caracteres)", field: "reason" });
    }
    const includeHighSeverity = cl.includeHighSeverity === true;
    if (includeHighSeverity && reason.length < 20) {
      return res.status(422).json({ error: "Incluir CRITICAL/HIGH exige un motivo de al menos 20 caracteres.", field: "reason", minChars: 20 });
    }
    const createSuppressions = cl.createSuppressions !== false; // default true
    const suppressionDays = Math.max(1, Math.min(365, Number.parseInt(cl.suppressionDays, 10) || 30));
    const smartSuppressions = cl.smartSuppressions !== false;   // M4: default true
    const forceVetoed = cl.forceVetoed === true;                // M2: override del veto
    if (forceVetoed && reason.length < 20) {
      return res.status(422).json({ error: "Forzar casos vetados (amenaza/CRITICAL) exige un motivo de al menos 20 caracteres.", field: "reason", minChars: 20 });
    }
    const classificationIn = cl.classification ?? (status === "FALSO_POSITIVO" ? "FALSE_POSITIVE" : null);

    // RBAC de transición: el rol del SM debe tener el cap de cierre (can_close_fp/case).
    const rbac = await checkTransitionRbac(operatorCi, status);
    if (!rbac.ok) return res.status(rbac.status).json(rbac.body);

    // El token NO se consume acá: vale hasta su TTL (5 min) para permitir el
    // combo "agregar a watchlist + cerrar" sobre el mismo preview. Re-ejecutar
    // es seguro: los casos ya cerrados se saltan.

    let rows;
    try {
      rows = await pgQuery(
        `SELECT id, status, severity, score, ioc_value, ioc_type, dedup_key, classification,
                mitre_tactic_id, mitre_technique_id, firewall_action
           FROM incident_cases_pg WHERE id = ANY($1::text[])`,
        [caseIds],
      );
    } catch (err) { return res.status(500).json({ error: `Lookup de casos falló: ${err.message}` }); }
    const byId = new Map(rows.map((r) => [String(r.id), r]));

    let closed = 0, suppressionsCreated = 0;
    const skipped = [], errors = [], closedIds = [], closedCases = [], suppressionKeys = [];
    let suppressionsSkippedPublic = 0;
    const opOpts = { status, classificationIn, reason, operatorCi, includeHighSeverity, createSuppressions, suppressionDays, smartSuppressions, forceVetoed };

    for (const id of caseIds) {
      const row = byId.get(id);
      if (!row) { skipped.push({ caseId: id, reason: "no encontrado" }); continue; }
      try {
        const r = await _closeOneCase(row, opOpts);
        if (r.skipped) { skipped.push(r.skipped); continue; }
        if (r.error) { errors.push(r.error); continue; }
        closed++; closedIds.push(r.closedId);
        closedCases.push({ id: r.closedId, prevStatus: r.prevStatus });
        if (r.suppressionKey) { suppressionKeys.push(r.suppressionKey); suppressionsCreated++; }
        if (r.suppressionSkipped === "public_use_watchlist") suppressionsSkippedPublic++;
      } catch (err) { errors.push({ caseId: id, error: err.message }); }
    }

    // M3: registrar la operación (reversible) si hubo cierres.
    let opId = null;
    if (closedIds.length > 0) {
      try {
        const [op] = await pgQuery(
          `INSERT INTO legacyhunt_soc.bulk_close_operations
             (kind, operator_ci, to_status, classification, reason, criteria, closed_cases, suppression_keys, closed_count)
           VALUES ('close', $1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::text[], $8) RETURNING op_id`,
          [operatorCi, status, classificationIn, reason, JSON.stringify(req.body?.criteria ?? {}),
            JSON.stringify(closedCases), suppressionKeys, closed],
        );
        opId = op?.op_id ?? null;
      } catch (e) { logger.warn("incidents.bulk_close.op_record_failed", { err: e?.message }); }
    }

    // Mirror batcheado + invalidación de KPIs + WS (best-effort).
    if (closedIds.length > 0) {
      await mirrorCasesToIceberg(closedIds).catch((e) => logger.warn("incidents.bulk_close.mirror_iceberg_failed", { err: e?.message }));
      await mirrorCasesToIndex(closedIds).catch((e) => logger.warn("incidents.bulk_close.mirror_index_failed", { err: e?.message }));
      invalidateCasesKpisCache();
      getIo()?.emit("incident:bulk-close-done", { caseIds: closedIds, status, operatorCi, count: closed, opId });
    }

    logger.info("incidents.bulk_close", {
      operatorCi, status, requested: caseIds.length, closed, opId,
      skipped: skipped.length, errors: errors.length, suppressionsCreated, suppressionsSkippedPublic,
    });
    res.json({
      ok: true, opId, closed, skipped: skipped.length, suppressionsCreated, suppressionsSkippedPublic, errors,
      detail: { skipped },
    });
  });

  // ── M3: POST /bulk-close/undo/:opId → reabre el lote de una operación y expira
  // las supresiones que creó. Sólo SM activo. Best-effort por caso; idempotente
  // (casos ya reabiertos / operación ya deshecha se saltan).
  router.post("/bulk-close/undo/:opId", async (req, res) => {
    const gate = await requireActiveShiftManager(req);
    if (!gate.ok) return res.status(gate.status).json(gate.body);
    const operatorCi = gate.ci;
    const opId = String(req.params.opId ?? "");
    if (!/^[0-9a-f-]{36}$/i.test(opId)) return res.status(400).json({ error: "opId inválido" });

    let op;
    try {
      const [row] = await pgQuery(`SELECT * FROM legacyhunt_soc.bulk_close_operations WHERE op_id = $1::uuid`, [opId]);
      op = row;
    } catch (err) { return res.status(500).json({ error: `Lookup de operación falló: ${err.message}` }); }
    if (!op) return res.status(404).json({ error: "Operación no encontrada" });
    if (op.undone_at) return res.status(409).json({ error: "La operación ya fue deshecha", undoneAt: op.undone_at });

    const closedCases = Array.isArray(op.closed_cases) ? op.closed_cases : [];
    const ids = closedCases.map((x) => String(x.id));
    let reopened = 0; const reopenedIds = []; const skipped = [];
    let cur = new Map();
    try {
      const rows = await pgQuery(`SELECT id, status, severity, score FROM incident_cases_pg WHERE id = ANY($1::text[])`, [ids]);
      cur = new Map(rows.map((r) => [String(r.id), r]));
    } catch (err) { return res.status(500).json({ error: `Lookup de casos falló: ${err.message}` }); }

    for (const { id, prevStatus } of closedCases) {
      const row = cur.get(String(id));
      if (!row) { skipped.push({ caseId: id, reason: "no encontrado" }); continue; }
      // Sólo reabrir si SIGUE en el estado terminal al que lo llevó la operación.
      if (row.status !== "CERRADO" && row.status !== "FALSO_POSITIVO") {
        skipped.push({ caseId: id, reason: `ya no está cerrado (${row.status})` }); continue;
      }
      const restore = (prevStatus && prevStatus !== "CERRADO" && prevStatus !== "FALSO_POSITIVO") ? prevStatus : "MONITOREADO";
      try {
        await pgUpsertCase(String(id), {
          severity: String(row.severity ?? "MEDIUM").toUpperCase(), status: restore, score: Number(row.score ?? 50),
          timelineEntry: buildTimelineEntry("STATUS_CHANGE", operatorCi, `Reapertura por deshacer cierre masivo (op ${opId.slice(0, 8)}) → ${restore}`),
        });
        reopened++; reopenedIds.push(String(id));
      } catch (err) { skipped.push({ caseId: id, reason: err.message }); }
    }

    // Expirar las supresiones creadas por la operación.
    let suppressionsExpired = 0;
    const keys = Array.isArray(op.suppression_keys) ? op.suppression_keys : [];
    if (keys.length > 0) {
      try {
        const r = await pgQuery(
          `UPDATE legacyhunt_soc.case_suppressions SET suppressed_until = NOW(), updated_at = NOW()
            WHERE dedup_key = ANY($1::text[]) AND suppressed_until > NOW()`,
          [keys],
        );
        suppressionsExpired = r?.rowCount ?? keys.length;
      } catch (e) { logger.warn("incidents.bulk_close.undo_suppr_failed", { err: e?.message }); }
    }

    try {
      await pgQuery(
        `UPDATE legacyhunt_soc.bulk_close_operations SET undone_at = NOW(), undone_by = $2, reopened_count = $3 WHERE op_id = $1::uuid`,
        [opId, operatorCi, reopened],
      );
    } catch (e) { logger.warn("incidents.bulk_close.undo_mark_failed", { err: e?.message }); }

    if (reopenedIds.length > 0) {
      await mirrorCasesToIceberg(reopenedIds).catch(() => {});
      await mirrorCasesToIndex(reopenedIds).catch(() => {});
      invalidateCasesKpisCache();
      getIo()?.emit("incident:bulk-close-undone", { opId, reopened, operatorCi });
    }
    logger.info("incidents.bulk_close_undo", { operatorCi, opId, reopened, suppressionsExpired, skipped: skipped.length });
    res.json({ ok: true, opId, reopened, suppressionsExpired, skipped: skipped.length, detail: { skipped } });
  });

  // ── M5: POST /bulk-close/drain → vacía un CLUSTER completo (más allá del cap
  // de 200) cerrando en lotes server-side hasta agotarlo o llegar a maxTotal.
  // Toma criterios (NO caseIds/token) — es una acción de cluster, no de muestra.
  // Mismo RBAC (SM activo), mismo veto/supresión cluster-aware, una sola operación
  // M3 reversible que agrega todos los lotes.
  router.post("/bulk-close/drain", async (req, res) => {
    const gate = await requireActiveShiftManager(req);
    if (!gate.ok) return res.status(gate.status).json(gate.body);
    const operatorCi = gate.ci;

    const parsed = parseBulkCloseCriteria(req.body?.criteria ?? {});
    if (!parsed.ok) return res.status(400).json({ error: "Criterios inválidos", details: parsed.errors });
    const c = parsed.criteria;

    const cl = req.body?.closure ?? {};
    const status = cl.status === "CERRADO" ? "CERRADO" : "FALSO_POSITIVO";
    const reason = String(cl.reason ?? "").trim();
    if (reason.length < 10) return res.status(422).json({ error: "reason requerido (mín. 10 caracteres para drain)", field: "reason" });
    const includeHighSeverity = cl.includeHighSeverity === true;
    const forceVetoed = cl.forceVetoed === true;
    if ((includeHighSeverity || forceVetoed) && reason.length < 20) {
      return res.status(422).json({ error: "Incluir CRITICAL/HIGH o forzar vetados exige motivo ≥ 20 caracteres.", field: "reason", minChars: 20 });
    }
    const createSuppressions = cl.createSuppressions !== false;
    const suppressionDays = Math.max(1, Math.min(365, Number.parseInt(cl.suppressionDays, 10) || 30));
    const smartSuppressions = cl.smartSuppressions !== false;
    const classificationIn = cl.classification ?? (status === "FALSO_POSITIVO" ? "FALSE_POSITIVE" : null);
    const maxTotal = Math.max(1, Math.min(5000, Number.parseInt(req.body?.maxTotal, 10) || 2000));

    const rbac = await checkTransitionRbac(operatorCi, status);
    if (!rbac.ok) return res.status(rbac.status).json(rbac.body);

    const opOpts = { status, classificationIn, reason, operatorCi, includeHighSeverity, createSuppressions, suppressionDays, smartSuppressions, forceVetoed };
    const BATCH = 200, MAX_ITER = Math.ceil(maxTotal / BATCH) + 2;
    let closed = 0, suppressionsCreated = 0, suppressionsSkippedPublic = 0, iter = 0;
    const allClosedIds = [], closedCases = [], suppressionKeys = []; let skippedTotal = 0, errorsTotal = 0;

    try {
      while (closed < maxTotal && iter < MAX_ITER) {
        iter++;
        const { where, params } = _bulkCloseWhere(c, c.effectiveSeverities);
        params.push(Math.min(BATCH, maxTotal - closed));
        const batch = await pgQuery(
          `SELECT c.id, c.status, c.severity, c.score, c.ioc_value, c.ioc_type,
                  COALESCE(c.dedup_key, idx.dedup_key) AS dedup_key, c.classification,
                  c.mitre_tactic_id, c.mitre_technique_id, c.firewall_action
             FROM incident_cases_pg c
             LEFT JOIN legacyhunt_soc.incident_case_index idx ON idx.case_id::varchar = c.id
            WHERE ${where} ORDER BY c.created_at DESC LIMIT $${params.length}`,
          params,
        );
        if (batch.length === 0) break;
        let progressedThisBatch = 0;
        for (const row of batch) {
          const r = await _closeOneCase(row, opOpts);
          if (r.skipped) { skippedTotal++; continue; }
          if (r.error) { errorsTotal++; continue; }
          closed++; progressedThisBatch++; allClosedIds.push(r.closedId);
          closedCases.push({ id: r.closedId, prevStatus: r.prevStatus });
          if (r.suppressionKey) { suppressionKeys.push(r.suppressionKey); suppressionsCreated++; }
          if (r.suppressionSkipped === "public_use_watchlist") suppressionsSkippedPublic++;
        }
        getIo()?.emit("incident:bulk-close-drain-progress", { operatorCi, closed, iter });
        // Si un lote no progresó (todos vetados/bloqueados), cortar para no ciclar.
        if (progressedThisBatch === 0) break;
      }
    } catch (err) { return res.status(500).json({ error: `Drain falló: ${err.message}`, partialClosed: closed }); }

    let opId = null;
    if (allClosedIds.length > 0) {
      try {
        const [op] = await pgQuery(
          `INSERT INTO legacyhunt_soc.bulk_close_operations
             (kind, operator_ci, to_status, classification, reason, criteria, closed_cases, suppression_keys, closed_count)
           VALUES ('drain', $1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::text[], $8) RETURNING op_id`,
          [operatorCi, status, classificationIn, reason, JSON.stringify(req.body?.criteria ?? {}),
            JSON.stringify(closedCases), suppressionKeys, closed],
        );
        opId = op?.op_id ?? null;
      } catch (e) { logger.warn("incidents.bulk_close.drain_op_record_failed", { err: e?.message }); }
      await mirrorCasesToIceberg(allClosedIds).catch(() => {});
      await mirrorCasesToIndex(allClosedIds).catch(() => {});
      invalidateCasesKpisCache();
      getIo()?.emit("incident:bulk-close-done", { caseIds: allClosedIds, status, operatorCi, count: closed, opId, drain: true });
    }
    logger.info("incidents.bulk_close_drain", { operatorCi, status, closed, iter, opId, skipped: skippedTotal, errors: errorsTotal, suppressionsCreated, suppressionsSkippedPublic });
    res.json({ ok: true, opId, closed, iterations: iter, reachedCap: closed >= maxTotal, skipped: skippedTotal, errors: errorsTotal, suppressionsCreated, suppressionsSkippedPublic });
  });

  // ── T1: GET /bulk-close/triage → clasifica TODO el backlog abierto en las 4
  // disposiciones (auto-cerrar+suppress / cerrar+watchlist / revisar / escalar).
  // Dry-run, sólo SM. Un GROUP BY (mismas clases que el scoring) → cada grupo se
  // enruta con triageDisposition. Devuelve buckets con count + criteria de 1 clic.
  router.get("/bulk-close/triage", async (req, res) => {
    const gate = await requireActiveShiftManager(req);
    if (!gate.ok) return res.status(gate.status).json(gate.body);
    const maxAgeDays = Math.max(1, Math.min(365, Number.parseInt(req.query?.maxAgeDays, 10) || 30));
    const { netclass, fwclass, techclass } = _clusterKeyExpr();
    let groups;
    try {
      groups = await pgQuery(
        `SELECT ${netclass} AS netclass, ${fwclass} AS fwclass, ${techclass} AS techclass,
                upper(c.severity) AS severity, COUNT(*)::int AS n
           FROM incident_cases_pg c
          WHERE c.status NOT IN ('CERRADO','FALSO_POSITIVO','RESUELTO')
            AND c.created_at >= now() - ($1 || ' days')::interval
          GROUP BY 1,2,3,4`,
        [String(maxAgeDays)],
      );
    } catch (err) { return res.status(500).json({ error: `Triage falló: ${err.message}` }); }

    const counts = {};
    let total = 0;
    for (const g of groups) {
      const disp = triageDisposition({ netclass: g.netclass, techClass: g.techclass, blocked: g.fwclass === "blocked", severity: g.severity });
      counts[disp] = (counts[disp] ?? 0) + g.n;
      total += g.n;
    }
    const buckets = Object.entries(TRIAGE_BUCKETS)
      .map(([id, meta]) => ({ id, count: counts[id] ?? 0, ...meta }))
      .sort((a, b) => a.order - b.order);
    res.json({ ok: true, generatedAt: new Date().toISOString(), total, maxAgeDays, buckets });
  });

  // ── M6: GET /bulk-close/candidates-digest → dry-run SIEMPRE on. Cuenta los
  // candidatos de ALTA confianza por cluster accionable (interno bloqueado, público
  // bloqueado) listos para que el SM cierre/vacíe con un clic. No cierra nada.
  router.get("/bulk-close/candidates-digest", async (req, res) => {
    const gate = await requireActiveShiftManager(req);
    if (!gate.ok) return res.status(gate.status).json(gate.body);
    // Definiciones de cluster de alta confianza (perfil real del lake).
    const DIGEST_CLUSTERS = [
      { id: "internal_blocked", label: "Discovery interno ya bloqueado", action: "close_and_suppress",
        criteria: { mitreTechniqueId: "T1046", netClass: "internal", firewallAction: "blocked", iocType: "ip", severityIn: ["MEDIUM", "HIGH"], includeHighSeverity: true } },
      { id: "public_blocked", label: "Discovery público ya bloqueado", action: "close_and_watchlist",
        criteria: { mitreTechniqueId: "T1046", netClass: "public", firewallAction: "blocked", iocType: "ip", severityIn: ["MEDIUM", "HIGH"], includeHighSeverity: true } },
    ];
    const out = [];
    let totalCandidates = 0;
    for (const d of DIGEST_CLUSTERS) {
      try {
        const parsed = parseBulkCloseCriteria(d.criteria);
        const { where, params } = _bulkCloseWhere(parsed.criteria, parsed.criteria.effectiveSeverities);
        const [row] = await pgQuery(`SELECT COUNT(*)::int AS n FROM incident_cases_pg c WHERE ${where}`, params);
        const n = row?.n ?? 0;
        totalCandidates += n;
        out.push({ ...d, count: n });
      } catch (e) { out.push({ ...d, count: 0, error: e?.message }); }
    }
    res.json({ ok: true, generatedAt: new Date().toISOString(), totalCandidates, clusters: out });
  });

  // POST /bulk-watchlist → acción alternativa del asistente: agrega en lote
  // las IPs de los casos previsualizados al feed saliente lgcrBL (bloqueo). Mismo
  // RBAC (SM activo) y mismo confirmToken que el preview. Sólo IPs públicas; las
  // reservadas/allowlisted las rechaza watchlistManualInclude (best-effort).
  router.post("/bulk-watchlist", async (req, res) => {
    const gate = await requireActiveShiftManager(req);
    if (!gate.ok) return res.status(gate.status).json(gate.body);
    const operatorCi = gate.ci;

    const { confirmToken, caseIds: rawCaseIds, watchlist } = req.body ?? {};
    if (typeof confirmToken !== "string" || !confirmToken) {
      return res.status(400).json({ error: "confirmToken requerido (previsualizá primero)" });
    }
    _pruneBulkCloseTokens();
    const tokenEntry = _bulkCloseTokens.get(confirmToken);
    if (!tokenEntry) {
      return res.status(409).json({ error: "Token de confirmación inválido o expirado. Volvé a previsualizar." });
    }
    if (!Array.isArray(rawCaseIds) || rawCaseIds.length === 0) {
      return res.status(400).json({ error: "caseIds debe ser un array no vacío" });
    }
    if (rawCaseIds.length > 200) {
      return res.status(400).json({ error: "Máximo 200 casos por batch" });
    }
    const caseIds = rawCaseIds.map(String);
    const foreign = caseIds.filter((id) => !tokenEntry.caseIds.has(id));
    if (foreign.length > 0) {
      return res.status(409).json({ error: "caseIds no coinciden con el preview", invalid: foreign.slice(0, 5) });
    }

    const wl = watchlist ?? {};
    const days = Math.max(1, Math.min(90, Number.parseInt(wl.days, 10) || 30));
    const reason = String(wl.reason ?? "").trim() || `Alta masiva al feed por SM ${operatorCi}`;

    let rows;
    try {
      rows = await pgQuery(
        `SELECT id, ioc_value, ioc_type FROM incident_cases_pg WHERE id = ANY($1::text[])`,
        [caseIds],
      );
    } catch (err) { return res.status(500).json({ error: `Lookup de casos falló: ${err.message}` }); }

    // Dedup por IP (varios casos pueden compartir el mismo IOC).
    const ipByCase = new Map();
    const ips = new Set();
    for (const r of rows) {
      if (String(r.ioc_type ?? "").toLowerCase() !== "ip") continue;
      const ip = String(r.ioc_value ?? "").trim();
      if (!ip) continue;
      ips.add(ip);
      ipByCase.set(String(r.id), ip);
    }

    const skipped = [], errors = [], addedIps = [];
    let added = 0;
    for (const id of caseIds) {
      if (!ipByCase.has(id)) skipped.push({ caseId: id, reason: "IOC no es IP pública" });
    }
    for (const ip of ips) {
      try {
        await watchlistManualInclude({ ip, addedBy: operatorCi, reason, days });
        added++; addedIps.push(ip);
      } catch (e) {
        errors.push({ ip, error: e?.message ?? "error", code: e?.code });
      }
    }

    getIo()?.emit("incident:bulk-watchlist-done", { count: added, operatorCi });
    logger.info("incidents.bulk_watchlist", {
      operatorCi, requested: caseIds.length, uniqueIps: ips.size, added, errors: errors.length,
    });
    res.json({
      ok: true, added, uniqueIps: ips.size, skipped: skipped.length, errors,
      addedIps: addedIps.slice(0, 50),
    });
  });

  // ── POST /api/incidents/bulk-assign ────────────────────────────────────────
  // Asigna en lote N casos a un operador concreto. Pensado como salida del
  // banner "X casos sin asignar" (LEADER distribuye huérfanos al Shift Manager
  // o reparte entre L1 activos). Diseño consciente:
  //   - RBAC: sólo LEADER/ADMIN. Asignar a otros no es trivial; un L1 que
  //     decide redistribuir 50 casos rompe la trazabilidad de adopción.
  //   - Si el caso está en NUEVO, se transiciona a EN_ANALISIS (mismo patrón
  //     que /adopt — un asignado no debería quedar en NUEVO porque ya tiene
  //     dueño y entra en el pipeline operativo).
  //   - Best-effort por caso: errores individuales NO abortan el batch;
  //     se reportan en `errors[]` con caseId + motivo. El operador ve qué falló.
  //   - WS + KPI cache invalidation se cablean vía pgUpsertCase (P0.2/P0.3).
  //   - Notification única al target con el resumen del batch (evita 200
  //     toasts si se asignan 200 casos).
  router.post("/bulk-assign", async (req, res) => {
    const { caseIds, targetCi: rawTargetCi, reason } = req.body ?? {};

    // ── Identidad del operador que ejecuta ──────────────────────────────────
    const jwtCi = await resolveJwtOperatorCi(req);
    if (!jwtCi) return res.status(400).json({ error: "CI del operador no resuelto" });

    // ── RBAC: LEADER/ADMIN asigna a CUALQUIER operador. Un operador no-líder
    //    sólo puede AUTOASIGNARSE en lote ("Tomar yo") — targetCi === su propio
    //    CI; es adopción masiva, no reasignación de terceros. ──────────────────
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    const isLeader = roles.includes("manager") || roles.includes("admin");
    const isSelfAssign = String(rawTargetCi ?? "").trim() === jwtCi && jwtCi.length >= 5;
    if (!isLeader && !isSelfAssign) {
      logger.warn("incidents.bulk_assign.forbidden", {
        ci: jwtCi, user: req.user?.preferred_username, roles, targetCi: rawTargetCi,
      });
      return res.status(403).json({ error: "Sólo LEADER/ADMIN puede asignar a otro operador (podés autoasignarte tus casos)" });
    }

    // ── Validación de inputs ────────────────────────────────────────────────
    if (!Array.isArray(caseIds) || caseIds.length === 0) {
      return res.status(400).json({ error: "caseIds debe ser un array no vacío" });
    }
    if (caseIds.length > 200) {
      return res.status(400).json({ error: "Máximo 200 casos por batch" });
    }
    const UUID_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
    const invalidIds = caseIds.filter((id) => typeof id !== "string" || !UUID_RE.test(id));
    if (invalidIds.length > 0) {
      return res.status(400).json({ error: "caseIds contiene UUIDs inválidos", invalid: invalidIds.slice(0, 5) });
    }
    const targetCi = String(rawTargetCi ?? "").trim();
    if (targetCi.length < 5) {
      return res.status(400).json({ error: "targetCi requerido (CI del destinatario)" });
    }

    // ── Validar destinatario: existe + activo. Si no, evitamos crear casos
    //    asignados a un operador fantasma que nadie va a trabajar. ────────────
    let targetRow;
    try {
      const r = await pgQuery(
        `SELECT id, name, role_id, is_active FROM soc_operators WHERE id = $1 LIMIT 1`,
        [targetCi],
      );
      targetRow = r[0];
    } catch (err) {
      return res.status(500).json({ error: `No se pudo validar destinatario: ${err.message}` });
    }
    if (!targetRow) {
      return res.status(404).json({ error: `Operador ${targetCi} no existe en soc_operators` });
    }
    if (!targetRow.is_active) {
      return res.status(400).json({ error: `Operador ${targetCi} no está activo` });
    }

    // ── Traer status/severity actuales para decidir transición. Una sola
    //    query con ANY($1) en vez de N selects. ──────────────────────────────
    let currentRows;
    try {
      currentRows = await pgQuery(
        // id es varchar(64) (uuid con guiones O hex32 de autoClassify). Cast a
        // ::text[] — con ::uuid[] Postgres tira "operator does not exist:
        // character varying = uuid" y bulk-assign devolvía 500 (asignación a SW).
        `SELECT id, status, severity, score, operator_id
           FROM incident_cases_pg
          WHERE id = ANY($1::text[])`,
        [caseIds],
      );
    } catch (err) {
      return res.status(500).json({ error: `Lookup de casos falló: ${err.message}` });
    }
    const byId = new Map(currentRows.map((r) => [String(r.id), r]));

    const now = new Date().toISOString();
    const reasonText = String(reason ?? "").trim() || `Asignación en lote por ${jwtCi}`;
    const detail = `Asignado a ${targetRow.name ?? targetCi} (${targetCi}) por ${jwtCi}: ${reasonText}`;

    let assigned = 0;
    const skipped = [];
    const errors  = [];
    const assignedIds = [];

    for (const id of caseIds) {
      const row = byId.get(String(id));
      if (!row) {
        skipped.push({ caseId: id, reason: "no encontrado en PG" });
        continue;
      }
      // Si el caso ya está cerrado/FP no tiene sentido reasignar — saltamos
      // con motivo explícito para que el caller lo vea en `skipped`.
      if (row.status === "CERRADO" || row.status === "FALSO_POSITIVO") {
        skipped.push({ caseId: id, reason: `caso ya está ${row.status}` });
        continue;
      }
      // Transición NUEVO → EN_ANALISIS al asignar (mismo patrón que /adopt).
      // Para el resto de estados (EN_ANALISIS/CONFIRMADO/MONITOREADO/ESCALADO)
      // conservamos el status — sólo cambia el owner.
      const nextStatus = row.status === "NUEVO" ? "EN_ANALISIS" : row.status;
      try {
        // adoptedAt: sólo se setea si el caso era huérfano (sin operator_id).
        // Si ya tenía dueño y le cambiamos el dueño, NO pisamos el adopted_at
        // original — preserva la métrica L1→L2 (escalated_at - adopted_at)
        // que cuenta desde la primera adopción real (audit migración 064).
        // `undefined` hace que pgUpsertCase skipee la columna; `null` la pisaría.
        await pgUpsertCase(String(id), {
          severity:      String(row.severity ?? "MEDIUM").toUpperCase(),
          status:        nextStatus,
          score:         Number(row.score ?? 50),
          operatorId:    targetCi,
          adoptedAt:     row.operator_id ? undefined : now,
          timelineEntry: buildTimelineEntry("ASSIGN", jwtCi, detail),
        });
        assigned++;
        assignedIds.push(String(id));
      } catch (err) {
        errors.push({ caseId: id, error: err.message });
      }
    }

    // Sync índice canónico (best-effort, paralelo a bulk-escalate). El KPI
    // cache ya quedó invalidado por cada pgUpsertCase via P0.2.
    if (assignedIds.length > 0) {
      void mirrorCasesToIndex(assignedIds).catch(() => {});
    }

    // Notificación única al destinatario con el resumen del batch — evita
    // saturar la campana con N toasts si se asignaron 50 casos.
    if (assigned > 0) {
      try {
        await createNotification({
          operatorId: targetCi,
          type:       "CASE_ASSIGNED_BULK",
          priority:   "MEDIUM",
          title:      `${assigned} caso${assigned === 1 ? "" : "s"} asignado${assigned === 1 ? "" : "s"} a tu cola`,
          body:       `${jwtCi} te asignó ${assigned} caso${assigned === 1 ? "" : "s"} en lote. Motivo: ${reasonText}`,
          io:         getIo(),
        });
      } catch (notifErr) {
        logger.warn("incidents.bulk_assign.notification_failed", { targetCi, err: notifErr.message });
      }
    }

    // Evento WS agregado: el front escucha incident:status_change y dispara
    // invalidateAll() — refresca KPIs, tabla y facets. caseIds permite a
    // listeners downstream filtrar sin pegar al backend.
    getIo()?.emit("incident:status_change", {
      source:  "bulk-assign",
      count:   assigned,
      caseIds: assignedIds,
      targetCi,
    });

    res.json({
      ok: true,
      assigned,
      skipped: skipped.length,
      errors:  errors.length,
      target:  { ci: targetCi, name: targetRow.name, role: targetRow.role_id },
      detail:  { skipped, errors },
    });
  });

  // ── POST /api/incidents/open-from-leak ─────────────────────────────────────
  // Apertura de caso a partir de una detección de credenciales fugadas
  // (Vigilancia Digital → TabCredenciales). Modelo: 1 caso = 1 dominio × 1 dump.
  //
  // Esta ruta es PG-only por diseño: no toca Iceberg `incident_cases` (hoy con
  // metadata corrupta) y no necesita perfiles de apertura — el operador firma
  // explícitamente la decisión adjuntando su CI. La dedup se hace contra PG por
  // (ioc_value, ioc_type='domain', dedup_key embebido en enrichment_data) en
  // ventana de 30 días.
  router.post("/open-from-leak", async (req, res) => {
    const {
      domain,
      operatorCi,
      riskScore,
      riskLabel,
      leakSource,         // { filename, s3Key, sourceLabel }
      metrics,            // objeto libre con conteos
      topAffectedUsers,   // array (top 20)
      criticalServices,   // array
      riskFactors,        // array
      dedupKey: dedupKeyIn,
      force = false,
    } = req.body ?? {};

    // ── Validaciones mínimas ────────────────────────────────────────────────
    const dom = String(domain ?? "").trim().toLowerCase().replace(/^\.+/, "");
    if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(dom) || dom.length < 3 || dom.length > 253) {
      return res.status(400).json({ error: "domain inválido" });
    }
    const ci = String(operatorCi ?? "").trim();
    if (ci.length < 5) return res.status(400).json({ error: "CI inválido (mín. 5 caracteres)" });

    // Verifica que el CI corresponda a un operador registrado en soc_operators.
    // Si no existe, el caso se crea como NUEVO sin owner y se anota el trigger
    // en el timeline. Esto evita romper el FK fk_cases_operator pero preserva
    // trazabilidad de quién disparó la apertura.
    let registeredOperator = null;
    try {
      const opRows = await pgQuery(
        `SELECT id, name FROM soc_operators WHERE id = $1 AND is_active = true LIMIT 1`,
        [ci],
      );
      registeredOperator = opRows[0] ?? null;
    } catch { /* tabla puede no existir en envs aislados — degradar */ }

    const score = Math.max(0, Math.min(100, Number(riskScore ?? 0) | 0));

    // Mapeo severity ← riskScore vía la autoridad única Node (R3 audit
    // 2026-06-05): severityFromScore espeja al DAG _severity_from_score (5
    // niveles, NEGLIGIBLE<10). Antes este path reimplementaba el mapeo inline
    // con sólo 4 niveles → un score<10 quedaba LOW acá pero NEGLIGIBLE vía DAG.
    // Umbrales mutables en runtime (R15): cache TTL 30s sobre soc_thresholds.
    const sev = severityFromScore(score);

    // dedup_key estable: dominio + slug del leak (filename o s3Key). Si el
    // cliente no lo envía, lo derivamos para que re-procesar el mismo dump
    // produzca un 409 en lugar de duplicar el caso.
    const leakSlug = String(
      leakSource?.s3Key ?? leakSource?.filename ?? leakSource?.sourceLabel ?? "unknown"
    ).trim().toLowerCase();
    const dedupKey = String(dedupKeyIn ?? `leak|${dom}|${leakSlug}`).slice(0, 256);

    // ── Dedup PG: mismo dominio + dedupKey activo en ventana 30 días ────────
    if (!force) {
      const dupRows = await pgQuery(
        `SELECT id, severity, status, score, operator_id,
                enrichment_data->>'dedup_key' AS dk
         FROM incident_cases_pg
         WHERE ioc_value = $1
           AND ioc_type  = 'domain'
           AND status NOT IN ('CERRADO','FALSO_POSITIVO')
           AND created_at >= now() - INTERVAL '30 days'
         ORDER BY created_at DESC
         LIMIT 5`,
        [dom],
      );
      const dup = dupRows.find((r) => r.dk === dedupKey) ?? dupRows[0];
      if (dup) {
        return res.status(409).json({
          error:            "Ya existe un caso activo para este dominio en los últimos 30 días",
          existingCaseId:   dup.id,
          existingStatus:   dup.status,
          existingSeverity: dup.severity,
          existingScore:    dup.score,
          existingOperator: dup.operator_id,
          dedupKeyMatch:    dup.dk === dedupKey,
          hint:             dup.dk === dedupKey
            ? "Mismo dump ya analizado. Añade re-ocurrencia con POST /:id/add-occurrence."
            : "Otro dump del mismo dominio sigue abierto. Usa force=true para abrir caso paralelo.",
        });
      }
    }

    // ── Construcción del enrichment_data documental ─────────────────────────
    const safeArray = (a, n = 20) => Array.isArray(a) ? a.slice(0, n) : [];
    const enrichmentData = {
      detection: "leak_intel",
      domain: dom,
      dedup_key: dedupKey,
      leak_source: {
        filename:    leakSource?.filename    ?? null,
        s3_key:      leakSource?.s3Key       ?? null,
        sourceLabel: leakSource?.sourceLabel ?? null,
      },
      metrics: metrics && typeof metrics === "object" ? metrics : {},
      risk: { score, label: riskLabel ?? null },
      top_affected_users: safeArray(topAffectedUsers, 20),
      critical_services:  safeArray(criticalServices, 20),
      risk_factors:       safeArray(riskFactors, 20),
      created_from: "vigilancia-digital/credenciales",
    };

    // ── Texto de acción recomendada ─────────────────────────────────────────
    const emailsAffected = Number(
      metrics?.emailsForOrg ?? metrics?.emails_for_org ?? metrics?.emailsExposed ?? 0
    );
    const recommendedAction = [
      `Forzar reset de contraseña para ${emailsAffected || "todas las"} cuentas afectadas del dominio ${dom}`,
      "Habilitar/verificar MFA en Webmail y O365 para usuarios listados",
      "Auditar Sign-in logs (O365) últimos 90 días para detectar accesos sospechosos",
      "Notificar a usuarios afectados y registrar evidencia del dump en case_evidences",
    ].join(" | ");

    const caseId = randomUUID();
    const now    = new Date().toISOString();

    const summaryDetail =
      `Dump '${leakSource?.filename ?? leakSource?.sourceLabel ?? "leak"}' afecta al dominio ${dom}. ` +
      `Risk ${score}/100 (${riskLabel ?? sev}). Top user: ${
        safeArray(topAffectedUsers, 1)[0]?.email ?? "n/d"
      }. Servicios críticos: ${safeArray(criticalServices, 3).map((s) => s?.label ?? s?.name ?? s).join(", ") || "—"}.`;

    // Operador registrado → caso adoptado (EN_ANALISIS). Si no, NUEVO sin owner.
    const adopted = !!registeredOperator;
    const triggerNote = adopted
      ? summaryDetail
      : `[trigger CI=${ci} no registrado como operador] ${summaryDetail}`;

    try {
      await pgUpsertCase(caseId, {
        severity:           sev,
        status:             adopted ? "EN_ANALISIS" : "NUEVO",
        score,
        operatorId:         adopted ? ci  : undefined,
        adoptedAt:          adopted ? now : undefined,
        iocValue:           dom,
        iocType:            "domain",
        sourceLog:          "leak_intel",
        mitreTacticId:      "TA0006",
        mitreTacticName:    "Acceso a credenciales",
        mitreTechniqueId:   "T1589",   // Gather Victim Identity Information: Email Addresses
        enrichmentData,
        recommendedAction,
        timelineEntry:      buildTimelineEntry("DETECTION", ci, triggerNote),
        // Migration 023: dedup_key habilita lookup en PG para futuros leaks del mismo dominio
        dedupKey:           dedupKey ? String(dedupKey).slice(0, 256) : null,
      });

      // Evento DETECTION en case_timeline_events (fase NIST correcta)
      await pgQuery(
        `INSERT INTO case_timeline_events
           (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source, metadata)
         VALUES ($1,$2,$3::timestamptz,'DETECTION','DETECTION',$4,$5,$6,'LEAK_INTEL',$7)
         ON CONFLICT DO NOTHING`,
        [
          randomUUID(), caseId, now,
          `Detección de credenciales fugadas — ${sev}`,
          summaryDetail,
          ci,
          JSON.stringify({ score, severity: sev, leak_source: enrichmentData.leak_source, dedup_key: dedupKey }),
        ],
      ).catch((e) => logger.warn("open_from_leak.timeline_insert_failed", { caseId, err: e.message }));
    } catch (err) {
      return res.status(500).json({ error: `Error al crear caso: ${err.message}` });
    }

    // ── Auto-prep del caso: pobla case_tasks/case_iocs/case_assets/case_evidences ──
    // Lo que antes era responsabilidad manual del analista (crear cada tarea,
    // registrar IOCs, vincular el dump como evidencia) ahora se genera en el
    // mismo flujo. Falla silenciosa por tabla — si una no existe, no rompe la
    // creación del caso.
    const prep = { tasks: 0, iocs: 0, assets: 0, evidences: 0 };

    // 1. Tasks NIST 800-61 derivadas del playbook leak-intel
    try {
      const taskCtx = {
        severity:        sev,
        domain:          dom,
        emailsAffected:  Number(metrics?.emailsForOrgUnique ?? metrics?.emailsForOrg ?? safeArray(topAffectedUsers).length ?? 0),
        weakPwdRate:     Number(metrics?.weakPwdRate ?? 0),
        stealerRows:     Number(metrics?.stealerRows ?? 0),
        firewallOverlap: Number(metrics?.firewallOverlapCount ?? 0),
        hasCtiSnapshot:  false,                  // sin lookup aquí — se rellena en follow-up
      };
      const tasks = buildLeakIntelTasks(taskCtx);
      for (const t of tasks) {
        const taskId = randomUUID();
        const dueAt  = new Date(Date.now() + t.due_offset_min * 60_000).toISOString();
        await pgQuery(
          `INSERT INTO case_tasks
             (id, case_id, title, description, phase, status, assignee, due_at, sort_order, created_by)
           VALUES ($1,$2,$3,$4,$5,'OPEN',$6,$7::timestamptz,$8,$9)`,
          [taskId, caseId, t.title, t.description, t.phase, registeredOperator ? ci : null, dueAt, t.sort_order, ci],
        );
        prep.tasks += 1;
      }
    } catch (e) {
      logger.warn("open_from_leak.tasks_bootstrap_failed", { caseId, err: e.message });
    }

    // 2. IOCs: dominio primario + cada email afectado como IOC type=email
    try {
      // Dominio principal
      await pgQuery(
        `INSERT INTO case_iocs (id, case_id, ioc_type, ioc_value, tlp, description, is_primary, added_by)
         VALUES ($1,$2,'domain',$3,'AMBER',$4,true,$5)
         ON CONFLICT DO NOTHING`,
        [randomUUID(), caseId, dom,
         `Dominio impactado por filtración (fuente: ${leakSource?.filename ?? "leak"}).`,
         ci],
      );
      prep.iocs += 1;

      // Hasta 30 emails (lo suficiente para enriquecer; el dump completo queda en S3)
      const seen = new Set();
      for (const u of safeArray(topAffectedUsers, 30)) {
        const email = String(u?.email ?? "").trim().toLowerCase();
        if (!email || !email.includes("@") || seen.has(email)) continue;
        seen.add(email);
        await pgQuery(
          `INSERT INTO case_iocs (id, case_id, ioc_type, ioc_value, tlp, description, is_primary, added_by)
           VALUES ($1,$2,'email',$3,'AMBER',$4,false,$5)
           ON CONFLICT DO NOTHING`,
          [randomUUID(), caseId, email,
           `Cuenta filtrada · ${u?.hits ?? 0} hits · ${u?.uniquePwds ?? 0} pwds únicos · ${(u?.topServices ?? []).slice(0,2).join(", ") || "—"}`,
           ci],
        );
        prep.iocs += 1;
      }
    } catch (e) {
      logger.warn("open_from_leak.iocs_bootstrap_failed", { caseId, err: e.message });
    }

    // 3. Assets: dominio como NETWORK + top-3 usuarios como USER
    try {
      await pgQuery(
        `INSERT INTO case_assets
           (id, case_id, asset_type, asset_value, domain, description, compromised, added_by)
         VALUES ($1,$2,'NETWORK',$3,$3,$4,true,$5)
         ON CONFLICT DO NOTHING`,
        [randomUUID(), caseId, dom,
         `Dominio organizativo con credenciales filtradas. ${safeArray(topAffectedUsers).length} cuentas identificadas.`,
         ci],
      );
      prep.assets += 1;
      for (const u of safeArray(topAffectedUsers, 3)) {
        const email = String(u?.email ?? "").trim().toLowerCase();
        if (!email || !email.includes("@")) continue;
        await pgQuery(
          `INSERT INTO case_assets
             (id, case_id, asset_type, asset_value, domain, description, compromised, added_by)
           VALUES ($1,$2,'USER',$3,$4,$5,true,$6)
           ON CONFLICT DO NOTHING`,
          [randomUUID(), caseId, email, dom,
           `Cuenta con credenciales filtradas (${u?.hits ?? 0} apariciones, ${u?.uniquePwds ?? 0} pwds únicas).`,
           ci],
        );
        prep.assets += 1;
      }
    } catch (e) {
      logger.warn("open_from_leak.assets_bootstrap_failed", { caseId, err: e.message });
    }

    // 4. Evidencias: el dump fuente + (si existe) la s3Key
    try {
      await pgQuery(
        `INSERT INTO case_evidences
           (id, case_id, evidence_type, name, description, collected_by, storage_path, tags)
         VALUES ($1,$2,'DUMP',$3,$4,$5,$6,$7::text[])`,
        [
          randomUUID(), caseId,
          `Dump fuente: ${leakSource?.filename ?? "leak"}`,
          `Snapshot de Leak Intel Hub que originó este caso. ${score}/100 risk score. ` +
          `dedup_key=${dedupKey}.`,
          ci,
          leakSource?.s3Key ?? null,
          ["leak-intel", "vigilancia-digital", `domain:${dom}`],
        ],
      );
      prep.evidences += 1;
    } catch (e) {
      logger.warn("open_from_leak.evidence_bootstrap_failed", { caseId, err: e.message });
    }

    // 5. NIST 800-61 prefill — heurísticas básicas según severidad/scope
    try {
      const emailsScope = Number(metrics?.emailsForOrgUnique ?? metrics?.emailsForOrg ?? 0);
      const incidentCategory  = "Unauthorized Disclosure of Information";
      const functionalImpact  = sev === "CRITICAL" ? "HIGH"
                               : sev === "HIGH"     ? "MEDIUM"
                               : "LOW";
      const informationImpact = emailsScope >= 100 ? "PROPRIETARY_BREACH"
                               : emailsScope >= 10  ? "PRIVACY_BREACH"
                               : "INTEGRITY_LOSS";
      const recoverability    = (Number(metrics?.stealerRows ?? 0) > 0) ? "SUPPLEMENTED" : "REGULAR";
      await pgQuery(
        `UPDATE incident_cases_pg
            SET incident_category   = COALESCE(incident_category, $2),
                functional_impact   = COALESCE(functional_impact, $3),
                information_impact  = COALESCE(information_impact, $4),
                recoverability      = COALESCE(recoverability, $5)
          WHERE id = $1`,
        [caseId, incidentCategory, functionalImpact, informationImpact, recoverability],
      );
    } catch (e) {
      logger.warn("open_from_leak.nist_prefill_failed", { caseId, err: e.message });
    }

    // Notificación en tiempo real para refrescar listas
    try { getIo()?.emit("incident:created", { source: "leak_intel", caseId, severity: sev, score, prep }); } catch { /* */ }

    res.status(201).json({
      ok: true,
      caseId,
      severity: sev,
      score,
      dedupKey,
      adopted,
      operatorId: adopted ? ci : null,
      prep,                                   // { tasks, iocs, assets, evidences }
      url: `/gestion/incidentes?case=${encodeURIComponent(caseId)}`,
    });

    // ── Follow-up 5: auto-lookup CTI Cloud & Olé en background ────────────
    // No bloquea la respuesta (ya enviada arriba). El frontend recibe el
    // socket event "cti:snapshot_ready" cuando completa y puede refrescar
    // la vista del caso. Respeta el throttle 6h: si hay snapshot reciente,
    // es un no-op cheap.
    if (typeof ensureFreshCtiSnapshot === "function") {
      setImmediate(() => {
        ensureFreshCtiSnapshot(dom, caseId)
          .then((r) => {
            if (r?.fetched) {
              // Anotar en el timeline del caso para que el analista vea que la
              // info externa se enriqueció automáticamente.
              pgQuery(
                `INSERT INTO case_timeline_events
                   (id, case_id, event_ts, event_type, phase, title, description, operator_ci, source, metadata)
                 VALUES ($1,$2, now(), 'ENRICHMENT', 'IDENTIFICATION',
                   $3, $4, 'system', 'cti-auto-lookup', $5)`,
                [
                  randomUUID(), caseId,
                  `CTI Cloud & Olé enriquecimiento automático — ${r.count ?? 0} hits`,
                  `Búsqueda automática post-apertura: ${r.count ?? 0} credenciales filtradas adicionales detectadas en CTI Cloud & Olé para ${dom}. JSON crudo en S3: ${r.s3Key ?? "n/d"}.`,
                  JSON.stringify({ count: r.count, s3Key: r.s3Key, domain: dom }),
                ],
              ).catch((e) => logger.warn("open_from_leak.cti_timeline_insert_failed", { caseId, err: e.message }));
            }
          })
          .catch((e) => logger.warn("open_from_leak.cti_auto_lookup_failed", { caseId, err: e?.message }));
      });
    }
  });

  return router;
}

// ── Mapeo incident_cases → SocCase frontend ────────────────────────────────────
// pgRow: fila de incident_cases_pg (enriquecimiento, escalación, timeline, slack)

// isRfc1918 ahora vive en services/netClass.mjs (fuente única; ver import arriba).

/**
 * Frente A (audit 2026-05-21): `resolveNetworkZone` y `labelOrigenSistema` se
 * delegan al catálogo `legacyhunt_soc.source_log_catalog` (mig 056) vía
 * `services/sourceLogCatalog.mjs`. Los wrappers locales se mantienen para que
 * los call sites existentes no necesiten cambiar.
 *
 * Para agregar un sensor nuevo: INSERT en la tabla + actualizar el seed de
 * la mig 056. El cache se refresca cada 5min o vía `invalidateCatalogCache()`.
 */
const resolveNetworkZone   = (sourceLog) => catalogNetworkZone(sourceLog);
const labelOrigenSistema   = (sourceLog) => catalogSensorLabel(sourceLog);

function mapCaseRow(r, pgRow) {
  const sev = String(r.severity_text ?? "MEDIUM").toUpperCase();

  // PG es la fuente autoritativa del estado operacional (transiciones de workflow,
  // cierre, FP). Iceberg sólo se usa como fallback para casos sin fila PG todavía.
  const status = normalizeStatus(pgRow?.pg_status ?? r.status);

  // score_breakdown: prioridad — columnas directas Iceberg > score_breakdown JSON
  // > enrichment_data PG (fuente operacional cuando Iceberg está stale o vacío).
  // Si el mirror aún no propagó, PG tiene los valores reales en enrichment_data.
  let scoreBreakdown = { mitre: 0, evidence: 0, wazuh: 0, misp: 0, context: 0 };
  try {
    const bd = (() => { try { return JSON.parse(r.score_breakdown ?? "{}"); } catch { return {}; } })();
    const ed = pgRow?.enrichment_data ?? {};
    const pick = (icebergCol, bdSnake, bdShort, edSnake) =>
      Number(icebergCol ?? bd[bdSnake] ?? bd[bdShort] ?? ed[edSnake] ?? 0);
    scoreBreakdown = {
      mitre:    pick(r.score_mitre,    "score_mitre",    "mitre",    "score_mitre"),
      evidence: pick(r.score_evidence, "score_evidence", "evidence", "score_evidence"),
      wazuh:    pick(r.score_wazuh,    "score_wazuh",    "wazuh",    "score_wazuh"),
      misp:     pick(r.score_misp,     "score_misp",     "misp",     "score_misp"),
      context:  pick(r.score_context,  "score_context",  "context",  "score_context"),
    };
  } catch { /* usa defaults */ }

  // raw_context de enriched_ioc (JOIN en GET /open) → hostname, dst_ip, src_ip
  let ctx = {};
  try { ctx = JSON.parse(r.raw_context ?? "{}"); } catch { /* vacío */ }

  // Enriquecimiento: prioridad a PG (operacional) > Iceberg columnas directas
  const enrData = pgRow?.enrichment_data ?? {};
  const enrichment = {
    vtMalicious:     enrData.vt_malicious     ?? (r.vt_malicious     != null ? Number(r.vt_malicious)     : null),
    vtSuspicious:    enrData.vt_suspicious    ?? (r.vt_suspicious    != null ? Number(r.vt_suspicious)    : null),
    abuseConfidence: enrData.abuse_confidence ?? (r.abuse_confidence != null ? Number(r.abuse_confidence) : null),
    inUrlhaus:       enrData.in_urlhaus  ?? Boolean(r.in_urlhaus),
    inOpenphish:     enrData.in_openphish ?? Boolean(r.in_openphish),
  };

  // Escalación: prioridad PG (columnas estructuradas) > Iceberg
  const escLevel = pgRow?.escalation_level ?? r.escalation_level ?? null;
  const escalation = escLevel ? {
    level:       escLevel,
    escalatedTo: pgRow?.escalated_to      ?? r.escalated_to      ?? null,
    escalatedAt: pgRow?.escalated_at      ? new Date(pgRow.escalated_at).toISOString()
                                          : (r.escalated_at ? new Date(r.escalated_at).toISOString() : null),
    reason:      pgRow?.escalation_reason ?? r.escalation_reason ?? null,
  } : null;

  // recommended_action: columna dedicada > filtrar [ESCALADO...] de notes (datos históricos)
  const rawNotes = String(r.notes ?? "");
  const recommendedAction =
    pgRow?.recommended_action
    ?? r.recommended_action
    ?? (rawNotes
        .split("\n")
        .filter((l) => !l.startsWith("[ESCALADO"))
        .join("\n")
        .trim() || null);

  // adoptedAt: PG adopted_at (preciso) > Iceberg adopted_at > fallback last_seen si hay operador
  const adoptedAt =
    pgRow?.adopted_at
      ? new Date(pgRow.adopted_at).toISOString()
      : r.adopted_at
        ? new Date(r.adopted_at).toISOString()
        : null;

  // Timeline desde PG
  let timeline = [];
  try {
    timeline = Array.isArray(pgRow?.timeline) ? pgRow.timeline : JSON.parse(pgRow?.timeline ?? "[]");
  } catch { /* vacío */ }

  // ── Contexto de red desde raw_context ──────────────────────────────────────
  // Jerarquía: ctx.src_ip / ctx.srcip / ioc_value para src;
  //            ctx.dst_ip / ctx.dstip para dst.
  const ctxSrcIp   = ctx.src_ip  || ctx.srcip  || (r.ioc_type === "ip" ? r.ioc_value : null) || null;
  const ctxDstIp   = ctx.dst_ip  || ctx.dstip  || ctx.data?.dstip  || null;
  const ctxDstPort = ctx.dst_port != null ? Number(ctx.dst_port) : null;
  const ctxSrcPort = ctx.src_port != null ? Number(ctx.src_port)
                   : ctx.srcport  != null ? Number(ctx.srcport)  : null;
  // Protocolo: Suricata → proto, Fortigate → proto key=value, OPNsense → proto
  const ctxProto   = (ctx.proto || ctx.protocol || ctx.ip_protocol
                   || ctx.data?.proto || null)?.toString().toLowerCase() ?? null;
  // Acción de firewall: Fortigate (action), OPNsense (filterlog action field)
  const ctxFwAction = (ctx.action || ctx.data?.action || null)?.toString().toUpperCase() ?? null;
  // País origen: resuelto por VT/Shodan tras enriquecimiento
  const ctxCountry  = ctx.srccountry || ctx.country || null;
  const ctxHostname =
    ctx.agent?.name  || ctx.agent?.hostname ||
    ctx.hostname     || ctx.host            || null;
  const ctxUser    = ctx.user || ctx.srcuser || ctx.data?.srcuser || null;

  // ── Sensor/agente origen ────────────────────────────────────────────────────
  // Clave para el registro de sensores (sensor_registry).
  // Jerarquía de resolución:
  //   1. ctx.sensor_host  — campo inyectado por Vector desde la cabecera syslog RFC3164
  //                         (.host) normalizado como sensor_host en enriched_syslog /
  //                         enriched_wazuh_alerts / enrich_wazuh_fluent.
  //                         Identifica el DISPOSITIVO FÍSICO emisor del log:
  //                           OPNsense  → hostname del firewall (ej. "opnsense-fw01")
  //                           Suricata  → hostname OPNsense donde corre el IDS
  //                           Fortigate → hostname del UTM
  //                           Wazuh 9014→ hostname del Wazuh Manager
  //                           Fluent    → wazuh_manager_host inyectado por Fluent Bit
  //   2. ctx.devname      — Fortigate legacy (campo key=value, previo a sensor_host)
  //   3. ctx.agent?.ip    — Wazuh: IP del endpoint monitorizado (agent.ip)
  const sensorKey =
    ctx.sensor_host  ||   // Vector: hostname/IP RFC3164 del dispositivo emisor (todos los paths)
    ctx.devname      ||   // Fortigate legacy (pre sensor_host)
    ctx.agent?.ip    ||   // Wazuh agente: IP del endpoint (legacy)
    null;

  // Flag RFC1918
  const iocIp     = r.ioc_type === "ip" ? String(r.ioc_value ?? "") : null;
  const internal  = isRfc1918(iocIp ?? ctxSrcIp);

  return {
    id:               String(r.case_id ?? ""),
    caseNumber:       pgRow?.case_number != null ? Number(pgRow.case_number) : null,
    caseCode:         formatCaseNumber(pgRow?.case_number),
    severity:         sev,
    status,
    srcIp:            String(r.ioc_value ?? ""),
    iocType:          String(r.ioc_type  ?? "ip"),
    source:           String(r.source_log ?? ""),
    sourceLabel:      labelOrigenSistema(r.source_log),
    sensorKey:        sensorKey,
    score:            Number(r.severity_score ?? 0),
    scoreBreakdown,
    mitre: {
      techniqueId: r.mitre_technique_id ?? null,
      tacticId:    r.mitre_tactic_id    ?? null,
      tacticName:  r.mitre_tactic_name  ?? null,
    },
    enrichment,
    recommendedAction,
    detectedAt:        r.first_seen ? new Date(r.first_seen).toISOString() : null,
    // createdAt: cuándo se INSERTÓ el caso en BD (PG es el reloj de la cola
    // SOC). Diferente de detectedAt (timestamp del evento original en Wazuh).
    // Fallback a first_seen para casos pre-PG.
    createdAt:         pgRow?.created_at ? new Date(pgRow.created_at).toISOString()
                     : r.first_seen     ? new Date(r.first_seen).toISOString()
                     :                    null,
    adoptedAt,
    resolvedAt:        pgRow?.resolved_at ? new Date(pgRow.resolved_at).toISOString() : null,
    // statusEnteredAt: cuándo entró a la fase/estado actual (stage_entered_at,
    // poblado por transitionCase). Alimenta el indicador "tiempo en estado" de
    // la cola para TODOS los estados (antes solo NUEVO/EN_ANALISIS/cerrados).
    statusEnteredAt:   (pgRow?.stage_entered_at ?? r.stage_entered_at)
                         ? new Date(pgRow?.stage_entered_at ?? r.stage_entered_at).toISOString()
                         : null,
    // PG es la fuente de verdad operacional. NO usamos r.assigned_to como
    // fallback porque puede contener CIs históricos que el FK fk_cases_operator
    // habría rechazado (operadores no registrados): mostraría owners falsos
    // y rompería el filtro "Sin asignar".
    operatorCi:        pgRow?.operator_id ?? null,
    closureReason:     r.closure_reason ?? null,
    detectionType:     r.source_category ?? null,
    ruleFamily:        null,
    confidenceLevel:   r.confidence_level ?? null,
    // Clasificación eCSIRT/MISP derivada (taxonomía estándar CSIRT). Cubre TODO
    // caso aunque no tenga categoría NIST manual. Usa enrichment del full-case
    // GET si está disponible; en la cola se deriva de MITRE+IOC+fuente.
    incidentClass:     classifyEcsirt({
      mitreTacticId: r.mitre_tactic_id,
      iocType:       r.ioc_type,
      sourceLog:     r.source_log,
      detectionType: r.source_category,
      enrichment:    (() => {
        const ed = pgRow?.enrichment_data;
        if (!ed) return null;
        const obj = typeof ed === "string" ? (() => { try { return JSON.parse(ed); } catch { return null; } })() : ed;
        return obj?.iocEnrichment ?? obj ?? null;
      })(),
    }),
    alertCount:        r.occurrence_count != null ? Number(r.occurrence_count) : null,
    assetsCount:       r.assets_count     != null ? Number(r.assets_count)     : 0,
    isInternal:        internal,
    slaSec:            getSlaSec(sev),
    escalation,
    timeline,
    slackNotifiedAt:   pgRow?.slack_notified_at
                         ? new Date(pgRow.slack_notified_at).toISOString()
                         : null,
    // ── Contexto de red: PG (operador puede editar) > raw_context (automático) ──
    hostname:          pgRow?.hostname        ?? ctxHostname,
    sourceIp:          pgRow?.source_ip       ?? ctxSrcIp,
    destinationIp:     pgRow?.destination_ip  ?? ctxDstIp,
    destinationPort:   pgRow?.destination_port ?? ctxDstPort,
    sourcePort:        pgRow?.source_port      ?? ctxSrcPort,
    protocol:          pgRow?.protocol         ?? ctxProto,
    firewallAction:    pgRow?.firewall_action  ?? ctxFwAction,
    srcCountry:        pgRow?.src_country      ?? ctxCountry,
    networkZone:       pgRow?.network_zone     ?? null,
    sensorKey:         pgRow?.sensor_key       ?? sensorKey,
    affectedUser:      pgRow?.affected_user    ?? ctxUser,
    assetId:           pgRow?.asset_id         ?? null,
    assetType:         pgRow?.asset_type       ?? null,
    businessImpact:    pgRow?.business_impact  ?? null,
    evidenceLinks:     pgRow?.evidence_links   ?? [],
    // ── NIST SP 800-61: leído de PG, completado por el operador ──────────────
    incidentCategory:  pgRow?.incident_category  ?? null,
    functionalImpact:  pgRow?.functional_impact  ?? null,
    informationImpact: pgRow?.information_impact ?? null,
    recoverability:    pgRow?.recoverability     ?? null,
    containmentStatus: pgRow?.containment_status ?? null,
    rootCause:         pgRow?.root_cause         ?? null,
    lessonsLearned:    pgRow?.lessons_learned    ?? null,
    // ── Escalación automática ────────────────────────────────────────────────
    escalationSuggested:   pgRow?.escalation_suggested    ?? false,
    escalationReasonAuto:  pgRow?.escalation_reason_auto  ?? null,
    // ── Trazabilidad de fusión (migration 050) ───────────────────────────────
    // Si NOT NULL, este caso fue fusionado en el canónico indicado.
    mergedIntoCaseId:      pgRow?.merged_into_case_id     ?? null,
    // ── Enriquecimiento IOC (case_iocs) ──────────────────────────────────────
    enrichment: {
      ...enrichment,
      vtPermalink:   pgRow?._ioc?.vt_permalink  ?? null,
      inMisp:        pgRow?._ioc?.in_misp       ?? false,
      shodanOrg:     null,
      shodanPorts:   [],
      shodanCountry: null,
      enrichedAt:    pgRow?._ioc?.enriched_at
                       ? new Date(pgRow._ioc.enriched_at).toISOString()
                       : null,
      ...(() => {
        try {
          const sh = typeof pgRow?._ioc?.shodan_summary === "string"
            ? JSON.parse(pgRow._ioc.shodan_summary)
            : (pgRow?._ioc?.shodan_summary ?? null);
          if (!sh) return {};
          return {
            shodanOrg:     sh.org     ?? null,
            shodanPorts:   sh.ports   ?? [],
            shodanCountry: sh.country ?? null,
          };
        } catch { return {}; }
      })(),
    },
    governanceContext: (() => {
      const sl = String(r.source_log ?? "");
      if (!["software_governance", "noc_inventory_governance", "noc_down"].includes(sl)) return null;
      const rawEd = pgRow?.enrichment_data;
      const ed = !rawEd
        ? {}
        : typeof rawEd === "string"
          ? (() => { try { return JSON.parse(rawEd); } catch { return {}; } })()
          : rawEd;
      const payload = ed.payload ?? ed;
      return {
        sourceLog: sl,
        incidentType: ed.incident_type ?? null,
        nocDeviceId: ed.noc_device_id ?? ed.node_id ?? payload?.noc_device_id ?? null,
        payload,
        autoOpened: Boolean(ed.auto_opened),
      };
    })(),
  };
}

function normalizeStatus(raw) {
  const s = String(raw ?? "NUEVO").toUpperCase();
  const MAP = {
    NUEVO: "NUEVO", EN_ANALISIS: "EN_ANALISIS", CONFIRMADO: "CONFIRMADO",
    MONITOREADO: "MONITOREADO", ESCALADO: "ESCALADO",
    FALSO_POSITIVO: "FALSO_POSITIVO", CERRADO: "CERRADO",
    ABIERTO: "NUEVO", EN_CURSO: "EN_ANALISIS", CONTENIDO: "CONFIRMADO",
    RESUELTO: "CERRADO", CLOSED: "CERRADO", FALSE_POSITIVE: "FALSO_POSITIVO",
    RESOLVED: "CERRADO",
  };
  return MAP[s] ?? "NUEVO";
}

// ── buildCasesInsert para incident_cases (Iceberg) ───────────────────────────

function buildCasesInsert(r) {
  return `
INSERT INTO ${TCASES} (
  case_id, dedup_key, ioc_value, ioc_type, source_log,
  mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
  source_category, severity_text, severity_rank, severity_score,
  confidence_level, status, occurrence_count,
  first_seen, last_seen, anchor_dt,
  linked_evidence, score_breakdown, notes,
  assigned_to, closure_reason, created_at, updated_at,
  adopted_at, escalation_level, escalated_to, escalated_at, escalation_reason,
  recommended_action
) VALUES (
  ${sq(r.case_id)}, ${sq(r.dedup_key ?? "")}, ${sq(r.ioc_value ?? "")}, ${sq(r.ioc_type ?? "ip")}, ${sq(r.source_log ?? "")},
  ${nullOrSq(r.mitre_technique_id)}, ${nullOrSq(r.mitre_tactic_id)}, ${nullOrSq(r.mitre_tactic_name)},
  ${nullOrSq(r.source_category)}, ${sq(r.severity_text ?? "MEDIUM")},
  ${r.severity_rank  != null ? Number(r.severity_rank)  : "NULL"},
  ${r.severity_score != null ? Number(r.severity_score) : "NULL"},
  ${nullOrSq(r.confidence_level)}, ${sq(r.status ?? "NUEVO")},
  ${r.occurrence_count != null ? Number(r.occurrence_count) : "NULL"},
  ${r.first_seen  ? tsz(r.first_seen)  : "NULL"},
  ${r.last_seen   ? tsz(r.last_seen)   : "NULL"},
  ${r.anchor_dt   ? `DATE '${String(r.anchor_dt).slice(0, 10)}'` : "CURRENT_DATE"},
  ${nullOrSq(r.linked_evidence)}, ${nullOrSq(r.score_breakdown)}, ${nullOrSq(r.notes)},
  ${nullOrSq(r.assigned_to)}, ${nullOrSq(r.closure_reason)},
  ${r.created_at  ? tsz(r.created_at)  : "NOW()"},
  ${r.updated_at  ? tsz(r.updated_at)  : "NOW()"},
  ${r.adopted_at         ? tsz(r.adopted_at)         : "NULL"},
  ${nullOrSq(r.escalation_level)},
  ${nullOrSq(r.escalated_to)},
  ${r.escalated_at       ? tsz(r.escalated_at)       : "NULL"},
  ${nullOrSq(r.escalation_reason)},
  ${nullOrSq(r.recommended_action)}
)`.trim();
}

// ── buildInsert para incident_classifications (mutaciones legacy) ──────────────

function buildInsert(row, overrides = {}) {
  const r  = { ...row, ...overrides };
  const dt = r.classified_at
    ? new Date(r.classified_at).toISOString().slice(0, 10)
    : new Date().toISOString().slice(0, 10);

  return `
INSERT INTO ${TC} (
  incident_key, ioc_value, ioc_type, source_log,
  score, score_mitre, score_evidence, score_wazuh, severity,
  mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
  vt_malicious, vt_suspicious, vt_permalink,
  shodan_ports, shodan_vulns, abuse_confidence,
  in_urlhaus, in_openphish,
  recommended_action, classified_at, dt,
  adopted_by, adopted_at,
  status, resolved_at, closure_notes,
  detection_type, rule_family, confidence_level
) VALUES (
  ${sq(r.incident_key)}, ${sq(r.ioc_value)}, ${sq(r.ioc_type ?? "ip")}, ${sq(r.source_log ?? "")},
  ${Number(r.score ?? 0)}, ${Number(r.score_mitre ?? 0)}, ${Number(r.score_evidence ?? 0)}, ${Number(r.score_wazuh ?? 0)},
  ${sq(r.severity ?? "MEDIUM")},
  ${nullOrSq(r.mitre_technique_id)}, ${nullOrSq(r.mitre_tactic_id)}, ${nullOrSq(r.mitre_tactic_name)},
  ${r.vt_malicious    != null ? Number(r.vt_malicious)    : "NULL"},
  ${r.vt_suspicious   != null ? Number(r.vt_suspicious)   : "NULL"},
  ${nullOrSq(r.vt_permalink)},
  ${nullOrSq(r.shodan_ports)}, ${nullOrSq(r.shodan_vulns)},
  ${r.abuse_confidence != null ? Number(r.abuse_confidence) : "NULL"},
  ${r.in_urlhaus  ? "true" : "false"},
  ${r.in_openphish ? "true" : "false"},
  ${nullOrSq(r.recommended_action)},
  ${r.classified_at ? tsz(r.classified_at) : "NOW()"},
  DATE '${dt}',
  ${nullOrSq(r.adopted_by)},
  ${r.adopted_at  ? tsz(r.adopted_at)  : "NULL"},
  ${nullOrSq(r.status ?? "NUEVO")},
  ${r.resolved_at ? tsz(r.resolved_at) : "NULL"},
  ${nullOrSq(r.closure_notes)},
  ${nullOrSq(r.detection_type)},
  ${nullOrSq(r.rule_family)},
  ${nullOrSq(r.confidence_level)}
)`.trim();
}
