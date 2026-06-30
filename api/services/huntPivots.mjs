/**
 * services/huntPivots.mjs — Lógica del feature "Hunt Pivots".
 *
 * Recibe un pivote (entidad + valor) y orquesta queries Trino para devolver
 * evidencia agregada lista para previsualizar antes de abrir un caso. La
 * persistencia del caso final se delega al endpoint existente
 * `/api/incidents/open-from-flow` — este módulo solo PREPARA.
 *
 * Diseño: docs/HUNT-PIVOTS.md
 * Endpoints que consumen: routes/hunt.mjs
 *
 * Pivots soportados:
 *   - src_ip         → query Wazuh + Fortigate + Filterlog (24h)
 *   - agent_name     → query Wazuh + Wazuh Fluent (24h)
 *   - cve            → query Wazuh vulnerabilities (24h)
 *   - sender_ip      → query PMG phishing (24h)
 *   - sender_domain  → query PMG phishing (24h)
 *   - outlier        → query Iceberg outliers (24h, por outlier_id)
 *
 * NO soportado: dest_port (la tab "Puertos atacados" no abre caso — solo
 * navega a /gestion con filtro).
 */

import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { stringStyleWindow, integerStyleWindow } from "../trino/time-window.mjs";

export const PIVOT_TYPES = Object.freeze([
  "src_ip", "agent_name", "cve",
  "sender_ip", "sender_domain", "outlier",
]);

const TRINO_SESSION = { catalog: "minio", schema: "hunting" };
const ICEBERG_SESSION = { catalog: "minio_iceberg", schema: "hunting" };

// Helpers de ventana 24h reusados por los SQL builders de ranking — antes
// huntPivots construía SQL ad-hoc con `ingest_ts` (columna inexistente) +
// `year=YYYY` (escaneo de año entero). Eso generaba dos bugs combinados:
// (1) queries que fallaban silenciosamente vía Promise.allSettled,
// (2) queries que pasaban el filtro de columnas pero escaneaban TB → timeout
//     a TRINO_QUERY_TOTAL_TIMEOUT_MS (115s) en wazuh_alerts (audit 2026-05-22).
// Ahora usa el mismo combo que el ranking: PART_2D (filter de partición
// últimas 48h) + INGEST_TS >= now-24h para precisión exacta.
const { INGEST_TS: STR_INGEST_TS, PART_2D: STR_PART_2D } = stringStyleWindow();
const { WINDOW_24H_LEX: FLUENT_WINDOW_24H } = integerStyleWindow();

/** Escapa string para SQL literal. Defensa básica contra inyección — los
 *  values pueden venir del cliente (IPs, hostnames, CVEs). */
function esc(v) {
  return `'${String(v ?? "").replace(/'/g, "''")}'`;
}

/** Valida y normaliza el valor según el tipo de pivote. Tira si inválido. */
function normalizeValue(pivot, raw) {
  const v = String(raw ?? "").trim();
  if (!v) throw badRequest("value vacío");
  switch (pivot) {
    case "src_ip":
    case "sender_ip":
      if (!/^[0-9a-fA-F:.]+$/.test(v) || v.length > 45) {
        throw badRequest(`valor inválido para ${pivot}: esperado IPv4/IPv6`);
      }
      return v;
    case "agent_name":
    case "sender_domain":
      if (v.length > 255 || /['"\s]/.test(v)) {
        throw badRequest(`valor inválido para ${pivot}: caracteres prohibidos`);
      }
      return v.toLowerCase();
    case "cve":
      if (!/^CVE-\d{4}-\d{4,7}$/i.test(v)) {
        throw badRequest("valor inválido para cve: esperado CVE-YYYY-NNNN");
      }
      return v.toUpperCase();
    case "outlier":
      if (!/^[0-9a-f-]{36}$/i.test(v)) {
        throw badRequest("valor inválido para outlier: esperado UUID");
      }
      return v.toLowerCase();
    default:
      throw badRequest(`pivot desconocido: ${pivot}`);
  }
}

function badRequest(msg) {
  const e = new Error(msg);
  e.status = 400;
  return e;
}

// ── Aggregate evidence (entry point) ──────────────────────────────────────────

/**
 * Orquesta queries Trino por tipo de pivote. Devuelve evidencia normalizada.
 *
 * @param {Function} runQuery — runTrinoQueryWithInitRetries del server.mjs
 * @param {{pivot:string,value:string}} input
 * @returns {Promise<EvidenceShape>}
 */
export async function aggregateEvidence(runQuery, { pivot, value }) {
  const v = normalizeValue(pivot, value);
  switch (pivot) {
    case "src_ip":        return _evidenceForSrcIp(runQuery, v);
    case "agent_name":    return _evidenceForAgent(runQuery, v);
    case "cve":           return _evidenceForCve(runQuery, v);
    case "sender_ip":     return _evidenceForSender(runQuery, v, "sender_ip");
    case "sender_domain": return _evidenceForSender(runQuery, v, "sender_domain");
    case "outlier":       return _evidenceForOutlier(runQuery, v);
    default:              throw badRequest(`pivot no implementado: ${pivot}`);
  }
}

// ── Evidence builders por pivote ──────────────────────────────────────────────
// Cada uno corre 1-2 queries Trino en paralelo y agrega a la forma estándar:
//   {
//     totalEvents24h, bySource, severityBreakdown, topRules, mitreTactics,
//     lastSeen, representativeEvent, defaultSourceLog, defaultIocType
//   }

async function _evidenceForSrcIp(runQuery, ip) {
  const wazuhSql = `
    SELECT
      CAST(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.level') AS INTEGER) AS lvl,
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.id')           AS rule_id,
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.description')  AS rule_desc,
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.rule.mitre.tactic') AS mitre_tactic,
      ${STR_INGEST_TS} AS ts
    FROM minio.hunting.wazuh_alerts
    WHERE ${STR_PART_2D}
      AND ${STR_INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
      AND json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.srcip') = ${esc(ip)}
    LIMIT 1000`;

  const fortigateSql = `
    SELECT level AS lvl, NULL AS rule_id, NULL AS rule_desc, NULL AS mitre_tactic, ${STR_INGEST_TS} AS ts
    FROM minio.hunting.fortigate
    WHERE ${STR_PART_2D}
      AND ${STR_INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
      AND src_ip = ${esc(ip)}
    LIMIT 1000`;

  const filterlogSql = `
    SELECT NULL AS lvl, NULL AS rule_id, NULL AS rule_desc, NULL AS mitre_tactic, ${STR_INGEST_TS} AS ts
    FROM minio.hunting.syslog
    WHERE ${STR_PART_2D}
      AND ${STR_INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
      AND log_family LIKE 'filterlog_%'
      AND SPLIT_PART(message, ',', 19) = ${esc(ip)}
    LIMIT 1000`;

  const [wazuh, fortigate, filterlog] = await Promise.allSettled([
    runQuery(wazuhSql,     TRINO_SESSION),
    runQuery(fortigateSql, TRINO_SESSION),
    runQuery(filterlogSql, TRINO_SESSION),
  ]);

  const wRows  = pickRows(wazuh,     "src_ip:wazuh_alerts");
  const fgRows = pickRows(fortigate, "src_ip:fortigate");
  const flRows = pickRows(filterlog, "src_ip:filterlog");

  return normalizeEvidence({
    pivot: "src_ip",
    bySource: {
      wazuh_alerts: wRows.length,
      fortigate:    fgRows.length,
      filterlog:    flRows.length,
    },
    severityRows: wRows.map((r) => ({ lvl: wazuhLevelToSev(r.lvl), ts: r.ts, ruleId: r.rule_id, ruleDesc: r.rule_desc, mitre: r.mitre_tactic })),
    fallbackRows: [...fgRows, ...flRows].map((r) => ({ lvl: "LOW", ts: r.ts })),
    defaultIocType:  "ip",
  });
}

async function _evidenceForAgent(runQuery, agentName) {
  // El ranking (topAgents24h) usa COALESCE(agent.name, predecoder.hostname) —
  // algunos hosts solo aparecen via predecoder. Aplicamos el mismo fallback
  // acá para que la preview no muestre 0 eventos contra esos.
  //
  // Agregación en SQL (GROUP BY) — antes traíamos LIMIT 1000 rows × 2 fuentes
  // (2000 rows con json_parse per row) y agregábamos en JS; eso tardaba ~60s
  // contra agentes con tráfico (audit web-ine01.ine.gov.py 2026-05-22).
  // Ahora cada fuente devuelve ~10-50 filas agregadas por (lvl, rule_id,
  // rule_desc) con su COUNT(*) → totales exactos, mismo top-rules, ~3s.
  const wazuhSql = `
    WITH base AS (
      SELECT
        CAST(json_extract_scalar(j, '$.rule.level') AS INTEGER) AS lvl,
        json_extract_scalar(j, '$.rule.id')          AS rule_id,
        json_extract_scalar(j, '$.rule.description') AS rule_desc,
        ${STR_INGEST_TS} AS ts
      FROM (
        SELECT message, ingest_time, year, month, day,
               TRY(json_parse(CAST(message AS varchar))) AS j
        FROM minio.hunting.wazuh_alerts
        WHERE ${STR_PART_2D}
          AND ${STR_INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
      ) p
      WHERE j IS NOT NULL
        AND (
          lower(json_extract_scalar(j, '$.agent.name'))           = ${esc(agentName)}
          OR lower(json_extract_scalar(j, '$.predecoder.hostname')) = ${esc(agentName)}
        )
    )
    SELECT lvl, rule_id, rule_desc, MAX(ts) AS ts, COUNT(*) AS hits
    FROM base
    GROUP BY lvl, rule_id, rule_desc`;

  const fluentSql = `
    SELECT rule_level AS lvl, rule_id, NULL AS rule_desc,
           MAX(${STR_INGEST_TS}) AS ts, COUNT(*) AS hits
    FROM minio.hunting.wazuh_fluent
    WHERE ${STR_PART_2D}
      AND ${STR_INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
      AND lower(agent_name) = ${esc(agentName)}
    GROUP BY rule_level, rule_id`;

  const [wazuh, fluent] = await Promise.allSettled([
    runQuery(wazuhSql,  TRINO_SESSION),
    runQuery(fluentSql, TRINO_SESSION),
  ]);

  const wRows = pickRows(wazuh,  "agent_name:wazuh_alerts");
  const fRows = pickRows(fluent, "agent_name:wazuh_fluent");

  return normalizeEvidence({
    pivot: "agent_name",
    bySource: {
      wazuh_alerts: sumHits(wRows),
      wazuh_fluent: sumHits(fRows),
    },
    severityRows: [
      ...wRows.map((r) => ({ lvl: wazuhLevelToSev(r.lvl), ts: r.ts, ruleId: r.rule_id, ruleDesc: r.rule_desc, hits: Number(r.hits ?? 1) })),
      ...fRows.map((r) => ({ lvl: wazuhLevelToSev(r.lvl), ts: r.ts, ruleId: String(r.rule_id ?? ""), hits: Number(r.hits ?? 1) })),
    ],
    fallbackRows: [],
    defaultIocType: "host",
  });
}

async function _evidenceForCve(runQuery, cveId) {
  // Wazuh vulnerability detection — la regla típica es 23505 (vuln-detector).
  // Buscamos por $.data.vulnerability.cve.
  const sql = `
    SELECT
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.name') AS agent_name,
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.agent.ip')   AS agent_ip,
      json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.vulnerability.severity') AS vuln_sev,
      CAST(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.vulnerability.cvss.cvss3.base_score') AS DOUBLE) AS cvss,
      ${STR_INGEST_TS} AS ts
    FROM minio.hunting.wazuh_alerts
    WHERE ${STR_PART_2D}
      AND ${STR_INGEST_TS} >= current_timestamp - INTERVAL '24' HOUR
      AND upper(json_extract_scalar(json_parse(CAST(message AS varchar)), '$.data.vulnerability.cve')) = ${esc(cveId)}
    LIMIT 1000`;

  const res = await runQuery(sql, TRINO_SESSION).catch(() => []);
  const rows = Array.isArray(res) ? res : [];

  // Severity desde Wazuh vuln-detector (Critical/High/Medium/Low en string).
  const sevRows = rows.map((r) => ({
    lvl: (String(r.vuln_sev || "").toUpperCase()) || cvssToSev(r.cvss),
    ts: r.ts,
    ruleId: cveId,
    ruleDesc: `Host: ${r.agent_name ?? "?"} (${r.agent_ip ?? "?"})`,
  }));

  // KEV lookup en PG (gratis, ya está mig 057).
  let kev = false;
  try {
    const rk = await pgQuery(
      `SELECT 1 FROM legacyhunt_soc.cve_kev WHERE cve_id = $1 LIMIT 1`,
      [cveId],
    );
    kev = rk.length > 0;
  } catch {/* tabla puede no existir aún en algunos entornos */}

  const ev = normalizeEvidence({
    pivot: "cve",
    bySource: { wazuh_alerts: rows.length },
    severityRows: sevRows,
    fallbackRows: [],
    defaultIocType: "cve",
  });
  ev.kev = kev;
  ev.affectedHostsCount = new Set(rows.map((r) => r.agent_name).filter(Boolean)).size;
  return ev;
}

async function _evidenceForSender(runQuery, value, field) {
  // field: "sender_ip" | "sender_domain"
  const sql = `
    SELECT
      spam_score, dmarc_result, spf_result, dkim_result, action,
      recipient_email, ts
    FROM minio.hunting.pmg_phishing
    WHERE year = CAST(year(current_timestamp) AS varchar)
      AND ts >= current_timestamp - INTERVAL '24' HOUR
      AND lower(${field}) = ${esc(value)}
    LIMIT 1000`;

  const res = await runQuery(sql, TRINO_SESSION).catch(() => []);
  const rows = Array.isArray(res) ? res : [];

  // Severity por spam_score: ≥10 HIGH, ≥5 MEDIUM, ≥2 LOW, else NEGLIGIBLE.
  // Auth fail (DMARC/SPF/DKIM = fail) sube un escalón.
  const sevRows = rows.map((r) => {
    const score = Number(r.spam_score ?? 0);
    let lvl = score >= 10 ? "HIGH" : score >= 5 ? "MEDIUM" : score >= 2 ? "LOW" : "NEGLIGIBLE";
    const authFail = [r.dmarc_result, r.spf_result, r.dkim_result]
      .some((x) => String(x || "").toLowerCase() === "fail");
    if (authFail && lvl === "MEDIUM") lvl = "HIGH";
    if (authFail && lvl === "LOW")    lvl = "MEDIUM";
    return { lvl, ts: r.ts, ruleId: r.action ?? null, ruleDesc: r.recipient_email ?? null };
  });

  const ev = normalizeEvidence({
    pivot: field,
    bySource: { pmg_phishing: rows.length },
    severityRows: sevRows,
    fallbackRows: [],
    defaultIocType: field === "sender_ip" ? "ip" : "domain",
  });
  ev.recipientsCount = new Set(rows.map((r) => r.recipient_email).filter(Boolean)).size;
  return ev;
}

async function _evidenceForOutlier(runQuery, outlierId) {
  // Lectura directa al row Iceberg. Severity viene de la columna 'severity'.
  const sql = `
    SELECT outlier_id, entity_type, entity_value, severity, score,
           z_score, iqr_score, isolation_score, anomaly_type, log_family,
           detection_time, baseline_value, observed_value, related_case_id
    FROM minio_iceberg.hunting.outliers
    WHERE outlier_id = ${esc(outlierId)}
    LIMIT 1`;

  const res = await runQuery(sql, ICEBERG_SESSION).catch(() => []);
  const rows = Array.isArray(res) ? res : [];
  if (rows.length === 0) {
    const e = new Error(`outlier ${outlierId} no encontrado`);
    e.status = 404;
    throw e;
  }
  const r = rows[0];

  const sevRows = [{
    lvl: String(r.severity || "MEDIUM").toUpperCase(),
    ts: r.detection_time,
    ruleId: r.anomaly_type,
    ruleDesc: `${r.entity_type}=${r.entity_value} (z=${r.z_score})`,
  }];

  // El defaultIocType deriva del entity_type del outlier.
  const iocType = ({ ip: "ip", domain: "domain", host: "host", user: "user" })[r.entity_type] || "ip";

  const ev = normalizeEvidence({
    pivot: "outlier",
    bySource: { outliers: 1 },
    severityRows: sevRows,
    fallbackRows: [],
    defaultIocType: iocType,
  });
  ev.outlier = {
    outlierId: r.outlier_id,
    entityType: r.entity_type,
    entityValue: r.entity_value,
    zScore: r.z_score,
    iqrScore: r.iqr_score,
    isolationScore: r.isolation_score,
    logFamily: r.log_family,
    relatedCaseId: r.related_case_id,
    baseline: r.baseline_value,
    observed: r.observed_value,
  };
  // El IOC del caso es el entity_value, no el outlier_id.
  ev.iocValue = r.entity_value;
  return ev;
}

// ── Helpers de agregación ─────────────────────────────────────────────────────

/** Suma `hits` de filas pre-agregadas (queries con GROUP BY).
 *  Fallback a r.length para builders que emiten 1 row por evento. */
function sumHits(rows) {
  if (!Array.isArray(rows)) return 0;
  if (rows.length === 0) return 0;
  if (rows[0]?.hits === undefined) return rows.length;
  return rows.reduce((acc, r) => acc + Number(r.hits ?? 0), 0);
}

function pickRows(settled, label = "?") {
  if (settled.status === "fulfilled" && Array.isArray(settled.value)) return settled.value;
  // Surface query rejections que antes quedaban silenciadas. No escala a
  // HTTP 500 (otras fuentes pueden devolver datos válidos) pero deja
  // rastro en logs para detectar schema drift como el reportado 2026-05-22.
  if (settled.status === "rejected") {
    logger.warn("hunt/evidence_query_rejected", {
      label,
      err: settled.reason?.message ?? String(settled.reason),
    });
  }
  return [];
}

function wazuhLevelToSev(lvl) {
  const n = Number(lvl);
  if (Number.isNaN(n)) return "LOW";
  if (n >= 13) return "CRITICAL";
  if (n >= 10) return "HIGH";
  if (n >=  7) return "MEDIUM";
  if (n >=  3) return "LOW";
  return "NEGLIGIBLE";
}

function cvssToSev(cvss) {
  const s = Number(cvss);
  if (s >= 9)   return "CRITICAL";
  if (s >= 7)   return "HIGH";
  if (s >= 4)   return "MEDIUM";
  if (s >  0)   return "LOW";
  return "MEDIUM";
}

function normalizeEvidence({ pivot, bySource, severityRows, fallbackRows, defaultIocType }) {
  // `hits` opcional por row — cuando el builder agrega en SQL (GROUP BY),
  // cada row representa N eventos, no 1. Default 1 para builders que aún
  // emiten una fila por evento (src_ip, cve, sender, outlier).
  const rowHits = (r) => Number(r.hits ?? 1);

  const allRows = [...severityRows, ...fallbackRows];
  const breakdown = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NEGLIGIBLE: 0 };
  for (const r of allRows) {
    const k = breakdown[r.lvl] !== undefined ? r.lvl : "LOW";
    breakdown[k] += rowHits(r);
  }
  // Top 5 reglas (solo de severityRows que tienen ruleId).
  const ruleCount = new Map();
  for (const r of severityRows) {
    if (!r.ruleId) continue;
    const key = String(r.ruleId);
    const prev = ruleCount.get(key) || { hits: 0, desc: r.ruleDesc || null };
    prev.hits += rowHits(r);
    if (!prev.desc && r.ruleDesc) prev.desc = r.ruleDesc;
    ruleCount.set(key, prev);
  }
  const topRules = [...ruleCount.entries()]
    .map(([id, v]) => ({ id, hits: v.hits, desc: v.desc }))
    .sort((a, b) => b.hits - a.hits)
    .slice(0, 5);

  // MITRE tactics (solo presentes si vienen en severityRows).
  const mitreSet = new Set(severityRows.map((r) => r.mitre).filter(Boolean));

  // Último visto + evento representativo (más reciente con severity máxima).
  const sortable = severityRows
    .filter((r) => r.ts)
    .sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
  const lastSeen = sortable[0]?.ts || null;
  const sevOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NEGLIGIBLE: 1 };
  const representativeEvent = severityRows
    .slice()
    .sort((a, b) => (sevOrder[b.lvl] - sevOrder[a.lvl]) || String(b.ts || "").localeCompare(String(a.ts || "")))[0] || null;

  // defaultSourceLog = la fuente con más eventos.
  const defaultSourceLog = Object.entries(bySource)
    .sort((a, b) => b[1] - a[1])[0]?.[0] || "wazuh_alerts";

  return {
    pivot,
    totalEvents24h:      Object.values(bySource).reduce((a, b) => a + b, 0),
    bySource,
    severityBreakdown:   breakdown,
    topRules,
    mitreTactics:        [...mitreSet],
    lastSeen,
    representativeEvent,
    defaultSourceLog,
    defaultIocType,
  };
}

// ── Heurísticas (D1, D2 de docs/HUNT-PIVOTS.md) ───────────────────────────────

/**
 * Sugiere severity del caso a abrir, según breakdown agregado.
 * D1: CRITICAL≥1 → HIGH; HIGH≥5 OR total≥50 → MEDIUM; else LOW.
 */
export function suggestSeverity(evidence) {
  const b = evidence.severityBreakdown || {};
  const total = evidence.totalEvents24h || 0;
  if ((b.CRITICAL ?? 0) >= 1) return "HIGH";
  if ((b.HIGH ?? 0) >= 5 || total >= 50) return "MEDIUM";
  return "LOW";
}

/**
 * Score sugerido. Mapeo conservador desde severity + bonus por volumen.
 * El backend de /open-from-flow puede re-evaluar si el caller pasa
 * `force:false` — esto es solo el default para el modal.
 */
export function suggestScore(evidence) {
  const sev = suggestSeverity(evidence);
  const total = evidence.totalEvents24h || 0;
  const base = ({ HIGH: 60, MEDIUM: 35, LOW: 15 })[sev] ?? 15;
  const bonus = Math.min(20, Math.floor(Math.log10(Math.max(1, total)) * 10));
  return base + bonus;
}

/** Default source_log para el caso a abrir (D5 — la fuente con más count). */
export function suggestSourceLog(evidence) {
  return evidence.defaultSourceLog || "wazuh_alerts";
}

// ── Lookup de caso existente para dedup warning ───────────────────────────────

/**
 * Busca en `legacyhunt_soc.incident_case_index` un caso abierto con el mismo
 * IOC en los últimos 30 días. Devuelve el más reciente o null.
 *
 * El endpoint /open-from-flow hace el dedup CANÓNICO (por dedup_key) — esta
 * función es solo para mostrar warning en la UI ANTES de enviar.
 */
export async function lookupExistingCase(iocValue) {
  if (!iocValue) return null;
  const rows = await pgQuery(
    `SELECT case_id, status, severity_text, severity_score, last_seen, occurrence_count
       FROM legacyhunt_soc.incident_case_index
      WHERE ioc_value = $1
        AND status NOT IN ('CERRADO','FALSO_POSITIVO','RESOLVED','CLOSED','FALSE_POSITIVE')
        AND last_seen >= now() - INTERVAL '30 days'
      ORDER BY last_seen DESC
      LIMIT 1`,
    [iocValue],
  );
  if (rows.length === 0) return null;
  const r = rows[0];
  return {
    caseId:          r.case_id,
    status:          r.status,
    severity:        r.severity_text,
    score:           r.severity_score,
    lastSeen:        r.last_seen,
    occurrenceCount: r.occurrence_count,
  };
}

/**
 * Variante batch para el flag "caso abierto" en la grilla /hunt. Recibe N
 * IOCs y devuelve un Map<iocValue, existingCase>. Usa `DISTINCT ON` para
 * quedarse con la fila más reciente por IOC en una sola query.
 *
 * Devuelve solo las claves con match — la UI trata ausencia como "sin caso".
 *
 * Nota: `incident_case_index` solo persiste rows con ioc_type='ip', por lo que
 * para hosts/CVEs/dominios/senders quedaban sin flag. Consultamos directo a
 * `incident_cases_pg` (source of truth, todos los IOC types).
 */
export async function lookupExistingCasesBatch(iocValues) {
  if (!Array.isArray(iocValues)) return {};
  const unique = [...new Set(iocValues.filter((v) => typeof v === "string" && v.length > 0))];
  if (unique.length === 0) return {};
  const rows = await pgQuery(
    `SELECT DISTINCT ON (ioc_value)
            ioc_value,
            id                                          AS case_id,
            status,
            severity                                    AS severity_text,
            score                                       AS severity_score,
            COALESCE(last_seen, updated_at)             AS last_seen,
            occurrence_count
       FROM incident_cases_pg
      WHERE ioc_value = ANY($1::text[])
        AND status NOT IN ('CERRADO','FALSO_POSITIVO','RESOLVED','CLOSED','FALSE_POSITIVE')
        AND COALESCE(last_seen, updated_at) >= now() - INTERVAL '30 days'
      ORDER BY ioc_value, COALESCE(last_seen, updated_at) DESC`,
    [unique],
  );
  const out = {};
  for (const r of rows) {
    out[r.ioc_value] = {
      caseId:          r.case_id,
      status:          r.status,
      severity:        r.severity_text,
      score:           r.severity_score,
      lastSeen:        r.last_seen,
      occurrenceCount: r.occurrence_count,
    };
  }
  return out;
}
