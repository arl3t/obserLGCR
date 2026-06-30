/**
 * technicalReportService.mjs
 *
 * Genera el Informe TÉCNICO SOC para LEADER/ADMIN — complementario (no sustituto)
 * del Informe Ejecutivo. Mientras el ejecutivo se centra en KPIs de gestión, el
 * técnico profundiza en la huella de amenaza:
 *
 *   1. Resumen y alcance (volumen, severidad, fuentes activas)
 *   2. Top 10 países atacantes (origen geográfico) + datos para mapa mundial
 *   3. Tendencia diaria por severidad (para gráfico de líneas/área)
 *   4. Eventos reincidentes (IOCs que reaparecen — candidatos a bloqueo durable)
 *   5. Cobertura / Top tácticas MITRE ATT&CK
 *   6. Distribución por fuente de detección
 *   7. Top IOCs / atacantes externos
 *
 * Geo: el país sale de `incident_cases_pg.src_country` (ISO alpha-2, indexado).
 * Para los casos sin país persistido se resuelve la IP pública en caliente vía
 * MaxMind offline (geoipService.lookupCountry) — autoritativo y sin red.
 *
 * Fuente: incident_cases_pg (PG, rápido). No toca Trino — evita timeouts de
 * metadata Iceberg, igual que el informe ejecutivo.
 */

import { pgQuery } from "../db/postgres.mjs";
import { lookupCountry } from "./geoipService.mjs";
import { resolveReportRange } from "./executiveReportService.mjs";
import { getTacticPlaybook } from "./casePlaybookService.mjs";

// ── Nombres de país en español (ISO 3166-1 alpha-2). Fallback al código. ──────
const COUNTRY_ES = {
  AF: "Afganistán", AL: "Albania", DZ: "Argelia", AO: "Angola", AR: "Argentina",
  AM: "Armenia", AU: "Australia", AT: "Austria", AZ: "Azerbaiyán", BD: "Bangladés",
  BE: "Bélgica", BO: "Bolivia", BA: "Bosnia y Herzegovina", BR: "Brasil",
  BG: "Bulgaria", BY: "Bielorrusia", KH: "Camboya", CM: "Camerún", CA: "Canadá",
  CL: "Chile", CN: "China", CO: "Colombia", CR: "Costa Rica", HR: "Croacia",
  CU: "Cuba", CY: "Chipre", CZ: "Chequia", DK: "Dinamarca", DO: "Rep. Dominicana",
  EC: "Ecuador", EG: "Egipto", SV: "El Salvador", EE: "Estonia", ET: "Etiopía",
  FI: "Finlandia", FR: "Francia", GE: "Georgia", DE: "Alemania", GH: "Ghana",
  GR: "Grecia", GT: "Guatemala", HN: "Honduras", HK: "Hong Kong", HU: "Hungría",
  IS: "Islandia", IN: "India", ID: "Indonesia", IR: "Irán", IQ: "Irak",
  IE: "Irlanda", IL: "Israel", IT: "Italia", JM: "Jamaica", JP: "Japón",
  JO: "Jordania", KZ: "Kazajistán", KE: "Kenia", KP: "Corea del Norte",
  KR: "Corea del Sur", KW: "Kuwait", KG: "Kirguistán", LA: "Laos", LV: "Letonia",
  LB: "Líbano", LY: "Libia", LT: "Lituania", LU: "Luxemburgo", MY: "Malasia",
  MX: "México", MD: "Moldavia", MN: "Mongolia", ME: "Montenegro", MA: "Marruecos",
  MM: "Myanmar", NP: "Nepal", NL: "Países Bajos", NZ: "Nueva Zelanda",
  NI: "Nicaragua", NG: "Nigeria", MK: "Macedonia del Norte", NO: "Noruega",
  OM: "Omán", PK: "Pakistán", PA: "Panamá", PY: "Paraguay", PE: "Perú",
  PH: "Filipinas", PL: "Polonia", PT: "Portugal", QA: "Catar", RO: "Rumanía",
  RU: "Rusia", SA: "Arabia Saudita", RS: "Serbia", SG: "Singapur", SK: "Eslovaquia",
  SI: "Eslovenia", ZA: "Sudáfrica", ES: "España", LK: "Sri Lanka", SD: "Sudán",
  SE: "Suecia", CH: "Suiza", SY: "Siria", TW: "Taiwán", TJ: "Tayikistán",
  TZ: "Tanzania", TH: "Tailandia", TN: "Túnez", TR: "Turquía", TM: "Turkmenistán",
  UG: "Uganda", UA: "Ucrania", AE: "Emiratos Árabes Unidos", GB: "Reino Unido",
  US: "Estados Unidos", UY: "Uruguay", UZ: "Uzbekistán", VE: "Venezuela",
  VN: "Vietnam", YE: "Yemen", ZM: "Zambia", ZW: "Zimbabue",
};

function countryNameEs(cc) {
  if (!cc) return "Desconocido";
  return COUNTRY_ES[cc] ?? cc;
}

// Países de mayor riesgo (espejo informativo de geo_risk_config). Sólo para
// resaltar en el informe; el peso real lo aplica el scoring v4.
const HIGH_RISK_CC = new Set(["KP", "IR", "RU", "CN", "SY", "CU", "BY"]);
const ELEVATED_CC = new Set(["NG", "RO", "BR", "PK", "VN", "UA", "IN", "ID"]);

const SEV_RANK_TO_LABEL = { 5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "NEGLIGIBLE", 0: "—" };
const SEV_RANK_SQL = `
  CASE severity
    WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 2 WHEN 'NEGLIGIBLE' THEN 1 ELSE 0 END`;

// ── Helpers de formato ────────────────────────────────────────────────────────
function _fmtNum(n) {
  if (n == null || Number.isNaN(Number(n))) return "—";
  return Math.round(Number(n)).toString();
}
function _fmtDate(d) {
  if (!d) return "—";
  return d instanceof Date ? d.toISOString().slice(0, 10) : String(d).slice(0, 10);
}

// ── Queries ───────────────────────────────────────────────────────────────────

/** Resumen: totales, severidad, estados. */
async function _summary(from, to) {
  const rows = await pgQuery(`
    SELECT
      COUNT(*)                                                          AS total_cases,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL')                     AS critical_total,
      COUNT(*) FILTER (WHERE severity = 'HIGH')                         AS high_total,
      COUNT(*) FILTER (WHERE severity = 'MEDIUM')                       AS medium_total,
      COUNT(*) FILTER (WHERE severity IN ('LOW','NEGLIGIBLE'))          AS low_total,
      COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO')) AS open_cases,
      COUNT(*) FILTER (WHERE status = 'FALSO_POSITIVO')                 AS fp_cases,
      COUNT(*) FILTER (WHERE status = 'ESCALADO')                       AS escalated_cases,
      COUNT(*) FILTER (WHERE is_recurrence)                             AS recurrence_cases,
      COUNT(DISTINCT ioc_value) FILTER (WHERE ioc_value IS NOT NULL AND ioc_value <> '') AS unique_iocs,
      COUNT(DISTINCT mitre_tactic_id) FILTER (WHERE mitre_tactic_id IS NOT NULL) AS mitre_tactics_hit
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
  `, [from, to]);
  return rows[0] ?? {};
}

/**
 * Top países atacantes. Híbrido:
 *  · Casos con `src_country` persistido → agregación directa en PG.
 *  · Casos sin país pero con IP pública → resolución en caliente vía MaxMind.
 * Devuelve el ranking completo (para el mapa) y deja que el caller corte el top.
 */
export async function _topCountries(from, to) {
  // A) País ya persistido.
  const known = await pgQuery(`
    SELECT
      UPPER(src_country)                                            AS cc,
      COUNT(*)                                                      AS total,
      COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH'))       AS high_risk,
      COUNT(DISTINCT COALESCE(NULLIF(host(source_ip), ''),
                              CASE WHEN ioc_type = 'ip' THEN ioc_value END)) AS unique_ips,
      MAX(score)                                                    AS max_score
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
      AND src_country IS NOT NULL AND src_country <> ''
    GROUP BY UPPER(src_country)
  `, [from, to]);

  const tally = new Map();
  const add = (cc, total, high, uniq, maxScore) => {
    if (!cc) return;
    const e = tally.get(cc) ?? { cc, total: 0, high_risk: 0, unique_ips: 0, max_score: 0 };
    e.total += Number(total) || 0;
    e.high_risk += Number(high) || 0;
    e.unique_ips += Number(uniq) || 0;
    e.max_score = Math.max(e.max_score, Number(maxScore) || 0);
    tally.set(cc, e);
  };
  for (const r of known) add(r.cc, r.total, r.high_risk, r.unique_ips, r.max_score);

  // B) Sin país: resolver IP pública vía MaxMind (offline). Acotado para no
  //    disparar millones de lookups en ventanas grandes.
  const orphan = await pgQuery(`
    SELECT ip, SUM(total) AS total, SUM(high_risk) AS high_risk, MAX(max_score) AS max_score
    FROM (
      SELECT
        COALESCE(NULLIF(host(source_ip), ''),
                 CASE WHEN ioc_type = 'ip' THEN ioc_value END)      AS ip,
        COUNT(*)                                                    AS total,
        COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH'))     AS high_risk,
        MAX(score)                                                  AS max_score
      FROM incident_cases_pg
      WHERE created_at >= $1 AND created_at < $2
        AND (src_country IS NULL OR src_country = '')
        AND (source_ip IS NOT NULL OR ioc_type = 'ip')
      GROUP BY 1
    ) s
    WHERE ip IS NOT NULL AND ip <> ''
    GROUP BY ip
    ORDER BY total DESC
    LIMIT 5000
  `, [from, to]);

  if (orphan.length) {
    const resolved = await Promise.all(
      orphan.map(async (r) => ({ cc: await lookupCountry(r.ip), r })),
    );
    for (const { cc, r } of resolved) {
      if (!cc) continue;
      add(cc, r.total, r.high_risk, 1, r.max_score);
    }
  }

  const ranked = [...tally.values()]
    .map((e) => ({
      ...e,
      name: countryNameEs(e.cc),
      risk: HIGH_RISK_CC.has(e.cc) ? "high" : ELEVATED_CC.has(e.cc) ? "elevated" : "normal",
    }))
    .sort((a, b) => b.total - a.total || b.high_risk - a.high_risk);

  return ranked;
}

/** Tendencia diaria por severidad (ascendente, para gráfico). */
async function _dailyTrend(from, to) {
  return pgQuery(`
    SELECT
      DATE(created_at)                                       AS day,
      COUNT(*)                                               AS total,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL')          AS critical,
      COUNT(*) FILTER (WHERE severity = 'HIGH')              AS high,
      COUNT(*) FILTER (WHERE severity = 'MEDIUM')            AS medium,
      COUNT(*) FILTER (WHERE severity IN ('LOW','NEGLIGIBLE')) AS low
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
    GROUP BY DATE(created_at)
    ORDER BY day ASC
  `, [from, to]);
}

/** Eventos reincidentes: IOCs que reaparecen en la ventana. */
async function _recurrentEvents(from, to, limit = 15) {
  return pgQuery(`
    SELECT
      ioc_value, ioc_type,
      COUNT(*)                                       AS case_count,
      COALESCE(MAX(occurrence_count), 1)             AS max_occurrences,
      COUNT(*) FILTER (WHERE is_recurrence)          AS recurrence_cases,
      MAX(score)                                     AS max_score,
      MAX(${SEV_RANK_SQL})                           AS sev_rank,
      MIN(created_at)                                AS first_seen,
      MAX(COALESCE(last_seen, created_at))           AS last_seen,
      COUNT(DISTINCT source_log)                     AS source_diversity,
      MAX(mitre_tactic_id)                           AS mitre_tactic_id
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
      AND ioc_value IS NOT NULL AND ioc_value <> ''
    GROUP BY ioc_value, ioc_type
    HAVING COUNT(*) > 1 OR MAX(occurrence_count) > 1 OR bool_or(is_recurrence)
    ORDER BY max_occurrences DESC, case_count DESC, max_score DESC
    LIMIT ${limit}
  `, [from, to]).then((rows) =>
    rows.map((r) => ({ ...r, max_severity: SEV_RANK_TO_LABEL[Number(r.sev_rank)] ?? "—" })),
  );
}

/** Top tácticas MITRE. */
async function _topMitre(from, to, limit = 10) {
  return pgQuery(`
    SELECT
      mitre_tactic_id                                AS tactic_id,
      COALESCE(mitre_tactic_name, '(sin nombre)')     AS tactic_name,
      COUNT(*)                                       AS hits,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL')  AS critical_hits,
      COUNT(*) FILTER (WHERE severity = 'HIGH')      AS high_hits,
      COUNT(DISTINCT ioc_value)                      AS unique_iocs
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
      AND mitre_tactic_id IS NOT NULL
    GROUP BY mitre_tactic_id, mitre_tactic_name
    ORDER BY hits DESC
    LIMIT ${limit}
  `, [from, to]);
}

/** Distribución por fuente de detección. */
async function _bySource(from, to, limit = 12) {
  return pgQuery(`
    SELECT
      COALESCE(NULLIF(source_log, ''), '(sin fuente)') AS source_log,
      COUNT(*)                                          AS total,
      COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH')) AS high_risk,
      COUNT(DISTINCT ioc_value)                         AS unique_iocs
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
    GROUP BY 1
    ORDER BY total DESC
    LIMIT ${limit}
  `, [from, to]);
}

/** Top IOCs externos (IP pública). */
async function _topIocs(from, to, limit = 10) {
  return pgQuery(`
    SELECT
      ioc_value, ioc_type,
      COUNT(*)                                       AS case_count,
      MAX(score)                                     AS max_score,
      MAX(${SEV_RANK_SQL})                           AS sev_rank,
      COUNT(DISTINCT source_log)                     AS source_diversity,
      MAX(COALESCE(last_seen, created_at))           AS last_seen
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
      AND ioc_value IS NOT NULL AND ioc_value <> ''
      AND ioc_type = 'ip'
      AND NOT (ioc_value LIKE '10.%' OR ioc_value LIKE '192.168.%'
               OR ioc_value ~ '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
    GROUP BY ioc_value, ioc_type
    ORDER BY max_score DESC, case_count DESC
    LIMIT ${limit}
  `, [from, to]).then((rows) =>
    rows.map((r) => ({ ...r, max_severity: SEV_RANK_TO_LABEL[Number(r.sev_rank)] ?? "—" })),
  );
}

/**
 * Acciones realizadas por los operadores (timeline MANUAL) agregadas por
 * operador y categoría. + total global y desglose por tipo.
 */
async function _operatorActions(from, to) {
  const byOperator = await pgQuery(`
    SELECT
      operator_ci,
      COUNT(*)                                                            AS total,
      COUNT(*) FILTER (WHERE event_type = 'ADOPT')                        AS adopt,
      COUNT(*) FILTER (WHERE event_type IN ('STATUS_CHANGE','SEVERITY_CHANGE')) AS status_changes,
      COUNT(*) FILTER (WHERE event_type IN ('ESCALATE','TRANSFER'))       AS escalate,
      COUNT(*) FILTER (WHERE event_type IN ('CONTAINMENT','ERADICATION','RECOVERY')) AS response,
      COUNT(*) FILTER (WHERE event_type IN ('NOTE','EVIDENCE','IOC','ASSET','ENRICHMENT')) AS notes_evidence,
      COUNT(*) FILTER (WHERE event_type IN ('SLACK_NOTIFY','CLIENT_NOTIFY')) AS notifications,
      COUNT(DISTINCT case_id)                                             AS cases_touched,
      MAX(event_ts)                                                       AS last_action
    FROM case_timeline_events
    WHERE source = 'MANUAL'
      AND event_ts >= $1 AND event_ts < $2
      AND operator_ci IS NOT NULL AND operator_ci NOT IN ('system','')
    GROUP BY operator_ci
    ORDER BY total DESC
    LIMIT 20
  `, [from, to]);

  const byType = await pgQuery(`
    SELECT event_type, COUNT(*) AS n
    FROM case_timeline_events
    WHERE source = 'MANUAL'
      AND event_ts >= $1 AND event_ts < $2
      AND operator_ci IS NOT NULL AND operator_ci NOT IN ('system','')
    GROUP BY event_type
    ORDER BY n DESC
  `, [from, to]);

  const totalActions = byType.reduce((a, r) => a + Number(r.n || 0), 0);
  return { byOperator, byType, totalActions, activeOperators: byOperator.length };
}

/** Acciones automáticas del sistema (incident_auto_actions) por tipo. */
async function _autoActions(from, to) {
  return pgQuery(`
    SELECT action_type, COUNT(*) AS n, COUNT(DISTINCT case_id) AS cases
    FROM incident_auto_actions
    WHERE performed_at >= $1 AND performed_at < $2
    GROUP BY action_type
    ORDER BY n DESC
  `, [from, to]);
}

/**
 * Resumen macro de acciones POR REALIZAR según las tácticas MITRE detectadas en
 * la ventana: cruza las tácticas con volumen contra el playbook recomendado
 * (casePlaybookService). Devuelve los pasos clave + si la táctica exige escalar.
 */
async function _recommendedByTactic(from, to, limit = 12) {
  const detected = await pgQuery(`
    SELECT
      mitre_tactic_id                               AS tactic_id,
      COALESCE(mitre_tactic_name, '')               AS tactic_name,
      COUNT(*)                                      AS hits,
      COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH')) AS high_hits,
      COUNT(DISTINCT ioc_value)                     AS unique_iocs
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
      AND mitre_tactic_id IS NOT NULL
    GROUP BY mitre_tactic_id, mitre_tactic_name
    ORDER BY hits DESC
    LIMIT ${limit}
  `, [from, to]);

  return detected.map((d) => {
    const pb = getTacticPlaybook(d.tactic_id);
    return {
      tactic_id:   d.tactic_id,
      tactic_name: d.tactic_name || pb.title,
      hits:        Number(d.hits) || 0,
      high_hits:   Number(d.high_hits) || 0,
      unique_iocs: Number(d.unique_iocs) || 0,
      escalate:    pb.escalate,
      nist_phase:  pb.nist_phase,
      steps:       pb.steps.slice(0, 4),
    };
  });
}

/**
 * Estadísticas del feed saliente lgcrBL (legacyhunt_soc.infragovpy_watchlist):
 * IOCs ingresadas en el período, total/activas/expiradas, auto vs manual,
 * severidad, penalizadas, + allowlist. Tolerante a que la tabla no exista.
 */
async function _feedStats(from, to) {
  try {
    const totals = (await pgQuery(`
      SELECT
        COUNT(*)                                                          AS total,
        COUNT(*) FILTER (WHERE expires_at > now())                        AS active,
        COUNT(*) FILTER (WHERE expires_at <= now())                       AS expired,
        COUNT(*) FILTER (WHERE first_seen >= $1 AND first_seen < $2)      AS added_window,
        COUNT(*) FILTER (WHERE last_seen >= $1 AND last_seen < $2
                           AND first_seen < $1)                           AS rereported_window,
        COUNT(*) FILTER (WHERE expires_at > now() AND origin = 'auto')    AS active_auto,
        COUNT(*) FILTER (WHERE expires_at > now() AND origin = 'manual')  AS active_manual,
        COUNT(*) FILTER (WHERE expires_at > now() AND last_severity = 'CRITICAL') AS active_critical,
        COUNT(*) FILTER (WHERE expires_at > now() AND last_severity = 'HIGH')     AS active_high,
        COUNT(*) FILTER (WHERE expires_at > now() AND report_count >= 2) AS penalized
      FROM legacyhunt_soc.infragovpy_watchlist
    `, [from, to]))[0] ?? {};

    const daily = await pgQuery(`
      SELECT DATE(first_seen) AS day, COUNT(*) AS n
      FROM legacyhunt_soc.infragovpy_watchlist
      WHERE first_seen >= $1 AND first_seen < $2
      GROUP BY DATE(first_seen)
      ORDER BY day ASC
    `, [from, to]);

    const excl = (await pgQuery(`
      SELECT COUNT(*) AS n
      FROM legacyhunt_soc.infragovpy_exclusions
      WHERE expires_at IS NULL OR expires_at > now()
    `))[0] ?? { n: 0 };

    return { available: true, totals, daily, exclusions: Number(excl.n) || 0 };
  } catch {
    return { available: false, totals: {}, daily: [], exclusions: 0 };
  }
}

// ── Render Markdown ───────────────────────────────────────────────────────────
function _renderMarkdown(ctx) {
  const {
    windowLabel, windowDays, rangeFrom, rangeTo, generatedAt, generatedBy,
    summary, countries, dailyTrend, recurrent, topTactics, bySource, topIocs,
    operatorActions, autoActions, recommendedByTactic, feedStats,
  } = ctx;
  const L = [];
  const top10 = countries.slice(0, 10);

  L.push(`# Informe Técnico SOC — ${windowLabel}`);
  L.push("");
  L.push(`**Período evaluado:** ${_fmtDate(rangeFrom)} → ${_fmtDate(rangeTo)} (${windowDays} días)`);
  L.push(`**Emitido:** ${new Date(generatedAt).toLocaleString("es-ES")}`);
  if (generatedBy) L.push(`**Operador:** ${generatedBy}`);
  L.push(`**Clasificación:** CONFIDENCIAL — Sólo LEADER / ADMIN`);
  L.push("");
  L.push("---");
  L.push("");

  // 1. Resumen
  const s = summary;
  L.push(`## 1. Resumen y alcance`);
  L.push("");
  L.push(`En **${windowDays} días** se registraron **${_fmtNum(s.total_cases)} incidentes** ` +
    `(${_fmtNum(s.critical_total)} CRITICAL · ${_fmtNum(s.high_total)} HIGH · ${_fmtNum(s.medium_total)} MEDIUM · ` +
    `${_fmtNum(s.low_total)} LOW/NEGL), sobre **${_fmtNum(s.unique_iocs)} IOCs únicos**. ` +
    `Permanecen **${_fmtNum(s.open_cases)} abiertos**; ${_fmtNum(s.recurrence_cases)} fueron reincidencias.`);
  L.push("");
  L.push(`Se detectó actividad desde **${countries.length} países** distintos y ` +
    `**${topTactics.length}+ tácticas MITRE**.`);
  L.push("");

  // 2. Top países
  L.push(`## 2. Top 10 países atacantes`);
  L.push("");
  if (top10.length === 0) {
    L.push(`_Sin origen geográfico resuelto en el período (IPs privadas o sin geo)._`);
  } else {
    L.push(`| # | País | Incidentes | Crit/High | IPs únicas | Score máx | Riesgo geo |`);
    L.push(`|---|---|---|---|---|---|---|`);
    top10.forEach((c, i) => {
      const risk = c.risk === "high" ? "ALTO" : c.risk === "elevated" ? "Elevado" : "—";
      L.push(`| ${i + 1} | ${c.name} (${c.cc}) | ${_fmtNum(c.total)} | ${_fmtNum(c.high_risk)} | ${_fmtNum(c.unique_ips)} | ${_fmtNum(c.max_score)} | ${risk} |`);
    });
    L.push("");
    L.push(`> El mapa mundial coloreado por volumen de contacto se incluye en la versión PDF/UI del informe.`);
  }
  L.push("");

  // 3. Tendencia
  L.push(`## 3. Tendencia diaria`);
  L.push("");
  if (dailyTrend.length === 0) {
    L.push(`_Sin datos de tendencia en el período._`);
  } else {
    const last = dailyTrend.slice(-14);
    L.push(`| Fecha | Total | CRITICAL | HIGH | MEDIUM | LOW/NEGL |`);
    L.push(`|---|---|---|---|---|---|`);
    for (const d of last) {
      L.push(`| ${_fmtDate(d.day)} | ${_fmtNum(d.total)} | ${_fmtNum(d.critical)} | ${_fmtNum(d.high)} | ${_fmtNum(d.medium)} | ${_fmtNum(d.low)} |`);
    }
    L.push("");
    L.push(`> Gráfico de tendencias (área apilada por severidad) disponible en la versión PDF/UI.`);
  }
  L.push("");

  // 4. Reincidentes
  L.push(`## 4. Eventos reincidentes`);
  L.push("");
  if (recurrent.length === 0) {
    L.push(`_Sin IOCs reincidentes en el período._`);
  } else {
    L.push(`IOCs que reaparecen (recurrencia detectada o múltiples casos). Candidatos a bloqueo durable / watchlist:`);
    L.push("");
    L.push(`| IOC | Tipo | Casos | Ocurrencias | Sev. máx | Fuentes | Primera vez | Última vez |`);
    L.push(`|---|---|---|---|---|---|---|---|`);
    for (const r of recurrent) {
      L.push(`| \`${String(r.ioc_value).slice(0, 32)}\` | ${r.ioc_type} | ${_fmtNum(r.case_count)} | ${_fmtNum(r.max_occurrences)} | ${r.max_severity} | ${_fmtNum(r.source_diversity)} | ${_fmtDate(r.first_seen)} | ${_fmtDate(r.last_seen)} |`);
    }
  }
  L.push("");

  // 5. MITRE
  L.push(`## 5. Cobertura MITRE ATT&CK`);
  L.push("");
  L.push(`Tácticas detectadas: **${_fmtNum(s.mitre_tactics_hit)} / 14**.`);
  L.push("");
  if (topTactics.length > 0) {
    L.push(`| Táctica | ID | Hits | CRITICAL | HIGH | IOCs únicos |`);
    L.push(`|---|---|---|---|---|---|`);
    for (const t of topTactics) {
      L.push(`| ${t.tactic_name} | \`${t.tactic_id}\` | ${_fmtNum(t.hits)} | ${_fmtNum(t.critical_hits)} | ${_fmtNum(t.high_hits)} | ${_fmtNum(t.unique_iocs)} |`);
    }
  }
  L.push("");

  // 6. Por fuente
  L.push(`## 6. Distribución por fuente de detección`);
  L.push("");
  if (bySource.length > 0) {
    L.push(`| Fuente | Incidentes | Crit/High | IOCs únicos |`);
    L.push(`|---|---|---|---|`);
    for (const b of bySource) {
      L.push(`| ${b.source_log} | ${_fmtNum(b.total)} | ${_fmtNum(b.high_risk)} | ${_fmtNum(b.unique_iocs)} |`);
    }
  }
  L.push("");

  // 7. Top IOCs
  L.push(`## 7. Top IOCs / atacantes externos`);
  L.push("");
  if (topIocs.length === 0) {
    L.push(`_Sin IOCs públicos relevantes en el período._`);
  } else {
    L.push(`| IOC | Tipo | Casos | Score máx | Sev. máx | Fuentes |`);
    L.push(`|---|---|---|---|---|---|`);
    for (const i of topIocs) {
      L.push(`| \`${i.ioc_value}\` | ${i.ioc_type} | ${_fmtNum(i.case_count)} | ${_fmtNum(i.max_score)} | ${i.max_severity} | ${_fmtNum(i.source_diversity)} |`);
    }
  }
  L.push("");

  // 8. Acciones realizadas por los operadores
  L.push(`## 8. Acciones realizadas por los operadores`);
  L.push("");
  const oa = operatorActions ?? { byOperator: [], byType: [], totalActions: 0, activeOperators: 0 };
  L.push(`Total de acciones manuales en el período: **${_fmtNum(oa.totalActions)}** por **${_fmtNum(oa.activeOperators)} operadores**.`);
  L.push("");
  if (oa.byOperator.length === 0) {
    L.push(`_Sin acciones manuales registradas de operadores en el período._`);
  } else {
    L.push(`| Operador | Total | Adopción | Cambios estado | Escalación | Respuesta | Notas/Evid. | Notif. | Casos |`);
    L.push(`|---|---|---|---|---|---|---|---|---|`);
    for (const o of oa.byOperator) {
      L.push(`| ${o.operator_ci} | ${_fmtNum(o.total)} | ${_fmtNum(o.adopt)} | ${_fmtNum(o.status_changes)} | ${_fmtNum(o.escalate)} | ${_fmtNum(o.response)} | ${_fmtNum(o.notes_evidence)} | ${_fmtNum(o.notifications)} | ${_fmtNum(o.cases_touched)} |`);
    }
  }
  if ((autoActions ?? []).length > 0) {
    L.push("");
    L.push(`**Acciones automáticas del sistema:**`);
    L.push("");
    L.push(`| Acción automática | Veces | Casos |`);
    L.push(`|---|---|---|`);
    for (const a of autoActions) {
      L.push(`| ${a.action_type} | ${_fmtNum(a.n)} | ${_fmtNum(a.cases)} |`);
    }
  }
  L.push("");

  // 9. Acciones por realizar según tácticas
  L.push(`## 9. Acciones por realizar según tácticas detectadas`);
  L.push("");
  const rbt = recommendedByTactic ?? [];
  if (rbt.length === 0) {
    L.push(`_Sin tácticas MITRE detectadas en el período._`);
  } else {
    L.push(`Resumen macro: por cada táctica detectada, las acciones recomendadas (playbook NIST) y si exige escalar a L2.`);
    L.push("");
    for (const t of rbt) {
      const flag = t.escalate ? " — ⚠️ ESCALAR A L2" : "";
      L.push(`### ${t.tactic_name} (\`${t.tactic_id}\`) · ${_fmtNum(t.hits)} casos · ${t.nist_phase}${flag}`);
      for (const s of t.steps) L.push(`- ${s}`);
      L.push("");
    }
  }

  // 10. Feed saliente lgcrBL
  L.push(`## 10. IOCs ingresadas al feed saliente lgcrBL`);
  L.push("");
  const fs = feedStats ?? { available: false };
  if (!fs.available) {
    L.push(`_Feed lgcrBL no disponible (tabla \`infragovpy_watchlist\` ausente)._`);
  } else {
    const ft = fs.totals;
    L.push(`En el período se **ingresaron ${_fmtNum(ft.added_window)} IOCs nuevas** al feed saliente lgcrBL ` +
      `(y ${_fmtNum(ft.rereported_window)} re-reportadas). El feed mantiene **${_fmtNum(ft.active)} IOCs activas** ` +
      `de ${_fmtNum(ft.total)} históricas (${_fmtNum(ft.expired)} expiradas/removidas).`);
    L.push("");
    L.push(`| Métrica del feed | Valor |`);
    L.push(`|---|---|`);
    L.push(`| Ingresadas en el período | ${_fmtNum(ft.added_window)} |`);
    L.push(`| Re-reportadas en el período | ${_fmtNum(ft.rereported_window)} |`);
    L.push(`| Activas (total) | ${_fmtNum(ft.active)} |`);
    L.push(`| Activas automáticas | ${_fmtNum(ft.active_auto)} |`);
    L.push(`| Activas manuales | ${_fmtNum(ft.active_manual)} |`);
    L.push(`| Activas CRITICAL | ${_fmtNum(ft.active_critical)} |`);
    L.push(`| Activas HIGH | ${_fmtNum(ft.active_high)} |`);
    L.push(`| Penalizadas (≥2 reportes) | ${_fmtNum(ft.penalized)} |`);
    L.push(`| Expiradas/removidas | ${_fmtNum(ft.expired)} |`);
    L.push(`| Exclusiones vigentes (allowlist) | ${_fmtNum(fs.exclusions)} |`);
    L.push("");
    if (fs.daily.length > 0) {
      L.push(`**Altas diarias al feed:** ` + fs.daily.map((d) => `${_fmtDate(d.day)}=${_fmtNum(d.n)}`).join(" · "));
      L.push("");
    }
  }

  L.push("---");
  L.push("");
  L.push(`*Informe técnico generado por LegacyHunt SOC. Geo vía MaxMind GeoLite2 (offline). Datos sobre \`incident_cases_pg\` + \`case_timeline_events\` + feed lgcrBL.*`);
  return L.join("\n") + "\n";
}

// ── API pública ───────────────────────────────────────────────────────────────
/**
 * Construye el informe técnico.
 * @param {{ preset?: string, from?: string|Date, to?: string|Date, generatedBy?: string }} opts
 * @returns {Promise<{ markdown, filename, meta, data }>}
 */
export async function buildTechnicalReport(opts = {}) {
  const { generatedBy = null } = opts;
  const presetOrDays = opts.preset ?? "30d";
  const range = resolveReportRange({ preset: presetOrDays, from: opts.from, to: opts.to });

  const [
    summary, countries, dailyTrend, recurrent, topTactics, bySource, topIocs,
    operatorActions, autoActions, recommendedByTactic, feedStats,
  ] = await Promise.all([
    _summary(range.from, range.to),
    _topCountries(range.from, range.to),
    _dailyTrend(range.from, range.to),
    _recurrentEvents(range.from, range.to, 15),
    _topMitre(range.from, range.to, 10),
    _bySource(range.from, range.to, 12),
    _topIocs(range.from, range.to, 10),
    _operatorActions(range.from, range.to),
    _autoActions(range.from, range.to),
    _recommendedByTactic(range.from, range.to, 12),
    _feedStats(range.from, range.to),
  ]);

  const generatedAt = new Date().toISOString();
  const markdown = _renderMarkdown({
    windowLabel: range.label, windowDays: range.windowDays,
    rangeFrom: range.from, rangeTo: range.to, generatedAt, generatedBy,
    summary, countries, dailyTrend, recurrent, topTactics, bySource, topIocs,
    operatorActions, autoActions, recommendedByTactic, feedStats,
  });

  const stamp = generatedAt.slice(0, 10);
  const filename = `informe-tecnico-soc-${stamp}-${range.slug}`;
  return {
    markdown,
    filename,
    meta: {
      windowDays: range.windowDays,
      windowLabel: range.label,
      rangeFrom: range.from.toISOString(),
      rangeTo: range.to.toISOString(),
      generatedAt, generatedBy,
      totalCases: Number(summary.total_cases ?? 0),
      countriesHit: countries.length,
      topCountry: countries[0]?.name ?? null,
      recurrentCount: recurrent.length,
      operatorActions: operatorActions.totalActions,
      feedAddedWindow: feedStats.available ? Number(feedStats.totals.added_window ?? 0) : 0,
      feedActive: feedStats.available ? Number(feedStats.totals.active ?? 0) : 0,
    },
    // Datos estructurados para el PDF/UI (mapa, gráfico de tendencias, tablas).
    data: {
      summary, countries, dailyTrend, recurrent, topTactics, bySource, topIocs,
      operatorActions, autoActions, recommendedByTactic, feedStats,
    },
  };
}
