/**
 * executiveReportService.mjs
 *
 * Genera el Informe Ejecutivo SOC para LEADER/ADMIN. Devuelve el contenido en
 * Markdown (Phase 1). El PDF (Phase 3) se construirá cliente-side reusando
 * este MD como fuente única de verdad.
 *
 * Estructura alineada a NIST SP 800-61 Rev. 3 + CSF 2.0:
 *   1. Resumen ejecutivo
 *   2. KPIs operacionales (MTTA/MTTR/SLA/FP)
 *   3. Volumen y tendencia (período actual vs anterior)
 *   4. Incidentes CRITICAL del período
 *   5. Cobertura MITRE ATT&CK
 *   6. Performance operativa (por analista)
 *   7. Top IOCs / atacantes externos
 *   8. Conclusiones y recomendaciones (P1/P2/P3 derivadas de umbrales)
 *
 * Fuentes: incident_cases_pg (PG, rápido). No toca Trino — evita timeouts de
 * metadata Iceberg.
 */

import { pgQuery } from "../db/postgres.mjs";
import {
  buildExecutiveNarrative,
  narrativeAnalystAvailable,
  renderNarrativeMarkdown,
} from "./executiveNarrativeAnalyst.mjs";

const MITRE_TACTIC_LABEL = {
  TA0001: "Acceso Inicial",
  TA0002: "Ejecución",
  TA0003: "Persistencia",
  TA0004: "Escalada de Privilegios",
  TA0005: "Evasión de Defensas",
  TA0006: "Acceso a Credenciales",
  TA0007: "Descubrimiento",
  TA0008: "Movimiento Lateral",
  TA0009: "Recolección",
  TA0010: "Exfiltración",
  TA0011: "Comando y Control",
  TA0040: "Impacto",
  TA0042: "Desarrollo de Recursos",
  TA0043: "Reconocimiento",
};

const MITRE_TOTAL_TACTICS = 14;

// ── Helpers ──────────────────────────────────────────────────────────────────
function _fmtNum(n, d = 0) {
  if (n == null || Number.isNaN(Number(n))) return "—";
  const x = Number(n);
  return d > 0 ? x.toFixed(d) : Math.round(x).toString();
}

function _fmtMin(mins) {
  if (mins == null || Number.isNaN(Number(mins))) return "—";
  const m = Number(mins);
  if (m >= 1440) return `${(m / 1440).toFixed(1)} d`;
  if (m >= 60)   return `${(m / 60).toFixed(1)} h`;
  return `${Math.round(m)} min`;
}

function _fmtPct(n, d = 1) {
  if (n == null || Number.isNaN(Number(n))) return "—";
  return `${Number(n).toFixed(d)}%`;
}

function _delta(curr, prev, kind = "num") {
  if (curr == null || prev == null) return { sign: "", str: "n/d" };
  const c = Number(curr);
  const p = Number(prev);
  if (!Number.isFinite(c) || !Number.isFinite(p)) return { sign: "", str: "n/d" };
  if (p === 0) return { sign: c > 0 ? "+" : "", str: c === 0 ? "=" : `+${c}${kind === "pct" ? "%" : ""}` };
  const pct = ((c - p) / Math.abs(p)) * 100;
  const sign = pct > 0 ? "+" : pct < 0 ? "" : "";
  return { sign, str: `${sign}${pct.toFixed(1)}%` };
}

function _deltaArrow(curr, prev, direction = "lower_better") {
  if (curr == null || prev == null) return "";
  const c = Number(curr), p = Number(prev);
  if (!Number.isFinite(c) || !Number.isFinite(p) || c === p) return "➖";
  const improved = direction === "lower_better" ? c < p : c > p;
  return improved ? "🟢 ↓" : "🔴 ↑";
}

// ── Queries (parametrizadas por ventana en días) ─────────────────────────────

/** Resumen: conteos totales, severidad, MTTA/MTTR, SLA critical. */
async function _summary(from, to) {
  const rows = await pgQuery(`
    WITH wnd AS (
      SELECT *
        FROM incident_cases_pg
       WHERE created_at >= $1 AND created_at < $2
    )
    SELECT
      COUNT(*)                                                                AS total_cases,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL')                            AS critical_total,
      COUNT(*) FILTER (WHERE severity = 'HIGH')                                AS high_total,
      COUNT(*) FILTER (WHERE severity = 'MEDIUM')                              AS medium_total,
      COUNT(*) FILTER (WHERE severity IN ('LOW','NEGLIGIBLE'))                 AS low_total,
      COUNT(*) FILTER (WHERE status NOT IN ('CERRADO','FALSO_POSITIVO'))       AS open_cases,
      COUNT(*) FILTER (WHERE status = 'CERRADO')                               AS closed_cases,
      COUNT(*) FILTER (WHERE status = 'FALSO_POSITIVO')                        AS fp_cases,
      COUNT(*) FILTER (WHERE status = 'ESCALADO')                              AS escalated_cases,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL) AS critical_adopted,
      ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
            FILTER (WHERE adopted_at IS NOT NULL), 1)                          AS mtta_min,
      ROUND(AVG(EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0)
            FILTER (WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL), 1) AS mtta_critical_min,
      ROUND(AVG(EXTRACT(EPOCH FROM COALESCE(resolved_at, updated_at) - created_at) / 60.0)
            FILTER (WHERE status = 'CERRADO'
                      AND NOT (severity IN ('LOW','NEGLIGIBLE') AND operator_id IS NULL)), 1) AS mttr_min,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND adopted_at IS NOT NULL
                         AND EXTRACT(EPOCH FROM adopted_at - created_at) / 60.0 <= 60) AS sla_ok,
      COUNT(DISTINCT mitre_tactic_id) FILTER (WHERE mitre_tactic_id IS NOT NULL) AS mitre_tactics_hit
    FROM wnd
  `, [from, to]);
  return rows[0] ?? {};
}

/** Top MITRE tactics con volumen y severidad promedio. */
async function _topMitreTactics(from, to, limit = 10) {
  return pgQuery(`
    SELECT
      mitre_tactic_id                                   AS tactic_id,
      COALESCE(mitre_tactic_name, '(sin nombre)')        AS tactic_name,
      COUNT(*)                                          AS hits,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL')     AS critical_hits,
      COUNT(*) FILTER (WHERE severity = 'HIGH')         AS high_hits,
      COUNT(DISTINCT ioc_value)                         AS unique_iocs
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
      AND mitre_tactic_id IS NOT NULL
    GROUP BY mitre_tactic_id, mitre_tactic_name
    ORDER BY hits DESC
    LIMIT ${limit}
  `, [from, to]);
}

/** Top IOCs por actividad. */
async function _topIocs(from, to, limit = 10) {
  return pgQuery(`
    SELECT
      ioc_value, ioc_type,
      COUNT(*)                                       AS case_count,
      MAX(score)                                      AS max_score,
      MAX(severity)                                   AS max_severity,
      COUNT(DISTINCT source_log)                     AS source_diversity,
      MAX(last_seen)                                  AS last_seen
    FROM incident_cases_pg
    WHERE created_at >= $1 AND created_at < $2
      AND ioc_value IS NOT NULL AND ioc_value <> ''
      AND ioc_type = 'ip'
      -- RFC 1918: 10/8, 192.168/16, 172.16.0.0/12 (=172.16–172.31). El comodín
      -- previo 172.1%/172.2%/172.3% excluía además públicas (172.1.x, 172.10–15.x,
      -- 172.32–39.x) del informe de IOCs externos. Audit 2026-06-06.
      AND NOT (ioc_value LIKE '10.%' OR ioc_value LIKE '192.168.%' OR ioc_value ~ '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
    GROUP BY ioc_value, ioc_type
    ORDER BY max_score DESC, case_count DESC
    LIMIT ${limit}
  `, [from, to]);
}

/** Distribución de casos por día (para línea de tendencia en texto). */
async function _dailyVolume(from, to, limitDays = 60) {
  return pgQuery(`
    SELECT DATE(created_at)                           AS day,
           COUNT(*)                                   AS total,
           COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical,
           COUNT(*) FILTER (WHERE severity='HIGH')     AS high
      FROM incident_cases_pg
     WHERE created_at >= $1 AND created_at < $2
     GROUP BY DATE(created_at)
     ORDER BY day DESC
     LIMIT ${limitDays}
  `, [from, to]);
}

/** Performance operativa: casos manejados y MTTA por operador. */
async function _operatorPerformance(from, to, limit = 10) {
  return pgQuery(`
    SELECT
      c.operator_id,
      COALESCE(o.name, c.operator_id)                AS operator_name,
      o.role_id                                        AS role_id,
      COUNT(*)                                         AS adopted_cases,
      COUNT(*) FILTER (WHERE c.status = 'CERRADO')     AS closed_cases,
      COUNT(*) FILTER (WHERE c.severity = 'CRITICAL')  AS critical_handled,
      ROUND(AVG(EXTRACT(EPOCH FROM c.adopted_at - c.created_at) / 60.0), 1) AS avg_mtta_min,
      ROUND(AVG(EXTRACT(EPOCH FROM COALESCE(c.resolved_at, c.updated_at) - c.adopted_at) / 60.0)
            FILTER (WHERE c.status = 'CERRADO'), 1)    AS avg_mttr_min
    FROM incident_cases_pg c
    LEFT JOIN soc_operators o ON o.id = c.operator_id
    WHERE c.created_at >= $1 AND c.created_at < $2
      AND c.adopted_at IS NOT NULL
      AND c.operator_id IS NOT NULL
    GROUP BY c.operator_id, o.name, o.role_id
    ORDER BY adopted_cases DESC
    LIMIT ${limit}
  `, [from, to]);
}

/**
 * Analítica de CIERRES CON VALOR ANALÍTICO del período.
 *
 * Alcance: casos terminales (CERRADO / FALSO_POSITIVO) creados en la ventana,
 * EXCLUYENDO los auto-cerrados LOW/NEGLIGIBLE (churn de ruido). La criba
 * `NOT (auto_closed_at IS NOT NULL AND severity IN ('LOW','NEGLIGIBLE'))` es la
 * misma frontera que ya usa _summary para no contaminar el MTTR: separa el
 * cierre con intervención/valor humano del auto-cierre de ruido.
 *
 * Un LOW que SÍ fue revisado por un humano (auto_closed_at NULL) se conserva.
 */
async function _closedCaseAnalytics(from, to) {
  const rows = await pgQuery(`
    WITH wnd AS (
      SELECT *
        FROM incident_cases_pg
       WHERE created_at >= $1 AND created_at < $2
         AND status IN ('CERRADO','FALSO_POSITIVO')
         AND NOT (auto_closed_at IS NOT NULL AND severity IN ('LOW','NEGLIGIBLE'))
    )
    SELECT
      COUNT(*)                                                                    AS closed_total,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL')                                AS critical,
      COUNT(*) FILTER (WHERE severity = 'HIGH')                                    AS high,
      COUNT(*) FILTER (WHERE severity = 'MEDIUM')                                  AS medium,
      COUNT(*) FILTER (WHERE severity IN ('LOW','NEGLIGIBLE'))                     AS low,
      COUNT(*) FILTER (WHERE classification IN ('TRUE_POSITIVE','AUTO_TP'))        AS true_positive,
      COUNT(*) FILTER (WHERE classification IN ('FALSE_POSITIVE','AUTO_FP')
                          OR status = 'FALSO_POSITIVO')                            AS false_positive,
      COUNT(*) FILTER (WHERE classification IN ('DUPLICATE','AUTO_DUPLICATE'))     AS duplicate,
      COUNT(*) FILTER (WHERE classification IN ('NO_ACTIONABLE','AUTO_NO_ACTIONABLE')) AS no_actionable,
      COUNT(*) FILTER (WHERE operator_id IS NOT NULL)                             AS human_closed,
      COUNT(*) FILTER (WHERE COALESCE(reopened_count,0) > 0)                       AS reopened_cases,
      COUNT(DISTINCT operator_id) FILTER (WHERE operator_id IS NOT NULL)          AS operators_involved,
      ROUND(AVG(EXTRACT(EPOCH FROM COALESCE(resolved_at, updated_at) - created_at) / 60.0), 1) AS avg_mttr_min
    FROM wnd
  `, [from, to]);
  return rows[0] ?? {};
}

/** Muestra de cierres analizables (mayor severidad/score primero) para el LLM. */
async function _closedCaseSample(from, to, limit = 12) {
  return pgQuery(`
    SELECT
      c.id, c.ioc_value, c.severity, c.score, c.classification, c.status,
      c.source_log, c.mitre_tactic_id, c.mitre_tactic_name,
      (c.operator_id IS NOT NULL)                       AS human_closed,
      COALESCE(o.name, c.operator_id)                    AS operator_name,
      ROUND(EXTRACT(EPOCH FROM COALESCE(c.resolved_at, c.updated_at) - c.created_at) / 60.0) AS mttr_min,
      LEFT(COALESCE(NULLIF(c.lessons_learned,''),
                    NULLIF(c.auto_closed_reason,''), ''), 280) AS notes
    FROM incident_cases_pg c
    LEFT JOIN soc_operators o ON o.id = c.operator_id
    WHERE c.created_at >= $1 AND c.created_at < $2
      AND c.status IN ('CERRADO','FALSO_POSITIVO')
      AND NOT (c.auto_closed_at IS NOT NULL AND c.severity IN ('LOW','NEGLIGIBLE'))
    ORDER BY
      CASE c.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                      WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
      c.score DESC NULLS LAST, c.created_at DESC
    LIMIT ${limit}
  `, [from, to]);
}

/** Incidentes CRITICAL del período (para tabla detallada). */
async function _criticalCases(from, to, limit = 15) {
  return pgQuery(`
    SELECT
      c.id, c.ioc_value, c.ioc_type, c.source_log,
      c.mitre_tactic_id, c.mitre_tactic_name, c.status,
      c.created_at, c.adopted_at, c.resolved_at,
      c.operator_id, COALESCE(o.name, c.operator_id) AS operator_name,
      c.score
    FROM incident_cases_pg c
    LEFT JOIN soc_operators o ON o.id = c.operator_id
    WHERE c.severity = 'CRITICAL'
      AND c.created_at >= $1 AND c.created_at < $2
    ORDER BY c.created_at DESC
    LIMIT ${limit}
  `, [from, to]);
}

// ── Renderizado Markdown ─────────────────────────────────────────────────────

function _renderMarkdown({ windowLabel, windowDays, rangeFrom, rangeTo, curr, prev, dailyVolume, topTactics, topIocs, operatorPerf, criticalCases, closedAnalytics, llmNarrativeMarkdown, generatedAt, generatedBy }) {
  const lines = [];

  // ── Header ─────────────────────────────────────────────────────────────────
  lines.push(`# Informe Ejecutivo SOC — ${windowLabel}`);
  lines.push("");
  lines.push(`**Período evaluado:** ${rangeFrom.toISOString().slice(0, 10)} → ${rangeTo.toISOString().slice(0, 10)} (${windowDays} días)`);
  lines.push(`**Emitido:** ${new Date(generatedAt).toLocaleString("es-ES")}`);
  if (generatedBy) lines.push(`**Operador:** ${generatedBy}`);
  lines.push(`**Clasificación:** CONFIDENCIAL — Sólo LEADER / ADMIN`);
  lines.push("");
  lines.push("---");
  lines.push("");

  // ── 1. Resumen ejecutivo ──────────────────────────────────────────────────
  const totalCurr = Number(curr.total_cases ?? 0);
  const totalPrev = Number(prev.total_cases ?? 0);
  const dCases    = _delta(totalCurr, totalPrev);
  const critCurr  = Number(curr.critical_total ?? 0);
  const openCurr  = Number(curr.open_cases ?? 0);

  lines.push(`## 1. Resumen ejecutivo`);
  lines.push("");
  lines.push(`En los últimos **${windowDays} días** se gestionaron **${_fmtNum(totalCurr)} incidentes**, de los cuales **${_fmtNum(critCurr)} fueron CRITICAL** y **${_fmtNum(openCurr)} permanecen abiertos** al momento de emisión.`);
  lines.push("");
  lines.push(`Comparado con el período equivalente previo (${windowDays} días anteriores), el volumen total ${totalCurr >= totalPrev ? "aumentó" : "disminuyó"} **${dCases.str}** (${_fmtNum(totalPrev)} casos previos).`);
  lines.push("");

  // 3 hallazgos destacados automáticos
  const highlights = [];
  if (curr.mtta_critical_min != null && curr.mtta_critical_min > 60) {
    highlights.push(`**MTTA crítico fuera de SLA**: ${_fmtMin(curr.mtta_critical_min)} (objetivo ≤ 60 min). Requiere revisión de auto-assign / cobertura L1.`);
  }
  const fpRate = totalCurr > 0 ? (Number(curr.fp_cases ?? 0) / totalCurr) * 100 : 0;
  if (fpRate > 10) {
    highlights.push(`**Tasa de falsos positivos elevada**: ${_fmtPct(fpRate)} supera el umbral NIST (< 10%). Revisar reglas de detección.`);
  }
  const tacticsHit = Number(curr.mitre_tactics_hit ?? 0);
  const mitreCov = (tacticsHit / MITRE_TOTAL_TACTICS) * 100;
  if (mitreCov < 70) {
    highlights.push(`**Cobertura MITRE ATT&CK por debajo del objetivo**: ${_fmtPct(mitreCov)} (objetivo ≥ 70%). Completar reglas para tácticas faltantes.`);
  }
  if (highlights.length === 0) {
    highlights.push("Sin desvíos críticos detectados respecto a umbrales NIST SP 800-61 en el período evaluado.");
  }
  lines.push(`### Hallazgos destacados`);
  lines.push("");
  for (const h of highlights.slice(0, 3)) lines.push(`- ${h}`);
  lines.push("");

  // ── 2. KPIs operacionales ────────────────────────────────────────────────
  lines.push(`## 2. KPIs operacionales (NIST SP 800-61 / CSF 2.0)`);
  lines.push("");
  lines.push(`| Indicador | Período actual | Período previo | Tendencia |`);
  lines.push(`|---|---|---|---|`);
  const slaPct = critCurr > 0 ? (Number(curr.sla_ok ?? 0) / critCurr) * 100 : null;
  const slaPctPrev = Number(prev.critical_total ?? 0) > 0
    ? (Number(prev.sla_ok ?? 0) / Number(prev.critical_total)) * 100 : null;
  lines.push(`| MTTA global              | ${_fmtMin(curr.mtta_min)}          | ${_fmtMin(prev.mtta_min)}          | ${_deltaArrow(curr.mtta_min, prev.mtta_min)} |`);
  lines.push(`| MTTA CRITICAL            | ${_fmtMin(curr.mtta_critical_min)} | ${_fmtMin(prev.mtta_critical_min)} | ${_deltaArrow(curr.mtta_critical_min, prev.mtta_critical_min)} |`);
  lines.push(`| SLA Critical (≤ 60 min)  | ${_fmtPct(slaPct)}                 | ${_fmtPct(slaPctPrev)}             | ${_deltaArrow(slaPct, slaPctPrev, "higher_better")} |`);
  lines.push(`| FP Rate                  | ${_fmtPct(fpRate)}                 | ${_fmtPct(totalPrev > 0 ? (Number(prev.fp_cases ?? 0) / totalPrev) * 100 : null)} | ${_deltaArrow(fpRate, totalPrev > 0 ? (Number(prev.fp_cases ?? 0) / totalPrev) * 100 : null)} |`);
  lines.push(`| Cobertura MITRE          | ${_fmtPct(mitreCov)}               | ${_fmtPct(Number(prev.mitre_tactics_hit ?? 0) / MITRE_TOTAL_TACTICS * 100)} | ${_deltaArrow(mitreCov, Number(prev.mitre_tactics_hit ?? 0) / MITRE_TOTAL_TACTICS * 100, "higher_better")} |`);
  lines.push("");
  lines.push(`> Umbrales NIST: MTTA CRITICAL ≤ 60 min · FP Rate < 10% · Cobertura MITRE ≥ 70%`);
  lines.push("");

  // ── 3. Volumen y tendencia ────────────────────────────────────────────────
  lines.push(`## 3. Volumen y tendencia`);
  lines.push("");
  lines.push(`| Categoría | ${windowDays} d actual | ${windowDays} d previo | Δ |`);
  lines.push(`|---|---|---|---|`);
  const cats = [
    ["Total",      curr.total_cases,    prev.total_cases],
    ["CRITICAL",   curr.critical_total, prev.critical_total],
    ["HIGH",       curr.high_total,     prev.high_total],
    ["MEDIUM",     curr.medium_total,   prev.medium_total],
    ["LOW/NEGL",   curr.low_total,      prev.low_total],
    ["Cerrados",   curr.closed_cases,   prev.closed_cases],
    ["Abiertos",   curr.open_cases,     prev.open_cases],
    ["Escalados",  curr.escalated_cases,prev.escalated_cases],
    ["FP",         curr.fp_cases,       prev.fp_cases],
  ];
  for (const [label, c, p] of cats) {
    lines.push(`| ${label} | ${_fmtNum(c)} | ${_fmtNum(p)} | ${_delta(c, p).str} |`);
  }
  lines.push("");

  // Tendencia diaria (últimos 7 días del período, desc)
  if (dailyVolume.length > 0) {
    lines.push(`### Evolución diaria (últimos ${Math.min(7, dailyVolume.length)} días)`);
    lines.push("");
    lines.push(`| Fecha | Total | CRITICAL | HIGH |`);
    lines.push(`|---|---|---|---|`);
    for (const d of dailyVolume.slice(0, 7)) {
      const date = d.day instanceof Date ? d.day.toISOString().slice(0, 10) : String(d.day);
      lines.push(`| ${date} | ${_fmtNum(d.total)} | ${_fmtNum(d.critical)} | ${_fmtNum(d.high)} |`);
    }
    lines.push("");
  }

  // ── 4. Incidentes CRITICAL ───────────────────────────────────────────────
  lines.push(`## 4. Incidentes CRITICAL del período`);
  lines.push("");
  if (criticalCases.length === 0) {
    lines.push(`_Sin incidentes CRITICAL registrados en los últimos ${windowDays} días._`);
  } else {
    lines.push(`Se listan los últimos ${criticalCases.length} incidentes CRITICAL; estado al momento de emisión:`);
    lines.push("");
    lines.push(`| ID | IOC | Táctica MITRE | Estado | Operador | Resolución |`);
    lines.push(`|---|---|---|---|---|---|`);
    for (const c of criticalCases) {
      const tactic = c.mitre_tactic_id
        ? `${c.mitre_tactic_id}${c.mitre_tactic_name ? " · " + c.mitre_tactic_name : ""}`
        : "—";
      const res = c.resolved_at
        ? _fmtMin((new Date(c.resolved_at) - new Date(c.created_at)) / 60000)
        : (c.adopted_at ? "en proceso" : "sin adoptar");
      const id = String(c.id).slice(0, 8);
      const ioc = String(c.ioc_value ?? "—").slice(0, 32);
      lines.push(`| \`${id}\` | \`${ioc}\` | ${tactic} | ${c.status} | ${c.operator_name ?? "—"} | ${res} |`);
    }
  }
  lines.push("");

  // ── 5. Cobertura MITRE ATT&CK ─────────────────────────────────────────────
  lines.push(`## 5. Cobertura MITRE ATT&CK`);
  lines.push("");
  lines.push(`Tácticas detectadas en el período: **${tacticsHit} / ${MITRE_TOTAL_TACTICS}** (${_fmtPct(mitreCov)}).`);
  lines.push("");
  if (topTactics.length > 0) {
    lines.push(`| Táctica | ID | Hits | CRITICAL | HIGH | IOCs únicos |`);
    lines.push(`|---|---|---|---|---|---|`);
    for (const t of topTactics) {
      const name = t.tactic_name && t.tactic_name !== "(sin nombre)"
        ? t.tactic_name
        : MITRE_TACTIC_LABEL[t.tactic_id] ?? "(sin nombre)";
      lines.push(`| ${name} | \`${t.tactic_id}\` | ${_fmtNum(t.hits)} | ${_fmtNum(t.critical_hits)} | ${_fmtNum(t.high_hits)} | ${_fmtNum(t.unique_iocs)} |`);
    }
    lines.push("");
  }
  // Tácticas NO cubiertas (para accionar)
  const covered = new Set(topTactics.map((t) => t.tactic_id));
  const missing = Object.keys(MITRE_TACTIC_LABEL).filter((id) => !covered.has(id));
  if (missing.length > 0) {
    lines.push(`**Tácticas sin actividad detectada:** ${missing.map((id) => `\`${id}\``).join(", ")}. Validar si la ausencia se debe a cobertura de reglas o a ausencia real de actividad.`);
    lines.push("");
  }

  // ── 6. Performance operativa ──────────────────────────────────────────────
  lines.push(`## 6. Performance operativa`);
  lines.push("");
  if (operatorPerf.length === 0) {
    lines.push(`_Sin casos adoptados por operadores en el período._`);
  } else {
    lines.push(`| Operador | Rol | Casos adoptados | Cerrados | CRITICAL |`);
    lines.push(`|---|---|---|---|---|`);
    for (const o of operatorPerf) {
      lines.push(`| ${o.operator_name ?? "—"} | ${o.role_id ?? "—"} | ${_fmtNum(o.adopted_cases)} | ${_fmtNum(o.closed_cases)} | ${_fmtNum(o.critical_handled)} |`);
    }
  }
  lines.push("");

  // ── 7. Top IOCs / atacantes ───────────────────────────────────────────────
  lines.push(`## 7. Top IOCs / atacantes externos`);
  lines.push("");
  if (topIocs.length === 0) {
    lines.push(`_Sin IOCs públicos relevantes en el período._`);
  } else {
    lines.push(`| IOC | Tipo | Casos | Score máx | Severidad máx | Fuentes distintas |`);
    lines.push(`|---|---|---|---|---|---|`);
    for (const i of topIocs) {
      lines.push(`| \`${i.ioc_value}\` | ${i.ioc_type} | ${_fmtNum(i.case_count)} | ${_fmtNum(i.max_score)} | ${i.max_severity ?? "—"} | ${_fmtNum(i.source_diversity)} |`);
    }
  }
  lines.push("");

  // ── 8. Conclusiones y recomendaciones ─────────────────────────────────────
  lines.push(`## 8. Conclusiones y recomendaciones`);
  lines.push("");
  const recs = [];
  if (curr.mtta_critical_min != null && curr.mtta_critical_min > 60) {
    recs.push(["P1", `Reducir MTTA CRITICAL (actual ${_fmtMin(curr.mtta_critical_min)}, objetivo ≤ 60 min).`, "Activar turno nocturno adicional o revisar umbrales de auto-assign.", "14 días"]);
  }
  if (fpRate > 10) {
    recs.push(["P1", `Revisar reglas de alta-FP — tasa actual ${_fmtPct(fpRate)} supera umbral.`, "Auditar top 5 signatures con mayor FP rate y ajustar o silenciar.", "30 días"]);
  }
  if (mitreCov < 70) {
    recs.push(["P2", `Ampliar cobertura MITRE a ${_fmtPct(70)} mínimo (actual ${_fmtPct(mitreCov)}).`, `Crear reglas para tácticas ${missing.slice(0, 3).join(", ")}.`, "60 días"]);
  }
  if (Number(curr.escalated_cases ?? 0) > totalCurr * 0.1) {
    recs.push(["P2", `Tasa de escalación elevada (${_fmtPct((Number(curr.escalated_cases) / totalCurr) * 100)}).`, "Revisar criterios de escalación L1→L2 y refuerzo de playbooks.", "30 días"]);
  }
  const unassigned = Number(curr.open_cases ?? 0) > 0 && operatorPerf.length < 3;
  if (unassigned) {
    recs.push(["P3", `Concentración de carga en pocos operadores (${operatorPerf.length} analistas activos).`, "Considerar rotación / redistribución de casos entre turnos.", "30 días"]);
  }
  if (recs.length === 0) {
    recs.push(["P4", "Mantener tendencia actual.", "Continuar monitoreo semanal y revisión de KPIs en reuniones de equipo.", "Continuo"]);
  }
  lines.push(`| Prioridad | Acción | Detalle | Plazo |`);
  lines.push(`|---|---|---|---|`);
  for (const [p, a, d, pl] of recs) lines.push(`| **${p}** | ${a} | ${d} | ${pl} |`);
  lines.push("");

  // ── 9. Análisis de cierres (excl. auto-cerrados LOW/NEG) ───────────────────
  const ca = closedAnalytics ?? {};
  const closedTotal = Number(ca.closed_total ?? 0);
  lines.push(`## 9. Análisis de cierres (con valor analítico)`);
  lines.push("");
  lines.push(`Casos terminales del período **excluyendo los auto-cerrados LOW/NEGLIGIBLE** (churn de ruido). Mide el trabajo de cierre con valor analítico.`);
  lines.push("");
  if (closedTotal === 0) {
    lines.push(`_Sin cierres analizables en el período (todos los cierres fueron auto-cerrados LOW/NEGLIGIBLE o no hubo cierres)._`);
    lines.push("");
  } else {
    const fpRateClosed = (Number(ca.false_positive ?? 0) / closedTotal) * 100;
    const humanPct     = (Number(ca.human_closed ?? 0) / closedTotal) * 100;
    lines.push(`| Indicador | Valor |`);
    lines.push(`|---|---|`);
    lines.push(`| Cierres analizables           | ${_fmtNum(closedTotal)} |`);
    lines.push(`| Por severidad (C/H/M/L)       | ${_fmtNum(ca.critical)} / ${_fmtNum(ca.high)} / ${_fmtNum(ca.medium)} / ${_fmtNum(ca.low)} |`);
    lines.push(`| Verdaderos positivos          | ${_fmtNum(ca.true_positive)} |`);
    lines.push(`| Falsos positivos              | ${_fmtNum(ca.false_positive)} (${_fmtPct(fpRateClosed)}) |`);
    lines.push(`| Duplicados / No accionables   | ${_fmtNum(ca.duplicate)} / ${_fmtNum(ca.no_actionable)} |`);
    lines.push(`| Cerrados por humano           | ${_fmtNum(ca.human_closed)} (${_fmtPct(humanPct)}) |`);
    lines.push(`| Operadores involucrados       | ${_fmtNum(ca.operators_involved)} |`);
    lines.push(`| Casos reabiertos (pingpong)   | ${_fmtNum(ca.reopened_cases)} |`);
    lines.push("");
  }

  // ── 10. Lectura del Analista (IA) — opcional, sólo si el LLM respondió ──────
  if (llmNarrativeMarkdown && llmNarrativeMarkdown.trim()) {
    lines.push(llmNarrativeMarkdown.trim());
    lines.push("");
  }

  // ── Footer ────────────────────────────────────────────────────────────────
  lines.push("---");
  lines.push("");
  lines.push(`*Informe generado automáticamente por LegacyHunt SOC — Plataforma de Threat Intelligence.*  `);
  lines.push(`*Datos consultados sobre \`incident_cases_pg\` (fuente operacional). Las métricas siguen la taxonomía NIST SP 800-61 Rev. 3 + CSF 2.0.*`);

  return lines.join("\n") + "\n";
}

// ── Resolución de presets y rangos ───────────────────────────────────────────
/**
 * Resuelve un preset o rango a { from, to, label, slug, windowDays }.
 * Presets soportados:
 *   · "15d", "30d", "7d", "90d", "Nd" (cualquier N entre 1 y 365)
 *   · "this_day"      — día en curso (hoy, 00:00 → ahora)
 *   · "this_week"     — semana en curso (lunes → ahora, ISO)
 *   · "last_month"    — mes calendario anterior completo
 *   · "this_month"    — mes en curso (hasta hoy)
 *   · "last_quarter"  — trimestre calendario anterior completo (Q1/Q2/Q3/Q4)
 *   · "this_quarter"  — trimestre en curso
 *   · "ytd"           — 1-ene del año en curso hasta hoy
 * Rango custom: pasar `{ from, to }` (Date o ISO "YYYY-MM-DD").
 */
export function resolveReportRange({ preset, from, to, now = new Date() } = {}) {
  const _d = (y, m, d) => new Date(Date.UTC(y, m, d, 0, 0, 0, 0));
  const Y = now.getUTCFullYear(), M = now.getUTCMonth(), D = now.getUTCDate();
  const today00 = _d(Y, M, D);
  const tomorrow00 = _d(Y, M, D + 1);

  // Rango custom explícito
  if (from && to) {
    const fDate = from instanceof Date ? from : new Date(String(from));
    const tDate = to   instanceof Date ? to   : new Date(String(to));
    // Normalizar: tomar `to` como fin-exclusivo (día siguiente a las 00:00)
    const tExcl = new Date(tDate);
    tExcl.setUTCDate(tExcl.getUTCDate() + 1);
    tExcl.setUTCHours(0, 0, 0, 0);
    const days = Math.max(1, Math.round((tExcl - fDate) / 86400000));
    return {
      from: fDate, to: tExcl,
      label: `${fDate.toISOString().slice(0, 10)} → ${tDate.toISOString().slice(0, 10)}`,
      slug:  `custom-${fDate.toISOString().slice(0, 10)}-${tDate.toISOString().slice(0, 10)}`,
      windowDays: days,
    };
  }

  const p = String(preset ?? "15d").toLowerCase().trim();

  // "Nd" — últimos N días (por defecto)
  const mNd = p.match(/^(\d{1,3})\s*d?$/);
  if (mNd) {
    const days = Math.min(365, Math.max(1, Number(mNd[1])));
    return {
      from: new Date(tomorrow00.getTime() - days * 86400000),
      to:   tomorrow00,
      label: `últimos ${days} días`,
      slug:  `${days}d`,
      windowDays: days,
    };
  }

  if (p === "this_day" || p === "today") {
    return { from: today00, to: tomorrow00, label: "día en curso (hoy)", slug: "hoy",
             windowDays: 1 };
  }
  if (p === "this_week") {
    // Semana ISO: lunes como primer día. getUTCDay(): 0=domingo … 6=sábado.
    const dow = today00.getUTCDay();
    const backToMon = (dow + 6) % 7;          // domingo(0)→6, lunes(1)→0, …
    const f = new Date(today00.getTime() - backToMon * 86400000);
    return { from: f, to: tomorrow00, label: "semana en curso",
             slug: "semana-actual",
             windowDays: Math.round((tomorrow00 - f) / 86400000) };
  }
  if (p === "last_week") {
    const dow = today00.getUTCDay();
    const backToMon = (dow + 6) % 7;
    const thisMon = new Date(today00.getTime() - backToMon * 86400000);
    const f = new Date(thisMon.getTime() - 7 * 86400000);
    return { from: f, to: thisMon, label: "semana anterior", slug: "semana-anterior",
             windowDays: 7 };
  }
  if (p === "this_month") {
    const f = _d(Y, M, 1);
    return { from: f, to: tomorrow00, label: "mes en curso", slug: "mes-actual",
             windowDays: Math.round((tomorrow00 - f) / 86400000) };
  }
  if (p === "last_month") {
    const f = _d(Y, M - 1, 1);
    const t = _d(Y, M, 1);
    return { from: f, to: t, label: "mes anterior", slug: "mes-anterior",
             windowDays: Math.round((t - f) / 86400000) };
  }
  if (p === "this_quarter") {
    const qStart = Math.floor(M / 3) * 3;
    const f = _d(Y, qStart, 1);
    return { from: f, to: tomorrow00, label: `trimestre en curso (Q${qStart / 3 + 1})`,
             slug: `Q${qStart / 3 + 1}-${Y}`,
             windowDays: Math.round((tomorrow00 - f) / 86400000) };
  }
  if (p === "last_quarter") {
    const qStart = Math.floor(M / 3) * 3;
    const f = _d(Y, qStart - 3, 1);
    const t = _d(Y, qStart, 1);
    const q = qStart === 0 ? 4 : qStart / 3;
    const yy = qStart === 0 ? Y - 1 : Y;
    return { from: f, to: t, label: `trimestre anterior (Q${q} ${yy})`,
             slug: `Q${q}-${yy}`,
             windowDays: Math.round((t - f) / 86400000) };
  }
  if (p === "ytd") {
    const f = _d(Y, 0, 1);
    return { from: f, to: tomorrow00, label: `año en curso (YTD)`, slug: `ytd-${Y}`,
             windowDays: Math.round((tomorrow00 - f) / 86400000) };
  }

  // Default: 15d
  const def = 15;
  return {
    from: new Date(tomorrow00.getTime() - def * 86400000),
    to:   tomorrow00,
    label: `últimos ${def} días`, slug: `${def}d`, windowDays: def,
  };
}

// ── API pública ──────────────────────────────────────────────────────────────

/**
 * Construye el informe ejecutivo.
 *
 * @param {{
 *   preset?: string,                        // "15d"|"30d"|"last_month"|...
 *   from?: string|Date, to?: string|Date,   // rango custom (fin inclusive)
 *   windowDays?: number,                    // compat: equivalente a preset "Nd"
 *   generatedBy?: string,
 * }} opts
 * @returns {Promise<{ markdown, filename, meta }>}
 */
export async function buildExecutiveReport(opts = {}) {
  const { generatedBy = null, llm = false } = opts;
  const presetOrDays = opts.preset ?? (opts.windowDays != null ? `${opts.windowDays}d` : "15d");
  const curRange = resolveReportRange({ preset: presetOrDays, from: opts.from, to: opts.to });
  // Ventana previa: mismo tamaño, shift back
  const prevTo    = curRange.from;
  const prevFrom  = new Date(prevTo.getTime() - (curRange.to - curRange.from));

  const [curr, prev, dailyVolume, topTactics, topIocs, operatorPerf, criticalCases, closedAnalytics, closedSample] = await Promise.all([
    _summary(curRange.from, curRange.to),
    _summary(prevFrom, prevTo),
    _dailyVolume(curRange.from, curRange.to, Math.min(90, curRange.windowDays)),
    _topMitreTactics(curRange.from, curRange.to, 10),
    _topIocs(curRange.from, curRange.to, 10),
    _operatorPerformance(curRange.from, curRange.to, 10),
    _criticalCases(curRange.from, curRange.to, 15),
    _closedCaseAnalytics(curRange.from, curRange.to),
    _closedCaseSample(curRange.from, curRange.to, 12),
  ]);

  const generatedAt = new Date().toISOString();
  const meta = {
    windowDays:   curRange.windowDays,
    windowLabel:  curRange.label,
    rangeFrom:    curRange.from.toISOString(),
    rangeTo:      curRange.to.toISOString(),
    generatedAt,
    generatedBy,
    totalCases:    Number(curr.total_cases    ?? 0),
    criticalCases: Number(curr.critical_total ?? 0),
    openCases:     Number(curr.open_cases     ?? 0),
    closedAnalyzable: Number(closedAnalytics.closed_total ?? 0),
  };

  // Capa LLM (opcional): la narrativa interpreta las métricas YA calculadas. Si
  // el LLM no está disponible o no responde, narrative=null y el informe se emite
  // igual con sus 9 secciones deterministas (degradación elegante).
  let llmNarrative = null;
  let llmRequested = Boolean(llm);
  const llmAvailable = narrativeAnalystAvailable();
  if (llmRequested && llmAvailable) {
    const res = await buildExecutiveNarrative({
      meta, summary: curr, closed: closedAnalytics,
      sample: closedSample, topTactics,
    });
    llmNarrative = res.narrative;
  }
  meta.llmRequested = llmRequested;
  meta.llmAvailable = llmAvailable;
  meta.llmApplied   = Boolean(llmNarrative);

  const markdown = _renderMarkdown({
    windowLabel: curRange.label,
    windowDays:  curRange.windowDays,
    rangeFrom:   curRange.from,
    rangeTo:     curRange.to,
    curr, prev, dailyVolume, topTactics, topIocs, operatorPerf, criticalCases,
    closedAnalytics,
    llmNarrativeMarkdown: llmNarrative ? renderNarrativeMarkdown(llmNarrative) : "",
    generatedAt, generatedBy,
  });

  const stamp = generatedAt.slice(0, 10);
  const filename = `informe-ejecutivo-soc-${stamp}-${curRange.slug}`;
  return {
    markdown,
    filename,
    meta,
    // Datos estructurados para que consumidores (p.ej. el PDF builder del
    // dashboard) no tengan que parsear el Markdown.
    data: { curr, prev, dailyVolume, topTactics, topIocs, operatorPerf, criticalCases, closedAnalytics },
    llmNarrative,
  };
}
