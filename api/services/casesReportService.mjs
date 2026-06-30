/**
 * casesReportService.mjs
 *
 * Informe ejecutivo para un CONJUNTO de casos seleccionados por un operador en la
 * cola de gestión (p.ej. para un escalamiento, un handover o una revisión
 * dirigida). Agrega el contexto de los casos y lo pasa por el analista LLM, con
 * enfoque en CONTEXTO e IMPACTO DE NEGOCIO (sin métricas de tiempos de respuesta).
 *
 * Determinístico-primero: los agregados se calculan en SQL/JS; el LLM sólo
 * redacta la narrativa sobre ese contexto. Degradación elegante: si el LLM no
 * está disponible, devuelve narrative=null y el informe sale igual.
 *
 * Fuente: incident_cases_pg (PG). No menciona el motor de IA concreto.
 */

import { pgQuery } from "../db/postgres.mjs";
import { buildCasesNarrative } from "./executiveNarrativeAnalyst.mjs";

const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NEGLIGIBLE: 4 };

function _topN(map, n) {
  return [...map.entries()]
    .map(([k, v]) => ({ key: k, ...v }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

/**
 * @param {string[]} caseIds
 * @param {{ generatedBy?: string|null }} [opts]
 * @returns {Promise<{ meta, agg, cases, narrative }>}
 */
export async function buildSelectedCasesReport(caseIds, opts = {}) {
  const ids = (Array.isArray(caseIds) ? caseIds : []).map(String).filter(Boolean);
  if (ids.length === 0) {
    const e = new Error("caseIds vacío"); e.code = "EMPTY"; throw e;
  }

  const rows = await pgQuery(
    `SELECT c.id, c.severity, c.status, c.score,
            c.ioc_value, c.ioc_type, c.source_log,
            c.mitre_tactic_id, c.mitre_tactic_name, c.mitre_technique_id,
            c.classification, c.operator_id, c.created_at, c.detected_at,
            c.business_impact,
            COALESCE(o.name, c.operator_id) AS operator_name
       FROM incident_cases_pg c
       LEFT JOIN soc_operators o ON o.id = c.operator_id
      WHERE c.id = ANY($1::text[])`,
    [ids],
  );

  const TERMINAL = new Set(["CERRADO", "FALSO_POSITIVO"]);
  const TP = new Set(["TRUE_POSITIVE", "AUTO_TP"]);
  const FP = new Set(["FALSE_POSITIVE", "AUTO_FP"]);

  const agg = {
    total: rows.length,
    critical: 0, high: 0, medium: 0, low: 0,
    open: 0, closed: 0, escalated: 0,
    true_positive: 0, false_positive: 0,
    max_score: 0,
  };
  const tactics = new Map();   // label → { count }
  const sources = new Map();   // source_log → { count }
  const iocs = new Map();      // ioc_value → { count, ioc_type, max_severity }
  const iocSet = new Set();
  const srcSet = new Set();

  for (const r of rows) {
    const sev = String(r.severity ?? "").toUpperCase();
    if (sev === "CRITICAL") agg.critical++;
    else if (sev === "HIGH") agg.high++;
    else if (sev === "MEDIUM") agg.medium++;
    else agg.low++; // LOW + NEGLIGIBLE
    if (TERMINAL.has(r.status)) agg.closed++; else agg.open++;
    if (r.status === "ESCALADO") agg.escalated++;
    if (TP.has(r.classification)) agg.true_positive++;
    if (FP.has(r.classification) || r.status === "FALSO_POSITIVO") agg.false_positive++;
    agg.max_score = Math.max(agg.max_score, Number(r.score ?? 0));

    const tlabel = r.mitre_tactic_name
      ? `${r.mitre_tactic_name}${r.mitre_tactic_id ? " (" + r.mitre_tactic_id + ")" : ""}`
      : (r.mitre_tactic_id || "Sin táctica");
    tactics.set(tlabel, { count: (tactics.get(tlabel)?.count ?? 0) + 1 });

    const slabel = r.source_log || "—";
    sources.set(slabel, { count: (sources.get(slabel)?.count ?? 0) + 1 });
    if (r.source_log) srcSet.add(r.source_log);

    if (r.ioc_value) {
      iocSet.add(r.ioc_value);
      const prev = iocs.get(r.ioc_value) ?? { count: 0, ioc_type: r.ioc_type, max_severity: r.severity };
      prev.count++;
      if ((SEV_RANK[String(r.severity).toUpperCase()] ?? 9) < (SEV_RANK[String(prev.max_severity).toUpperCase()] ?? 9))
        prev.max_severity = r.severity;
      iocs.set(r.ioc_value, prev);
    }
  }
  agg.distinct_iocs = iocSet.size;
  agg.distinct_sources = srcSet.size;
  agg.topTactics = _topN(tactics, 8).map((t) => ({ label: t.key, count: t.count }));
  agg.topSources = _topN(sources, 6).map((s) => ({ label: s.key, count: s.count }));
  agg.topIocs = _topN(iocs, 8).map((i) => ({
    ioc_value: i.key, ioc_type: i.ioc_type, count: i.count, max_severity: i.max_severity,
  }));

  // Muestra para el LLM: mayor severidad/score primero (cap 12).
  const sorted = [...rows].sort((a, b) => {
    const sr = (SEV_RANK[String(a.severity).toUpperCase()] ?? 9) - (SEV_RANK[String(b.severity).toUpperCase()] ?? 9);
    return sr !== 0 ? sr : (Number(b.score) || 0) - (Number(a.score) || 0);
  });
  const sample = sorted.slice(0, 12).map((r) => ({
    severity: r.severity, status: r.status, score: r.score,
    ioc_value: r.ioc_value, ioc_type: r.ioc_type, source_log: r.source_log,
    mitre_tactic_id: r.mitre_tactic_id, mitre_tactic_name: r.mitre_tactic_name,
    classification: r.classification,
    business_impact: r.business_impact ?? null,
  }));

  // Narrativa LLM (degradación elegante).
  const { narrative } = await buildCasesNarrative({ agg, sample });

  const generatedAt = new Date().toISOString();
  return {
    meta: { generatedBy: opts.generatedBy ?? null, generatedAt, total: rows.length },
    agg,
    cases: sorted,
    narrative,
  };
}
