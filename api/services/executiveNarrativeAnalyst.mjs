/**
 * executiveNarrativeAnalyst.mjs
 *
 * Capa LLM (narrativa) del Informe Ejecutivo. Toma las MÉTRICAS YA CALCULADAS
 * por executiveReportService (KPIs NIST + analítica de cierres) y produce una
 * lectura ejecutiva en prosa: tendencias, calidad de los cierres, riesgo
 * residual y recomendaciones priorizadas.
 *
 * Determinístico-primero (igual criterio que threatFindingAnalyst.mjs): el LLM
 * NO calcula ni inventa cifras — sólo interpreta y redacta sobre los números que
 * se le pasan. Si Ollama no responde o el JSON no parsea, devuelve null y el
 * informe se emite igual con sus recomendaciones por umbral (degradación
 * elegante).
 *
 * El alcance del análisis son los CASOS CERRADOS con valor analítico, EXCLUYENDO
 * los auto-cerrados LOW/NEGLIGIBLE (churn de ruido). Esa criba la aplica
 * executiveReportService._closedCaseAnalytics / _closedCaseSample; aquí sólo se
 * recibe el agregado.
 *
 * Reusa la misma config LLM que soc-chat / el analista de findings:
 *   - host/modelo/api-key:  config.socChatLlm*  (qwen3.5 vía Ollama)
 *   - endpoint NATIVO /api/chat con think:false  (única forma de desactivar el
 *     CoT de qwen3.5 — ver nota en threatFindingAnalyst.callLlm)
 */

import { config } from "../config.mjs";

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const bool = (v, d) => (v == null || v === "" ? d : String(v).trim().toLowerCase() === "true");

const CFG = {
  // La narrativa es más larga que un veredicto de finding (~400-600 tokens),
  // pero con think:false qwen3.5 la emite en ~10-20s. 90s da margen holgado.
  timeoutMs: num(process.env.EXEC_NARRATIVE_TIMEOUT_MS, 90_000),
  noThink:   bool(process.env.EXEC_NARRATIVE_NO_THINK, true),
  // Nº máximo de casos de muestra que se inyectan en el prompt (post-mortem).
  sampleCap: num(process.env.EXEC_NARRATIVE_SAMPLE_CAP, 12),
};

/** ¿Está disponible el analista narrativo? (mismo gate que soc-chat). */
export function narrativeAnalystAvailable() {
  return (
    config.socChatLlmEnabled &&
    Boolean(config.socChatLlmApiKey) &&
    (process.env.EXEC_NARRATIVE_ENABLED ?? "true").trim().toLowerCase() === "true"
  );
}

// Endpoint nativo Ollama derivado del OpenAI-compat (…/v1/chat/completions →
// …/api/chat). Solo con noThink=true; si el URL no es Ollama, el replace no
// matchea y se cae al path OpenAI. (Espejo de threatFindingAnalyst.)
const OLLAMA_NATIVE_URL = CFG.noThink
  ? config.socChatLlmApiUrl.replace(/\/v1\/chat\/completions\/?$/, "/api/chat")
  : null;

const _fmtMin = (m) => {
  const x = Number(m);
  if (!Number.isFinite(x)) return "n/d";
  if (x >= 1440) return `${(x / 1440).toFixed(1)} d`;
  if (x >= 60)   return `${(x / 60).toFixed(1)} h`;
  return `${Math.round(x)} min`;
};

// ── Prompt ───────────────────────────────────────────────────────────────────
function buildMessages(ctx) {
  const { meta, summary, closed, sample, topTactics } = ctx;

  const sampleLines = (sample ?? []).slice(0, CFG.sampleCap).map((c, i) => {
    const tactic = c.mitre_tactic_id
      ? `${c.mitre_tactic_id}${c.mitre_tactic_name ? "/" + c.mitre_tactic_name : ""}`
      : "—";
    const notes = String(c.notes ?? "").replace(/\s+/g, " ").trim().slice(0, 200);
    return `${i + 1}. [${c.severity}] score=${c.score ?? "—"} clasif=${c.classification ?? "—"} `
      + `mitre=${tactic}`
      + (notes ? ` · "${notes}"` : "");
  }).join("\n");

  const tacticLines = (topTactics ?? []).slice(0, 6)
    .map((t) => `- ${t.tactic_id} ${t.tactic_name ?? ""}: ${t.hits} casos (${t.critical_hits} CRIT)`)
    .join("\n");

  const fpRate = closed.closed_total > 0
    ? ((Number(closed.false_positive ?? 0) / Number(closed.closed_total)) * 100).toFixed(1)
    : "0.0";

  const system = [
    "Eres un analista SOC senior redactando la sección de análisis de un Informe",
    "Ejecutivo para LEADER/ADMIN. Tu audiencia es directiva: redacta en español,",
    "claro y conciso, orientado a RIESGO DE NEGOCIO y decisión, sin jerga innecesaria.",
    "",
    "ENFOQUE: el análisis debe girar en torno al CONTEXTO DE LOS CASOS y su IMPACTO",
    "EN EL NEGOCIO (activos/servicios afectados, tácticas de los atacantes, exposición,",
    "criticidad), NO en métricas de tiempos de respuesta. NO menciones MTTR, MTTA ni",
    "tiempos de resolución aunque pudieras inferirlos.",
    "",
    "REGLAS ESTRICTAS:",
    "- Analiza ÚNICAMENTE los datos provistos. NO inventes cifras, IOCs ni hechos.",
    "- El alcance son los CASOS CERRADOS con valor analítico; los auto-cerrados",
    "  LOW/NEGLIGIBLE (ruido) YA fueron excluidos del agregado — no los menciones.",
    "- Si un dato no está, dilo como limitación, no lo rellenes.",
    "- Sé específico: cita números del contexto cuando respalden una afirmación.",
    "- Devuelve EXCLUSIVAMENTE un objeto JSON válido, sin texto fuera del JSON,",
    "  sin markdown, con esta forma EXACTA:",
    "{",
    '  "executive_summary": "2-4 frases: panorama de amenazas e impacto en el negocio del período",',
    '  "key_trends": ["3-5 bullets de patrones de amenaza/contexto observados en los casos"],',
    '  "business_impact": "2-3 frases sobre el impacto en el negocio (activos/servicios expuestos, severidad, proporción de amenaza real vs falsos positivos)",',
    '  "residual_risks": ["2-4 riesgos residuales o puntos ciegos para el negocio que sugieren los datos"],',
    '  "recommendations": [{"priority":"P1|P2|P3|P4","action":"…","rationale":"…"}]',
    "}",
  ].join("\n");

  const user = [
    `PERÍODO: ${meta.windowLabel} (${meta.windowDays} días, ${meta.rangeFrom?.slice?.(0,10) ?? ""} → ${meta.rangeTo?.slice?.(0,10) ?? ""})`,
    "",
    "VOLUMEN GLOBAL DEL PERÍODO (todos los casos):",
    `- Total: ${summary.total_cases ?? 0} · CRITICAL: ${summary.critical_total ?? 0} · HIGH: ${summary.high_total ?? 0} · MEDIUM: ${summary.medium_total ?? 0} · LOW/NEG: ${summary.low_total ?? 0}`,
    `- Abiertos: ${summary.open_cases ?? 0} · Escalados: ${summary.escalated_cases ?? 0}`,
    "",
    "CIERRES CON VALOR ANALÍTICO (excluye auto-cerrados LOW/NEGLIGIBLE):",
    `- Cerrados analizables: ${closed.closed_total ?? 0}`,
    `- Por severidad → CRITICAL: ${closed.critical ?? 0} · HIGH: ${closed.high ?? 0} · MEDIUM: ${closed.medium ?? 0} · LOW/NEG (revisados): ${closed.low ?? 0}`,
    `- Disposición → Verdaderos positivos: ${closed.true_positive ?? 0} · Falsos positivos: ${closed.false_positive ?? 0} (${fpRate}%) · Duplicados: ${closed.duplicate ?? 0} · No accionables: ${closed.no_actionable ?? 0}`,
    "",
    "TOP TÁCTICAS MITRE DEL PERÍODO:",
    tacticLines || "- (sin tácticas registradas)",
    "",
    `MUESTRA DE CASOS CERRADOS (hasta ${CFG.sampleCap}, mayor severidad/score primero):`,
    sampleLines || "- (sin casos en la muestra)",
    "",
    "Redacta el análisis ejecutivo en el JSON especificado, centrado en contexto e impacto de negocio.",
  ].join("\n");

  return [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
}

// ── Prompt para un CONJUNTO de casos seleccionados (reporte ejecutivo ad-hoc) ──
// Mismo esquema JSON, enfoque en contexto de los casos + impacto de negocio.
function buildSelectedCasesMessages(ctx) {
  const { agg, sample } = ctx;

  const sampleLines = (sample ?? []).slice(0, CFG.sampleCap).map((c, i) => {
    const tactic = c.mitre_tactic_name
      ? `${c.mitre_tactic_name}${c.mitre_tactic_id ? "/" + c.mitre_tactic_id : ""}`
      : (c.mitre_tactic_id ?? "—");
    return `${i + 1}. [${c.severity}] ${c.status} score=${c.score ?? "—"} `
      + `ioc=${c.ioc_value ?? "—"}(${c.ioc_type ?? "?"}) fuente=${c.source_log ?? "—"} `
      + `mitre=${tactic} clasif=${c.classification ?? "—"}`;
  }).join("\n");

  const sevLine = `CRITICAL: ${agg.critical ?? 0} · HIGH: ${agg.high ?? 0} · MEDIUM: ${agg.medium ?? 0} · LOW/NEG: ${agg.low ?? 0}`;
  const tacticLines = (agg.topTactics ?? []).slice(0, 8)
    .map((t) => `- ${t.label}: ${t.count} caso(s)`).join("\n");
  const sourceLines = (agg.topSources ?? []).slice(0, 6)
    .map((s) => `- ${s.label}: ${s.count}`).join("\n");
  const iocLines = (agg.topIocs ?? []).slice(0, 8)
    .map((i) => `- ${i.ioc_value} (${i.ioc_type ?? "?"}): ${i.count} caso(s), sev máx ${i.max_severity ?? "—"}`).join("\n");

  const system = [
    "Eres un analista SOC senior. Redactas un INFORME EJECUTIVO sobre un conjunto de",
    "casos seleccionados por un operador (p.ej. para un escalamiento, un handover o una",
    "revisión dirigida). Audiencia directiva, en español, claro y conciso.",
    "",
    "ENFOQUE: contexto de los casos e IMPACTO EN EL NEGOCIO — activos/servicios",
    "afectados, tácticas y objetivos del atacante, exposición y criticidad. NO uses",
    "métricas de tiempos de respuesta (MTTR/MTTA) ni hables de tiempos de resolución.",
    "",
    "REGLAS ESTRICTAS:",
    "- Analiza ÚNICAMENTE los datos provistos. NO inventes cifras, IOCs ni hechos.",
    "- Sé específico: cita IOCs/tácticas/activos del contexto cuando respalden algo.",
    "- Devuelve EXCLUSIVAMENTE un objeto JSON válido, sin texto fuera del JSON,",
    "  sin markdown, con esta forma EXACTA:",
    "{",
    '  "executive_summary": "2-4 frases: qué representan estos casos y su relevancia para el negocio",',
    '  "key_trends": ["3-5 bullets de patrones/contexto común (tácticas, IOCs, fuentes, activos)"],',
    '  "business_impact": "2-3 frases sobre el impacto/riesgo de negocio del conjunto",',
    '  "residual_risks": ["2-4 riesgos o puntos ciegos a vigilar"],',
    '  "recommendations": [{"priority":"P1|P2|P3|P4","action":"…","rationale":"…"}]',
    "}",
  ].join("\n");

  const user = [
    `CONJUNTO SELECCIONADO: ${agg.total ?? 0} caso(s).`,
    `Por severidad → ${sevLine}`,
    `Estados → abiertos: ${agg.open ?? 0} · cerrados/terminales: ${agg.closed ?? 0} · escalados: ${agg.escalated ?? 0}`,
    `Disposición → verdaderos positivos: ${agg.true_positive ?? 0} · falsos positivos: ${agg.false_positive ?? 0}`,
    `Score máximo del conjunto: ${agg.max_score ?? "—"} · IOCs distintos: ${agg.distinct_iocs ?? 0} · activos/fuentes distintas: ${agg.distinct_sources ?? 0}`,
    "",
    "TÁCTICAS MITRE PRESENTES:",
    tacticLines || "- (sin tácticas registradas)",
    "",
    "FUENTES / SENSORES:",
    sourceLines || "- (sin fuentes)",
    "",
    "IOCs MÁS REPETIDOS:",
    iocLines || "- (sin IOCs)",
    "",
    `MUESTRA DE CASOS (hasta ${CFG.sampleCap}, mayor severidad/score primero):`,
    sampleLines || "- (sin casos)",
    "",
    "Redacta el informe ejecutivo en el JSON especificado, centrado en contexto e impacto de negocio.",
  ].join("\n");

  return [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
}

async function callLlm(messages) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CFG.timeoutMs);
  try {
    if (OLLAMA_NATIVE_URL && OLLAMA_NATIVE_URL !== config.socChatLlmApiUrl) {
      const r = await fetch(OLLAMA_NATIVE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.socChatLlmApiKey}`,
        },
        body: JSON.stringify({
          model: config.socChatLlmModel,
          messages,
          stream: false,
          think: false,
          options: { temperature: 0.2 },
        }),
        signal: controller.signal,
      });
      if (!r.ok) return null;
      const json = await r.json();
      return json?.message?.content ?? null;
    }
    const r = await fetch(config.socChatLlmApiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.socChatLlmApiKey}`,
      },
      body: JSON.stringify({ model: config.socChatLlmModel, messages, temperature: 0.2 }),
      signal: controller.signal,
    });
    if (!r.ok) return null;
    const json = await r.json();
    return json?.choices?.[0]?.message?.content ?? null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Extrae el primer objeto JSON balanceado de la respuesta (qwen a veces envuelve
// en ```json o añade texto). Espejo de la tolerancia de threatFindingAnalyst.
function parseNarrative(raw) {
  if (!raw || typeof raw !== "string") return null;
  let s = raw.trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  let obj;
  try { obj = JSON.parse(s.slice(start, end + 1)); } catch { return null; }
  if (!obj || typeof obj !== "object") return null;

  const arr = (v) => (Array.isArray(v) ? v.filter((x) => x != null).map(String) : []);
  const recs = Array.isArray(obj.recommendations)
    ? obj.recommendations
        .filter((r) => r && typeof r === "object")
        .map((r) => ({
          priority: /^P[1-4]$/.test(String(r.priority ?? "").trim()) ? String(r.priority).trim() : "P3",
          action: String(r.action ?? "").trim(),
          rationale: String(r.rationale ?? "").trim(),
        }))
        .filter((r) => r.action)
    : [];

  const summary = String(obj.executive_summary ?? "").trim();
  if (!summary && recs.length === 0) return null; // respuesta vacía → degradar

  return {
    executive_summary: summary,
    key_trends: arr(obj.key_trends),
    // business_impact reemplaza al antiguo closure_quality (enfoque negocio, no
    // tiempos). Aceptamos el alias viejo por si el modelo lo devuelve.
    business_impact: String(obj.business_impact ?? obj.closure_quality ?? "").trim(),
    residual_risks: arr(obj.residual_risks),
    recommendations: recs,
  };
}

/**
 * Genera la narrativa ejecutiva sobre los cierres del período.
 * @param {{ meta:object, summary:object, closed:object, sample:object[], topTactics:object[] }} ctx
 * @returns {Promise<{ available:boolean, narrative:object|null, error?:string }>}
 */
export async function buildExecutiveNarrative(ctx, deps = {}) {
  const logger = deps.logger ?? console;
  if (!narrativeAnalystAvailable()) return { available: false, narrative: null };
  try {
    const messages = buildMessages(ctx);
    const raw = await callLlm(messages);
    const narrative = parseNarrative(raw);
    if (!narrative) {
      logger.warn?.("exec_narrative_unparsed", { rawLen: raw?.length ?? 0 });
      return { available: true, narrative: null, error: "unparsed" };
    }
    return { available: true, narrative };
  } catch (err) {
    logger.error?.("exec_narrative_failed", { error: err?.message });
    return { available: true, narrative: null, error: err?.message ?? "error" };
  }
}

/**
 * Genera la narrativa para un CONJUNTO de casos seleccionados.
 * @param {{ agg:object, sample:object[] }} ctx
 * @returns {Promise<{ available:boolean, narrative:object|null, error?:string }>}
 */
export async function buildCasesNarrative(ctx, deps = {}) {
  const logger = deps.logger ?? console;
  if (!narrativeAnalystAvailable()) return { available: false, narrative: null };
  try {
    const raw = await callLlm(buildSelectedCasesMessages(ctx));
    const narrative = parseNarrative(raw);
    if (!narrative) {
      logger.warn?.("cases_narrative_unparsed", { rawLen: raw?.length ?? 0 });
      return { available: true, narrative: null, error: "unparsed" };
    }
    return { available: true, narrative };
  } catch (err) {
    logger.error?.("cases_narrative_failed", { error: err?.message });
    return { available: true, narrative: null, error: err?.message ?? "error" };
  }
}

/**
 * Renderiza la narrativa a Markdown (sección del informe). null → "".
 * No menciona el motor de IA concreto. Parametrizable para reuso en distintos
 * informes (encabezado + nota de alcance).
 * @param {object|null} narrative
 * @param {{ heading?: string, scopeNote?: string }} [opts]
 */
export function renderNarrativeMarkdown(narrative, opts = {}) {
  if (!narrative) return "";
  const heading = opts.heading ?? "## 10. Lectura del Analista";
  const scopeNote = opts.scopeNote
    ?? "Análisis asistido por IA sobre los **cierres con valor analítico** del período — excluye los auto-cerrados LOW/NEGLIGIBLE. Las cifras provienen de los datos operacionales; la IA sólo las interpreta.";
  const L = [];
  L.push(heading);
  L.push("");
  L.push(`> ${scopeNote}`);
  L.push("");
  if (narrative.executive_summary) {
    L.push(narrative.executive_summary);
    L.push("");
  }
  if (narrative.key_trends?.length) {
    L.push(`### Contexto y patrones observados`);
    L.push("");
    for (const t of narrative.key_trends) L.push(`- ${t}`);
    L.push("");
  }
  if (narrative.business_impact) {
    L.push(`### Impacto en el negocio`);
    L.push("");
    L.push(narrative.business_impact);
    L.push("");
  }
  if (narrative.residual_risks?.length) {
    L.push(`### Riesgo residual / puntos ciegos`);
    L.push("");
    for (const r of narrative.residual_risks) L.push(`- ${r}`);
    L.push("");
  }
  if (narrative.recommendations?.length) {
    L.push(`### Recomendaciones del analista`);
    L.push("");
    L.push(`| Prioridad | Acción | Justificación |`);
    L.push(`|---|---|---|`);
    for (const r of narrative.recommendations) {
      L.push(`| **${r.priority}** | ${r.action} | ${r.rationale || "—"} |`);
    }
    L.push("");
  }
  return L.join("\n");
}
