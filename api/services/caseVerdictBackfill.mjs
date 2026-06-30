/**
 * caseVerdictBackfill.mjs
 * Pase ÚNICO (one-time): recorre los casos abiertos y escribe en su timeline un
 * VEREDICTO HONESTO del incidente, emitido por el analista LLM local (Ollama
 * qwen3.5, misma config que soc-chat / F2 de caza externa).
 *
 * Honesto = el LLM razona SOLO sobre la evidencia del caso; si parece falso
 * positivo o la evidencia es delgada, lo dice — no infla severidad. No inventa
 * IOCs ni consulta fuentes externas.
 *
 * Idempotente y REANUDABLE: antes de procesar un caso comprueba si ya tiene una
 * entrada de timeline `metadata.kind='llm_case_verdict'`; si existe, lo salta.
 * Secuencial a propósito: la GPU es única y la comparte el chat en vivo + el F2.
 *
 * Uso (one-shot, dentro del contenedor de la API):
 *   node services/caseVerdictBackfill.mjs
 *   STATUSES=EN_ANALISIS,ESCALADO LIMIT=948 node services/caseVerdictBackfill.mjs
 *   DRY_RUN=true node services/caseVerdictBackfill.mjs   (no escribe, solo loguea)
 */

import { config } from "../config.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { addTimelineEvent } from "./timelineService.mjs";

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const bool = (v, d) => (v == null || v === "" ? d : String(v).trim().toLowerCase() === "true");

const CFG = {
  statuses:  (process.env.STATUSES || "EN_ANALISIS,ESCALADO").split(",").map((s) => s.trim()).filter(Boolean),
  limit:     num(process.env.LIMIT, 100000),
  dryRun:    bool(process.env.DRY_RUN, false),
  noThink:   bool(process.env.CASE_VERDICT_NO_THINK, true),
  // qwen3.5:9b en la RTX 4060 genera ~2-7 tok/s bajo contención (comparte GPU con
  // chat en vivo + F2). Con `think:false` (API nativa) un veredicto sale en ~3s; el
  // timeout holgado cubre la contención de GPU con el chat en vivo + F2.
  timeoutMs: num(process.env.CASE_VERDICT_TIMEOUT_MS, 150_000),
  maxTokens: num(process.env.CASE_VERDICT_MAX_TOKENS, 700),  // acota la generación; holgado para el JSON completo
  sleepMs:   num(process.env.CASE_VERDICT_SLEEP_MS, 0),   // pausa entre casos (anti-contención)
};

const VERDICTS = new Set(["amenaza_real", "falso_positivo_probable", "inconcluso", "benigno"]);
const ACTIONS  = new Set(["investigar", "escalar", "contener", "monitorear", "cerrar_fp"]);
const VERDICT_LABEL = {
  amenaza_real:             "Amenaza real",
  falso_positivo_probable:  "Falso positivo probable",
  inconcluso:               "Inconcluso",
  benigno:                  "Benigno",
};

function sleep(ms) { return ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve(); }

// Columnas que `buildContext` necesita de incident_cases_pg. Exportadas para que
// el analista continuo (caseVerdictAnalyst.mjs) seleccione EXACTAMENTE el mismo
// set — así `runVerdictForCase` recibe filas idénticas venga del backfill o del
// scheduler. Sin prefijo de tabla: se usa tanto en `FROM incident_cases_pg` como
// en un CTE `FROM params c` con `SELECT c.*`.
export const CASE_VERDICT_COLS = `
  id, case_number, status, severity, score, ioc_value, ioc_type, source_log, sensor_key,
  mitre_tactic_name, mitre_technique_id, source_ip, src_country, destination_ip, destination_port,
  protocol, firewall_action, network_zone, hostname, occurrence_count, is_recurrence,
  incident_category, classification, recommended_action, escalated_to, escalation_reason,
  escalation_reason_auto, CAST(detected_at AS varchar) AS detected_at, CAST(last_seen AS varchar) AS last_seen`;

/** ¿Disponible el LLM? (misma config que soc-chat). */
function llmAvailable() {
  return Boolean(config.socChatLlmEnabled && config.socChatLlmApiKey);
}

// ── Contexto cuantificado del caso (nada que el modelo deba inventar) ─────────
function buildContext(c, iocs) {
  const fmt = (v) => (v == null || v === "" ? null : v);
  return {
    caso: c.case_number ? `INC-${String(c.case_number).padStart(6, "0")}` : c.id,
    estado: c.status,
    severidad: c.severity,
    score: c.score,
    categoria: fmt(c.incident_category),
    clasificacion: fmt(c.classification),
    ioc_primario: fmt(c.ioc_value),
    tipo_ioc: fmt(c.ioc_type),
    iocs_adicionales: (iocs || []).filter((x) => x && x !== c.ioc_value).slice(0, 8),
    fuente: fmt(c.source_log),
    sensor: fmt(c.sensor_key),
    mitre_tactica: fmt(c.mitre_tactic_name),
    mitre_tecnica: fmt(c.mitre_technique_id),
    origen_ip: fmt(c.source_ip),
    pais_origen: fmt(c.src_country),
    destino_ip: fmt(c.destination_ip),
    destino_puerto: fmt(c.destination_port),
    protocolo: fmt(c.protocol),
    accion_firewall: fmt(c.firewall_action),
    zona_red: fmt(c.network_zone),
    host: fmt(c.hostname),
    ocurrencias: c.occurrence_count,
    es_recurrencia: c.is_recurrence,
    detectado: fmt(c.detected_at),
    ultimo_visto: fmt(c.last_seen),
    escalado_a: fmt(c.escalated_to),
    razon_escalado: fmt(c.escalation_reason || c.escalation_reason_auto),
    accion_recomendada_actual: fmt(c.recommended_action),
    // Señales de enriquecimiento desde case_iocs (VT/Abuse/MISP) — intel ya resuelta.
    intel_ioc: (iocs_meta(c, iocs)),
  };
}

// Compacta señales de intel de los IOCs (sin volcar blobs).
function iocs_meta(c, _iocs) {
  const m = c._intel || {};
  const out = {};
  if (m.vt_malicious != null) out.vt_malicious = m.vt_malicious;
  if (m.abuse_score != null) out.abuse_score = m.abuse_score;
  if (m.in_misp != null) out.in_misp = m.in_misp;
  if (m.shodan_summary) out.shodan = String(m.shodan_summary).slice(0, 160);
  return Object.keys(out).length ? out : null;
}

function buildMessages(ctx) {
  const sys =
    "Sos un analista senior de un SOC de infraestructura crítica/OT en Paraguay. " +
    "Recibís un INCIDENTE ya abierto, con su evidencia cuantificada (severidad, score, " +
    "IOC, geo/país, MITRE, puertos, acción del firewall, recurrencia, intel VT/Abuse/MISP). " +
    "Tu trabajo es emitir un VEREDICTO HONESTO y retrospectivo: ¿es una amenaza real, un " +
    "falso positivo probable, algo inconcluso o benigno? Reglas de honestidad: razoná SOLO " +
    "con la evidencia dada; NO inventes IOCs, dominios ni CVEs; si la evidencia es delgada o " +
    "el caso huele a falso positivo (tráfico interno legítimo, escaneo del propio FW, baja " +
    "amplitud, sin intel negativa), DECILO claramente y NO infles la severidad; si hay intel " +
    "negativa dura, geo de alto riesgo, C2/beaconing o brute-force, sostené la gravedad. " +
    "Respondé ÚNICAMENTE con un objeto JSON válido, sin markdown ni texto extra, con las claves: " +
    '{"verdict":"amenaza_real|falso_positivo_probable|inconcluso|benigno","confidence":0-100,' +
    '"assessment":"2-3 frases CONCISAS en español, técnicas y honestas, citando los números de la evidencia",' +
    '"recommended_action":"investigar|escalar|contener|monitorear|cerrar_fp",' +
    '"key_evidence":["clave1","clave2"]}';
  // Nota: el modo sin-razonamiento se controla con `think:false` en la API nativa
  // (ver callLlm); el sufijo `/no_think` por prompt NO lo respeta qwen3.5 → se omite.
  return [
    { role: "system", content: sys },
    { role: "user", content: "INCIDENTE:\n" + JSON.stringify(ctx, null, 2) },
  ];
}

function stripThink(text) {
  return String(text)
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/```json\s*/gi, "")
    .replace(/```/g, "")
    .trim();
}

function parseVerdict(text) {
  if (!text) return null;
  const s = stripThink(text);
  const a = s.indexOf("{"), b = s.lastIndexOf("}");
  if (a === -1 || b === -1 || b <= a) return null;
  let obj;
  try { obj = JSON.parse(s.slice(a, b + 1)); } catch { return null; }
  const verdict = String(obj.verdict ?? "").toLowerCase().trim();
  if (!VERDICTS.has(verdict)) return null;
  let confidence = Math.round(Number(obj.confidence));
  if (!Number.isFinite(confidence)) confidence = 50;
  confidence = Math.min(100, Math.max(0, confidence));
  const action = String(obj.recommended_action ?? "").toLowerCase().trim();
  return {
    verdict,
    confidence,
    assessment: String(obj.assessment ?? "").trim().slice(0, 2000),
    recommended_action: ACTIONS.has(action) ? action : "investigar",
    key_evidence: Array.isArray(obj.key_evidence) ? obj.key_evidence.map((x) => String(x)).slice(0, 12) : [],
  };
}

// Endpoint nativo de Ollama derivado de la URL OpenAI-compat de soc-chat.
// `/v1/chat/completions` → `/api/chat`. La nativa permite `think:false`, que SÍ
// desactiva el razonamiento de qwen3.5 (el sufijo `/no_think` por prompt no lo hace):
// el modelo entonces deja `message.content` con el JSON limpio (sin <think>) en ~3s,
// en vez de gastar todo el presupuesto de tokens razonando y devolver content vacío.
function nativeChatUrl() {
  const u = String(config.socChatLlmApiUrl || "");
  return u.replace(/\/v1\/chat\/completions\/?$/, "/api/chat");
}

async function callLlm(messages) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CFG.timeoutMs);
  try {
    const r = await fetch(nativeChatUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.socChatLlmApiKey}` },
      body: JSON.stringify({
        model: config.socChatLlmModel,
        messages,
        think: !CFG.noThink,          // default noThink=true → think:false (sin razonamiento)
        stream: false,
        options: { temperature: 0.1, num_predict: CFG.maxTokens },
      }),
      signal: controller.signal,
    });
    if (!r.ok) return null;
    const json = await r.json();
    return json?.message?.content ?? null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** ¿El caso ya tiene un veredicto LLM en su timeline? (idempotencia/reanudación) */
async function alreadyHasVerdict(caseId) {
  const [row] = await pgQuery(
    `SELECT 1 FROM case_timeline_events
      WHERE case_id = $1 AND metadata->>'kind' = 'llm_case_verdict' LIMIT 1`,
    [caseId],
  );
  return Boolean(row);
}

/**
 * Emite (o simula) el veredicto honesto del analista LLM para UN caso ya cargado.
 * Reutilizado por el pase one-shot (runCaseVerdictBackfill) y por el analista
 * continuo gobernado por SLA (caseVerdictAnalyst.runCaseVerdictAnalyst). La fila
 * `c` debe traer las columnas de CASE_VERDICT_COLS.
 *
 * Idempotente: si el caso ya tiene un veredicto LLM en su timeline, retorna
 * `skipped` sin llamar al modelo. El evento se escribe como NOTE/ENRICHMENT con
 * operador `analista-llm` → NO afecta MTTC (no cierra ni es CONTAINMENT) ni cuenta
 * como actividad MANUAL del operador.
 *
 * @param {object} c  fila de incident_cases_pg (columnas de CASE_VERDICT_COLS)
 * @param {{ dryRun?: boolean, passTag?: string, logger?: any }} [opts]
 * @returns {Promise<{ outcome: "written"|"skipped"|"failed", caso?: string, verdict?: object, dry?: boolean }>}
 */
export async function runVerdictForCase(c, opts = {}) {
  const { dryRun = CFG.dryRun, passTag = "one-time-2026-06-25", logger = console } = opts;

  if (await alreadyHasVerdict(c.id)) return { outcome: "skipped" };

  // Trae IOCs adicionales + señales de intel del IOC primario.
  const iocRows = await pgQuery(
    `SELECT ioc_value, vt_malicious, abuse_score, in_misp, shodan_summary, is_primary
       FROM case_iocs WHERE case_id = $1 ORDER BY is_primary DESC LIMIT 12`,
    [c.id],
  ).catch(() => []);
  const primary = iocRows.find((x) => x.is_primary) || iocRows[0] || {};
  c._intel = {
    vt_malicious: primary.vt_malicious, abuse_score: primary.abuse_score,
    in_misp: primary.in_misp, shodan_summary: primary.shodan_summary,
  };
  const ctx = buildContext(c, iocRows.map((x) => x.ioc_value));

  const rawLlm = await callLlm(buildMessages(ctx));
  const v = parseVerdict(rawLlm);
  if (!v) {
    if (bool(process.env.CASE_VERDICT_DEBUG, false)) {
      logger.warn?.(`[case-verdict][DEBUG] ${ctx.caso} raw=${rawLlm == null ? "NULL(timeout/http)" : JSON.stringify(String(rawLlm).slice(0, 500))}`);
    }
    return { outcome: "failed", caso: ctx.caso };
  }

  const label = VERDICT_LABEL[v.verdict] ?? v.verdict;
  if (dryRun) {
    logger.info?.(`[case-verdict][DRY] ${ctx.caso} → ${label} (${v.confidence}%) · ${v.recommended_action}`);
    return { outcome: "written", caso: ctx.caso, verdict: v, dry: true };
  }

  await addTimelineEvent(c.id, {
    eventType: "NOTE",
    title: `Veredicto honesto del analista LLM: ${label} (confianza ${v.confidence}%)`,
    description:
      (v.assessment || "Veredicto del analista LLM sobre el incidente.") +
      `\nAcción recomendada: ${v.recommended_action}.`,
    operatorCi: "analista-llm",
    source: "ENRICHMENT",
    metadata: {
      kind: "llm_case_verdict",
      verdict: v.verdict,
      confidence: v.confidence,
      recommended_action: v.recommended_action,
      key_evidence: v.key_evidence,
      model: config.socChatLlmModel,
      pass: passTag,
    },
  });
  return { outcome: "written", caso: ctx.caso, verdict: v };
}

/**
 * Corre el pase único de veredictos sobre los casos abiertos de los estados dados.
 * @param {{ logger?: any }} [deps]
 */
export async function runCaseVerdictBackfill(deps = {}) {
  const logger = deps.logger ?? console;
  const t0 = Date.now();
  if (!llmAvailable()) {
    logger.warn?.("[case-verdict] LLM no disponible (config soc-chat) — abort");
    return { ok: false, error: "llm_unavailable" };
  }
  const placeholders = CFG.statuses.map((_, i) => `$${i + 1}`).join(",");
  const cases = await pgQuery(
    `SELECT ${CASE_VERDICT_COLS}
       FROM incident_cases_pg
      WHERE status IN (${placeholders})
      ORDER BY score DESC NULLS LAST, updated_at DESC
      LIMIT ${CFG.limit}`,
    CFG.statuses,
  );
  logger.info?.(`[case-verdict] casos candidatos: ${cases.length} (estados=${CFG.statuses.join(",")}, dryRun=${CFG.dryRun})`);

  let processed = 0, written = 0, skipped = 0, failed = 0;
  for (const c of cases) {
    processed++;
    try {
      const r = await runVerdictForCase(c, { dryRun: CFG.dryRun, passTag: "one-time-2026-06-25", logger });
      if (r.outcome === "skipped") { skipped++; continue; }
      if (r.outcome === "failed") {
        failed++;
        logger.warn?.(`[case-verdict] ${r.caso}: sin veredicto válido (reintentable)`);
        continue;
      }
      written++;
      if (written % 10 === 0) {
        const mins = ((Date.now() - t0) / 60000).toFixed(1);
        logger.info?.(`[case-verdict] progreso: ${written} escritos / ${processed} vistos / ${skipped} ya tenían / ${failed} fallidos — ${mins} min`);
      }
      await sleep(CFG.sleepMs);
    } catch (e) {
      failed++;
      logger.warn?.(`[case-verdict] error en caso ${c.case_number ?? c.id}: ${e.message}`);
    }
  }

  const summary = { ok: true, candidates: cases.length, processed, written, skipped, failed, mins: ((Date.now() - t0) / 60000).toFixed(1) };
  logger.info?.(`[case-verdict] DONE ${JSON.stringify(summary)}`);
  return summary;
}

// ── Runner one-shot ──────────────────────────────────────────────────────────
// Ejecutado directamente (no importado): corre el pase y termina el proceso.
if (import.meta.url === `file://${process.argv[1]}`) {
  runCaseVerdictBackfill({ logger: console })
    .then((s) => { console.log("[case-verdict] resultado:", s); process.exit(s.ok ? 0 : 1); })
    .catch((e) => { console.error("[case-verdict] fatal:", e); process.exit(1); });
}
