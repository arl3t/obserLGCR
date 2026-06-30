/**
 * threatFindingAnalyst.mjs
 * Centro de Inteligencia de Caza de Amenazas Externas — F2 (analista LLM).
 *
 * Lee findings NEW de `hunt_findings` (materializados por threatPatternScan, F1a),
 * los pasa por el LLM local (qwen3.5 vía Ollama, OpenAI-compatible — misma config
 * que soc-chat) para producir un veredicto RAZONADO + acción recomendada, y
 * persiste los campos `llm_*` + status NEW → ANALYZED. El Panel del Manager (F3)
 * consume el veredicto.
 *
 * Determinístico-primero: el finding ya trae TODA la evidencia cuantificada
 * (geo/ASN, allowed_ratio, cadencia CV, volumen, puerto). El LLM SOLO razona
 * sobre esa evidencia provista — no inventa IOCs ni consulta fuentes externas.
 * Si el LLM no está disponible o la respuesta no parsea, el finding queda NEW
 * (se reintenta en el próximo tick). Ver docs/CENTRO-INTELIGENCIA-CAZA-EXTERNA-F1.md
 */

import { config } from "../config.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { addTimelineEvent } from "./timelineService.mjs";

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const bool = (v, d) => (v == null || v === "" ? d : String(v).trim().toLowerCase() === "true");
const CFG = {
  batch:     num(process.env.HUNT_ANALYST_BATCH, 5),     // findings por corrida
  // #1 (no_think): qwen3.5 razona ~85-90s en modo thinking. El veredicto aquí es
  // estructurado sobre evidencia ya cuantificada — el razonamiento extendido aporta
  // poco. GOTCHA verificado 2026-06-25: ni el token textual `/no_think` ni
  // `enable_thinking/think:false` por el endpoint OpenAI-compat suprimen el CoT de
  // qwen3.5 (sigue generando 2k+ tokens → supera el timeout de 45s → TODOS los
  // findings fallaban, 0 progreso). Solo el parámetro NATIVO `think:false` del
  // endpoint /api/chat de Ollama lo desactiva (≈3-4s, ~100 tokens, JSON directo).
  // Por eso con noThink=true callLlm conmuta al endpoint nativo (ver callLlm).
  // HUNT_ANALYST_NO_THINK=false vuelve al modo razonado por el endpoint OpenAI.
  noThink:   bool(process.env.HUNT_ANALYST_NO_THINK, true),
  // Timeout: 45s alcanza de sobra con no_think; 150s es el techo histórico del modo
  // thinking. Se elige según el flag salvo override explícito por env.
  timeoutMs: num(process.env.HUNT_ANALYST_TIMEOUT_MS, bool(process.env.HUNT_ANALYST_NO_THINK, true) ? 45_000 : 150_000),
  // #4 (feedback loop): nº de decisiones humanas previas sobre hallazgos similares
  // que se inyectan en el prompt para calibrar el veredicto al criterio real del SOC.
  feedbackK: num(process.env.HUNT_ANALYST_FEEDBACK_K, 5),
};

const VERDICTS = new Set(["benign", "suspicious", "malicious", "inconclusive"]);
const ACTIONS  = new Set(["open_case", "create_rule", "suppress_class", "monitor", "fp"]);

/** ¿Está disponible el analista? (LLM soc-chat activo + gate propio). */
export function findingAnalystAvailable() {
  return (
    config.socChatLlmEnabled &&
    Boolean(config.socChatLlmApiKey) &&
    (process.env.HUNT_ANALYST_ENABLED ?? "true").trim().toLowerCase() === "true"
  );
}

// Etiqueta legible de la disposición humana, para el bloque de feedback.
const DISPO_MEANING = {
  confirmed:  "amenaza real (se abrió caso)",
  dismissed:  "falso positivo / egress autorizado",
  suppressed: "ruido recurrente (suprimido)",
  monitoring: "en vigilancia (no concluyente)",
};

// ── Prompt: el LLM razona SOBRE la evidencia provista y devuelve JSON estricto ──
// `feedback` (#4): líneas con decisiones humanas previas sobre hallazgos similares.
function buildMessages(f, feedback = []) {
  const ev = f.evidence ?? {};
  // Contexto compacto y cuantificado — nada que el modelo deba inventar.
  const ctx = {
    titulo: f.title,
    patron: f.pattern_key,
    severidad_motor: f.severity,
    host_interno: f.internal_asset,
    destino_externo: f.external_entity,
    puerto: ev.dst_port ?? null,
    pais_destino: ev.country ?? null,
    asn_org: ev.asn_org ?? null,
    es_foraneo: ev.is_foreign ?? null,
    es_nube_riesgo: ev.is_cloud ?? null,
    permitido_por_firewall: ev.is_allowed ?? null,
    ratio_permitido: ev.allowed_ratio ?? null,   // 1.0 = todo aceptado por el FW
    eventos_total: ev.event_count ?? f.event_count,
    horas_activas: ev.active_hours ?? null,
    cadencia_cv: ev.cadence_cv ?? null,          // <0.45 = beaconing plano (máquina)
    log_family: ev.log_family ?? null,
    // P3 (F1b): intel negativa confirmada sobre el destino (feeds keyless). Si
    // viene poblada es señal DURA — un canal permitido a una IP de malware/blocklist.
    intel_negativa: ev.intel_malicious ?? false,
    intel_razones: ev.intel_reasons ?? [],
    // P4 (F1b): brute-force de login. Si attack_kind viene poblado, el HALLAZGO es
    // una IP atacante con N fallos de autenticación (no un egress) — el IOC es la
    // IP de ORIGEN (external_entity), no un destino.
    brute_force: ev.attack_kind ?? null,        // "SSL-VPN" | "login" | null
    fallos_login: ev.fails ?? null,
    usuarios_distintos: ev.distinct_users ?? null,
    usuarios_muestra: ev.sample_users ?? null,
    razones_fallo: ev.reasons ?? null,
    dispositivo_atacado: ev.device ?? null,
    es_password_spray: ev.is_password_spray ?? null,
  };
  // #4 (feedback loop): bloque opcional con el criterio histórico del SOC sobre
  // hallazgos parecidos. Calibra al modelo al juicio humano real, sin reentrenar.
  const fbBlock = feedback.length
    ? "\n\nDECISIONES HUMANAS PREVIAS sobre hallazgos similares (criterio del SOC — tenelas en " +
      "cuenta, NO las copies a ciegas; si esta evidencia difiere, primá la evidencia):\n" +
      feedback.map((l) => `- ${l}`).join("\n")
    : "";

  const sys =
    "Sos un analista senior de caza de amenazas externas en un SOC de infraestructura " +
    "crítica/OT en Paraguay. Recibís un HALLAZGO ya cuantificado por el motor de patrones " +
    "(geo/ASN por MaxMind, cadencia, volumen, si el firewall lo PERMITIÓ). Tu trabajo es " +
    "emitir un veredicto razonado SOLO con la evidencia dada — NO inventes IOCs, dominios, " +
    "CVEs ni datos que no estén en el contexto. Principios: 'lo permitido es el peligro' (un " +
    "canal de salida ACEPTADO a nube/país extranjero es más grave, no menos); cadencia plana " +
    "(cv bajo) 24x7 = señal de máquina/C2; egress OT a nube extranjera = exfil potencial / " +
    "acceso remoto ICS, dual-use (el Manager valida si está autorizado). " +
    "Si el hallazgo es un BRUTE-FORCE de login (brute_force poblado): el IOC es la IP de " +
    "ORIGEN; muchos fallos o muchos usuarios distintos (password spray) desde una IP foránea = " +
    "intento de acceso inicial (T1110) — eleva; pocos fallos de un usuario conocido desde IP " +
    "local puede ser un usuario despistado (benigno/inconclusive). " +
    "Respondé ÚNICAMENTE con un objeto JSON válido, sin markdown ni texto extra, con las claves: " +
    '{"verdict":"benign|suspicious|malicious|inconclusive","confidence":0-100,' +
    '"narrative":"2-4 frases en español, técnicas, citando los números de la evidencia",' +
    '"recommended_action":"open_case|create_rule|suppress_class|monitor|fp",' +
    '"evidence_cited":["clave1","clave2"]}';

  // #1 (no_think): la directiva /no_think de Qwen3 desactiva el razonamiento extendido
  // para este turno → responde el JSON directo. Se ubica al final del mensaje de usuario.
  const noThink = CFG.noThink ? "\n\n/no_think" : "";

  return [
    { role: "system", content: sys },
    { role: "user", content: "HALLAZGO:\n" + JSON.stringify(ctx, null, 2) + fbBlock + noThink },
  ];
}

/**
 * #4 (feedback loop): junta hasta K decisiones humanas previas sobre hallazgos
 * SIMILARES al actual (mismo destino externo › mismo ASN › mismo patrón), para
 * inyectarlas en el prompt. Best-effort: ante error devuelve [] (no rompe el análisis).
 * Prioriza la coincidencia más específica (mismo IOC) y las decisiones más recientes.
 */
async function gatherFeedback(f) {
  if (CFG.feedbackK <= 0) return [];
  const ioc = String(f.external_entity ?? "").trim() || null;
  const asn = String(f?.evidence?.asn_org ?? "").trim() || null;
  try {
    const rows = await pgQuery(
      `SELECT pattern_key, external_entity, operator_disposition,
              evidence->>'country' AS country, evidence->>'asn_org' AS asn_org,
              CASE
                WHEN external_entity = $2 THEN 0
                WHEN evidence->>'asn_org' = $3 AND $3 IS NOT NULL THEN 1
                ELSE 2
              END AS proximity
         FROM hunt_findings
        WHERE operator_disposition IS NOT NULL
          AND finding_id <> $1
          AND (external_entity = $2
               OR (evidence->>'asn_org' = $3 AND $3 IS NOT NULL)
               OR pattern_key = $4)
        ORDER BY proximity ASC, updated_at DESC
        LIMIT $5`,
      [f.finding_id ?? "", ioc, asn, f.pattern_key, CFG.feedbackK],
    );
    return rows.map((r) => {
      const meaning = DISPO_MEANING[r.operator_disposition] ?? r.operator_disposition;
      const where = [r.external_entity, [r.country, r.asn_org].filter(Boolean).join("/")].filter(Boolean).join(" ");
      return `patrón ${r.pattern_key} · ${where} → el SOC lo marcó como ${meaning}`;
    });
  } catch {
    return [];
  }
}

// Extrae el primer objeto JSON de la respuesta (qwen a veces antepone razonamiento
// o envuelve en ```json). Robusto a fences y texto circundante.
function parseVerdict(text) {
  if (!text) return null;
  // Qwen3 emite <think>…</think> antes del JSON; con /no_think suele venir vacío,
  // pero se elimina igual para no confundir el localizador de llaves.
  let s = String(text)
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/```json\s*/gi, "")
    .replace(/```/g, "")
    .trim();
  const a = s.indexOf("{");
  const b = s.lastIndexOf("}");
  if (a === -1 || b === -1 || b <= a) return null;
  let obj;
  try { obj = JSON.parse(s.slice(a, b + 1)); } catch { return null; }

  const verdict = String(obj.verdict ?? "").toLowerCase().trim();
  const action  = String(obj.recommended_action ?? "").toLowerCase().trim();
  if (!VERDICTS.has(verdict)) return null;       // sin veredicto válido → reintenta
  let confidence = Math.round(Number(obj.confidence));
  if (!Number.isFinite(confidence)) confidence = 50;
  confidence = Math.min(100, Math.max(0, confidence));
  const narrative = String(obj.narrative ?? "").trim().slice(0, 2000);
  const cited = Array.isArray(obj.evidence_cited)
    ? obj.evidence_cited.map((x) => String(x)).slice(0, 12)
    : [];
  return {
    verdict,
    confidence,
    narrative,
    recommended_action: ACTIONS.has(action) ? action : "monitor",
    evidence_cited: cited,
  };
}

/**
 * Tras emitir un veredicto, busca un caso ABIERTO cuyo IOC coincida con el destino
 * externo del finding (ioc_value primario o cualquier IOC en case_iocs) y, si existe:
 *   1. linkea el finding al caso (sin pisar un link previo),
 *   2. escribe el veredicto del LLM en el TIMELINE del caso ("Caza de Amenazas LLM").
 * El operador ve así el veredicto de caza dentro de la investigación, sin salir de
 * Gestión. Idempotente: solo agrega entrada de timeline si NO existe ya una para
 * este (finding, veredicto) — un re-análisis que CAMBIA el veredicto sí deja traza
 * (evolución), uno que lo confirma no duplica. Best-effort: nunca rompe el análisis.
 */
async function linkVerdictToCase(finding, v, logger) {
  const ioc = String(finding.external_entity ?? "").trim();
  if (!ioc) return null;
  try {
    const [c] = await pgQuery(
      `SELECT ic.id, ic.case_number
         FROM incident_cases_pg ic
        WHERE (ic.ioc_value = $1
               OR EXISTS (SELECT 1 FROM case_iocs ci
                           WHERE ci.case_id = ic.id AND ci.ioc_value = $1))
          AND ic.status NOT IN ('CERRADO','FALSO_POSITIVO')
          AND ic.updated_at >= now() - INTERVAL '30 days'
        ORDER BY ic.updated_at DESC
        LIMIT 1`,
      [ioc],
    );
    if (!c) return null;
    // Linkea el finding al caso (no pisa un link manual ya existente).
    await pgQuery(
      `UPDATE hunt_findings
          SET linked_case_id = COALESCE(linked_case_id, $2), updated_at = now()
        WHERE finding_id = $1`,
      [finding.finding_id, c.id],
    );
    // Dedup del timeline por (finding, veredicto): no repetir el mismo veredicto.
    const [dup] = await pgQuery(
      `SELECT 1 FROM case_timeline_events
        WHERE case_id = $1
          AND metadata->>'finding_id' = $2
          AND metadata->>'verdict'    = $3
        LIMIT 1`,
      [c.id, finding.finding_id, v.verdict],
    );
    if (dup) return c.id;
    await addTimelineEvent(c.id, {
      eventType: "DETECTION",
      phase: "DETECTION",
      title: `Caza de Amenazas LLM: ${v.verdict} (confianza ${v.confidence}%)`,
      description:
        (v.narrative || "Veredicto del analista de caza externa.") +
        `\nAcción recomendada: ${v.recommended_action}. Patrón: ${finding.pattern_key}.`,
      operatorCi: "caza-externa",
      source: "ENRICHMENT",
      metadata: {
        finding_id: finding.finding_id,
        pattern_key: finding.pattern_key,
        verdict: v.verdict,
        confidence: v.confidence,
        recommended_action: v.recommended_action,
        external_entity: ioc,
      },
    });
    logger?.info?.({ finding: finding.finding_id, case: c.case_number ?? c.id, verdict: v.verdict },
      "[finding-analyst] veredicto enlazado al timeline del caso");
    return c.id;
  } catch (e) {
    logger?.warn?.({ err: e.message, finding: finding.finding_id }, "[finding-analyst] link-to-case failed");
    return null;
  }
}

// Endpoint nativo de Ollama derivado del OpenAI-compat configurado
// (…/v1/chat/completions → …/api/chat). Solo se usa con noThink=true; si el URL no
// es un endpoint OpenAI de Ollama, el replace no matchea y se cae al path OpenAI.
const OLLAMA_NATIVE_URL = CFG.noThink
  ? config.socChatLlmApiUrl.replace(/\/v1\/chat\/completions\/?$/, "/api/chat")
  : null;

async function callLlm(messages) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CFG.timeoutMs);
  try {
    // Vía NATIVA Ollama con think:false — única forma real de desactivar el CoT de
    // qwen3.5 (el /no_think textual y el think:false por OpenAI NO lo logran → CoT de
    // 2k+ tokens → timeout → 0 análisis). Respuesta nativa: { message: { content } }.
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
          options: { temperature: 0.1 },
        }),
        signal: controller.signal,
      });
      if (!r.ok) return null;
      const json = await r.json();
      return json?.message?.content ?? null;
    }
    // Fallback OpenAI-compatible (otros backends, o noThink=false → modo razonado).
    const r = await fetch(config.socChatLlmApiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.socChatLlmApiKey}`,
      },
      body: JSON.stringify({ model: config.socChatLlmModel, messages, temperature: 0.1 }),
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

async function persistVerdict(findingId, v) {
  // Sólo promueve si sigue NEW (no pisa una decisión humana ya tomada).
  await pgQuery(
    `UPDATE hunt_findings SET
       llm_verdict            = $2,
       llm_confidence         = $3,
       llm_narrative          = $4,
       llm_recommended_action = $5,
       llm_evidence_cited     = $6::jsonb,
       llm_analyzed_at        = now(),
       status                 = 'ANALYZED',
       updated_at             = now()
     WHERE finding_id = $1 AND status = 'NEW'`,
    [
      findingId, v.verdict, v.confidence, v.narrative,
      v.recommended_action, JSON.stringify(v.evidence_cited),
    ],
  );
}

/**
 * Analiza UN finding por id (botón "re-analizar" del Panel del Manager, F3).
 * Re-analiza cualquier finding salvo SUPPRESSED; promueve a ANALYZED.
 * @returns {Promise<{ ok:boolean, finding_id?:string, verdict?:string, error?:string }>}
 */
export async function analyzeFindingById(findingId, deps = {}) {
  const logger = deps.logger ?? console;
  if (!findingAnalystAvailable()) return { ok: false, error: "llm_unavailable" };
  const [f] = await pgQuery(
    `SELECT finding_id, pattern_key, severity, title, internal_asset,
            external_entity, evidence, event_count, status
       FROM hunt_findings WHERE finding_id = $1`,
    [findingId],
  );
  if (!f) return { ok: false, error: "not_found" };
  if (f.status === "SUPPRESSED") return { ok: false, error: "suppressed" };
  const feedback = await gatherFeedback(f);            // #4: criterio histórico del SOC
  const v = parseVerdict(await callLlm(buildMessages(f, feedback)));
  if (!v) return { ok: false, error: "llm_no_verdict" };
  // Single: actualiza sin el guard status='NEW' (permite re-análisis de ANALYZED).
  await pgQuery(
    `UPDATE hunt_findings SET
       llm_verdict=$2, llm_confidence=$3, llm_narrative=$4,
       llm_recommended_action=$5, llm_evidence_cited=$6::jsonb,
       llm_analyzed_at=now(), status='ANALYZED', updated_at=now()
     WHERE finding_id=$1 AND status <> 'SUPPRESSED'`,
    [findingId, v.verdict, v.confidence, v.narrative, v.recommended_action, JSON.stringify(v.evidence_cited)],
  );
  const linkedCaseId = await linkVerdictToCase(f, v, logger); // best-effort: caso + timeline
  logger.info?.({ id: findingId, verdict: v.verdict }, "[finding-analyst] single analyzed");
  return { ok: true, finding_id: findingId, verdict: v.verdict, confidence: v.confidence, linked_case_id: linkedCaseId };
}

/**
 * Analiza un lote de findings NEW con el LLM y persiste los veredictos.
 * @param {{ logger?: any, batch?: number }} [deps]
 * @returns {Promise<{ ok:boolean, analyzed:number, failed:number, skipped?:string, ms:number }>}
 */
export async function runFindingAnalysis(deps = {}) {
  const logger = deps.logger ?? console;
  const t0 = Date.now();
  if (!findingAnalystAvailable()) {
    return { ok: true, analyzed: 0, failed: 0, skipped: "llm_unavailable", ms: 0 };
  }
  const batch = num(deps.batch, CFG.batch);
  const rows = await pgQuery(
    `SELECT finding_id, pattern_key, severity, title, internal_asset,
            external_entity, evidence, event_count
       FROM hunt_findings
      WHERE status = 'NEW'
      ORDER BY (severity='HIGH') DESC, (severity='MEDIUM') DESC, event_count DESC
      LIMIT $1`,
    [batch],
  );

  let analyzed = 0, failed = 0;
  for (const f of rows) {
    const feedback = await gatherFeedback(f);        // #4: criterio histórico del SOC
    const v = parseVerdict(await callLlm(buildMessages(f, feedback)));
    if (!v) { failed++; continue; }            // queda NEW → reintenta próximo tick
    try {
      await persistVerdict(f.finding_id, v); analyzed++;
      await linkVerdictToCase(f, v, logger);   // best-effort: enlaza caso + timeline
    }
    catch (e) { failed++; logger.warn?.({ err: e.message, id: f.finding_id }, "[finding-analyst] persist failed"); }
  }

  const summary = { ok: true, analyzed, failed, ms: Date.now() - t0 };
  if (analyzed > 0 || failed > 0) logger.info?.(summary, "[finding-analyst] done");
  return summary;
}
