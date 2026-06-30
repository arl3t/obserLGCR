/**
 * casePlaybookDoc.mjs — "documento" playbook (markdown + HTML) para adjuntar a un
 * ticket / publicar en la base de conocimiento.
 *
 * Dos capas, igual criterio que executiveNarrativeAnalyst / threatFindingAnalyst:
 *   1. RULE-BASED (siempre): generatePlaybook() de casePlaybookService produce el
 *      esqueleto determinístico (título, SLA, fase NIST, pasos, evidencia). Es el
 *      fallback y, además, el ANDAMIAJE que se le pasa al LLM para que no invente.
 *   2. LLM (opcional): si el analista LLM está disponible (mismo gate que soc-chat),
 *      redacta un playbook en prosa/markdown a partir del contexto del caso + el
 *      esqueleto. Si el LLM no responde, se degrada al markdown rule-based.
 *
 * El HTML se renderiza escape-first (markdownToSafeHtml) → lo que se adjunta al
 * ticket y se publica en kb_articles nunca ejecuta scripts.
 */
import { config } from "../config.mjs";
import { markdownToSafeHtml } from "./markdownSafe.mjs";
import { generatePlaybook } from "./casePlaybookService.mjs";

const bool = (v, d) => (v == null || v === "" ? d : String(v).trim().toLowerCase() === "true");
const NO_THINK = bool(process.env.PLAYBOOK_LLM_NO_THINK, true);
const TIMEOUT_MS = Number(process.env.PLAYBOOK_LLM_TIMEOUT_MS) || 90_000;

/** ¿Está disponible el analista LLM para playbooks? (mismo gate que soc-chat). */
export function playbookLlmAvailable() {
  return (
    config.socChatLlmEnabled &&
    Boolean(config.socChatLlmApiKey) &&
    (process.env.PLAYBOOK_LLM_ENABLED ?? "true").trim().toLowerCase() === "true"
  );
}

// Endpoint nativo Ollama derivado del OpenAI-compat (…/v1/chat/completions →
// …/api/chat). Solo con noThink=true; si el URL no es Ollama no matchea y cae a OpenAI.
const OLLAMA_NATIVE_URL = NO_THINK
  ? config.socChatLlmApiUrl.replace(/\/v1\/chat\/completions\/?$/, "/api/chat")
  : null;

async function callLlm(messages) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    if (OLLAMA_NATIVE_URL && OLLAMA_NATIVE_URL !== config.socChatLlmApiUrl) {
      const r = await fetch(OLLAMA_NATIVE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.socChatLlmApiKey}` },
        body: JSON.stringify({ model: config.socChatLlmModel, messages, stream: false, think: false, options: { temperature: 0.2 } }),
        signal: controller.signal,
      });
      if (!r.ok) return null;
      const json = await r.json();
      return json?.message?.content ?? null;
    }
    const r = await fetch(config.socChatLlmApiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.socChatLlmApiKey}` },
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

// ── Clave de matching: define cuándo dos casos comparten playbook reutilizable ──
function sevBucket(caseData) {
  return String(caseData.severity_text ?? caseData.severity ?? "MEDIUM").toUpperCase();
}
export function contextKeyFor(caseData = {}) {
  const tactic = caseData.mitre_tactic_id ?? "NA";
  const source = caseData.source_log ?? "NA";
  return `${tactic}|${source}|${sevBucket(caseData)}`;
}

// ── Título genérico (modelo SOCFortress: IRP por CLASE de incidente, no por caso) ──
// Ref: github.com/socfortress/Playbooks → IRP-Phishing, IRP-Malware, IRP-Ransom…
// El título describe la CLASE (táctica MITRE + severidad), nunca un caso concreto:
// es reutilizable (mismo context_key) y se publica así en la base de conocimiento.
// stripCaseSpecifics() es una red de seguridad por si la clase trae datos sueltos.
function stripCaseSpecifics(s) {
  return String(s ?? "")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "")               // IPv4
    .replace(/\b(?:[0-9a-f]{32,64})\b/gi, "")                   // hashes md5/sha
    .replace(/\b(?:CASE|CASO|INC|TKT|HUNT)[-_]?\d+\b/gi, "")    // nº de caso/ticket
    .replace(/\s{2,}/g, " ").trim();
}
function genericTitle(pb, sev) {
  const cls = stripCaseSpecifics(pb.title) || "Investigación de Amenaza";
  return `Playbook IRP — ${cls} [${sev}]`;
}

// ── Fases NIST SP 800-61 r2 genéricas (modelo SOCFortress) ─────────────────────
// Andamiaje reutilizable por clase de incidente. Los pasos de investigación
// específicos (pb.steps) entran en la fase 2; el resto son buenas prácticas.
const PREP_STEPS = [
  "Confirmar accesos a las herramientas necesarias (SIEM, EDR, firewall, threat intel) y al inventario de activos del cliente.",
  "Validar la línea base de comportamiento normal para distinguir actividad legítima de la sospechosa.",
  "Tener a mano el canal de comunicación con el cliente y el criterio de escalamiento a L2.",
];
const RECOVERY_STEPS = [
  "Aislar/contener el activo o la cuenta afectada según las acciones pre-autorizadas con el cliente.",
  "Erradicar el vector (bloqueo perimetral, reset de credenciales, remoción de persistencia o malware) y cerrar el punto de entrada.",
  "Restaurar el servicio a operación normal y validar que la amenaza ya no está presente antes de dar por cerrada la contención.",
];
const POST_STEPS = [
  "Registrar lecciones aprendidas y actualizar este playbook si el procedimiento cambió.",
  "Proponer nuevas reglas de detección / hardening derivadas del incidente.",
  "Revisar gestión de parches y exposición para reducir la probabilidad de recurrencia.",
];

// ── Markdown determinístico (fallback + andamiaje para el LLM) ─────────────────
// Estructura NIST SP 800-61 r2 de 4 fases, alineada al modelo SOCFortress.
function ruleMarkdown(pb, sev) {
  const L = [];
  L.push(`# ${genericTitle(pb, sev)}`);
  L.push("");
  L.push(`_Playbook genérico de respuesta a incidentes (NIST SP 800-61 r2). Plantilla reutilizable para incidentes de esta clase; el análisis específico del caso va en el informe adjunto._`);
  L.push("");
  L.push(`**Clase de incidente:** ${pb.title}  ·  **SLA objetivo:** ${pb.sla_label}  ·  **Fuente típica:** ${pb.detection_source}`);
  if (pb.mitre_tactic_id) L.push(`**MITRE ATT&CK:** ${pb.mitre_tactic_id} — ${pb.mitre_tactic}`);
  if (pb.escalate_now) L.push(`\n> ⚠️ **Escalar a L2 de inmediato** — clase de severidad/táctica crítica.`);
  L.push("");
  L.push("## 1. Preparación");
  PREP_STEPS.forEach((s) => L.push(`- ${s}`));
  L.push("");
  L.push("## 2. Detección y análisis");
  pb.steps.forEach((s, i) => L.push(`${i + 1}. ${s}`));
  L.push("");
  L.push("## 3. Contención, erradicación y recuperación");
  RECOVERY_STEPS.forEach((s) => L.push(`- ${s}`));
  L.push("");
  L.push("## 4. Actividad post-incidente");
  POST_STEPS.forEach((s) => L.push(`- ${s}`));
  L.push("");
  L.push("## Evidencia a recolectar");
  pb.evidence_required.forEach((e) => L.push(`- ${e}`));
  L.push("");
  L.push("## Criterio de cierre");
  L.push("- La amenaza está contenida/erradicada, el servicio restaurado y la evidencia documentada; o se descarta como falso positivo con justificación.");
  return L.join("\n");
}

// ── Prompt para el analista LLM ────────────────────────────────────────────────
// Pide una PLANTILLA GENÉRICA por clase de incidente (modelo SOCFortress), NO un
// documento atado a un caso: nada de IPs, hashes, nº de caso ni cifras puntuales.
function buildMessages(pb, sev) {
  const ctx = [
    `Clase de incidente: ${pb.title}`,
    `Severidad (bucket): ${sev}  ·  SLA objetivo: ${pb.sla_label}`,
    `Fuente de detección típica: ${pb.detection_source}`,
    pb.mitre_tactic_id ? `MITRE ATT&CK: ${pb.mitre_tactic_id} — ${pb.mitre_tactic}` : null,
    pb.escalate_now ? `Esta clase requiere escalamiento inmediato a L2.` : null,
  ].filter(Boolean).join("\n");

  const scaffold = [
    `Pasos de investigación sugeridos (esqueleto determinístico; NO inventes pasos fuera de este alcance):`,
    ...pb.steps.map((s, i) => `${i + 1}. ${s}`),
    ``,
    `Evidencia sugerida:`,
    ...pb.evidence_required.map((e) => `- ${e}`),
  ].join("\n");

  const system = [
    "Sos un analista SOC senior. Redactás un PLAYBOOK GENÉRICO de respuesta a incidentes, claro y accionable, en español, en formato MARKDOWN.",
    "Modelo de referencia: los playbooks IRP de SOCFortress (github.com/socfortress/Playbooks), estructurados según NIST SP 800-61 r2.",
    "Reglas estrictas:",
    "- Es una PLANTILLA REUTILIZABLE por CLASE de incidente, NO el informe de un caso. PROHIBIDO incluir IPs, hostnames, hashes, números de caso/ticket, CVEs concretos ni cifras puntuales: redactá en términos generales (\"la IP de origen\", \"el host afectado\", \"el indicador\").",
    "- Respetá el SLA y la táctica MITRE indicados. NO inventes herramientas ni datos fuera del contexto provisto.",
    "- Estructura OBLIGATORIA con estas 4 fases NIST como encabezados de nivel 2: '## 1. Preparación', '## 2. Detección y análisis', '## 3. Contención, erradicación y recuperación', '## 4. Actividad post-incidente'. Cerrá con '## Evidencia a recolectar' y '## Criterio de cierre'.",
    `- El título (encabezado nivel 1) debe ser EXACTAMENTE: '# ${genericTitle(pb, sev)}'.`,
    "- Conciso y operativo. Sin preámbulos ni disclaimers. Devolvé SOLO el markdown del playbook.",
  ].join("\n");

  const user = [
    "## Contexto de la clase de incidente", ctx, "",
    "## Andamiaje", scaffold, "",
    `Generá el playbook genérico completo en markdown siguiendo las 4 fases NIST.`,
  ].join("\n");

  return [{ role: "system", content: system }, { role: "user", content: user }];
}

function cleanMarkdown(raw) {
  if (!raw || typeof raw !== "string") return null;
  const s = raw.trim().replace(/^```(?:markdown|md)?\s*/i, "").replace(/```$/, "").trim();
  return s.length > 40 ? s : null;
}

/**
 * Genera el documento playbook para un caso.
 * @returns {{ title, bodyMd, bodyHtml, source:'llm'|'rule', model:string|null,
 *             contextKey:string, meta:object }}
 */
export async function generateCasePlaybookDoc(caseData = {}, enrichmentData = {}) {
  const pb = generatePlaybook(caseData, enrichmentData);
  const sev = sevBucket(caseData);
  const contextKey = contextKeyFor(caseData);
  const title = genericTitle(pb, sev);
  const meta = {
    mitre_tactic_id: pb.mitre_tactic_id ?? null,
    source_log: caseData.source_log ?? null,
    severity_text: sev,
    severity_score: Number(caseData.severity_score ?? caseData.score ?? 0) || 0,
  };

  let bodyMd = null;
  let source = "rule";
  let model = null;
  if (playbookLlmAvailable()) {
    const raw = await callLlm(buildMessages(pb, sev));
    const md = cleanMarkdown(raw);
    if (md) { bodyMd = md; source = "llm"; model = config.socChatLlmModel; }
  }
  if (!bodyMd) bodyMd = ruleMarkdown(pb, sev);

  return {
    title,
    bodyMd,
    bodyHtml: markdownToSafeHtml(bodyMd),
    source,
    model,
    contextKey,
    meta,
  };
}
