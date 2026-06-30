/**
 * ticketClassifier.mjs — clasificación automática de tickets por IA (#3, #7).
 *
 * Del asunto + cuerpo del cliente deduce: tipo, categoría/servicio, prioridad
 * sugerida, sentimiento y etiquetas. Es SUGERENCIA con gate humano — nunca se
 * aplica sola; se guarda en tickets.ai_suggested y el analista decide.
 *
 * Reusa el LLM ya integrado (qwen3.5 vía Ollama nativo /api/chat con think:false,
 * ver memoria ollama_llm_integration). Si el LLM está deshabilitado o falla,
 * devuelve una heurística por palabras clave (degradación elegante).
 */
import { config } from "../config.mjs";
import { logger } from "../logger.mjs";

const TIMEOUT_MS = Number(process.env.TICKET_AI_TIMEOUT_MS) || 45_000;

export function ticketClassifierAvailable() {
  return Boolean(config.socChatLlmEnabled && config.socChatLlmApiUrl && config.socChatLlmModel);
}

const TYPES = ["INCIDENTE", "CONSULTA", "CAMBIO", "REPORTE_FP", "ACEPTACION_RIESGO"];
const PRIORITIES = ["LOW", "MEDIUM", "HIGH", "URGENT"];
const SENTIMENTS = ["POSITIVO", "NEUTRAL", "FRUSTRADO", "ENOJADO"];

// Endpoint nativo de Ollama (…/v1/chat/completions → …/api/chat) para think:false.
const OLLAMA_NATIVE_URL = config.socChatLlmApiUrl
  ? config.socChatLlmApiUrl.replace(/\/v1\/chat\/completions\/?$/, "/api/chat")
  : null;

async function callLlm(messages) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const native = OLLAMA_NATIVE_URL && OLLAMA_NATIVE_URL !== config.socChatLlmApiUrl;
    const url = native ? OLLAMA_NATIVE_URL : config.socChatLlmApiUrl;
    const body = native
      ? { model: config.socChatLlmModel, messages, stream: false, think: false, options: { temperature: 0.1 } }
      : { model: config.socChatLlmModel, messages, temperature: 0.1 };
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.socChatLlmApiKey}` },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!r.ok) return null;
    const json = await r.json();
    return native ? (json?.message?.content ?? null) : (json?.choices?.[0]?.message?.content ?? null);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function parseJsonLoose(text) {
  if (!text) return null;
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

function clampEnum(v, allowed, fallback) {
  const up = String(v ?? "").toUpperCase().trim();
  return allowed.includes(up) ? up : fallback;
}

// Heurística de respaldo (sin LLM): señales léxicas en español.
function heuristic(subject, body) {
  const txt = `${subject ?? ""} ${body ?? ""}`.toLowerCase();
  const has = (...ws) => ws.some((w) => txt.includes(w));

  let type = "CONSULTA";
  if (has("falso positivo", "no es real", "no era", "marcar como fp")) type = "REPORTE_FP";
  else if (has("cambio", "solicito habilitar", "agregar regla", "abrir puerto", "modificar")) type = "CAMBIO";
  else if (has("acepto el riesgo", "asumimos el riesgo", "no vamos a")) type = "ACEPTACION_RIESGO";
  else if (has("ataque", "incidente", "comprometido", "ransomware", "malware", "brecha", "intrusión", "phishing")) type = "INCIDENTE";

  let priority = "MEDIUM";
  if (has("urgente", "crítico", "critico", "caído", "caido", "ransomware", "producción parada", "no funciona nada")) priority = "URGENT";
  else if (has("importante", "lo antes posible", "asap", "afecta", "comprometido")) priority = "HIGH";
  else if (has("consulta", "duda", "información", "informacion", "cuando puedan")) priority = "LOW";

  let sentiment = "NEUTRAL";
  if (has("inaceptable", "indignante", "harto", "reclamo", "pésimo", "pesimo", "furioso", "!!!", "exijo")) sentiment = "ENOJADO";
  else if (has("preocupado", "frustrado", "otra vez", "de nuevo", "sigue sin", "no me responden")) sentiment = "FRUSTRADO";
  else if (has("gracias", "excelente", "perfecto", "muy bien")) sentiment = "POSITIVO";

  const tags = [];
  if (has("firewall", "fortigate", "vpn")) tags.push("firewall");
  if (has("phishing", "correo", "email", "mail")) tags.push("correo");
  if (has("malware", "virus", "ransomware", "edr", "wazuh")) tags.push("endpoint");
  if (has("contraseña", "password", "credencial", "acceso")) tags.push("accesos");

  return { type, priority, sentiment, tags, confidence: 35, source: "heuristic" };
}

const SYSTEM = `Sos un clasificador de tickets de soporte de un SOC (centro de operaciones de seguridad).
Recibís el asunto y el cuerpo de un ticket escrito por un cliente y devolvés SOLO un objeto JSON, sin explicaciones, con estas claves exactas:
{
 "type": uno de ["INCIDENTE","CONSULTA","CAMBIO","REPORTE_FP","ACEPTACION_RIESGO"],
 "priority": uno de ["LOW","MEDIUM","HIGH","URGENT"]  (prioridad sugerida según urgencia percibida),
 "sentiment": uno de ["POSITIVO","NEUTRAL","FRUSTRADO","ENOJADO"]  (tono del cliente),
 "service_slug": uno de ["soc","firewall","endpoint","correo","infra","otro"],
 "tags": lista de 1 a 4 etiquetas cortas en minúscula (palabras clave del tema),
 "confidence": entero 0-100,
 "summary": resumen en una frase del pedido del cliente (máx 140 caracteres)
}
Reglas: REPORTE_FP = el cliente dice que una alerta es falso positivo. CAMBIO = pide habilitar/modificar algo. ACEPTACION_RIESGO = decide asumir un riesgo. INCIDENTE = reporta un ataque/compromiso. CONSULTA = pregunta/duda. Respondé en español.`;

/**
 * Clasifica el texto de un ticket. Devuelve una SUGERENCIA (no aplica nada).
 * @returns {Promise<{type,priority,sentiment,service_slug?,tags,confidence,summary?,source,at}>}
 */
export async function classifyTicketText({ subject = "", body = "" }) {
  const fallback = () => ({ ...heuristic(subject, body), at: new Date().toISOString() });

  if (!ticketClassifierAvailable()) return fallback();
  const user = `Asunto: ${String(subject).slice(0, 300)}\n\nCuerpo:\n${String(body).slice(0, 2000)}`;
  let raw;
  try {
    raw = await callLlm([{ role: "system", content: SYSTEM }, { role: "user", content: user }]);
  } catch (err) {
    logger.warn?.({ err: err.message }, "[ticketClassifier] LLM falló — usando heurística");
    return fallback();
  }
  const parsed = parseJsonLoose(raw);
  if (!parsed) return fallback();

  let conf = Number(parsed.confidence);
  if (!Number.isFinite(conf)) conf = 60;
  return {
    type: clampEnum(parsed.type, TYPES, "CONSULTA"),
    priority: clampEnum(parsed.priority, PRIORITIES, "MEDIUM"),
    sentiment: clampEnum(parsed.sentiment, SENTIMENTS, "NEUTRAL"),
    service_slug: typeof parsed.service_slug === "string" ? parsed.service_slug.toLowerCase() : undefined,
    tags: Array.isArray(parsed.tags)
      ? parsed.tags.map((t) => String(t).toLowerCase().trim().slice(0, 24)).filter(Boolean).slice(0, 4)
      : [],
    confidence: Math.max(0, Math.min(100, Math.round(conf))),
    summary: typeof parsed.summary === "string" ? parsed.summary.slice(0, 140) : undefined,
    source: "llm",
    at: new Date().toISOString(),
  };
}
