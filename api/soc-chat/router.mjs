/**
 * SOC Chat — Router de intents (regex + LLM tool-calling).
 *
 * Dos caminos, mismo contrato de salida:
 *   { intent, queryId, params: { days, limit }, mode: "regex" | "llm" }
 *
 * El regexRouter es el fallback determinístico (gratis, sub-ms, sin red). El
 * llmRouter usa tool-calling de una API OpenAI-compatible (`/v1/chat/completions`):
 * pasa el catálogo como `tools[]` y deja que el modelo elija la función y
 * complete parámetros. Si el modelo no invoca tool, no se aloja la API, o la
 * respuesta falla el schema, caemos al regex.
 *
 * El gating de intents sensibles (can_review_kpis) se decide en server.mjs con
 * `isSensitiveIntent(intent)` — el router NO decide autorizaciones.
 */

import { logger } from "../logger.mjs";
import { socLlmChat } from "./ollamaChat.mjs";

// ── Catálogo ─────────────────────────────────────────────────────────────────
// Cada herramienta expone:
//   intent     — key interno compartido con server.mjs / formatSocChatSummary
//   queryId    — id en trino/registry.mjs que resuelve a un SQL named-query
//   name       — nombre OpenAI-tool (sin puntos; requerido por el schema)
//   description— string que el LLM lee para elegir
//   schema     — JSON Schema de parámetros
//   sensitive  — true si requiere caps.canReviewKpis

/**
 * @typedef {Object} SocChatTool
 * @property {string}  intent
 * @property {string}  queryId
 * @property {string}  name
 * @property {string}  description
 * @property {Object}  schema
 * @property {boolean} sensitive
 */

/**
 * Severidades aceptadas en orden ascendente. El builder SQL y el normalizador
 * de params comparten esta lista para no divergir.
 */
export const SEVERITY_ORDER = /** @type {const} */ ([
  "NEGLIGIBLE",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
]);

const SEVERITY_ENUM_SCHEMA = {
  type: "string",
  enum: [...SEVERITY_ORDER],
  description:
    "Severidad mínima a incluir (jerarquía NEGLIGIBLE<LOW<MEDIUM<HIGH<CRITICAL). Si se omite, no se filtra.",
};

/** @type {SocChatTool[]} */
export const SOC_CHAT_TOOLS = [
  {
    intent: "top_hosts",
    queryId: "lh.chat.top_attacked_hosts",
    name: "top_attacked_hosts",
    description:
      "Top N hosts (activos internos) con más eventos detectados. Responde '¿qué host recibe más ataques?', 'hosts más golpeados', 'cuáles son los hosts atacados'.",
    schema: {
      type: "object",
      properties: {
        days:  { type: "integer", minimum: 1, maximum: 90, description: "Ventana en días" },
        limit: { type: "integer", minimum: 1, maximum: 50, description: "Cantidad de filas" },
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: false,
  },
  {
    intent: "top_ips",
    queryId: "lh.chat.top_attacker_ips",
    name: "top_attacker_ips",
    description:
      "Top N IPs origen con más eventos. Responde 'IPs que más atacan', 'direcciones origen', 'cuál es la IP atacante principal'.",
    schema: {
      type: "object",
      properties: {
        days:  { type: "integer", minimum: 1, maximum: 90 },
        limit: { type: "integer", minimum: 1, maximum: 50 },
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: false,
  },
  {
    intent: "highest_cves",
    queryId: "lh.chat.highest_cves",
    name: "highest_cves",
    description:
      "CVEs observados en los eventos ordenados por CVSS y por cantidad. Responde '¿qué CVE aparece con más score?', 'vulnerabilidades críticas', 'top CVEs'.",
    schema: {
      type: "object",
      properties: {
        days:  { type: "integer", minimum: 1, maximum: 90 },
        limit: { type: "integer", minimum: 1, maximum: 50 },
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: true,
  },
  {
    intent: "business_most_attacked",
    queryId: "lh.chat.business_most_attacked",
    name: "business_most_attacked",
    description:
      "Negocio / servicio (business_tag) con más eventos, usando la tabla business_ip_tags. Responde 'qué empresa está bajo ataque', 'qué servicio es el más golpeado'.",
    schema: {
      type: "object",
      properties: {
        days:  { type: "integer", minimum: 1, maximum: 90 },
        limit: { type: "integer", minimum: 1, maximum: 50 },
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: true,
  },
  {
    intent: "recent_critical",
    queryId: "lh.chat.recent_critical",
    name: "recent_critical_incidents",
    description:
      "Últimos incidentes con severity=CRITICAL en la ventana, ordenados por score desc y fecha desc. Responde 'críticos recientes', 'últimos incidentes altos', 'qué pasó recientemente'.",
    schema: {
      type: "object",
      properties: {
        days:  { type: "integer", minimum: 1, maximum: 90 },
        limit: { type: "integer", minimum: 1, maximum: 50 },
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: true,
  },
  {
    intent: "top_source_countries",
    queryId: "lh.chat.top_source_countries",
    name: "top_source_countries",
    description:
      "Países origen con más eventos (geo breakdown). Responde '¿de qué país vienen los ataques?', 'origen geográfico', 'top países atacantes'.",
    schema: {
      type: "object",
      properties: {
        days:        { type: "integer", minimum: 1, maximum: 90 },
        limit:       { type: "integer", minimum: 1, maximum: 50 },
        severityMin: SEVERITY_ENUM_SCHEMA,
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: false,
  },
  {
    intent: "top_mitre_tactics",
    queryId: "lh.chat.top_mitre_tactics",
    name: "top_mitre_tactics",
    description:
      "Tácticas MITRE ATT&CK más frecuentes en la ventana — útil para ver qué fase del kill-chain está activa (initial-access, lateral-movement, exfil, etc.). Responde 'qué MITRE está pegando', 'tácticas ATT&CK', 'TTPs más vistos'.",
    schema: {
      type: "object",
      properties: {
        days:        { type: "integer", minimum: 1, maximum: 90 },
        limit:       { type: "integer", minimum: 1, maximum: 50 },
        severityMin: SEVERITY_ENUM_SCHEMA,
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: false,
  },
  {
    intent: "top_source_logs",
    queryId: "lh.chat.top_source_logs",
    name: "top_source_logs",
    description:
      "Breakdown por sensor/origen (WAZUH, FORTIGATE, SURICATA, OPNSENSE, SYSLOG) — responde '¿qué sensor reporta más?', 'qué fuente detecta más', 'qué log genera más ruido'. Útil para decidir dónde hacer tuning.",
    schema: {
      type: "object",
      properties: {
        days:        { type: "integer", minimum: 1, maximum: 90 },
        limit:       { type: "integer", minimum: 1, maximum: 50 },
        severityMin: SEVERITY_ENUM_SCHEMA,
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: false,
  },
  {
    intent: "fortigate_vpn_logins",
    queryId: "lh.chat.fortigate_vpn_logins",
    name: "fortigate_vpn_logins",
    description:
      "Logins de VPN (SSL-VPN FortiGate) por USUARIO en la ventana: intentos fallidos vs exitosos, con la IP origen y el firewall. Responde 'usuarios con intentos fallidos y exitosos de la VPN', 'logins VPN fortigate', 'quién falla el login de VPN', 'brute-force / spray de VPN'. Ventana en días (el raw se capea a ~48h).",
    schema: {
      type: "object",
      properties: {
        days:  { type: "integer", minimum: 1, maximum: 90, description: "Ventana en días (capeada a 2)" },
        limit: { type: "integer", minimum: 1, maximum: 50 },
      },
      required: ["days", "limit"],
      additionalProperties: false,
    },
    sensitive: false,
  },
];

const TOOL_BY_INTENT = new Map(SOC_CHAT_TOOLS.map((t) => [t.intent, t]));
const TOOL_BY_NAME   = new Map(SOC_CHAT_TOOLS.map((t) => [t.name,   t]));

const DEFAULT_INTENT = "top_ips";
const DEFAULT_PARAMS = Object.freeze({ days: 7, limit: 10 });

export function isSensitiveIntent(intent) {
  return TOOL_BY_INTENT.get(intent)?.sensitive === true;
}

export function listSocChatIntents() {
  return SOC_CHAT_TOOLS.map((t) => ({
    intent:      t.intent,
    queryId:     t.queryId,
    description: t.description,
    sensitive:   t.sensitive,
  }));
}

// ── Regex router ─────────────────────────────────────────────────────────────

/**
 * Detecta intent por patrones en español. Es el fallback cuando el LLM no está
 * disponible o no eligió tool.
 *
 * @param {string} question
 * @returns {string} intent
 */
export function detectIntentRegex(question) {
  const q = String(question ?? "").toLowerCase().trim();
  // Orden intencional: intents más específicos primero. "geo / país" gana sobre
  // "ip origen" si aparecen juntos; "mitre/táctica" gana sobre "ataque".
  if (/\bvpn\b|ssl-?login|fortigate.*(login|usuario|fall)/.test(q))               return "fortigate_vpn_logins";
  if (/\bpa[ií]s(es)?\b|\bcountry\b|\bgeo\b|origen geogr[aá]fico/.test(q))        return "top_source_countries";
  if (/\bmitre\b|\batt&ck\b|\bttp[s]?\b|\bt[aá]ctica[s]?\b|kill[- ]chain/.test(q)) return "top_mitre_tactics";
  if (/\bfuente[s]?\b|\bsensor(es)?\b|\bsource.?log\b|qu[eé] detector|qu[eé] log/.test(q)) return "top_source_logs";
  if (/host/.test(q) && /(ataque|ataques|incidente|incidentes|eventos)/.test(q)) return "top_hosts";
  if (/\bcve\b|cvss|vulnerabilidad|vuln/.test(q))                                 return "highest_cves";
  if (/(\bips?\b)/.test(q) && /(ataque|ataques|origen|atac)/.test(q))             return "top_ips";
  if (/negocio|empresa|servicio/.test(q))                                         return "business_most_attacked";
  if (/cr[ií]tico|critical/.test(q))                                              return "recent_critical";
  return DEFAULT_INTENT;
}

/**
 * Parsea severidad mínima desde lenguaje natural. "severidad alta" / "sólo
 * críticos" / "high y más". Devuelve string válido de SEVERITY_ORDER o null.
 */
export function detectSeverityMinFromText(question) {
  const q = String(question ?? "").toLowerCase();
  if (/cr[ií]tico[s]?\b|\bcritical\b/.test(q))         return "CRITICAL";
  if (/\balto[s]?\b|\bhigh\b|severidad alta/.test(q))  return "HIGH";
  if (/medio[s]?\b|\bmedium\b|severidad media/.test(q)) return "MEDIUM";
  if (/bajo[s]?\b|\blow\b|severidad baja/.test(q))      return "LOW";
  return null;
}

/**
 * Parsea `days` y `limit` desde la pregunta. Los valores quedan clampeados al
 * rango del schema (1–90 / 1–50).
 *
 * @param {string} question
 * @returns {{ days: number, limit: number }}
 */
export function parseParamsFromText(question) {
  const q = String(question ?? "").toLowerCase();
  let days  = DEFAULT_PARAMS.days;
  let limit = DEFAULT_PARAMS.limit;
  const mDays = q.match(/(\d+)\s*(d[ií]as|dias|day|days)/);
  if (mDays) days = clamp(Number(mDays[1]) || 7, 1, 90);
  const mHours = q.match(/(\d+)\s*(h|hora|horas)/);
  if (mHours) {
    const h = Number(mHours[1]) || 24;
    days = clamp(Math.ceil(h / 24), 1, 90);
  }
  const mTop = q.match(/top\s*(\d+)/);
  if (mTop) limit = clamp(Number(mTop[1]) || 10, 1, 50);
  return { days, limit };
}

export function regexRouter(question) {
  const intent = detectIntentRegex(question);
  const tool   = TOOL_BY_INTENT.get(intent) ?? TOOL_BY_INTENT.get(DEFAULT_INTENT);
  const base   = parseParamsFromText(question);
  const severityMin = toolAcceptsSeverityMin(tool)
    ? (detectSeverityMinFromText(question) ?? undefined)
    : undefined;
  const params = severityMin ? { ...base, severityMin } : base;
  return {
    intent:  tool.intent,
    queryId: tool.queryId,
    params,
    mode:    "regex",
  };
}

function toolAcceptsSeverityMin(tool) {
  return Boolean(tool?.schema?.properties?.severityMin);
}

// ── LLM router (tool-calling) ────────────────────────────────────────────────

const SYSTEM_PROMPT = [
  "Sos un router de consultas para un chat SOC en español.",
  "Tenés que elegir EXACTAMENTE una de las herramientas disponibles, la que mejor responda la pregunta del operador, y completar sus parámetros.",
  "Reglas:",
  "- Si la pregunta no menciona una ventana, usá days=7.",
  "- Si la pregunta no menciona un límite, usá limit=10.",
  "- Si la pregunta menciona 'últimas 24h' o similar, convertí a días (mínimo 1).",
  "- No respondas en texto plano: usá siempre tool-calling.",
].join("\n");

/**
 * Llama a un endpoint OpenAI-compatible de chat completions con tools. Devuelve
 * una ruta válida o `null` si el modelo no invocó tool, la red falló, o los
 * argumentos no cumplen el schema.
 *
 * @param {Object}  opts
 * @param {string}  opts.question
 * @param {Array<{ role: "user" | "assistant", content: string }>} [opts.history]
 * @param {Object}  opts.config
 */
export async function llmRouter({ question, history = [], config }) {
  if (!config?.socChatLlmRouterEnabled) return null;
  if (!config?.socChatLlmApiKey)        return null;

  const tools = SOC_CHAT_TOOLS.map((t) => ({
    type: "function",
    function: {
      name:        t.name,
      description: t.description,
      parameters:  t.schema,
    },
  }));

  const messages = [
    { role: "system", content: SYSTEM_PROMPT },
    ...history.slice(-6).map((h) => ({
      role:    h.role === "user" ? "user" : "assistant",
      content: String(h.content ?? ""),
    })),
    { role: "user", content: String(question ?? "") },
  ];

  // think:false vía socLlmChat: el router razonaba ~1.5k+ tokens (~37s) antes de
  // emitir el tool_call; con el canal de razonamiento apagado decide en ~2s.
  // num_predict bajo: sólo necesita emitir el tool_call, no prosa.
  const res = await socLlmChat({ messages, tools, numPredict: 200, temperature: 0, timeoutMs: 25_000 });
  if (!res) {
    logger.warn?.("soc_chat_llm_router_no_response");
    return null;
  }
  const call = res.toolCalls[0];
  if (!call?.name) return null;

  const tool = TOOL_BY_NAME.get(call.name);
  if (!tool) {
    logger.warn?.("soc_chat_llm_router_unknown_tool", { name: call.name });
    return null;
  }

  const params = normalizeParams(call.args);
  return { intent: tool.intent, queryId: tool.queryId, params, mode: "llm" };
}

/**
 * Orquestador: si el LLM-router está habilitado, intenta LLM primero; si
 * devuelve null (no tool, timeout, error), cae a regex. El modo se devuelve en
 * el resultado para que la ruta emita telemetría.
 *
 * @param {Object} opts
 * @param {string} opts.question
 * @param {Array<{ role: "user" | "assistant", content: string }>} [opts.history]
 * @param {Object} opts.config
 */
export async function routeQuestion({ question, history = [], config }) {
  if (config?.socChatLlmRouterEnabled) {
    const llmRoute = await llmRouter({ question, history, config });
    if (llmRoute) return llmRoute;
  }
  return regexRouter(question);
}

// ── Memoria conversacional (in-memory ring buffer) ───────────────────────────
// Usada como contexto para el LLM-router y para el LLM de respuesta. 3b va a
// reemplazar esto con persistencia en PG (`soc_chat_turns`).

const SOC_CHAT_MEMORY_MAX = 80;
/** @type {Array<{ q: string, intent: string, ts: string, preview: string }>} */
const socChatMemory = [];

export function rememberSocChat(q, intent, preview) {
  socChatMemory.push({ q, intent, preview, ts: new Date().toISOString() });
  if (socChatMemory.length > SOC_CHAT_MEMORY_MAX) socChatMemory.shift();
}

/**
 * Devuelve los últimos N pares user/assistant como context para LLMs.
 *
 * @param {number} [pairs=4]
 */
export function getRecentChatHistory(pairs = 4) {
  const slice = socChatMemory.slice(-pairs);
  const out = [];
  for (const m of slice) {
    out.push({ role: "user",      content: m.q });
    out.push({ role: "assistant", content: m.preview });
  }
  return out;
}

export function getRawMemorySnapshot() {
  return socChatMemory.slice();
}

// ── Internos ─────────────────────────────────────────────────────────────────

function clamp(n, lo, hi) {
  const v = Number(n);
  if (!Number.isFinite(v)) return lo;
  return Math.max(lo, Math.min(hi, Math.round(v)));
}

function normalizeParams(raw) {
  const days  = clamp(raw?.days  ?? DEFAULT_PARAMS.days,  1, 90);
  const limit = clamp(raw?.limit ?? DEFAULT_PARAMS.limit, 1, 50);
  const out = { days, limit };
  if (raw?.severityMin) {
    const upper = String(raw.severityMin).toUpperCase();
    if (SEVERITY_ORDER.includes(upper)) out.severityMin = upper;
  }
  return out;
}
