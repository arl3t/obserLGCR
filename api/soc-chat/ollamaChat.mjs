/**
 * ollamaChat.mjs — llamada al LLM local del SOC con el canal de razonamiento
 * DESACTIVADO.
 *
 * Por qué existe: qwen3.5 IGNORA la directiva "/no_think" en el prompt y razona
 * igual ~6k tokens en un canal invisible → ~40s por llamada. El chat hace dos
 * llamadas seriales (router + redacción) → >60s y revienta el timeout del front.
 * El API NATIVO de Ollama (`/api/chat`) acepta `think:false`, que corta el
 * razonamiento de raíz: misma respuesta en ~2-8s (medido). Mismo patrón que
 * services/casePlaybookDoc.mjs.
 *
 * Si la URL configurada no es Ollama (no matchea …/v1/chat/completions), cae al
 * endpoint OpenAI-compatible (sin supresión, pero funcional). Devuelve
 * `{ content, toolCalls }` normalizado, o `null` ante error/red/timeout.
 */
import { config } from "../config.mjs";

// …/v1/chat/completions → …/api/chat. Si no matchea, NATIVE_URL === apiUrl y se
// usa el camino OpenAI-compat.
const NATIVE_URL = config.socChatLlmApiUrl
  ? config.socChatLlmApiUrl.replace(/\/v1\/chat\/completions\/?$/, "/api/chat")
  : null;
const IS_OLLAMA = Boolean(NATIVE_URL) && NATIVE_URL !== config.socChatLlmApiUrl;

function safeJson(s) {
  try { return JSON.parse(s || "{}"); } catch { return {}; }
}

/**
 * @param {Object} opts
 * @param {Array<{role:string, content:string}>} opts.messages
 * @param {Array<Object>} [opts.tools]      tools OpenAI-style (se pasan tal cual)
 * @param {number} [opts.numPredict=512]    tope de tokens de salida
 * @param {number} [opts.temperature=0]
 * @param {number} [opts.timeoutMs=30000]
 * @returns {Promise<{content:string, toolCalls:Array<{name:string, args:Object}>}|null>}
 */
export async function socLlmChat({ messages, tools = null, numPredict = 512, temperature = 0, timeoutMs = 30_000 }) {
  if (!config.socChatLlmEnabled || !config.socChatLlmApiKey) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = IS_OLLAMA ? NATIVE_URL : config.socChatLlmApiUrl;
    const body = IS_OLLAMA
      ? {
          model: config.socChatLlmModel,
          messages,
          stream: false,
          think: false,
          ...(tools ? { tools } : {}),
          options: { temperature, num_predict: numPredict },
        }
      : {
          model: config.socChatLlmModel,
          messages,
          temperature,
          max_tokens: numPredict,
          ...(tools ? { tools, tool_choice: "auto" } : {}),
        };
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.socChatLlmApiKey}` },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!r.ok) return null;
    const json = await r.json();
    const msg = IS_OLLAMA ? json?.message : json?.choices?.[0]?.message;
    if (!msg) return null;
    const toolCalls = (msg.tool_calls || []).map((c) => ({
      name: c.function?.name,
      // nativo: arguments ya es objeto; OpenAI-compat: string JSON.
      args: typeof c.function?.arguments === "string" ? safeJson(c.function.arguments) : (c.function?.arguments ?? {}),
    }));
    return { content: msg.content ?? "", toolCalls };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
