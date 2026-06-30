/**
 * mispService.mjs — cliente HTTP minimalista para la API REST de MISP.
 *
 * Variables de entorno:
 *   MISP_BASE_URL        https://misp.lgcserver.net
 *   MISP_API_KEY         clave de autorización
 *   MISP_VERIFY_SSL      true|false  (default true; false solo para lab sin cert público)
 *   MISP_TIMEOUT_SEC     timeout en segundos (default 30)
 */

import http  from "node:http";
import https from "node:https";
import { getResolvedKeySync } from "./apiKeysService.mjs";

// ── config ────────────────────────────────────────────────────────────────────

function getMispConfig() {
  const baseUrl   = (process.env.MISP_BASE_URL ?? "").trim().replace(/\/+$/, "");
  const apiKey    = (getResolvedKeySync("MISP_API_KEY") ?? "").trim();   // DB (Ajustes) → .env
  const verifySsl = (process.env.MISP_VERIFY_SSL ?? "true").trim().toLowerCase() !== "false";
  const timeoutMs = Math.max(5000, parseInt(process.env.MISP_TIMEOUT_SEC ?? "30", 10) * 1000);
  return { baseUrl, apiKey, verifySsl, timeoutMs };
}

export function mispConfigured() {
  const { baseUrl, apiKey } = getMispConfig();
  return Boolean(baseUrl && apiKey);
}

/**
 * Normaliza el campo `timestamp` que MISP devuelve en cada atributo / evento.
 *
 * MISP histórico devuelve string de segundos-desde-epoch (e.g. "1714512345"),
 * pero se han visto instancias devolviendo:
 *   - número (segundos o milisegundos según versión)
 *   - ISO string (algunos forks)
 *   - null/undefined cuando el atributo es muy antiguo
 *
 * Esta función devuelve siempre ISO 8601 o null, para que el frontend no
 * tenga que hacer `parseInt(...) * 1000` (frágil si el valor ya es ISO).
 *
 * @param {string|number|null|undefined} ts
 * @returns {string|null}
 */
export function normalizeMispTimestamp(ts) {
  if (ts == null || ts === "") return null;

  // Número directo (segundos o ms)
  if (typeof ts === "number" && Number.isFinite(ts)) {
    const ms = ts < 1e12 ? ts * 1000 : ts;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }

  if (typeof ts === "string") {
    const s = ts.trim();
    // String puramente numérico → epoch en segundos (o ms si > 1e12)
    if (/^\d+$/.test(s)) {
      const n = Number(s);
      const ms = n < 1e12 ? n * 1000 : n;
      const d = new Date(ms);
      return Number.isNaN(d.getTime()) ? null : d.toISOString();
    }
    // ISO o RFC2822 directo
    const d = new Date(s);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }

  return null;
}

// ── transporte ────────────────────────────────────────────────────────────────

/**
 * Realiza una llamada HTTP(S) a la API MISP.
 * @param {"GET"|"POST"} method
 * @param {string} path  — p.ej. "/users/view/me.json"
 * @param {object|undefined} body — payload JSON (solo para POST)
 * @returns {Promise<any>}
 */
function mispFetch(method, path, body) {
  const { baseUrl, apiKey, verifySsl, timeoutMs } = getMispConfig();
  if (!baseUrl || !apiKey) {
    return Promise.reject(new Error("MISP no configurado (MISP_BASE_URL / MISP_API_KEY vacíos)"));
  }

  return new Promise((resolve, reject) => {
    const parsed  = new URL(`${baseUrl}${path}`);
    const isHttps = parsed.protocol === "https:";
    const lib     = isHttps ? https : http;
    const reqBody = body ? JSON.stringify(body) : undefined;

    const options = {
      hostname:             parsed.hostname,
      port:                 parsed.port || (isHttps ? 443 : 80),
      path:                 parsed.pathname + parsed.search,
      method,
      agent:                false,   // disable keep-alive; MISP PHP-FPM drops stale connections
      headers: {
        Authorization:    apiKey,
        Accept:           "application/json",
        "Content-Type":   "application/json",
        Connection:       "close",
        ...(reqBody ? { "Content-Length": Buffer.byteLength(reqBody) } : {}),
      },
      rejectUnauthorized: verifySsl,
    };

    const req = lib.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        if (res.statusCode >= 400) {
          const err    = new Error(`MISP HTTP ${res.statusCode} — ${method} ${path}`);
          err.status   = res.statusCode;
          err.mispBody = data.slice(0, 500);
          return reject(err);
        }
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error(`MISP timeout (${timeoutMs}ms) — ${method} ${path}`));
    });
    req.on("error", reject);

    if (reqBody) req.write(reqBody);
    req.end();
  });
}

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Verifica conectividad con MISP.
 * @returns {Promise<{ ok: boolean, email?: string, org_id?: string, error?: string }>}
 */
export async function ping() {
  try {
    const body = await mispFetch("GET", "/users/view/me");
    const user = body?.User ?? body;
    return { ok: true, email: user?.email ?? null, org_id: user?.org_id ?? null };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * Busca un IOC (IP, dominio, hash, URL) entre los atributos de MISP.
 *
 * @param {string} value
 * @param {{ lookbackDays?: number }} opts
 * @returns {Promise<MispLookupResult>}
 *
 * @typedef {{ configured: boolean, hits: object[], count: number, value?: string, error?: string }} MispLookupResult
 */
export async function lookupIoc(value, { lookbackDays = 365 } = {}) {
  if (!mispConfigured()) {
    return { configured: false, hits: [], count: 0 };
  }

  const payload = {
    returnFormat:     "json",
    value,
    timestamp:        `${lookbackDays}d`,
    includeEventUuid: true,
    includeEventTags: true,
    // to_ids omitido → MISP devuelve atributos con y sin flag IDS.
    // to_ids:0 filtraría solo los que NO tienen IDS y en algunas versiones
    // provoca HTTP 500 en el PHP-FPM de MISP.
    limit:            50,
    page:             1,
  };

  try {
    const body  = await mispFetch("POST", "/attributes/restSearch", payload);
    const attrs = Array.isArray(body)
      ? body
      : (body?.response?.Attribute ?? body?.Attribute ?? []);

    const hits = attrs.map((a) => ({
      id:           a.id,
      uuid:         a.uuid,
      type:         a.type,
      value:        a.value,
      category:     a.category,
      to_ids:       Boolean(a.to_ids),
      comment:      a.comment || null,
      event_id:     a.event_id,
      event_uuid:   a.Event?.uuid  ?? a.event_uuid  ?? null,
      event_title:  a.Event?.info  ?? null,
      threat_level: a.Event?.threat_level_id ?? null,
      tags:         (a.Tag ?? []).map((t) => t.name).filter(Boolean),
      timestamp:    normalizeMispTimestamp(a.timestamp),
    }));

    return { configured: true, hits, count: hits.length, value };
  } catch (e) {
    return { configured: true, hits: [], count: 0, value, error: e.message };
  }
}

/**
 * Registra un sighting para un atributo MISP.
 *
 * @param {string|number} attributeId
 * @param {string} [source]
 * @returns {Promise<boolean>}
 */
export async function addSighting(attributeId, source = "LegacyHunt-API") {
  if (!mispConfigured()) return false;
  try {
    await mispFetch("POST", `/sightings/add/${attributeId}`, { source });
    return true;
  } catch {
    return false;
  }
}

/**
 * Obtiene los últimos eventos publicados (solo cabeceras, sin atributos completos).
 *
 * @param {{ limit?: number, threatLevelMax?: number, lookbackDays?: number }} opts
 * @returns {Promise<{ configured: boolean, events: object[], count: number, error?: string }>}
 */
export async function getRecentEvents({ limit = 25, threatLevelMax = 3, lookbackDays = 30 } = {}) {
  if (!mispConfigured()) return { configured: false, events: [], count: 0 };

  const payload = {
    returnFormat:    "json",
    published:       true,
    threat_level_id: String(threatLevelMax),
    timestamp:       `${lookbackDays}d`,
    limit,
    page:            1,
    metadata:        true,   // cabeceras sin Attribute[]
  };

  try {
    const body   = await mispFetch("POST", "/events/restSearch", payload);
    const raw    = Array.isArray(body) ? body : (body?.response ?? []);
    const events = raw.map((item) => {
      const ev = item?.Event ?? item;
      return {
        id:              ev.id,
        uuid:            ev.uuid,
        title:           ev.info,
        threat_level:    parseInt(ev.threat_level_id ?? 4, 10),
        date:            ev.date,
        org:             ev.Org?.name ?? ev.org ?? null,
        attribute_count: parseInt(ev.attribute_count ?? 0, 10),
        tags:            (ev.Tag ?? []).map((t) => t.name).filter(Boolean),
        published:       Boolean(ev.published),
        timestamp:       normalizeMispTimestamp(ev.timestamp),
      };
    });
    return { configured: true, events, count: events.length };
  } catch (e) {
    return { configured: true, events: [], count: 0, error: e.message };
  }
}

/**
 * Crea un nuevo evento en MISP con atributos IOC opcionales.
 *
 * @param {{
 *   title: string,
 *   threatLevel?: 1|2|3|4,
 *   analysis?: 0|1|2,
 *   distribution?: 0|1|2|3|4|5,
 *   tags?: string[],
 *   attributes?: Array<{ type: string, value: string, category?: string, comment?: string, to_ids?: boolean }>,
 *   info?: string
 * }} opts
 * @returns {Promise<{ ok: boolean, event_id?: string, event_uuid?: string, error?: string }>}
 */
export async function createEvent({
  title,
  threatLevel   = 2,   // 1=High 2=Medium 3=Low 4=Undefined
  analysis      = 1,   // 0=Initial 1=Ongoing 2=Complete
  distribution  = 0,   // 0=Your org only
  tags          = [],
  attributes    = [],
  info,
} = {}) {
  if (!mispConfigured()) return { ok: false, error: "MISP no configurado" };

  const eventPayload = {
    Event: {
      info:             title ?? info ?? "LegacyHunt Export",
      threat_level_id:  String(threatLevel),
      analysis:         String(analysis),
      distribution:     String(distribution),
      published:        false,
      Tag:              tags.map((t) => ({ name: t })),
      Attribute:        attributes.map((a) => ({
        type:     a.type,
        value:    a.value,
        category: a.category ?? "Network activity",
        comment:  a.comment  ?? "",
        to_ids:   a.to_ids   ?? true,
      })),
    },
  };

  try {
    const body = await mispFetch("POST", "/events/add", eventPayload);
    const ev   = body?.Event ?? body;
    return { ok: true, event_id: String(ev?.id ?? ""), event_uuid: String(ev?.uuid ?? "") };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * Devuelve el estado de conectividad MISP con conteo de IOCs/eventos recientes.
 * Usado por el widget Feed Status del dashboard.
 *
 * @returns {Promise<{
 *   configured: boolean,
 *   ok: boolean,
 *   baseUrl?: string,
 *   email?: string,
 *   org_id?: string,
 *   recentIocs?: number,
 *   recentEvents?: number,
 *   error?: string,
 *   checkedAt: string
 * }>}
 */
export async function getStatus() {
  const { baseUrl } = getMispConfig();
  const checkedAt   = new Date().toISOString();

  if (!mispConfigured()) {
    return { configured: false, ok: false, checkedAt };
  }

  const pingResult = await ping();
  if (!pingResult.ok) {
    return { configured: true, ok: false, baseUrl, error: pingResult.error, checkedAt };
  }

  // Conteo ligero de IOCs/eventos recientes (30d, solo metadatos)
  const [iocResult, evResult] = await Promise.allSettled([
    lookupIoc("*", { lookbackDays: 30 }).catch(() => ({ count: null })),
    getRecentEvents({ limit: 1, lookbackDays: 30 }).catch(() => ({ count: null })),
  ]);

  return {
    configured:    true,
    ok:            true,
    baseUrl,
    email:         pingResult.email ?? null,
    org_id:        pingResult.org_id ?? null,
    recentEvents:  evResult.status === "fulfilled" ? evResult.value.count : null,
    checkedAt,
  };
}
