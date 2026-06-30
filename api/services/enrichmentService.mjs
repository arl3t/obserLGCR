/**
 * enrichmentService.mjs — Enriquecimiento paralelo de IOCs
 * NIST SP 800-61 §3.2.2 — Detection and Analysis: gather indicators + context
 *
 * Fuentes (live fan-out):
 *  · VirusTotal   — reporte detallado (VT_API_KEY / VIRUSTOTAL_TOKEN)
 *  · Shodan       — exposición pública, puertos, CVEs, ISP (SHODAN_API_KEY)
 *  · AbuseIPDB    — confidence score (ABUSEIPDB_API_KEY)
 *  · URLhaus      — presencia en feeds (abuse.ch, ruteo por tipo de IOC)
 *  · OpenPhish    — presencia en feed de phishing (feed público cacheado)
 *  · MISP         — eventos relacionados, tags, threat_level
 *  · GreyNoise    — clasificación benigno/malicioso, RIOT (community, sin key)
 *  · ThreatFox    — IOC→malware (abuse.ch, opcional THREATFOX_API_KEY)
 *  · AlienVault OTX — pulses de threat intel (OTX_API_KEY)
 *  · Spamhaus     — DNSBL ZEN (IP) / DBL (dominio), sin key
 *
 * Cada fuente reporta un `status`:
 *   ok | clean | unconfigured | error | na
 * para que la UI distinga "limpio" (verde) de "no consultado" (gris) y de
 * "falló" (alerta) — antes todo colapsaba a `false`/`null` (audit intel 2026-06-05).
 *
 * Mejoras integ. 2026-06-05:
 *   B1 — OpenPhish ya no es stub: usa el feed público (reusa pmgEnrichmentService).
 *   B2 — URLhaus rutea por tipo (url/host/payload) en vez de host para todo.
 *   B3 — caché TTL in-memory para no re-pegar a los proveedores en cada apertura.
 *   B4 — `status` por-fuente diferenciando no-configurado/limpio/error.
 */

import { config } from "../config.mjs";
import {
  mispConfigured,
  lookupIoc as mispLookupIoc,
} from "./mispService.mjs";
import {
  checkSpamhausIp,
  checkSpamhausDomain,
  checkOpenPhish as pmgCheckOpenPhish,
} from "./pmgEnrichmentService.mjs";
import { computeIocVerdict } from "./iocVerdict.mjs";
import { lookupCountry as geoCountry, lookupAsn as geoAsn } from "./geoipService.mjs";
import { withCircuitBreaker } from "./circuitBreaker.mjs";
import { isRfc1918 } from "./netClass.mjs";
import { getResolvedKey } from "./apiKeysService.mjs";

// ── Helpers ───────────────────────────────────────────────────────────────────

function safeJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/**
 * Inferencia barata del tipo de IOC desde su valor. Para callers (p.ej. el gate
 * de auto-cierre) que sólo tienen ioc_value. Heurística, no exhaustiva.
 */
export function guessIocType(value) {
  const v = String(value ?? "").trim();
  if (!v) return "ip";
  if (IPV4_RE.test(v)) return "ip";
  if (v.includes("@")) return "email";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
  if (/^[a-z]+:\/\//i.test(v) || v.includes("/")) return "url";
  if (v.includes(".")) return "domain";
  return "ip";
}

/** Fetch JSON distinguiendo 404 (no encontrado) de error real (red/5xx/timeout). */
async function httpJson(url, opts = {}, timeoutMs = 8000) {
  try {
    const res  = await fetch(url, { ...opts, signal: AbortSignal.timeout(timeoutMs) });
    const text = await res.text().catch(() => "");
    return { httpOk: res.ok, httpStatus: res.status, json: safeJson(text) };
  } catch {
    return { httpOk: false, httpStatus: 0, json: null };
  }
}

/** Resultado uniforme de cada fuente. */
const SRC = (status, data = null) => ({ status, data });

// ── VirusTotal ─────────────────────────────────────────────────────────────────

async function enrichVirusTotal(iocValue, iocType = "ip") {
  const apiKey = (await getResolvedKey("VT_API_KEY")) || config.VIRUSTOTAL_TOKEN;
  if (!apiKey) return SRC("unconfigured");

  const typeMap = { ip: "ip_addresses", domain: "domains", hash: "files", url: "urls" };
  const endpoint = typeMap[iocType] ?? "ip_addresses";

  let url;
  if (iocType === "url") {
    const encoded = Buffer.from(iocValue).toString("base64url");
    url = `https://www.virustotal.com/api/v3/urls/${encoded}`;
  } else {
    url = `https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(iocValue)}`;
  }

  const { httpStatus, json } = await httpJson(url, {
    headers: { "x-apikey": apiKey, Accept: "application/json" },
  });
  if (httpStatus === 404) return SRC("clean");        // VT no conoce el IOC
  if (!json?.data?.attributes) return SRC("error");

  const a = json.data.attributes;
  const stats = a.last_analysis_stats ?? {};
  const data = {
    malicious:    stats.malicious    ?? 0,
    suspicious:   stats.suspicious   ?? 0,
    harmless:     stats.harmless     ?? 0,
    undetected:   stats.undetected   ?? 0,
    total:        Object.values(stats).reduce((s, v) => s + (v ?? 0), 0),
    reputation:   a.reputation       ?? null,
    country:      a.country          ?? null,
    asOwner:      a.as_owner         ?? null,
    asn:          a.asn              ?? null,
    network:      a.network          ?? null,
    tags:         a.tags             ?? [],
    lastAnalysis: a.last_analysis_date
      ? new Date(a.last_analysis_date * 1000).toISOString()
      : null,
    permalink: `https://www.virustotal.com/gui/${endpoint}/${encodeURIComponent(iocValue)}`,
  };
  const hit = (data.malicious + data.suspicious) > 0;
  return SRC(hit ? "ok" : "clean", data);
}

// ── Shodan ───────────────────────────────────────────────────────────────────

async function enrichShodan(ip, iocType) {
  if (iocType !== "ip") return SRC("na");
  const apiKey = (await getResolvedKey("SHODAN_API_KEY")) || config.SHODAN_API_KEY;
  if (!apiKey) return SRC("unconfigured");
  if (!IPV4_RE.test(ip)) return SRC("na");

  const { httpStatus, json } = await httpJson(
    `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`,
  );
  if (httpStatus === 404) return SRC("clean");        // sin info pública en Shodan
  if (!json) return SRC("error");

  const data = {
    ip:           json.ip_str,
    org:          json.org          ?? null,
    isp:          json.isp          ?? null,
    country:      json.country_name ?? null,
    countryCode:  json.country_code ?? null,
    city:         json.city         ?? null,
    asn:          json.asn          ?? null,
    os:           json.os           ?? null,
    ports:        json.ports        ?? [],
    hostnames:    json.hostnames    ?? [],
    tags:         json.tags         ?? [],
    vulns:        json.vulns ? Object.keys(json.vulns) : [],
    lastUpdate:   json.last_update  ?? null,
    services: (json.data ?? []).slice(0, 5).map((s) => ({
      port:      s.port,
      transport: s.transport,
      product:   s.product ?? null,
      version:   s.version ?? null,
      banner:    (s.data ?? "").slice(0, 200),
    })),
  };
  return SRC(data.ports.length > 0 ? "ok" : "clean", data);
}

// ── AbuseIPDB ────────────────────────────────────────────────────────────────

async function enrichAbuseIPDB(ip, iocType) {
  if (iocType !== "ip") return SRC("na");
  const apiKey = await getResolvedKey("ABUSEIPDB_API_KEY");
  if (!apiKey) return SRC("unconfigured");
  if (!IPV4_RE.test(ip)) return SRC("na");

  const { json } = await httpJson(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
    { headers: { Key: apiKey, Accept: "application/json" } },
  );
  if (!json?.data) return SRC("error");
  const d = json.data;
  const data = {
    abuseConfidenceScore: d.abuseConfidenceScore ?? 0,
    totalReports:         d.totalReports         ?? 0,
    numDistinctUsers:     d.numDistinctUsers      ?? 0,
    countryCode:          d.countryCode           ?? null,
    isp:                  d.isp                   ?? null,
    domain:               d.domain                ?? null,
    isWhitelisted:        d.isWhitelisted          ?? false,
    lastReportedAt:       d.lastReportedAt         ?? null,
    usageType:            d.usageType              ?? null,
  };
  return SRC(data.abuseConfidenceScore > 0 ? "ok" : "clean", data);
}

// ── URLhaus (abuse.ch) — ruteo por tipo de IOC (B2) ────────────────────────────

async function checkUrlhaus(ioc, iocType) {
  let url, body;
  if (iocType === "url") {
    url = "https://urlhaus-api.abuse.ch/v1/url/";
    body = `url=${encodeURIComponent(ioc)}`;
  } else if (iocType === "hash") {
    url = "https://urlhaus-api.abuse.ch/v1/payload/";
    const field = ioc.length === 32 ? "md5_hash" : "sha256_hash";
    body = `${field}=${encodeURIComponent(ioc)}`;
  } else {
    // ip | domain → lookup por host
    url = "https://urlhaus-api.abuse.ch/v1/host/";
    body = `host=${encodeURIComponent(ioc)}`;
  }

  const { json } = await httpJson(url, {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!json) return SRC("error");

  const status = json.query_status;
  // "no_results" / "ok" (url/payload) / "is_host" (host) son respuestas válidas.
  const hit = status === "is_host"
    || (status === "ok" && (iocType === "url" || iocType === "hash"));
  const data = {
    inFeed:   hit,
    urlCount: Array.isArray(json.urls) ? json.urls.length : (json.url_count ?? 0),
    tags:     json.tags ?? [],
    threat:   json.threat ?? json.payload?.signature ?? null,
  };
  return SRC(hit ? "ok" : "clean", data);
}

// ── OpenPhish — feed público real (B1) ─────────────────────────────────────────

async function checkOpenPhishSrc(ioc, iocType) {
  // El feed es de URLs; aplicable a url y (por hostname) a domain.
  if (iocType !== "url" && iocType !== "domain") return SRC("na");
  const probe = iocType === "domain" ? `http://${ioc}` : ioc;
  try {
    const r = await pmgCheckOpenPhish(probe);
    const data = { inFeed: Boolean(r?.inFeed), matchType: r?.matchType ?? null };
    return SRC(data.inFeed ? "ok" : "clean", data);
  } catch {
    return SRC("error");
  }
}

// ── MISP ────────────────────────────────────────────────────────────────────

async function enrichMisp(iocValue) {
  if (!mispConfigured()) return SRC("unconfigured");
  try {
    const result = await mispLookupIoc(iocValue);
    if (!result) return SRC("clean");
    const data = {
      events:       result.events       ?? [],
      tags:         result.tags         ?? [],
      threatLevel:  result.threat_level ?? null,
      sightings:    result.sightings    ?? 0,
      firstSeen:    result.first_seen   ?? null,
      lastSeen:     result.last_seen    ?? null,
    };
    return SRC((data.events.length ?? 0) > 0 ? "ok" : "clean", data);
  } catch {
    return SRC("error");
  }
}

// ── GreyNoise (community, sin key) ─────────────────────────────────────────────
// Señal #1 de triage IP: ¿es ruido de internet (escáneres) / servicio benigno
// conocido (RIOT) o un actor real? Community API es gratuita y sin key; si hay
// GREYNOISE_API_KEY se manda como header para subir el rate-limit.

async function enrichGreyNoise(ip, iocType) {
  if (iocType !== "ip") return SRC("na");
  if (!IPV4_RE.test(ip)) return SRC("na");
  // RFC1918 / loopback / link-local no tienen contexto público.
  if (isRfc1918(ip)) return SRC("na");

  const apiKey = await getResolvedKey("GREYNOISE_API_KEY");
  const { httpStatus, json } = await httpJson(
    `https://api.greynoise.io/v3/community/${ip}`,
    apiKey ? { headers: { key: apiKey, Accept: "application/json" } } : {},
  );
  if (httpStatus === 404) return SRC("clean");        // IP no observada por GreyNoise
  if (httpStatus === 429) return SRC("error");        // rate-limited
  if (!json || json.noise === undefined) return SRC("error");

  const data = {
    noise:          Boolean(json.noise),
    riot:           Boolean(json.riot),
    classification: json.classification ?? null,   // benign | malicious | unknown
    name:           json.name ?? null,
    link:           json.link ?? null,
    lastSeen:       json.last_seen ?? null,
  };
  return SRC("ok", data);
}

// ── ThreatFox (abuse.ch) ───────────────────────────────────────────────────────

async function enrichThreatFox(ioc) {
  const apiKey = await getResolvedKey("THREATFOX_API_KEY");
  const { httpStatus, json } = await httpJson(
    "https://threatfox-api.abuse.ch/api/v1/",
    {
      method:  "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "Auth-Key": apiKey } : {}),
      },
      body: JSON.stringify({ query: "search_ioc", search_term: ioc }),
    },
  );
  if (httpStatus === 401) return SRC("unconfigured"); // abuse.ch exige Auth-Key
  if (!json) return SRC("error");
  if (json.query_status === "no_result") return SRC("clean");
  if (json.query_status !== "ok" || !Array.isArray(json.data)) return SRC("error");

  const rows = json.data;
  const first = rows[0] ?? {};
  const data = {
    count:      rows.length,
    malware:    first.malware_printable ?? first.malware ?? null,
    threatType: first.threat_type ?? null,
    confidence: first.confidence_level ?? null,
    tags:       first.tags ?? [],
    firstSeen:  first.first_seen ?? null,
    reference:  first.reference ?? null,
  };
  return SRC("ok", data);
}

// ── AlienVault OTX ─────────────────────────────────────────────────────────────

async function enrichOtx(ioc, iocType) {
  const apiKey = await getResolvedKey("OTX_API_KEY");
  if (!apiKey) return SRC("unconfigured");

  const sectionMap = { ip: "IPv4", domain: "domain", hash: "file", url: "url" };
  const section = sectionMap[iocType] ?? "IPv4";
  const value = iocType === "url" ? encodeURIComponent(ioc) : encodeURIComponent(ioc);

  const { httpStatus, json } = await httpJson(
    `https://otx.alienvault.com/api/v1/indicators/${section}/${value}/general`,
    { headers: { "X-OTX-API-KEY": apiKey, Accept: "application/json" } },
  );
  if (httpStatus === 404) return SRC("clean");
  if (!json?.pulse_info) return SRC("error");

  const pi = json.pulse_info;
  const pulses = Array.isArray(pi.pulses) ? pi.pulses : [];
  const data = {
    pulseCount: pi.count ?? pulses.length,
    pulses:     pulses.slice(0, 5).map((p) => ({ name: p.name, tags: p.tags ?? [] })),
    tags:       [...new Set(pulses.flatMap((p) => p.tags ?? []))].slice(0, 15),
    malwareFamilies: (pi.related?.alienvault?.malware_families
      ?? pi.related?.other?.malware_families ?? []).slice(0, 10),
  };
  return SRC(data.pulseCount > 0 ? "ok" : "clean", data);
}

// ── Spamhaus (DNSBL, reusa pmgEnrichmentService) ───────────────────────────────

async function enrichSpamhaus(ioc, iocType) {
  try {
    if (iocType === "ip") {
      const r = await checkSpamhausIp(ioc);
      if (r?.private) return SRC("na");
      if (r?.error) return SRC("error");   // resolver falló → no concluir "limpio"
      const data = { listed: Boolean(r?.listed), labels: r?.labels ?? [], codes: r?.codes ?? [] };
      return SRC(data.listed ? "ok" : "clean", data);
    }
    if (iocType === "domain") {
      const r = await checkSpamhausDomain(ioc);
      if (r?.error) return SRC("error");
      const data = { listed: Boolean(r?.listed), label: r?.label ?? null, codes: r?.codes ?? [] };
      return SRC(data.listed ? "ok" : "clean", data);
    }
    return SRC("na");
  } catch {
    return SRC("error");
  }
}

// ── GeoIP (MaxMind local, autoritativo) ───────────────────────────────────────
// Fuente local/offline de country+asn. Si las bases .mmdb no están instaladas,
// devuelve status "unconfigured" (data null) y los callers caen al fallback por
// VT/Shodan/AbuseIPDB. Instantáneo: no pega a red, no consume cuota.

async function enrichGeoIp(ioc, iocType) {
  if (iocType !== "ip") return SRC("na");
  try {
    const [country, asn] = await Promise.all([geoCountry(ioc), geoAsn(ioc)]);
    if (country == null && asn == null) {
      // Sin datos: distinguir "base ausente" (unconfigured) de "IP privada/no
      // geolocalizable" (na) sería ideal, pero ambos dan null aquí; reportamos
      // "clean" sólo si la base respondió. Para no inducir error, usamos na.
      return SRC("na");
    }
    return SRC("ok", {
      country,
      asn:    asn?.asn ?? null,
      asnOrg: asn?.org ?? null,
    });
  } catch {
    return SRC("error");
  }
}

// ── Caché TTL in-memory (B3) ───────────────────────────────────────────────────
// Evita re-pegar a los proveedores en cada apertura de caso / re-render. El
// enriquecimiento de un IOC cambia lento; un TTL de minutos protege la cuota.

const _cache = new Map();
const CACHE_TTL_MS = (Number(process.env.IOC_ENRICH_CACHE_TTL_SEC) || 600) * 1000;
const CACHE_MAX = 2000;

// Deadline global del fan-out (I3 audit 2026-06-05). Cada fuente ya trae su
// propio AbortSignal en httpJson (8s), pero las que encadenan varias llamadas
// (MISP, Shodan, OTX) podían acumular 16-24s y bloquear la respuesta del panel.
// Envolvemos cada fuente con un deadline: la que no termina a tiempo se reporta
// como status "timeout" (data null) y no frena al resto. Como corren en
// paralelo, el fan-out completo queda acotado a ~IOC_ENRICH_FANOUT_MS.
const FANOUT_DEADLINE_MS = Number(process.env.IOC_ENRICH_FANOUT_MS) || 12_000;

function withDeadline(promise, ms = FANOUT_DEADLINE_MS) {
  let timer;
  const guard = new Promise((resolve) => {
    timer = setTimeout(() => resolve(SRC("timeout")), ms);
  });
  return Promise.race([
    Promise.resolve(promise).then((v) => { clearTimeout(timer); return v; }),
    guard,
  ]);
}

// Circuit breaker por-fuente (P1 audit flujo 2026-06-06). Antes, una API
// consistentemente caída/lenta pagaba el deadline completo (8-12s) en CADA
// apertura de caso porque el fan-out no tenía breaker. Ahora, tras N fallos
// consecutivos de una fuente, el breaker la abre y el resto de aperturas
// fallan-rápido para esa fuente (status "error") sin pegar a la red, hasta el
// cooldown. Estado visible en /api/health/breakers (getBreakerStats).
//
// El breaker cuenta como "fallo" sólo status error/timeout; ok/clean/
// unconfigured/na NO cuentan (no son fallos del proveedor). Las fuentes ya
// capturan internamente, así que re-lanzamos un error sintético para que el
// breaker lo registre, y lo reconvertimos al SRC original en el catch.
async function runSource(name, thunk) {
  try {
    return await withCircuitBreaker(
      `enrich:${name}`,
      async () => {
        const r = await withDeadline(Promise.resolve().then(thunk));
        if (r && (r.status === "error" || r.status === "timeout")) {
          const err = new Error(`${name}:${r.status}`);
          err.srcResult = r;
          throw err;
        }
        return r;
      },
      { cooldownMs: Number(process.env.IOC_ENRICH_BREAKER_COOLDOWN_MS) || 60_000 },
    );
  } catch (err) {
    // Breaker abierto (no se llamó a la fuente) → "error"; o fuente devolvió
    // error/timeout → recuperamos el SRC original.
    return err?.srcResult ?? SRC("error");
  }
}

function cacheKey(value, type) { return `${type}|${String(value).toLowerCase()}`; }

function cacheGet(key) {
  const hit = _cache.get(key);
  if (hit && Date.now() - hit.ts < CACHE_TTL_MS) return hit.result;
  if (hit) _cache.delete(key);
  return null;
}

function cacheSet(key, result) {
  if (_cache.size >= CACHE_MAX) {
    // Evicción simple del más viejo insertado.
    const oldest = _cache.keys().next().value;
    if (oldest) _cache.delete(oldest);
  }
  _cache.set(key, { ts: Date.now(), result });
}

// ── Orquestador principal ──────────────────────────────────────────────────────

/**
 * Enriquece un IOC en paralelo desde todas las fuentes disponibles.
 *
 * @param {string} iocValue  — valor del IOC (IP, dominio, hash, URL)
 * @param {string} iocType   — "ip" | "domain" | "hash" | "url"
 * @param {{force?: boolean}} [opts] — force omite la caché TTL
 * @returns {Promise<EnrichmentResult>}
 */
export async function enrichIoc(iocValue, iocType = "ip", opts = {}) {
  const key = cacheKey(iocValue, iocType);
  if (!opts.force) {
    const cached = cacheGet(key);
    if (cached) return { ...cached, fromCache: true };
  }

  const settled = await Promise.allSettled([
    runSource("virustotal", () => enrichVirusTotal(iocValue, iocType)),
    runSource("shodan",     () => enrichShodan(iocValue, iocType)),
    runSource("abuseipdb",  () => enrichAbuseIPDB(iocValue, iocType)),
    runSource("urlhaus",    () => checkUrlhaus(iocValue, iocType)),
    runSource("openphish",  () => checkOpenPhishSrc(iocValue, iocType)),
    runSource("misp",       () => enrichMisp(iocValue)),
    runSource("greynoise",  () => enrichGreyNoise(iocValue, iocType)),
    runSource("threatfox",  () => enrichThreatFox(iocValue)),
    runSource("otx",        () => enrichOtx(iocValue, iocType)),
    runSource("spamhaus",   () => enrichSpamhaus(iocValue, iocType)),
    runSource("geoip",      () => enrichGeoIp(iocValue, iocType)),
  ]);

  // Si el helper rechaza (no debería: capturan internamente) → error.
  const r = (i) => (settled[i].status === "fulfilled" ? settled[i].value : SRC("error"));
  const vt = r(0), shodan = r(1), abuse = r(2), urlhaus = r(3), openphish = r(4),
        misp = r(5), greynoise = r(6), threatfox = r(7), otx = r(8), spamhaus = r(9),
        geoip = r(10);

  const sources = {
    virustotal: vt.data,
    shodan:     shodan.data,
    abuseipdb:  abuse.data,
    urlhaus:    urlhaus.data,
    openphish:  openphish.data,
    misp:       misp.data,
    greynoise:  greynoise.data,
    threatfox:  threatfox.data,
    otx:        otx.data,
    spamhaus:   spamhaus.data,
    geoip:      geoip.data,
  };

  const status = {
    virustotal: vt.status,
    shodan:     shodan.status,
    abuseipdb:  abuse.status,
    urlhaus:    urlhaus.status,
    openphish:  openphish.status,
    misp:       misp.status,
    greynoise:  greynoise.status,
    threatfox:  threatfox.status,
    otx:        otx.status,
    spamhaus:   spamhaus.status,
    geoip:      geoip.status,
  };

  const summary = {
    vtMalicious:      vt.data?.malicious          ?? null,
    vtSuspicious:     vt.data?.suspicious         ?? null,
    abuseConfidence:  abuse.data?.abuseConfidenceScore ?? null,
    inUrlhaus:        urlhaus.data?.inFeed        ?? false,
    inOpenphish:      openphish.data?.inFeed      ?? false,
    inMisp:           (misp.data?.events?.length ?? 0) > 0,
    // GeoIP MaxMind es autoritativo (local, offline); APIs de intel como fallback.
    country:          geoip.data?.country ?? shodan.data?.country ?? vt.data?.country ?? abuse.data?.countryCode ?? null,
    asn:              geoip.data?.asn    ?? shodan.data?.asn ?? vt.data?.asn ?? null,
    asnOrg:           geoip.data?.asnOrg ?? shodan.data?.org ?? null,
    shodanPorts:      shodan.data?.ports          ?? [],
    shodanVulns:      shodan.data?.vulns          ?? [],
    mispThreatLevel:  misp.data?.threatLevel      ?? null,
    mispTags:         misp.data?.tags             ?? [],
    // Nuevas fuentes
    inThreatfox:      (threatfox.data?.count ?? 0) > 0,
    threatfoxMalware: threatfox.data?.malware     ?? null,
    spamhausListed:   spamhaus.data?.listed       ?? false,
    spamhausLabel:    spamhaus.data?.label ?? (spamhaus.data?.labels?.[0] ?? null),
    otxPulseCount:    otx.data?.pulseCount        ?? 0,
    greynoise:        greynoise.data
      ? { noise: greynoise.data.noise, riot: greynoise.data.riot,
          classification: greynoise.data.classification, name: greynoise.data.name }
      : null,
  };

  const verdict = computeIocVerdict({ summary, sources });

  const result = {
    iocValue,
    iocType,
    enrichedAt: new Date().toISOString(),
    sources,
    status,
    summary,
    verdict,
  };

  cacheSet(key, result);
  return result;
}

/**
 * screenIocMalice — criba LIGERA de un IOC sólo contra feeds keyless/baratos
 * (GreyNoise community, ThreatFox, OTX, Spamhaus DNSBL, URLhaus, OpenPhish). NO
 * toca VT/Shodan/AbuseIPDB/MISP → no quema cuota ni requiere infra. Pensado para
 * el gate de auto-cierre (R1 audit 2026-06-05): decidir si un LOW que iba a
 * auto-cerrarse es en realidad un IOC malicioso conocido que merece triaje.
 *
 * Reusa la caché por-IOC de enrichIoc indirectamente (cada fuente es barata).
 * Devuelve señales DURAS (no el score difuso de computeIocVerdict): un único
 * feed de malware/blocklist confirmado basta para NO cerrar. OTX exige ≥2 pulses
 * (un pulse aislado suele ser research benigno).
 *
 * @returns {{ malicious:boolean, reasons:string[], sources:object, status:object }}
 */
export async function screenIocMalice(iocValue, iocType) {
  const value = String(iocValue ?? "").trim();
  if (!value) return { malicious: false, reasons: [], sources: {}, status: {} };
  const type = iocType || guessIocType(value);

  const settled = await Promise.allSettled([
    runSource("greynoise",  () => enrichGreyNoise(value, type)),
    runSource("threatfox",  () => enrichThreatFox(value)),
    runSource("otx",        () => enrichOtx(value, type)),
    runSource("spamhaus",   () => enrichSpamhaus(value, type)),
    runSource("urlhaus",    () => checkUrlhaus(value, type)),
    runSource("openphish",  () => checkOpenPhishSrc(value, type)),
  ]);
  const r = (i) => (settled[i].status === "fulfilled" ? settled[i].value : SRC("error"));
  const greynoise = r(0), threatfox = r(1), otx = r(2), spamhaus = r(3),
        urlhaus = r(4), openphish = r(5);

  const reasons = [];
  if (threatfox.status === "ok" && (threatfox.data?.count ?? 0) > 0) {
    reasons.push(`ThreatFox${threatfox.data?.malware ? ` — ${threatfox.data.malware}` : ""}`);
  }
  if (urlhaus.status === "ok" && urlhaus.data?.inFeed) {
    reasons.push("URLhaus (host/URL de malware activo)");
  }
  if (openphish.status === "ok" && openphish.data?.inFeed) {
    reasons.push("OpenPhish (phishing activo)");
  }
  if (spamhaus.status === "ok" && spamhaus.data?.listed) {
    const lbl = spamhaus.data?.label ?? spamhaus.data?.labels?.[0] ?? null;
    reasons.push(`Spamhaus${lbl ? ` — ${lbl}` : ""}`);
  }
  if (greynoise.status === "ok" && greynoise.data?.classification === "malicious") {
    reasons.push("GreyNoise: scanner malicioso");
  }
  if (otx.status === "ok" && (otx.data?.pulseCount ?? 0) >= 2) {
    reasons.push(`AlienVault OTX: ${otx.data.pulseCount} pulses`);
  }

  // Señal BENIGNA (P1, 2026-06-16): GreyNoise marca la IP como servicio/escáner
  // benigno conocido (RIOT) o classification=benign. Sirve al gate de apertura
  // para NO abrir caso de ruido benigno conocido. `malicious` siempre gana: si
  // hay cualquier señal dura de amenaza, la IP no se considera benigna.
  const benignReasons = [];
  if (greynoise.status === "ok" &&
      (greynoise.data?.riot || greynoise.data?.classification === "benign")) {
    benignReasons.push(greynoise.data?.name
      ? `GreyNoise RIOT: ${greynoise.data.name}`
      : "GreyNoise: escáner/servicio benigno conocido");
  }

  return {
    malicious: reasons.length > 0,
    reasons,
    benign: reasons.length === 0 && benignReasons.length > 0,
    benignReasons,
    sources: { greynoise: greynoise.data, threatfox: threatfox.data, otx: otx.data,
               spamhaus: spamhaus.data, urlhaus: urlhaus.data, openphish: openphish.data },
    status:  { greynoise: greynoise.status, threatfox: threatfox.status, otx: otx.status,
               spamhaus: spamhaus.status, urlhaus: urlhaus.status, openphish: openphish.status },
  };
}

/**
 * Enriquece un caso completo (puede tener múltiples IOCs en el futuro).
 * Por ahora, enriquece el IOC principal.
 */
export async function enrichCase(caseData) {
  const iocValue = caseData.iocValue ?? caseData.ioc_value ?? caseData.srcIp;
  const iocType  = caseData.iocType  ?? caseData.ioc_type  ?? "ip";
  if (!iocValue) return null;
  return enrichIoc(iocValue, iocType);
}
