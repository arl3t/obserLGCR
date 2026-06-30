/**
 * pmgEnrichmentService.mjs — Enriquecimiento de threat intelligence para email/phishing.
 *
 * Fuentes:
 *   · AbuseIPDB    — reputación de IP remitente (confidence score)
 *   · Spamhaus DNS — consulta DNS contra zonas zen.spamhaus.org, dbl.spamhaus.org
 *   · MXToolbox    — DNSBL multi-lista vía API (requiere MXTOOLBOX_API_KEY)
 *   · OpenPhish    — feed de phishing URLs (caché in-memory, TTL configurable)
 *
 * Diseño:
 *   - Todas las llamadas son best-effort (null en caso de error / falta de clave).
 *   - Caché in-memory por clave (ip / domain / url) con TTL configurable.
 *   - Rate limits: AbuseIPDB 1000/día free, MXToolbox 100/mes free; la caché
 *     reduce llamadas efectivas drásticamente.
 *   - El enriquecimiento se llama bajo demanda desde la ruta GET /api/pmg/enrich,
 *     NO en tiempo real durante la ingesta (eso lo haría Vector HTTP sink, pero
 *     añadiría latencia y complejidad de secretos en la VM pública).
 *
 * Variables de entorno:
 *   ABUSEIPDB_API_KEY      — clave API AbuseIPDB (ya existe en enrichmentService.mjs)
 *   MXTOOLBOX_API_KEY      — clave API MXToolbox (nueva)
 *   PMG_OPENPHISH_TTL_SEC  — TTL caché feed OpenPhish (default: 14400 = 4 h)
 *   PMG_ENRICH_CACHE_TTL_SEC — TTL caché enriquecimiento por IP/dominio/URL (default: 3600)
 */

import { promises as dns } from "node:dns";
import { isRfc1918 } from "./netClass.mjs";
import { getResolvedKey } from "./apiKeysService.mjs";

/**
 * Distingue una respuesta DNS de "no existe el registro" (la IP/dominio NO está
 * en la blocklist → limpio) de un fallo del resolver (SERVFAIL, timeout, refused
 * → sin datos, NO concluir "limpio"). Sin esto, un resolver caído marcaba todo
 * como no-listado (falsos negativos de blocklist). Audit flujo P0 2026-06-06.
 */
function isDnsNotFound(err) {
  return err?.code === "ENOTFOUND" || err?.code === "ENODATA";
}

// ── Caché in-memory ───────────────────────────────────────────────────────────

const ENRICH_TTL_MS =
  (Number(process.env.PMG_ENRICH_CACHE_TTL_SEC ?? 3600) || 3600) * 1000;

const OPENPHISH_TTL_MS =
  (Number(process.env.PMG_OPENPHISH_TTL_SEC ?? 14400) || 14400) * 1000;

/** @type {Map<string, { data: any, ts: number }>} */
const _cache = new Map();

function cacheGet(key) {
  const entry = _cache.get(key);
  if (!entry) return undefined;
  if (Date.now() - entry.ts > ENRICH_TTL_MS) {
    _cache.delete(key);
    return undefined;
  }
  return entry.data;
}

function cacheSet(key, data) {
  _cache.set(key, { data, ts: Date.now() });
  // Cleanup: purge entries older than 2× TTL to prevent unbounded growth
  if (_cache.size > 2000) {
    const cutoff = Date.now() - ENRICH_TTL_MS * 2;
    for (const [k, v] of _cache.entries()) {
      if (v.ts < cutoff) _cache.delete(k);
    }
  }
}

// ── OpenPhish feed state ──────────────────────────────────────────────────────

/** @type {{ urls: Set<string>, ts: number } | null} */
let _openphishFeed = null;
let _openphishFetching = false;

// ── Helpers ───────────────────────────────────────────────────────────────────

async function safeFetch(url, opts = {}, timeoutMs = 10_000) {
  try {
    const res = await fetch(url, {
      ...opts,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

async function safeFetchJson(url, opts = {}, timeoutMs = 10_000) {
  const text = await safeFetch(url, opts, timeoutMs);
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async function enrichAbuseIPDB(ip) {
  const apiKey = await getResolvedKey("ABUSEIPDB_API_KEY");
  if (!apiKey) return null;
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return null;

  const data = await safeFetchJson(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    { headers: { Key: apiKey, Accept: "application/json" } },
  );
  if (!data?.data) return null;

  const d = data.data;
  return {
    abuseConfidenceScore: d.abuseConfidenceScore ?? 0,
    totalReports:         d.totalReports         ?? 0,
    numDistinctUsers:     d.numDistinctUsers      ?? 0,
    countryCode:          d.countryCode           ?? null,
    isp:                  d.isp                   ?? null,
    domain:               d.domain                ?? null,
    isWhitelisted:        d.isWhitelisted          ?? false,
    lastReportedAt:       d.lastReportedAt         ?? null,
    usageType:            d.usageType              ?? null,
    permalink:            `https://www.abuseipdb.com/check/${ip}`,
  };
}

// ── Spamhaus DNS Blocklist ────────────────────────────────────────────────────
//
// Zonas consultadas:
//   zen.spamhaus.org  → IPs (SBL + XBL + PBL combinados)
//   dbl.spamhaus.org  → dominios
//
// Códigos de retorno (A records):
//   127.0.0.2  = SBL (Spamhaus Block List — spammers)
//   127.0.0.3  = SBL CSS (snowshoe)
//   127.0.0.4-7 = XBL (Exploits Block List)
//   127.0.0.10-11 = PBL (Policy Block List — IPs dinámica)

const SPAMHAUS_CODES = {
  "127.0.0.2":  "SBL (spammer)",
  "127.0.0.3":  "SBL-CSS (snowshoe spam)",
  "127.0.0.4":  "XBL-CBL (malware botnet)",
  "127.0.0.5":  "XBL-CBL (malware botnet)",
  "127.0.0.6":  "XBL-CBL (malware botnet)",
  "127.0.0.7":  "XBL-CBL (malware botnet)",
  "127.0.0.10": "PBL (política ISP)",
  "127.0.0.11": "PBL (política Spamhaus)",
};

export async function checkSpamhausIp(ip) {
  // Validar IPv4 simple
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return { listed: false, codes: [], labels: [] };
  }
  // Ignorar RFC1918 / loopback / link-local
  if (isRfc1918(ip)) {
    return { listed: false, codes: [], labels: [], private: true };
  }

  const reversed = ip.split(".").reverse().join(".");
  try {
    const records = await dns.resolve4(`${reversed}.zen.spamhaus.org`);
    const labels = records
      .map((r) => SPAMHAUS_CODES[r] ?? `desconocido(${r})`)
      .filter(Boolean);
    return { listed: true, codes: records, labels };
  } catch (err) {
    // NXDOMAIN/NODATA = respuesta válida "no listado". SERVFAIL/timeout/refused
    // = el resolver falló → NO es "limpio", es "sin datos" (audit P0 2026-06-06).
    if (isDnsNotFound(err)) return { listed: false, codes: [], labels: [] };
    return { listed: false, codes: [], labels: [], error: true, errorCode: err?.code ?? "DNS_ERROR" };
  }
}

export async function checkSpamhausDomain(domain) {
  if (!domain || domain.length > 253) return { listed: false };
  // Solo dominios públicos
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) return { listed: false };

  try {
    const records = await dns.resolve4(`${domain}.dbl.spamhaus.org`);
    return {
      listed: true,
      codes:  records,
      label:  records.includes("127.0.1.2")
        ? "phishing"
        : records.includes("127.0.1.4")
          ? "malware"
          : records.includes("127.0.1.5")
            ? "botnet C&C"
            : "spam domain",
    };
  } catch (err) {
    if (isDnsNotFound(err)) return { listed: false };
    return { listed: false, error: true, errorCode: err?.code ?? "DNS_ERROR" };
  }
}

// ── MXToolbox DNSBL ───────────────────────────────────────────────────────────
// API free tier: ~100 lookups/mes. Usar solo si MXTOOLBOX_API_KEY está definido.
// Endpoint: GET https://api.mxtoolbox.com/api/v1/lookup/blacklist/<ip>

async function checkMxToolbox(ip) {
  const apiKey = await getResolvedKey("MXTOOLBOX_API_KEY");
  if (!apiKey) return null;
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return null;

  const data = await safeFetchJson(
    `https://api.mxtoolbox.com/api/v1/lookup/blacklist/${ip}`,
    { headers: { Authorization: apiKey, Accept: "application/json" } },
    15_000,
  );
  if (!data) return null;

  const failed  = (data.Failed  ?? []).length;
  const passed  = (data.Passed  ?? []).length;
  const failedItems = (data.Failed ?? [])
    .slice(0, 5)
    .map((f) => f.Name ?? f.name ?? "(desconocida)");

  return {
    blacklisted:  failed > 0,
    failedCount:  failed,
    passedCount:  passed,
    failedLists:  failedItems,
    permalink:    `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${ip}`,
  };
}

// ── OpenPhish Feed ────────────────────────────────────────────────────────────
// Feed público gratuito: lista de URLs de phishing activas.
// Se descarga una vez cada PMG_OPENPHISH_TTL_SEC y se mantiene en memoria.

const OPENPHISH_FEED_URL =
  process.env.PMG_OPENPHISH_FEED_URL ??
  "https://openphish.com/feed.txt";

async function getOpenPhishFeed() {
  const now = Date.now();
  if (_openphishFeed && now - _openphishFeed.ts < OPENPHISH_TTL_MS) {
    return _openphishFeed.urls;
  }
  // Evitar fetches paralelos concurrentes
  if (_openphishFetching) {
    return _openphishFeed?.urls ?? new Set();
  }
  _openphishFetching = true;
  try {
    const text = await safeFetch(OPENPHISH_FEED_URL, {}, 20_000);
    if (text) {
      const urls = new Set(
        text.split("\n")
          .map((u) => u.trim().toLowerCase())
          .filter((u) => u.startsWith("http")),
      );
      _openphishFeed = { urls, ts: now };
      return urls;
    }
  } finally {
    _openphishFetching = false;
  }
  return _openphishFeed?.urls ?? new Set();
}

export async function checkOpenPhish(url) {
  if (!url) return { inFeed: false };
  try {
    const feed = await getOpenPhishFeed();
    const normalized = url.trim().toLowerCase();
    // Exact match o match de hostname
    if (feed.has(normalized)) return { inFeed: true, matchType: "exact" };
    try {
      const urlHost = new URL(normalized).hostname;
      for (const feedUrl of feed) {
        try {
          if (new URL(feedUrl).hostname === urlHost) {
            return { inFeed: true, matchType: "hostname", matchedHost: urlHost };
          }
        } catch { /* skip */ }
      }
    } catch { /* URL inválida */ }
    return { inFeed: false };
  } catch {
    return { inFeed: false };
  }
}

// ── Orquestador principal ─────────────────────────────────────────────────────

/**
 * Enriquece un evento PMG con datos de threat intelligence.
 *
 * @param {{ ip?: string, domain?: string, url?: string }} opts
 * @returns {Promise<PmgEnrichmentResult>}
 */
export async function enrichPmgEvent({ ip, domain, url } = {}) {
  const cacheKey = `pmg:${ip ?? ""}:${domain ?? ""}:${url ?? ""}`;
  const cached = cacheGet(cacheKey);
  if (cached !== undefined) return { ...cached, fromCache: true };

  // Ejecutar todas las fuentes en paralelo
  const [abuseRes, spamhausIpRes, spamhausDomRes, mxtoolRes, openphishRes] =
    await Promise.allSettled([
      ip     ? enrichAbuseIPDB(ip)                : Promise.resolve(null),
      ip     ? checkSpamhausIp(ip)               : Promise.resolve(null),
      domain ? checkSpamhausDomain(domain)        : Promise.resolve(null),
      ip     ? checkMxToolbox(ip)                 : Promise.resolve(null),
      url    ? checkOpenPhish(url)                : Promise.resolve(null),
    ]);

  const get = (r) => (r.status === "fulfilled" ? r.value : null);

  const abuseData      = get(abuseRes);
  const spamhausIp     = get(spamhausIpRes);
  const spamhausDomain = get(spamhausDomRes);
  const mxtool         = get(mxtoolRes);
  const openphish      = get(openphishRes);

  // Calcular score de riesgo agregado (0-100)
  let riskScore = 0;
  if (abuseData)      riskScore += Math.round((abuseData.abuseConfidenceScore ?? 0) * 0.4);
  if (spamhausIp?.listed)     riskScore += 35;
  if (spamhausDomain?.listed) riskScore += 20;
  if (mxtool?.blacklisted)    riskScore += 20;
  if (openphish?.inFeed)      riskScore += 25;
  riskScore = Math.min(100, riskScore);

  const result = {
    ip:     ip     ?? null,
    domain: domain ?? null,
    url:    url    ?? null,
    enrichedAt: new Date().toISOString(),
    riskScore,
    riskLevel:
      riskScore >= 75 ? "critical"
      : riskScore >= 50 ? "high"
      : riskScore >= 25 ? "medium"
      : riskScore > 0   ? "low"
      : "clean",
    sources: {
      abuseipdb:     abuseData,
      spamhausIp:    spamhausIp,
      spamhausDomain: spamhausDomain,
      mxtoolbox:     mxtool,
      openphish:     openphish,
    },
    summary: {
      abuseConfidence:      abuseData?.abuseConfidenceScore    ?? null,
      spamhausListed:       spamhausIp?.listed                 ?? false,
      spamhausLabels:       spamhausIp?.labels                 ?? [],
      spamhausDomainListed: spamhausDomain?.listed             ?? false,
      spamhausDomainLabel:  spamhausDomain?.label              ?? null,
      mxtoolboxBlacklisted: mxtool?.blacklisted                ?? false,
      mxtoolboxFailedLists: mxtool?.failedLists                ?? [],
      inOpenPhish:          openphish?.inFeed                  ?? false,
      openPhishMatchType:   openphish?.matchType               ?? null,
      country:              abuseData?.countryCode             ?? null,
      isp:                  abuseData?.isp                     ?? null,
    },
    fromCache: false,
  };

  cacheSet(cacheKey, result);
  return result;
}

/**
 * Estadísticas del caché de enriquecimiento (para endpoint de diagnóstico).
 */
export function pmgEnrichmentCacheStats() {
  return {
    entries:         _cache.size,
    ttlSec:          Math.round(ENRICH_TTL_MS / 1000),
    openphishLoaded: Boolean(_openphishFeed),
    openphishUrls:   _openphishFeed?.urls?.size ?? 0,
    openphishAgeSec: _openphishFeed
      ? Math.round((Date.now() - _openphishFeed.ts) / 1000)
      : null,
    openphishTtlSec: Math.round(OPENPHISH_TTL_MS / 1000),
  };
}
