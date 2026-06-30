/**
 * Reverse DNS vía ip.thc.org (API JSON) + lectura opcional de thc_rdns_results en Iceberg.
 * @see https://ip.thc.org/docs/API/reverse-dns-lookup
 */

const THC_URL_DEFAULT = "https://ip.thc.org/api/v1/lookup";
const THC_MIN_INTERVAL_MS = 2100;

let _lastThcCallMs = 0;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export function safeIcebergIdent(raw, fallback) {
  const t = String(raw ?? fallback).trim();
  return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(t) ? t : fallback;
}

/** IPv4 pública (misma idea que threat_intel: no RFC1918 / loopback / link-local). */
export function parsePublicIpv4(raw) {
  const s = String(raw ?? "").trim();
  if (!/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s)) return null;
  const parts = s.split(".").map((x) => Number(x));
  if (parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  const [a, b] = parts;
  if (a === 10) return null;
  if (a === 127) return null;
  if (a === 0) return null;
  if (a === 172 && b >= 16 && b <= 31) return null;
  if (a === 192 && b === 168) return null;
  if (a === 169 && b === 254) return null;
  if (a === 100 && b >= 64 && b <= 127) return null;
  return s;
}

function sqlEscapeIp(ip) {
  return String(ip).replace(/'/g, "''");
}

/**
 * @param {((q: string) => Promise<unknown[]>) | null} runTrinoQuery
 * @param {string} fqtn catalog.schema.table
 * @param {string} ip
 */
export async function fetchLatestThcRdnsRow(runTrinoQuery, fqtn, ip) {
  if (!runTrinoQuery) return null;
  const esc = sqlEscapeIp(ip);
  const sql = `
SELECT matching_records, domain_sample_count, domains_json,
       CAST(query_ts AS varchar) AS query_ts
FROM ${fqtn}
WHERE ip = '${esc}'
ORDER BY query_ts DESC
LIMIT 1
`.trim();
  try {
    const rows = await runTrinoQuery(sql);
    const row = rows?.[0];
    if (!row || typeof row !== "object") return null;
    return row;
  } catch {
    return null;
  }
}

export function parseDomainsJsonColumn(raw) {
  if (raw == null) return [];
  if (Array.isArray(raw)) {
    return raw.map((x) => String(x).trim()).filter(Boolean);
  }
  const s = String(raw).trim();
  if (!s.startsWith("[")) return [];
  try {
    const j = JSON.parse(s);
    return Array.isArray(j) ? j.map((x) => String(x).trim()).filter(Boolean) : [];
  } catch {
    return [];
  }
}

/**
 * @param {string} ip
 * @param {{ limit?: number, baseUrl?: string }} opts
 */
export async function fetchThcReverseDnsLive(ip, opts = {}) {
  const limit = Math.max(1, Math.min(120, Number(opts.limit) || 40));
  const url = (opts.baseUrl || process.env.THC_RDNS_API_URL || THC_URL_DEFAULT).trim();

  const now = Date.now();
  const wait = THC_MIN_INTERVAL_MS - (now - _lastThcCallMs);
  if (wait > 0) await sleep(wait);
  _lastThcCallMs = Date.now();

  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 45_000);
  let r;
  try {
    r = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "legacyhunt-api/1.0",
      },
      body: JSON.stringify({ ip_address: ip, limit }),
      signal: ac.signal,
    });
  } finally {
    clearTimeout(t);
  }

  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return {
      httpStatus: r.status,
      error: "respuesta no JSON",
      matching_records: 0,
      domains: [],
      rawSnippet: text.slice(0, 500),
    };
  }

  if (!r.ok || (body && body.status === "error")) {
    return {
      httpStatus: r.status,
      error: typeof body?.error === "string" ? body.error : r.statusText || "error THC",
      matching_records: 0,
      domains: [],
      body,
    };
  }

  const matching = Number(body?.matching_records) || 0;
  const doms = Array.isArray(body?.domains) ? body.domains : [];
  const domains = doms
    .map((d) => (typeof d === "object" && d && d.domain ? String(d.domain).trim() : ""))
    .filter(Boolean);

  return {
    httpStatus: r.status,
    error: null,
    matching_records: matching,
    domains,
    has_more: Boolean(body?.next_page_state),
    body,
  };
}
