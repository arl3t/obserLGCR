/**
 * geoipService.mjs — Resolución GeoIP autoritativa vía MaxMind GeoLite2 (mmdb).
 *
 * Fuente local y offline de `country_code` y `ASN`, en reemplazo de depender
 * únicamente de las respuestas de VT/Shodan/AbuseIPDB (que requieren API key,
 * conocer la IP y responder dentro del deadline; si fallan, el geo-risk caía a
 * 1.00 en silencio — ver audit flujo 2026-06-06, P0/P1).
 *
 * Diseño:
 *  · Lee las bases .mmdb desde rutas configurables. Si NO existen, el servicio
 *    queda "no disponible" y `lookupCountry`/`lookupAsn` devuelven null → los
 *    callers caen al fallback por APIs de intel. Nunca lanza.
 *  · Lazy-load del reader + recarga automática cuando cambia el mtime del .mmdb
 *    (el actualizador semanal reemplaza el archivo en caliente).
 *  · Sin dependencia de red: `maxmind.open` mapea el archivo local.
 *
 * Variables de entorno:
 *   MAXMIND_DB_DIR        Directorio base (default: <repo>/data/geoip)
 *   MAXMIND_COUNTRY_DB    Ruta al GeoLite2-Country.mmdb (default: <dir>/GeoLite2-Country.mmdb)
 *   MAXMIND_ASN_DB        Ruta al GeoLite2-ASN.mmdb     (default: <dir>/GeoLite2-ASN.mmdb)
 *   MAXMIND_RELOAD_SEC    Intervalo mínimo entre chequeos de mtime (default: 300)
 *
 * Descarga/actualización: scripts/update-geoip.sh (requiere MAXMIND_LICENSE_KEY).
 */

import { statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import maxmind from "maxmind";
import { logger } from "../logger.mjs";
import { isRfc1918 } from "./netClass.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_DIR = process.env.MAXMIND_DB_DIR || join(__dirname, "..", "..", "data", "geoip");

const COUNTRY_DB = process.env.MAXMIND_COUNTRY_DB || join(DEFAULT_DIR, "GeoLite2-Country.mmdb");
const ASN_DB     = process.env.MAXMIND_ASN_DB     || join(DEFAULT_DIR, "GeoLite2-ASN.mmdb");
const RELOAD_MS  = (Number(process.env.MAXMIND_RELOAD_SEC) || 300) * 1000;

/**
 * @typedef {Object} ReaderSlot
 * @property {import("maxmind").Reader<any>|null} reader
 * @property {number} mtimeMs    mtime del archivo cargado (0 = nunca)
 * @property {number} checkedAt  último chequeo de mtime (epoch ms)
 * @property {boolean} missingLogged
 */

/** @type {Record<string, ReaderSlot>} */
const slots = {
  country: { reader: null, mtimeMs: 0, checkedAt: 0, missingLogged: false, loading: null },
  asn:     { reader: null, mtimeMs: 0, checkedAt: 0, missingLogged: false, loading: null },
};

const PATHS = { country: COUNTRY_DB, asn: ASN_DB };

/** Carga (o recarga si cambió el mtime) el reader del slot. Devuelve el reader o null. */
async function getReader(kind) {
  const slot = slots[kind];
  const path = PATHS[kind];
  const now = Date.now();

  // No re-stat en cada lookup: respetar el intervalo de recarga salvo primera vez.
  if (slot.reader && now - slot.checkedAt < RELOAD_MS) return slot.reader;

  // Coalescing: si ya hay una carga/recarga en vuelo, esperar ESA en vez de abrir
  // el .mmdb otra vez. Sin esto, un Promise.all de cientos de lookups en frío
  // dispara cientos de `maxmind.open` concurrentes (thundering herd) — visto en
  // _topCountries (503 IPs → ~280 cargas del archivo en una sola corrida).
  if (slot.loading) return slot.loading;

  slot.loading = (async () => {
    let st;
    try {
      st = statSync(path);
    } catch {
      if (!slot.missingLogged) {
        logger.warn?.(`[geoip] base ${kind} no encontrada en ${path} — fallback a APIs de intel`);
        slot.missingLogged = true;
      }
      slot.reader = null;
      slot.checkedAt = now;
      return null;
    }

    slot.checkedAt = now;
    // Reusar el reader si el archivo no cambió.
    if (slot.reader && st.mtimeMs === slot.mtimeMs) return slot.reader;

    try {
      const reader = await maxmind.open(path);
      slot.reader = reader;
      slot.mtimeMs = st.mtimeMs;
      slot.missingLogged = false;
      logger.info?.(`[geoip] base ${kind} cargada desde ${path}`);
      return reader;
    } catch (err) {
      logger.error?.(`[geoip] error abriendo ${kind} (${path}): ${err?.message ?? err}`);
      slot.reader = null;
      return null;
    }
  })().finally(() => { slot.loading = null; });

  return slot.loading;
}

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const IPV6_RE = /^[0-9a-f:]+$/i;

function isLookupableIp(ip) {
  const v = String(ip ?? "").trim();
  if (!v) return false;
  if (IPV4_RE.test(v)) {
    // Excluir RFC1918 / loopback / link-local: MaxMind no los geolocaliza.
    if (isRfc1918(v)) return false;
    return true;
  }
  return IPV6_RE.test(v) && v.includes(":");
}

/**
 * Resuelve el país (ISO 3166-1 alpha-2) de una IP pública vía MaxMind.
 * @param {string} ip
 * @returns {Promise<string|null>} ej. "RU", o null si no disponible/privada.
 */
export async function lookupCountry(ip) {
  if (!isLookupableIp(ip)) return null;
  const reader = await getReader("country");
  if (!reader) return null;
  try {
    const rec = reader.get(String(ip).trim());
    const iso = rec?.country?.iso_code || rec?.registered_country?.iso_code || null;
    return iso ? String(iso).toUpperCase().slice(0, 2) : null;
  } catch {
    return null;
  }
}

/**
 * Resuelve el ASN de una IP pública vía MaxMind.
 * @param {string} ip
 * @returns {Promise<{asn:number, org:string|null}|null>}
 */
export async function lookupAsn(ip) {
  if (!isLookupableIp(ip)) return null;
  const reader = await getReader("asn");
  if (!reader) return null;
  try {
    const rec = reader.get(String(ip).trim());
    const asn = rec?.autonomous_system_number;
    if (asn == null) return null;
    return { asn: Number(asn), org: rec?.autonomous_system_organization ?? null };
  } catch {
    return null;
  }
}

/** Estado del servicio (para /api/health y diagnóstico). */
export async function geoipStatus() {
  const country = await getReader("country");
  const asn = await getReader("asn");
  return {
    available: Boolean(country),
    country: { configured: PATHS.country, loaded: Boolean(country) },
    asn:     { configured: PATHS.asn,     loaded: Boolean(asn) },
  };
}

/** True si al menos la base de país está disponible. */
export async function geoipAvailable() {
  return Boolean(await getReader("country"));
}
