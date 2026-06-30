/**
 * services/apiKeysService.mjs — gestión de API keys de fuentes de inteligencia.
 *
 * Resuelve cada key como DB (cifrada) → fallback `process.env`. Esto permite
 * editarlas desde Ajustes (ADMIN) sin reiniciar el contenedor, manteniendo el
 * `.env` como respaldo. Sólo claves del CATÁLOGO threat-intel; NO secretos de
 * infra (AWS/Trino/OIDC/VAPID).
 *
 * Cifrado en reposo: AES-256-GCM con master key `SETTINGS_ENC_KEY` (.env).
 * Formato almacenado: base64(iv).base64(authTag).base64(ciphertext).
 *
 * Tabla: legacyhunt_soc.integration_credentials (migración 082).
 */

import crypto from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

// ── Catálogo de claves editables (solo threat-intel) ─────────────────────────
// `name` = nombre canónico de env que consultan los consumidores.
// `aliases` = otros env equivalentes aceptados como fallback (compat histórica).
// `tier`: modelo de acceso de la fuente — usado por la UI de Ajustes para
// resaltar cuáles requieren licencia/suscripción de PAGO ("paid") vs free-tier
// con clave ("freemium") vs gratis/self-hosted ("free").
//   paid     → requiere licencia/suscripción de pago para obtener la clave.
//   freemium → free tier con clave (premium opcional, no obligatorio).
//   free     → sin costo: clave opcional, API pública o self-hosted.
export const CATALOG = [
  { name: "VT_API_KEY",          label: "VirusTotal",       aliases: ["VIRUSTOTAL_TOKEN"], docUrl: "https://www.virustotal.com/gui/my-apikey", tier: "freemium" },
  { name: "SHODAN_API_KEY",      label: "Shodan",           aliases: ["SHODAN_TOKEN"],     docUrl: "https://account.shodan.io", tier: "paid" },
  { name: "ABUSEIPDB_API_KEY",   label: "AbuseIPDB",        aliases: ["ABUSE_IPDB_API_KEY"], docUrl: "https://www.abuseipdb.com/account/api", tier: "freemium" },
  { name: "GREYNOISE_API_KEY",   label: "GreyNoise",        aliases: [], docUrl: "https://viz.greynoise.io/account/api-key", tier: "freemium" },
  { name: "OTX_API_KEY",         label: "AlienVault OTX",   aliases: [], docUrl: "https://otx.alienvault.com/api", tier: "free" },
  { name: "THREATFOX_API_KEY",   label: "ThreatFox (Abuse.ch)", aliases: [], docUrl: "https://threatfox.abuse.ch/api/", tier: "free" },
  { name: "MISP_API_KEY",        label: "MISP",             aliases: [], docUrl: null, tier: "free" },
  { name: "NVD_API_KEY",         label: "NVD (NIST CVE)",   aliases: [], docUrl: "https://nvd.nist.gov/developers/request-an-api-key", tier: "free" },
  { name: "MXTOOLBOX_API_KEY",   label: "MXToolbox",        aliases: [], docUrl: "https://mxtoolbox.com/restapi.aspx", tier: "freemium" },
  { name: "BRAND24_API_KEY",     label: "Brand24",          aliases: [], docUrl: "https://brand24.com", tier: "paid" },
  { name: "CTI_CLOUDYOLE_API_KEY", label: "CTI Cloud & Olé", aliases: [], docUrl: null, tier: "paid" },
  // Telegram CTI (MTProto / cuenta de usuario). API ID/Hash se obtienen gratis en
  // my.telegram.org; SESSION es el StringSession generado una vez tras el login
  // (teléfono+código). Los consume el DAG telegram_cti (F2), no la API en F1.
  { name: "TELEGRAM_API_ID",     label: "Telegram API ID",            aliases: [], docUrl: "https://my.telegram.org/apps", tier: "free" },
  { name: "TELEGRAM_API_HASH",   label: "Telegram API Hash",          aliases: [], docUrl: "https://my.telegram.org/apps", tier: "free" },
  { name: "TELEGRAM_SESSION",    label: "Telegram Session (MTProto)", aliases: [], docUrl: null, tier: "free" },
];

const CATALOG_BY_NAME = new Map(CATALOG.map((c) => [c.name, c]));

/** ¿`name` es una clave editable conocida? */
export function isKnownKey(name) {
  return CATALOG_BY_NAME.has(name);
}

// ── Cifrado AES-256-GCM ──────────────────────────────────────────────────────
function masterKey() {
  const raw = (process.env.SETTINGS_ENC_KEY ?? "").trim();
  if (!raw) return null;
  // Deriva 32 bytes deterministas desde el secreto del .env.
  return crypto.createHash("sha256").update(raw, "utf8").digest();
}

/** ¿Está disponible el cifrado? (master key presente) — gate de escritura. */
export function encryptionAvailable() {
  return masterKey() !== null;
}

function encrypt(plain) {
  const key = masterKey();
  if (!key) throw new Error("SETTINGS_ENC_KEY no configurada — cifrado no disponible");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}.${tag.toString("base64")}.${ct.toString("base64")}`;
}

function decrypt(stored) {
  const key = masterKey();
  if (!key) throw new Error("SETTINGS_ENC_KEY no configurada");
  const [ivB64, tagB64, ctB64] = String(stored).split(".");
  if (!ivB64 || !tagB64 || !ctB64) throw new Error("formato cifrado inválido");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]).toString("utf8");
}

// ── Caché del snapshot DB (TTL) ──────────────────────────────────────────────
const TTL_MS = 30_000;
let _cache = new Map();   // key_name → { value, updatedBy, updatedAt }
let _cachedAt = 0;
let _refreshing = null;

async function _refresh() {
  const rows = await pgQuery(
    `SELECT key_name, value_enc, updated_by, updated_at
       FROM legacyhunt_soc.integration_credentials`,
  );
  const m = new Map();
  for (const r of rows) {
    try {
      m.set(r.key_name, { value: decrypt(r.value_enc), updatedBy: r.updated_by, updatedAt: r.updated_at });
    } catch (e) {
      logger.warn({ key: r.key_name, err: e.message }, "[apiKeys] no se pudo descifrar (¿cambió SETTINGS_ENC_KEY?)");
    }
  }
  _cache = m;
  _cachedAt = Date.now();
}

async function _ensureFresh() {
  if (Date.now() - _cachedAt <= TTL_MS) return;
  if (!_refreshing) {
    _refreshing = _refresh().catch((e) => {
      logger.warn({ err: e.message }, "[apiKeys] refresh falló, uso caché previa");
    }).finally(() => { _refreshing = null; });
  }
  await _refreshing;
}

/** Hidrata el caché al boot (no lanza). */
export async function primeApiKeysCache() {
  try { await _refresh(); } catch (e) { logger.warn({ err: e.message }, "[apiKeys] prime falló"); }
}

function _envFallback(name) {
  const meta = CATALOG_BY_NAME.get(name);
  for (const en of [name, ...(meta?.aliases ?? [])]) {
    const v = (process.env[en] ?? "").trim();
    if (v) return v;
  }
  return null;
}

/**
 * Resuelve el valor efectivo de una key: DB (cifrada) → fallback .env.
 * @returns {Promise<string|null>}
 */
export async function getResolvedKey(name) {
  await _ensureFresh();
  const hit = _cache.get(name);
  if (hit?.value) return hit.value;
  return _envFallback(name);
}

/**
 * Variante síncrona: lee el snapshot en memoria (cebado al boot y refrescado por
 * cualquier lectura async / por setKey-clearKey) → fallback `.env`. No bloquea ni
 * toca la DB; si el caché está vencido dispara un refresh en background para que
 * la *próxima* lectura esté fresca. Para consumidores en contexto síncrono
 * (p.ej. getMispConfig/getCtiConfig) donde no se puede `await`.
 * @returns {string|null}
 */
export function getResolvedKeySync(name) {
  if (Date.now() - _cachedAt > TTL_MS) { void _ensureFresh(); }
  const hit = _cache.get(name);
  if (hit?.value) return hit.value;
  return _envFallback(name);
}

function mask(v) {
  if (!v) return null;
  const s = String(v);
  return s.length <= 4 ? "••••" : `••••${s.slice(-4)}`;
}

/**
 * Lista el catálogo con estado enmascarado (NUNCA el valor completo).
 * @returns {Promise<Array<{name,label,docUrl,source,configured,masked,updatedBy,updatedAt}>>}
 */
export async function listMasked() {
  await _ensureFresh();
  return CATALOG.map((c) => {
    const db = _cache.get(c.name);
    const env = _envFallback(c.name);
    const value = db?.value ?? env;
    const source = db?.value ? "db" : env ? "env" : "none";
    return {
      name: c.name, label: c.label, docUrl: c.docUrl, tier: c.tier ?? "free",
      source, configured: Boolean(value), masked: mask(value),
      updatedBy: db?.updatedBy ?? null, updatedAt: db?.updatedAt ?? null,
    };
  });
}

/** Upsert cifrado de una key del catálogo. */
export async function setKey(name, value, operator) {
  if (!isKnownKey(name)) throw new Error(`Clave desconocida: ${name}`);
  const v = String(value ?? "").trim();
  if (!v) throw new Error("El valor no puede estar vacío");
  const enc = encrypt(v);
  await pgQuery(
    `INSERT INTO legacyhunt_soc.integration_credentials (key_name, value_enc, updated_by, updated_at)
     VALUES ($1, $2, $3, now())
     ON CONFLICT (key_name) DO UPDATE
       SET value_enc = EXCLUDED.value_enc, updated_by = EXCLUDED.updated_by, updated_at = now()`,
    [name, enc, operator ?? null],
  );
  _cachedAt = 0;   // invalida caché (la siguiente lectura refresca)
  // Refresca proactivamente → lecturas sync y async quedan frescas sin lag.
  // No fatal: el upsert ya está confirmado; si el refresh falla, el TTL lo corrige.
  await _refresh().catch(() => {});
}

/** Borra la key de la DB → revierte al .env. */
export async function clearKey(name) {
  if (!isKnownKey(name)) throw new Error(`Clave desconocida: ${name}`);
  await pgQuery(`DELETE FROM legacyhunt_soc.integration_credentials WHERE key_name = $1`, [name]);
  _cachedAt = 0;
  await _refresh().catch(() => {});   // revierte al .env de inmediato; no fatal si falla
}
