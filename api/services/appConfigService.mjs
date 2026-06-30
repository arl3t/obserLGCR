/**
 * services/appConfigService.mjs — resolución de config del .env editable desde
 * Ajustes (ADMIN). Resuelve cada key como DB (cifrada) → fallback process.env →
 * default del catálogo. Permite editar en runtime sin reiniciar el contenedor
 * para las vars con applyMode "live" (consumidores cableados a este resolver).
 *
 * Cifrado en reposo: AES-256-GCM (services/secretCrypto.mjs, master key
 * SETTINGS_ENC_KEY). Se cifra TODO (incluso no-secretos) → una sola ruta de I/O.
 *
 * Tabla: legacyhunt_soc.app_config (migración 112). Catálogo: appConfigCatalog.mjs.
 */

import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { encryptSecret, decryptSecret, encryptionAvailable } from "./secretCrypto.mjs";
import {
  CONFIG_CATALOG, SECTIONS, isKnownConfigKey, getConfigMeta,
} from "./appConfigCatalog.mjs";

export { encryptionAvailable, isKnownConfigKey };

// ── Caché del snapshot DB (TTL) — mismo patrón que apiKeysService ────────────
const TTL_MS = 30_000;
let _cache = new Map();   // key_name → { value, isSecret, updatedBy, updatedAt }
let _cachedAt = 0;
let _refreshing = null;

async function _refresh() {
  const rows = await pgQuery(
    `SELECT key_name, value_enc, is_secret, updated_by, updated_at
       FROM legacyhunt_soc.app_config`,
  );
  const m = new Map();
  for (const r of rows) {
    try {
      m.set(r.key_name, {
        value: decryptSecret(r.value_enc),
        isSecret: r.is_secret,
        updatedBy: r.updated_by,
        updatedAt: r.updated_at,
      });
    } catch (e) {
      logger.warn({ key: r.key_name, err: e.message }, "[appConfig] no se pudo descifrar (¿cambió SETTINGS_ENC_KEY?)");
    }
  }
  _cache = m;
  _cachedAt = Date.now();
}

async function _ensureFresh() {
  if (Date.now() - _cachedAt <= TTL_MS) return;
  if (!_refreshing) {
    _refreshing = _refresh().catch((e) => {
      logger.warn({ err: e.message }, "[appConfig] refresh falló, uso caché previa");
    }).finally(() => { _refreshing = null; });
  }
  await _refreshing;
}

/** Hidrata el caché al boot (no lanza). */
export async function primeAppConfigCache() {
  try { await _refresh(); } catch (e) { logger.warn({ err: e.message }, "[appConfig] prime falló"); }
}

function _fallback(key) {
  const env = (process.env[key] ?? "").trim();
  if (env) return env;
  const def = getConfigMeta(key)?.default;
  return def != null && String(def).trim() ? String(def) : null;
}

/** Resuelve el valor efectivo: DB (cifrada) → .env → default. */
export async function getResolvedConfig(key) {
  await _ensureFresh();
  const hit = _cache.get(key);
  if (hit?.value != null && hit.value !== "") return hit.value;
  return _fallback(key);
}

/**
 * Variante síncrona: lee el snapshot en memoria (cebado al boot, refrescado por
 * lecturas async / setConfig-clearConfig) → fallback .env/default. Si el caché
 * está vencido dispara un refresh en background. Para consumidores síncronos.
 */
export function getResolvedConfigSync(key) {
  if (Date.now() - _cachedAt > TTL_MS) { void _ensureFresh(); }
  const hit = _cache.get(key);
  if (hit?.value != null && hit.value !== "") return hit.value;
  return _fallback(key);
}

/** Helper boolean (sync). Acepta 1/true/yes/on (case-insensitive). */
export function getResolvedConfigBool(key, def = false) {
  const v = getResolvedConfigSync(key);
  if (v == null) return def;
  return /^(1|true|yes|on)$/i.test(String(v).trim());
}

/** Helper entero (sync). Devuelve `def` si no parsea. */
export function getResolvedConfigInt(key, def = 0) {
  const v = getResolvedConfigSync(key);
  const n = Number.parseInt(String(v ?? "").trim(), 10);
  return Number.isFinite(n) ? n : def;
}

function mask(v) {
  if (!v) return null;
  const s = String(v);
  return s.length <= 4 ? "••••" : `••••${s.slice(-4)}`;
}

/**
 * Lista el catálogo agrupado por sección con estado. Secretos: sólo máscara.
 * No-secretos: devuelve `value` en claro para edición cómoda.
 */
export async function listConfigMasked() {
  await _ensureFresh();
  const items = CONFIG_CATALOG.map((c) => {
    const db = _cache.get(c.key);
    const dbVal = db?.value != null && db.value !== "" ? db.value : null;
    const envVal = _fallback(c.key);
    const value = dbVal ?? envVal;
    const source = dbVal ? "db" : envVal ? "env" : "none";
    return {
      key: c.key, label: c.label, section: c.section, applyMode: c.applyMode,
      secret: c.secret, docUrl: c.docUrl ?? null,
      source, configured: Boolean(value),
      masked: mask(value),
      value: c.secret ? null : (value ?? null),   // claro sólo para no-secretos
      updatedBy: db?.updatedBy ?? null, updatedAt: db?.updatedAt ?? null,
    };
  });

  // Agrupar respetando el orden de SECTIONS; omitir secciones vacías.
  return SECTIONS
    .map((s) => ({ section: s.id, label: s.label, items: items.filter((i) => i.section === s.id) }))
    .filter((g) => g.items.length > 0);
}

/** Upsert cifrado de una key del catálogo. */
export async function setConfig(key, value, operator) {
  const meta = getConfigMeta(key);
  if (!meta) throw new Error(`Clave desconocida: ${key}`);
  const v = String(value ?? "").trim();
  if (!v) throw new Error("El valor no puede estar vacío");
  const enc = encryptSecret(v);
  await pgQuery(
    `INSERT INTO legacyhunt_soc.app_config (key_name, value_enc, is_secret, updated_by, updated_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (key_name) DO UPDATE
       SET value_enc = EXCLUDED.value_enc, is_secret = EXCLUDED.is_secret,
           updated_by = EXCLUDED.updated_by, updated_at = now()`,
    [key, enc, Boolean(meta.secret), operator ?? null],
  );
  _cachedAt = 0;
  await _refresh().catch(() => {});   // refresca → lecturas sync/async frescas
  return meta.applyMode;
}

/** Borra la key de la DB → revierte al .env/default. */
export async function clearConfig(key, _operator) {
  if (!isKnownConfigKey(key)) throw new Error(`Clave desconocida: ${key}`);
  await pgQuery(`DELETE FROM legacyhunt_soc.app_config WHERE key_name = $1`, [key]);
  _cachedAt = 0;
  await _refresh().catch(() => {});
}

/** Texto de advertencia honesta según applyMode (para la respuesta del PUT/UI). */
export function applyModeWarning(applyMode) {
  switch (applyMode) {
    case "live":          return null;
    case "api-restart":   return "Guardado. Requiere recrear el contenedor de la API para aplicar.";
    case "other-service": return "Guardado en BD, pero lo consume otro contenedor (postgres/airflow/keycloak/minio/trino): actualizá el .env y recreá ese servicio.";
    case "build-time":    return "Guardado en BD, pero es una variable VITE_* del dashboard: requiere rebuild del dashboard para aplicar.";
    default:              return null;
  }
}
