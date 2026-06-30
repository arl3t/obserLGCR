/**
 * Caché LRU en memoria del proceso para resultados Trino
 * (`POST /api/trino/query` y `POST /api/trino/run`). TTL vía `TRINO_QUERY_CACHE_TTL_SEC`.
 */
import { createHash } from "node:crypto";

/** @type {number} */
let memoryMaxEntries = 256;

/** Contadores de rendimiento (acumulativos desde el arranque del proceso). */
const _stats = { hits: 0, misses: 0, evictions: 0, sets: 0 };

/**
 * Devuelve métricas de rendimiento de la caché en memoria.
 * @returns {{ hits, misses, evictions, sets, size, maxEntries, enabled, hitRate }}
 */
export function getCacheStats() {
  const total = _stats.hits + _stats.misses;
  return {
    ..._stats,
    size:       memoryStore.size,
    maxEntries: memoryMaxEntries,
    enabled:    memoryMaxEntries > 0,
    // Fracción 0–1 (NO porcentaje) — el frontend formatea como %.
    // Bug histórico: este campo devolvía 0–100 y el frontend multiplicaba por
    // 100 ⇒ "Cache 8460%". Alineamos con el nombre del campo.
    hitRate:    total > 0 ? Math.round((_stats.hits / total) * 10000) / 10000 : null,
  };
}

/**
 * LRU cache usando un solo Map (JavaScript mantiene orden de inserción).
 * Touch = delete + re-insert → mueve la entrada al final en O(1).
 * Eviction = borrar la primera clave del Map (la más antigua) en O(1).
 *
 * @type {Map<string, { rows: Record<string, unknown>[], exp: number }>}
 */
const memoryStore = new Map();

function memoryTouch(key) {
  const val = memoryStore.get(key);
  if (val !== undefined) {
    memoryStore.delete(key);
    memoryStore.set(key, val);   // re-inserta al final → MRU
  }
}

function memoryEvictIfNeeded() {
  while (memoryStore.size > memoryMaxEntries) {
    memoryStore.delete(memoryStore.keys().next().value);
    _stats.evictions++;
  }
}

export function initQueryCache(opts = {}) {
  memoryMaxEntries = Math.max(0, Math.min(10_000, Number(opts.memoryMaxEntries) || 256));
  if (memoryMaxEntries <= 0) {
    // eslint-disable-next-line no-console
    console.warn("[query-cache] CACHÉ DESACTIVADA (memoryMaxEntries=0) — todas las queries irán a Trino sin cache");
  }
}

export function cacheKeyForSql(sql) {
  const h = createHash("sha256").update(sql, "utf8").digest("hex");
  return `trino:q:${h}`;
}

export function cacheKeyForNamed(id, params) {
  const body = JSON.stringify({ id, params: params ?? {} });
  const h = createHash("sha256").update(body, "utf8").digest("hex");
  return `trino:n:${h}`;
}

/**
 * @param {string} key
 * @returns {Promise<Record<string, unknown>[] | null>}
 */
export async function cacheGetJson(key) {
  if (memoryMaxEntries <= 0) return null;
  const slot = memoryStore.get(key);
  if (!slot) { _stats.misses++; return null; }
  if (slot.exp > Date.now()) {
    memoryTouch(key);
    _stats.hits++;
    return slot.rows;
  }
  memoryStore.delete(key);
  _stats.misses++;
  return null;
}

export async function cacheSetJson(key, rows, ttlSec) {
  const ttl = Math.max(0, ttlSec);
  if (memoryMaxEntries <= 0 || ttl <= 0) return;
  const exp = Date.now() + ttl * 1000;
  if (memoryStore.has(key)) memoryStore.delete(key);
  memoryStore.set(key, { rows, exp });
  _stats.sets++;
  memoryEvictIfNeeded();
}
