/**
 * circuitBreaker.mjs — circuit breaker + retry para llamadas externas.
 *
 * Estado en memoria por proceso (`Map<source, BreakerState>`). No persiste
 * en DB porque el reinicio del API ya reabre todos los breakers como
 * `closed` — que es el comportamiento deseado tras restart.
 *
 * Estados:
 *   closed     → operaciones pasan; cada failure suma al counter.
 *   open       → operaciones rechazadas con throw; tras cooldown pasa a
 *                half-open en el siguiente call.
 *   half-open  → 1 call pasa; si succeeds → closed, si falla → open + cooldown.
 *
 * Métricas: `getBreakerStats()` expone el estado actual de todos los
 * breakers para un endpoint `/api/health/breakers` opcional.
 */

import { logger } from "../logger.mjs";

const DEFAULTS = {
  failureThreshold: 5,    // fallos consecutivos para abrir el breaker
  cooldownMs:       60_000, // 60s en open antes de probar half-open
};

/** @type {Map<string, BreakerState>} */
const states = new Map();

/**
 * @typedef {Object} BreakerState
 * @property {"closed"|"open"|"half-open"} state
 * @property {number} consecutiveFailures
 * @property {number|null} openedAt       Epoch ms — null si no está open.
 * @property {number} totalCalls
 * @property {number} totalFailures
 */

function getOrInit(source) {
  let s = states.get(source);
  if (!s) {
    s = {
      state: "closed",
      consecutiveFailures: 0,
      openedAt: null,
      totalCalls: 0,
      totalFailures: 0,
    };
    states.set(source, s);
  }
  return s;
}

/** Devuelve true si la operación puede pasar; sino throw. */
function checkBreaker(source, cooldownMs = DEFAULTS.cooldownMs) {
  const s = getOrInit(source);
  if (s.state === "open") {
    const elapsed = Date.now() - (s.openedAt ?? 0);
    if (elapsed < cooldownMs) {
      throw new Error(`Circuit breaker '${source}' open (cooldown ${Math.round((cooldownMs - elapsed) / 1000)}s)`);
    }
    // Cooldown expirado → transicion a half-open.
    s.state = "half-open";
    logger.info?.(`[breaker] ${source}: open → half-open (cooldown expired)`);
  }
  return true;
}

function recordSuccess(source) {
  const s = getOrInit(source);
  s.totalCalls += 1;
  s.consecutiveFailures = 0;
  if (s.state !== "closed") {
    logger.info?.(`[breaker] ${source}: ${s.state} → closed`);
    s.state = "closed";
    s.openedAt = null;
  }
}

function recordFailure(source, failureThreshold = DEFAULTS.failureThreshold) {
  const s = getOrInit(source);
  s.totalCalls += 1;
  s.totalFailures += 1;
  s.consecutiveFailures += 1;
  if (s.state === "half-open") {
    s.state = "open";
    s.openedAt = Date.now();
    logger.warn?.(`[breaker] ${source}: half-open → open (probe failed)`);
    return;
  }
  if (s.consecutiveFailures >= failureThreshold) {
    s.state = "open";
    s.openedAt = Date.now();
    logger.warn?.(`[breaker] ${source}: closed → open (${s.consecutiveFailures} consec failures)`);
  }
}

/**
 * Wraps `fn` with circuit breaker + retry-with-backoff. Falla si el breaker
 * está abierto. Retry max `retries` veces con backoff exponencial.
 *
 * @template T
 * @param {string} source
 * @param {() => Promise<T>} fn
 * @param {{retries?: number, baseDelayMs?: number, cooldownMs?: number, failureThreshold?: number}} [opts]
 * @returns {Promise<T>}
 */
export async function withCircuitBreaker(source, fn, opts = {}) {
  const {
    retries = 0,
    baseDelayMs = 500,
    cooldownMs = DEFAULTS.cooldownMs,
    failureThreshold = DEFAULTS.failureThreshold,
  } = opts;

  checkBreaker(source, cooldownMs);

  let lastErr = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const result = await fn();
      recordSuccess(source);
      return result;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        const delay = baseDelayMs * Math.pow(2, attempt) + Math.random() * 200;
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }
  recordFailure(source, failureThreshold);
  throw lastErr;
}

/** Stats de todos los breakers para endpoints de salud. */
export function getBreakerStats() {
  const out = {};
  for (const [source, s] of states) {
    out[source] = {
      state: s.state,
      consecutiveFailures: s.consecutiveFailures,
      openedAt: s.openedAt,
      totalCalls: s.totalCalls,
      totalFailures: s.totalFailures,
      failureRate: s.totalCalls > 0 ? s.totalFailures / s.totalCalls : 0,
    };
  }
  return out;
}

/** Forzar reset de un breaker (admin tool). */
export function resetBreaker(source) {
  const s = states.get(source);
  if (!s) return false;
  s.state = "closed";
  s.consecutiveFailures = 0;
  s.openedAt = null;
  logger.info?.(`[breaker] ${source}: forced reset → closed`);
  return true;
}
