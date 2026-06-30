/**
 * scoringBonus.mjs — Bonos adicionales del motor de scoring v2
 *
 * Implementa las 6 mejoras adicionales al sistema de scoring base:
 *   1. Kill-chain depth bonus    (+5 si MITRE cubre ≥3 fases de la kill-chain)
 *   2. Temporal freshness mult   (×1.20 si IOC fue visto por primera vez < 2 h)
 *   3. FP historical penalty     (−10 si el mismo IOC fue cerrado como FP < 90 días)
 *   4. Score decay histórico     (−5/−10/−15 si el IOC no ha reaparecido en 7/30/90 días)
 *   5. Geo-risk multiplier       (×1.25 o ×1.10 según país de la IP)
 *   6. Asset criticality bonus   (+20/+13/+6 según tier1/tier2/tier3 del activo)
 *
 * Todos los bonos son opcionales y no bloquean el scoring si fallan.
 * Cada función devuelve { value, detail } para el scoring_bonus_log.
 */

import { pgQuery } from "../db/postgres.mjs";

// ── 1. Kill-chain depth bonus ─────────────────────────────────────────────────

/**
 * Mapa de tactic_id → fase de kill-chain (Lockheed Martin simplificado sobre ATT&CK).
 * Las 14 tácticas se agrupan en 6 fases; el bono se aplica si el IOC cubre ≥3 fases.
 */
const TACTIC_PHASE = {
  // Fase 1 — Reconocimiento / Preparación
  TA0043: "recon",          // Reconnaissance
  TA0042: "recon",          // Resource Development

  // Fase 2 — Acceso inicial
  TA0001: "initial_access", // Initial Access
  TA0002: "execution",      // Execution (puede coincidir con fase 2)

  // Fase 3 — Instalación / Persistencia
  TA0003: "persistence",    // Persistence
  TA0004: "persistence",    // Privilege Escalation
  TA0005: "persistence",    // Defense Evasion

  // Fase 4 — Acceso a credenciales / Descubrimiento
  TA0006: "credential",     // Credential Access
  TA0007: "credential",     // Discovery

  // Fase 5 — Movimiento lateral / Recolección
  TA0008: "lateral",        // Lateral Movement
  TA0009: "lateral",        // Collection

  // Fase 6 — C2 / Impacto / Exfiltración
  TA0011: "impact",         // Command and Control
  TA0010: "impact",         // Exfiltration
  TA0040: "impact",         // Impact
};

const KILL_CHAIN_BONUS_PTS = 5;
const KILL_CHAIN_MIN_PHASES = 3;

/**
 * Calcula el bono de profundidad de kill-chain.
 * @param {string[]} tacticIds — Array de tactic IDs del mismo IOC (ej. ["TA0001","TA0006","TA0008"])
 * @returns {{ value: number, detail: object }}
 */
export function calcKillChainBonus(tacticIds = []) {
  if (!tacticIds?.length) return { value: 0, detail: { phases: 0, tactics: [] } };

  const phases = new Set(
    tacticIds
      .map((t) => TACTIC_PHASE[String(t).toUpperCase()])
      .filter(Boolean),
  );

  const phasesCount = phases.size;
  const value = phasesCount >= KILL_CHAIN_MIN_PHASES ? KILL_CHAIN_BONUS_PTS : 0;

  return {
    value,
    detail: {
      phases:      phasesCount,
      phaseNames:  [...phases],
      tactics:     tacticIds,
      threshold:   KILL_CHAIN_MIN_PHASES,
      applied:     value > 0,
    },
  };
}

// ── 1b. RFC1918 score_evidence (paridad SQL ↔ Node) ──────────────────────────

/**
 * Réplica Node de la fórmula `score_evidence` para IOCs RFC1918 de las vistas
 * `v_incident_score_v2` / `v3` (`scripts/sql/threat-hunt/21_*.sql`,
 * `42_*.sql`). Cierra la asimetría detectada en R5 (audit Scoring 2026-05-21):
 *
 *   SQL:     CASE source_severity 1→30, 2→20, 3→10, else→5 END
 *          + CASE alert_count ≥500→5, ≥100→3, ≥50→1, else→0 END  (cap 35)
 *   Node:    /open-from-flow y forcedAckController persistían `score_evidence=0`
 *            cuando Trino no había materializado todavía el IOC interno → el
 *            DAG recalculaba con un valor distinto al sincronizar.
 *
 * Uso: aplicar SOLO cuando el IOC es RFC1918 (las IPs públicas tienen
 * VT/AbuseIPDB/Shodan y por tanto otra fórmula).
 *
 * Cuando `sourceSeverity` (1=crit, 2=high, 3=med) no esté disponible, se
 * deriva desde la severidad del caso (`CRITICAL→1, HIGH→2, MEDIUM→3, …`) —
 * no es 1:1 con el `source_severity` del sensor pero replica el comportamiento
 * del DAG en ausencia de telemetría enriquecida.
 *
 * @param {object} opts
 * @param {number} [opts.sourceSeverity] — 1|2|3 del sensor (Wazuh level mapeado)
 * @param {number} [opts.alertCount]     — alertas del IOC en la ventana de 30d
 * @param {string} [opts.severity]       — fallback si no hay sourceSeverity (CRITICAL|HIGH|MEDIUM|LOW|NEGLIGIBLE)
 * @returns {number} score_evidence en [0, 35]
 */
export function calcScoreEvidenceRfc1918({ sourceSeverity, alertCount, severity } = {}) {
  const fromSeverity = ({
    CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NEGLIGIBLE: 5,
  })[String(severity ?? "").toUpperCase()] ?? 4;

  const sev = Number.isFinite(Number(sourceSeverity))
    ? Number(sourceSeverity)
    : fromSeverity;

  const sevPts = sev === 1 ? 30
               : sev === 2 ? 20
               : sev === 3 ? 10
               :              5;

  const ac     = Number.isFinite(Number(alertCount)) ? Number(alertCount) : 0;
  const acPts  = ac >= 500 ? 5
               : ac >= 100 ? 3
               : ac >= 50  ? 1
               :             0;

  return Math.min(35, sevPts + acPts);
}

// ── 2. Temporal freshness multiplier ─────────────────────────────────────────

const FRESH_WINDOW_MS  = 2 * 60 * 60 * 1000; // 2 horas
const FRESH_MULTIPLIER = 1.20;
const DECAY_WINDOW_MS  = 24 * 60 * 60 * 1000; // 24 horas (inicio de decay)

/**
 * Multiplica el score base si el IOC fue detectado por primera vez recientemente.
 *
 * Lógica:
 *  - < 2 h:  ×1.20 (IOC fresco, alta relevancia operacional)
 *  - 2–24 h: ×1.00 (sin modificación — ventana normal de análisis)
 *  - > 24 h: score base sin multiplicador temporal
 *
 * @param {string|Date} firstSeenTs — ISO timestamp o Date del primer evento
 * @returns {{ multiplier: number, detail: object }}
 */
export function calcTemporalMultiplier(firstSeenTs) {
  if (!firstSeenTs) return { multiplier: 1.0, detail: { fresh: false, ageMs: null } };

  try {
    const firstSeen = new Date(firstSeenTs);
    if (isNaN(firstSeen.getTime())) {
      return { multiplier: 1.0, detail: { fresh: false, ageMs: null, error: "invalid_timestamp" } };
    }

    const ageMs     = Date.now() - firstSeen.getTime();
    const fresh     = ageMs <= FRESH_WINDOW_MS;
    const multiplier = fresh ? FRESH_MULTIPLIER : 1.0;

    return {
      multiplier,
      detail: {
        fresh,
        ageMs,
        ageHours:    +(ageMs / 3_600_000).toFixed(2),
        firstSeen:   firstSeen.toISOString(),
        threshold2h: FRESH_WINDOW_MS,
        applied:     fresh,
      },
    };
  } catch {
    return { multiplier: 1.0, detail: { fresh: false, error: "calc_error" } };
  }
}

// ── 3. FP historical penalty ─────────────────────────────────────────────────

const FP_WINDOW_DAYS   = 90;   // ventana de búsqueda en días
const FP_PENALTY_PTS   = -10;  // penalización por FP histórico reciente
const FP_DECAY_PTS     = -5;   // penalización reducida si FP es de hace > 45 días

/**
 * Penaliza el score si el mismo IOC fue marcado como FALSO_POSITIVO en los
 * últimos 90 días. Consulta `case_suppressions` (tabla ya existente).
 *
 * @param {string} iocValue  — valor del IOC (IP, dominio, etc.)
 * @param {string} [dedupKey] — clave de deduplicación opcional
 * @returns {Promise<{ value: number, detail: object }>}
 */
export async function calcFpPenalty(iocValue, dedupKey = null) {
  if (!iocValue) return { value: 0, detail: { checked: false } };

  try {
    // Buscar en case_suppressions — se crea cuando un caso se marca FP o CERRADO
    const window90 = new Date(Date.now() - FP_WINDOW_DAYS * 24 * 3_600_000).toISOString();

    const conditions = [`original_ioc = $1`, `suppressed_until > $2`];
    const params     = [String(iocValue).trim(), window90];

    if (dedupKey) {
      conditions.push(`dedup_key = $${params.length + 1}`);
      params.push(dedupKey);
    }

    const rows = await pgQuery(
      `SELECT reason, suppressed_until, suppressed_by,
              EXTRACT(EPOCH FROM (NOW() - suppressed_until)) / 86400 AS days_ago
       FROM legacyhunt_soc.case_suppressions
       WHERE ${conditions.join(" AND ")}
       ORDER BY suppressed_until DESC
       LIMIT 1`,
      params,
    );

    if (!rows.length) {
      return { value: 0, detail: { hasFpHistory: false, checked: true } };
    }

    const rec     = rows[0];
    const daysAgo = Math.abs(Number(rec.days_ago ?? 0));

    // Penalización decae si el FP es de hace > 45 días
    const value   = daysAgo < 45 ? FP_PENALTY_PTS : FP_DECAY_PTS;

    return {
      value,
      detail: {
        hasFpHistory:    true,
        daysAgo:         +daysAgo.toFixed(1),
        reason:          rec.reason,
        suppressedUntil: rec.suppressed_until,
        suppressedBy:    rec.suppressed_by,
        penalty:         value,
        applied:         true,
      },
    };
  } catch (err) {
    // No bloquear el scoring si la consulta falla
    return { value: 0, detail: { checked: false, error: err.message } };
  }
}

// ── 4. Score decay histórico ──────────────────────────────────────────────────

/**
 * Escalones de decay según antigüedad del último caso TP para el mismo IOC.
 * La idea: si el IOC generó casos en el pasado pero no ha reaparecido recientemente,
 * su score actual se reduce porque la amenaza puede haber caducado o migrado.
 *
 * Rangos (días desde el último caso NO-FP):
 *   < 7 d    → sin decay (amenaza activa)
 *   7–30 d   → −5  pts (actividad reciente pero declinando)
 *   30–90 d  → −10 pts (amenaza histórica moderada)
 *   > 90 d   → −15 pts (amenaza muy antigua — prioridad reducida)
 *
 * Solo aplica cuando:
 *  - Existen casos previos del IOC (no es la primera vez que se ve)
 *  - El IOC no tiene actividad nueva en el último período de decay
 *  - Los casos anteriores NO son todos FP (eso ya lo cubre calcFpPenalty)
 */

const DECAY_BRACKETS = [
  { maxDays: 7,   pts:   0 },   // activo — sin penalización
  { maxDays: 30,  pts:  -5 },   // reciente — penalización leve
  { maxDays: 90,  pts: -10 },   // histórico — penalización moderada
  { maxDays: Infinity, pts: -15 }, // muy antiguo — penalización alta
];

/**
 * Calcula la penalización por decay histórico del IOC.
 * Consulta `incident_cases_pg` buscando casos previos para el mismo ioc_value.
 *
 * @param {string}  iocValue     — valor del IOC (IP, dominio, hash, URL)
 * @param {string}  [dedupKey]   — clave de deduplicación (alternativa de búsqueda)
 * @param {string}  [firstSeenTs]— timestamp del evento actual; si el IOC ya fue visto
 *                                 recientemente (mismo día) no se aplica decay
 * @returns {Promise<{ value: number, detail: object }>}
 */
export async function calcScoreDecay(iocValue, dedupKey = null, firstSeenTs = null) {
  if (!iocValue) return { value: 0, detail: { checked: false, reason: "no_ioc" } };

  try {
    // Si la primera detección del IOC es muy reciente (<= 1 hora), es nuevo — sin decay
    if (firstSeenTs) {
      const firstSeen = new Date(firstSeenTs);
      if (!isNaN(firstSeen.getTime())) {
        const ageMs = Date.now() - firstSeen.getTime();
        if (ageMs <= 60 * 60 * 1000) {
          return { value: 0, detail: { checked: true, reason: "ioc_is_new", ageMs } };
        }
      }
    }

    // Buscar casos anteriores para el mismo IOC (excluir FP — ya cubiertos por calcFpPenalty)
    // Tomamos el caso más reciente que NO sea false_positive
    const rows = await pgQuery(
      `SELECT
         created_at,
         resolved_at,
         status,
         EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400 AS days_since_created,
         COUNT(*) OVER () AS total_cases
       FROM incident_cases_pg
       WHERE ioc_value = $1
         AND is_false_positive = false
         AND status != 'FALSO_POSITIVO'
       ORDER BY created_at DESC
       LIMIT 1`,
      [String(iocValue).trim()],
    );

    if (!rows.length) {
      // Sin historial — primera vez que se ve, no hay decay
      return { value: 0, detail: { checked: true, hasPriorCases: false, reason: "no_prior_cases" } };
    }

    const rec      = rows[0];
    const daysSince = Math.abs(Number(rec.days_since_created ?? 0));
    const totalCases = Number(rec.total_cases ?? 1);

    // Calcular bracket
    const bracket = DECAY_BRACKETS.find((b) => daysSince < b.maxDays) ?? DECAY_BRACKETS.at(-1);

    // Si el caso más reciente es < 7 días, no hay decay — IOC sigue activo
    if (bracket.pts === 0) {
      return {
        value: 0,
        detail: {
          checked: true, hasPriorCases: true,
          reason: "recent_activity_no_decay",
          daysSinceLastCase: +daysSince.toFixed(1),
          lastCaseStatus: rec.status,
          totalPriorCases: totalCases,
        },
      };
    }

    return {
      value: bracket.pts,
      detail: {
        checked:          true,
        hasPriorCases:    true,
        applied:          true,
        daysSinceLastCase: +daysSince.toFixed(1),
        lastCaseDate:     rec.created_at,
        lastCaseStatus:   rec.status,
        totalPriorCases:  totalCases,
        bracketMaxDays:   bracket.maxDays,
        decayPts:         bracket.pts,
      },
    };
  } catch (err) {
    return { value: 0, detail: { checked: false, error: err.message } };
  }
}

// ── 5. Geo-risk multiplier ────────────────────────────────────────────────────

/**
 * Lista hardcoded de países de alto riesgo.
 * Los operadores pueden sobreescribir via tabla `geo_risk_config` (migration 010).
 */
const GEO_RISK_HARDCODED = {
  // HIGH: ×1.25
  KP: "high", IR: "high", RU: "high", CN: "high",
  SY: "high", CU: "high", BY: "high",
  // ELEVATED: ×1.10
  NG: "elevated", RO: "elevated", BR: "elevated",
  PK: "elevated", VN: "elevated", UA: "elevated",
  IN: "elevated", ID: "elevated",
};

const GEO_MULTIPLIER = {
  high:     1.25,
  elevated: 1.10,
  standard: 1.00,
  low:      0.95,
};

/** Caché simple para geo_risk_config de PostgreSQL (5 min TTL) */
let geoCache      = null;
let geoCacheAt    = 0;
const GEO_TTL_MS  = 5 * 60 * 1000;

async function loadGeoRiskConfig() {
  const now = Date.now();
  if (geoCache && (now - geoCacheAt) < GEO_TTL_MS) return geoCache;

  try {
    const rows = await pgQuery(
      `SELECT country_code, risk_tier FROM geo_risk_config`,
    );
    if (rows.length) {
      geoCache   = Object.fromEntries(rows.map((r) => [r.country_code, r.risk_tier]));
      geoCacheAt = now;
      return geoCache;
    }
  } catch {
    // Fallback a hardcoded
  }

  geoCache   = GEO_RISK_HARDCODED;
  geoCacheAt = now;
  return geoCache;
}

/**
 * Devuelve el multiplicador de riesgo geográfico para una IP.
 * Requiere que el llamador haya resuelto el country_code. Fuente primaria:
 * MaxMind GeoLite2 (geoipService.mjs, local/offline); fallback: VT/Shodan/AbuseIPDB.
 *
 * @param {string|null} countryCode — código ISO 3166-1 alpha-2 (ej. "RU", "US")
 * @returns {Promise<{ multiplier: number, detail: object }>}
 */
export async function calcGeoRiskMultiplier(countryCode) {
  if (!countryCode) return { multiplier: 1.0, detail: { country: null, tier: "standard" } };

  const cc   = String(countryCode).toUpperCase().slice(0, 2);
  const cfg  = await loadGeoRiskConfig();
  const tier = cfg[cc] ?? "standard";
  const multiplier = GEO_MULTIPLIER[tier] ?? 1.0;

  return {
    multiplier,
    detail: {
      country:    cc,
      tier,
      multiplier,
      applied:    multiplier !== 1.0,
    },
  };
}

/** Invalida la caché de geo-risk (útil cuando el operador actualiza geo_risk_config) */
export function invalidateGeoCache() {
  geoCache   = null;
  geoCacheAt = 0;
}

// ── 5. Asset criticality bonus ────────────────────────────────────────────────

const ASSET_CRITICALITY_PTS = { tier1: 20, tier2: 13, tier3: 6 };

/** Caché de asset_registry — TTL unificado con geo-risk (5 min) para scoring consistente. */
let assetCache    = null;
let assetCacheAt  = 0;
const ASSET_TTL_MS = GEO_TTL_MS; // 5 min — mismo TTL que geo-risk (antes era 2 min)

async function loadAssetRegistry() {
  const now = Date.now();
  if (assetCache && (now - assetCacheAt) < ASSET_TTL_MS) return assetCache;

  try {
    const rows = await pgQuery(
      `SELECT sensor_key, hostname, ip_address::text AS ip, criticality, asset_type, tags
       FROM asset_registry
       WHERE is_active = true`,
    );
    const map = {};
    for (const r of rows) {
      map[r.sensor_key.toLowerCase()] = r;
      // Indexar también por IP si está presente
      if (r.ip) map[r.ip] = r;
    }
    assetCache   = map;
    assetCacheAt = now;
  } catch {
    assetCache   = {};
    assetCacheAt = now;
  }

  return assetCache;
}

/**
 * Devuelve el bono de criticidad de activo para un sensorKey/IP.
 * Solo aplica a IPs RFC1918 — para IPs públicas este componente es 0.
 *
 * @param {string|null} sensorKey — hostname, IP, o nombre de dispositivo
 * @param {boolean} isInternal — si el IOC es RFC1918
 * @returns {Promise<{ value: number, detail: object }>}
 */
export async function calcAssetCriticality(sensorKey, isInternal = false) {
  // Solo aplica a IPs internas — activos públicos no tienen tier en este modelo
  if (!isInternal || !sensorKey) {
    return { value: 0, detail: { applied: false, reason: isInternal ? "no_sensor_key" : "public_ip" } };
  }

  const registry = await loadAssetRegistry();
  const key      = String(sensorKey).toLowerCase().trim();
  const asset    = registry[key] ?? registry[key.split(".")[0]]; // probar hostname corto

  if (!asset) {
    return { value: 0, detail: { applied: false, sensorKey, reason: "not_in_registry" } };
  }

  const tier  = asset.criticality ?? "tier3";
  const value = ASSET_CRITICALITY_PTS[tier] ?? 0;

  return {
    value,
    detail: {
      applied:    true,
      sensorKey,
      assetType:  asset.asset_type,
      criticality: tier,
      hostname:   asset.hostname,
      tags:       asset.tags ?? [],
    },
  };
}

/** Invalida la caché de asset registry */
export function invalidateAssetCache() {
  assetCache   = null;
  assetCacheAt = 0;
}

/**
 * Invalida simultáneamente geo-risk y asset-registry.
 * Útil cuando el operador actualiza `geo_risk_config` o `asset_registry`
 * y necesita que el próximo ciclo de scoring use los datos nuevos.
 */
export function invalidateAllCaches() {
  invalidateGeoCache();
  invalidateAssetCache();
  invalidateOffHoursCache();
}

// ── 7. Off-hours (franja horaria) multiplier ──────────────────────────────────

/**
 * Defaults (deben coincidir con business_hours_config / py_holidays de la
 * migración 099 y con el CASE inline de scripts/sql/threat-hunt/44_*.sql).
 * Horario laboral tradicional PY: L–V 05:00–18:00, Sáb 05:00–14:00.
 */
const OFFHOURS_DEFAULTS = Object.freeze({
  timezone:        "America/Asuncion",
  weekdayStart:    5,  weekdayEnd:    18,
  saturdayStart:   5,  saturdayEnd:   14,
  deepNightStart:  22, deepNightEnd:  5,
  multBusiness:    1.00, multSoft:    1.08, multDeep: 1.15,
  combinedMultCap: 1.60,
  enabled:         true,
});

/** Fallback de feriados PY (espejo de py_holidays 2026–2027). */
const PY_HOLIDAYS_FALLBACK = new Set([
  "2026-01-01","2026-03-01","2026-04-02","2026-04-03","2026-05-01","2026-05-14",
  "2026-05-15","2026-06-12","2026-08-15","2026-09-29","2026-12-08","2026-12-25",
  "2027-01-01","2027-03-01","2027-03-25","2027-03-26","2027-05-01","2027-05-14",
  "2027-05-15","2027-06-12","2027-08-15","2027-09-29","2027-12-08","2027-12-25",
]);

let offHoursCache   = null;
let offHoursCacheAt = 0;

/** Carga business_hours_config + py_holidays de PG (cache 5 min). Fallback a defaults. */
async function loadOffHoursConfig() {
  const now = Date.now();
  if (offHoursCache && (now - offHoursCacheAt) < GEO_TTL_MS) return offHoursCache;

  let cfg = { ...OFFHOURS_DEFAULTS };
  let holidays = PY_HOLIDAYS_FALLBACK;

  try {
    const rows = await pgQuery(
      `SELECT timezone, weekday_start, weekday_end, saturday_start, saturday_end,
              deep_night_start, deep_night_end, mult_business, mult_soft, mult_deep,
              combined_mult_cap, enabled
         FROM business_hours_config WHERE id = 1`,
    );
    if (rows.length) {
      const r = rows[0];
      cfg = {
        timezone:        r.timezone || OFFHOURS_DEFAULTS.timezone,
        weekdayStart:    Number(r.weekday_start),  weekdayEnd:    Number(r.weekday_end),
        saturdayStart:   Number(r.saturday_start), saturdayEnd:   Number(r.saturday_end),
        deepNightStart:  Number(r.deep_night_start), deepNightEnd: Number(r.deep_night_end),
        multBusiness:    Number(r.mult_business), multSoft: Number(r.mult_soft), multDeep: Number(r.mult_deep),
        combinedMultCap: Number(r.combined_mult_cap),
        enabled:         r.enabled !== false,
      };
    }
  } catch {
    /* defaults */
  }

  try {
    const hr = await pgQuery(`SELECT to_char(holiday_date, 'YYYY-MM-DD') AS d FROM py_holidays`);
    if (hr.length) holidays = new Set(hr.map((x) => x.d));
  } catch {
    /* fallback holidays */
  }

  offHoursCache   = { cfg, holidays };
  offHoursCacheAt = now;
  return offHoursCache;
}

/** Invalida la caché de off-hours (config + feriados). */
export function invalidateOffHoursCache() {
  offHoursCache   = null;
  offHoursCacheAt = 0;
}

/**
 * Extrae hora local, día de la semana (1=Lun…7=Dom) y fecha (YYYY-MM-DD) en la
 * zona IANA indicada. Usa Intl (maneja el histórico DST de PY y el UTC-3 fijo
 * post-2024 correctamente — NUNCA un offset fijo).
 */
function localTimeParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", hour12: false, weekday: "short",
  }).formatToParts(date);
  const get = (t) => parts.find((p) => p.type === t)?.value ?? "";
  let hour = parseInt(get("hour"), 10);
  if (hour === 24) hour = 0; // algunos entornos emiten '24' a medianoche
  const ymd = `${get("year")}-${get("month")}-${get("day")}`;
  const dowMap = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
  const dow = dowMap[get("weekday")] ?? 0;
  return { hour, dow, ymd };
}

/**
 * Multiplicador de franja horaria para un timestamp de EVENTO (no de creación
 * del caso). Espejo Node del CASE de la mat v4. Amplifica (≥1.0), nunca penaliza.
 *
 * @param {string|Date} eventTs — ISO/Date del primer evento (first_alert_ts)
 * @returns {Promise<{ multiplier: number, detail: object, combinedMultCap: number }>}
 */
export async function calcOffHoursMultiplier(eventTs) {
  const { cfg, holidays } = await loadOffHoursConfig();
  const cap = cfg.combinedMultCap ?? OFFHOURS_DEFAULTS.combinedMultCap;

  if (!cfg.enabled || !eventTs) {
    return { multiplier: 1.0, detail: { applied: false, reason: !eventTs ? "no_timestamp" : "disabled" }, combinedMultCap: cap };
  }

  const d = new Date(eventTs);
  if (isNaN(d.getTime())) {
    return { multiplier: 1.0, detail: { applied: false, reason: "invalid_timestamp" }, combinedMultCap: cap };
  }

  const { hour, dow, ymd } = localTimeParts(d, cfg.timezone);

  let band, multiplier;
  const inDeepNight = hour >= cfg.deepNightStart || hour < cfg.deepNightEnd;
  if (holidays.has(ymd))                          { band = "holiday";      multiplier = cfg.multDeep; }
  else if (dow === 7)                             { band = "sunday";       multiplier = cfg.multDeep; }
  else if (inDeepNight)                           { band = "deep_night";   multiplier = cfg.multDeep; }
  else if (dow >= 1 && dow <= 5 && hour >= cfg.weekdayStart && hour < cfg.weekdayEnd)
                                                  { band = "business";     multiplier = cfg.multBusiness; }
  else if (dow === 6 && hour >= cfg.saturdayStart && hour < cfg.saturdayEnd)
                                                  { band = "business";     multiplier = cfg.multBusiness; }
  else                                            { band = "soft_offhours"; multiplier = cfg.multSoft; }

  return {
    multiplier,
    combinedMultCap: cap,
    detail: {
      applied:   multiplier !== 1.0,
      band,
      localHour: hour,
      localDow:  dow,        // 1=Lun … 7=Dom
      localDate: ymd,
      timezone:  cfg.timezone,
      isHoliday: holidays.has(ymd),
    },
  };
}

// ── Aplicación compuesta de todos los bonos ────────────────────────────────────

/**
 * Aplica todos los bonos v2 sobre un score base y devuelve el score final.
 *
 * @param {number}   baseScore     — score calculado por el engine base (0–130)
 * @param {object}   opts
 * @param {string[]} [opts.tacticIds]    — tactic IDs MITRE para kill-chain
 * @param {string}   [opts.firstSeenTs]  — ISO timestamp del primer evento
 * @param {string}   [opts.iocValue]     — valor IOC para FP lookup y decay
 * @param {string}   [opts.dedupKey]     — dedup key para FP lookup
 * @param {string}   [opts.countryCode]  — país de la IP (de VT/Shodan)
 * @param {string}   [opts.sensorKey]    — key del activo afectado
 * @param {boolean}  [opts.isInternal]   — true si RFC1918
 * @param {string}   [opts.caseId]       — para logging en scoring_bonus_log
 * @returns {Promise<{
 *   finalScore: number,
 *   baseScore:  number,
 *   bonuses: {
 *     killChain:   { value: number, detail: object },
 *     temporal:    { multiplier: number, detail: object },
 *     fpPenalty:   { value: number, detail: object },
 *     scoreDecay:  { value: number, detail: object },
 *     geoRisk:     { multiplier: number, detail: object },
 *     assetTier:   { value: number, detail: object },
 *   }
 * }>}
 */
/**
 * R1 audit 2026-05-21 — Identifica qué bonos ya aplica la vista SQL v4.
 *
 * `v_incident_score_v4` calcula en SQL:
 *   - kill-chain bonus (+5 si ≥3 fases, +2 si ≥2 fases)
 *   - novelty multiplier por día (×1.10 si first_seen=today, ×1.05 si ayer)
 *   - geo-risk multiplier (×1.25/×1.10 para países de alto/medio riesgo)
 *   - off-hours multiplier (×1.08/×1.15 por franja horaria PY) — la mat v4 (file 44)
 *
 * Si Node aplica `applyAllBonuses()` sobre un score que ya viene de v4, esos
 * bonos se duplicarían (kill-chain +5+5=+10, geo ×1.25×1.25=×1.5625,
 * temporal ×1.20 × novelty ×1.10 = ×1.32, off-hours ×1.15×1.15). Usar este Set
 * en `skipBonuses` o llamar `applyNodeOnlyBonuses(score, opts)` (wrapper directo).
 *
 * Lo que v4 NO calcula y Node sí: `fpPenalty`, `scoreDecay`, `assetTier`.
 * Esos vienen de tablas PG (case_suppressions, incident_cases_pg,
 * asset_registry) que la vista Trino no puede consultar fácilmente.
 */
export const BONUSES_IN_SQL_V4 = Object.freeze(["killChain", "temporal", "geoRisk", "offHours"]);

/**
 * Sub-routine reutilizable: ejecuta un bono async/sync resolviendo a un
 * resultado "skipped" cuando el caller pidió omitirlo. Mantiene la forma del
 * `bonuses` map estable para callers downstream (UI, persistBonusLog).
 */
function _skippedAdditive(reason) {
  return { value: 0, detail: { applied: false, reason } };
}
function _skippedMultiplier(reason) {
  return { multiplier: 1.0, detail: { applied: false, reason } };
}

export async function applyAllBonuses(baseScore, opts = {}) {
  const {
    tacticIds    = [],
    firstSeenTs  = null,
    iocValue     = null,
    dedupKey     = null,
    countryCode  = null,
    sensorKey    = null,
    isInternal   = false,
    // R1 audit: lista de bonos a omitir cuando ya están aplicados upstream
    // (típicamente cuando el score viene de v_incident_score_v4).
    // Valores válidos: 'killChain'|'temporal'|'fpPenalty'|'scoreDecay'|'geoRisk'|'assetTier'
    skipBonuses  = [],
  } = opts;

  const skip = new Set(skipBonuses);
  const skipReason = "already_applied_upstream"; // típicamente SQL v4

  // Calcular todos los bonos en paralelo (los skipped resuelven sync a no-op).
  const [killChain, fpPenalty, scoreDecay, geoRisk, assetTier] = await Promise.all([
    skip.has("killChain")
      ? Promise.resolve(_skippedAdditive(skipReason))
      : Promise.resolve(calcKillChainBonus(tacticIds)),
    skip.has("fpPenalty")
      ? Promise.resolve(_skippedAdditive(skipReason))
      : calcFpPenalty(iocValue, dedupKey),
    skip.has("scoreDecay")
      ? Promise.resolve(_skippedAdditive(skipReason))
      : calcScoreDecay(iocValue, dedupKey, firstSeenTs),
    skip.has("geoRisk")
      ? Promise.resolve(_skippedMultiplier(skipReason))
      : isInternal
        ? Promise.resolve({ multiplier: 1.0, detail: { applied: false, reason: "internal_ip" } })
        : calcGeoRiskMultiplier(countryCode),
    skip.has("assetTier")
      ? Promise.resolve(_skippedAdditive(skipReason))
      : calcAssetCriticality(sensorKey, isInternal),
  ]);

  const temporal = skip.has("temporal")
    ? _skippedMultiplier(skipReason)
    : calcTemporalMultiplier(firstSeenTs);

  // P1: off-hours (franja horaria). Usa el timestamp del EVENTO (first_alert_ts).
  // Skipeado cuando el score viene de la mat v4 (ya lo aplica) → BONUSES_IN_SQL_V4.
  const offHours = skip.has("offHours")
    ? { ..._skippedMultiplier(skipReason), combinedMultCap: OFFHOURS_DEFAULTS.combinedMultCap }
    : await calcOffHoursMultiplier(firstSeenTs);

  // ── Aplicar en orden determinístico ─────────────────────────────────────────
  // 1. Sumar bonos aditivos: kill-chain, FP penalty, score decay, asset tier
  let score = baseScore + killChain.value + fpPenalty.value + scoreDecay.value + assetTier.value;

  // 2. Aplicar multiplicadores: geo-risk × temporal × off-hours (se componen).
  //    Tope combinado (combined_mult_cap, default 1.60) para que un borderline no
  //    explote (ej. 60×1.8=108). Sólo amplifica: el piso del producto es 1.0.
  const cap = Math.max(1.0, Number(offHours.combinedMultCap ?? OFFHOURS_DEFAULTS.combinedMultCap));
  const rawMultiplier = geoRisk.multiplier * temporal.multiplier * offHours.multiplier;
  const combinedMultiplier = +Math.min(cap, rawMultiplier).toFixed(4);
  score = score * combinedMultiplier;

  // 3. Clamp al rango válido [0, 200]
  // El score puede superar 130 con todos los bonos activos; 200 es el límite técnico
  const finalScore = Math.min(200, Math.max(0, Math.round(score)));

  return {
    finalScore,
    baseScore,
    combinedMultiplier,
    skipped: [...skip],
    bonuses: { killChain, temporal, fpPenalty, scoreDecay, geoRisk, assetTier, offHours },
  };
}

/**
 * Atajo: aplica solo los bonos que la vista SQL v4 NO calcula. Use this
 * cuando el `baseScore` viene de `v_incident_score_v4`. Equivalente a llamar
 * `applyAllBonuses(score, { ..., skipBonuses: BONUSES_IN_SQL_V4 })`.
 */
export function applyNodeOnlyBonuses(baseScore, opts = {}) {
  return applyAllBonuses(baseScore, { ...opts, skipBonuses: BONUSES_IN_SQL_V4 });
}

// ── Log de bonos aplicados ────────────────────────────────────────────────────

/**
 * Persiste el resultado de applyAllBonuses en scoring_bonus_log (best-effort).
 * No lanza excepciones — solo logea si falla.
 *
 * @param {string} caseId
 * @param {object} bonusResult — resultado de applyAllBonuses
 */
export async function persistBonusLog(caseId, bonusResult) {
  if (!caseId || !bonusResult?.bonuses) return;

  const { bonuses, combinedMultiplier, baseScore, finalScore } = bonusResult;
  const entries = [
    bonuses.killChain.value   !== 0
      && { type: "kill_chain_depth", value: bonuses.killChain.value,   detail: bonuses.killChain.detail },
    bonuses.temporal.multiplier !== 1.0
      && { type: "temporal_fresh",   value: null, mult: bonuses.temporal.multiplier, detail: bonuses.temporal.detail },
    bonuses.fpPenalty.value   !== 0
      && { type: "fp_penalty",       value: bonuses.fpPenalty.value,   detail: bonuses.fpPenalty.detail },
    bonuses.scoreDecay?.value !== 0
      && bonuses.scoreDecay?.value != null
      && { type: "score_decay",      value: bonuses.scoreDecay.value,  detail: bonuses.scoreDecay.detail },
    bonuses.geoRisk.multiplier !== 1.0
      && { type: "geo_risk",         value: null, mult: bonuses.geoRisk.multiplier,  detail: bonuses.geoRisk.detail },
    bonuses.offHours?.multiplier !== undefined && bonuses.offHours.multiplier !== 1.0
      && { type: "off_hours",        value: null, mult: bonuses.offHours.multiplier, detail: bonuses.offHours.detail },
    bonuses.assetTier.value   !== 0
      && { type: "asset_criticality",value: bonuses.assetTier.value,  detail: bonuses.assetTier.detail },
  ].filter(Boolean);

  if (!entries.length) return;

  try {
    // Batch INSERT — un solo round-trip PG por caso (hasta 6 bonos)
    const params = [caseId];
    const valueClauses = entries.map((e) => {
      const base = params.length + 1; // $2, $6, $10 …
      params.push(e.type, e.value ?? 0, e.mult ?? null, JSON.stringify(e.detail));
      return `($1, $${base}, $${base + 1}, $${base + 2}, $${base + 3})`;
    });
    await pgQuery(
      `INSERT INTO scoring_bonus_log
         (case_id, bonus_type, bonus_value, multiplier, detail)
       VALUES ${valueClauses.join(", ")}`,
      params,
    );
  } catch {
    // best-effort — no bloquear el flujo principal
  }
}
