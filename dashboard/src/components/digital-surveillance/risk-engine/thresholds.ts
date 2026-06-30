/**
 * Single source of truth — umbrales del módulo Vigilancia Digital.
 *
 * Toda la lógica que decide si una métrica es "ok / warning / critical"
 * (strip, alert-builders, risk factors, futuros tabs) lee de aquí. Cualquier
 * cambio de umbral debe hacerse en un único lugar.
 *
 * Ver `docs/VIGILANCIA-DIGITAL.md` §3 para la lógica de scoring del backend
 * y §4.0 para los estados de columna del strip.
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. Banda de riesgo global (alineada con backend `/api/surveillance/domain`)
// ─────────────────────────────────────────────────────────────────────────────

export const RISK_BAND = {
  /** score >= high → banda "high" (rojo). */
  high: 70,
  /** score >= medium → banda "medium" (ámbar). Por debajo, "low" (verde). */
  medium: 40,
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// 2. Apertura de caso SOC desde un risk factor / alerta
// ─────────────────────────────────────────────────────────────────────────────

/** Score mínimo del factor para mostrar el CTA "Abrir caso SOC". */
export const SOC_MIN_SCORE_FOR_CTA = 15;

/** Mapeo `score → severidad` para prerellenar el form del caso SOC. */
export const SOC_SEVERITY = {
  HIGH: 30,
  MEDIUM: 15,
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// 3. Infraestructura (Shodan)
// ─────────────────────────────────────────────────────────────────────────────

/** Puertos que disparan estado "critical" de la columna Infra del strip. */
export const HIGH_RISK_PORTS = new Set<number>([
  // Acceso remoto
  22,    // SSH
  23,    // Telnet
  3389,  // RDP
  5900,  // VNC
  // SMB / file-sharing
  139,   // NetBIOS
  445,   // SMB
  2049,  // NFS
  21,    // FTP
  // Bases de datos
  3306,  // MySQL
  5432,  // PostgreSQL
  6379,  // Redis
  9200,  // Elasticsearch
  27017, // MongoDB
]);

/** Etiqueta human-readable para puertos críticos. */
export const PORT_LABELS: Record<number, string> = {
  22: "SSH",
  23: "Telnet",
  21: "FTP",
  139: "NetBIOS",
  445: "SMB",
  2049: "NFS",
  3306: "MySQL",
  3389: "RDP",
  5432: "Postgres",
  5900: "VNC",
  6379: "Redis",
  9200: "Elasticsearch",
  27017: "MongoDB",
};

/** Puertos "estándar" — su sola presencia no eleva el estado a warning. */
export const STANDARD_PORTS = new Set<number>([80, 443, 25, 53]);

/** Cuántos hosts críticos del top-N exporta el alert-builder de infra. */
export const INFRA_TOP_N_ALERTS = 5;

/** Score que aporta cada hallazgo de infra al risk score (referencia backend). */
export const INFRA_SCORE = {
  EXPOSED_HOST: 5,         // por cada host visible
  CRITICAL_PORT: 30,       // suma fija al detectar 1+ puerto crítico
  EXPOSED_HOST_MAX: 35,    // tope por exposed-host
  CRITICAL_PORT_MAX: 45,   // tope por critical-port
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// 4. Dark web / IOCs (MISP)
// ─────────────────────────────────────────────────────────────────────────────

/** El backend MISP codifica threat-level alto como "1" (string). */
export const MISP_HIGH_THREAT_LEVEL = "1";
export const MISP_MEDIUM_THREAT_LEVEL = "2";

/** Top-N IOCs threat-level alto que el alert-builder convierte en alertas. */
export const MISP_TOP_N_HIGH_ALERTS = 3;

/** ≥ esta cantidad de IOCs en los últimos 7d → alerta "spike de IOCs". */
export const MISP_SPIKE_7D_THRESHOLD = 5;
export const MISP_SPIKE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** Aporte al risk score (referencia backend). */
export const MISP_SCORE = {
  IOC_HIT: 10,
  IOC_HIT_MAX: 35,
  HIGH_THREAT: 25,
  HIGH_THREAT_MAX: 45,
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// 5. Marca / sentimiento (Brand24)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lógica negRatio (positivas + negativas, ignora neutro):
 *   N >= MIN_CLASSIFIED && negRatio >= NEG_RATIO_CRITICAL  → critical
 *   N >= MIN_CLASSIFIED && negRatio >= NEG_RATIO_WARNING   → warning
 *
 * Este conjunto SE USA EN 3 LUGARES — strip, alert-builder, risk factor backend.
 * Mantenerlos sincronizados es la razón de existir de este archivo.
 */
export const BRAND24_NEG_RATIO_CRITICAL = 0.6;  // 60% negativo → crisis
export const BRAND24_NEG_RATIO_WARNING = 0.4;   // 40% negativo → alerta temprana
export const BRAND24_MIN_CLASSIFIED = 20;        // muestra mínima estadísticamente sana

/** ≥ ±X% de delta de volumen vs período previo → "anomalía de volumen". */
export const BRAND24_VOL_DELTA_WARN_PERCENT = 100;

/** Reach mínimo para considerar "alto reach" en menciones individuales. */
export const BRAND24_HIGH_REACH = 100_000;

/** Top-N menciones de alto reach + negativas que se convierten en alertas. */
export const BRAND24_TOP_N_HIGH_REACH_ALERTS = 3;

/** Aporte al risk score (referencia backend factor `brand24-sentiment`). */
export const BRAND24_SCORE = {
  SENTIMENT_MULTIPLIER: 25,   // round(negRatio * 25)
  SENTIMENT_MAX: 20,          // tope del factor
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// 6. Noticias / RSS
// ─────────────────────────────────────────────────────────────────────────────

/** ≥ N menciones directas → estado "warning" en strip + alerta de spike. */
export const RSS_COVERAGE_SPIKE = 20;

// ─────────────────────────────────────────────────────────────────────────────
// 7. Shodan — umbrales de exposición de infraestructura
// ─────────────────────────────────────────────────────────────────────────────

/** ≥ N hosts visibles en Shodan → finding agregado en feed de analista. */
export const SHODAN_HOSTS_WARN = 5;

// ─────────────────────────────────────────────────────────────────────────────
// 8. MISP — categorías que disparan findings críticos sin requerir threshold
// ─────────────────────────────────────────────────────────────────────────────

/** Categorías MISP que indican C2 / acceso activo — siempre `critical`. */
export const MISP_CRITICAL_CATEGORIES = new Set([
  "Network activity",
  "Persistence mechanism",
  "External analysis",
]);

/** Tags MISP (lowercase) que indican botnet / RAT / malware activo. */
export const MISP_CRITICAL_TAG_PATTERNS = [
  "botnet",
  "c2",
  "command-and-control",
  "rat",
  "stealer",
  "malware",
];

/** Top-N noticias con tono negativo que se convierten en alertas. */
export const RSS_TOP_N_NEG_ALERTS = 3;

/**
 * Regex de palabras clave negativas en título/snippet (ES). Heurística simple
 * — no es NLP. Pensada para captar noticias de riesgo reputacional clásicas.
 */
export const RSS_NEG_KEYWORDS =
  /\b(denun|fraude|hack|leak|breach|multa|crisis|fall|delit|estafa|robo|fuga|cierre|cae|caída|caido)\w*/i;

// ─────────────────────────────────────────────────────────────────────────────
// 7. Credenciales filtradas (snapshot leak-intel)
// ─────────────────────────────────────────────────────────────────────────────

/** ≥ N correos del dominio en datasets cargados → estado "critical" + fuga masiva. */
export const CREDS_MASS_LEAK_THRESHOLD = 1000;

/** Cualquier emailCount > 0 con N < threshold → estado "warning" / fuga parcial. */
export const CREDS_PARTIAL_LEAK_MIN = 1;

/** ≥ X% de contraseñas débiles (con muestra mínima) → alerta de hábito de contraseñas. */
export const CREDS_WEAK_PWD_RATE = 0.4;
export const CREDS_WEAK_PWD_MIN_SAMPLES = 50;

/** Aporte al risk score (referencia backend factor `leak-creds`). */
export const CREDS_SCORE = {
  PARTIAL: 10,
  PARTIAL_MAX: 25,
  MASS: 30,
  MASS_MAX: 40,
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// 8. Globos del dominio para búsqueda de archivos en S3 (intel-files)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Longitud mínima del primer label (`abc.com.py` → label="abc") para emitir
 * el glob `acme*`. Labels cortos como `fdc` o `abc` matcheaban filenames
 * ajenos en el bucket — ver auditoría hallazgo #11. Mantener alineado con
 * `legacyhunt-api/server.mjs:autoPatternsFromDomain`.
 */
export const APEX_GLOB_MIN_LEN = 5;

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cache TTLs cliente (espejo del servidor)
// ─────────────────────────────────────────────────────────────────────────────

export const STALE_TIME_MS = {
  /** Snapshot principal: agregador Shodan + MISP. */
  domain: 2 * 60 * 1000,        // 2 min
  /** RSS: feeds, cache server-side 30 min. */
  rss: 30 * 60 * 1000,          // 30 min
  /** Brand24: cache server-side 30 min. */
  brand24: 30 * 60 * 1000,      // 30 min
  /** Lista de archivos S3 que coinciden con el dominio. */
  intelFiles: 5 * 60 * 1000,    // 5 min
  /** CT logs (crt.sh) — cambian rápido, TTL corto. */
  ctLogs: 5 * 60 * 1000,        // 5 min (Fase 3 §9.2)
  /** Typosquatting (dnstwist) — DNS no muta tan rápido. */
  typosquatting: 60 * 60 * 1000, // 1 h
  /** Phishing kits (URLhaus/OpenPhish). */
  phishingKits: 15 * 60 * 1000, // 15 min
  /** Leak velocity — derivado, no fetch externo. */
  leakVelocity: 60 * 1000,      // 1 min (recalcula on demand)
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// Fase 3 — DRP / Impersonation real-time (§9 del doc)
// ─────────────────────────────────────────────────────────────────────────────

// 11. Certificate Transparency Logs ───────────────────────────────────────────

/** Score 0-1 de Levenshtein normalizado para considerar un cert "look-alike". */
export const CT_LOOK_ALIKE_THRESHOLD = 0.7;

/** Ventana de horas para considerar un cert "fresh" (alta urgencia). */
export const CT_FRESH_WINDOW_HOURS = 24;

/** Aporte al risk score por cert look-alike detectado. */
export const CT_SCORE = {
  /** Cert nuevo (≤24h) + dominio resuelve DNS → critical. */
  FRESH_RESOLVING: 45,
  /** Cert nuevo sin DNS resolución (preparación). */
  FRESH_PARKED:    25,
  /** Cert antiguo (>7d) sin DNS — informativo. */
  STALE:           10,
} as const;

// 12. Typosquatting (dnstwist) ───────────────────────────────────────────────

/** Similaridad mínima para considerar un dominio "candidato real". */
export const TYPO_SIMILARITY_THRESHOLD = 0.6;

/** Aporte al risk score por candidato. */
export const TYPO_SCORE = {
  /** Dominio resuelve A + tiene MX (email spoofing-ready). */
  WITH_MX:    35,
  /** Resuelve A pero sin MX (probable parking / squat). */
  WITH_DNS:   20,
  /** Solo registrado sin DNS activo. */
  REGISTERED: 10,
} as const;

/** Mínimo de candidatos resolviendo para escalar la severidad de la columna. */
export const TYPO_RESOLVING_WARN = 1;
export const TYPO_RESOLVING_CRITICAL = 3;

// 13. Leak Velocity ──────────────────────────────────────────────────────────

/** Spike ratio (current / baseline) que dispara la alerta de velocidad alta. */
export const VELOCITY_SPIKE_WARN = 2;        // 2x baseline
export const VELOCITY_SPIKE_CRITICAL = 5;    // 5x baseline = ataque masivo

/** Aporte al risk score por spike. */
export const VELOCITY_SCORE = {
  WARN:     20,
  CRITICAL: 40,
} as const;

// 14. Impersonation Confidence (modelo IA) ────────────────────────────────────

/** Score 0-1 del modelo que considera "alta confianza en suplantación". */
export const IMPERSONATION_HIGH_CONFIDENCE = 0.8;

/** Aporte al risk score. */
export const IMPERSONATION_SCORE = {
  HIGH: 50,    // ≥0.8 → critical
  MED:  30,    // ≥0.6 → high
  LOW:  15,    // ≥0.4 → medium
} as const;

// 15. Phishing Kit detection (URLhaus / OpenPhish) ───────────────────────────

/** Aporte al risk score por match contra base de phishing kits. */
export const PHISHING_KIT_SCORE = {
  /** Match en feed activo (último reporte ≤7d). */
  ACTIVE:   50,
  /** Match histórico (>7d desde último reporte). */
  HISTORIC: 25,
} as const;

