/**
 * scoringEngine.mjs — Motor de Scoring Dinámico por perfil
 *
 * Define los 4 perfiles canónicos del sistema. Cada perfil contiene:
 *  - La configuración completa de fórmula compatible con scoringFormulaPublishService
 *  - Multiplicadores de fuentes (wWazuh, wEvidence, wContext, wMisp, wTor)
 *  - Umbrales de severidad
 *  - Reglas de bonificación específicas del perfil
 *
 * Flujo seguro "draft → diff → confirmación → apply":
 *  1. Operador elige perfil → getProfile(id) devuelve la config draft
 *  2. Frontend muestra diff vs. fórmula activa (via /api/scoring/formula/current)
 *  3. Operador confirma → POST /api/scoring/formula/publish (con código de attestation)
 *  4. API aplica la vista runtime en Trino via sqlCreateRuntimeScoringView()
 */

// ── Perfiles canónicos ────────────────────────────────────────────────────────

export const SCORING_PROFILES = [
  {
    id:          "wazuh-critico",
    name:        "Wazuh Crítico",
    description: "Máximo peso en alertas Wazuh. Para entornos con cobertura Wazuh extensiva.",
    requiredSources: ["wazuh"],
    color:       "#00f5ff",
    // Pesos
    w_mitre:     1.0,
    w_evidence:  0.5,   // reducido — sin corroboración externa
    w_wazuh:     2.0,   // amplificado
    w_context:   1.0,
    w_tor:       1.0,
    w_misp:      1.0,
    // Bonuses estándar
    bonus_vt_malicious:  8,
    bonus_abuseipdb_high: 6,
    bonus_urlhaus:       10,
    bonus_openphish:      8,
    abuseipdb_high_threshold: 50,
    // Umbrales de severidad
    thr_critical: 60,   // bajo → más sensible a Wazuh críticos
    thr_high:     45,
    thr_medium:   22,
    thr_low:      10,
  },
  {
    id:          "wazuh-suricata",
    name:        "Wazuh + Suricata",
    description: "Combina detección endpoint (Wazuh) con IDS de red (Suricata). Perfil por defecto.",
    requiredSources: ["wazuh", "suricata"],
    color:       "#a855f7",
    w_mitre:     1.0,
    w_evidence:  1.0,
    w_wazuh:     1.8,
    w_context:   2.5,   // contexto multi-fuente amplificado
    w_tor:       1.0,
    w_misp:      1.0,
    bonus_vt_malicious:   8,
    bonus_abuseipdb_high: 6,
    bonus_urlhaus:       10,
    bonus_openphish:      8,
    abuseipdb_high_threshold: 50,
    thr_critical: 75,
    thr_high:     55,
    thr_medium:   28,
    thr_low:      12,
  },
  {
    id:          "fortigate-wazuh",
    name:        "Fortigate + Wazuh",
    description: "Correlación perímetro (Fortigate) + endpoint (Wazuh). Recompensa el mismo IOC bloqueado en el firewall y alertado en el host.",
    requiredSources: ["fortigate", "wazuh"],
    color:       "#06b6d4",
    w_mitre:     1.2,
    w_evidence:  1.0,
    w_wazuh:     1.8,
    w_context:   2.5,   // correlación perímetro↔endpoint amplificada
    w_tor:       1.5,
    w_misp:      1.0,
    bonus_vt_malicious:   8,
    bonus_abuseipdb_high: 6,
    bonus_urlhaus:       10,
    bonus_openphish:      8,
    abuseipdb_high_threshold: 50,
    thr_critical: 74,
    thr_high:     48,
    thr_medium:   27,
    thr_low:      10,
  },
  {
    id:          "wazuh-suricata-logs",
    name:        "Wazuh + Suricata + Logs",
    description: "Triple cobertura: endpoint + IDS + syslog. Bonus automático por 3+ fuentes.",
    requiredSources: ["wazuh", "suricata", "syslog"],
    color:       "#ff9500",
    w_mitre:     1.0,
    w_evidence:  1.2,
    w_wazuh:     1.5,
    w_context:   3.0,   // contexto máximo — 3 fuentes confirman el evento
    w_tor:       1.0,
    w_misp:      1.0,
    bonus_vt_malicious:   8,
    bonus_abuseipdb_high: 6,
    bonus_urlhaus:       10,
    bonus_openphish:      8,
    // Bonus adicional por correlación de 3+ fuentes (se aplica en la vista SQL)
    bonus_multi_source:  27,
    abuseipdb_high_threshold: 50,
    thr_critical: 78,
    thr_high:     58,
    thr_medium:   32,
    thr_low:      15,
  },
  {
    id:          "intel-externa",
    name:        "Intel Externa Completa",
    description: "Máxima integración con inteligencia externa: VirusTotal + MISP + AbuseIPDB.",
    requiredSources: ["wazuh", "threat_intel"],
    color:       "#ff3b5c",
    w_mitre:     1.0,
    w_evidence:  2.5,   // evidencia externa máxima
    w_wazuh:     1.0,
    w_context:   1.5,
    w_tor:       1.2,
    w_misp:      2.0,   // MISP double weight
    bonus_vt_malicious:   12,  // mayor penalización por VT positivos
    bonus_abuseipdb_high:  8,
    bonus_urlhaus:        12,
    bonus_openphish:      10,
    // Bonus especial por evento MISP de alta amenaza
    bonus_misp_high:      40,
    abuseipdb_high_threshold: 40,  // umbral más bajo → más sensible
    thr_critical: 80,
    thr_high:     60,
    thr_medium:   35,
    thr_low:      18,
  },
];

// ── Cache de perfiles activos (sincronizado con PostgreSQL en producción) ──────

let profilesCache = null;
let cacheLoadedAt = 0;
const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Carga perfiles desde PostgreSQL (con caché).
 * Si PostgreSQL no está disponible, usa los perfiles canónicos.
 * @param {import("pg").Pool} [pgPool]
 */
async function loadProfiles(pgPool) {
  const now = Date.now();
  if (profilesCache && (now - cacheLoadedAt) < CACHE_TTL_MS) {
    return profilesCache;
  }

  if (pgPool) {
    try {
      const { rows } = await pgPool.query(
        "SELECT * FROM scoring_profiles WHERE active = true ORDER BY base_score DESC",
      );
      if (rows.length > 0) {
        profilesCache = rows;
        cacheLoadedAt = now;
        return profilesCache;
      }
    } catch {
      // Fallback a perfiles canónicos
    }
  }

  profilesCache = SCORING_PROFILES;
  cacheLoadedAt = now;
  return profilesCache;
}

/** Devuelve todos los perfiles disponibles */
export function listProfiles() {
  return SCORING_PROFILES;
}

/** Devuelve un perfil por ID (canónico) */
export function getProfile(id) {
  return SCORING_PROFILES.find((p) => p.id === id) ?? null;
}

/** Invalida la caché de perfiles */
export function invalidateProfilesCache() {
  profilesCache = null;
  cacheLoadedAt = 0;
}

/**
 * Calcula el score de un incidente dado sus fuentes activas, usando el
 * perfil especificado.
 *
 * @param {{ sources: string[], severity?: string, scoreComponents?: object }} incident
 * @param {string}  profileId  — ID del perfil a aplicar
 * @param {import("pg").Pool} [pgPool]
 */
export async function scoreIncident(incident, profileId = "wazuh-suricata", pgPool = null) {
  const profiles = await loadProfiles(pgPool);

  // Buscar perfil (primero en cache/PG, luego canónico)
  const profile = profiles.find((p) => p.id === profileId)
    ?? getProfile(profileId)
    ?? SCORING_PROFILES[1]; // wazuh-suricata como fallback

  const activeSources  = new Set(incident.sources ?? []);
  const sourcesMatched = profile.requiredSources?.every?.((s) => activeSources.has(s)) ?? true;

  if (!sourcesMatched) {
    // El incidente no tiene las fuentes requeridas para este perfil
    return {
      score:   50,
      profile: null,
      reason:  `Fuentes requeridas no presentes: ${profile.requiredSources?.join(", ")}`,
    };
  }

  // Aplicar pesos al score base si viene con componentes
  const c = incident.scoreComponents ?? {};
  const raw =
    (c.mitre    ?? 0) * profile.w_mitre    +
    (c.evidence ?? 0) * profile.w_evidence +
    (c.wazuh    ?? 0) * profile.w_wazuh    +
    (c.context  ?? 0) * profile.w_context  +
    (c.misp     ?? 0) * profile.w_misp;

  const score = Math.min(100, Math.max(0, Math.round(raw)));

  return {
    score,
    profile,
    appliedWeights: {
      w_mitre:    profile.w_mitre,
      w_evidence: profile.w_evidence,
      w_wazuh:    profile.w_wazuh,
      w_context:  profile.w_context,
      w_misp:     profile.w_misp,
    },
  };
}

/**
 * Convierte un perfil canónico al formato de scoringFormulaConfig
 * esperado por scoringFormulaPublishService.mjs
 */
export function profileToFormulaConfig(profile) {
  return {
    wMitre:    profile.w_mitre,
    wEvidence: profile.w_evidence,
    wWazuh:    profile.w_wazuh,
    wContext:  profile.w_context,
    wTor:      profile.w_tor    ?? 1.0,
    wMisp:     profile.w_misp,
    bonusVtMalicious:   profile.bonus_vt_malicious    ?? 8,
    bonusAbuseipdbHigh: profile.bonus_abuseipdb_high  ?? 6,
    bonusUrlhaus:       profile.bonus_urlhaus         ?? 10,
    bonusOpenphish:     profile.bonus_openphish       ?? 8,
    abuseipdbHighThreshold: profile.abuseipdb_high_threshold ?? 50,
    thrCritical: profile.thr_critical,
    thrHigh:     profile.thr_high,
    thrMedium:   profile.thr_medium,
    thrLow:      profile.thr_low,
  };
}
