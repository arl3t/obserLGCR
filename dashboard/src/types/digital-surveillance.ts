export type RiskBand = "low" | "medium" | "high";

// ── RSS / Noticias ────────────────────────────────────────────────────────────

export type RssNewsItem = {
  title:       string;
  url:         string;
  source:      string;
  publishedAt: string | null;
  snippet:     string;
  matched?:    boolean;  // true cuando el item coincide con el dominio buscado
};

export type SurveillanceRssResult = {
  domain:     string;
  items:      RssNewsItem[];   // menciones directas (Google News + coincidencias en custom)
  custom:     RssNewsItem[];   // TODOS los items de feeds personalizados (matched=true si coincide)
  general:    RssNewsItem[];   // noticias de seguridad sin coincidencia directa
  fetchedAt:  string;
  fromCache:  boolean;
};

// ── Gestión de feeds RSS personalizados ──────────────────────────────────────

export type RssFeed = {
  id:         number;
  name:       string;
  url:        string;
  category:   string;
  active:     boolean;
  created_at: string;
  last_ok_at: string | null;
  last_items: number | null;
};

/** Canal de Telegram como fuente CTI (integración MTProto, F1: catálogo). */
export type TelegramFeed = {
  id:             number;
  channel_ref:    string;
  name:           string;
  trust_tier:     number;        // 1 alta · 2 media · 3 ruido
  active:         boolean;
  last_msg_id:    number;
  last_sync_at:   string | null;
  last_ioc_count: number | null;
  created_at:     string;
};

export type RiskFactorItem = {
  id: string;
  title: string;
  detail: string;
  score: number;
};

// ── Shodan ────────────────────────────────────────────────────────────────────

export type SurveillanceShodanMatch = {
  ip: string | null;
  hostnames: string[];
  org: string | null;
  port: number | null;
  transport: string | null;
  product: string | null;
  country: string | null;
  timestamp: string | null;
};

// ── MISP ──────────────────────────────────────────────────────────────────────

export type SurveillanceMispHit = {
  id: string;
  uuid: string;
  type: string;
  value: string;
  category: string;
  to_ids: boolean;
  comment: string | null;
  event_id: string;
  event_title: string | null;
  threat_level: string | null;
  tags: string[];
  /** ISO 8601 string. El backend (`mispService.normalizeMispTimestamp`) ya
   *  convierte el formato variable de MISP (epoch en segundos, ms o ISO) a
   *  ISO 8601 antes de salir, así que el frontend lo consume directamente. */
  timestamp: string | null;
};

// ── Resultado agregado por dominio (respuesta de /api/surveillance/domain) ────

export type SurveillanceDomainResult = {
  domain: string;
  queriedAt: string;
  shodan: {
    configured: boolean;
    total?: number;
    matches?: SurveillanceShodanMatch[];
    error?: string;
  };
  misp: {
    configured: boolean;
    hits?: SurveillanceMispHit[];
    count?: number;
    error?: string;
  };
  /**
   * @deprecated CTI Cloud & Olé fue desconectado de este endpoint y se invoca
   * manualmente vía `POST /api/intel/cti/leaks/domain` (ver `server.mjs`).
   * El servidor retorna siempre `{ configured: false }` aquí; el campo se
   * mantiene para compatibilidad de contrato con clientes antiguos.
   */
  cti: {
    configured: boolean;
    hits?: unknown[];
    count?: number;
    error?: string;
  };
  brand24: {
    configured: boolean;
  };
  risk: {
    score: number;
    band: RiskBand;
    factors: RiskFactorItem[];
  };
};

// ── Brand24 (pestañas Marca y Menciones) ─────────────────────────────────────

export type Brand24Sentiment = "positive" | "negative" | "neutral";

/**
 * Origen del payload servido por `/api/surveillance/brand24`:
 *   - "live"          → llamada en vivo a la API de Brand24
 *   - "snapshot-pdf"  → derivado del importador de PDF (offline / trial)
 *   - "cache"         → respuesta cacheada en memoria del backend
 *
 * Cuando `projectId` es `null` y `summary` es `null`, el dominio aún no tiene
 * proyecto Brand24 configurado en `brand24_projects` ni snapshots históricos.
 */
export type Brand24Source = "live" | "snapshot-pdf" | "cache";

export type Brand24Summary = {
  volumeMentions: number;
  volumeDelta: number;
  volumeDeltaPercent: number;
  socialReach: number;
  nonSocialReach: number;
  positiveCount: number;
  negativeCount: number;
  interactions: number;
  ugc: number;
  /** Advertising Value Equivalent en USD. */
  ave: number;
  byCategory: Array<{ category: string; count: number; deltaPercent: number }>;
  timeline:   Array<{ date: string; current: number; previous: number }>;
};

export type Brand24Mention = {
  id: string;
  author: string;
  source: string;
  publishedAt: string;
  snippet: string;
  url: string;
  sentiment: Brand24Sentiment;
  reach: number | null;
};

export type Brand24Author = {
  handle: string;
  source: string;
  followers: number;
  mentions: number;
  voiceSharePercent?: number;
  estSocialReach?: number;
};

export type Brand24Site = {
  domain: string;
  mentions: number;
  visits?: number;
  /** 0-10 según Brand24 (influence score). */
  influenceScore?: number;
};

export type Brand24Hashtag = { tag: string; mentions: number };

export type SurveillanceBrand24Result = {
  domain: string;
  projectId: string | null;
  summary: Brand24Summary | null;
  mentions: Brand24Mention[];
  authors: Brand24Author[];
  sites: Brand24Site[];
  hashtags: Brand24Hashtag[];
  source: Brand24Source;
  /** ISO date (YYYY-MM-DD) del snapshot cuando `source === "snapshot-pdf"`. */
  snapshotDate: string | null;
  fetchedAt: string;
  fromCache: boolean;
};

// ─────────────────────────────────────────────────────────────────────────────
// Fase 3 — DRP / Impersonation real-time
// Ver `docs/REWRITE-VIGILANCIA-PROGRESO.md §9` para el contexto completo.
// ─────────────────────────────────────────────────────────────────────────────

/** Severidad común de las amenazas DRP — alineada con `BrandAlertSeverity`. */
export type ThreatSeverity = "low" | "medium" | "high" | "critical";

/** Categoría de la amenaza (usada por filtros y badges en el feed). */
export type ThreatKind =
  | "ct-impersonation"
  | "typosquatting"
  | "leak-velocity"
  | "phishing-kit"
  | "impersonation-confidence";

// ── Certificate Transparency Logs ────────────────────────────────────────────

export type CTCertificate = {
  /** ID interno del log (sha256 del precert / leaf). */
  id: string;
  /** Dominio look-alike emitido (`m1crosoft-paraguay.com`). */
  domain: string;
  /** Issuer del cert (Let's Encrypt, Sectigo, etc.). */
  issuer: string;
  /** Alt-names del cert. */
  altNames: string[];
  /** Timestamp ISO del log entry (cuando crt.sh lo vio). */
  loggedAt: string;
  /** ISO de cuándo fue notBefore (validez). */
  notBefore: string | null;
  /** Score 0-1 de cuán parecido es el dominio al base (Levenshtein normalizado). */
  lookAlikeScore: number;
  /** ¿El dominio resuelve actualmente en DNS? */
  resolvesDns: boolean;
};

export type SurveillanceCTResult = {
  domain: string;
  /** Certs emitidos en los últimos 7 días (filtrados look-alike). */
  certificates: CTCertificate[];
  fetchedAt: string;
  fromCache: boolean;
};

// ── Typosquatting (dnstwist) ─────────────────────────────────────────────────

/** Tipo de permutación que generó el candidato. */
export type TypoMutationKind =
  | "addition"        // m1crosoft → microsoft
  | "omission"
  | "transposition"
  | "replacement"
  | "homoglyph"        // micr0soft, mіcrosoft (cyrillic)
  | "tld-swap"         // .com → .net
  | "subdomain"        // microsoft.com.attacker.tld
  | "bitsquatting";

export type TypoCandidate = {
  /** Dominio candidato. */
  domain: string;
  /** Tipo de mutación (categorización dnstwist). */
  mutation: TypoMutationKind;
  /** ¿Resuelve A/AAAA? */
  hasA: boolean;
  /** ¿Tiene MX activo? Si sí, el riesgo de email spoofing crece. */
  hasMx: boolean;
  /** ¿Responde HTTP/HTTPS? */
  hasHttp: boolean;
  /** Similaridad 0-1 vs el dominio base. */
  similarity: number;
  /** ISO de cuándo se vio por primera vez registrado. */
  firstSeen: string | null;
};

export type SurveillanceTypoResult = {
  domain: string;
  candidates: TypoCandidate[];
  fetchedAt: string;
  fromCache: boolean;
};

// ── Phishing Kits (URLhaus / OpenPhish) ──────────────────────────────────────

export type PhishingKitMatch = {
  /** URL del kit detectado. */
  url: string;
  /** Hash MD5/SHA256 de assets coincidentes. */
  hash: string | null;
  /** Fuente que lo reportó. */
  source: "URLhaus" | "OpenPhish" | "PhishTank" | "Internal";
  /** ISO de cuándo se vio. */
  reportedAt: string;
  /** Tags / clasificadores de la fuente. */
  tags: string[];
};

export type SurveillancePhishingResult = {
  domain: string;
  matches: PhishingKitMatch[];
  fetchedAt: string;
  fromCache: boolean;
};

// ── Leak Velocity (deriva de snapshot + brand24 history) ─────────────────────

/** Tasa de aparición de credenciales — comparable contra baseline. */
export type LeakVelocityResult = {
  domain: string;
  /** Cuentas nuevas detectadas en window (24h por default). */
  newCredsLast24h: number;
  /** Cuentas nuevas en últimos 7d. */
  newCredsLast7d: number;
  /** Baseline 30d para comparar (promedio de 24h en los últimos 30 días). */
  baseline24h: number;
  /** Razón actual / baseline — > 1 indica spike. */
  spikeRatio: number;
  /** ISO timestamp del cálculo. */
  computedAt: string;
};

// ── Active Impersonation (correlación cross-source) ──────────────────────────

/** Identificador de la correlación canónica detectada. */
export type CorrelationKind =
  | "active-impersonation-campaign"        // CT + DNS + leak velocity
  | "spoofing-infrastructure-ready"        // Typosquatting + MX + phishing-kit
  | "coordinated-reputation-credential";   // Brand24 spike + look-alike + leak

export type CorrelationFinding = {
  id: string;
  kind: CorrelationKind;
  severity: ThreatSeverity;
  title: string;
  detail: string;
  /** IDs de las evidencias que dispararon la correlación. */
  evidenceIds: string[];
  /** ISO timestamp de detección. */
  detectedAt: string;
};

// ── Threat unificado (lo que consume la UI) ─────────────────────────────────

/** Item del feed "Amenazas en Tiempo Real" — fuente normalizada. */
export type BrandThreat = {
  id: string;
  kind: ThreatKind;
  severity: ThreatSeverity;
  title: string;
  detail: string;
  /** Dominio o URL relacionada. */
  target: string;
  /** ISO timestamp de cuándo se detectó. */
  detectedAt: string;
  /** Origen humano-readable. */
  source: string;
};

export type SurveillanceBrandThreats = {
  domain: string;
  threats: BrandThreat[];
  correlations: CorrelationFinding[];
  /** Conteo agregado por kind (para badges/KPIs). */
  byKind: Record<ThreatKind, number>;
  /** Hay al menos 1 correlación activa de severidad critical/high. */
  hasActiveCampaign: boolean;
  fetchedAt: string;
};

// ─────────────────────────────────────────────────────────────────────────────
// Workspace del Analista — feed unificado de hallazgos cross-source
//
// Las fuentes (Shodan, MISP, Brand24, RSS, snapshot de credenciales,
// brandThreats) producen findings con estructura SOC playbook (qué/dónde/
// por qué/refs/acción). Un analista trabaja desde TabResumen consumiendo
// este feed; los tabs por-fuente se mantienen como vista de detalle.
// ─────────────────────────────────────────────────────────────────────────────

/** Categoría del finding — define icono + filtros + ruteo a tab de detalle. */
export type AnalystFindingKind =
  | "credential-leak"        // snapshot Leak Intel Hub
  | "shodan-exposure"        // hosts/puertos visibles
  | "misp-ioc"               // IOCs en MISP
  | "brand-mention-negative" // sentiment negativo Brand24
  | "news-coverage"          // mención directa en RSS
  | "brand-threat"           // typosquatting/CT/phishing kit (DRP)
  | "correlation";           // cross-source detectado

/** 5 niveles — `info` para hallazgos contextuales que no requieren acción. */
export type AnalystFindingSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Referencia cruzada — chip clickeable a otro tab del módulo. */
export type AnalystFindingRef = {
  /** Tab de Vigilancia al que dirige el chip. */
  tab: "ejecutivo" | "resumen" | "analisis" | "darkweb" | "credenciales" | "noticias" | "marca" | "reporte";
  /** Etiqueta visible (ej. "MISP IOC", "Shodan host"). */
  label: string;
  /** Hint para el tooltip — dato concreto referenciado (ej. la IP, el email). */
  hint?: string;
};

/** Acción recomendada — botón con handler conocido por TabResumen/Provider. */
export type AnalystFindingAction = {
  /** ID estable para tracking. */
  id: string;
  /** Texto del botón. */
  label: string;
  /** Tipo de acción — el handler lo despacha al flujo correspondiente. */
  kind:
    | "open-case"        // dispara OpenSocCaseForm con el factor
    | "add-watchlist"    // openWatchlist() del Provider
    | "rotate-creds"     // copia el email al clipboard + abre flujo IT
    | "block-ioc"        // copia el IOC al clipboard
    | "external-link"    // abre URL en nueva pestaña
    | "navigate-tab";    // cambia de tab
  /** Solo 1 acción primaria por card (botón con énfasis visual). */
  primary?: boolean;
  /** Payload opcional consumido por el handler (URL, IOC, email, etc.). */
  payload?: Record<string, string | number | boolean>;
};

/**
 * Finding del workspace de analista. Estructura SOC playbook de 5 campos:
 * (1) qué + severidad → `title` + `severity` + `kind`
 * (2) dónde → `sourceLabel` + `evidence` + `evidenceTimestamp`
 * (3) por qué importa → `why`
 * (4) refs cruzadas → `refs[]`
 * (5) recomendación → `actions[]` (al menos 1 con `primary: true`)
 */
export type AnalystFinding = {
  id: string;
  kind: AnalystFindingKind;
  severity: AnalystFindingSeverity;
  title: string;
  /** Origen humano-readable: "RedLine stealer dump", "Shodan", "MISP feed XYZ". */
  sourceLabel: string;
  /** Evidencia textual mostrada en la card (email + password, IP+puerto, IOC value). */
  evidence: string;
  /** Timestamp ISO del dato — cuándo se observó originalmente. */
  evidenceTimestamp: string | null;
  /** Razón por la que el analista debe actuar (contexto + correlaciones). */
  why: string;
  /** Chips clickeables a otros tabs con datos relacionados. */
  refs: AnalystFindingRef[];
  /** Botones de acción — al menos 1 primary cuando `severity` es `high`/`critical`. */
  actions: AnalystFindingAction[];
  /** ISO del momento de detección por el agregador (no del dato). */
  detectedAt: string;
};

/** Severity rank para ordenamiento — `critical` primero. */
export const ANALYST_SEVERITY_RANK: Record<AnalystFindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
