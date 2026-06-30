/**
 * brand-analyzer — heurísticas TS sobre un snapshot Brand24 para producir
 * análisis ejecutivo (resumen, narrativas, riesgos/oportunidades, acciones).
 *
 * Determinístico, sin LLM. Se ejecuta en el cliente sobre el payload que ya
 * vino del backend (`brand24_snapshots.payload` → `SurveillanceBrand24Result`).
 *
 * Diseño:
 * - No se asume conocimiento del dominio. El país "home" se infiere del TLD.
 * - El cluster de narrativas se construye combinando:
 *     1. País de pertenencia del hashtag (home / otro país LATAM / global).
 *     2. Si el hashtag matchea patrones genéricos off-topic (hardware/viral).
 * - Cuando no hay separación clara, el panel muestra una sola narrativa.
 *
 * Limitaciones honestas:
 * - El snapshot no incluye lista de "keywords del wordcloud" del PDF.
 *   La separación se hace solo por hashtags + sites/authors (cuando hay).
 * - No hay sentiment delta vs período previo en el shape persistido — solo
 *   absolutos. El driver "aumento del negativo" se infiere del volumeDelta.
 */

import type {
  SurveillanceBrand24Result,
  Brand24Hashtag,
} from "@/types/digital-surveillance";

// ─────────────────────────────────────────────────────────────────────────────
// Diccionario de países LATAM — pattern por país
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Mapeo país → patrones de hashtag/keyword que sugieren contexto de ese país.
 * El pattern es laxo: cubre nombre, ciudades grandes, medios principales y
 * términos institucionales habituales. NO es una lista cerrada — la idea es
 * separar "marca está siendo discutida acá" vs "marca está siendo discutida
 * en otro país", y bajo la suposición razonable de que el operador SOC se
 * ocupa de su país de operación.
 *
 * Ampliable: cuando se agregue un país, sumar la entrada al diccionario y
 * el analyzer lo respeta sin más cambios.
 */
type CountryDef = {
  code: string;            // ISO 3166-1 alpha-2 lowercase
  name: string;            // nombre para mostrar
  /** Pattern (i flag) que matchea hashtags/strings asociados al país. */
  patterns: RegExp;
};

const COUNTRIES: CountryDef[] = [
  { code: "py", name: "Paraguay",  patterns: /\b(paraguay|asunci[óo]n|abc|nanduti|telefuturo|ultimahora|laci|nacionales|abcnoticias|abctvpy|telefuturopy|cdepy)\b/i },
  { code: "co", name: "Colombia",  patterns: /\b(colombia|bogot[áa]|cali|medell[íi]n|barranquilla|caracol|eltiempo|elcolombiano|semana|fomag)\b/i },
  { code: "cl", name: "Chile",     patterns: /\b(chile|santiago|emol|biobio|latercera|chileatiende)\b/i },
  { code: "ar", name: "Argentina", patterns: /\b(argentina|buenosaires|clar[íi]n|lanacionar|infobae|tn|c5n)\b/i },
  { code: "br", name: "Brasil",    patterns: /\b(brasil|brazil|s[ãa]o.?paulo|riodejaneiro|globo|folha|uol)\b/i },
  { code: "mx", name: "México",    patterns: /\b(m[ée]xico|cdmx|guadalajara|reforma|milenio|eluniversal|excelsior)\b/i },
  { code: "pe", name: "Perú",      patterns: /\b(per[úu]|lima|comercio|larepublica|rpp)\b/i },
  { code: "uy", name: "Uruguay",   patterns: /\b(uruguay|montevideo|elpa[íi]suy|elobservador|subrayado)\b/i },
  { code: "bo", name: "Bolivia",   patterns: /\b(bolivia|lapaz|santacruz|eldeber|paginasiete)\b/i },
  { code: "ec", name: "Ecuador",   patterns: /\b(ecuador|quito|guayaquil|elcomercio|eluniverso)\b/i },
  { code: "ve", name: "Venezuela", patterns: /\b(venezuela|caracas|maracaibo|elnacional|eluniversal)\b/i },
  { code: "us", name: "USA",       patterns: /\b(usa|miami|nyc|losangeles|nytimes|wsj|cnn|foxnews)\b/i },
  { code: "es", name: "España",    patterns: /\b(espa[ñn]a|madrid|barcelona|elpais|elmundo|abces)\b/i },
];

/**
 * Patrones genéricos off-topic — independientes del país. Cubren tres casos
 * típicos donde el nombre de una marca colisiona con otro contexto:
 *   - Hardware tech (Lenovo, monitores, RAM, SSD, "portátil") — caso real IPS.
 *   - Algoritmo de distribución viral (#fyp, #foryou, #parati) — no es ruido
 *     por sí mismo pero sí marca contenido sin relación con la marca.
 *   - Spam de marketing (#offer, #promo) — barato dejarlo afuera.
 */
const GENERIC_OFFTOPIC_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "Hardware/tech", re: /\b(laptop|tablet|monitor|lenovo|asus|hp|dell|samsung|gaming|videojuego|ssd|ram|hardware|computad|portatil|portátil|pulgad|lcd|oled|pixel|cpu|gpu)\b/i },
  { name: "Algoritmo viral", re: /\b(fyp|foryou|parati|viral|trending|tiktokmademe)\b/i },
  { name: "Spam/marketing", re: /\b(offer|promo|descuento|sale|black.?friday|cybermonday|openshop)\b/i },
];

// ─────────────────────────────────────────────────────────────────────────────
// Inferencia de país desde el dominio
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Devuelve el código de país (ISO alpha-2 lowercase) inferido del TLD.
 *
 * Reglas:
 *   - `.com.py`, `.gov.py`, `.edu.py` → `py`
 *   - `.py` → `py`
 *   - `.com.co` → `co`
 *   - `.com`, `.net`, `.org` (gTLD) → `null` (sin país conocido)
 *
 * Si el TLD no está en la lista de países cubiertos, también devuelve null.
 */
export function inferHomeCountryFromDomain(domain: string): string | null {
  const parts = domain.toLowerCase().split(".");
  if (parts.length < 2) return null;
  const tld = parts[parts.length - 1];
  // Segundo nivel (ej. `gov.py`, `com.py`) — preferimos el alpha-2 del último.
  if (tld.length === 2 && COUNTRIES.some((c) => c.code === tld)) return tld;
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shape del análisis devuelto
// ─────────────────────────────────────────────────────────────────────────────

export type ExecutiveSummary = {
  oneLine: string;
  highlights: Array<{ label: string; value: string; tone: "positive" | "negative" | "neutral" }>;
  drivers: string[];
};

export type NarrativeSplit = {
  /** Identificador estable para keys de React. */
  id: string;
  label: string;
  /** % aproximado del total de hashtags clasificables. */
  weightPercent: number;
  sentimentBias: "negative" | "positive" | "neutral";
  driver: string;
  hashtags: string[];
  /** Si esta narrativa es ruido (foránea u off-topic) y debería excluirse del análisis institucional. */
  isNoise: boolean;
};

export type Risk = {
  severity: "high" | "medium" | "low";
  label: string;
  detail: string;
};

export type Opportunity = { label: string; detail: string };

export type ActionItem = {
  priority: 1 | 2 | 3;
  category: "crisis" | "social" | "pr" | "kpi" | "product";
  label: string;
  dueIn: string;
};

export type KpiTarget = { name: string; baseline: string; target: string };

export type BrandAnalysis = {
  executive: ExecutiveSummary;
  narratives: NarrativeSplit[];
  risks: Risk[];
  opportunities: Opportunity[];
  actions: ActionItem[];
  kpis: KpiTarget[];
  /** Información sobre el país inferido y la calidad del split. Útil para la UI. */
  context: {
    homeCountry: { code: string; name: string } | null;
    hashtagCoverage: { classified: number; total: number };
  };
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de formato
// ─────────────────────────────────────────────────────────────────────────────

function fmtCompact(n: number): string {
  if (!Number.isFinite(n)) return "—";
  const abs = Math.abs(n);
  if (abs >= 1_000_000) return `${(n / 1_000_000).toFixed(abs >= 10_000_000 ? 0 : 1)} M`;
  if (abs >= 1_000)     return `${(n / 1_000).toFixed(abs >= 10_000 ? 0 : 1)} K`;
  return String(Math.round(n));
}

function fmtPercent(n: number, digits = 0): string {
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(digits)}%`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Clasificador de hashtags
// ─────────────────────────────────────────────────────────────────────────────

type HashtagCluster = {
  /** "home" | "foreign:<code>" | "offtopic:<name>" | "ambiguous" */
  key: string;
  countryCode: string | null;
  offTopicName: string | null;
  isHome: boolean;
};

function classifyHashtag(tag: string, homeCode: string | null): HashtagCluster {
  // Países: primer match gana
  for (const c of COUNTRIES) {
    if (c.patterns.test(tag)) {
      const isHome = homeCode === c.code;
      return {
        key: isHome ? "home" : `foreign:${c.code}`,
        countryCode: c.code,
        offTopicName: null,
        isHome,
      };
    }
  }
  // Off-topic
  for (const ot of GENERIC_OFFTOPIC_PATTERNS) {
    if (ot.re.test(tag)) {
      return { key: `offtopic:${ot.name}`, countryCode: null, offTopicName: ot.name, isHome: false };
    }
  }
  return { key: "ambiguous", countryCode: null, offTopicName: null, isHome: false };
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline principal
// ─────────────────────────────────────────────────────────────────────────────

export function analyzeBrand(data: SurveillanceBrand24Result | null): BrandAnalysis | null {
  if (!data?.summary) return null;
  const s = data.summary;

  // ── Contexto base ────────────────────────────────────────────────────────
  const homeCode = inferHomeCountryFromDomain(data.domain);
  const homeCountry = homeCode ? { code: homeCode, name: COUNTRIES.find((c) => c.code === homeCode)!.name } : null;

  // ── Ratios ───────────────────────────────────────────────────────────────
  const totalPolar  = s.positiveCount + s.negativeCount;
  const negRatio    = totalPolar > 0 ? s.negativeCount / totalPolar : 0;
  const negRatioPct = negRatio * 100;
  const totalReach  = (s.socialReach ?? 0) + (s.nonSocialReach ?? 0);

  // ── Narrativas ───────────────────────────────────────────────────────────
  const { narratives, hashtagCoverage } = buildNarratives(data.hashtags ?? [], homeCode);

  // ── Resumen ejecutivo ────────────────────────────────────────────────────
  const driverTokens: string[] = [];
  if (negRatioPct >= 65) driverTokens.push("sentimiento mayoritariamente negativo");
  else if (negRatioPct >= 50) driverTokens.push("sentimiento balanceado-negativo");
  else if (negRatioPct > 0) driverTokens.push("sentimiento balanceado o positivo");

  if (s.volumeDeltaPercent >= 5) driverTokens.push(`volumen creciendo (${fmtPercent(s.volumeDeltaPercent)})`);
  else if (s.volumeDeltaPercent <= -5) driverTokens.push(`volumen en caída (${fmtPercent(s.volumeDeltaPercent)})`);

  const noiseTotal = narratives.filter((n) => n.isNoise).reduce((a, n) => a + n.weightPercent, 0);
  if (noiseTotal >= 15) {
    driverTokens.push(`mezcla con narrativa ruido (≈${fmtPercent(noiseTotal)})`);
  }

  const executive: ExecutiveSummary = {
    oneLine:
      negRatioPct >= 60 && s.volumeDeltaPercent >= 5
        ? "El volumen crece pero el sentimiento se deteriora más rápido — escenario de alerta."
        : negRatioPct >= 60
        ? "Sentimiento mayoritariamente negativo — atención reputacional necesaria."
        : s.volumeDeltaPercent >= 15
        ? "Crecimiento de volumen significativo — capturar la conversación."
        : totalPolar === 0
        ? "Sin polarización clasificada en el snapshot — falta data de sentiment."
        : "Marca con cobertura estable — oportunidad de profundizar contenido propio.",
    highlights: [
      {
        label: "Menciones",
        value: `${fmtCompact(s.volumeMentions)} (${s.volumeDeltaPercent >= 0 ? "+" : ""}${fmtPercent(s.volumeDeltaPercent)})`,
        tone: s.volumeDeltaPercent >= 0 ? "neutral" : "negative",
      },
      { label: "Alcance total", value: fmtCompact(totalReach), tone: "neutral" },
      {
        label: "Negativas",
        value: totalPolar > 0 ? `${s.negativeCount} (${fmtPercent(negRatioPct)})` : "s/clasificar",
        tone: negRatioPct >= 60 ? "negative" : negRatioPct >= 40 ? "neutral" : "positive",
      },
      { label: "AVE", value: `USD ${fmtCompact(s.ave)}`, tone: "neutral" },
    ],
    drivers: driverTokens,
  };

  // ── Riesgos y oportunidades ──────────────────────────────────────────────
  const risks: Risk[] = [];
  const opportunities: Opportunity[] = [];

  if (negRatioPct >= 70) {
    risks.push({
      severity: "high",
      label: `Sentimiento crítico (${fmtPercent(negRatioPct)} negativo)`,
      detail: "Mayoría abrumadora de menciones polarizadas son negativas. Requiere intervención de crisis.",
    });
  } else if (negRatioPct >= 50) {
    risks.push({
      severity: "medium",
      label: `Sentimiento adverso (${fmtPercent(negRatioPct)} negativo)`,
      detail: "Más de la mitad de las menciones polarizadas son negativas. Vigilar drivers narrativos.",
    });
  } else if (totalPolar > 0) {
    opportunities.push({
      label: "Sentimiento balanceado",
      detail: `${fmtPercent(negRatioPct)} negativo — base sana para amplificar contenido positivo.`,
    });
  }

  if (s.volumeDeltaPercent >= 30) {
    risks.push({
      severity: "medium",
      label: `Volumen +${fmtPercent(s.volumeDeltaPercent)} — viralización en curso`,
      detail: "Alta velocidad de propagación: sin canal propio fuerte, la narrativa puede consolidarse antes de poder responder.",
    });
  }

  if (noiseTotal >= 15) {
    const noiseSample = narratives
      .filter((n) => n.isNoise)
      .flatMap((n) => n.hashtags.slice(0, 2))
      .slice(0, 4);
    risks.push({
      severity: "low",
      label: `Narrativa ruido ≈${fmtPercent(noiseTotal)} del feed`,
      detail: `${noiseSample.map((h) => `\`${h}\``).join(", ")} no corresponden al contexto monitoreado. Considerá exclusiones en el proyecto Brand24.`,
    });
    opportunities.push({
      label: "Limpieza de métricas",
      detail: "Excluir los clusters ruido del feed mejora la lectura del sentiment institucional real.",
    });
  }

  if (s.ugc >= 1000) {
    opportunities.push({
      label: `Comunidad activa (${fmtCompact(s.ugc)} UGC)`,
      detail: "Volumen alto de contenido generado por usuarios — base para programa de embajadores o response amplification.",
    });
  }

  if (s.socialReach > 0 && s.nonSocialReach > 0 && s.socialReach / Math.max(1, s.nonSocialReach) >= 0.8) {
    opportunities.push({
      label: "Alcance social ≈ medio tradicional",
      detail: "Paridad redes / noticias: oportunidad para campañas digital-first que multipliquen contenido editorial.",
    });
  }

  // ── Acciones priorizadas ─────────────────────────────────────────────────
  const actions: ActionItem[] = [];

  if (negRatioPct >= 60) {
    actions.push({
      priority: 1,
      category: "crisis",
      label: "Activar war room: identificar las top quejas por keyword y asignar dueño funcional",
      dueIn: "72 h",
    });
    actions.push({
      priority: 1,
      category: "social",
      label: "Activar/refrescar canales propios con plan editorial (≥ 3 posts/sem por canal)",
      dueIn: "1 semana",
    });
  }

  if (s.volumeDeltaPercent >= 20) {
    actions.push({
      priority: 1,
      category: "pr",
      label: "Designar 2-4 voceros con guion para entrevistas — el volumen subió y se está hablando sin la marca",
      dueIn: "1 semana",
    });
  }

  if (noiseTotal >= 15) {
    const noiseSample = narratives.filter((n) => n.isNoise).flatMap((n) => n.hashtags).slice(0, 3);
    actions.push({
      priority: 2,
      category: "kpi",
      label: `Excluir keywords ruido del feed Brand24 (${noiseSample.join(", ")}) para limpiar métricas`,
      dueIn: "Esta semana",
    });
  }

  actions.push({
    priority: 2,
    category: "social",
    label: "Serie de contenido educativo pinneable (FAQ, guías, procesos) en canales propios",
    dueIn: "2-4 semanas",
  });

  actions.push({
    priority: 3,
    category: "kpi",
    label: "Establecer baseline mensual: ratio negativo, share of voice oficial vs orgánico, tiempo de ack a quejas",
    dueIn: "30 días",
  });

  // ── KPIs ─────────────────────────────────────────────────────────────────
  const kpis: KpiTarget[] = [
    {
      name: "Ratio sentiment negativo",
      baseline: totalPolar > 0 ? fmtPercent(negRatioPct) : "s/medir",
      target: negRatioPct >= 70 ? "< 50% en 30 d" : negRatioPct >= 50 ? "< 40% en 60 d" : "mantener < 40%",
    },
    { name: "Tiempo de ack a denuncia", baseline: "s/medir", target: "< 24 h" },
    { name: "Engagement rate canales propios", baseline: "s/medir", target: "≥ 3% promedio" },
    { name: "Share of voice oficial", baseline: "s/medir", target: "≥ 10% del volumen orgánico" },
    {
      name: "UGC positivo / UGC total",
      baseline: `${fmtCompact(s.ugc)} UGC`,
      target: "establecer baseline + meta de crecimiento mes a mes",
    },
  ];

  return {
    executive,
    narratives,
    risks,
    opportunities,
    actions: actions.sort((a, b) => a.priority - b.priority),
    kpis,
    context: {
      homeCountry,
      hashtagCoverage,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Construcción de narrativas
// ─────────────────────────────────────────────────────────────────────────────

type NarrativeBucket = {
  weight: number;
  tags: string[];
};

function buildNarratives(
  hashtags: Brand24Hashtag[],
  homeCode: string | null,
): { narratives: NarrativeSplit[]; hashtagCoverage: { classified: number; total: number } } {
  if (hashtags.length === 0) {
    return {
      narratives: [],
      hashtagCoverage: { classified: 0, total: 0 },
    };
  }

  // Buckets dinámicos por cluster.
  const buckets = new Map<string, NarrativeBucket>();
  let classified = 0;
  let total = 0;

  for (const h of hashtags) {
    const w = Math.max(1, h.mentions);
    total += w;
    const cls = classifyHashtag(h.tag, homeCode);
    if (cls.key === "ambiguous") continue;
    classified += w;
    const b = buckets.get(cls.key) ?? { weight: 0, tags: [] };
    b.weight += w;
    b.tags.push(h.tag);
    buckets.set(cls.key, b);
  }

  if (classified === 0) {
    return {
      narratives: [
        {
          id: "single",
          label: "Narrativa única (sin separación detectable)",
          weightPercent: 100,
          sentimentBias: "neutral",
          driver: "Los hashtags disponibles no permiten separar contextos. Revisar manualmente o ampliar el snapshot.",
          hashtags: hashtags.slice(0, 5).map((h) => h.tag),
          isNoise: false,
        },
      ],
      hashtagCoverage: { classified: 0, total },
    };
  }

  // Convertir buckets a NarrativeSplit con label legible.
  const out: NarrativeSplit[] = [];
  for (const [key, bucket] of buckets.entries()) {
    const pct = Math.round((bucket.weight / classified) * 100);
    if (pct < 5) continue; // ruido < 5% no vale la pena mostrar

    let label: string;
    let driver: string;
    let isNoise: boolean;
    let sentimentBias: NarrativeSplit["sentimentBias"];

    if (key === "home") {
      const homeName = homeCode ? COUNTRIES.find((c) => c.code === homeCode)?.name : null;
      label = homeName ? `Narrativa local — ${homeName}` : "Narrativa principal";
      driver = "Conversación sobre la marca en el país monitoreado (servicios, denuncias, cobertura mediática local).";
      isNoise = false;
      sentimentBias = "negative"; // heurística: la narrativa institucional local suele ser la que arrastra crítica
    } else if (key.startsWith("foreign:")) {
      const code = key.slice("foreign:".length);
      const country = COUNTRIES.find((c) => c.code === code);
      label = `Narrativa foránea — ${country?.name ?? code.toUpperCase()}`;
      driver = `Menciones desde ${country?.name ?? code.toUpperCase()}: posible homonimia o cobertura cruzada. Verificar si corresponde monitorear.`;
      isNoise = true;
      sentimentBias = "neutral";
    } else if (key.startsWith("offtopic:")) {
      const name = key.slice("offtopic:".length);
      label = `Narrativa off-topic — ${name}`;
      driver = `Menciones que comparten el nombre pero refieren a otro contexto (${name.toLowerCase()}). Candidatas a exclusión en el proyecto Brand24.`;
      isNoise = true;
      sentimentBias = "neutral";
    } else {
      label = "Narrativa adicional";
      driver = "Cluster no clasificable automáticamente.";
      isNoise = false;
      sentimentBias = "neutral";
    }

    out.push({
      id: key,
      label,
      weightPercent: pct,
      sentimentBias,
      driver,
      hashtags: bucket.tags.slice(0, 6),
      isNoise,
    });
  }

  // Si no había "home" detectado pero hay clusters, sumamos un fallback "principal"
  // marcando que el feed parece distribuido entre varios contextos sin local claro.
  if (!buckets.has("home") && out.length > 0) {
    out.unshift({
      id: "principal-implicit",
      label: "Sin narrativa local clara",
      weightPercent: 100 - out.reduce((a, n) => a + n.weightPercent, 0),
      sentimentBias: "neutral",
      driver: homeCode
        ? `No se detectaron hashtags asociados al país de operación (${COUNTRIES.find((c) => c.code === homeCode)?.name}). Revisar coverage local del proyecto Brand24.`
        : "El dominio no permite inferir país. Configurar el TLD o agregar tags locales al proyecto Brand24.",
      hashtags: [],
      isNoise: false,
    });
  }

  // Ordenar: home primero, luego por peso descendente
  out.sort((a, b) => {
    if (a.id === "home") return -1;
    if (b.id === "home") return 1;
    return b.weightPercent - a.weightPercent;
  });

  return {
    narratives: out,
    hashtagCoverage: { classified, total },
  };
}
