/** Query `?tab=` en `/credential-exposure` para abrir caza en documentos. */
export const CREDENTIAL_TAB_EXTERNAL_HUNT = "external-hunt";

/**
 * Extracción heurística de IOCs textuales desde dumps ULP / CSV de fugas:
 * familias de stealer/malware, foros, marketplaces y canales de distribución.
 * Listas ampliables (VITE_* o futuro backend).
 */

import { sortBy, take } from "lodash";

/** Evita dependencia circular con leak-intel.ts */
export type LeakFileScanInput = {
  path: string;
  rows: Record<string, string>[];
};

export type ThreatIndicatorCategory =
  | "malware_family"
  | "distribution_forum"
  | "marketplace"
  | "telegram";

export type ThreatIndicatorSample = {
  category: ThreatIndicatorCategory;
  label: string;
  sourceFile: string;
  excerpt: string;
};

export type DocumentThreatHuntResult = {
  malwareFamilies: { label: string; count: number }[];
  distributionSites: { label: string; count: number }[];
  telegramHandles: { handle: string; count: number }[];
  totalIndicatorHits: number;
  samples: ThreatIndicatorSample[];
};

/** Patrones (etiqueta legible, regex). */
const MALWARE_STEALER_PATTERNS: { label: string; re: RegExp }[] = [
  { label: "RedLine", re: /\bred[_\s.-]?line\b/gi },
  { label: "Lumma (LummaC2)", re: /\blumma(c2)?\b/gi },
  { label: "Raccoon Stealer", re: /\braccoon\b/gi },
  { label: "Stealc", re: /\bstealc\b/gi },
  { label: "Vidar", re: /\bvidar\b/gi },
  { label: "Mars Stealer", re: /\bmars\s*stealer\b/gi },
  { label: "Atomic Stealer", re: /\batomic\s*stealer\b/gi },
  { label: "Rhadamanthys", re: /\brhadamanthys\b/gi },
  { label: "RisePro", re: /\brisepro\b/gi },
  { label: "Meduza Stealer", re: /\bmeduza\b/gi },
  { label: "CryptBot", re: /\bcryptbot\b/gi },
  { label: "Formbook", re: /\bformbook\b/gi },
  { label: "Agent Tesla", re: /\bagent\s*tesla\b/gi },
  { label: "LokiBot", re: /\blokibot\b/gi },
  { label: "Infostealer", re: /\binfostealer\b/gi },
  { label: "Keylogger", re: /\bkeylogger\b/gi },
  { label: "Botnet", re: /\bbotnet\b/gi },
  { label: "ULP / combo malware", re: /\bulp\b/gi },
];

/** Sitios / marcas de venta o redistribución de credenciales (texto libre en dumps). */
const DISTRIBUTION_PATTERNS: { label: string; re: RegExp; cat: "distribution_forum" | "marketplace" }[] = [
  { label: "DemonForums", re: /demonforums?\.[a-z.]+|demonforums\b/gi, cat: "distribution_forum" },
  { label: "TurkHacks", re: /turkhacks\b/gi, cat: "distribution_forum" },
  { label: "Cracked.sh / cracked", re: /cracked\.sh\b|@cracked/gi, cat: "marketplace" },
  { label: "Nohide.io", re: /nohide\.io\b/gi, cat: "marketplace" },
  { label: "BHC Forums", re: /bhcforums\b/gi, cat: "distribution_forum" },
  { label: "Leakbase / LEAKBASE", re: /leakbase\b/gi, cat: "marketplace" },
  { label: "Hoodmails", re: /hoodmails\b/gi, cat: "marketplace" },
  { label: "StarLinkCloud / StarLinkClub", re: /starlink(cloud|club)\b/gi, cat: "marketplace" },
  { label: "TXT_ALIENS / @TXT_ALIENS", re: /txt_aliens|@txt_aliens\b/gi, cat: "marketplace" },
  { label: "Russia34 / Russia combo sites", re: /russia34\.com\b/gi, cat: "marketplace" },
  { label: "Kraken / KRAKEN bonus", re: /\bkraken[_\s]?bonus\b|\bkraken\b.*ulp/gi, cat: "marketplace" },
  { label: "ArhontCloud / Slurm", re: /arhontcloud|slurm[_\s]?data/gi, cat: "marketplace" },
  { label: "InfernoLogs", re: /infernologs\b/gi, cat: "marketplace" },
  { label: "SkyULP", re: /skyulp\b/gi, cat: "marketplace" },
  { label: "BLACK_CLOUDX", re: /black_cloudx\b/gi, cat: "marketplace" },
  { label: "EclipsoN", re: /eclipson\b/gi, cat: "marketplace" },
  { label: "DaxusProBot", re: /daxusprobot\b/gi, cat: "marketplace" },
  { label: "Pastebin / pastes", re: /pastebin\.com\b/gi, cat: "marketplace" },
  { label: "BreachForums", re: /breachforums?\b/gi, cat: "distribution_forum" },
  { label: "RaidForums (hist.)", re: /raidforums?\b/gi, cat: "distribution_forum" },
  { label: "Sell / venta ULP", re: /\b(sell|selling|shop|market|vendor)\b.*\b(ulp|combo|log|stealer)\b/gi, cat: "marketplace" },
  { label: "Telegram cloud ULP", re: /telegram.*\b(ulp|cloud|database|dump)\b/gi, cat: "marketplace" },
];

const MAX_SAMPLES = 80;
const EXCERPT_LEN = 120;

function excerptAround(text: string, idx: number): string {
  const start = Math.max(0, idx - 40);
  const end = Math.min(text.length, idx + EXCERPT_LEN);
  let s = text.slice(start, end).replace(/\s+/g, " ").trim();
  if (start > 0) s = "…" + s;
  if (end < text.length) s = s + "…";
  return s.slice(0, EXCERPT_LEN + 20);
}

function pushSample(
  samples: ThreatIndicatorSample[],
  category: ThreatIndicatorCategory,
  label: string,
  sourceFile: string,
  text: string,
  idx: number,
) {
  if (samples.length >= MAX_SAMPLES) return;
  samples.push({
    category,
    label,
    sourceFile,
    excerpt: excerptAround(text, idx),
  });
}

/**
 * Escanea un texto largo y acumula contadores + muestras.
 */
export function scanTextForThreatIndicators(
  text: string,
  sourceFile: string,
  acc: {
    malware: Map<string, number>;
    distribution: Map<string, number>;
    telegram: Map<string, number>;
    samples: ThreatIndicatorSample[];
  },
) {
  if (!text || text.length < 3) return;
  const t = text;

  for (const { label, re } of MALWARE_STEALER_PATTERNS) {
    for (const m of t.matchAll(re)) {
      acc.malware.set(label, (acc.malware.get(label) ?? 0) + 1);
      pushSample(acc.samples, "malware_family", label, sourceFile, t, m.index);
    }
  }

  for (const { label, re, cat } of DISTRIBUTION_PATTERNS) {
    for (const m of t.matchAll(re)) {
      acc.distribution.set(label, (acc.distribution.get(label) ?? 0) + 1);
      const sampleCat: ThreatIndicatorCategory =
        cat === "marketplace" ? "marketplace" : "distribution_forum";
      pushSample(acc.samples, sampleCat, label, sourceFile, t, m.index);
    }
  }

  const tgUrl = /t\.me\/([a-z][a-z0-9_]{2,40})/gi;
  let tm: RegExpExecArray | null;
  while ((tm = tgUrl.exec(t)) != null) {
    const h = tm[1]!.toLowerCase();
    acc.telegram.set(h, (acc.telegram.get(h) ?? 0) + 1);
    pushSample(acc.samples, "telegram", `@${h} (t.me)`, sourceFile, t, tm.index);
  }

  const atHandle = /(?:^|[\s,|"'(\[])(@[a-z][a-z0-9_]{3,30})\b/gi;
  while ((tm = atHandle.exec(t)) != null) {
    const raw = tm[1]!;
    if (raw.includes(".") && /@\w+\.\w+/.test(raw)) continue;
    const h = raw.slice(1).toLowerCase();
    if (/^\d+$/.test(h)) continue;
    acc.telegram.set(h, (acc.telegram.get(h) ?? 0) + 1);
    pushSample(acc.samples, "telegram", `@${h}`, sourceFile, t, tm.index);
  }
}

function mapToSortedArray(m: Map<string, number>, limit: number) {
  return take(
    sortBy(
      [...m.entries()].map(([label, count]) => ({ label, count })),
      (x) => -x.count,
    ),
    limit,
  );
}

/**
 * Agrega indicadores de todos los CSV parseados (incl. nombres de archivo y rutas ZIP).
 */
export function aggregateDocumentThreatIndicators(
  files: LeakFileScanInput[],
): DocumentThreatHuntResult {
  const acc = {
    malware: new Map<string, number>(),
    distribution: new Map<string, number>(),
    telegram: new Map<string, number>(),
    samples: [] as ThreatIndicatorSample[],
  };

  for (const f of files) {
    if (f.path.toLowerCase().includes("botnet")) continue;
    scanTextForThreatIndicators(f.path, f.path, acc);
    for (const row of f.rows) {
      const chunk = [
        ...Object.entries(row).map(([k, v]) => `${k}:${v}`),
      ].join("\n");
      scanTextForThreatIndicators(chunk, f.path, acc);
    }
  }

  const malwareFamilies = mapToSortedArray(acc.malware, 40);
  const distributionSites = mapToSortedArray(acc.distribution, 40);
  const telegramHandles = take(
    sortBy(
      [...acc.telegram.entries()].map(([handle, count]) => ({ handle, count })),
      (x) => -x.count,
    ),
    50,
  );

  const totalIndicatorHits =
    [...acc.malware.values()].reduce((a, b) => a + b, 0) +
    [...acc.distribution.values()].reduce((a, b) => a + b, 0) +
    [...acc.telegram.values()].reduce((a, b) => a + b, 0);

  const seen = new Set<string>();
  const samples: ThreatIndicatorSample[] = [];
  for (const s of acc.samples) {
    const key = `${s.category}:${s.label}:${s.excerpt.slice(0, 60)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    samples.push(s);
    if (samples.length >= MAX_SAMPLES) break;
  }

  return {
    malwareFamilies,
    distributionSites,
    telegramHandles,
    totalIndicatorHits,
    samples,
  };
}
