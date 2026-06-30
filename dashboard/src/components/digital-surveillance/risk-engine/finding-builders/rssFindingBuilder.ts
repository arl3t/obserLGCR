/**
 * rssFindingBuilder — produce findings desde rss.items + rss.custom matched.
 *
 * Genera findings cuando:
 *   - Hay ≥ RSS_COVERAGE_SPIKE menciones directas en window → finding spike
 *   - Hay ≥ 1 mención con keywords negativos → finding por noticia (top 3)
 *
 * El feed completo de noticias vive en TabNoticias; este builder elige las
 * 3-4 más accionables.
 */

import type {
  SurveillanceRssResult,
  AnalystFinding,
  AnalystFindingSeverity,
} from "@/types/digital-surveillance";
import {
  RSS_COVERAGE_SPIKE,
  RSS_NEG_KEYWORDS,
} from "@/components/digital-surveillance/risk-engine/thresholds";

export type RssFindingInput = {
  domain: string;
  rss: SurveillanceRssResult | undefined;
};

export function buildRssFindings(input: RssFindingInput): AnalystFinding[] {
  const { domain, rss } = input;
  if (!rss) return [];

  const out: AnalystFinding[] = [];
  const detectedAt = new Date().toISOString();

  const directMentions = [
    ...(rss.items ?? []),
    ...(rss.custom ?? []).filter((i) => i.matched),
  ];

  if (directMentions.length === 0) return [];

  // 1. Spike de cobertura
  if (directMentions.length >= RSS_COVERAGE_SPIKE) {
    const sample = directMentions.slice(0, 3).map((i) => `"${i.title}"`).join(" · ");
    out.push({
      id: `finding-rss-spike-${domain}`,
      kind: "news-coverage",
      severity: directMentions.length >= 50 ? "high" : "medium",
      title: `Spike de cobertura — ${directMentions.length} menciones directas`,
      sourceLabel: "Google News + RSS custom",
      evidence: `${directMentions.length} noticias mencionan ${domain} directamente. Muestra: ${sample}`,
      evidenceTimestamp: rss.fetchedAt,
      why: `Volumen de cobertura alto. Cruzar con sentimiento Brand24 y leak velocity — si coinciden, ` +
        `probable incidente reputacional o data leak ya público.`,
      refs: [
        { tab: "noticias", label: "Feed completo", hint: `${directMentions.length} menciones` },
        { tab: "marca", label: "Sentimiento social", hint: "comparar con neg ratio" },
      ],
      actions: [
        {
          id: `rss-spike-review-${domain}`,
          label: "Revisar feed",
          kind: "navigate-tab",
          primary: true,
          payload: { tab: "noticias" },
        },
      ],
      detectedAt,
    });
  }

  // 2. Top 2 noticias con keywords negativos
  const negativeNews = directMentions
    .filter((i) => RSS_NEG_KEYWORDS.test(`${i.title} ${i.snippet}`))
    .slice(0, 2);

  for (const news of negativeNews) {
    const sev: AnalystFindingSeverity = "medium";
    out.push({
      id: `finding-rss-neg-${hash(news.url)}`,
      kind: "news-coverage",
      severity: sev,
      title: news.title.length > 80 ? `${news.title.slice(0, 77)}…` : news.title,
      sourceLabel: news.source,
      evidence: news.snippet || "(sin extracto disponible)",
      evidenceTimestamp: news.publishedAt,
      why: `Cobertura con keywords de incidente / vulnerabilidad / fuga. Aún si la noticia es ajena al ` +
        `evento actual, valida que el público asocia ${domain} con riesgo — input para gestión de comunicación.`,
      refs: [
        { tab: "noticias", label: "Ver en feed" },
      ],
      actions: [
        {
          id: `rss-neg-open-${hash(news.url)}`,
          label: "Abrir nota",
          kind: "external-link",
          primary: true,
          payload: { url: news.url },
        },
      ],
      detectedAt,
    });
  }

  return out;
}

/** Hash trivial para IDs estables — no criptográfico. */
function hash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}
