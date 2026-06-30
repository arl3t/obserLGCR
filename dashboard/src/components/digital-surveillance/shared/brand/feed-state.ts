/**
 * Estado del feed Brand24 — filtros + paginación + helpers puros.
 *
 * `useBrandFeedState` produce el estado controlado que `BrandFeed` consume.
 * Filtros: sentimiento, fuente, autor, búsqueda libre, orden (urgencia/fecha/reach).
 * Paginación: tamaño fijo `FEED_PAGE_SIZE`, "Cargar más" suma páginas.
 *
 * Cuando aplica un filtro o cambia el orden, la paginación se resetea.
 */

import { useCallback, useState } from "react";
import type { Brand24Mention, Brand24Sentiment } from "@/types/digital-surveillance";

export type FeedOrder = "urgencia" | "fecha" | "reach";

export type BrandFeedFilters = {
  sentiment: Brand24Sentiment | "all";
  source: string;
  author: string;
  query: string;
  order: FeedOrder;
};

export const FEED_PAGE_SIZE = 25;
export const HIGH_URGENCY_REACH_THRESHOLD = 50_000;

export const FEED_DEFAULTS: BrandFeedFilters = {
  sentiment: "all",
  source:    "all",
  author:    "all",
  query:     "",
  order:     "urgencia",
};

export const BRAND_SENTIMENT_LABEL: Record<Brand24Sentiment, string> = {
  positive: "Positiva",
  negative: "Negativa",
  neutral:  "Neutra",
};

export const BRAND_SENTIMENT_BORDER: Record<Brand24Sentiment, string> = {
  positive: "border-l-emerald-500 bg-emerald-500/[0.04]",
  negative: "border-l-red-500    bg-red-500/[0.04]",
  neutral:  "border-l-border/60",
};

export function useBrandFeedState() {
  const [filters, setFilters] = useState<BrandFeedFilters>(FEED_DEFAULTS);
  const [visibleCount, setVisibleCount] = useState(FEED_PAGE_SIZE);

  const setFilter = useCallback((patch: Partial<BrandFeedFilters>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
    setVisibleCount(FEED_PAGE_SIZE);
  }, []);

  const loadMore = useCallback(() => {
    setVisibleCount((v) => v + FEED_PAGE_SIZE);
  }, []);

  const reset = useCallback(() => {
    setFilters(FEED_DEFAULTS);
    setVisibleCount(FEED_PAGE_SIZE);
  }, []);

  return { filters, setFilter, visibleCount, loadMore, reset };
}

function urgencyScore(m: Brand24Mention, now: number): number {
  const reach = Math.max(1, m.reach ?? 1);
  const sentW = m.sentiment === "negative" ? 2 : m.sentiment === "neutral" ? 1 : 0.5;
  const ageH = m.publishedAt
    ? Math.max(0.5, (now - new Date(m.publishedAt).getTime()) / 3_600_000)
    : 24;
  return (reach * sentW) / Math.log10(ageH + 9);
}

export function isHighUrgency(m: Brand24Mention): boolean {
  return m.sentiment === "negative" && (m.reach ?? 0) >= HIGH_URGENCY_REACH_THRESHOLD;
}

export function applyFeedFilters(mentions: Brand24Mention[], filters: BrandFeedFilters): Brand24Mention[] {
  const q = filters.query.trim().toLowerCase();
  const filtered = mentions.filter((m) => {
    if (filters.sentiment !== "all" && m.sentiment !== filters.sentiment) return false;
    if (filters.source    !== "all" && m.source    !== filters.source)    return false;
    if (filters.author    !== "all" && m.author    !== filters.author)    return false;
    if (q && !`${m.author} ${m.source} ${m.snippet}`.toLowerCase().includes(q)) return false;
    return true;
  });
  const now = Date.now();
  return filtered.slice().sort((a, b) => {
    if (filters.order === "fecha") {
      const ta = a.publishedAt ? new Date(a.publishedAt).getTime() : 0;
      const tb = b.publishedAt ? new Date(b.publishedAt).getTime() : 0;
      return tb - ta;
    }
    if (filters.order === "reach") {
      return (b.reach ?? 0) - (a.reach ?? 0);
    }
    return urgencyScore(b, now) - urgencyScore(a, now);
  });
}

export function isFeedFiltered(f: BrandFeedFilters): boolean {
  return f.sentiment !== "all" || f.source !== "all" || f.author !== "all" || f.query.trim().length > 0;
}
