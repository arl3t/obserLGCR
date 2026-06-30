/**
 * Feed unificado de menciones Brand24 (§3.2.5).
 *
 * Card con filtros (sentimiento/fuente/autor/búsqueda/orden), chips de filtros
 * activos, lista de menciones paginada y CTA SOC para menciones de alta
 * urgencia (negativas con reach ≥ 50k). El estado de filtros lo provee
 * `useBrandFeedState` desde `feed-state.ts`.
 *
 * Sub-componentes locales: `FeedFilterBar`, `FilterChip`, `ActiveFiltersChips`,
 * `FeedMentionCard`. No se exportan — sólo el contenedor `BrandFeed` es
 * público.
 */

import { Clock, ExternalLink, MessageSquare } from "lucide-react";
import { useMemo } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { OpenSocCaseButton } from "@/components/digital-surveillance/shared/OpenSocCaseButton";
import { NewsSourceBadge } from "@/components/digital-surveillance/shared/news-source-badge";
import { NoResults } from "@/components/digital-surveillance/shared/source-states";
import { formatCompactNumber } from "@/components/digital-surveillance/shared/format";
import {
  BRAND_SENTIMENT_BORDER,
  BRAND_SENTIMENT_LABEL,
  applyFeedFilters,
  isFeedFiltered,
  isHighUrgency,
  type BrandFeedFilters,
  type FeedOrder,
} from "@/components/digital-surveillance/shared/brand/feed-state";
import type { Brand24Mention, SurveillanceBrand24Result } from "@/types/digital-surveillance";
import { formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Sub-componentes — internos al módulo del feed
// ─────────────────────────────────────────────────────────────────────────────

function FeedFilterBar({
  filters,
  onChange,
  sources,
}: {
  filters: BrandFeedFilters;
  onChange: (patch: Partial<BrandFeedFilters>) => void;
  sources: string[];
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className="text-muted-foreground">Sentimiento:</span>
      {(["all", "positive", "negative", "neutral"] as const).map((s) => (
        <button
          key={s}
          type="button"
          onClick={() => onChange({ sentiment: s })}
          className={cn(
            "rounded-md border px-2 py-1 transition-colors",
            filters.sentiment === s
              ? "border-primary/60 bg-primary/10 text-primary"
              : "border-border/60 text-muted-foreground hover:bg-muted/40",
          )}
        >
          {s === "all" ? "Todas" : BRAND_SENTIMENT_LABEL[s]}
        </button>
      ))}

      {sources.length > 1 && (
        <>
          <span className="ml-2 text-muted-foreground">Fuente:</span>
          <select
            value={filters.source}
            onChange={(e) => onChange({ source: e.target.value })}
            className="rounded-md border border-border/60 bg-background px-2 py-1 text-xs"
          >
            <option value="all">Todas</option>
            {sources.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </>
      )}

      <Input
        type="search"
        placeholder="Buscar autor, fuente o texto…"
        value={filters.query}
        onChange={(e) => onChange({ query: e.target.value })}
        className="ml-auto h-7 w-44 text-xs"
      />

      <span className="text-muted-foreground">Orden:</span>
      <select
        value={filters.order}
        onChange={(e) => onChange({ order: e.target.value as FeedOrder })}
        className="rounded-md border border-border/60 bg-background px-2 py-1 text-xs"
      >
        <option value="urgencia">⚡ urgencia</option>
        <option value="fecha">📅 fecha</option>
        <option value="reach">📈 alcance</option>
      </select>
    </div>
  );
}

function FilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <button
      type="button"
      onClick={onClear}
      className="inline-flex items-center gap-1 rounded-full border border-primary/40 bg-primary/10 px-2 py-0.5 text-primary hover:bg-primary/20"
    >
      {label}
      <span aria-hidden>✕</span>
    </button>
  );
}

function ActiveFiltersChips({
  filters,
  onChange,
}: {
  filters: BrandFeedFilters;
  onChange: (patch: Partial<BrandFeedFilters>) => void;
}) {
  if (!isFeedFiltered(filters)) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
      {filters.sentiment !== "all" && (
        <FilterChip label={`Sentimiento: ${BRAND_SENTIMENT_LABEL[filters.sentiment]}`} onClear={() => onChange({ sentiment: "all" })} />
      )}
      {filters.source !== "all" && (
        <FilterChip label={`Fuente: ${filters.source}`} onClear={() => onChange({ source: "all" })} />
      )}
      {filters.author !== "all" && (
        <FilterChip label={`Autor: ${filters.author}`} onClear={() => onChange({ author: "all" })} />
      )}
      {filters.query.trim() && (
        <FilterChip label={`Búsqueda: "${filters.query.trim()}"`} onClear={() => onChange({ query: "" })} />
      )}
    </div>
  );
}

function FeedMentionCard({
  mention,
  domain,
  onClickAuthor,
  onClickSource,
}: {
  mention: Brand24Mention;
  domain: string;
  onClickAuthor: () => void;
  onClickSource: () => void;
}) {
  const date = mention.publishedAt ? new Date(mention.publishedAt) : null;
  const highUrgency = isHighUrgency(mention);

  return (
    <div
      className={cn(
        "rounded-xl border border-border/60 border-l-4 p-3 transition-colors hover:bg-muted/30",
        BRAND_SENTIMENT_BORDER[mention.sentiment],
        highUrgency && "ring-1 ring-red-500/30",
      )}
    >
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        <button
          type="button"
          onClick={onClickAuthor}
          className="font-mono font-medium text-foreground hover:underline"
          title="Filtrar por este autor"
        >
          {mention.author}
        </button>
        <span aria-hidden>·</span>
        <button
          type="button"
          onClick={onClickSource}
          title="Filtrar por esta fuente"
          className="hover:opacity-80"
        >
          <NewsSourceBadge source={mention.source} />
        </button>
        {date && (
          <>
            <span aria-hidden>·</span>
            <Clock className="h-3 w-3" aria-hidden />
            <span>{formatRelativeTimeEs(date.toISOString())}</span>
          </>
        )}
        <Badge
          variant="outline"
          className={cn(
            "ml-auto text-[10px]",
            mention.sentiment === "positive" && "border-emerald-500/40 text-emerald-700 dark:text-emerald-400",
            mention.sentiment === "negative" && "border-red-500/40 text-red-700 dark:text-red-400",
            mention.sentiment === "neutral"  && "text-muted-foreground",
          )}
        >
          {BRAND_SENTIMENT_LABEL[mention.sentiment]}
        </Badge>
        {mention.reach != null && (
          <span className="text-[10px] tabular-nums">
            alcance {formatCompactNumber(mention.reach)}
          </span>
        )}
        {highUrgency && (
          <Badge variant="outline" className="border-red-500/40 text-red-700 dark:text-red-400 text-[10px]">
            ⚡ alta
          </Badge>
        )}
      </div>
      <p className="mt-1.5 text-sm leading-snug">{mention.snippet}</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {mention.url && (
          <a
            href={mention.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline"
          >
            Ver original <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        )}
        {highUrgency && (
          <OpenSocCaseButton
            domain={domain}
            forceShow
            buttonClassName="h-6 px-2 text-[10px]"
            finding={{
              id: `brand-mention-${mention.id}`,
              title: `Mención negativa de alto reach (${mention.source})`,
              detail: `${mention.author} · alcance ${formatCompactNumber(mention.reach ?? 0)} · "${mention.snippet}"`,
              score: 18,
            }}
          />
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Componente público
// ─────────────────────────────────────────────────────────────────────────────

export function BrandFeed({
  domain,
  data,
  filters,
  setFilter,
  visibleCount,
  loadMore,
  reset,
}: {
  domain: string;
  data: SurveillanceBrand24Result;
  filters: BrandFeedFilters;
  setFilter: (patch: Partial<BrandFeedFilters>) => void;
  visibleCount: number;
  loadMore: () => void;
  reset: () => void;
}) {
  const allMentions = data.mentions ?? [];
  const sources = useMemo(
    () => Array.from(new Set(allMentions.map((m) => m.source))).sort(),
    [allMentions],
  );
  const sortedFiltered = useMemo(
    () => applyFeedFilters(allMentions, filters),
    [allMentions, filters],
  );
  const visible = sortedFiltered.slice(0, visibleCount);

  const counts = useMemo(() => ({
    total:    allMentions.length,
    positive: allMentions.filter((m) => m.sentiment === "positive").length,
    negative: allMentions.filter((m) => m.sentiment === "negative").length,
    neutral:  allMentions.filter((m) => m.sentiment === "neutral").length,
  }), [allMentions]);

  if (allMentions.length === 0) {
    return <NoResults message="Sin menciones disponibles. Importá un PDF Brand24 o configurá un proyecto activo." />;
  }

  const filtered = isFeedFiltered(filters);

  return (
    <Card className="border-border/60">
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            <MessageSquare className="h-4 w-4 text-primary" aria-hidden />
            Menciones · {sortedFiltered.length}
            {filtered && (
              <span className="text-[11px] font-normal text-muted-foreground">
                (de {counts.total} totales)
              </span>
            )}
            <span className="text-[11px] font-normal text-muted-foreground">
              global: {counts.positive} pos · {counts.negative} neg · {counts.neutral} neu
            </span>
          </CardTitle>
          {filtered && (
            <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={reset}>
              Limpiar filtros
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <FeedFilterBar filters={filters} onChange={setFilter} sources={sources} />
        <ActiveFiltersChips filters={filters} onChange={setFilter} />

        {sortedFiltered.length === 0 ? (
          <NoResults message="Ningún resultado con los filtros aplicados." />
        ) : (
          <>
            <div className="space-y-2">
              {visible.map((m) => (
                <FeedMentionCard
                  key={m.id}
                  mention={m}
                  domain={domain}
                  onClickAuthor={() => setFilter({ author: m.author })}
                  onClickSource={() => setFilter({ source: m.source })}
                />
              ))}
            </div>
            {sortedFiltered.length > visibleCount && (
              <div className="flex justify-center">
                <Button type="button" size="sm" variant="outline" onClick={loadMore}>
                  Cargar más ({sortedFiltered.length - visibleCount} restantes)
                </Button>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
