/**
 * NarrativesCard — separa las conversaciones detectadas en el feed.
 *
 * El caso clásico (e.g. "IPS" = Instituto previsional PY vs portátiles
 * Colombia) inflaba métricas. Acá mostramos el split aproximado por hashtag
 * y los tags sample de cada cluster.
 */

import { TrendingDown, TrendingUp, Volume2, VolumeX } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type {
  BrandAnalysis,
  NarrativeSplit,
} from "@/components/digital-surveillance/risk-engine/brand-analyzer";

const SENTIMENT_ICON = {
  negative: TrendingDown,
  positive: TrendingUp,
  neutral:  Volume2,
};

const SENTIMENT_TONE = {
  negative: "text-red-600 dark:text-red-400",
  positive: "text-emerald-600 dark:text-emerald-400",
  neutral:  "text-muted-foreground",
};

export function NarrativesCard({
  narratives,
  context,
}: {
  narratives: NarrativeSplit[];
  context?: BrandAnalysis["context"];
}) {
  if (narratives.length === 0) return null;

  const coverage = context?.hashtagCoverage;
  const coveragePct = coverage && coverage.total > 0
    ? Math.round((coverage.classified / coverage.total) * 100)
    : null;
  const homeLabel = context?.homeCountry
    ? `país inferido: ${context.homeCountry.name}`
    : "país no inferible del TLD";

  return (
    <Card className="border-border/60">
      <CardContent className="space-y-3 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            Mapa de narrativas
          </p>
          <span className="text-[10px] text-muted-foreground/70">
            {homeLabel}
            {coveragePct !== null && ` · ${coveragePct}% de hashtags clasificados`}
          </span>
        </div>

        <ul className="space-y-2.5">
          {narratives.map((n) => {
            const Icon = n.isNoise ? VolumeX : SENTIMENT_ICON[n.sentimentBias];
            return (
              <li
                key={n.id}
                className={cn(
                  "rounded-md border px-3 py-2.5",
                  n.isNoise
                    ? "border-amber-500/40 bg-amber-500/5"
                    : "border-border/60 bg-muted/20",
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <Icon className={cn("h-3.5 w-3.5 shrink-0", n.isNoise ? "text-amber-600" : SENTIMENT_TONE[n.sentimentBias])} aria-hidden />
                      <p className="text-sm font-semibold text-foreground">
                        {n.label}
                      </p>
                      <Badge
                        variant="outline"
                        className={cn(
                          "h-5 px-1.5 font-mono text-[10px]",
                          n.isNoise && "border-amber-500/50 text-amber-700 dark:text-amber-300",
                        )}
                      >
                        ≈{n.weightPercent}%
                      </Badge>
                    </div>
                    <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                      {n.driver}
                    </p>
                    {n.hashtags.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {n.hashtags.map((tag) => (
                          <span
                            key={tag}
                            className="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  {/* Barra vertical de peso */}
                  <div className="flex w-1 shrink-0 flex-col self-stretch">
                    <div
                      className={cn(
                        "w-full rounded-full",
                        n.isNoise ? "bg-amber-500/60" : "bg-primary/60",
                      )}
                      style={{ height: `${Math.max(10, n.weightPercent)}%` }}
                      aria-hidden
                    />
                  </div>
                </div>
              </li>
            );
          })}
        </ul>

        <p className="text-[10px] leading-relaxed text-muted-foreground/70">
          Clustering automático: país inferido del TLD + diccionario LATAM/global.
          Si una narrativa foránea u off-topic supera ~15 %, conviene excluir
          esas keywords en el proyecto Brand24 para limpiar el sentiment.
        </p>
      </CardContent>
    </Card>
  );
}
