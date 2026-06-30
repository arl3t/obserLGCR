/**
 * ExecutiveSummaryCard — primer bloque del panel ejecutivo del tab Marca.
 * Pega arriba del detalle del snapshot, con 1 frase + KPIs en chips.
 */

import { Sparkles } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { ExecutiveSummary } from "@/components/digital-surveillance/risk-engine/brand-analyzer";

const TONE_STYLES = {
  positive: "border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300",
  negative: "border-red-500/40 bg-red-500/5 text-red-700 dark:text-red-300",
  neutral:  "border-border/60 bg-muted/30 text-foreground",
};

export function ExecutiveSummaryCard({ executive }: { executive: ExecutiveSummary }) {
  return (
    <Card className="border-primary/20 bg-primary/[0.02]">
      <CardContent className="space-y-3 p-5">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-primary/10">
            <Sparkles className="h-3.5 w-3.5 text-primary" aria-hidden />
          </div>
          <div className="space-y-0.5">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Resumen ejecutivo
            </p>
            <p className="text-sm font-semibold leading-snug text-foreground">
              {executive.oneLine}
            </p>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {executive.highlights.map((h) => (
            <div
              key={h.label}
              className={cn(
                "rounded-md border px-3 py-2",
                TONE_STYLES[h.tone],
              )}
            >
              <p className="text-[10px] uppercase tracking-wider opacity-80">{h.label}</p>
              <p className="font-mono text-sm font-semibold tabular-nums">{h.value}</p>
            </div>
          ))}
        </div>

        {executive.drivers.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <span className="text-muted-foreground">Drivers:</span>
            {executive.drivers.map((d) => (
              <span
                key={d}
                className="rounded-full border border-border/60 bg-background px-2 py-0.5 text-foreground/90"
              >
                {d}
              </span>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
