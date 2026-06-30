/**
 * ExecutivePanel — agrega los 4 sub-bloques ejecutivos arriba del detalle.
 *
 * Renderiza nada si el analizador no produce análisis (sin summary).
 */

import type { SurveillanceBrand24Result } from "@/types/digital-surveillance";
import { analyzeBrand } from "@/components/digital-surveillance/risk-engine/brand-analyzer";
import { ExecutiveSummaryCard } from "./ExecutiveSummaryCard";
import { NarrativesCard } from "./NarrativesCard";
import { RisksOpportunitiesGrid } from "./RisksOpportunitiesGrid";
import { PrioritizedActionsCard } from "./PrioritizedActionsCard";

export function ExecutivePanel({ data }: { data: SurveillanceBrand24Result }) {
  const analysis = analyzeBrand(data);
  if (!analysis) return null;

  return (
    <section className="space-y-3">
      <ExecutiveSummaryCard executive={analysis.executive} />

      <NarrativesCard narratives={analysis.narratives} context={analysis.context} />

      <div className="grid gap-3 lg:grid-cols-2">
        <RisksOpportunitiesGrid
          risks={analysis.risks}
          opportunities={analysis.opportunities}
        />
        <PrioritizedActionsCard
          actions={analysis.actions}
          kpis={analysis.kpis}
        />
      </div>

      {/* Separador visual hacia el detalle */}
      <div className="flex items-center gap-3 pt-2 text-[10px] uppercase tracking-widest text-muted-foreground/70">
        <div className="h-px flex-1 bg-border/50" />
        <span>Detalle del snapshot</span>
        <div className="h-px flex-1 bg-border/50" />
      </div>
    </section>
  );
}
