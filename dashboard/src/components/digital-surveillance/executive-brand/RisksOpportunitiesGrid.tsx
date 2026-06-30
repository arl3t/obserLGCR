/**
 * RisksOpportunitiesGrid — dos columnas para riesgos y oportunidades
 * derivados del análisis heurístico.
 */

import { AlertTriangle, Lightbulb } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { Risk, Opportunity } from "@/components/digital-surveillance/risk-engine/brand-analyzer";

const SEVERITY_DOT = {
  high:   "bg-red-500",
  medium: "bg-amber-500",
  low:    "bg-emerald-500",
};

export function RisksOpportunitiesGrid({
  risks,
  opportunities,
}: {
  risks: Risk[];
  opportunities: Opportunity[];
}) {
  return (
    <Card className="border-border/60">
      <CardContent className="space-y-4 p-5">
        <div>
          <div className="mb-2 flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-red-600 dark:text-red-400" aria-hidden />
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Riesgos detectados
            </p>
          </div>
          {risks.length === 0 ? (
            <p className="text-xs text-muted-foreground">Sin riesgos disparados por las heurísticas actuales.</p>
          ) : (
            <ul className="space-y-2">
              {risks.map((r, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", SEVERITY_DOT[r.severity])} aria-hidden />
                  <div className="min-w-0">
                    <p className="font-medium text-foreground">{r.label}</p>
                    <p className="text-muted-foreground">{r.detail}</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="border-t border-border/40 pt-3">
          <div className="mb-2 flex items-center gap-1.5">
            <Lightbulb className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden />
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Oportunidades
            </p>
          </div>
          {opportunities.length === 0 ? (
            <p className="text-xs text-muted-foreground">Sin oportunidades destacables — feed estable.</p>
          ) : (
            <ul className="space-y-2">
              {opportunities.map((o, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" aria-hidden />
                  <div className="min-w-0">
                    <p className="font-medium text-foreground">{o.label}</p>
                    <p className="text-muted-foreground">{o.detail}</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
