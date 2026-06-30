/**
 * PrioritizedActionsCard — checklist accionable + KPIs para el próximo período.
 *
 * El check del item no se persiste (Item 8 a futuro: snooze/ack por finding
 * en notification_log). Por ahora la UI es read-only — sirve para que el
 * analista lea la lista, no para tracking de tareas.
 */

import { CheckSquare, ListChecks, Target } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type {
  ActionItem,
  KpiTarget,
} from "@/components/digital-surveillance/risk-engine/brand-analyzer";

const PRIORITY_BADGE = {
  1: { label: "P1", className: "border-red-500/50 bg-red-500/10 text-red-700 dark:text-red-300" },
  2: { label: "P2", className: "border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300" },
  3: { label: "P3", className: "border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" },
} as const;

const CATEGORY_LABEL: Record<ActionItem["category"], string> = {
  crisis:  "Crisis",
  social:  "Social",
  pr:      "PR",
  kpi:     "Métricas",
  product: "Producto",
};

export function PrioritizedActionsCard({
  actions,
  kpis,
}: {
  actions: ActionItem[];
  kpis: KpiTarget[];
}) {
  return (
    <Card className="border-border/60">
      <CardContent className="space-y-4 p-5">
        <div>
          <div className="mb-2 flex items-center gap-1.5">
            <ListChecks className="h-3.5 w-3.5 text-primary" aria-hidden />
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Acciones priorizadas
            </p>
          </div>
          {actions.length === 0 ? (
            <p className="text-xs text-muted-foreground">Sin acciones disparadas por las heurísticas.</p>
          ) : (
            <ul className="space-y-1.5">
              {actions.map((a, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <CheckSquare className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground/60" aria-hidden />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge
                        variant="outline"
                        className={cn("h-4 px-1 text-[9px]", PRIORITY_BADGE[a.priority].className)}
                      >
                        {PRIORITY_BADGE[a.priority].label}
                      </Badge>
                      <Badge variant="outline" className="h-4 px-1 text-[9px] text-muted-foreground">
                        {CATEGORY_LABEL[a.category]}
                      </Badge>
                      <span className="font-mono text-[10px] text-muted-foreground/80">{a.dueIn}</span>
                    </div>
                    <p className="mt-0.5 leading-snug text-foreground">{a.label}</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="border-t border-border/40 pt-3">
          <div className="mb-2 flex items-center gap-1.5">
            <Target className="h-3.5 w-3.5 text-primary" aria-hidden />
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              KPIs próximo período
            </p>
          </div>
          <ul className="space-y-1">
            {kpis.map((k) => (
              <li
                key={k.name}
                className="grid grid-cols-[1fr,auto,auto] items-center gap-2 text-[11px]"
              >
                <span className="truncate text-foreground">{k.name}</span>
                <span className="font-mono text-muted-foreground/80">{k.baseline}</span>
                <span className="font-mono font-semibold text-foreground">→ {k.target}</span>
              </li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
