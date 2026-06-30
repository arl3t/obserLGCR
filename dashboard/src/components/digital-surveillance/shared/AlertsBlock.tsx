import { AlertOctagon, AlertTriangle, Info, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import {
  OpenSocCaseButton,
  type Finding,
} from "@/components/digital-surveillance/shared/OpenSocCaseButton";
import { cn } from "@/lib/utils";

export type AlertSeverity = "high" | "medium" | "low";

export type Alert = {
  id: string;
  severity: AlertSeverity;
  title: string;
  detail: string;
  /** Línea de contexto opcional (ej. "@critic · TikTok · 850k seguidores"). */
  context?: string;
  /** Si se provee, renderiza un OpenSocCaseButton inline con este Finding. */
  socFinding?: Finding;
  /** Acciones extra (links, ver original, scroll-to-section). */
  extraActions?: ReactNode;
};

const SEVERITY_ICON: Record<AlertSeverity, LucideIcon> = {
  high:   AlertOctagon,
  medium: AlertTriangle,
  low:    Info,
};

const SEVERITY_BORDER: Record<AlertSeverity, string> = {
  high:   "border-red-500/40 bg-red-500/[0.04]",
  medium: "border-amber-500/40 bg-amber-500/[0.04]",
  low:    "border-blue-500/40 bg-blue-500/[0.04]",
};

const SEVERITY_ICON_COLOR: Record<AlertSeverity, string> = {
  high:   "text-red-600 dark:text-red-400",
  medium: "text-amber-600 dark:text-amber-400",
  low:    "text-blue-600 dark:text-blue-400",
};

const SEVERITY_DOT: Record<AlertSeverity, string> = {
  high:   "bg-red-500",
  medium: "bg-amber-500",
  low:    "bg-blue-500",
};

const SEVERITY_LABEL: Record<AlertSeverity, string> = {
  high:   "Alta",
  medium: "Media",
  low:    "Baja",
};

const SEVERITY_RANK: Record<AlertSeverity, number> = { high: 3, medium: 2, low: 1 };

export type AlertsBlockProps = {
  alerts: Alert[];
  domain: string;
  title?: string;
  /** Si no hay alertas, no renderiza nada (true) o muestra estado vacío (false). Default: false. */
  hideWhenEmpty?: boolean;
  className?: string;
};

export function AlertsBlock({
  alerts,
  domain,
  title = "Alertas accionables",
  hideWhenEmpty = false,
  className,
}: AlertsBlockProps) {
  if (alerts.length === 0) {
    if (hideWhenEmpty) return null;
    return (
      <div
        className={cn(
          "rounded-xl border border-emerald-500/30 bg-emerald-500/[0.03] p-4 text-sm text-emerald-700 dark:text-emerald-400",
          className,
        )}
      >
        Sin alertas accionables en este momento.
      </div>
    );
  }

  const sorted = [...alerts].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
  );
  const counts = {
    high:   alerts.filter((a) => a.severity === "high").length,
    medium: alerts.filter((a) => a.severity === "medium").length,
    low:    alerts.filter((a) => a.severity === "low").length,
  };

  return (
    <section
      className={cn(
        "rounded-xl border border-border/70 bg-card/50 p-4 shadow-sm",
        className,
      )}
      aria-label={title}
    >
      <header className="mb-3 flex flex-wrap items-center gap-2">
        <AlertOctagon className="h-4 w-4 text-red-500" aria-hidden />
        <h3 className="text-sm font-semibold">{title}</h3>
        <span className="text-xs text-muted-foreground">({alerts.length})</span>
        <div className="ml-auto flex items-center gap-1.5 text-[11px] text-muted-foreground">
          {counts.high   > 0 && <span className="flex items-center gap-1"><span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_DOT.high)} />{counts.high} alta</span>}
          {counts.medium > 0 && <span className="flex items-center gap-1"><span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_DOT.medium)} />{counts.medium} media</span>}
          {counts.low    > 0 && <span className="flex items-center gap-1"><span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_DOT.low)} />{counts.low} baja</span>}
        </div>
      </header>

      <div className="space-y-2">
        {sorted.map((a) => {
          const Icon = SEVERITY_ICON[a.severity];
          return (
            <article
              key={a.id}
              className={cn(
                "flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-start sm:gap-3",
                SEVERITY_BORDER[a.severity],
              )}
            >
              <div className="flex shrink-0 items-start gap-2">
                <Icon className={cn("mt-0.5 h-4 w-4", SEVERITY_ICON_COLOR[a.severity])} aria-hidden />
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                    a.severity === "high"   ? "bg-red-500/15 text-red-700 dark:text-red-400" :
                    a.severity === "medium" ? "bg-amber-500/15 text-amber-700 dark:text-amber-400" :
                                              "bg-blue-500/15 text-blue-700 dark:text-blue-400",
                  )}
                >
                  {SEVERITY_LABEL[a.severity]}
                </span>
              </div>
              <div className="min-w-0 flex-1 space-y-1">
                <p className="text-sm font-semibold leading-tight">{a.title}</p>
                <p className="text-xs text-muted-foreground">{a.detail}</p>
                {a.context && (
                  <p className="truncate text-[11px] text-muted-foreground/80" title={a.context}>
                    {a.context}
                  </p>
                )}
                {(a.socFinding || a.extraActions) && (
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {a.socFinding && (
                      <OpenSocCaseButton
                        domain={domain}
                        finding={a.socFinding}
                        forceShow
                        buttonClassName="h-7 text-[11px]"
                      />
                    )}
                    {a.extraActions}
                  </div>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
