import type { LucideIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export type KpiTone = "neutral" | "ok" | "warn" | "critical" | "muted";

export type KpiItem = {
  key: string;
  label: string;
  value: string | number | null;
  icon?: LucideIcon;
  tone?: KpiTone;
  /** Línea pequeña debajo del valor (ej. "+27%", "social 4.5M"). */
  hint?: string;
  /** Si true, ignora value y muestra "no configurado". */
  unconfigured?: boolean;
  onClick?: () => void;
};

export type KpiStripProps = {
  items: KpiItem[];
  /** Columnas en >=lg breakpoint. Mobile siempre se acomoda en 2 cols. Default: items.length. */
  columns?: 2 | 3 | 4 | 5 | 6;
  className?: string;
};

const TONE_BG: Record<KpiTone, string> = {
  critical: "bg-red-500/10 text-red-600 dark:text-red-400",
  warn:     "bg-amber-500/10 text-amber-600 dark:text-amber-400",
  ok:       "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  neutral:  "bg-primary/10 text-primary",
  muted:    "bg-muted text-muted-foreground",
};

const TONE_BORDER: Record<KpiTone, string> = {
  critical: "border-l-red-500/70",
  warn:     "border-l-amber-500/70",
  ok:       "border-l-emerald-500/60",
  neutral:  "border-l-primary/40",
  muted:    "border-l-transparent",
};

const COL_CLASS: Record<NonNullable<KpiStripProps["columns"]>, string> = {
  2: "lg:grid-cols-2",
  3: "lg:grid-cols-3",
  4: "lg:grid-cols-4",
  5: "lg:grid-cols-5",
  6: "lg:grid-cols-6",
};

export function KpiStrip({ items, columns, className }: KpiStripProps) {
  const cols = columns ?? (Math.min(6, Math.max(2, items.length)) as NonNullable<KpiStripProps["columns"]>);

  return (
    <div
      className={cn(
        "grid gap-3 sm:grid-cols-2",
        COL_CLASS[cols],
        className,
      )}
      role="list"
      aria-label="Indicadores"
    >
      {items.map((k) => {
        const tone = k.tone ?? (k.unconfigured ? "muted" : "neutral");
        const Icon = k.icon;
        const clickable = Boolean(k.onClick) && !k.unconfigured;
        const valueDisplay = k.unconfigured ? null : k.value ?? "—";

        return (
          <Card
            key={k.key}
            role="listitem"
            tabIndex={clickable ? 0 : undefined}
            onClick={clickable ? k.onClick : undefined}
            onKeyDown={
              clickable
                ? (e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      k.onClick?.();
                    }
                  }
                : undefined
            }
            className={cn(
              "border border-border/70 border-l-4 transition-colors",
              TONE_BORDER[tone],
              clickable && "cursor-pointer hover:bg-muted/40 focus-visible:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40",
            )}
          >
            <CardContent className="flex items-center gap-3 p-4">
              {Icon && (
                <div
                  className={cn(
                    "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg",
                    TONE_BG[tone],
                  )}
                >
                  <Icon className="h-5 w-5" aria-hidden />
                </div>
              )}
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs text-muted-foreground" title={k.label}>
                  {k.label}
                </p>
                {k.unconfigured ? (
                  <p className="text-xs font-medium text-muted-foreground/60">No configurado</p>
                ) : (
                  <p className="text-2xl font-bold tabular-nums leading-tight">
                    {valueDisplay}
                  </p>
                )}
                {!k.unconfigured && k.hint && (
                  <p className="truncate text-[11px] text-muted-foreground/80" title={k.hint}>
                    {k.hint}
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
