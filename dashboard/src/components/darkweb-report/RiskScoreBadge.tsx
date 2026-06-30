import { AlertTriangle, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type Props = {
  /** 1 = bajo, 10 = crítico */
  score: number;
  className?: string;
};

function clampScore(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.min(10, Math.max(1, Math.round(n)));
}

export function RiskScoreBadge({ score, className }: Props) {
  const s = clampScore(score);
  const tone =
    s <= 3
      ? {
          label: "Bajo",
          bar: "from-emerald-500 to-emerald-600",
          text: "text-emerald-300",
          bg: "bg-emerald-500/15 border-emerald-500/40",
        }
      : s <= 5
        ? {
            label: "Moderado",
            bar: "from-amber-400 to-amber-600",
            text: "text-amber-200",
            bg: "bg-amber-500/15 border-amber-500/40",
          }
        : s <= 7
          ? {
              label: "Alto",
              bar: "from-orange-500 to-orange-600",
              text: "text-orange-200",
              bg: "bg-orange-500/15 border-orange-500/40",
            }
          : {
              label: "Crítico",
              bar: "from-red-600 to-red-700",
              text: "text-red-200",
              bg: "bg-red-500/15 border-red-500/45",
            };

  const pct = (s / 10) * 100;

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl border p-4 shadow-inner",
        tone.bg,
        className,
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Puntuación global de riesgo
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            Escala 1 (bajo) – 10 (crítico)
          </p>
        </div>
        <div className="flex items-center gap-2">
          {s >= 8 ? (
            <ShieldAlert className={cn("h-8 w-8", tone.text)} aria-hidden />
          ) : (
            <AlertTriangle className={cn("h-7 w-7 opacity-80", tone.text)} aria-hidden />
          )}
          <span className={cn("text-5xl font-black tabular-nums tracking-tight", tone.text)}>
            {s}
          </span>
          <Badge variant="outline" className={cn("border-current text-xs", tone.text)}>
            {tone.label}
          </Badge>
        </div>
      </div>
      <div className="mt-4 h-2 overflow-hidden rounded-full bg-background/50">
        <div
          className={cn("h-full rounded-full bg-gradient-to-r transition-all duration-500", tone.bar)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
