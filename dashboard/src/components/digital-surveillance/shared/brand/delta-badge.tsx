/**
 * Badge de delta porcentual — verde si ≥ 0, rojo si < 0. Para deltas semana a
 * semana en KPIs Brand24 (volumen, reach por categoría, etc.).
 */

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function DeltaBadge({ value }: { value: number }) {
  if (!Number.isFinite(value)) return null;
  const positive = value >= 0;
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-0.5 text-[10px] tabular-nums",
        positive
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
          : "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
      )}
    >
      {positive ? "+" : ""}{Math.round(value)}%
    </Badge>
  );
}
