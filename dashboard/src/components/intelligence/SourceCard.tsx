import { motion } from "framer-motion";
import { RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { formatNumber, formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { SourceCardProps } from "@/types/intelligence-sources";

const statusConfig: Record<
  SourceCardProps["source"]["status"],
  { label: string; badgeClass: string; dotClass: string }
> = {
  processed: {
    label: "Procesado",
    badgeClass:
      "border-emerald-500/50 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/15",
    dotClass: "bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.45)]",
  },
  pending: {
    label: "Pendiente",
    badgeClass:
      "border-amber-500/50 bg-amber-500/10 text-amber-200 hover:bg-amber-500/15",
    dotClass: "bg-amber-400 shadow-[0_0_10px_rgba(251,191,36,0.4)]",
  },
  error: {
    label: "Error",
    badgeClass:
      "border-red-500/50 bg-red-500/10 text-red-300 hover:bg-red-500/15",
    dotClass: "bg-red-400 shadow-[0_0_10px_rgba(248,113,113,0.45)]",
  },
  partial: {
    label: "Parcial",
    badgeClass:
      "border-sky-500/50 bg-sky-500/10 text-sky-200 hover:bg-sky-500/15",
    dotClass: "bg-sky-400 shadow-[0_0_10px_rgba(56,189,248,0.4)]",
  },
};

function MiniSparkline({ series }: { series: number[] }) {
  const h = 32;
  const w = 72;
  const max = Math.max(...series, 0.01);
  return (
    <svg
      width={w}
      height={h}
      className="shrink-0 text-primary/80"
      aria-hidden
    >
      {series.map((v, i) => {
        const barH = (v / max) * (h - 4);
        const x = (i / Math.max(1, series.length - 1)) * (w - 6) + 2;
        return (
          <rect
            key={i}
            x={x - 3}
            y={h - 2 - barH}
            width={4}
            height={Math.max(2, barH)}
            rx={1}
            fill="currentColor"
            opacity={0.35 + v * 0.5}
          />
        );
      })}
    </svg>
  );
}

export function SourceCard({
  source,
  icon: Icon,
  index,
  onRefresh,
  refreshing,
}: SourceCardProps) {
  const cfg = statusConfig[source.status];
  const pct =
    source.progress != null
      ? Math.min(100, Math.max(0, source.progress))
      : source.status === "processed"
        ? 100
        : source.status === "error"
          ? 0
          : 45;

  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 10 },
        show: { opacity: 1, y: 0 },
      }}
    >
      <Card
        className={cn(
          "group relative h-full overflow-hidden border-border/80 bg-card/90 shadow-sm transition-shadow",
          "hover:border-primary/35 hover:shadow-[0_0_0_1px_oklch(0.72_0.19_145/0.25),0_12px_40px_-20px_oklch(0.72_0.19_145/0.35)]",
        )}
      >
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-70"
          aria-hidden
        />
        <CardHeader className="space-y-3 pb-2">
          <div className="flex items-start justify-between gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex min-w-0 cursor-default items-center gap-2 text-left">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary ring-1 ring-primary/20">
                    <Icon className="h-5 w-5" aria-hidden />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate font-semibold leading-tight">
                      {source.name}
                    </p>
                    <p className="line-clamp-2 text-xs text-muted-foreground">
                      {source.description}
                    </p>
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs text-xs leading-relaxed">
                {source.tooltip}
              </TooltipContent>
            </Tooltip>
            <div className="flex shrink-0 flex-col items-end gap-1">
              <Badge variant="outline" className={cn("text-[11px] font-medium", cfg.badgeClass)}>
                <span
                  className={cn("mr-1.5 inline-block size-1.5 rounded-full", cfg.dotClass)}
                  aria-hidden
                />
                {cfg.label}
              </Badge>
            </div>
          </div>
          <div className="flex items-end justify-between gap-3">
            <div>
              <p className="text-2xl font-bold tabular-nums tracking-tight text-foreground">
                {formatNumber(source.recordCount)}
              </p>
              <p className="text-xs text-muted-foreground">
                {source.recordUnit} procesados
              </p>
            </div>
            <MiniSparkline series={source.activitySeries} />
          </div>
          <div className="space-y-1">
            <div className="flex justify-between text-[10px] uppercase tracking-wide text-muted-foreground">
              <span>Actividad reciente</span>
              <span className="tabular-nums text-foreground/80">{pct}%</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-muted">
              <motion.div
                className={cn(
                  "h-full rounded-full",
                  source.status === "error"
                    ? "bg-destructive/80"
                    : source.status === "pending"
                      ? "bg-amber-500/80"
                      : "bg-primary/90",
                )}
                initial={{ width: 0 }}
                animate={{ width: `${pct}%` }}
                transition={{ duration: 0.6, delay: 0.08 + index * 0.04 }}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="pb-2 pt-0">
          <p className="text-xs text-muted-foreground">
            {source.lastProcessedLabel ?? "Última ingesta"}:{" "}
            <span className="font-medium text-foreground">
              {formatRelativeTimeEs(source.lastProcessedAt)}
            </span>
          </p>
        </CardContent>
        <CardFooter className="flex flex-wrap gap-2 border-t border-border/60 bg-muted/5 pt-3">
          {source.detailHref ? (
            <Button variant="outline" size="sm" className="flex-1 text-xs" asChild>
              <Link to={source.detailHref}>Ver detalles</Link>
            </Button>
          ) : (
            <Button variant="outline" size="sm" className="flex-1 text-xs" type="button" disabled>
              Ver detalles
            </Button>
          )}
          <Button
            variant="secondary"
            size="sm"
            className="text-xs"
            type="button"
            disabled={refreshing}
            onClick={() => onRefresh?.(source.id)}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", refreshing && "animate-spin")}
              aria-hidden
            />
            Actualizar
          </Button>
        </CardFooter>
      </Card>
    </motion.div>
  );
}
