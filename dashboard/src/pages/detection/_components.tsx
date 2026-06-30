/**
 * Primitivas compartidas por las páginas de detalle del Detection Center
 * (Wazuh, Suricata, Filterlog, Fortigate, PMG, Wazuh Fluent). Mantener
 * el lenguaje visual uniforme y evita que cada página re-invente loading,
 * empty-state y filas de barra.
 */

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatNumber } from "@/lib/format";

export type Tone = "critical" | "warning" | "ok" | "info" | "muted";

export function toneText(tone: Tone): string {
  switch (tone) {
    case "critical": return "text-red-400";
    case "warning":  return "text-amber-400";
    case "ok":       return "text-emerald-400";
    case "info":     return "text-sky-400";
    default:         return "text-foreground";
  }
}

export function toneBar(tone: Tone): string {
  switch (tone) {
    case "critical": return "bg-red-500/70";
    case "warning":  return "bg-amber-500/70";
    case "ok":       return "bg-emerald-500/70";
    case "info":     return "bg-sky-500/70";
    default:         return "bg-muted-foreground/50";
  }
}

// ── KPI Tile ──────────────────────────────────────────────────────────────────

export function KpiTile({
  label,
  value,
  sub,
  icon: Icon,
  tone,
  loading,
}: {
  label:    string;
  value:    number | string;
  sub?:     string;
  icon?:    React.ElementType;
  tone?:    Tone;
  loading?: boolean;
}) {
  return (
    <div className="rounded-xl border border-border/80 bg-card/60 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </p>
        {Icon && <Icon className={cn("h-3.5 w-3.5", toneText(tone ?? "muted"))} aria-hidden />}
      </div>
      {loading ? (
        <Skeleton className="mt-1 h-7 w-20" />
      ) : (
        <p className={cn(
          "mt-1 text-2xl font-bold tabular-nums tracking-tight",
          toneText(tone ?? "muted"),
        )}>
          {typeof value === "number" ? formatNumber(value) : value}
        </p>
      )}
      {sub && <p className="mt-0.5 text-[11px] text-muted-foreground">{sub}</p>}
    </div>
  );
}

// ── Section Card — card genérica con título + slot de contenido ─────────────

export function SectionCard({
  title,
  subtitle,
  right,
  children,
  className,
}: {
  title:     string;
  subtitle?: string;
  right?:    ReactNode;
  children:  ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("border-border/80 bg-card/60", className)}>
      <CardHeader className="flex flex-row items-start justify-between gap-2 pb-3">
        <div className="min-w-0">
          <CardTitle className="text-sm">{title}</CardTitle>
          {subtitle && <p className="mt-0.5 text-[11px] text-muted-foreground">{subtitle}</p>}
        </div>
        {right}
      </CardHeader>
      <CardContent className="pt-0">{children}</CardContent>
    </Card>
  );
}

// ── Bar Row — fila con etiqueta + barra proporcional + valor ─────────────────
// Reemplaza BarChart vertical + YAxis custom en tablas top-N. Ligero y sin
// dependencia de Recharts para datos pequeños (≤ 20 filas).

export function BarRow({
  label,
  value,
  max,
  tone,
  right,
  onClick,
  title,
}: {
  label:   ReactNode;
  value:   number;
  max:     number;
  tone?:   Tone;
  right?:  ReactNode;
  onClick?: () => void;
  title?:  string;
}) {
  const pct = max > 0 ? Math.max(4, Math.round((value / max) * 100)) : 0;
  return (
    <div
      title={title}
      onClick={onClick}
      className={cn(
        "group flex items-center gap-3 px-3 py-1.5",
        onClick && "cursor-pointer rounded-md hover:bg-muted/40",
      )}
    >
      <div className="min-w-0 flex-1 truncate text-xs">{label}</div>
      <div className="relative h-2 w-32 overflow-hidden rounded-full bg-muted/40 sm:w-48">
        <div
          className={cn("h-full rounded-full", toneBar(tone ?? "info"))}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="w-14 text-right text-xs font-semibold tabular-nums">
        {formatNumber(value)}
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}

// ── Empty / Loading helpers ─────────────────────────────────────────────────

export function LoadingRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2 py-2">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-5 w-full" />
      ))}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <p className="py-6 text-center text-xs text-muted-foreground">{message}</p>
  );
}

// ── Sparkline minimal — timeline horaria sin Recharts ───────────────────────
// Para detalles donde un AreaChart es innecesario. ≤ 24 puntos = 24 columnas.

export function MiniSparkline({
  data,
  height = 32,
  tone = "info",
  label,
}: {
  data:    Array<{ value: number; label?: string }>;
  height?: number;
  tone?:   Tone;
  label?:  string;
}) {
  if (data.length === 0) return <div className="text-[11px] text-muted-foreground">—</div>;
  const max = Math.max(1, ...data.map((p) => p.value));
  return (
    <div className="flex flex-col gap-1">
      {label && <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</p>}
      <div className="flex items-end gap-[2px]" style={{ height }}>
        {data.map((p, i) => {
          const pct = Math.max(3, Math.round((p.value / max) * 100));
          return (
            <div
              key={i}
              title={`${p.label ?? ""}: ${formatNumber(p.value)}`}
              className={cn("w-full rounded-sm transition-colors", toneBar(tone))}
              style={{ height: `${pct}%` }}
            />
          );
        })}
      </div>
    </div>
  );
}

// ── Severity badge unificado ────────────────────────────────────────────────
// Útil para Suricata (1..4), Wazuh (0..15), PMG (spam score), etc.

export function SeverityBadge({
  label,
  tone,
}: {
  label: string;
  tone:  Tone;
}) {
  const cls = cn(
    "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
    tone === "critical" && "border-red-500/40 bg-red-500/10 text-red-400",
    tone === "warning"  && "border-amber-500/40 bg-amber-500/10 text-amber-400",
    tone === "ok"       && "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
    tone === "info"     && "border-sky-500/40 bg-sky-500/10 text-sky-400",
    tone === "muted"    && "border-border bg-muted/60 text-muted-foreground",
  );
  return <span className={cls}>{label}</span>;
}

// ── Header compartido de página de detalle ─────────────────────────────────

export function DetailHeader({
  title,
  subtitle,
  icon: Icon,
  right,
}: {
  title:    string;
  subtitle: string;
  icon:     React.ElementType;
  right?:   ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted text-foreground/80">
          <Icon className="h-5 w-5" aria-hidden />
        </div>
        <div>
          <h1 className="text-xl font-semibold leading-tight">{title}</h1>
          <p className="text-xs text-muted-foreground">{subtitle}</p>
        </div>
      </div>
      {right}
    </div>
  );
}
