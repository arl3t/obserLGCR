/**
 * DetectionOverview — Resumen por familia de logs (PostgreSQL).
 * KPIs desde detection_events ingeridos por scripts/agentes.
 */

import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldAlert,
  Radio,
  Shield,
  Mail,
  ArrowRight,
  RefreshCw,
  FileText,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchDetectionKpis, type DetectionFamilyKpi } from "@/api/detection";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

const CATEGORY_ICON: Record<string, React.ElementType> = {
  siem: ShieldAlert,
  ids: Radio,
  ips: Radio,
  firewall: Shield,
  email: Mail,
  other: FileText,
};

type Tone = "critical" | "warning" | "ok";

function toneFor(f: DetectionFamilyKpi): Tone {
  if (f.critical_24h > 0) return "critical";
  if (f.warn_24h > 10 || f.events_24h > 500) return "warning";
  return "ok";
}

function toneColor(tone: Tone) {
  return tone === "critical" ? "text-red-400" : tone === "warning" ? "text-amber-400" : "text-emerald-400";
}

function toneDot(tone: Tone) {
  return tone === "critical" ? "bg-red-500" : tone === "warning" ? "bg-amber-500" : "bg-emerald-500";
}

function FamilyCard({
  family,
  loading,
  onOpen,
}: {
  family: DetectionFamilyKpi;
  loading: boolean;
  onOpen: (family: string) => void;
}) {
  const Icon = CATEGORY_ICON[family.category] ?? FileText;
  const tone = toneFor(family);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onOpen(family.family)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen(family.family);
        }
      }}
      className={cn(
        "obser-stat-card cursor-pointer transition-colors hover:border-cyan-500/30",
        tone === "critical" && "border-red-500/30",
        !family.enabled && "opacity-60",
      )}
    >
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="rounded-lg bg-cyan-500/10 p-2 text-cyan-400">
            <Icon className="h-4 w-4" />
          </div>
          <div>
            <p className="text-sm font-semibold text-foreground">{family.label}</p>
            <p className="text-[11px] text-muted-foreground">{family.family}</p>
          </div>
        </div>
        <span className={cn("mt-1 h-2 w-2 shrink-0 rounded-full", toneDot(tone))} />
      </div>

      {!family.enabled && (
        <Badge variant="outline" className="mb-2 border-amber-500/40 text-[10px] text-amber-400">
          deshabilitada
        </Badge>
      )}

      <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">Eventos 24h</p>
      {loading ? (
        <Skeleton className="mt-1 h-8 w-20" />
      ) : (
        <p className={cn("obser-mono mt-1 text-2xl font-bold tabular-nums", toneColor(tone))}>
          {formatNumber(family.events_24h)}
        </p>
      )}

      <div className="mt-3 grid grid-cols-3 gap-2 border-t border-border/60 pt-3 text-[11px]">
        <div>
          <p className="text-muted-foreground">Críticos</p>
          <p className="obser-mono font-semibold text-red-400">{loading ? "—" : formatNumber(family.critical_24h)}</p>
        </div>
        <div>
          <p className="text-muted-foreground">Warn</p>
          <p className="obser-mono font-semibold text-amber-400">{loading ? "—" : formatNumber(family.warn_24h)}</p>
        </div>
        <div>
          <p className="text-muted-foreground">Hosts</p>
          <p className="obser-mono font-semibold">{loading ? "—" : formatNumber(family.hosts_24h)}</p>
        </div>
      </div>

      <div className="mt-3 flex items-center justify-end text-xs text-muted-foreground hover:text-cyan-400">
        Explorar logs
        <ArrowRight className="ml-1 h-3.5 w-3.5" />
      </div>
    </div>
  );
}

export function DetectionOverviewPage() {
  const [, setParams] = useSearchParams();

  const { data: families = [], isLoading, isFetching, refetch, error } = useQuery({
    queryKey: ["detection", "kpis"],
    queryFn: fetchDetectionKpis,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const openExplorer = (family: string) => {
    setParams({ tab: "explorer", family }, { replace: false });
  };

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Resumen de detecciones</h1>
          <p className="mt-0.5 max-w-2xl text-sm text-muted-foreground">
            Logs ingeridos por scripts y agentes · ventana 24h · almacenados en PostgreSQL.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="shrink-0 border-cyan-500/30 text-cyan-400">
            {families.length} familias
          </Badge>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1 text-[12px]"
            onClick={() => void refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
            Actualizar
          </Button>
        </div>
      </header>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs text-red-400">
          No se pudieron cargar los KPIs. ¿Migración 120 aplicada y API en ejecución?
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {isLoading
          ? Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="obser-stat-card">
                <Skeleton className="h-32 w-full" />
              </div>
            ))
          : families.map((f) => (
              <FamilyCard key={f.family} family={f} loading={isFetching} onOpen={openExplorer} />
            ))}
      </div>

      {!isLoading && families.every((f) => f.events_24h === 0) && (
        <div className="obser-panel py-12 text-center">
          <FileText className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">Sin eventos en las últimas 24 horas.</p>
          <p className="mt-1 text-[12px] text-muted-foreground/70">
            Configure el script <code className="text-cyan-400/80">obserlgcr-detection-shipper</code> en la pestaña Fuentes.
          </p>
        </div>
      )}
    </div>
  );
}
