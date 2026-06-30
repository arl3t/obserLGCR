/**
 * DetectionOverview — Resumen global + KPIs por familia de sensor.
 */

import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  Clock,
  FileText,
  Server,
  Radio,
  RefreshCw,
  Shield,
  Mail,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { DetectionTimeline } from "@/components/detection/DetectionTimeline";
import { fetchDetectionKpis, fetchDetectionStats, type DetectionFamilyKpi } from "@/api/detection";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import { BarRow, KpiTile } from "@/pages/detection/_components";

const CATEGORY_ICON: Record<string, React.ElementType> = {
  siem: Shield,
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
        "detection-family-card obser-stat-card cursor-pointer transition-colors hover:border-cyan-500/30",
        tone === "critical" && "border-red-500/30",
        !family.enabled && "opacity-60",
      )}
    >
      <div className="relative z-[1]">
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
            <p className="obser-mono font-semibold text-red-400">
              {loading ? "—" : formatNumber(family.critical_24h)}
            </p>
          </div>
          <div>
            <p className="text-muted-foreground">Warn</p>
            <p className="obser-mono font-semibold text-amber-400">
              {loading ? "—" : formatNumber(family.warn_24h)}
            </p>
          </div>
          <div>
            <p className="text-muted-foreground">Hosts</p>
            <p className="obser-mono font-semibold">{loading ? "—" : formatNumber(family.hosts_24h)}</p>
          </div>
        </div>

        {family.last_event_at && (
          <p className="mt-2 flex items-center gap-1 text-[10px] text-muted-foreground">
            <Clock className="h-3 w-3" />
            Último: {new Date(family.last_event_at).toLocaleString("es-PY")}
          </p>
        )}

        <div className="mt-3 flex items-center justify-end text-xs text-muted-foreground hover:text-cyan-400">
          Explorar logs
          <ArrowRight className="ml-1 h-3.5 w-3.5" />
        </div>
      </div>
    </div>
  );
}

export function DetectionOverviewPage() {
  const [, setParams] = useSearchParams();

  const statsQ = useQuery({
    queryKey: ["detection", "stats", 24],
    queryFn: () => fetchDetectionStats(24),
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const kpisQ = useQuery({
    queryKey: ["detection", "kpis"],
    queryFn: fetchDetectionKpis,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const families = kpisQ.data ?? [];
  const stats = statsQ.data;
  const isFetching = statsQ.isFetching || kpisQ.isFetching;

  const refetch = () => {
    void statsQ.refetch();
    void kpisQ.refetch();
  };

  const openExplorer = (family: string) => {
    setParams({ tab: "explorer", family }, { replace: false });
  };

  const sevMax = Math.max(...(stats?.severity.map((s) => s.count) ?? [1]), 1);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Resumen operativo</h1>
          <p className="mt-0.5 max-w-2xl text-sm text-muted-foreground">
            Ventana 24h · datos en PostgreSQL (`detection_events`) · ingesta vía shipper
          </p>
        </div>
        <div className="flex items-center gap-2">
          {stats?.last_event_at && (
            <Badge variant="outline" className="shrink-0 border-emerald-500/30 text-emerald-400">
              Último evento: {new Date(stats.last_event_at).toLocaleTimeString("es-PY")}
            </Badge>
          )}
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1 text-[12px]"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
            Actualizar
          </Button>
        </div>
      </header>

      {(statsQ.error || kpisQ.error) && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs text-red-400">
          No se pudieron cargar los KPIs. ¿Migración 120 aplicada y API en ejecución?
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KpiTile
          label="Eventos totales"
          value={stats?.total ?? 0}
          icon={FileText}
          tone={stats && stats.critical > 0 ? "critical" : "info"}
          loading={statsQ.isLoading}
        />
        <KpiTile
          label="Críticos / error"
          value={stats?.critical ?? 0}
          icon={AlertTriangle}
          tone="critical"
          loading={statsQ.isLoading}
        />
        <KpiTile
          label="Hosts distintos"
          value={stats?.hosts ?? 0}
          icon={Server}
          tone="ok"
          loading={statsQ.isLoading}
        />
        <KpiTile
          label="Fuentes activas"
          value={stats?.source_logs ?? 0}
          sub={`${families.length} familias en catálogo`}
          icon={Radio}
          tone="info"
          loading={statsQ.isLoading}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="obser-panel p-4">
          <p className="mb-3 text-[13px] font-medium text-foreground">Actividad por hora</p>
          <DetectionTimeline buckets={stats?.timeline ?? []} loading={statsQ.isLoading} />
        </div>
        <div className="obser-panel p-4">
          <p className="mb-3 text-[13px] font-medium text-foreground">Distribución por severidad</p>
          {statsQ.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : stats?.severity.length ? (
            <div className="space-y-2">
              {stats.severity.map((s) => (
                <BarRow
                  key={s.severity}
                  label={s.severity}
                  value={s.count}
                  max={sevMax}
                  tone={
                    s.severity === "critical" || s.severity === "error"
                      ? "critical"
                      : s.severity === "warn"
                        ? "warning"
                        : "muted"
                  }
                />
              ))}
            </div>
          ) : (
            <p className="py-8 text-center text-[12px] text-muted-foreground">Sin datos de severidad</p>
          )}
        </div>
      </div>

      <div>
        <p className="mb-3 text-[13px] font-medium text-foreground">Por familia de sensor</p>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {kpisQ.isLoading
            ? Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="obser-stat-card">
                  <Skeleton className="h-32 w-full" />
                </div>
              ))
            : families.map((f) => (
                <FamilyCard key={f.family} family={f} loading={isFetching} onOpen={openExplorer} />
              ))}
        </div>
      </div>

      {!kpisQ.isLoading && families.every((f) => f.events_24h === 0) && (
        <div className="obser-panel py-12 text-center">
          <FileText className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" />
          <p className="text-sm font-medium text-foreground">Sin eventos en las últimas 24 horas</p>
          <p className="mx-auto mt-2 max-w-md text-[12px] text-muted-foreground">
            Instale el shipper en un host con acceso a los logs de Wazuh, Suricata o firewall y envíe lotes a{" "}
            <code className="text-cyan-400/80">POST /api/detection/ingest</code>. Vea la pestaña Fuentes.
          </p>
          <Button
            variant="outline"
            size="sm"
            className="mt-4"
            onClick={() => setParams({ tab: "sources" })}
          >
            Configurar fuentes
          </Button>
        </div>
      )}
    </div>
  );
}
