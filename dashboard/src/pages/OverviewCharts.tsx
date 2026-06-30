import { keepPreviousData } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  ArrowRight,
  Bug,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  Skull,
  Ticket,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { computeRiskScore, severityFromScore } from "@/lib/risk-score";
import { useSocThresholds } from "@/hooks/useSocThresholds";
import { SocKpiPanel } from "@/components/soc/SocKpiPanel";
import { TicketCommMetricsPanel } from "@/components/tickets/TicketCommMetricsPanel";
import { GeoOriginRadarPanel } from "@/components/geo/GeoOriginRadarPanel";
import { PyHolidaysCalendar } from "@/components/calendar/PyHolidaysCalendar";
import { cn } from "@/lib/utils";

/** Cache 2 min + auto-refresh cada 5 min — dashboard operativo */
const STALE_2M = {
  staleTime: 2 * 60 * 1000,
  gcTime: 10 * 60 * 1000,
  placeholderData: keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

/* ── Ventanas de tiempo ─────────────────────────────────────────────────── */
type TimeWindow = "1d" | "7d" | "30d" | "365d";
const TIME_WINDOWS: { id: TimeWindow; label: string; hours: number; days: number }[] = [
  { id: "1d",   label: "Día",    hours: 24,   days: 1   },
  { id: "7d",   label: "Semana", hours: 168,  days: 7   },
  { id: "30d",  label: "Mes",    hours: 720,  days: 30  },
  { id: "365d", label: "Año",    hours: 8760, days: 365 },
];

function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") {
    const x = Number(v);
    return Number.isNaN(x) ? 0 : x;
  }
  return 0;
}

/* ── Severity badge ────────────────────────────────────────────────── */
function SeverityBadge({ level }: { level: string }) {
  const l = level.toLowerCase();
  const variant =
    l === "critical" || l === "high"
      ? "destructive"
      : l === "medium"
        ? "secondary"
        : "outline";
  return (
    <Badge variant={variant} className="capitalize text-[11px]">
      {level}
    </Badge>
  );
}

// Rediseño 2026-06-25: el Centro de Mando se concentró en lo que tiene señal real
// (origen geográfico, riesgo global, KPIs SOC e IOC confirmados por VT). Se quitaron
// los bloques de perímetro OPNsense/filterlog (fuente deshabilitada → siempre 0) y los
// paneles de Top reglas Wazuh / CVE críticos, cuyas queries (wazRules, wazCves) y la de
// outliers daban "batch item timeout (30000 ms)" y saturaban Trino. Con eso el batch
// pasó de 7 a 4 queries → carga más rápida y sin timeouts.
type OverviewKey = "syslogBundle" | "wazCrit";

function buildOverviewBatch(hours: number, _days: number): readonly BatchSpec[] {
  return [
    // Bundle filterlog: 1 scan para los contadores del riesgo global (blocks/uniqueIps).
    { key: "syslogBundle", id: "lh.syslog.overview_bundle_Nh",
      params: { hours, topIpLimit: 0, topPortLimit: 0 } },
    { key: "wazCrit",   id: "lh.wazuh.critical_count_Nh",        params: { hours }                    },
  ] satisfies BatchSpec[];
}

interface BundleRow {
  kind?: string;
  label?: string | null;
  hits?: number | string | null;
  unique_ips?: number | string | null;
}

/** Demuxa filas del bundle (UNION ALL) → contadores 24h para el riesgo global. */
function demuxSyslogBundle(rows: BundleRow[] | undefined) {
  if (!rows) return { blocks24: [], ips24: [] };
  const totalsRow = rows.find((r) => r.kind === "total");
  return {
    blocks24: totalsRow ? [{ c: n(totalsRow.hits) }] : [],
    ips24:    totalsRow ? [{ c: n(totalsRow.unique_ips) }] : [],
  };
}

export function OverviewChartsPage() {
  const [activeWindow, setActiveWindow] = useState<TimeWindow>("1d");

  const { hours, days } = useMemo(
    () => TIME_WINDOWS.find((w) => w.id === activeWindow) ?? TIME_WINDOWS[0],
    [activeWindow],
  );

  const overviewBatch = useMemo(
    () => buildOverviewBatch(hours, days),
    [hours, days],
  );

  /* ── Una sola petición batch (4 queries) — la queryKey incluye la ventana ── */
  const { results, isLoading: batchLoading, isFetching: batchFetching, refetch } =
    useTrinoNamedBatch<OverviewKey>(["cmd", "overview", activeWindow], overviewBatch, STALE_2M);

  function batchAlias(key: OverviewKey) {
    const r = results[key];
    return {
      data: r.data,
      isLoading: batchLoading && r.data === undefined,
      error: r.error ? new Error(r.error) : null,
    };
  }

  const bundleRaw   = batchAlias("syslogBundle");
  const bundleDemux = useMemo(
    () => demuxSyslogBundle(bundleRaw.data as BundleRow[] | undefined),
    [bundleRaw.data],
  );
  const blocks24 = { data: bundleDemux.blocks24, isLoading: bundleRaw.isLoading, error: bundleRaw.error };
  const ips24    = { data: bundleDemux.ips24,    isLoading: bundleRaw.isLoading, error: bundleRaw.error };
  const wazCrit  = batchAlias("wazCrit");

  /* ── Derivados ── */
  const b24       = n(blocks24.data?.[0]?.c);
  const u24       = n(ips24.data?.[0]?.c);
  const critCount = n(wazCrit.data?.[0]?.c);

  const globalRisk = computeRiskScore({
    blocks24h: b24,
    uniqueBlockedIps24h: u24,
    wazuhCritical24h: critCount,
  });
  const { data: sevThr } = useSocThresholds();
  const gLabel = severityFromScore(globalRisk, sevThr);
  const isHigh = gLabel === "critical" || gLabel === "high";

  /* ── Navegación rápida ── */
  const quickNav = [
    { to: "/external-threats",       label: "Amenazas externas",  icon: Shield       },
    { to: "/wazuh-intelligence",     label: "Wazuh",              icon: ShieldAlert  },
    { to: "/enriched-score",         label: "IOC enriquecidos",   icon: Bug          },
    { to: "/operacion-analista-soc", label: "SOC MITRE",          icon: Radio        },
    { to: "/live-activity",          label: "Live activity",      icon: AlertTriangle },
    { to: "/intelligence-sources",   label: "Fuentes intel",      icon: ArrowRight   },
  ] as const;

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">

      {/* CABECERA */}
      <header className="flex flex-col gap-3">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight md:text-3xl">Centro de mando</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
              Estado consolidado del SOC: origen geográfico de la amenaza, riesgo global,
              KPIs operativos e IOC confirmados por VirusTotal. Ventana activa:{" "}
              <strong>
                {TIME_WINDOWS.find((w) => w.id === activeWindow)?.label ?? activeWindow}
              </strong>.
            </p>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            <Badge variant="cyber" className="w-fit shrink-0">
              lh.wazuh · lh.hunting
            </Badge>
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1 text-[11px] text-muted-foreground">
                <RefreshCw className="h-3 w-3 animate-none" aria-hidden />
                Actualización manual
              </span>
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1 text-[11px]"
                onClick={() => void refetch()}
                disabled={batchFetching}
              >
                <RefreshCw className={cn("h-3.5 w-3.5", batchFetching && "animate-spin")} />
                {batchFetching ? "Actualizando..." : "Refrescar"}
              </Button>
            </div>
          </div>
        </div>

        {/* Selector de ventana temporal */}
        <div className="flex items-center gap-1 rounded-lg border border-border/60 bg-muted/30 p-1 w-fit">
          {TIME_WINDOWS.map((w) => (
            <button
              key={w.id}
              onClick={() => setActiveWindow(w.id)}
              className={cn(
                "rounded-md px-3 py-1 text-xs font-medium transition-colors",
                activeWindow === w.id
                  ? "bg-background text-foreground shadow-sm border border-border/60"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/60",
              )}
            >
              {w.label}
            </button>
          ))}
        </div>
      </header>

      {/* Origen geográfico — radar táctico (mismo WorldRadarMap del informe técnico) */}
      <GeoOriginRadarPanel windowHours={hours} />

      {/* BANNER RIESGO GLOBAL */}
      <motion.div
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        className={cn(
          "flex flex-col gap-2 rounded-xl border px-5 py-4 sm:flex-row sm:items-center sm:justify-between",
          isHigh ? "border-destructive/50 bg-destructive/5" : "border-border/80 bg-card/50",
        )}
      >
        <div className="flex items-center gap-3">
          {isHigh ? (
            <Skull className="h-5 w-5 shrink-0 text-destructive" aria-hidden />
          ) : (
            <Shield className="h-5 w-5 shrink-0 text-primary" aria-hidden />
          )}
          <div>
            <p className="text-sm font-semibold">Riesgo global de infraestructura</p>
            <p className="text-xs text-muted-foreground">
              Heurística combinada: volumen de bloqueos, IPs únicas y alertas Wazuh críticas
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-4xl font-bold tabular-nums">{globalRisk}</span>
          <SeverityBadge level={gLabel} />
        </div>
      </motion.div>

      {/* SOC KPIs operacionales */}
      <SocKpiPanel windowHours={hours} />

      {/* Tickets — métricas de comunicación con el cliente (F4) */}
      <div className="flex flex-col gap-3">
        <Link to="/tickets" className="flex items-center gap-2 text-sm font-medium text-foreground hover:underline w-fit">
          <Ticket className="h-4 w-4 text-cyan-400" /> Comunicación con clientes (tickets)
        </Link>
        <TicketCommMetricsPanel days={30} compact />
      </div>

      <Separator />

      {/* NAVEGACIÓN RÁPIDA */}
      <section>
        <p className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Ir a sección detallada
        </p>
        <div className="flex flex-wrap gap-2">
          {quickNav.map(({ to, label, icon: Icon }) => (
            <Button key={to} variant="secondary" size="sm" className="gap-1.5" asChild>
              <Link to={to}>
                <Icon className="h-3.5 w-3.5 opacity-70" aria-hidden />
                {label}
                <ArrowRight className="h-3 w-3 opacity-50" aria-hidden />
              </Link>
            </Button>
          ))}
        </div>
      </section>

      {/* Calendario sutil de feriados de Paraguay */}
      <PyHolidaysCalendar />

    </div>
  );
}
