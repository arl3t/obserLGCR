/**
 * SocKpiPanel.tsx
 * KPIs operacionales SOC alineados con NIST SP 800-61 Rev. 3 + CSF 2.0.
 *
 * 12 métricas clave:
 *  1. MTTD  — Mean Time to Detect            (DE.CM · DE.AE)
 *  2. MTTR  — Mean Time to Respond           (RS.MA · RS.MI · RC.RP)
 *  3. MTTC  — Mean Time to Contain           (RS.MI)
 *  4. MTTA  — Mean Time to Acknowledge       (RS.MA)
 *  5. FPR   — False Positive Rate            (DE.AE)
 *  6. MITRE — ATT&CK Coverage                (ID.RA · DE.CM)
 *  7. DEDUP — Auto-deduplication Rate        (RS.MA)
 *  8. ESC   — L1→L2 Escalation Time          (RS.MA · RS.CO)
 *  9. WAZUH — Rule Fallback Rate             (ID.IM · DE.CM)
 * 10. PM    — Post-Mortem / Lessons Rate     (ID.IM)
 * 11. SLA   — SLA Critical Compliance        (RS.MA)
 * 12. ESCR  — Escalation Rate                (RS.MA)
 */
import { useMemo, useState } from "react";
import { RefreshCw, TrendingDown, TrendingUp, Minus, Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { DashboardKpis, MitreCoverageBySource } from "@/components/case-management/types";
import { formatNumber } from "@/lib/format";

// Mapea source_log crudo a etiqueta amigable. Réplica simple del CASE SQL en
// incident-scoring-sql.mjs:1457 — sólo para presentación.
function prettySourceLabel(raw: string): string {
  const s = raw.toLowerCase();
  if (s.startsWith("wazuh_fluent"))                       return "Wazuh Fluent";
  if (s === "wazuh_alerts" || s === "wazuh")              return "Wazuh SIEM";
  if (s.includes("filterlog") || s.includes("opnsense"))  return "OPNsense FW";
  if (s === "suricata" || s.startsWith("suricata_"))      return "Suricata IDS";
  if (s === "fortigate" || s.startsWith("forti"))         return "FortiGate FW";
  if (s === "pmg" || s.includes("phishing"))              return "PMG Email";
  if (s === "manual-flow")                                return "Apertura manual";
  if (!raw || raw === "(sin fuente)")                     return "(sin fuente)";
  return raw;
}

function MitreCoveragePanel({
  data, loading,
}: { data: MitreCoverageBySource[]; loading: boolean }) {
  // Filtramos fuentes con muy poca muestra (n<3) para evitar barras volátiles,
  // y limitamos a las 6 top por volumen — suficiente para la conversación
  // "dónde meter trabajo de mapeo".
  const rows = useMemo(() => {
    return [...data]
      .filter((r) => r.total >= 3)
      .sort((a, b) => b.total - a.total)
      .slice(0, 6);
  }, [data]);

  if (loading) {
    return (
      <div className="rounded-lg border border-border/50 bg-card/60 p-3 space-y-2">
        <Skeleton className="h-3 w-40" />
        <Skeleton className="h-2 w-full" />
        <Skeleton className="h-2 w-full" />
        <Skeleton className="h-2 w-full" />
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-border/50 bg-card/60 p-3 text-[11px] text-muted-foreground">
        Cobertura MITRE por fuente: sin muestras suficientes en la ventana actual.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border/50 bg-card/60 p-3">
      <div className="flex items-center justify-between mb-2">
        <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">
          Cobertura MITRE por fuente
        </p>
        <span className="text-[9px] text-muted-foreground/60 font-mono">
          % de casos con táctica asignada
        </span>
      </div>
      <div className="space-y-1.5">
        {rows.map((r) => {
          const pct = r.pct ?? 0;
          const cls =
            pct >= 80 ? "bg-emerald-500"
            : pct >= 50 ? "bg-amber-400"
            : "bg-red-500";
          const labelCls =
            pct >= 80 ? "text-emerald-400"
            : pct >= 50 ? "text-amber-400"
            : "text-red-400";
          return (
            <div key={r.sourceLog} className="grid grid-cols-[140px_1fr_auto] items-center gap-2 text-[11px]">
              <span className="truncate text-foreground/90" title={r.sourceLog}>
                {prettySourceLabel(r.sourceLog)}
              </span>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted/40">
                <div
                  className={cn("h-full rounded-full transition-all duration-500", cls)}
                  style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
                />
              </div>
              <span className={cn("font-mono tabular-nums text-right w-20", labelCls)}>
                {pct.toFixed(0)}% · {formatNumber(r.mapped)}/{formatNumber(r.total)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Paleta ──────────────────────────────────────────────────────────────────

const COLOR = {
  green:  { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", hex: "#22c55e" },
  yellow: { text: "text-amber-400",   bg: "bg-amber-500/10",   border: "border-amber-500/30",   hex: "#f59e0b" },
  red:    { text: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/30",      hex: "#ef4444" },
  none:   { text: "text-muted-foreground", bg: "bg-muted/20", border: "border-border/60",        hex: "#64748b" },
};
type ColorKey = keyof typeof COLOR;

// ── Tipos ──────────────────────────────────────────────────────────────────

type MetricType = "time" | "percent" | "count" | "rate_lower";
type Priority   = "CRÍTICA" | "ALTA" | "MEDIA";

interface MetricDef {
  id:          string;
  abbr:        string;
  name:        string;
  nistRef:     string;
  what:        string;
  unit:        string;
  type:        MetricType;
  priority:    Priority;
  /** Verde ≤ umbral si lowerIsBetter=true, ≥ umbral si false */
  green:       number;
  yellow:      number;
  lowerIsBetter: boolean;
  targetLabel: string;
  /** Etiqueta aspiracional con XDR/IA */
  aspiracional?: string;
  /** Si está definido, esta métrica usa ventana fija (en horas) y no
   *  responde al selector global. P. ej. MITRE coverage y Postmortem rate
   *  necesitan 30d (720h) por significancia estadística. */
  fixedWindowHours?: number;
}

// ── Definición de las 10 métricas NIST ──────────────────────────────────────

const METRICS: MetricDef[] = [
  {
    id: "mttd",
    abbr: "MTTD",
    name: "Detection-to-Case Latency",
    nistRef: "DE.CM · DE.AE",
    what: "Latencia desde la detección del sensor hasta la creación del caso (proxy de MTTD; dwell-time real requiere event-time del log)",
    unit: "min", type: "time", priority: "CRÍTICA",
    green: 60, yellow: 240, lowerIsBetter: true,
    targetLabel: "< 4h Critical/High",
    aspiracional: "< 1h con XDR + IA",
  },
  {
    id: "mttr",
    abbr: "MTTR",
    name: "Mean Time to Respond",
    nistRef: "RS.MA · RS.MI · RC.RP",
    what: "Tiempo desde detección hasta contención y resolución completa",
    unit: "min", type: "time", priority: "CRÍTICA",
    green: 1440, yellow: 2880, lowerIsBetter: true,
    targetLabel: "< 24h",
  },
  {
    id: "mttc",
    abbr: "MTTC",
    name: "Mean Time to Contain",
    nistRef: "RS.MI",
    what: "Tiempo desde apertura del caso hasta primer evento de contención",
    unit: "min", type: "time", priority: "CRÍTICA",
    green: 60, yellow: 240, lowerIsBetter: true,
    targetLabel: "< 1h Critical · < 4h High",
  },
  {
    id: "mtta",
    abbr: "MTTA",
    name: "Mean Time to Acknowledge",
    nistRef: "RS.MA",
    what: "Tiempo desde creación del caso hasta que un analista lo adopta",
    unit: "min", type: "time", priority: "ALTA",
    green: 5, yellow: 10, lowerIsBetter: true,
    targetLabel: "< 5–10 min",
  },
  {
    id: "fpRate",
    abbr: "FPR",
    name: "False Positive Rate",
    nistRef: "DE.AE",
    what: "% de alertas/casos que resultan ser falsos positivos",
    unit: "%", type: "percent", priority: "ALTA",
    green: 5, yellow: 10, lowerIsBetter: true,
    targetLabel: "< 10% general",
    aspiracional: "< 5% con tuning + IA",
  },
  {
    id: "mitreCov",
    abbr: "MITRE",
    name: "ATT&CK Coverage",
    nistRef: "ID.RA · DE.CM",
    what: "% de tácticas MITRE Enterprise observadas (14 tácticas totales)",
    unit: "%", type: "percent", priority: "ALTA",
    green: 70, yellow: 50, lowerIsBetter: false,
    targetLabel: "100% tácticas · ≥ 70% técnicas críticas",
    fixedWindowHours: 720,
  },
  {
    id: "autoDedup",
    abbr: "DEDUP",
    name: "Auto-Deduplication Rate",
    nistRef: "RS.MA",
    what: "% de alertas/IOCs deduplicados automáticamente sin intervención",
    unit: "%", type: "percent", priority: "ALTA",
    green: 90, yellow: 70, lowerIsBetter: false,
    targetLabel: "> 90%",
  },
  {
    id: "l1l2Esc",
    abbr: "ESC L1→L2",
    name: "Tiempo Escalada L1→L2",
    nistRef: "RS.MA · RS.CO",
    what: "Tiempo desde adopción L1 hasta escalación a analista senior",
    unit: "min", type: "time", priority: "ALTA",
    green: 15, yellow: 30, lowerIsBetter: true,
    targetLabel: "< 15 min Critical/High",
  },
  {
    id: "wazuhFallback",
    abbr: "MITRE-GAP",
    name: "Casos sin táctica MITRE",
    nistRef: "ID.IM · DE.CM",
    what: "% agregado de casos sin mitre_tactic_id (desglose por sensor más abajo)",
    unit: "%", type: "rate_lower", priority: "MEDIA",
    green: 3, yellow: 10, lowerIsBetter: true,
    targetLabel: "< 3% en fallback genérico",
  },
  {
    id: "postmortem",
    abbr: "POST-M",
    name: "Post-Mortem Rate",
    nistRef: "ID.IM",
    what: "% de casos cerrados con lecciones aprendidas documentadas",
    unit: "%", type: "percent", priority: "MEDIA",
    green: 90, yellow: 60, lowerIsBetter: false,
    targetLabel: "> 90%",
    fixedWindowHours: 720,
  },
  {
    id: "slaCritical",
    abbr: "SLA",
    name: "SLA Critical Compliance",
    nistRef: "RS.MA",
    what: "% de casos CRITICAL adoptados dentro del SLA (≤ 60 min)",
    unit: "%", type: "percent", priority: "CRÍTICA",
    green: 95, yellow: 80, lowerIsBetter: false,
    targetLabel: "≥ 95% CRITICAL",
  },
  {
    id: "escalationRate",
    abbr: "ESC RATE",
    name: "Escalation Rate",
    nistRef: "RS.MA",
    what: "% de casos escalados a L2/L3 (proxy de complejidad y carga L1)",
    unit: "%", type: "percent", priority: "MEDIA",
    green: 15, yellow: 30, lowerIsBetter: true,
    targetLabel: "5–15% saludable",
  },
];

// ── Status helper ─────────────────────────────────────────────────────────────

function getColor(value: number | null, def: MetricDef): ColorKey {
  if (value === null) return "none";
  if (def.lowerIsBetter) {
    if (value <= def.green)  return "green";
    if (value <= def.yellow) return "yellow";
    return "red";
  } else {
    if (value >= def.green)  return "green";
    if (value >= def.yellow) return "yellow";
    return "red";
  }
}

function fmtValue(value: number | null, def: MetricDef): string {
  if (value === null) return "N/D";
  if (def.type === "time") {
    if (value < 60) return `${Math.round(value)} min`;
    return `${(value / 60).toFixed(1)} h`;
  }
  if (def.type === "count") return formatNumber(value);
  return `${value.toFixed(1)}%`;
}

// ── Gauge arc SVG ─────────────────────────────────────────────────────────────

function GaugeArc({ pct, colorKey }: { pct: number; colorKey: ColorKey }) {
  const r = 42, cx = 58, cy = 58;
  const arc = Math.PI * r;
  const fill = Math.min(1, Math.max(0, pct / 100)) * arc;
  const hex = COLOR[colorKey].hex;
  return (
    <svg viewBox="0 0 116 64" className="w-full" aria-hidden>
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
        fill="none" stroke="currentColor" strokeWidth="8" strokeLinecap="round"
        className="text-border/40" />
      {pct > 0 && (
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" stroke={hex} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={`${fill} ${arc}`}
          style={{ transition: "stroke-dasharray 0.7s ease" }} />
      )}
    </svg>
  );
}

// ── Barra horizontal ──────────────────────────────────────────────────────────

function Bar({ pct, colorKey }: { pct: number; colorKey: ColorKey }) {
  const cls = colorKey === "green" ? "bg-emerald-500"
            : colorKey === "yellow" ? "bg-amber-400"
            : colorKey === "red"    ? "bg-red-500"
            : "bg-muted-foreground/40";
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-muted/40">
      <div className={cn("h-full rounded-full transition-all duration-700", cls)}
        style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
    </div>
  );
}

// ── Trend icon ────────────────────────────────────────────────────────────────

function TrendIcon({ def, colorKey }: { def: MetricDef; colorKey: ColorKey }) {
  if (colorKey === "none") return <Minus className="h-3 w-3 text-muted-foreground/40" />;
  const good = colorKey === "green";
  const warn = colorKey === "yellow";
  const Icon = def.lowerIsBetter
    ? (good ? TrendingDown : TrendingUp)
    : (good ? TrendingUp  : TrendingDown);
  return (
    <Icon className={cn("h-3 w-3",
      good ? "text-emerald-400" : warn ? "text-amber-400" : "text-red-400"
    )} />
  );
}

// ── Priority badge ────────────────────────────────────────────────────────────

const PRIORITY_CLS: Record<Priority, string> = {
  "CRÍTICA": "bg-red-500/15 text-red-400 border-red-500/30",
  "ALTA":    "bg-amber-500/15 text-amber-400 border-amber-500/30",
  "MEDIA":   "bg-muted/30 text-muted-foreground border-border/50",
};

// ── Metric Card ───────────────────────────────────────────────────────────────

function fmtWindowLabel(hours: number): string {
  if (hours <= 48)     return `${hours}h`;
  if (hours <= 168)    return `${Math.round(hours / 24)}d`;
  if (hours <= 720)    return `${Math.round(hours / 24)}d`;
  return `${Math.round(hours / 24)}d`;
}

function MetricCard({
  def, value, loading, activeWindowHours, sampleSize,
}: {
  def: MetricDef;
  value: number | null;
  loading?: boolean;
  /** Ventana global activa (para detectar si el card está fijado en otra). */
  activeWindowHours: number;
  /** Tamaño muestral — si <30 marcamos "muestra baja" como aviso estadístico. */
  sampleSize?: number | null;
}) {
  const ck  = getColor(value, def);
  const col = COLOR[ck];
  const display = fmtValue(value, def);
  const windowMismatch =
    def.fixedWindowHours !== undefined &&
    def.fixedWindowHours !== activeWindowHours;

  const pct = useMemo(() => {
    if (value === null) return 0;
    if (def.lowerIsBetter) return Math.min(100, (value / Math.max(def.yellow, 1)) * 100);
    return Math.min(100, value);
  }, [value, def]);

  const isTime = def.type === "time";

  return (
    <div className={cn(
      "relative flex flex-col rounded-xl border bg-card/80 transition-colors",
      col.border, ck !== "none" ? col.bg : "",
    )}>
      {/* Top bar: priority + NIST ref (con badge de ventana fija si aplica) */}
      <div className="flex items-center justify-between px-4 pt-3 pb-0 gap-1">
        <span className={cn(
          "rounded border px-1.5 py-0 text-[9px] font-semibold tracking-wider uppercase",
          PRIORITY_CLS[def.priority],
        )}>
          {def.priority}
        </span>
        <div className="flex items-center gap-1">
          {windowMismatch && (
            <span
              title={`Esta métrica usa ventana fija de ${fmtWindowLabel(def.fixedWindowHours!)} por significancia estadística — no responde al selector global.`}
              className="rounded border border-border/50 bg-muted/30 px-1 py-0 text-[9px] font-mono text-muted-foreground/80"
            >
              {fmtWindowLabel(def.fixedWindowHours!)} fijo
            </span>
          )}
          <span className="text-[9px] text-muted-foreground/70 font-mono">{def.nistRef}</span>
        </div>
      </div>

      {/* Abbr + name */}
      <div className="px-4 pt-2">
        <div className="flex items-center gap-1.5">
          <span className="text-base font-black tracking-tight leading-none">{def.abbr}</span>
          <TrendIcon def={def} colorKey={ck} />
        </div>
        <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">{def.name}</p>
      </div>

      {/* Value visualization */}
      {isTime ? (
        <div className="relative px-2 -mb-1">
          <GaugeArc pct={pct} colorKey={ck} />
          <div className="absolute inset-0 flex items-center justify-center pb-2">
            {loading ? (
              <Skeleton className="h-7 w-14" />
            ) : (
              <span className={cn("text-xl font-bold tabular-nums", col.text)}>
                {display}
              </span>
            )}
          </div>
        </div>
      ) : (
        <div className="px-4 py-3 space-y-2">
          {loading ? (
            <Skeleton className="h-8 w-full" />
          ) : (
            <>
              <span className={cn("block text-2xl font-bold tabular-nums", col.text)}>
                {display}
              </span>
              <Bar pct={pct} colorKey={ck} />
            </>
          )}
        </div>
      )}

      {/* Target + description */}
      <div className="mt-auto px-4 pb-3 pt-1 space-y-0.5 border-t border-border/30">
        <p className="text-[10px] text-muted-foreground leading-snug">{def.what}</p>
        <p className={cn("text-[10px] font-medium", col.text)}>
          Objetivo: <span className="font-normal text-muted-foreground">{def.targetLabel}</span>
        </p>
        {def.aspiracional && (
          <p className="text-[9px] text-muted-foreground/60 italic">{def.aspiracional}</p>
        )}
        {/* n muestral — sólo relevante en métricas de tiempo (KPIs continuos) */}
        {isTime && sampleSize !== undefined && sampleSize !== null && (
          <p className={cn(
            "text-[9px] font-mono",
            sampleSize < 30
              ? "text-amber-400/80"
              : "text-muted-foreground/60"
          )} title={sampleSize < 30
            ? "Muestra baja (N<30): el promedio es ruidoso. NIST sugiere intervalo de confianza."
            : `Muestra: ${sampleSize} casos en la ventana.`}>
            n = {formatNumber(sampleSize)}{sampleSize < 30 && sampleSize > 0 ? " · muestra baja" : ""}
          </p>
        )}
        {value === null && !loading && (
          <p className="text-[9px] italic text-muted-foreground/50">Pendiente integración</p>
        )}
      </div>
    </div>
  );
}

interface VolumeRow { source: string; n: number }

// ── Componente principal ──────────────────────────────────────────────────────

export function SocKpiPanel({ windowHours = 24 }: { windowHours?: number }) {
  const [manualRefreshing, setManualRefreshing] = useState(false);

  // ── PG KPIs (fast path) ────────────────────────────────────────────────────
  // Alineado con el selector de tiempo global. windowHours se transmite al
  // backend para que la función soc_kpis_window(p_hours) aplique la misma
  // ventana operativa que el usuario ve. queryKey incluye windowHours para
  // invalidar caché al cambiar el filtro.
  const pgKpis = useQuery<DashboardKpis>({
    queryKey: ["nist-kpis-pg", windowHours],
    queryFn: async () => {
      const { data } = await api.get<DashboardKpis>("/api/cases/kpis", {
        params: { hours: windowHours },
      });
      return data;
    },
    staleTime: 30_000,
    refetchInterval: 30_000,
  });

  async function forceRefresh() {
    if (manualRefreshing) return;
    setManualRefreshing(true);
    try {
      await pgKpis.refetch();
    } finally {
      setManualRefreshing(false);
    }
  }

  // ── Volumen por fuente — derivado de coverageBySource (PG soc_kpis_window) ──
  // Cambio (vs F3 inicial): originalmente intentamos contar eventos crudos via
  // Trino, pero los scans full-table de wazuh+syslog+fortigate timeout-eaban
  // (HIVE_UNKNOWN_ERROR). Mostramos casos-por-fuente desde PG: más rápido y
  // operacionalmente más útil ("cuántos casos genera cada sensor"), no
  // "cuántos eventos crudos llegan".
  const volumeBySource = useMemo((): VolumeRow[] => {
    const cov = pgKpis.data?.coverageBySource;
    if (!cov?.length) return [];
    return cov
      .map((r) => ({ source: r.sourceLog, n: r.total }))
      .filter((r) => r.source && r.n > 0)
      .sort((a, b) => b.n - a.n);
  }, [pgKpis.data?.coverageBySource]);

  const k = pgKpis.data;
  const pgLoading = pgKpis.isLoading;

  // ── Mapa de valores → id de métrica ───────────────────────────────────────
  const values: Record<string, number | null> = {
    mttd:           k?.mttdMin           ?? null,
    mttr:           k?.mttrMin           ?? null,
    mttc:           k?.mttcMin           ?? null,
    mtta:           k?.mttaMin ?? k?.criticalAvgAckMin ?? null,
    fpRate:         k?.fpRate            ?? null,
    mitreCov:       k?.mitreCoveragePct  ?? null,
    autoDedup:      k?.autoDeduPct       ?? null,
    l1l2Esc:        k?.l1L2EscMin        ?? null,
    wazuhFallback:  k?.wazuhFallbackPct  ?? null,
    postmortem:     k?.postmortemRate    ?? null,
    slaCritical:    k?.slaCriticalPct    ?? null,
    escalationRate: k?.escalationRate    ?? null,
  };

  const isLoadingAll = pgLoading || manualRefreshing;

  // ── Resumen de estado global ───────────────────────────────────────────────
  const summary = useMemo(() => {
    const withData = METRICS.filter(m => values[m.id] !== null);
    const greens  = withData.filter(m => getColor(values[m.id], m) === "green").length;
    const reds    = withData.filter(m => getColor(values[m.id], m) === "red").length;
    return { total: withData.length, greens, reds };
  }, [values]);

  return (
    <section className="space-y-5">
      {/* ── Header ── */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight">
              KPIs Operacionales SOC
            </h2>
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-normal">
              NIST SP 800-61 Rev. 3 + CSF 2.0
            </Badge>
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-normal font-mono">
              ventana {fmtWindowLabel(windowHours)}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground flex flex-wrap items-center gap-3">
            {["CRÍTICA","ALTA","MEDIA"].map((p) => (
              <span key={p} className="inline-flex items-center gap-1">
                <span className={cn("inline-block h-1.5 w-1.5 rounded-full",
                  p === "CRÍTICA" ? "bg-red-500"
                  : p === "ALTA"  ? "bg-amber-400"
                  : "bg-muted-foreground/60"
                )} />
                {p}
              </span>
            ))}
          </p>
        </div>

        {/* Resumen estado + contadores */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Volumen de casos por fuente (derivado de coverageBySource).
              Fuente única PG — sin fallback Trino (cases-based, no event-based). */}
          {volumeBySource.length > 0 && (
            <Badge
              variant="outline"
              className="text-[11px] font-normal gap-1.5 flex-wrap"
              title="Casos creados por sensor dentro de la ventana del selector (no filtra por estado)"
            >
              {volumeBySource.slice(0, 5).map((r, i) => (
                <span key={r.source} className="inline-flex items-center gap-1">
                  {i > 0 && <span className="text-muted-foreground/40">·</span>}
                  <span className="font-mono tabular-nums">{formatNumber(r.n)}</span>
                  <span className="text-muted-foreground/80">{prettySourceLabel(r.source)}</span>
                </span>
              ))}
            </Badge>
          )}
          {k && (
            <>
              <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[11px] font-semibold">
                {summary.greens}/{summary.total} OK
              </Badge>
              {summary.reds > 0 && (
                <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-[11px] font-semibold">
                  {summary.reds} críticos
                </Badge>
              )}
              {/* Contadores de estado: snapshot agregado de los últimos 90d
                  (no respetan la ventana del selector — el SQL los calcula
                  sobre base90 para que el "stock" abierto/cerrado sea
                  estable). El tooltip lo deja explícito. */}
              <Badge variant="outline" className="text-[11px] font-normal gap-1"
                     title="Casos no cerrados creados en los últimos 90 días">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 inline-block" />
                {k.openCases} abiertos · 90d
              </Badge>
              <Badge variant="outline" className="text-[11px] font-normal gap-1"
                     title="Casos cerrados creados en los últimos 90 días — acumulado, no de la ventana">
                <span className="h-1.5 w-1.5 rounded-full bg-zinc-400 inline-block" />
                {k.closedCases} cerrados · 90d
              </Badge>
              <Badge variant="outline" className="text-[11px] font-normal"
                     title="Casos cerrados desde 00:00 de hoy, excluyendo auto-cierres LOW/NEG huérfanos">
                {k.resolvedToday} resueltos hoy
              </Badge>
            </>
          )}
          <Button
            size="sm" variant="outline"
            className="h-7 gap-1 text-[11px]"
            onClick={() => void forceRefresh()}
            disabled={manualRefreshing}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", manualRefreshing && "animate-spin")} />
            {manualRefreshing ? "Actualizando…" : "Actualizar"}
          </Button>
        </div>
      </div>

      {/* ── Fila 1: 4 métricas de tiempo críticas ── */}
      <div>
        <p className="mb-2 text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">
          Tiempos operativos
        </p>
        <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
          {METRICS.slice(0, 4).map((def) => {
            // Sample size por id de métrica (sólo para KPIs de tiempo).
            const n =
              def.id === "mttd" ? k?.nMttd
              : def.id === "mtta" ? k?.nMtta
              : def.id === "mttr" ? k?.nMttr
              : def.id === "mttc" ? k?.nMttc
              : null;
            return (
              <MetricCard
                key={def.id}
                def={def}
                value={values[def.id] ?? null}
                loading={isLoadingAll && values[def.id] === null}
                activeWindowHours={windowHours}
                sampleSize={n}
              />
            );
          })}
        </div>
      </div>

      {/* ── Fila 2: 8 métricas de calidad / cobertura / cumplimiento ── */}
      <div>
        <p className="mb-2 text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">
          Calidad, cobertura y madurez
        </p>
        <div className="grid gap-3 grid-cols-2 lg:grid-cols-4 xl:grid-cols-4">
          {METRICS.slice(4).map((def) => (
            <MetricCard
              key={def.id}
              def={def}
              value={values[def.id] ?? null}
              loading={isLoadingAll && values[def.id] === null}
              activeWindowHours={windowHours}
            />
          ))}
        </div>
      </div>

      {/* ── Desglose de cobertura MITRE por fuente ── */}
      <MitreCoveragePanel
        data={k?.coverageBySource ?? []}
        loading={isLoadingAll && (k?.coverageBySource?.length ?? 0) === 0}
      />

      {/* ── Nota NIST ── */}
      <div className="flex items-start gap-2 rounded-lg border border-border/50 bg-muted/10 px-4 py-2.5 text-[11px] text-muted-foreground">
        <Info className="h-3.5 w-3.5 mt-0.5 shrink-0 text-muted-foreground/60" />
        <span>
          Métricas alineadas con{" "}
          <span className="font-medium text-foreground">NIST SP 800-61 Rev. 3</span> y{" "}
          <span className="font-medium text-foreground">CSF 2.0</span>.
          Ventana operativa: <span className="font-medium text-foreground font-mono">{fmtWindowLabel(windowHours)}</span> (del selector global).{" "}
          <span className="font-medium text-foreground">MITRE</span> y{" "}
          <span className="font-medium text-foreground">Post-Mortem</span> mantienen 30d fijos por significancia estadística.
          DEDUP y WAZUH son aproximaciones desde PG; datos exactos disponibles con integración SOAR.
        </span>
      </div>
    </section>
  );
}
