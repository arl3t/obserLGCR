/**
 * SurfaceGrid — grid 3×2 de superficies monitoreadas con sparklines.
 *
 * Reemplaza la tabla lineal de `DimensionesTable`. Cada card muestra una
 * dimensión con: icono · label/descripción · valor actual · delta vs análisis
 * previo · sparkline 20 análisis · status pip de 5 puntos. Las cards son
 * cliqueables y navegan al tab destino correspondiente.
 *
 * Las sparklines se derivan de `findings_summary` en `useAnalysisHistory(20)`,
 * que es `Record<\`${kind}-${severity}\`, number>` por análisis. Para
 * dimensiones cuyas métricas no están en findings_summary (LEAKS = snapshot
 * Leak Intel Hub local, BOTNETS = heurística sobre tags MISP) la sparkline
 * se omite y el valor se muestra crudo.
 */

import { useMemo } from "react";
import {
  AlertTriangle,
  Eye,
  Globe2,
  KeyRound,
  Network,
  ShieldAlert,
  Skull,
  TrendingUp,
} from "lucide-react";
import {
  useSurveillance,
  type SurveillanceTabId,
} from "@/components/digital-surveillance/SurveillanceProvider";
import { useAnalysisHistory, type AnalysisRow } from "@/hooks/useSurveillanceWorkspace";
import type {
  AnalystFindingKind,
  SurveillanceMispHit,
} from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

type Status = "ok" | "warning" | "critical" | "pending";

type Dimension = {
  key: string;
  label: string;
  description: string;
  value: number | string;
  status: Status;
  icon: React.ComponentType<{ className?: string }>;
  tabValue?: SurveillanceTabId;
  pendingNote?: string;
  /** Lista de claves de findings_summary que sumadas dan el valor histórico
   *  por análisis. `null` cuando la dimensión no tiene serie temporal en
   *  el log de análisis. */
  historyKinds?: AnalystFindingKind[] | null;
};

const STATUS_PIP_COLOR: Record<Status, string> = {
  ok:       "bg-emerald-400 shadow-emerald-400/40",
  warning:  "bg-amber-400 shadow-amber-400/40",
  critical: "bg-red-400 shadow-red-400/40",
  pending:  "bg-muted-foreground/40",
};

const STATUS_LABEL: Record<Status, string> = {
  ok:       "Saludable",
  warning:  "Atención",
  critical: "Crítico",
  pending:  "Sin datos",
};

const STATUS_TEXT: Record<Status, string> = {
  ok:       "text-emerald-500",
  warning:  "text-amber-500",
  critical: "text-red-500",
  pending:  "text-muted-foreground",
};

const STATUS_BORDER: Record<Status, string> = {
  ok:       "border-l-emerald-500/60",
  warning:  "border-l-amber-500/70",
  critical: "border-l-red-500/70",
  pending:  "border-l-muted-foreground/30",
};

const SPARK_STROKE: Record<Status, string> = {
  ok:       "stroke-emerald-500",
  warning:  "stroke-amber-500",
  critical: "stroke-red-500",
  pending:  "stroke-muted-foreground/40",
};

/** Cantidad de pips llenos según status (de 5 totales). */
const STATUS_PIPS_FILLED: Record<Status, number> = {
  ok: 1, warning: 3, critical: 5, pending: 0,
};

/** Heurística: cuenta hits MISP cuya category o tags sugieren botnet. */
function botnetHitsFromMisp(hits: SurveillanceMispHit[] | undefined): number {
  if (!hits) return 0;
  return hits.filter((h) => {
    const cat = (h.category ?? "").toLowerCase();
    const tags = (h.tags ?? []).map((t) => t.toLowerCase());
    return cat.includes("botnet") || tags.some((t) => t.includes("botnet"));
  }).length;
}

/** Suma total para un set de kinds en `findings_summary` de un análisis. */
function sumKinds(row: AnalysisRow, kinds: AnalystFindingKind[]): number {
  let total = 0;
  for (const [k, v] of Object.entries(row.findings_summary ?? {})) {
    const kind = k.split("-").slice(0, -1).join("-") as AnalystFindingKind;
    if (kinds.includes(kind)) total += v;
  }
  return total;
}

/** Clasifica un conteo a status según thresholds, considerando si la fuente
 *  está disponible. */
function pickStatus(
  count: number,
  opts: { warn: number; crit: number; hasData: boolean },
): Status {
  if (!opts.hasData) return "pending";
  if (count >= opts.crit) return "critical";
  if (count >= opts.warn) return "warning";
  return "ok";
}

export function SurfaceGrid() {
  const {
    domain,
    data,
    snapshot,
    hasCoverage,
    emailCount,
    brandThreats,
    setActiveTab,
  } = useSurveillance();

  const historyQ = useAnalysisHistory(domain, 20);
  const sortedHistory = useMemo<AnalysisRow[]>(
    () => (historyQ.data ?? []).slice().sort(
      (a, b) => +new Date(a.queried_at) - +new Date(b.queried_at),
    ),
    [historyQ.data],
  );

  if (!data) return null;

  const similarCount =
    brandThreats.byKind["ct-impersonation"] + brandThreats.byKind["typosquatting"];
  const similarHasCritical = brandThreats.threats.some(
    (t) =>
      (t.kind === "ct-impersonation" || t.kind === "typosquatting") &&
      t.severity === "critical",
  );
  const mispBotnet = botnetHitsFromMisp(data.misp.hits);

  const dimensions: Dimension[] = [
    {
      key: "logins",
      label: "LOGINS",
      description: "Credenciales corporativas en dumps",
      value: hasCoverage ? emailCount : 0,
      status: pickStatus(emailCount, { warn: 1, crit: 50, hasData: hasCoverage }),
      icon: KeyRound,
      tabValue: "credenciales",
      historyKinds: ["credential-leak"],
    },
    {
      key: "similar",
      label: "SIMILAR DOMAINS",
      description: "Look-alike + typosquatting",
      value: similarCount,
      status: similarHasCritical
        ? "critical"
        : similarCount > 0
          ? "warning"
          : "ok",
      icon: Globe2,
      tabValue: "marca",
      pendingNote: similarCount === 0 ? "endpoints Fase 3 §9.7 pendientes" : undefined,
      historyKinds: ["brand-threat"],
    },
    {
      key: "leaks",
      label: "LEAKS",
      description: "Filtraciones (12 meses)",
      value: snapshot?.leaksLast12Months ?? (hasCoverage ? 0 : "—"),
      status: pickStatus(snapshot?.leaksLast12Months ?? 0, {
        warn: 1, crit: 5, hasData: hasCoverage && snapshot != null,
      }),
      icon: AlertTriangle,
      tabValue: "credenciales",
      // No hay serie temporal — el snapshot es local.
      historyKinds: null,
    },
    {
      key: "infra",
      label: "INFRA",
      description: "Hosts expuestos en Shodan",
      value: data.shodan.configured ? (data.shodan.total ?? 0) : "—",
      status: pickStatus(data.shodan.total ?? 0, {
        warn: 1, crit: 5, hasData: data.shodan.configured,
      }),
      icon: Network,
      tabValue: "analisis",
      historyKinds: ["shodan-exposure"],
    },
    {
      key: "botnets",
      label: "BOTNETS",
      description: "Indicadores C2 / botnet",
      value: data.misp.configured ? mispBotnet : "—",
      status: pickStatus(mispBotnet, {
        warn: 1, crit: 3, hasData: data.misp.configured,
      }),
      icon: Skull,
      tabValue: "darkweb",
      // Se deriva por heurística de tags — no tenemos serie historizada.
      historyKinds: null,
    },
    {
      key: "misp",
      label: "MISP",
      description: "Atributos en threat intel",
      value: data.misp.configured ? (data.misp.count ?? 0) : "—",
      status: pickStatus(data.misp.count ?? 0, {
        warn: 1, crit: 5, hasData: data.misp.configured,
      }),
      icon: ShieldAlert,
      tabValue: "darkweb",
      historyKinds: ["misp-ioc"],
    },
  ];

  return (
    <section className="rounded-2xl border border-border bg-card shadow-sm">
      <header className="flex items-center justify-between border-b border-border/50 px-6 py-4">
        <div className="flex items-center gap-2">
          <Eye className="h-4 w-4 text-emerald-500" aria-hidden />
          <h2 className="text-sm font-semibold uppercase tracking-widest text-foreground">
            Superficies Monitoreadas
          </h2>
        </div>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
          6 dimensiones · click para detalle
        </span>
      </header>

      <ul className="grid gap-px bg-border/40 sm:grid-cols-2 lg:grid-cols-3">
        {dimensions.map((d) => (
          <SurfaceCard
            key={d.key}
            dimension={d}
            history={sortedHistory}
            onNavigate={setActiveTab}
          />
        ))}
      </ul>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SurfaceCard — card individual de una dimensión
// ─────────────────────────────────────────────────────────────────────────────

function SurfaceCard({
  dimension,
  history,
  onNavigate,
}: {
  dimension: Dimension;
  history: AnalysisRow[];
  onNavigate: (tab: SurveillanceTabId) => void;
}) {
  const { icon: Icon, status, label, description, value, tabValue, pendingNote, historyKinds } = dimension;

  // Serie temporal de esta dimensión (sólo si historyKinds != null).
  const series = useMemo<number[]>(() => {
    if (!historyKinds || history.length === 0) return [];
    return history.map((row) => sumKinds(row, historyKinds));
  }, [history, historyKinds]);

  // Delta vs análisis previo — usa series si está disponible, si no -> null.
  const delta =
    series.length >= 2
      ? series[series.length - 1] - series[series.length - 2]
      : null;

  const clickable = !!tabValue && status !== "pending";
  const Component: "button" | "div" = clickable ? "button" : "div";

  return (
    <li className="bg-card">
      <Component
        type={clickable ? "button" : undefined}
        onClick={clickable ? () => onNavigate(tabValue!) : undefined}
        className={cn(
          "group flex w-full flex-col gap-3 border-l-4 px-5 py-4 text-left transition-colors",
          STATUS_BORDER[status],
          clickable && "hover:bg-muted/40",
          !clickable && "cursor-default",
        )}
        title={clickable ? `Ir al tab ${tabValue}` : undefined}
      >
        {/* ── Cabecera card: icono + label + valor + delta ──────────────── */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted ring-1 ring-inset ring-border">
              <Icon className="h-4 w-4 text-emerald-500" />
            </div>
            <div className="min-w-0">
              <p className="font-mono text-[11px] font-bold uppercase tracking-widest text-foreground">
                {label}
              </p>
              <p className="truncate text-[10px] text-muted-foreground">
                {description}
              </p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-0.5">
            <span className="font-mono text-2xl font-bold tabular-nums leading-none text-foreground">
              {value}
            </span>
            {delta !== null && (
              <DeltaInline value={delta} />
            )}
          </div>
        </div>

        {/* ── Sparkline + status row ────────────────────────────────────── */}
        <div className="flex items-center gap-3">
          <div className="h-7 flex-1">
            {series.length >= 2 ? (
              <Sparkline values={series} status={status} />
            ) : (
              <div className="flex h-full items-center text-[10px] text-muted-foreground/50">
                {historyKinds === null
                  ? "sin serie histórica"
                  : "datos insuficientes"}
              </div>
            )}
          </div>
          <StatusPip status={status} />
        </div>

        {pendingNote && (
          <p className="text-[10px] italic text-muted-foreground/70">
            {pendingNote}
          </p>
        )}
      </Component>
    </li>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Subcomponentes de visualización
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sparkline — line chart minimalista sobre `values[]`. Renderea SVG inline
 * con normalización Y al rango [min..max] de la serie. Sin recharts (overkill
 * para 7×120px).
 */
function Sparkline({ values, status }: { values: number[]; status: Status }) {
  const w = 100; // viewBox width
  const h = 24;  // viewBox height
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const stepX = values.length > 1 ? w / (values.length - 1) : 0;

  const points = values
    .map((v, i) => {
      const x = i * stepX;
      const y = h - ((v - min) / range) * h;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  const lastIdx = values.length - 1;
  const lastX = lastIdx * stepX;
  const lastY = h - ((values[lastIdx] - min) / range) * h;

  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      className="h-full w-full"
      aria-hidden
    >
      <polyline
        points={points}
        fill="none"
        strokeWidth="1.5"
        className={SPARK_STROKE[status]}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx={lastX} cy={lastY} r="1.6" className={cn("fill-current", STATUS_TEXT[status])} />
    </svg>
  );
}

/**
 * StatusPip — 5 puntos horizontales coloreados según severidad.
 * Indicador visual fuerte y consistente con el preview que aprobó el usuario.
 */
function StatusPip({ status }: { status: Status }) {
  const filled = STATUS_PIPS_FILLED[status];
  return (
    <div
      className="flex items-center gap-1"
      title={STATUS_LABEL[status]}
      role="img"
      aria-label={`Estado: ${STATUS_LABEL[status]}`}
    >
      {Array.from({ length: 5 }).map((_, i) => (
        <span
          key={i}
          className={cn(
            "h-1.5 w-1.5 rounded-full transition-colors",
            i < filled
              ? cn("shadow-md", STATUS_PIP_COLOR[status])
              : "bg-muted-foreground/15",
          )}
        />
      ))}
    </div>
  );
}

function DeltaInline({ value }: { value: number }) {
  const dir = value === 0 ? "flat" : value > 0 ? "up" : "down";
  // Δ positivo = peor (rojo) por convención SOC; flat = sin cambio.
  const color =
    dir === "flat" ? "text-muted-foreground" :
    dir === "up"   ? "text-red-600 dark:text-red-400" :
                     "text-emerald-600 dark:text-emerald-400";
  const sign = value > 0 ? "▲+" : value < 0 ? "▼" : "—";
  return (
    <span className={cn("flex items-center gap-0.5 font-mono text-[10px] tabular-nums", color)}>
      <TrendingUp className="hidden h-2.5 w-2.5" aria-hidden />
      {dir === "flat" ? "—" : `${sign}${Math.abs(value)}`}
    </span>
  );
}
