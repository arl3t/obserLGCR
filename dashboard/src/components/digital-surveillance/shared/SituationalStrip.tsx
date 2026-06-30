import {
  AlertTriangle,
  Eye,
  KeyRound,
  Megaphone,
  Network,
  Newspaper,
  Radar,
  type LucideIcon,
} from "lucide-react";
import type { LeakIntelHubSnapshot } from "@/store/leak-intel-hub-store";
import { useSurveillanceOptional } from "@/components/digital-surveillance/SurveillanceProvider";
import {
  BRAND24_MIN_CLASSIFIED,
  BRAND24_NEG_RATIO_CRITICAL,
  BRAND24_NEG_RATIO_WARNING,
  BRAND24_VOL_DELTA_WARN_PERCENT,
  CREDS_MASS_LEAK_THRESHOLD,
  HIGH_RISK_PORTS,
  MISP_HIGH_THREAT_LEVEL,
  MISP_MEDIUM_THREAT_LEVEL,
  RSS_COVERAGE_SPIKE,
} from "@/components/digital-surveillance/risk-engine/thresholds";
import { Badge } from "@/components/ui/badge";
import { riskLabelEs } from "@/lib/digital-surveillance-api";
import { formatRelativeTimeEs } from "@/lib/format";
import type {
  RiskBand,
  SurveillanceBrand24Result,
  SurveillanceBrandThreats,
  SurveillanceDomainResult,
  SurveillanceMispHit,
  SurveillanceRssResult,
  SurveillanceShodanMatch,
} from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Tipos / props
// ─────────────────────────────────────────────────────────────────────────────

type ColumnState = "ok" | "warning" | "critical" | "inactive";

type Column = {
  key: "infra" | "darkweb" | "marca" | "noticias" | "credenciales" | "impersonation";
  /** Tab al que se navega al hacer click. Debe coincidir con `SurveillanceTabId`. */
  tabValue: string;
  icon: LucideIcon;
  label: string;
  state: ColumnState;
  primary: string;
  fact: string;
  detail: string;
};

/**
 * Props del strip — TODAS opcionales. Modo de uso:
 *
 *   1. Bajo `<SurveillanceProvider>`: `<SituationalStrip />` (lee del context).
 *   2. Standalone / monolito legacy: pasar todos los datos por prop.
 *
 * Si se pasan props Y hay provider, las props ganan (override). Si no hay ni
 * uno ni otro, el strip muestra un placeholder vacío.
 */
export type SituationalStripProps = {
  data?: SurveillanceDomainResult;
  brand24?: SurveillanceBrand24Result | null;
  rss?: SurveillanceRssResult | null;
  snapshot?: LeakIntelHubSnapshot | null;
  hasCoverage?: boolean;
  emailCount?: number;
  /** DRP — Fase 3 §9. La columna "Impersonation" depende de esto. Cuando no
   *  está disponible (modo legacy del monolito), la columna queda inactiva. */
  brandThreats?: SurveillanceBrandThreats;
  /** Override del callback de click. Por defecto usa `setActiveTab` del provider. */
  onColumnClick?: (tabValue: string) => void;
  className?: string;
};

// ─────────────────────────────────────────────────────────────────────────────
// Estilos por estado / banda
// ─────────────────────────────────────────────────────────────────────────────

const STATE_DOT: Record<ColumnState, string> = {
  critical: "bg-red-500",
  warning:  "bg-amber-500",
  ok:       "bg-emerald-500",
  inactive: "bg-muted-foreground/30",
};

const STATE_BORDER: Record<ColumnState, string> = {
  critical: "border-l-red-500/70",
  warning:  "border-l-amber-500/70",
  ok:       "border-l-emerald-500/60",
  inactive: "border-l-muted-foreground/20",
};

const STATE_TEXT: Record<ColumnState, string> = {
  critical: "text-red-600 dark:text-red-400",
  warning:  "text-amber-700 dark:text-amber-400",
  ok:       "text-emerald-700 dark:text-emerald-400",
  inactive: "text-muted-foreground",
};

const RISK_BG: Record<RiskBand, string> = {
  high:   "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/30",
  medium: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30",
  low:    "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
};

const RISK_TEXT: Record<RiskBand, string> = {
  high:   "text-red-600 dark:text-red-400",
  medium: "text-amber-600 dark:text-amber-400",
  low:    "text-emerald-600 dark:text-emerald-400",
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de formato
// ─────────────────────────────────────────────────────────────────────────────

function formatCompact(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return String(Math.round(n));
}

function portCategoryLabel(port: number): string | null {
  if ([3389, 5900, 22].includes(port)) return port === 22 ? "SSH" : port === 3389 ? "RDP" : "VNC";
  if ([445, 139, 2049, 21].includes(port)) return port === 21 ? "FTP" : "SMB";
  if ([3306, 5432, 27017, 6379, 9200].includes(port)) return "DB";
  if ([23, 110, 143].includes(port)) return port === 23 ? "Telnet" : "legacy";
  return null;
}

function isCriticalPort(port: number | null): boolean {
  if (!port) return false;
  return HIGH_RISK_PORTS.has(port);
}

function newestTimestamp(items: { timestamp: string | null }[]): string | null {
  let bestIso: string | null = null;
  let best = -Infinity;
  for (const it of items) {
    if (!it.timestamp) continue;
    const t = +new Date(it.timestamp);
    if (Number.isFinite(t) && t > best) {
      best = t;
      bestIso = it.timestamp;
    }
  }
  return bestIso;
}

// ─────────────────────────────────────────────────────────────────────────────
// Builders por columna
// ─────────────────────────────────────────────────────────────────────────────

function buildInfraColumn(data: SurveillanceDomainResult): Column {
  const { shodan } = data;
  const base = { key: "infra" as const, tabValue: "analisis", icon: Network, label: "Infraestructura" };

  if (!shodan.configured) {
    return { ...base, state: "inactive", primary: "—", fact: "Shodan no configurado", detail: "API key faltante" };
  }
  if (shodan.error) {
    return { ...base, state: "warning", primary: "—", fact: "error consultando Shodan", detail: shodan.error.slice(0, 40) };
  }
  const matches: SurveillanceShodanMatch[] = shodan.matches ?? [];
  const total = shodan.total ?? matches.length;
  const critical = matches.filter((m) => isCriticalPort(m.port));
  const cats = Array.from(
    new Set(critical.map((m) => portCategoryLabel(m.port as number)).filter(Boolean) as string[]),
  ).slice(0, 2);

  if (total === 0) {
    return { ...base, state: "ok", primary: "0", fact: "sin hosts visibles", detail: "perímetro limpio en Shodan" };
  }
  if (critical.length > 0) {
    return {
      ...base,
      state: "critical",
      primary: `${total} host${total === 1 ? "" : "s"}`,
      fact: `${critical.length} ⚠ crítico${critical.length === 1 ? "" : "s"}`,
      detail: cats.length ? cats.join("·") : "puertos admin expuestos",
    };
  }
  return {
    ...base,
    state: "warning",
    primary: `${total} host${total === 1 ? "" : "s"}`,
    fact: "puertos estándar",
    detail: "sin servicios admin",
  };
}

function buildDarkWebColumn(data: SurveillanceDomainResult): Column {
  const { misp } = data;
  const base = { key: "darkweb" as const, tabValue: "darkweb", icon: Eye, label: "Dark web / IOCs" };

  if (!misp.configured) {
    return { ...base, state: "inactive", primary: "—", fact: "MISP no configurado", detail: "BASE_URL+API_KEY" };
  }
  if (misp.error) {
    return { ...base, state: "warning", primary: "—", fact: "error consultando MISP", detail: misp.error.slice(0, 40) };
  }
  const hits: SurveillanceMispHit[] = misp.hits ?? [];
  const count = misp.count ?? hits.length;
  if (count === 0) {
    return { ...base, state: "ok", primary: "0", fact: "sin IOCs en 90d", detail: "MISP limpio" };
  }

  const high = hits.filter((h) => h.threat_level === MISP_HIGH_THREAT_LEVEL).length;
  const medium = hits.filter((h) => h.threat_level === MISP_MEDIUM_THREAT_LEVEL).length;
  const newest = newestTimestamp(hits);

  const breakdown =
    high && medium ? `${high} alto · ${medium} medio` :
    high           ? `${high} alto` :
    medium         ? `${medium} medio` :
                     `${count} sin clasif.`;

  return {
    ...base,
    state: "critical",
    primary: `${count} IOC${count === 1 ? "" : "s"}`,
    fact: breakdown,
    detail: newest ? `últ. ${formatRelativeTimeEs(newest)}` : "sin fecha",
  };
}

function buildMarcaColumn(
  data: SurveillanceDomainResult,
  b24: SurveillanceBrand24Result | null | undefined,
): Column {
  const base = { key: "marca" as const, tabValue: "marca", icon: Megaphone, label: "Marca" };

  if (!data.brand24.configured || !b24 || !b24.summary) {
    return { ...base, state: "inactive", primary: "—", fact: "sin proyecto Brand24", detail: "importar PDF o configurar" };
  }
  const s = b24.summary;
  const total = s.positiveCount + s.negativeCount;
  const negRatio = total > 0 ? s.negativeCount / total : 0;
  const negPct = Math.round(negRatio * 100);
  const reach = s.socialReach + s.nonSocialReach;
  const volSpike = Math.abs(s.volumeDeltaPercent) >= BRAND24_VOL_DELTA_WARN_PERCENT;

  let state: ColumnState = "ok";
  let fact = `${formatCompact(s.volumeMentions)} mencs`;

  if (total >= BRAND24_MIN_CLASSIFIED && negRatio >= BRAND24_NEG_RATIO_CRITICAL) {
    state = "critical";
    fact = `${negPct}% neg`;
  } else if (volSpike) {
    state = "warning";
    fact = `spike ${s.volumeDeltaPercent > 0 ? "+" : ""}${s.volumeDeltaPercent}%`;
  } else if (total >= BRAND24_MIN_CLASSIFIED && negRatio >= BRAND24_NEG_RATIO_WARNING) {
    state = "warning";
    fact = `${negPct}% neg`;
  }

  return {
    ...base,
    state,
    primary: formatCompact(s.volumeMentions),
    fact,
    detail: `reach ${formatCompact(reach)}`,
  };
}

function buildNoticiasColumn(rss: SurveillanceRssResult | null | undefined): Column {
  const base = { key: "noticias" as const, tabValue: "noticias", icon: Newspaper, label: "Noticias" };

  if (!rss) {
    return { ...base, state: "inactive", primary: "—", fact: "sin datos RSS", detail: "" };
  }
  const direct = rss.items ?? [];
  const customMatched = (rss.custom ?? []).filter((i) => i.matched);
  const all = [...direct, ...customMatched];
  const count = all.length;

  if (count === 0) {
    return { ...base, state: "ok", primary: "0", fact: "sin menciones", detail: "feeds limpios" };
  }
  const newest = newestTimestamp(all.map((i) => ({ timestamp: i.publishedAt })));
  const state: ColumnState = count >= RSS_COVERAGE_SPIKE ? "warning" : "ok";

  return {
    ...base,
    state,
    primary: `${count} menc${count === 1 ? "." : "s."}`,
    fact: count >= RSS_COVERAGE_SPIKE ? "cobertura alta" : "cobertura activa",
    detail: newest ? `últ. ${formatRelativeTimeEs(newest)}` : "sin fecha",
  };
}

function buildImpersonationColumn(
  brandThreats: SurveillanceBrandThreats | undefined,
): Column {
  const base = {
    key: "impersonation" as const,
    tabValue: "marca",   // El feed DRP vive dentro del tab Marca (§9.5)
    icon: Radar,
    label: "Impersonation",
  };
  if (!brandThreats) {
    return { ...base, state: "inactive", primary: "—", fact: "Fase 3 sin proveedor", detail: "CT/typo no configurado" };
  }
  const total = brandThreats.threats.length;
  if (total === 0) {
    return { ...base, state: "ok", primary: "0", fact: "sin amenazas", detail: "CT + typo + phishing limpios" };
  }
  if (brandThreats.hasActiveCampaign) {
    return {
      ...base,
      state: "critical",
      primary: String(total),
      fact: `${brandThreats.correlations.length} campaña(s) activa(s)`,
      detail: `Correlación cross-source — abrir ${brandThreats.correlations[0]?.title ?? "feed Marca"}`,
    };
  }
  // Hay threats pero sin correlaciones críticas — escalar por kind/severity dominante.
  const hasCritical = brandThreats.threats.some((t) => t.severity === "critical");
  const hasHigh     = brandThreats.threats.some((t) => t.severity === "high");
  if (hasCritical) {
    return {
      ...base,
      state: "critical",
      primary: String(total),
      fact: `${total} amenaza(s) crítica(s)`,
      detail: "ver tab Marca para detalle",
    };
  }
  if (hasHigh) {
    return {
      ...base,
      state: "warning",
      primary: String(total),
      fact: `${total} amenaza(s) alta(s)`,
      detail: "ver tab Marca para detalle",
    };
  }
  return {
    ...base,
    state: "warning",
    primary: String(total),
    fact: `${total} indicador(es)`,
    detail: "ver tab Marca",
  };
}

function buildCredencialesColumn(
  hasCoverage: boolean,
  emailCount: number,
  snapshot: LeakIntelHubSnapshot | null | undefined,
): Column {
  const base = { key: "credenciales" as const, tabValue: "credenciales", icon: KeyRound, label: "Credenciales" };

  if (!hasCoverage || !snapshot) {
    return { ...base, state: "inactive", primary: "—", fact: "sin dataset cargado", detail: "tab Dark web → cargar" };
  }
  const weakPct = snapshot.weakPwdRate ? `${Math.round(snapshot.weakPwdRate * 100)}% débiles` : null;
  const updatedRel = formatRelativeTimeEs(snapshot.updatedAt);

  if (emailCount === 0) {
    return { ...base, state: "ok", primary: "0", fact: "sin correos del dominio", detail: updatedRel };
  }
  const state: ColumnState = emailCount >= CREDS_MASS_LEAK_THRESHOLD ? "critical" : "warning";

  return {
    ...base,
    state,
    primary: formatCompact(emailCount),
    fact: state === "critical" ? "fuga masiva" : "fuga detectada",
    detail: weakPct ?? updatedRel,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Componente
// ─────────────────────────────────────────────────────────────────────────────

export function SituationalStrip(props: SituationalStripProps) {
  // Resolver la fuente de datos: props (override) → context (default).
  const ctx = useSurveillanceOptional();
  const data        = props.data         ?? ctx?.data;
  const brand24     = props.brand24      ?? ctx?.brand24;
  const rss         = props.rss          ?? ctx?.rss;
  const snapshot    = props.snapshot     ?? ctx?.snapshot;
  const hasCoverage = props.hasCoverage  ?? ctx?.hasCoverage  ?? false;
  const emailCount  = props.emailCount   ?? ctx?.emailCount   ?? 0;
  const brandThreats = props.brandThreats ?? ctx?.brandThreats;
  // El context tipa setActiveTab con `SurveillanceTabId`, pero el strip
  // pasa `tabValue: string` por su propio contrato — los valores son los
  // mismos pero TS no lo sabe. Cast en el borde.
  const ctxSetTab = ctx?.setActiveTab as ((tab: string) => void) | undefined;
  const onColumnClick = props.onColumnClick ?? ctxSetTab;

  // Sin data principal todavía → placeholder mínimo (no rompe el layout sticky).
  if (!data) {
    return (
      <div
        className={cn(
          "rounded-xl border border-dashed border-border/50 bg-background/95 p-3 text-xs text-muted-foreground shadow-sm backdrop-blur",
          props.className,
        )}
        aria-label="Postura general (sin datos)"
      >
        Esperando datos del dominio…
      </div>
    );
  }

  const columns: Column[] = [
    buildInfraColumn(data),
    buildDarkWebColumn(data),
    buildMarcaColumn(data, brand24),
    buildImpersonationColumn(brandThreats),
    buildNoticiasColumn(rss),
    buildCredencialesColumn(hasCoverage, emailCount, snapshot),
  ];

  const criticalCount = columns.filter((c) => c.state === "critical").length;
  const warningCount  = columns.filter((c) => c.state === "warning").length;

  // Clamp defensivo del score (§7.1.4): el backend nunca debería emitir > 100,
  // pero si lo hace lo recortamos para no pintar "105/100" en el badge.
  const clampedScore = Math.max(0, Math.min(100, data.risk.score));

  return (
    <div
      className={cn(
        "rounded-xl border border-border/70 bg-background/95 p-3 shadow-sm backdrop-blur",
        "supports-[backdrop-filter]:bg-background/80",
        props.className,
      )}
      aria-label="Postura general de vigilancia"
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-stretch">
        {/* ── Izquierda: badge de score + dominio ──────────────────────── */}
        <div className="flex shrink-0 items-center gap-3 lg:border-r lg:border-border/60 lg:pr-4">
          <div
            className={cn(
              "flex h-14 w-14 shrink-0 flex-col items-center justify-center rounded-xl border tabular-nums",
              RISK_BG[data.risk.band],
            )}
          >
            <span className="text-lg font-bold leading-none">{clampedScore}</span>
            <span className="mt-0.5 text-[9px] font-semibold uppercase tracking-wider opacity-80">
              /100
            </span>
          </div>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Postura general
            </p>
            <p className="truncate font-mono text-sm font-semibold">{data.domain}</p>
            <p className="mt-0.5 text-[11px] text-muted-foreground">
              Riesgo{" "}
              <span className={cn("font-semibold", RISK_TEXT[data.risk.band])}>
                {riskLabelEs(data.risk.band)}
              </span>
              {data.risk.factors.length > 0 && (
                <> · {data.risk.factors.length} factor{data.risk.factors.length === 1 ? "" : "es"}</>
              )}
            </p>
          </div>
        </div>

        {/* ── Centro: 6 columnas clickeables ──────────────────────────── */}
        <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {columns.map((c) => {
            const Icon = c.icon;
            const clickable = Boolean(onColumnClick) && c.state !== "inactive";
            const Tag = clickable ? "button" : "div";
            return (
              <Tag
                key={c.key}
                type={clickable ? "button" : undefined}
                onClick={clickable ? () => onColumnClick?.(c.tabValue) : undefined}
                className={cn(
                  "flex flex-col gap-1 rounded-lg border-l-2 bg-muted/30 px-3 py-2 text-left transition-colors",
                  STATE_BORDER[c.state],
                  clickable
                    ? "cursor-pointer hover:bg-muted/60 focus-visible:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                    : "cursor-default",
                )}
                aria-label={clickable ? `Abrir tab ${c.label}` : c.label}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    <Icon className="h-3 w-3" aria-hidden />
                    {c.label}
                  </span>
                  <span
                    className={cn("h-1.5 w-1.5 shrink-0 rounded-full", STATE_DOT[c.state])}
                    aria-hidden
                  />
                </div>
                <span className="truncate text-sm font-bold tabular-nums" title={c.primary}>
                  {c.primary}
                </span>
                <span className={cn("truncate text-[11px] font-medium", STATE_TEXT[c.state])} title={c.fact}>
                  {c.fact}
                </span>
                {c.detail && (
                  <span className="truncate text-[10px] text-muted-foreground/80" title={c.detail}>
                    {c.detail}
                  </span>
                )}
              </Tag>
            );
          })}
        </div>

        {/* ── Derecha: badge agregado de severidad ────────────────────── */}
        <div className="flex shrink-0 items-center gap-2 lg:border-l lg:border-border/60 lg:pl-4">
          {criticalCount > 0 ? (
            <Badge
              variant="outline"
              className="gap-1.5 border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400"
            >
              <AlertTriangle className="h-3 w-3" aria-hidden />
              {criticalCount} crítica{criticalCount === 1 ? "" : "s"}
            </Badge>
          ) : warningCount > 0 ? (
            <Badge
              variant="outline"
              className="gap-1.5 border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
            >
              <AlertTriangle className="h-3 w-3" aria-hidden />
              {warningCount} advertencia{warningCount === 1 ? "" : "s"}
            </Badge>
          ) : (
            <Badge
              variant="outline"
              className="gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
            >
              sin alertas
            </Badge>
          )}
        </div>
      </div>
    </div>
  );
}
