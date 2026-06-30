/**
 * FindingsFeed — feed unificado del Workspace del Analista.
 *
 * Renderiza una lista de FindingCards con barra de filtros (severity + kind)
 * y conteos por bucket. Maneja el estado de filtros localmente — el parent
 * solo provee `findings` y handlers.
 *
 * Cuando todos los filtros están desactivados, no se muestra ninguna card
 * pero el toolbar sigue visible. El estado vacío "sin findings" aparece
 * solo cuando `findings.length === 0`.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Filter,
  History,
  Inbox,
  Radio,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import { FindingCard, type FindingDiffBadge } from "@/components/digital-surveillance/findings/FindingCard";
import {
  KIND_ICON,
  KIND_LABEL,
  KIND_TINT,
  SEVERITY_BADGE,
  SEVERITY_LABEL,
} from "@/components/digital-surveillance/findings/finding-styles";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAnnotations, useFindingsDiff } from "@/hooks/useSurveillanceWorkspace";
import { formatRelativeTimeEs, formatDateTimePy } from "@/lib/format";
import { cn } from "@/lib/utils";
import type {
  AnalystFinding,
  AnalystFindingAction,
  AnalystFindingKind,
  AnalystFindingRef,
  AnalystFindingSeverity,
} from "@/types/digital-surveillance";

const ALL_SEVERITIES: AnalystFindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const ALL_KINDS: AnalystFindingKind[] = [
  "credential-leak",
  "shodan-exposure",
  "misp-ioc",
  "brand-mention-negative",
  "news-coverage",
  "brand-threat",
  "correlation",
];

export type FindingsFeedProps = {
  findings: AnalystFinding[];
  domain: string;
  onAction: (action: AnalystFindingAction, finding: AnalystFinding) => void;
  onRefClick: (ref: AnalystFindingRef, finding: AnalystFinding) => void;
  /** Estado del live-tail (refetch periódico). Cuando es undefined la pill no aparece. */
  liveTailActive?: boolean;
  /** Toggle del live-tail; el padre maneja el setInterval con refetchAll. */
  onToggleLiveTail?: () => void;
};

export function FindingsFeed({
  findings,
  domain,
  onAction,
  onRefClick,
  liveTailActive,
  onToggleLiveTail,
}: FindingsFeedProps) {
  // Por defecto se muestran todas las severidades y kinds.
  const [severityFilter, setSeverityFilter] = useState<Set<AnalystFindingSeverity>>(
    () => new Set(ALL_SEVERITIES),
  );
  const [kindFilter, setKindFilter] = useState<Set<AnalystFindingKind>>(
    () => new Set(ALL_KINDS),
  );
  // Búsqueda libre — matchea title + evidence + why (case-insensitive).
  const [searchQuery, setSearchQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  // Anotaciones del backend — overlay sobre los findings vivos.
  const annotationsQ = useAnnotations(domain);
  const annotationByFindingId = useMemo(() => {
    const map = new Map<string, NonNullable<typeof annotationsQ.data>[number]>();
    for (const a of annotationsQ.data ?? []) map.set(a.finding_id, a);
    return map;
  }, [annotationsQ.data]);

  // Diff temporal vs análisis previo (feature #3).
  const diffQ = useFindingsDiff(domain);
  const diffBadgeByFindingId = useMemo(() => {
    const map = new Map<string, FindingDiffBadge>();
    if (!diffQ.data?.ok || !diffQ.data.hasPrevious) return map;
    for (const id of diffQ.data.newIds) map.set(id, { status: "new" });
    for (const up of diffQ.data.severityUp) {
      map.set(up.id, { status: "severity-up", prevSeverity: up.prevSeverity });
    }
    for (const dn of diffQ.data.severityDown) {
      map.set(dn.id, { status: "severity-down", prevSeverity: dn.prevSeverity });
    }
    return map;
  }, [diffQ.data]);

  // Filtro "solo cambios" — restringe a findings con diffBadge (new/up/down).
  const [onlyChanges, setOnlyChanges] = useState(false);
  // Sección "resueltos" colapsable.
  const [showResolved, setShowResolved] = useState(false);

  // Foco navegable por teclado (J/K) sobre la lista de cards filtradas.
  // -1 = sin foco (estado inicial). El parent renderiza ring-2 sobre la card focused.
  const [focusedIndex, setFocusedIndex] = useState<number>(-1);
  const cardsContainerRef = useRef<HTMLDivElement>(null);

  // Conteos por bucket (independientes de los filtros activos para que las
  // chips muestren siempre el universo total).
  const counts = useMemo(() => {
    const sev: Record<AnalystFindingSeverity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    const kind: Record<AnalystFindingKind, number> = {
      "credential-leak": 0,
      "shodan-exposure": 0,
      "misp-ioc": 0,
      "brand-mention-negative": 0,
      "news-coverage": 0,
      "brand-threat": 0,
      "correlation": 0,
    };
    for (const f of findings) {
      sev[f.severity] += 1;
      kind[f.kind] += 1;
    }
    return { sev, kind };
  }, [findings]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return findings.filter((f) => {
      if (!severityFilter.has(f.severity)) return false;
      if (!kindFilter.has(f.kind)) return false;
      if (onlyChanges && !diffBadgeByFindingId.has(f.id)) return false;
      if (q.length === 0) return true;
      // Buscamos en los campos textuales relevantes — sin source label/refs
      // para que el match sea por contenido y no por categoría.
      const haystack = `${f.title} ${f.evidence} ${f.why}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [findings, severityFilter, kindFilter, searchQuery, onlyChanges, diffBadgeByFindingId]);

  // Atajos de teclado SOC:
  //   `/`  → focusear búsqueda (Splunk/Sentinel)
  //   J/K o ↓/↑ → navegar cards (vim-style)
  //   Enter → disparar acción primaria de la card focused
  //   A → alias de Enter
  //   Escape → quitar foco (libera el ring visual)
  // No se activan si el foco está en un input/textarea/contentEditable.
  useEffect(() => {
    function onKey(ev: KeyboardEvent) {
      const t = ev.target as HTMLElement | null;
      const inField =
        !!t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);

      // `/` siempre focusea búsqueda (incluso para resetear desde otro input).
      if (ev.key === "/") {
        if (inField) return;
        ev.preventDefault();
        searchRef.current?.focus();
        return;
      }

      if (inField) return;

      if ((ev.key === "j" || ev.key === "ArrowDown") && filtered.length > 0) {
        ev.preventDefault();
        setFocusedIndex((i) => Math.min(filtered.length - 1, Math.max(0, i + 1)));
        return;
      }
      if ((ev.key === "k" || ev.key === "ArrowUp") && filtered.length > 0) {
        ev.preventDefault();
        setFocusedIndex((i) => (i <= 0 ? 0 : i - 1));
        return;
      }
      if ((ev.key === "Enter" || ev.key === "a" || ev.key === "A") && filtered.length > 0) {
        const idx = focusedIndex >= 0 && focusedIndex < filtered.length ? focusedIndex : -1;
        if (idx === -1) return;
        const f = filtered[idx];
        const primary = f.actions.find((a) => a.primary);
        if (primary) {
          ev.preventDefault();
          onAction(primary, f);
        }
        return;
      }
      if (ev.key === "Escape") {
        setFocusedIndex(-1);
        return;
      }
      // T → toggle live-tail (si el parent expuso el handler).
      if ((ev.key === "t" || ev.key === "T") && onToggleLiveTail) {
        ev.preventDefault();
        onToggleLiveTail();
        return;
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [filtered, focusedIndex, onAction, onToggleLiveTail]);

  // Cuando cambia la lista filtrada, re-clampear el índice para no apuntar
  // a una card que dejó de existir.
  useEffect(() => {
    if (focusedIndex >= filtered.length) {
      setFocusedIndex(filtered.length === 0 ? -1 : filtered.length - 1);
    }
  }, [filtered.length, focusedIndex]);

  // Auto-scroll de la card focused al viewport.
  useEffect(() => {
    if (focusedIndex < 0 || !cardsContainerRef.current) return;
    const el = cardsContainerRef.current.children[focusedIndex] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [focusedIndex]);

  // Estado: sin ningún finding del Provider — feed limpio.
  if (findings.length === 0) {
    return <EmptyState domain={domain} />;
  }

  function toggleSeverity(s: AnalystFindingSeverity) {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s); else next.add(s);
      return next;
    });
  }
  function toggleKind(k: AnalystFindingKind) {
    setKindFilter((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k); else next.add(k);
      return next;
    });
  }
  function resetFilters() {
    setSeverityFilter(new Set(ALL_SEVERITIES));
    setKindFilter(new Set(ALL_KINDS));
    setSearchQuery("");
    setOnlyChanges(false);
  }

  const filtersAreCustom =
    severityFilter.size !== ALL_SEVERITIES.length ||
    kindFilter.size !== ALL_KINDS.length ||
    searchQuery.length > 0 ||
    onlyChanges;

  const diff = diffQ.data?.ok && diffQ.data.hasPrevious ? diffQ.data : null;
  const changesCount = diff
    ? diff.newIds.length + diff.severityUp.length + diff.severityDown.length
    : 0;

  return (
    <div className="space-y-4">
      {/* Barra de comparación con análisis previo */}
      {diff && (
        <DiffStrip
          diff={diff}
          changesCount={changesCount}
          onlyChanges={onlyChanges}
          onToggleOnlyChanges={() => setOnlyChanges((v) => !v)}
        />
      )}

      {/* Toolbar de filtros */}
      <div className="space-y-2 rounded-xl border border-border/60 bg-muted/20 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-1 items-center gap-2">
            <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
              <Filter className="h-3.5 w-3.5" aria-hidden />
              Filtros
            </div>
            <div className="relative ml-2 max-w-xs flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/60" aria-hidden />
              <Input
                ref={searchRef}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Buscar en hallazgos…"
                className="h-7 pl-7 pr-7 text-xs"
                aria-label="Buscar texto en hallazgos"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  aria-label="Limpiar búsqueda"
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground/70 hover:bg-muted hover:text-foreground"
                >
                  <X className="h-3 w-3" aria-hidden />
                </button>
              )}
            </div>
            <kbd className="hidden rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground sm:inline-block">
              /
            </kbd>
          </div>
          <div className="flex items-center gap-1.5">
            {onToggleLiveTail && (
              <button
                type="button"
                onClick={onToggleLiveTail}
                title={liveTailActive
                  ? "Live tail activo (T para apagar)"
                  : "Activar live tail (T) — refetch automático cada 60s"}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors",
                  liveTailActive
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                    : "border-border/50 bg-muted/30 text-muted-foreground hover:text-foreground",
                )}
              >
                <Radio className={cn("h-3 w-3", liveTailActive && "animate-pulse")} aria-hidden />
                {liveTailActive ? "Live" : "Tail"}
                <kbd className="hidden rounded border border-border/40 bg-card/40 px-1 font-mono text-[9px] sm:inline-block">T</kbd>
              </button>
            )}
            {filtersAreCustom && (
              <Button
                size="sm"
                variant="ghost"
                className="h-6 px-2 text-[11px] text-muted-foreground hover:text-foreground"
                onClick={resetFilters}
              >
                Resetear
              </Button>
            )}
          </div>
        </div>

        {/* Severidad */}
        <div className="flex flex-wrap gap-1.5">
          {ALL_SEVERITIES.map((s) => {
            const c = counts.sev[s];
            const active = severityFilter.has(s);
            const disabled = c === 0;
            return (
              <button
                key={s}
                type="button"
                disabled={disabled}
                onClick={() => toggleSeverity(s)}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium transition-all",
                  active
                    ? cn("border-foreground/30", SEVERITY_BADGE[s])
                    : "border-border/40 bg-muted/30 text-muted-foreground/70 line-through",
                  disabled && "opacity-40 cursor-not-allowed",
                )}
              >
                {SEVERITY_LABEL[s]}
                <span className="font-mono tabular-nums">{c}</span>
              </button>
            );
          })}
        </div>

        {/* Kind */}
        <div className="flex flex-wrap gap-1.5">
          {ALL_KINDS.map((k) => {
            const c = counts.kind[k];
            const active = kindFilter.has(k);
            const disabled = c === 0;
            const Icon = KIND_ICON[k];
            return (
              <button
                key={k}
                type="button"
                disabled={disabled}
                onClick={() => toggleKind(k)}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border border-border/50 bg-muted/30 px-2 py-0.5 text-[11px] font-medium transition-all",
                  active
                    ? cn("text-foreground/90", KIND_TINT[k])
                    : "text-muted-foreground/70 line-through",
                  disabled && "opacity-40 cursor-not-allowed",
                )}
              >
                <Icon className="h-3 w-3" aria-hidden />
                {KIND_LABEL[k]}
                <span className="font-mono tabular-nums">{c}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Lista */}
      {filtered.length === 0 ? (
        <Card className="border-dashed border-border/60">
          <CardContent className="flex items-center gap-3 p-5 text-sm text-muted-foreground">
            <Inbox className="h-4 w-4 shrink-0" aria-hidden />
            Sin findings con los filtros activos. Ajustá la barra superior o reseteá.
          </CardContent>
        </Card>
      ) : (
        <div ref={cardsContainerRef} className="space-y-3">
          {filtered.map((f, i) => (
            <div
              key={f.id}
              className={cn(
                "rounded-lg transition-shadow",
                i === focusedIndex && "ring-2 ring-primary/50 ring-offset-2 ring-offset-background",
              )}
            >
              <FindingCard
                finding={f}
                domain={domain}
                annotation={annotationByFindingId.get(f.id)}
                diffBadge={diffBadgeByFindingId.get(f.id)}
                onAction={onAction}
                onRefClick={onRefClick}
              />
            </div>
          ))}
        </div>
      )}

      {/* Resueltos desde análisis previo (feature #3 — colapsable) */}
      {diff && diff.resolved.length > 0 && (
        <ResolvedSection
          resolved={diff.resolved}
          open={showResolved}
          onToggle={() => setShowResolved((v) => !v)}
        />
      )}

      {/* Footer informativo + hint de atajos */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-1 text-[11px] text-muted-foreground">
        <p>
          Mostrando <span className="font-mono">{filtered.length}</span> de{" "}
          <span className="font-mono">{findings.length}</span> hallazgo(s)
          {searchQuery && (
            <> · texto: <span className="font-mono text-foreground/70">"{searchQuery}"</span></>
          )}
          {onlyChanges && <> · solo cambios</>}
          {" · "}ordenados por severidad y fecha de detección
        </p>
        <p className="hidden items-center gap-2 sm:flex">
          <span><Kbd>/</Kbd> buscar</span>
          <span><Kbd>J</Kbd>/<Kbd>K</Kbd> navegar</span>
          <span><Kbd>Enter</Kbd> acción</span>
          {onToggleLiveTail && <span><Kbd>T</Kbd> live tail</span>}
        </p>
      </div>
    </div>
  );
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="rounded border border-border/50 bg-muted/40 px-1 py-px font-mono text-[10px] text-muted-foreground">
      {children}
    </kbd>
  );
}

function EmptyState({ domain }: { domain: string }) {
  return (
    <Card className="border-emerald-500/20 bg-emerald-500/[0.03]">
      <CardContent className="flex items-start gap-3 p-5">
        <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-500" aria-hidden />
        <div className="space-y-1">
          <p className="text-sm font-semibold">Sin hallazgos accionables</p>
          <p className="text-xs leading-relaxed text-muted-foreground">
            El agregador no detectó findings significativos para <strong>{domain}</strong> en
            las fuentes activas. Los KPIs de arriba siguen reflejando el estado del módulo —
            si esperabas más hallazgos, valida que las fuentes (Shodan, MISP, Brand24, dump
            de credenciales) estén configuradas y devolviendo datos.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

/** Re-export del badge de severity para que la banda KPI de TabResumen pueda usarlo. */
export { SEVERITY_BADGE };

// ─────────────────────────────────────────────────────────────────────────────
// DiffStrip — barra "comparado con análisis previo"
// ─────────────────────────────────────────────────────────────────────────────

function DiffStrip({
  diff,
  changesCount,
  onlyChanges,
  onToggleOnlyChanges,
}: {
  diff: {
    prev: { id: string; queriedAt: string };
    curr: { id: string; queriedAt: string };
    newIds: string[];
    severityUp: Array<{ id: string }>;
    severityDown: Array<{ id: string }>;
    resolved: Array<{ id: string }>;
  };
  changesCount: number;
  onlyChanges: boolean;
  onToggleOnlyChanges: () => void;
}) {
  const noChanges = changesCount === 0 && diff.resolved.length === 0;
  return (
    <div className={cn(
      "flex flex-wrap items-center gap-2 rounded-xl border px-3 py-2 text-xs",
      noChanges
        ? "border-emerald-500/30 bg-emerald-500/[0.04]"
        : "border-amber-500/30 bg-amber-500/[0.05]",
    )}>
      <History className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
      <span className="text-muted-foreground">
        Comparado con análisis del{" "}
        <span
          className="font-medium text-foreground/80"
          title={formatDateTimePy(diff.prev.queriedAt)}
        >
          {formatRelativeTimeEs(diff.prev.queriedAt)}
        </span>
      </span>
      <span className="text-muted-foreground/40">·</span>
      {noChanges ? (
        <span className="font-medium text-emerald-700 dark:text-emerald-400">
          Sin cambios en hallazgos
        </span>
      ) : (
        <div className="flex flex-wrap items-center gap-1.5">
          {diff.newIds.length > 0 && (
            <Badge
              variant="outline"
              className="h-5 gap-1 border-emerald-500/50 bg-emerald-500/10 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400"
              title={`${diff.newIds.length} hallazgo(s) nuevo(s)`}
            >
              <Sparkles className="h-2.5 w-2.5" aria-hidden />
              {diff.newIds.length} nuevo(s)
            </Badge>
          )}
          {diff.severityUp.length > 0 && (
            <Badge
              variant="outline"
              className="h-5 border-red-500/50 bg-red-500/10 text-[10px] font-semibold text-red-700 dark:text-red-400"
              title={`${diff.severityUp.length} hallazgo(s) subió(eron) de severidad`}
            >
              ↑ {diff.severityUp.length}
            </Badge>
          )}
          {diff.severityDown.length > 0 && (
            <Badge
              variant="outline"
              className="h-5 border-sky-500/40 bg-sky-500/10 text-[10px] font-semibold text-sky-700 dark:text-sky-400"
              title={`${diff.severityDown.length} hallazgo(s) bajó(aron) de severidad`}
            >
              ↓ {diff.severityDown.length}
            </Badge>
          )}
          {diff.resolved.length > 0 && (
            <Badge
              variant="outline"
              className="h-5 border-zinc-500/40 bg-zinc-500/10 text-[10px] font-semibold text-zinc-700 dark:text-zinc-400"
              title={`${diff.resolved.length} hallazgo(s) resuelto(s) — ver abajo`}
            >
              ✓ {diff.resolved.length} resuelto(s)
            </Badge>
          )}
        </div>
      )}
      {changesCount > 0 && (
        <Button
          size="sm"
          variant={onlyChanges ? "default" : "outline"}
          className="ml-auto h-6 gap-1.5 text-[11px]"
          onClick={onToggleOnlyChanges}
          title="Filtrar solo hallazgos con cambios desde el análisis previo"
        >
          {onlyChanges ? "Mostrar todo" : "Solo cambios"}
        </Button>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvedSection — findings que estaban en el análisis previo y ya no
// ─────────────────────────────────────────────────────────────────────────────

function ResolvedSection({
  resolved,
  open,
  onToggle,
}: {
  resolved: Array<{
    id: string;
    kind: AnalystFindingKind;
    severity: AnalystFindingSeverity;
    title: string;
    evidence: string;
  }>;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="rounded-xl border border-zinc-500/30 bg-zinc-500/[0.04]">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs hover:bg-zinc-500/[0.06]"
      >
        <div className="flex items-center gap-2">
          {open
            ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />}
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" aria-hidden />
          <span className="font-medium text-foreground/80">
            {resolved.length} hallazgo{resolved.length === 1 ? "" : "s"} resuelto{resolved.length === 1 ? "" : "s"} desde el análisis previo
          </span>
        </div>
        <span className="text-muted-foreground/60">
          {open ? "ocultar" : "ver detalle"}
        </span>
      </button>
      {open && (
        <ul className="divide-y divide-border/40 border-t border-border/40">
          {resolved.map((r) => {
            const Icon = KIND_ICON[r.kind];
            return (
              <li key={r.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs">
                <Badge variant="outline" className={cn("h-5 text-[10px] font-bold uppercase tracking-wider line-through opacity-70", SEVERITY_BADGE[r.severity])}>
                  {SEVERITY_LABEL[r.severity]}
                </Badge>
                <Badge variant="outline" className={cn("h-5 gap-1 text-[10px]", KIND_TINT[r.kind])}>
                  <Icon className="h-3 w-3" aria-hidden />
                  {KIND_LABEL[r.kind]}
                </Badge>
                <span className="text-muted-foreground line-through">{r.title}</span>
                {r.evidence && (
                  <code className="ml-auto truncate rounded bg-muted/50 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground/80">
                    {r.evidence}
                  </code>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
