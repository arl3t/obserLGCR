/**
 * SurveillanceMiDia — vista cross-watchlist "Mi Día" para el SOC con
 * priorización inteligente.
 *
 * Composición:
 *   1. Tareas del operador      — casos abiertos asignados a `operatorCi` +
 *                                 casos sin adoptar críticos/highs.
 *   2. Stats del día            — total urgentes + nuevos vs análisis previo
 *                                 + casos abiertos del operador.
 *   3. Grid de dominios         — KPI 1-línea por dominio bajo vigilancia
 *                                 (riskScore, crit/high count).
 *   4. Hallazgos consolidados   — feed ordenado por urgencia compuesta:
 *                                 severity × 100 − annotated × 30 − closedCase × 40
 *                                 + isNew × 25. False-positive y resolved
 *                                 quedan ocultos (toggle para reincorporar).
 *
 * Tope MAX_DOMAINS=10 para no saturar la API; el grid usa `useQueries` con
 * staleTime 2min para que el browser cache responda al navegar entre tabs.
 */

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ArrowRight,
  CalendarClock,
  CheckCircle2,
  ClipboardCheck,
  Globe2,
  Inbox,
  Loader2,
  Sparkles,
  UserCircle2,
} from "lucide-react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useWatchlistStore } from "@/store/surveillance-watchlist-store";
import {
  useHydrateWatchlist,
  annotationsKey,
  type AnnotationRow,
  type FindingsDiffResponse,
} from "@/hooks/useSurveillanceWorkspace";
import {
  surveillanceQueryKey,
} from "@/hooks/useDigitalSurveillance";
import {
  fetchSurveillanceDomain,
} from "@/lib/digital-surveillance-api";
import {
  emailCountForDomain,
  snapshotCoversDomain,
  useLeakIntelHubStore,
} from "@/store/leak-intel-hub-store";
import { buildShodanFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/shodanFindingBuilder";
import { buildMispFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/mispFindingBuilder";
import { buildCredentialFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/credentialFindingBuilder";
import {
  ANALYST_SEVERITY_RANK,
  type AnalystFinding,
  type SurveillanceDomainResult,
} from "@/types/digital-surveillance";
import { SEVERITY_BADGE, SEVERITY_LABEL } from "@/components/digital-surveillance/findings/finding-styles";
import { loadOperatorCi } from "@/lib/operator-ci";
import { formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";
import { authFetch } from "@/lib/auth-fetch";

const MAX_DOMAINS = 10;

// ─────────────────────────────────────────────────────────────────────────────
// Tareas del operador — casos PG abiertos
// ─────────────────────────────────────────────────────────────────────────────

type OpenCaseRow = {
  case_id: string;
  ioc_value: string;
  ioc_type: string;
  severity_text: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE";
  status: string;
  assigned_to: string | null;
  first_seen: string;
};

function useMyOpenCases(operatorCi: string) {
  return useQuery<{ cases: OpenCaseRow[]; total: number }>({
    queryKey: ["mi-dia", "my-open-cases", operatorCi],
    enabled: operatorCi.length > 0,
    queryFn: async () => {
      const r = await authFetch(
        `/api/incidents/open?assignedTo=${encodeURIComponent(operatorCi)}&pageSize=25&status=ALL&includeClosed=false`,
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    },
    staleTime: 60_000,
  });
}

function useUnadoptedUrgentCases() {
  return useQuery<{ cases: OpenCaseRow[]; total: number }>({
    queryKey: ["mi-dia", "unadopted-urgent"],
    queryFn: async () => {
      // assignedTo=__unassigned__ + severity=ALL → filtramos client-side por
      // CRITICAL/HIGH para mantener la query simple (1 endpoint, 1 round-trip).
      const r = await authFetch(
        `/api/incidents/open?assignedTo=__unassigned__&pageSize=50&status=ALL&includeClosed=false`,
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      const cases = (j.cases ?? []).filter((c: OpenCaseRow) =>
        c.severity_text === "CRITICAL" || c.severity_text === "HIGH",
      );
      return { cases, total: cases.length };
    },
    staleTime: 60_000,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Página
// ─────────────────────────────────────────────────────────────────────────────

export function SurveillanceMiDiaPage() {
  useHydrateWatchlist();

  const operatorCi = loadOperatorCi();
  const [onlyMine, setOnlyMine] = useState(false);
  const [includeAnnotated, setIncludeAnnotated] = useState(false);

  const entries = useWatchlistStore((s) => s.entries);
  const allWatchlist = useMemo(
    () =>
      Object.values(entries)
        .sort((a, b) => +new Date(b.addedAt) - +new Date(a.addedAt)),
    [entries],
  );

  // Filtro "Solo míos" — limita a dominios cuya sub tiene ownerLabel matching
  // el operador actual. Comparamos contra ownerLabel porque el store no
  // guarda owner_ci; el server-side lo conoce pero acá no se hidrata.
  const operatorLabel = operatorCi || "";
  const filteredWatchlist = useMemo(() => {
    if (!onlyMine) return allWatchlist;
    return allWatchlist.filter((e) =>
      e.ownerLabel.toLowerCase().includes(operatorLabel.toLowerCase()) ||
      e.ownerLabel === operatorLabel,
    );
  }, [allWatchlist, onlyMine, operatorLabel]);

  const domains = useMemo(
    () => filteredWatchlist.slice(0, MAX_DOMAINS).map((e) => e.domain.toLowerCase()),
    [filteredWatchlist],
  );

  const snapshot = useLeakIntelHubStore((s) => s.snapshot);

  const queries = useQueries({
    queries: domains.map((d) => ({
      queryKey: surveillanceQueryKey(d),
      queryFn:  () => fetchSurveillanceDomain(d),
      staleTime: 2 * 60 * 1000,
      retry: 1,
      enabled: d.length > 0,
    })),
  });

  const isLoading = queries.some((q) => q.isLoading);

  // Tareas del operador
  const myCasesQ = useMyOpenCases(operatorCi);
  const unadoptedQ = useUnadoptedUrgentCases();

  // Por dominio: findings + diff + anotaciones (en paralelo).
  const perDomain = useMemo(() => {
    return domains.map((domain, i) => {
      const q = queries[i];
      const data = q?.data as SurveillanceDomainResult | undefined;
      const findings: AnalystFinding[] = [];

      if (data) {
        findings.push(...buildShodanFindings({ domain, data }));
        findings.push(...buildMispFindings({ domain, data }));
      }

      const hasCoverage = snapshot ? snapshotCoversDomain(snapshot, domain) : false;
      if (hasCoverage && snapshot) {
        const emailCount = emailCountForDomain(snapshot, domain);
        findings.push(
          ...buildCredentialFindings({ domain, snapshot, hasCoverage, emailCount }),
        );
      }

      const urgent = findings
        .filter((f) => f.severity === "critical" || f.severity === "high")
        .sort((a, b) =>
          ANALYST_SEVERITY_RANK[b.severity] - ANALYST_SEVERITY_RANK[a.severity],
        );

      return {
        domain,
        riskScore: data?.risk?.score ?? null,
        riskBand:  data?.risk?.band ?? null,
        loading:   q?.isLoading ?? false,
        error:     q?.isError ? String(q.error?.message ?? q.error ?? "") : null,
        findings:  urgent,
      };
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domains, snapshot, ...queries.map((q) => q.data), ...queries.map((q) => q.isLoading)]);

  // ── Findings urgentes globales con priorización inteligente ──────────────
  const flatUrgent = useMemo(
    () =>
      perDomain
        .flatMap((d) => d.findings.map((f) => ({ ...f, _domain: d.domain })))
        .sort((a, b) => ANALYST_SEVERITY_RANK[b.severity] - ANALYST_SEVERITY_RANK[a.severity]),
    [perDomain],
  );

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6 px-1 pb-12 sm:px-0">
      {/* Cabecera */}
      <motion.header
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className="space-y-2"
      >
        <div className="flex flex-wrap items-center gap-2">
          <CalendarClock className="h-7 w-7 text-primary" aria-hidden />
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">Mi Día</h1>
          <Badge variant="cyber" className="font-normal">Cross-watchlist</Badge>
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
          Lo importante para HOY en una sola vista — casos abiertos asignados,
          hallazgos urgentes cross-watchlist (Shodan + MISP + credenciales del
          snapshot local) con prioridad por severidad, novedad y triaje pendiente.
          False-positive y resueltos quedan ocultos.
        </p>
      </motion.header>

      {/* Stats / toggles globales */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-border/60 bg-muted/20 p-3 text-xs">
        <StatChip
          label="Mis casos abiertos"
          value={myCasesQ.data?.cases.length ?? 0}
          loading={myCasesQ.isLoading}
          tone={myCasesQ.data && myCasesQ.data.cases.length > 0 ? "warn" : "muted"}
        />
        <StatChip
          label="Sin adoptar críticos"
          value={unadoptedQ.data?.cases.length ?? 0}
          loading={unadoptedQ.isLoading}
          tone={
            unadoptedQ.data && unadoptedQ.data.cases.length > 0 ? "critical" : "muted"
          }
        />
        <StatChip
          label="Dominios en watchlist"
          value={allWatchlist.length}
          loading={false}
          tone="muted"
        />
        <StatChip
          label="Findings urgentes"
          value={flatUrgent.length}
          loading={isLoading}
          tone={
            flatUrgent.some((f) => f.severity === "critical") ? "critical" :
            flatUrgent.length > 0 ? "warn" : "ok"
          }
        />

        <div className="ml-auto flex flex-wrap items-center gap-1.5">
          {operatorCi && (
            <Button
              size="sm"
              variant={onlyMine ? "default" : "outline"}
              className="h-7 gap-1.5 text-[11px]"
              onClick={() => setOnlyMine((v) => !v)}
              title="Filtrar dominios cuya watchlist tiene tu CI como owner"
            >
              <UserCircle2 className="h-3 w-3" aria-hidden />
              {onlyMine ? "Solo míos" : "Todos"}
            </Button>
          )}
          <Button
            size="sm"
            variant={includeAnnotated ? "default" : "outline"}
            className="h-7 gap-1.5 text-[11px]"
            onClick={() => setIncludeAnnotated((v) => !v)}
            title="Incluir findings con triage triaged (default: ocultar)"
          >
            <ClipboardCheck className="h-3 w-3" aria-hidden />
            {includeAnnotated ? "Inc. triaged" : "Sin triaged"}
          </Button>
        </div>
      </div>

      {/* Tareas del operador */}
      <TareasPendientes
        operatorCi={operatorCi}
        myCases={myCasesQ.data?.cases ?? []}
        unadopted={unadoptedQ.data?.cases ?? []}
      />

      {/* Watchlist vacía */}
      {domains.length === 0 && (
        <Card className="border-dashed border-border/60">
          <CardContent className="flex items-start gap-3 p-5 text-sm text-muted-foreground">
            <Globe2 className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
            <div className="space-y-1">
              <p className="font-medium text-foreground">
                {onlyMine ? "Sin dominios asignados a tu CI" : "Watchlist vacía"}
              </p>
              <p className="text-xs">
                {onlyMine ? (
                  <>Probá desactivar "Solo míos" o agregá un dominio con tu CI como owner.</>
                ) : (
                  <>
                    Agregá dominios desde Vigilancia Digital ({" "}
                    <Link to="/vigilancia" className="text-primary underline-offset-2 hover:underline">
                      abrir módulo
                    </Link>{" "}
                    ) para que aparezcan en Mi Día.
                  </>
                )}
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Grid de dominios */}
      {domains.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {perDomain.map((d) => (
            <DomainCard key={d.domain} domain={d} />
          ))}
        </div>
      )}

      {/* Findings urgentes consolidados con priorización inteligente */}
      {flatUrgent.length > 0 && (
        <PrioritizedFeed
          flat={flatUrgent}
          includeAnnotated={includeAnnotated}
        />
      )}

      {/* Estados de borde */}
      {isLoading && flatUrgent.length === 0 && (
        <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          Consultando {domains.length} dominio(s)…
        </div>
      )}

      {!isLoading && domains.length > 0 && flatUrgent.length === 0 && (
        <Card className="border-emerald-500/20 bg-emerald-500/[0.03]">
          <CardContent className="flex items-start gap-3 p-5">
            <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-500" aria-hidden />
            <div className="space-y-1">
              <p className="text-sm font-semibold">Sin findings urgentes en la watchlist</p>
              <p className="text-xs leading-relaxed text-muted-foreground">
                Ninguno de los {domains.length} dominio(s) reporta hallazgos critical/high
                en Shodan, MISP o credenciales locales.
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Componentes
// ─────────────────────────────────────────────────────────────────────────────

function StatChip({
  label, value, loading, tone,
}: {
  label: string;
  value: number;
  loading: boolean;
  tone: "muted" | "ok" | "warn" | "critical";
}) {
  const toneClass = {
    muted: "border-border/50 bg-card text-muted-foreground",
    ok:    "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
    warn:  "border-amber-500/40  bg-amber-500/10  text-amber-700  dark:text-amber-400",
    critical: "border-red-500/50 bg-red-500/15 text-red-700 dark:text-red-400",
  }[tone];
  return (
    <div className={cn("flex items-center gap-2 rounded-md border px-2.5 py-1.5", toneClass)}>
      <span className="text-[10px] uppercase tracking-wider opacity-80">{label}</span>
      <span className="font-mono text-sm font-semibold tabular-nums">
        {loading ? <Loader2 className="inline h-3 w-3 animate-spin" /> : value}
      </span>
    </div>
  );
}

function TareasPendientes({
  operatorCi,
  myCases,
  unadopted,
}: {
  operatorCi: string;
  myCases: OpenCaseRow[];
  unadopted: OpenCaseRow[];
}) {
  if (myCases.length === 0 && unadopted.length === 0) return null;
  return (
    <section className="space-y-3">
      <h2 className="flex items-center gap-2 text-base font-semibold">
        <Inbox className="h-4 w-4 text-primary" aria-hidden />
        Tareas pendientes hoy
      </h2>
      <div className="grid gap-3 md:grid-cols-2">
        {/* Mis casos asignados */}
        <Card className={cn("border-l-4", myCases.length > 0 ? "border-l-amber-500" : "border-l-border")}>
          <CardContent className="space-y-2 p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Mis casos abiertos {operatorCi && <code className="font-mono text-[10px]">CI {operatorCi}</code>}
              </p>
              <Badge variant="outline" className="h-5 text-[10px]">
                {myCases.length}
              </Badge>
            </div>
            {myCases.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                {operatorCi
                  ? "Sin casos asignados. Adoptá uno desde el panel SOC."
                  : "Configurá tu CI para ver tus casos asignados."}
              </p>
            ) : (
              <ul className="space-y-1">
                {myCases.slice(0, 6).map((c) => (
                  <CaseRow key={c.case_id} c={c} />
                ))}
                {myCases.length > 6 && (
                  <li className="text-[11px] text-muted-foreground">
                    +{myCases.length - 6} más en{" "}
                    <Link to="/gestion-casos" className="text-primary hover:underline">Gestión SOC</Link>.
                  </li>
                )}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Sin adoptar críticos/highs */}
        <Card className={cn("border-l-4", unadopted.length > 0 ? "border-l-red-500" : "border-l-border")}>
          <CardContent className="space-y-2 p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Sin adoptar (CRIT/HIGH)
              </p>
              <Badge variant="outline" className="h-5 text-[10px]">
                {unadopted.length}
              </Badge>
            </div>
            {unadopted.length === 0 ? (
              <p className="text-xs text-emerald-700 dark:text-emerald-400">
                Nadie esperando — todos los críticos están adoptados.
              </p>
            ) : (
              <ul className="space-y-1">
                {unadopted.slice(0, 6).map((c) => (
                  <CaseRow key={c.case_id} c={c} />
                ))}
                {unadopted.length > 6 && (
                  <li className="text-[11px] text-muted-foreground">
                    +{unadopted.length - 6} más esperando adopción.
                  </li>
                )}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

function CaseRow({ c }: { c: OpenCaseRow }) {
  const sevTone = c.severity_text === "CRITICAL"
    ? "border-red-500/50 bg-red-500/15 text-red-700 dark:text-red-400"
    : c.severity_text === "HIGH"
      ? "border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-400"
      : "border-border bg-muted/30 text-muted-foreground";
  return (
    <li className="grid grid-cols-[auto,1fr,auto] items-center gap-2 text-xs">
      <Badge variant="outline" className={cn("h-4 px-1 text-[9px] font-bold uppercase", sevTone)}>
        {c.severity_text.slice(0, 4)}
      </Badge>
      <Link
        to={`/gestion-casos?id=${encodeURIComponent(c.case_id)}`}
        className="truncate text-foreground/80 hover:text-primary hover:underline"
        title={`${c.case_id} · ${c.ioc_value}`}
      >
        <span className="font-mono text-[10px] text-muted-foreground">{c.case_id.slice(0, 12)}…</span>{" "}
        <span className="truncate">{c.ioc_value}</span>
      </Link>
      <span className="font-mono text-[10px] text-muted-foreground/70" title={c.first_seen}>
        {formatRelativeTimeEs(c.first_seen)}
      </span>
    </li>
  );
}

function DomainCard({
  domain,
}: {
  domain: {
    domain: string;
    riskScore: number | null;
    riskBand: "low" | "medium" | "high" | null;
    loading: boolean;
    error: string | null;
    findings: AnalystFinding[];
  };
}) {
  const urgentCount = domain.findings.length;
  const criticalCount = domain.findings.filter((f) => f.severity === "critical").length;

  return (
    <Card
      className={cn(
        "border-l-4 transition-shadow hover:shadow-sm",
        criticalCount > 0
          ? "border-l-red-500 bg-red-500/[0.03]"
          : urgentCount > 0
            ? "border-l-amber-500 bg-amber-500/[0.03]"
            : "border-l-emerald-500 bg-emerald-500/[0.02]",
      )}
    >
      <CardContent className="space-y-2 p-4">
        <div className="flex items-center justify-between gap-2">
          <Link
            to={`/vigilancia?domain=${encodeURIComponent(domain.domain)}`}
            className="truncate font-mono text-sm font-semibold hover:underline"
          >
            {domain.domain}
          </Link>
          {domain.loading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" aria-hidden />
          ) : domain.riskScore != null ? (
            <Badge variant="outline" className="h-5 text-[10px] tabular-nums">
              {domain.riskScore}/100
            </Badge>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
          {urgentCount === 0 ? (
            <span className="text-emerald-600 dark:text-emerald-400">Sin urgentes</span>
          ) : (
            <>
              {criticalCount > 0 && (
                <Badge variant="outline" className="h-5 border-red-500/40 bg-red-500/10 text-[10px] text-red-700 dark:text-red-400">
                  {criticalCount} crit
                </Badge>
              )}
              <Badge variant="outline" className="h-5 border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-700 dark:text-amber-400">
                {urgentCount - criticalCount} high
              </Badge>
            </>
          )}
          {domain.error && (
            <span className="text-destructive/80">err: {domain.error.slice(0, 30)}</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// PrioritizedFeed — fetch anotaciones + diff por dominio y reordena por urgencia
// ─────────────────────────────────────────────────────────────────────────────

function PrioritizedFeed({
  flat,
  includeAnnotated,
}: {
  flat: Array<AnalystFinding & { _domain: string }>;
  includeAnnotated: boolean;
}) {
  const uniqueDomains = useMemo(
    () => Array.from(new Set(flat.map((f) => f._domain))),
    [flat],
  );

  // Batch: anotaciones + diff por dominio en paralelo. useQueries para no
  // violar rules-of-hooks con un map() de useQuery.
  const annotationsQs = useQueries({
    queries: uniqueDomains.map((d) => ({
      queryKey: annotationsKey(d),
      queryFn: async () => {
        const r = await authFetch(`/api/surveillance/findings/${encodeURIComponent(d)}/annotations`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = await r.json();
        return (j.annotations ?? []) as AnnotationRow[];
      },
      staleTime: 30_000,
      enabled: d.length > 0,
    })),
  });
  const diffQs = useQueries({
    queries: uniqueDomains.map((d) => ({
      queryKey: ["surveillance-findings-diff", d],
      queryFn: async () => {
        const r = await authFetch(`/api/surveillance/findings/diff?domain=${encodeURIComponent(d)}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<FindingsDiffResponse>;
      },
      staleTime: 30_000,
      enabled: d.length > 0,
    })),
  });

  const indexByDomain = useMemo(() => {
    const map = new Map<string, {
      annotated: Set<string>;
      hidden:    Set<string>;
      newIds:    Set<string>;
      severityUp: Set<string>;
    }>();
    uniqueDomains.forEach((domain, i) => {
      const annotated = new Set<string>();
      const hidden    = new Set<string>();
      const annotations = (annotationsQs[i]?.data ?? []) as AnnotationRow[];
      for (const a of annotations) {
        if (a.state === "false-positive" || a.state === "resolved") {
          hidden.add(a.finding_id);
        } else {
          annotated.add(a.finding_id);
        }
      }
      const newIds = new Set<string>();
      const severityUp = new Set<string>();
      const d = diffQs[i]?.data as FindingsDiffResponse | undefined;
      if (d && d.ok && d.hasPrevious) {
        for (const id of d.newIds) newIds.add(id);
        for (const up of d.severityUp) severityUp.add(up.id);
      }
      map.set(domain, { annotated, hidden, newIds, severityUp });
    });
    return map;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [uniqueDomains, ...annotationsQs.map((q) => q.data), ...diffQs.map((q) => q.data)]);

  // Score de urgencia compuesto. La idea es:
  //   - severity domina (×100)
  //   - "nuevo" suma +25 (priorizar lo que entró desde el último análisis)
  //   - "subió" suma +15
  //   - "triaged" resta −30 (alguien ya lo miró, no es urgente)
  //   - "false-positive"/"resolved" → filtrado fuera del feed (a menos que
  //                                    `includeAnnotated`, en cuyo caso se
  //                                    mantienen "triaged" pero igual con penalty).
  function urgency(f: AnalystFinding & { _domain: string }): number {
    const sev = ANALYST_SEVERITY_RANK[f.severity];
    const idx = indexByDomain.get(f._domain);
    let score = sev * 100;
    if (idx?.newIds.has(f.id))     score += 25;
    if (idx?.severityUp.has(f.id)) score += 15;
    if (idx?.annotated.has(f.id))  score -= 30;
    return score;
  }

  const filtered = useMemo(() => {
    return flat
      .filter((f) => {
        const idx = indexByDomain.get(f._domain);
        if (idx?.hidden.has(f.id)) return false;
        if (!includeAnnotated && idx?.annotated.has(f.id)) return false;
        return true;
      })
      .map((f) => ({ f, score: urgency(f) }))
      .sort((a, b) => b.score - a.score)
      .map((x) => x.f);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flat, indexByDomain, includeAnnotated]);

  if (filtered.length === 0) return null;

  return (
    <section className="space-y-3">
      <h2 className="flex items-center gap-2 text-base font-semibold">
        <Sparkles className="h-4 w-4 text-amber-500" aria-hidden />
        Hallazgos urgentes consolidados
        <Badge variant="outline" className="ml-1 h-5 text-[10px]">{filtered.length}</Badge>
        <span className="text-[11px] font-normal text-muted-foreground">
          · priorizados por severidad + novedad − triaje
        </span>
      </h2>
      <div className="space-y-2">
        {filtered.slice(0, 30).map((f) => {
          const idx = indexByDomain.get(f._domain);
          const isNew = idx?.newIds.has(f.id) ?? false;
          const isUp  = idx?.severityUp.has(f.id) ?? false;
          const isTriaged = idx?.annotated.has(f.id) ?? false;
          return (
            <div
              key={`${f._domain}-${f.id}`}
              className={cn(
                "grid grid-cols-[auto,1fr,auto] items-center gap-3 rounded-lg border p-3 transition-colors",
                isNew ? "border-emerald-500/30 bg-emerald-500/[0.04]"
                  : isUp ? "border-red-500/30 bg-red-500/[0.03]"
                  : isTriaged ? "border-border/60 bg-muted/30 opacity-80"
                  : "border-border/60 bg-card",
              )}
            >
              <div className="flex flex-col items-start gap-0.5">
                <Badge variant="outline" className={cn("h-5 px-1.5 text-[10px] font-bold uppercase", SEVERITY_BADGE[f.severity])}>
                  {SEVERITY_LABEL[f.severity]}
                </Badge>
                {isNew && (
                  <Badge variant="outline" className="h-4 gap-0.5 border-emerald-500/40 bg-emerald-500/15 px-1 text-[9px] font-semibold text-emerald-700 dark:text-emerald-400">
                    <Sparkles className="h-2 w-2" aria-hidden /> Nuevo
                  </Badge>
                )}
                {!isNew && isUp && (
                  <Badge variant="outline" className="h-4 border-red-500/40 bg-red-500/15 px-1 text-[9px] font-semibold text-red-700 dark:text-red-400">
                    ↑ Subió
                  </Badge>
                )}
                {!isNew && !isUp && isTriaged && (
                  <Badge variant="outline" className="h-4 border-sky-500/40 bg-sky-500/10 px-1 text-[9px] font-medium text-sky-700 dark:text-sky-400">
                    Triaged
                  </Badge>
                )}
              </div>
              <div className="min-w-0">
                <p className={cn("truncate text-sm font-medium text-foreground", isTriaged && !isNew && "line-through opacity-70")}>
                  {f.title}
                </p>
                <p className="truncate text-[11px] text-muted-foreground">
                  {f.evidence.slice(0, 140)}
                </p>
              </div>
              <Link
                to={`/vigilancia?domain=${encodeURIComponent(f._domain)}`}
                className="flex items-center gap-1 text-[11px] text-primary underline-offset-2 hover:underline"
              >
                <span className="font-mono">{f._domain}</span>
                <ArrowRight className="h-3 w-3" aria-hidden />
              </Link>
            </div>
          );
        })}
      </div>
      {filtered.length > 30 && (
        <p className="px-1 text-[11px] text-muted-foreground">
          Mostrando 30 de {filtered.length} findings priorizados — abrí el análisis individual
          para ver el resto.
        </p>
      )}
    </section>
  );
}
