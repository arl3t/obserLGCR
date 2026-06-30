import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useMemo, useState, type ReactNode } from "react";
import { FolderOpen, ShieldCheck } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { IncidentPlaybookCard } from "@/components/incidents/IncidentPlaybookCard";
import { IncidentScoringBreakdown } from "@/components/incidents/IncidentScoringBreakdown";
import { ThcRdnsEnrichment } from "@/components/incidents/ThcRdnsEnrichment";
import { LiveScoringV2Panel } from "@/components/intelligence/LiveScoringV2Panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTrinoNamed } from "@/hooks/useTrinoQuery";
import { formatNumber } from "@/lib/format";
import { INCIDENT_PLAYBOOKS } from "@/lib/incident-playbooks";
import { loadOperatorCi, saveOperatorCi } from "@/lib/operator-ci";

// ── helpers ────────────────────────────────────────────────────────────────────

function num(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") {
    const n = Number(v);
    return Number.isNaN(n) ? 0 : n;
  }
  return 0;
}

function str(v: unknown): string {
  return v == null ? "—" : String(v);
}

const STALE_5M = { staleTime: 5 * 60 * 1000, gcTime: 15 * 60 * 1000 } as const;

// ── severity helpers ───────────────────────────────────────────────────────────

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "text-red-500",
  HIGH: "text-orange-500",
  MEDIUM: "text-yellow-500",
  LOW: "text-emerald-500",
};

const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "bg-red-500/10 border-red-500/30",
  HIGH: "bg-orange-500/10 border-orange-500/30",
  MEDIUM: "bg-yellow-500/10 border-yellow-500/30",
  LOW: "bg-emerald-500/10 border-emerald-500/30",
};

function severityColor(sev: string): string {
  return SEVERITY_COLOR[sev as Severity] ?? "text-muted-foreground";
}
function severityBg(sev: string): string {
  return SEVERITY_BG[sev as Severity] ?? "bg-muted/20 border-border";
}

// ── sub-components ─────────────────────────────────────────────────────────────

function QueryState({
  isLoading,
  error,
  empty,
  children,
}: {
  isLoading: boolean;
  error: Error | null;
  empty?: boolean;
  children: ReactNode;
}) {
  if (isLoading) return <Skeleton className="h-40 w-full" />;
  if (error)
    return (
      <p className="text-sm text-destructive" role="alert">
        {error.message}
      </p>
    );
  if (empty)
    return (
      <p className="text-sm text-muted-foreground">
        Sin datos en la ventana seleccionada. Ejecuta el DDL{" "}
        <code className="text-xs">16_iceberg_ddl_incident_classification.sql</code> y el DAG de
        enriquecimiento.
      </p>
    );
  return <>{children}</>;
}

function KpiCard({
  title,
  hint,
  value,
  accent,
  loading,
  error,
}: {
  title: string;
  hint: string;
  value: string;
  accent?: string;
  loading: boolean;
  error: Error | null;
}) {
  return (
    <Card className="border-border/80">
      <CardHeader className="pb-1">
        <CardTitle className="text-xs font-medium text-muted-foreground">{title}</CardTitle>
        <p className="text-[11px] text-muted-foreground/70">{hint}</p>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-24" />
        ) : error ? (
          <p className="text-xs text-destructive">Error</p>
        ) : (
          <p className={`text-2xl font-semibold tabular-nums ${accent ?? ""}`}>{value}</p>
        )}
      </CardContent>
    </Card>
  );
}

// ── Adopt button for Top Incidents ────────────────────────────────────────────

function AdoptButtonTop({
  r,
  operatorCi,
  onAdopted,
}: {
  r: Record<string, unknown>;
  operatorCi: string;
  onAdopted: (caseId: string) => void;
}) {
  const [busy, setBusy]     = useState(false);
  const [result, setResult] = useState<{ ok: boolean; caseId?: string; msg?: string } | null>(null);

  function sv(v: unknown): string { return v == null ? "—" : String(v); }
  function nv(v: unknown): number {
    if (typeof v === "number" && !Number.isNaN(v)) return v;
    if (typeof v === "string") { const n = Number(v); return Number.isNaN(n) ? 0 : n; }
    return 0;
  }

  async function handleAdopt(e: React.MouseEvent) {
    e.stopPropagation();
    const ci = operatorCi.trim();
    if (!ci) { setResult({ ok: false, msg: "Introduce tu CI" }); return; }
    setBusy(true);
    try {
      const resp = await fetch("/api/incidents/open-from-flow", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          iocValue:    sv(r.ioc_value),
          iocType:     sv(r.ioc_type),
          sourceLog:   sv(r.source_log),
          score:       nv(r.score),
          severity:    sv(r.severity),
          mitreTacticId:   r.mitre_tactic_id != null ? sv(r.mitre_tactic_id)   : undefined,
          mitreTacticName: r.mitre_tactic_name != null ? sv(r.mitre_tactic_name) : undefined,
          operatorCi:  ci,
        }),
      });
      const json = await resp.json() as { ok?: boolean; caseId?: string; error?: string };
      if (!resp.ok) setResult({ ok: false, msg: json.error ?? `HTTP ${resp.status}` });
      else { setResult({ ok: true, caseId: json.caseId }); onAdopted(json.caseId!); }
    } catch (e) {
      setResult({ ok: false, msg: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  if (result?.ok) {
    return (
      <span
        onClick={(e) => e.stopPropagation()}
        className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400"
      >
        Caso #{result.caseId?.slice(0, 6)}…
      </span>
    );
  }
  return (
    <div onClick={(e) => e.stopPropagation()} className="flex flex-col gap-0.5">
      <Button
        size="sm"
        variant="outline"
        className="h-6 gap-1 border-emerald-500/40 px-2 text-[10px] text-emerald-400 hover:bg-emerald-500/10"
        disabled={busy}
        onClick={handleAdopt}
      >
        <FolderOpen className="h-3 w-3" aria-hidden />
        {busy ? "Abriendo…" : "Abrir caso"}
      </Button>
      {result?.msg && (
        <span className="text-[10px] text-destructive">{result.msg}</span>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function IncidentClassificationPage() {
  const [days, setDays] = useState<7 | 14 | 30>(7);
  const [detailKey, setDetailKey] = useState<string | null>(null);
  const [operatorCi, setOperatorCi] = useState(loadOperatorCi);
  const [adoptedByKey, setAdoptedByKey] = useState<Record<string, string>>({});
  const queryClient = useQueryClient();
  const dayParams = useMemo(() => ({ days }), [days]);

  const kpis = useTrinoNamed(
    ["incidents", "kpis", days],
    "lh.incidents.kpis",
    dayParams,
    STALE_5M,
  );
  const bySev = useTrinoNamed(
    ["incidents", "bysev", days],
    "lh.incidents.by_severity",
    dayParams,
    STALE_5M,
  );
  const trend = useTrinoNamed(
    ["incidents", "trend", days],
    "lh.incidents.daily_trend",
    dayParams,
    STALE_5M,
  );
  const components = useTrinoNamed(
    ["incidents", "components", days],
    "lh.incidents.score_components",
    dayParams,
    STALE_5M,
  );
  const topIncidentsRaw = useTrinoNamed(
    ["incidents", "top", days],
    "lh.incidents.top",
    { limit: 200, days },
    STALE_5M,
  );

  // Casos abiertos desde PG (rápido). Antes case_id/case_status venían de un
  // JOIN Iceberg contra hunting.incident_cases que tardaba 2-3 min por metadata
  // explotada; ahora el SQL de lh.incidents.top deja esos campos en NULL y los
  // enriquecemos acá por ioc_value.
  const openCases = useQuery({
    queryKey: ["incidents", "open-idx"],
    queryFn: async () => {
      const { data } = await api.get<{ cases?: Array<{ id?: string; case_id?: string; ioc_value?: string | null; status?: string | null }> }>(
        "/api/incidents/open?pageSize=200&sort=severity&sortDir=asc",
      );
      return data?.cases ?? [];
    },
    staleTime:       60_000,
    gcTime:          5 * 60_000,
    refetchOnWindowFocus: false,
  });

  const caseByIoc = useMemo(() => {
    const m = new Map<string, { case_id: string; case_status: string }>();
    for (const c of openCases.data ?? []) {
      const ioc = (c.ioc_value ?? "").trim();
      if (!ioc) continue;
      const id = c.case_id ?? c.id;
      if (!id) continue;
      // Si hay varios casos por ioc, el primero (el más severo por sort=severity) gana.
      if (!m.has(ioc)) m.set(ioc, { case_id: String(id), case_status: String(c.status ?? "") });
    }
    return m;
  }, [openCases.data]);

  // Capa enriquecida: mantiene la misma shape que topIncidentsRaw pero
  // popula case_id/case_status desde PG. Así el JSX existente no cambia.
  const topIncidents = useMemo(() => {
    const rows = topIncidentsRaw.data ?? [];
    return {
      ...topIncidentsRaw,
      data: rows.map((r) => {
        const hit = caseByIoc.get(String(r.ioc_value ?? ""));
        return hit
          ? { ...r, case_id: hit.case_id, case_status: hit.case_status }
          : r;
      }),
    };
  }, [topIncidentsRaw, caseByIoc]);

  const k0 = kpis.data?.[0];
  const comp0 = components.data?.[0];

  const detailRow = useMemo(() => {
    const rows = topIncidents.data ?? [];
    if (!detailKey) return null;
    return (
      rows.find((r, i) => `${String(r.ioc_value)}-${String(r.dt)}-${i}` === detailKey) ?? null
    );
  }, [topIncidents.data, detailKey]);

  function handleAdopted(rowKey: string, caseId: string) {
    saveOperatorCi(operatorCi);
    setAdoptedByKey((prev) => ({ ...prev, [rowKey]: caseId }));
    void queryClient.invalidateQueries({ queryKey: ["incidents", "top", days] });
  }

  const chartSev = useMemo(
    () =>
      (bySev.data ?? []).map((r) => ({
        severity: str(r.severity),
        cnt: num(r.cnt),
        avg_score: num(r.avg_score),
      })),
    [bySev.data],
  );

  const chartTrend = useMemo(
    () =>
      (trend.data ?? []).map((r) => ({
        dt: str(r.dt),
        critical: num(r.critical),
        high: num(r.high),
        medium: num(r.medium),
        low: num(r.low),
      })),
    [trend.data],
  );

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-8">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
            Clasificación de incidentes
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Score compuesto (0–100) por IOC:{" "}
            <span className="font-mono text-xs">MITRE (0-40)</span> +{" "}
            <span className="font-mono text-xs">Evidencia (0-35)</span> +{" "}
            <span className="font-mono text-xs">Wazuh (0-25)</span>. Vista{" "}
            <code className="text-xs">v_incident_score</code>.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="cyber" className="w-fit">
            lh.incidents.*
          </Badge>
          <Input
            value={operatorCi}
            onChange={(e) => setOperatorCi(e.target.value)}
            placeholder="CI operador"
            className="h-9 w-32 text-xs"
          />
          <Tabs
            value={String(days)}
            onValueChange={(v) => setDays(Number(v) as 7 | 14 | 30)}
            className="w-fit"
          >
            <TabsList className="h-9">
              <TabsTrigger value="7" className="px-3 text-xs">7 d</TabsTrigger>
              <TabsTrigger value="14" className="px-3 text-xs">14 d</TabsTrigger>
              <TabsTrigger value="30" className="px-3 text-xs">30 d</TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
      </div>

      {/* Panel v2 — tiempo casi real */}
      <LiveScoringV2Panel />

      <Separator />

      {/* KPI cards (v1) */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          title="IOCs analizados"
          hint={`Ventana ${days} días`}
          value={k0 ? formatNumber(num(k0.total_iocs)) : "—"}
          loading={kpis.isLoading}
          error={kpis.error}
        />
        <KpiCard
          title="CRITICAL"
          hint="Score ≥ 75"
          value={k0 ? formatNumber(num(k0.critical_count)) : "—"}
          accent={num(k0?.critical_count) > 0 ? "text-red-500" : undefined}
          loading={kpis.isLoading}
          error={kpis.error}
        />
        <KpiCard
          title="HIGH"
          hint="Score ≥ 50"
          value={k0 ? formatNumber(num(k0.high_count)) : "—"}
          accent={num(k0?.high_count) > 0 ? "text-orange-500" : undefined}
          loading={kpis.isLoading}
          error={kpis.error}
        />
        <KpiCard
          title="Score promedio"
          hint="Sobre IOCs de la ventana"
          value={k0?.avg_score != null ? String(k0.avg_score) : "—"}
          loading={kpis.isLoading}
          error={kpis.error}
        />
      </div>

      {/* Charts row */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Severity bar chart */}
        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">IOCs por severidad</CardTitle>
            <p className="text-xs text-muted-foreground">
              Distribución CRITICAL / HIGH / MEDIUM / LOW en la ventana.
            </p>
          </CardHeader>
          <CardContent className="h-52">
            <QueryState
              isLoading={bySev.isLoading}
              error={bySev.error}
              empty={!bySev.isLoading && chartSev.length === 0}
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartSev} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/60" />
                  <XAxis dataKey="severity" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 10 }} width={36} />
                  <Tooltip
                    contentStyle={{ fontSize: 12 }}
                    formatter={(v: number, name: string) => [
                      formatNumber(v),
                      name === "cnt" ? "IOCs" : "Score avg",
                    ]}
                  />
                  <Bar dataKey="cnt" fill="var(--color-chart-1)" radius={[4, 4, 0, 0]} name="cnt" />
                </BarChart>
              </ResponsiveContainer>
            </QueryState>
          </CardContent>
        </Card>

        {/* Daily trend area chart */}
        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Tendencia diaria por severidad</CardTitle>
            <p className="text-xs text-muted-foreground">
              Evolución de incidentes por nivel en la ventana seleccionada.
            </p>
          </CardHeader>
          <CardContent className="h-52">
            <QueryState
              isLoading={trend.isLoading}
              error={trend.error}
              empty={!trend.isLoading && chartTrend.length === 0}
            >
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartTrend} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/60" />
                  <XAxis dataKey="dt" tick={{ fontSize: 9 }} interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 10 }} width={30} />
                  <Tooltip contentStyle={{ fontSize: 11 }} />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    stackId="1"
                    stroke="#ef4444"
                    fill="#ef444430"
                    name="CRITICAL"
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    stackId="1"
                    stroke="#f97316"
                    fill="#f9731630"
                    name="HIGH"
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    stackId="1"
                    stroke="#eab308"
                    fill="#eab30830"
                    name="MEDIUM"
                  />
                  <Area
                    type="monotone"
                    dataKey="low"
                    stackId="1"
                    stroke="#22c55e"
                    fill="#22c55e30"
                    name="LOW"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </QueryState>
          </CardContent>
        </Card>
      </div>

      {/* Score components */}
      <Card className="border-border/80">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Contribución media por componente</CardTitle>
          <p className="text-xs text-muted-foreground">
            Promedio de cada sub-score sobre los IOCs de la ventana. Útil para calibrar pesos.
          </p>
        </CardHeader>
        <CardContent>
          <QueryState
            isLoading={components.isLoading}
            error={components.error}
            empty={!components.isLoading && !comp0}
          >
            <div className="grid gap-3 sm:grid-cols-4">
              {[
                { label: "MITRE tácticas", key: "avg_mitre", max: 40 },
                { label: "Evidencia (VT+Abuse+Shodan)", key: "avg_evidence", max: 35 },
                { label: "Wazuh level", key: "avg_wazuh", max: 25 },
                { label: "Score total", key: "avg_total", max: 100 },
              ].map(({ label, key, max }) => {
                const val = num(comp0?.[key]);
                const pct = Math.round((val / max) * 100);
                return (
                  <div key={key} className="rounded-lg border border-border bg-muted/20 p-3">
                    <p className="text-[11px] text-muted-foreground">{label}</p>
                    <p className="mt-1 text-xl font-semibold tabular-nums">{val}</p>
                    <p className="text-[10px] text-muted-foreground/70">
                      {pct}% de {max} pts máx
                    </p>
                    <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-border">
                      <div
                        className="h-full rounded-full bg-primary/70 transition-all"
                        style={{ width: `${Math.min(pct, 100)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </QueryState>
        </CardContent>
      </Card>

      {/* Top incidents table */}
      <div>
        <h2 className="text-sm font-semibold tracking-tight text-foreground">
          Top incidentes (últimos {days} días)
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Ordenados por score descendente. Pulsa una tarjeta para ver el desglose MITRE / VT / Abuse /
          Shodan / Wazuh, historial en vista y el playbook de respuesta.
        </p>
        <Separator className="my-4" />

        <QueryState
          isLoading={topIncidents.isLoading}
          error={topIncidents.error}
          empty={!topIncidents.isLoading && (topIncidents.data?.length ?? 0) === 0}
        >
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {(topIncidents.data ?? []).map((r, i) => {
              const sev = str(r.severity);
              const score = num(r.score);
              const vtMal = num(r.vt_malicious);
              const abuse = num(r.abuse_confidence);
              const rowKey = `${String(r.ioc_value)}-${String(r.dt)}-${i}`;
              const selected = detailKey === rowKey;
              // Case from query JOIN or from local adoption
              const caseId  = adoptedByKey[rowKey] ?? (r.case_id != null ? str(r.case_id) : null);
              const caseSt  = adoptedByKey[rowKey] ? "EN_ANALISIS" : (r.case_status != null ? str(r.case_status) : null);
              const canAdopt = !caseId && (sev === "CRITICAL" || sev === "HIGH" || sev === "MEDIUM");
              return (
                <button
                  type="button"
                  key={rowKey}
                  onClick={() => setDetailKey((k) => (k === rowKey ? null : rowKey))}
                  className={`flex flex-col gap-2 rounded-lg border p-3 text-left transition-shadow ${severityBg(sev)} ${
                    selected ? "ring-2 ring-primary/60 ring-offset-2 ring-offset-background" : "hover:brightness-[1.02]"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <p
                      className="truncate font-mono text-xs font-medium"
                      title={str(r.ioc_value)}
                    >
                      {str(r.ioc_value)}
                    </p>
                    <div className="flex shrink-0 items-center gap-1">
                      {caseId && (
                        <span
                          className="rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-sky-400"
                          title={`Caso: ${caseId}`}
                        >
                          #{caseId.slice(0, 6)}{caseSt ? ` · ${caseSt}` : ""}
                        </span>
                      )}
                      <span className={`text-xs font-bold tabular-nums ${severityColor(sev)}`}>
                        {score}
                      </span>
                    </div>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    {str(r.ioc_type)} · {str(r.dt)} · {str(r.source_log)}
                  </p>
                  {r.mitre_tactic_name != null && (
                    <p className="text-[11px] text-muted-foreground/80">
                      {str(r.mitre_tactic_name)}{" "}
                      <span className="font-mono">{str(r.mitre_technique_id)}</span>
                    </p>
                  )}
                  <div className="flex flex-wrap gap-1 pt-1">
                    <Badge
                      variant={sev === "CRITICAL" ? "destructive" : "outline"}
                      className="text-[10px]"
                    >
                      {sev}
                    </Badge>
                    {vtMal > 0 && (
                      <Badge variant="destructive" className="text-[10px]">
                        VT {vtMal}
                      </Badge>
                    )}
                    {abuse >= 50 && (
                      <Badge variant="outline" className="text-[10px] text-orange-500">
                        Abuse {abuse}%
                      </Badge>
                    )}
                    {(r.in_urlhaus === true || r.in_urlhaus === "true") && (
                      <Badge variant="outline" className="text-[10px]">
                        URLhaus
                      </Badge>
                    )}
                    {(r.in_openphish === true || r.in_openphish === "true") && (
                      <Badge variant="outline" className="text-[10px]">
                        OpenPhish
                      </Badge>
                    )}
                    <Badge variant="secondary" className="ml-auto text-[10px]">
                      M:{num(r.score_mitre)} E:{num(r.score_evidence)} W:{num(r.score_wazuh)}
                    </Badge>
                  </div>
                  <p className="text-[10px] text-muted-foreground/70 line-clamp-2">
                    {str(r.recommended_action)}
                  </p>
                  {canAdopt && (
                    <AdoptButtonTop
                      r={r}
                      operatorCi={operatorCi}
                      onAdopted={(caseId) => handleAdopted(rowKey, caseId)}
                    />
                  )}
                </button>
              );
            })}
          </div>
        </QueryState>

        {detailRow && (
          <Card className="mt-6 border-primary/20 bg-card/90">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Desglose para clasificar</CardTitle>
              <p className="text-xs text-muted-foreground">
                IOC <span className="font-mono text-foreground">{str(detailRow.ioc_value)}</span> ·
                Fuente <span className="font-mono">{str(detailRow.source_log)}</span>
              </p>
              <ThcRdnsEnrichment
                className="mt-3"
                ip={str(detailRow.ioc_value)}
                enabled={str(detailRow.ioc_type).toLowerCase() === "ip"}
              />
            </CardHeader>
            <CardContent>
              <IncidentScoringBreakdown summaryRow={detailRow} showPlaybook />
            </CardContent>
          </Card>
        )}
      </div>

      {/* Playbooks section */}
      <div>
        <h2 className="text-sm font-semibold tracking-tight text-foreground">
          Playbooks por severidad
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Procedimientos de respuesta estándar. Ver{" "}
          <code className="text-xs">docs/INCIDENT-CLASSIFICATION.md</code> para detalle completo.
        </p>
        <Separator className="my-4" />
        <div className="grid gap-4 lg:grid-cols-2">
          {INCIDENT_PLAYBOOKS.map((pb) => (
            <IncidentPlaybookCard key={pb.severity} pb={pb} />
          ))}
        </div>
      </div>

      {/* Formula reference */}
      <Card className="border-border/40 bg-muted/30">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" aria-hidden />
            <CardTitle className="text-sm">Fórmula de scoring</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-xs text-muted-foreground">
          <p>
            <span className="font-mono font-semibold text-foreground">score</span> = score_mitre
            (0-40) + score_evidence (0-35) + score_wazuh (0-25) → capped a 100
          </p>
          <div className="grid gap-2 sm:grid-cols-3">
            <div>
              <p className="font-medium text-foreground">MITRE (0-40)</p>
              <ul className="mt-1 space-y-0.5">
                <li>Execution / C2 → 40 pts</li>
                <li>Lateral Movement / Impact → 38</li>
                <li>Persistence → 35</li>
                <li>Privilege Escalation → 30</li>
                <li>Credential Access → 28</li>
                <li>Initial Access → 22</li>
                <li>Defense Evasion → 18</li>
              </ul>
            </div>
            <div>
              <p className="font-medium text-foreground">Evidencia (0-35)</p>
              <ul className="mt-1 space-y-0.5">
                <li>VT malicious ≥15 → 30</li>
                <li>VT malicious ≥5 → 22</li>
                <li>VT malicious ≥1 → 15</li>
                <li>AbuseIPDB ≥80% → 18</li>
                <li>Shodan :4444 → 15</li>
                <li>Shodan :3389/:445 → 12</li>
                <li>URLhaus/OpenPhish → 10</li>
              </ul>
            </div>
            <div>
              <p className="font-medium text-foreground">Wazuh level (0-25)</p>
              <ul className="mt-1 space-y-0.5">
                <li>level ≥15 → 25 pts</li>
                <li>level ≥12 → 18 pts</li>
                <li>level ≥9 → 12 pts</li>
                <li>level ≥5 → 6 pts</li>
                <li>sin alerta → 2 pts</li>
              </ul>
              <p className="mt-3 font-medium text-foreground">Umbrales</p>
              <ul className="mt-1 space-y-0.5">
                <li className="text-red-500">CRITICAL ≥ 75</li>
                <li className="text-orange-500">HIGH ≥ 50</li>
                <li className="text-yellow-500">MEDIUM ≥ 25</li>
                <li className="text-emerald-500">LOW &lt; 25</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
