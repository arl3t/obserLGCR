import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useMemo, useState, type ReactNode } from "react";
import { EnrichedChartRecommendationsCard } from "@/components/intelligence/EnrichedChartRecommendationsCard";
import { EnrichedRiskPipelineCard } from "@/components/intelligence/EnrichedRiskPipelineCard";
import { EnrichedScoreRulesCard } from "@/components/intelligence/EnrichedScoreRulesCard";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTrinoNamedBatch } from "@/hooks/useTrinoQuery";
import { formatNumber } from "@/lib/format";

function num(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") {
    const n = Number(v);
    return Number.isNaN(n) ? 0 : n;
  }
  return 0;
}

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
      <p className="text-sm text-muted-foreground">Sin filas en la ventana seleccionada.</p>
    );
  return <>{children}</>;
}

function DataCardBadge({ children }: { children: ReactNode }) {
  return (
    <Badge variant="secondary" className="font-normal">
      {children}
    </Badge>
  );
}

const STALE_5M = { staleTime: 5 * 60 * 1000, gcTime: 15 * 60 * 1000 } as const;

export function EnrichedScorePage() {
  const [days, setDays] = useState<7 | 14 | 30>(7);

  const specs = useMemo(
    () => [
      { key: "kpis",      id: "lh.hunting.enriched_kpis",             params: { days } },
      { key: "daily",     id: "lh.hunting.enriched_daily_trend",       params: { days } },
      { key: "sources",   id: "lh.hunting.enriched_source_breakdown",  params: { days } },
      { key: "scores",    id: "lh.hunting.enriched_score_buckets",     params: { days } },
      { key: "vtCov",     id: "lh.hunting.enriched_vt_coverage",       params: { days } },
      { key: "topSample", id: "lh.hunting.enriched_vt_top_sample",     params: { limit: 24, days } },
      { key: "cbFailed",  id: "lh.hunting.enriched_cb_failed",         params: { days } },
    ],
    [days],
  );

  const { results, isLoading } = useTrinoNamedBatch(
    ["enriched-score", days],
    specs,
    STALE_5M,
  );

  const k0 = results.kpis.data?.[0];
  const chartDaily = useMemo(
    () =>
      (results.daily.data ?? []).map((r) => ({
        dt: String(r.dt ?? ""),
        cnt: num(r.cnt),
      })),
    [results.daily.data],
  );
  const chartSources = useMemo(
    () =>
      (results.sources.data ?? []).map((r) => ({
        source_log: String(r.source_log ?? ""),
        cnt: num(r.cnt),
      })),
    [results.sources.data],
  );
  const chartScores = useMemo(
    () =>
      (results.scores.data ?? []).map((r) => ({
        score: String(r.vt_priority_score ?? ""),
        cnt: num(r.cnt),
      })),
    [results.scores.data],
  );

  const vt0 = results.vtCov.data?.[0];
  const enrichedWindow = num(vt0?.enriched_rows_in_window);
  const vtJoin = num(vt0?.rows_with_vt_join);
  const pctVt =
    enrichedWindow > 0 ? Math.round((vtJoin / enrichedWindow) * 1000) / 10 : null;

  const cb0 = results.cbFailed.data?.[0];
  const cbFailedTotal = cb0 ? num(cb0.failed_total) : null;

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-8">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
            Score de riesgo e intel enriquecida
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Tarjetas con el flujo completo, la fórmula de prioridad VT y métricas vivas del{" "}
            <code className="text-xs">ioc_enriquecido</code> + <code className="text-xs">reputacion_vt</code>.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="cyber" className="w-fit">
            intel · lake
          </Badge>
          <Tabs
            value={String(days)}
            onValueChange={(v) => setDays(Number(v) as 7 | 14 | 30)}
            className="w-fit"
          >
            <TabsList className="h-9">
              <TabsTrigger value="7" className="px-3 text-xs">
                7 d
              </TabsTrigger>
              <TabsTrigger value="14" className="px-3 text-xs">
                14 d
              </TabsTrigger>
              <TabsTrigger value="30" className="px-3 text-xs">
                30 d
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
      </div>

      <EnrichedRiskPipelineCard />

      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <EnrichedScoreRulesCard />
        <EnrichedChartRecommendationsCard />
      </div>

      <div>
        <h2 className="text-sm font-semibold tracking-tight text-foreground">
          Datos enriquecidos (Trino)
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          KPIs y gráficos alimentados por consultas nombradas; reflejan el estado del lake, no el código del DAG.
        </p>
        <Separator className="my-4" />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          title="IOCs en tabla (total)"
          hint="Filas en ioc_enriquecido"
          value={k0 ? formatNumber(num(k0.total_rows)) : "—"}
          loading={isLoading}
          error={null}
        />
        <KpiCard
          title={`Registros últimos ${days} d`}
          hint="Ventana temporal activa"
          value={k0 ? formatNumber(num(k0.rows_in_window)) : "—"}
          loading={isLoading}
          error={null}
        />
        <KpiCard
          title="Con MITRE en ventana"
          hint="Contexto táctico propagado"
          value={k0 ? formatNumber(num(k0.rows_with_mitre_in_window)) : "—"}
          loading={isLoading}
          error={null}
        />
        <KpiCard
          title="Última partición `dt`"
          hint="Freshness de ingesta"
          value={k0?.max_dt_seen != null ? String(k0.max_dt_seen) : "—"}
          loading={isLoading}
          error={null}
        />
      </div>

      {/* Circuit-breaker failures */}
      {(cbFailedTotal === null || cbFailedTotal > 0) && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KpiCard
            title="Enriquecimiento fallido"
            hint={`IOCs con enrichment_failed=true en los últimos ${days} d (circuit breaker agotado)`}
            value={cbFailedTotal !== null ? formatNumber(cbFailedTotal) : "—"}
            loading={isLoading}
            error={null}
            alert={cbFailedTotal !== null && cbFailedTotal > 0}
          />
          <KpiCard
            title="Fallos VT"
            hint="VirusTotal — reintentos agotados"
            value={cb0 ? formatNumber(num(cb0.failed_vt)) : "—"}
            loading={isLoading}
            error={null}
          />
          <KpiCard
            title="Fallos Shodan / AbuseIPDB"
            hint="Shodan + AbuseIPDB combinados"
            value={cb0 ? formatNumber(num(cb0.failed_shodan) + num(cb0.failed_abuseipdb)) : "—"}
            loading={isLoading}
            error={null}
          />
          <KpiCard
            title="Fallos THC RDNS"
            hint="ip.thc.org reverse DNS — reintentos agotados"
            value={cb0 ? formatNumber(num(cb0.failed_thc_rdns)) : "—"}
            loading={isLoading}
            error={null}
          />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="border-border/80">
          <CardHeader className="space-y-2 pb-2">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle className="text-base">Volumen IOC por día</CardTitle>
              <DataCardBadge>Recomendación: serie por dt</DataCardBadge>
            </div>
            <p className="text-xs text-muted-foreground">
              Agrupación <code className="text-xs">dt</code> en la ventana seleccionada.
            </p>
          </CardHeader>
          <CardContent className="h-56">
            <QueryState
              isLoading={isLoading}
              error={null}
              empty={!isLoading && chartDaily.length === 0}
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartDaily} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/60" />
                  <XAxis dataKey="dt" tick={{ fontSize: 10 }} interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 10 }} width={36} />
                  <Tooltip
                    contentStyle={{ fontSize: 12 }}
                    formatter={(v: number) => [formatNumber(v), "IOC"]}
                  />
                  <Bar dataKey="cnt" fill="var(--color-chart-1)" radius={[4, 4, 0, 0]} name="IOC" />
                </BarChart>
              </ResponsiveContainer>
            </QueryState>
          </CardContent>
        </Card>

        <Card className="border-border/80">
          <CardHeader className="space-y-2 pb-2">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle className="text-base">Origen del observable</CardTitle>
              <DataCardBadge>Recomendación: mix source_log</DataCardBadge>
            </div>
            <p className="text-xs text-muted-foreground">
              Comparativa de extractores (OPNsense vs Wazuh) en la ventana.
            </p>
          </CardHeader>
          <CardContent className="h-56">
            <QueryState
              isLoading={isLoading}
              error={null}
              empty={!isLoading && chartSources.length === 0}
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={chartSources}
                  layout="vertical"
                  margin={{ top: 8, right: 8, left: 8, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/60" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10 }} />
                  <YAxis type="category" dataKey="source_log" width={120} tick={{ fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ fontSize: 12 }}
                    formatter={(v: number) => [formatNumber(v), "Filas"]}
                  />
                  <Bar dataKey="cnt" fill="var(--color-chart-2)" radius={[0, 4, 4, 0]} name="Filas" />
                </BarChart>
              </ResponsiveContainer>
            </QueryState>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="border-border/80">
          <CardHeader className="space-y-2 pb-2">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle className="text-base">Distribución del score de prioridad</CardTitle>
              <DataCardBadge>Recomendación: histograma</DataCardBadge>
            </div>
            <p className="text-xs text-muted-foreground">
              Misma expresión que el DAG; útil para calibrar <code className="text-xs">VT_MIN_PRIORITY_SCORE</code>.
            </p>
          </CardHeader>
          <CardContent className="h-56">
            <QueryState
              isLoading={isLoading}
              error={null}
              empty={!isLoading && chartScores.length === 0}
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartScores} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/60" />
                  <XAxis dataKey="score" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 10 }} width={36} />
                  <Tooltip
                    contentStyle={{ fontSize: 12 }}
                    formatter={(v: number) => [formatNumber(v), "Filas"]}
                  />
                  <Bar dataKey="cnt" fill="var(--color-chart-3)" radius={[4, 4, 0, 0]} name="Filas" />
                </BarChart>
              </ResponsiveContainer>
            </QueryState>
          </CardContent>
        </Card>

        <Card className="border-border/80">
          <CardHeader className="space-y-2 pb-2">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle className="text-base">Cobertura VirusTotal</CardTitle>
              <DataCardBadge>Recomendación: KPI join</DataCardBadge>
            </div>
            <p className="text-xs text-muted-foreground">
              Join mismo día (<code className="text-xs">ioc_value</code>, <code className="text-xs">ioc_type</code>,{" "}
              <code className="text-xs">dt</code>).
            </p>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <QueryState
              isLoading={isLoading}
              error={null}
              empty={!isLoading && !vt0}
            >
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-border bg-muted/20 p-3">
                  <p className="text-xs text-muted-foreground">Filas enriched (ventana)</p>
                  <p className="mt-1 text-xl font-semibold tabular-nums">
                    {formatNumber(enrichedWindow)}
                  </p>
                </div>
                <div className="rounded-lg border border-border bg-muted/20 p-3">
                  <p className="text-xs text-muted-foreground">Con fila en reputacion_vt</p>
                  <p className="mt-1 text-xl font-semibold tabular-nums">
                    {formatNumber(vtJoin)}
                    {pctVt != null && (
                      <span className="ml-2 text-sm font-normal text-muted-foreground">
                        ({pctVt}%)
                      </span>
                    )}
                  </p>
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/20 p-3">
                <p className="text-xs text-muted-foreground">Filas con vt_malicious &gt; 0</p>
                <p className="mt-1 text-xl font-semibold tabular-nums text-destructive">
                  {formatNumber(num(vt0?.rows_vt_malicious_positive))}
                </p>
              </div>
            </QueryState>
          </CardContent>
        </Card>
      </div>

      <Card className="border-border/80">
        <CardHeader className="space-y-2 pb-2">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="text-base">IOC priorizados (muestra enriquecida)</CardTitle>
            <DataCardBadge>Recomendación: ranking VT + score</DataCardBadge>
          </div>
          <p className="text-xs text-muted-foreground">
            Cada bloque es un observable de la ventana; orden: <code className="text-xs">vt_malicious</code> ↓,
            score ↓, fecha ↓. Máximo 24 entradas.
          </p>
        </CardHeader>
        <CardContent>
          <QueryState
            isLoading={isLoading}
            error={null}
            empty={!isLoading && (results.topSample.data?.length ?? 0) === 0}
          >
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {(results.topSample.data ?? []).map((r, i) => {
                const hasVt = r.has_vt_row === true || r.has_vt_row === "true";
                const mal = num(r.vt_malicious);
                return (
                  <div
                    key={`${r.ioc_value}-${r.dt}-${i}`}
                    className="flex flex-col gap-2 rounded-lg border border-border bg-card/60 p-3"
                  >
                    <p className="truncate font-mono text-xs font-medium" title={String(r.ioc_value ?? "")}>
                      {String(r.ioc_value ?? "—")}
                    </p>
                    <p className="text-[11px] text-muted-foreground">
                      {String(r.ioc_type ?? "—")} · {String(r.dt ?? "—")}
                    </p>
                    <p className="truncate text-[11px] text-muted-foreground">
                      {String(r.source_log ?? "—")}
                      {r.mitre_technique_id != null && (
                        <>
                          {" "}
                          · <span className="font-mono">{String(r.mitre_technique_id)}</span>
                        </>
                      )}
                    </p>
                    <div className="mt-auto flex flex-wrap gap-1.5">
                      <Badge variant="outline" className="text-[10px]">
                        score {formatNumber(num(r.vt_priority_score))}
                      </Badge>
                      <Badge
                        variant={mal > 0 ? "destructive" : "secondary"}
                        className="text-[10px]"
                      >
                        VT mal {formatNumber(mal)}
                      </Badge>
                      <Badge variant="secondary" className="text-[10px]">
                        susp {formatNumber(num(r.vt_suspicious))}
                      </Badge>
                      <Badge variant={hasVt ? "cyber" : "outline"} className="text-[10px]">
                        {hasVt ? "VT consultado" : "Sin VT mismo día"}
                      </Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          </QueryState>
        </CardContent>
      </Card>
    </div>
  );
}

function KpiCard({
  title,
  hint,
  value,
  loading,
  error,
  alert = false,
}: {
  title: string;
  hint: string;
  value: string;
  loading: boolean;
  error: Error | null;
  alert?: boolean;
}) {
  return (
    <Card className={alert ? "border-destructive/60 bg-destructive/5" : "border-border/80"}>
      <CardHeader className="pb-1">
        <CardTitle className="text-xs font-medium text-muted-foreground">{title}</CardTitle>
        <p className="text-[11px] text-muted-foreground/80">{hint}</p>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-24" />
        ) : error ? (
          <p className="text-xs text-destructive">Error</p>
        ) : (
          <p className={`text-2xl font-semibold tabular-nums${alert ? " text-destructive" : ""}`}>{value}</p>
        )}
      </CardContent>
    </Card>
  );
}
