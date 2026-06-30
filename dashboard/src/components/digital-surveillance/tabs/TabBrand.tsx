/**
 * TabBrand — inteligencia de marca unificada.
 *
 * Sustituye los antiguos TabMarca + TabMenciones (Sprint 6 del plan de
 * rediseño en `docs/MEJORA-VIGILANCIA.md`). Estructura del tab:
 *
 *   1. TabHeader con badges de fuente y refrescar.
 *   2. BrandAlertsBlock — alertas accionables (spike negativo, anomalía de
 *      volumen, menciones de alto reach con CTA SOC).
 *   3. KPI grid 4 columnas: Volumen · Alcance · Sentimiento · AVE.
 *      El KPI de Sentimiento es cliqueable y filtra el feed.
 *   4. Sentiment donut + Volumen timeline (stacked por sentimiento) lado a lado.
 *   5. BrandFeed — feed unificado con filtros (sentimiento/fuente/autor/orden).
 *   6. VoiceSplit — críticos vs aliados.
 *   7. Sitios influyentes + Categorías.
 *   8. Hashtags en tendencia.
 *
 * Datos: vía Provider — el tab consume `data` (snapshot) y `brand24` (resultado
 * social listening) del context. El feed usa estado local con `useBrandFeedState`.
 */

import { Megaphone, RefreshCw, Settings } from "lucide-react";
import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Legend,
  Line,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { TabHeader } from "@/components/digital-surveillance/shared/TabHeader";
import { NoResults, SourceError, SourceNotConfigured } from "@/components/digital-surveillance/shared/source-states";
import { formatCompactNumber } from "@/components/digital-surveillance/shared/format";
import { Brand24SourceBadge } from "@/components/digital-surveillance/shared/brand/source-badge";
import {
  Brand24PdfImporter,
  Brand24PdfReplaceButton,
} from "@/components/digital-surveillance/shared/brand/pdf-importer";
import { ExecutivePanel } from "@/components/digital-surveillance/executive-brand/ExecutivePanel";
import { BrandThreatsBlock } from "@/components/digital-surveillance/shared/BrandThreatsBlock";
import { DeltaBadge } from "@/components/digital-surveillance/shared/brand/delta-badge";
import { BrandAlertsBlock, computeBrandAlerts } from "@/components/digital-surveillance/shared/brand/alerts";
import { BrandFeed } from "@/components/digital-surveillance/shared/brand/feed";
import { VoiceSplit } from "@/components/digital-surveillance/shared/brand/voices";
import { useBrandFeedState } from "@/components/digital-surveillance/shared/brand/feed-state";
import { buildStackedTimeline } from "@/components/digital-surveillance/shared/brand/timeline";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useDigitalSurveillanceBrand24 } from "@/hooks/useDigitalSurveillance";
import type { Brand24Sentiment } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

export function TabBrand() {
  const { data, brandThreats } = useSurveillance();
  const domain = data?.domain ?? "";
  const brand24Q = useDigitalSurveillanceBrand24(domain);
  const { filters, setFilter, visibleCount, loadMore, reset } = useBrandFeedState();

  // Hooks derivados — siempre antes de cualquier early-return (React #310).
  const brand24Mentions = brand24Q.data?.mentions;
  const brand24TimelinePrev = brand24Q.data?.summary?.timeline;
  const stackedTimeline = useMemo(
    () => buildStackedTimeline(brand24Mentions ?? [], brand24TimelinePrev),
    [brand24Mentions, brand24TimelinePrev],
  );

  if (!data) return null;

  const toggleSentiment = (target: Brand24Sentiment) => {
    setFilter({ sentiment: filters.sentiment === target ? "all" : target });
  };

  if (brand24Q.isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="border-border/60">
              <CardContent className="p-4">
                <div className="h-3 w-24 animate-pulse rounded bg-muted" />
                <div className="mt-2 h-7 w-20 animate-pulse rounded bg-muted" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (brand24Q.isError) {
    return (
      <SourceError
        error={brand24Q.error instanceof Error ? brand24Q.error.message : "Error consultando Brand24."}
      />
    );
  }

  const brand24 = brand24Q.data;

  // Sin proyecto Brand24 configurado en DB y sin snapshot disponible.
  if (!brand24 || (brand24.projectId === null && !brand24.summary)) {
    const apiKeyConfigured = data.brand24.configured;
    return (
      <div className="space-y-4">
        {apiKeyConfigured ? (
          <Card className="border-amber-500/40 bg-amber-500/[0.04]">
            <CardContent className="flex items-start gap-3 p-5">
              <Settings className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
              <div className="space-y-1">
                <p className="text-sm font-semibold">
                  Brand24 sin proyecto asignado para <code className="font-mono">{domain}</code>
                </p>
                <p className="text-xs text-muted-foreground">
                  La clave global está configurada pero este dominio no tiene un{" "}
                  <code className="rounded bg-muted px-1 font-mono">project_id</code> en{" "}
                  <code className="rounded bg-muted px-1 font-mono">brand24_projects</code>. Brand24 trabaja con
                  proyectos (keywords + idioma + exclusiones), no con dominios — usá el panel admin para
                  asociar uno, o importá un PDF para tener un snapshot offline.
                </p>
              </div>
            </CardContent>
          </Card>
        ) : (
          <SourceNotConfigured name="Brand24 (Social Listening)" envKey="BRAND24_API_KEY" />
        )}

        <Brand24PdfImporter domain={domain} />

        <Card className="border-border/60">
          <CardContent className="space-y-2 p-5 text-sm text-muted-foreground">
            <p className="font-medium text-foreground">¿Qué ofrece Brand24?</p>
            <ul className="list-inside list-disc space-y-1 text-xs">
              <li>Monitoreo de menciones en redes sociales, noticias y foros en tiempo real</li>
              <li>Análisis de sentimiento (positivo / neutro / negativo)</li>
              <li>Share of Voice vs. competidores</li>
              <li>Detección de influencers relevantes</li>
              <li>Alertas de crisis reputacional</li>
            </ul>
            <p className="pt-2 text-xs">
              Obtené una clave en{" "}
              <a
                href="https://app.brand24.com/settings/api"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline-offset-4 hover:underline"
              >
                app.brand24.com/settings/api
              </a>
              {" "}o usá el importador de PDF para alimentar la pestaña con un export del trial.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Tenemos snapshot o data live: renderizar los bloques.
  const summary = brand24.summary;
  const sentimentTotal = summary
    ? summary.positiveCount + summary.negativeCount
    : 0;
  const negativeRatio = sentimentTotal > 0
    ? summary!.negativeCount / sentimentTotal
    : 0;

  const sentimentData = summary
    ? [
        { name: "Positivas", value: summary.positiveCount, color: "#10b981" },
        { name: "Negativas", value: summary.negativeCount, color: "#ef4444" },
      ]
    : [];

  const categoryData = summary?.byCategory ?? [];
  const timelineData = summary?.timeline ?? [];

  const alerts = computeBrandAlerts(brand24);
  const projectBadge = brand24.projectId ? (
    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
      project: {brand24.projectId}
    </code>
  ) : null;

  return (
    <div className="space-y-6">
      <TabHeader
        icon={Megaphone}
        title="Inteligencia de marca"
        domain={brand24.domain || domain}
        badges={
          <>
            {projectBadge}
            <Brand24SourceBadge data={brand24} />
          </>
        }
        freshness={{
          fetchedAt: brand24.fetchedAt ?? null,
          ttlLabel: brand24.fromCache ? "desde caché" : null,
        }}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Brand24PdfReplaceButton domain={domain} />
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-8 gap-1.5 text-xs"
              onClick={() => brand24Q.refetch()}
              disabled={brand24Q.isFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", brand24Q.isFetching && "animate-spin")} aria-hidden />
              Refrescar
            </Button>
          </div>
        }
      />

      {/* Panel ejecutivo — heurísticas TS sobre el snapshot. Va arriba para
          que el analista lea conclusión antes del detalle. Si no hay summary,
          el panel se autocensura. */}
      <ExecutivePanel data={brand24} />

      {/* DRP — Fase 3 §9.5: Amenazas en Tiempo Real (CT/typo/phishing/velocity)
          se muestran ARRIBA del feed Brand24 porque son la señal más urgente. */}
      <BrandThreatsBlock domain={domain} threats={brandThreats} />

      <BrandAlertsBlock domain={domain} alerts={alerts} />

      {!summary && (
        <NoResults message="Sin resumen disponible para este dominio. Importá un PDF de Brand24 para alimentar este panel." />
      )}

      {summary && (
        <>
          {/* KPI grid (4 cards) */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Card className="border-border/70">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-muted-foreground">Volumen</p>
                  <DeltaBadge value={summary.volumeDeltaPercent} />
                </div>
                <p className="mt-1 text-2xl font-bold tabular-nums">
                  {formatCompactNumber(summary.volumeMentions)}
                </p>
                <p className="text-[10px] text-muted-foreground">menciones</p>
              </CardContent>
            </Card>

            <Card className="border-border/70">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground">Alcance</p>
                <p className="mt-1 text-2xl font-bold tabular-nums">
                  {formatCompactNumber(summary.socialReach + summary.nonSocialReach)}
                </p>
                <p className="text-[10px] text-muted-foreground">
                  social {formatCompactNumber(summary.socialReach)} · web {formatCompactNumber(summary.nonSocialReach)}
                </p>
              </CardContent>
            </Card>

            <Card
              role="button"
              tabIndex={0}
              onClick={() => toggleSentiment("negative")}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggleSentiment("negative");
                }
              }}
              className={cn(
                "cursor-pointer border-border/70 transition-colors hover:border-primary/40",
                negativeRatio >= 0.6 && "border-red-500/40 bg-red-500/[0.04]",
                filters.sentiment === "negative" && "ring-2 ring-primary/40",
              )}
              title="Click para filtrar el feed por menciones negativas"
            >
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground">Sentimiento</p>
                <p className={cn(
                  "mt-1 text-2xl font-bold tabular-nums",
                  negativeRatio >= 0.6 && "text-red-600 dark:text-red-400",
                )}>
                  {sentimentTotal > 0 ? `${Math.round(negativeRatio * 100)}%` : "—"}
                </p>
                <p className="text-[10px] text-muted-foreground">
                  negativas ({summary.negativeCount}/{sentimentTotal || "—"})
                </p>
              </CardContent>
            </Card>

            <Card className="border-border/70">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground">AVE</p>
                <p className="mt-1 text-2xl font-bold tabular-nums">
                  ${formatCompactNumber(summary.ave)}
                </p>
                <p className="text-[10px] text-muted-foreground">valor publicitario equivalente</p>
              </CardContent>
            </Card>
          </div>

          {/* Sentiment donut + Volumen timeline lado a lado */}
          <div className="grid gap-3 lg:grid-cols-2">
            {sentimentTotal > 0 && (
              <Card className="border-border/60">
                <CardHeader className="pb-1">
                  <CardTitle className="text-sm">Sentimiento polarizado</CardTitle>
                </CardHeader>
                <CardContent className="pt-2">
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie
                        data={sentimentData}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={45}
                        outerRadius={70}
                        paddingAngle={2}
                        cursor="pointer"
                        onClick={(_d: unknown, idx: number) => {
                          const target = sentimentData[idx]?.name === "Negativas" ? "negative" : "positive";
                          toggleSentiment(target);
                        }}
                      >
                        {sentimentData.map((entry, idx) => (
                          <Cell key={idx} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{ fontSize: 11 }}
                        formatter={(v: number, name) => [`${v}`, name]}
                      />
                      <Legend wrapperStyle={{ fontSize: 11 }} />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            )}

            {(stackedTimeline.length > 0 || timelineData.length > 0) && (
              <Card className="border-border/60">
                <CardHeader className="pb-1">
                  <CardTitle className="text-sm">
                    {stackedTimeline.length > 0
                      ? "Volumen por sentimiento — actual vs anterior"
                      : "Volumen — actual vs período anterior"}
                  </CardTitle>
                  {stackedTimeline.length > 0 && (
                    <p className="text-[11px] text-muted-foreground">
                      Barras stacked por sentimiento del feed actual; línea punteada gris = período anterior.
                    </p>
                  )}
                </CardHeader>
                <CardContent className="pt-2">
                  <ResponsiveContainer width="100%" height={180}>
                    {stackedTimeline.length > 0 ? (
                      <ComposedChart data={stackedTimeline} margin={{ top: 4, right: 8, left: 0, bottom: 24 }}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-border/40" />
                        <XAxis dataKey="date" tick={{ fontSize: 9 }} angle={-45} textAnchor="end" />
                        <YAxis tick={{ fontSize: 9 }} />
                        <RechartsTooltip contentStyle={{ fontSize: 11 }} />
                        <Legend wrapperStyle={{ fontSize: 11 }} />
                        <Bar dataKey="negative" stackId="s" name="Negativas" fill="#ef4444" />
                        <Bar dataKey="neutral"  stackId="s" name="Neutras"   fill="#94a3b8" />
                        <Bar dataKey="positive" stackId="s" name="Positivas" fill="#10b981" radius={[2, 2, 0, 0]} />
                        <Line
                          type="monotone"
                          dataKey="previous"
                          name="Anterior"
                          stroke="#64748b"
                          strokeDasharray="3 3"
                          dot={false}
                          isAnimationActive={false}
                        />
                      </ComposedChart>
                    ) : (
                      <BarChart data={timelineData} margin={{ top: 4, right: 8, left: 0, bottom: 24 }}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-border/40" />
                        <XAxis dataKey="date" tick={{ fontSize: 9 }} angle={-45} textAnchor="end" />
                        <YAxis tick={{ fontSize: 9 }} />
                        <RechartsTooltip contentStyle={{ fontSize: 11 }} />
                        <Legend wrapperStyle={{ fontSize: 11 }} />
                        <Bar dataKey="previous" name="Anterior" fill="#94a3b8" radius={[2, 2, 0, 0]} />
                        <Bar dataKey="current"  name="Actual"   fill="#3b82f6" radius={[2, 2, 0, 0]} />
                      </BarChart>
                    )}
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Feed unificado de menciones (§3.2.5) */}
          <BrandFeed
            domain={domain}
            data={brand24}
            filters={filters}
            setFilter={setFilter}
            visibleCount={visibleCount}
            loadMore={loadMore}
            reset={reset}
          />

          {/* Voces — críticos vs aliados (Sprint 3 §3.2.6) */}
          <VoiceSplit
            mentions={brand24.mentions ?? []}
            filters={filters}
            setFilter={setFilter}
          />

          {/* Sitios influyentes + Categorías (lado a lado) */}
          <div className="grid gap-3 lg:grid-cols-2">
            {brand24.sites.length > 0 && (
              <Card className="border-border/60">
                <CardHeader className="pb-1">
                  <CardTitle className="text-sm">Sitios más influyentes</CardTitle>
                  <p className="text-[11px] text-muted-foreground">
                    Click sobre un sitio para filtrar el feed por su dominio.
                  </p>
                </CardHeader>
                <CardContent className="pt-2">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Dominio</TableHead>
                          <TableHead className="text-right">Menc.</TableHead>
                          <TableHead className="text-right">Visitas</TableHead>
                          <TableHead className="text-right">Score</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {brand24.sites.slice(0, 10).map((s, i) => {
                          const active = filters.query === s.domain;
                          return (
                            <TableRow
                              key={`${s.domain}-${i}`}
                              onClick={() => setFilter({ query: active ? "" : s.domain })}
                              className={cn(
                                "cursor-pointer transition-colors hover:bg-muted/30",
                                active && "bg-primary/5",
                              )}
                              title={`Filtrar feed por sitio: ${s.domain}`}
                            >
                              <TableCell className="font-mono text-xs">{s.domain}</TableCell>
                              <TableCell className="text-right text-xs tabular-nums">{s.mentions}</TableCell>
                              <TableCell className="text-right text-xs tabular-nums">
                                {s.visits != null ? formatCompactNumber(s.visits) : "—"}
                              </TableCell>
                              <TableCell className="text-right text-xs tabular-nums">
                                {s.influenceScore != null ? s.influenceScore.toFixed(1) : "—"}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            )}

            {categoryData.length > 0 && (
              <Card className="border-border/60">
                <CardHeader className="pb-1">
                  <CardTitle className="text-sm">Menciones por categoría</CardTitle>
                  <p className="text-[11px] text-muted-foreground">
                    Click sobre una categoría para filtrar el feed por esa fuente.
                  </p>
                </CardHeader>
                <CardContent className="pt-2">
                  <div className="space-y-2">
                    {categoryData.map((c) => {
                      const max = Math.max(...categoryData.map((x) => x.count));
                      const pct = max > 0 ? (c.count / max) * 100 : 0;
                      const active = filters.source === c.category;
                      return (
                        <button
                          key={c.category}
                          type="button"
                          onClick={() => setFilter({ source: active ? "all" : c.category })}
                          className={cn(
                            "block w-full space-y-0.5 rounded-md p-1 text-left transition-colors hover:bg-muted/40",
                            active && "bg-primary/5 ring-1 ring-primary/30",
                          )}
                          title={`Filtrar feed por fuente: ${c.category}`}
                        >
                          <div className="flex items-center justify-between gap-2 text-xs">
                            <span className="font-medium">{c.category}</span>
                            <div className="flex items-center gap-2">
                              <span className="tabular-nums text-muted-foreground">
                                {formatCompactNumber(c.count)}
                              </span>
                              <DeltaBadge value={c.deltaPercent} />
                            </div>
                          </div>
                          <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                            <div
                              className="h-full rounded-full bg-primary"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Trending hashtags */}
          {brand24.hashtags.length > 0 && (
            <Card className="border-border/60">
              <CardHeader className="pb-1">
                <CardTitle className="text-sm">Hashtags en tendencia</CardTitle>
              </CardHeader>
              <CardContent className="pt-2">
                <div className="flex flex-wrap gap-1.5">
                  {brand24.hashtags.slice(0, 30).map((h, i) => {
                    const active = filters.query === h.tag;
                    return (
                      <button
                        key={`${h.tag}-${i}`}
                        type="button"
                        onClick={() => setFilter({ query: active ? "" : h.tag })}
                        title={`Filtrar feed por hashtag: ${h.tag}`}
                      >
                        <Badge
                          variant="outline"
                          className={cn(
                            "cursor-pointer font-mono text-[10px] transition-colors hover:border-primary/40",
                            active && "border-primary/60 bg-primary/10 text-primary",
                          )}
                        >
                          {h.tag}
                          <span className="ml-1 text-muted-foreground">· {h.mentions}</span>
                        </Badge>
                      </button>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
