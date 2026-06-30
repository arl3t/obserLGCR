/**
 * TabReporte — vista consolidada del dominio con modo print-friendly.
 *
 * Único tab que mantiene la lógica de exportación PDF (recibe `onExportPdf`
 * como prop desde la página, donde vive `handleExportPdf` con datos del
 * Provider). El layout usa `print:break-inside-avoid` y `print:hidden` para
 * que `window.print()` produzca un reporte ejecutivo legible en papel.
 *
 * Secciones:
 *   1. Resumen ejecutivo (KPIs por fuente + factores de riesgo).
 *   2. Análisis — infraestructura expuesta (Shodan).
 *   3. MISP Threat Intelligence.
 *   4. Noticias RSS y menciones.
 *   5. Vigilancia de marca (Brand24 — placeholder hasta que F4 backend exista).
 *   6. Credenciales filtradas (condicional — solo si hay snapshot que cubre).
 */

import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Download,
  ExternalLink,
  KeyRound,
  Megaphone,
  Network,
  Newspaper,
  Printer,
  Radio,
  Settings,
  Shield,
  ShieldAlert,
} from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { NewsSourceBadge } from "@/components/digital-surveillance/shared/news-source-badge";
import { NoResults, SourceError, SourceNotConfigured } from "@/components/digital-surveillance/shared/source-states";
import { bandBadge, bandBorder } from "@/components/digital-surveillance/shared/band-styles";
import { portBand } from "@/components/digital-surveillance/shared/port-band";
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
import { bandFromScore } from "@/components/digital-surveillance/risk-engine/calculateRiskScore";
import { riskLabelEs } from "@/lib/digital-surveillance-api";
import { formatDateTimePy, formatDatePy, PY_TZ } from "@/lib/format";
import type { RiskBand, SurveillanceMispHit } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Sub-componente
// ─────────────────────────────────────────────────────────────────────────────

function RptSection({
  title,
  icon,
  count,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-3 print:break-inside-avoid">
      <div className="flex items-center gap-2 border-b border-border/60 pb-2">
        <span className="shrink-0 text-primary">{icon}</span>
        <h2 className="text-base font-bold tracking-tight">{title}</h2>
        {count != null && (
          <Badge variant="outline" className="ml-auto text-[10px]">{count}</Badge>
        )}
      </div>
      {children}
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Componente
// ─────────────────────────────────────────────────────────────────────────────

export function TabReporte({ onExportPdf }: { onExportPdf: () => void }) {
  const { data, rss, snapshot, hasCoverage, emailCount, infraCount } = useSurveillance();

  if (!data) return null;
  const { risk, shodan, misp, brand24 } = data;

  const rssItems    = rss?.items  ?? [];
  const rssCustom   = (rss?.custom ?? []).filter((i) => i.matched);
  const allMentions = [...rssItems, ...rssCustom];
  const rssGeneral  = (rss?.general ?? []).slice(0, 8);

  const sourcesActive = [
    shodan.configured && !shodan.error,
    misp.configured   && !misp.error,
  ].filter(Boolean).length;

  return (
    <div className="space-y-8 print:space-y-6" id="vigilancia-report">

      {/* ── Toolbar (oculto en impresión) ────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 print:hidden">
        <p className="text-sm text-muted-foreground">
          Reporte consolidado del dominio consultado — todos los módulos de vigilancia.
        </p>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={() => window.print()}>
            <Printer className="h-3.5 w-3.5" aria-hidden />
            Imprimir
          </Button>
          <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={onExportPdf}>
            <Download className="h-3.5 w-3.5" aria-hidden />
            Exportar PDF
          </Button>
        </div>
      </div>

      {/* ── Cabecera del reporte ─────────────────────────────────────────────── */}
      <div className={cn(
        "rounded-xl border-l-4 p-5",
        risk.band === "high"   ? "border-l-red-500    bg-red-500/[0.03]"    :
        risk.band === "medium" ? "border-l-amber-500  bg-amber-500/[0.03]"  :
                                 "border-l-emerald-500 bg-emerald-500/[0.03]",
      )}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:gap-6">
          <div className={cn(
            "flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl text-2xl font-bold tabular-nums",
            risk.band === "high"   ? "bg-red-500/15    text-red-600    dark:text-red-400"    :
            risk.band === "medium" ? "bg-amber-500/15  text-amber-600  dark:text-amber-400"  :
                                     "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
          )}>
            {risk.score}
          </div>
          <div className="flex-1">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              LegacyHunt SOC — Vigilancia Digital
            </p>
            <p className="mt-0.5 text-xl font-bold">{data.domain}</p>
            <p className="text-xs text-muted-foreground">
              Riesgo{" "}
              <span className={cn("font-semibold",
                risk.band === "high"   ? "text-red-600    dark:text-red-400"    :
                risk.band === "medium" ? "text-amber-600  dark:text-amber-400"  :
                                         "text-emerald-600 dark:text-emerald-400",
              )}>
                {riskLabelEs(risk.band)} ({risk.score}/100)
              </span>
              {" · "}{sourcesActive} fuente(s) activa(s)
              {" · "}
              <span className="font-mono">{formatDateTimePy(data.queriedAt)}</span>
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {shodan.configured  && <Badge variant="outline" className="gap-1 text-[10px]"><Radio      className="h-3 w-3" />Shodan</Badge>}
            {misp.configured    && <Badge variant="outline" className="gap-1 text-[10px]"><Shield     className="h-3 w-3" />MISP</Badge>}
            {brand24.configured && <Badge variant="outline" className="gap-1 text-[10px]"><Megaphone  className="h-3 w-3" />Brand24</Badge>}
          </div>
        </div>
      </div>

      {/* ── 1. Resumen Ejecutivo ─────────────────────────────────────────────── */}
      <RptSection title="Resumen Ejecutivo" icon={<Activity className="h-4 w-4" />}>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[
            {
              label: "Hosts en Shodan",
              value: shodan.configured ? (shodan.total ?? 0) : null,
              icon:  <Network className="h-4 w-4" />,
              color: (shodan.total ?? 0) > 0 ? "text-amber-500  bg-amber-500/10"  : "text-muted-foreground bg-muted",
            },
            {
              label: "IOCs en MISP",
              value: misp.configured ? (misp.count ?? 0) : null,
              icon:  <ShieldAlert className="h-4 w-4" />,
              color: (misp.count ?? 0) > 0 ? "text-red-500    bg-red-500/10"    : "text-muted-foreground bg-muted",
            },
            {
              label: "Menciones RSS",
              value: allMentions.length,
              icon:  <Newspaper className="h-4 w-4" />,
              color: allMentions.length > 0 ? "text-blue-500 bg-blue-500/10" : "text-muted-foreground bg-muted",
            },
          ].map((k) => (
            <Card key={k.label} className="border-border/70">
              <CardContent className="flex items-center gap-3 p-4">
                <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-lg", k.color)}>
                  {k.icon}
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{k.label}</p>
                  <p className="text-2xl font-bold tabular-nums">{k.value ?? "—"}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {risk.factors.length > 0 ? (
          <div className="space-y-2 pt-2">
            <p className="flex items-center gap-2 text-sm font-semibold">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              Factores de riesgo detectados
            </p>
            {risk.factors.map((f) => {
              const band: RiskBand = bandFromScore(f.score);
              return (
                <div key={f.id} className={cn("rounded-xl border border-border/60 border-l-4 p-4", bandBorder[band])}>
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold">{f.title}</p>
                    <Badge variant="outline" className={cn("text-[10px]", bandBadge[band])}>
                      {f.score} pts
                    </Badge>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{f.detail}</p>
                </div>
              );
            })}
          </div>
        ) : (
          <Card className="border-emerald-500/20 bg-emerald-500/[0.03]">
            <CardContent className="flex items-center gap-3 p-4">
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
              <p className="text-sm">Sin factores de riesgo detectados en las fuentes activas.</p>
            </CardContent>
          </Card>
        )}
      </RptSection>

      {/* ── 2. Análisis de Riesgos — Infraestructura Expuesta ───────────────── */}
      <RptSection
        title="Análisis de Riesgos — Infraestructura Expuesta"
        icon={<BarChart3 className="h-4 w-4" />}
        count={shodan.configured ? (shodan.total ?? 0) : undefined}
      >
        {!shodan.configured ? (
          <SourceNotConfigured name="Shodan" envKey="SHODAN_API_KEY" />
        ) : shodan.error ? (
          <SourceError error={shodan.error} />
        ) : (shodan.matches ?? []).length === 0 ? (
          <NoResults message="Sin hosts visibles en Shodan para este dominio." />
        ) : (
          <Card className="border-border/70">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">
                {shodan.total} host(s) · <code className="font-mono">{data.domain}</code>
                {(shodan.total ?? 0) > 50 && " · primeros 50"}
              </CardTitle>
            </CardHeader>
            <CardContent className="overflow-x-auto p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead>Hostname</TableHead>
                    <TableHead className="text-right">Puerto</TableHead>
                    <TableHead>Producto</TableHead>
                    <TableHead>País</TableHead>
                    <TableHead>Riesgo</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(shodan.matches ?? []).map((m, i) => (
                    <TableRow key={`rpt-sh-${m.ip}-${m.port}-${i}`}>
                      <TableCell className="font-mono text-xs">{m.ip ?? "—"}</TableCell>
                      <TableCell className="max-w-[140px] truncate text-xs text-muted-foreground">
                        {m.hostnames.slice(0, 2).join(", ") || "—"}
                      </TableCell>
                      <TableCell className="text-right tabular-nums font-medium">{m.port ?? "—"}</TableCell>
                      <TableCell className="text-xs">{m.product ?? "—"}</TableCell>
                      <TableCell className="text-xs">{m.country ?? "—"}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={cn("text-[10px]", bandBadge[portBand(m.port)])}>
                          {riskLabelEs(portBand(m.port))}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </RptSection>

      {/* ── 3. MISP Threat Intelligence ──────────────────────────────────────── */}
      <RptSection
        title="MISP Threat Intelligence"
        icon={<Shield className="h-4 w-4" />}
        count={misp.count || undefined}
      >
        <div className="space-y-2">
          <p className="flex items-center gap-2 text-sm font-semibold">
            <Shield className="h-3.5 w-3.5 text-primary" />
            MISP —{" "}
            {misp.configured ? `${misp.count ?? 0} atributo(s) (últimos 90 días)` : "No configurado"}
          </p>
          {!misp.configured ? (
            <SourceNotConfigured name="MISP" envKey="MISP_BASE_URL + MISP_API_KEY" />
          ) : misp.error ? (
            <SourceError error={misp.error} />
          ) : (misp.hits ?? []).length === 0 ? (
            <NoResults message={`Sin atributos en MISP para "${data.domain}" en los últimos 90 días.`} />
          ) : (
            <Card className="border-border/70">
              <CardContent className="overflow-x-auto p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Valor</TableHead>
                      <TableHead>Categoría</TableHead>
                      <TableHead>Evento</TableHead>
                      <TableHead>Tags</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(misp.hits ?? []).map((hit: SurveillanceMispHit) => (
                      <TableRow key={`rpt-misp-${hit.uuid ?? hit.id}`}>
                        <TableCell>
                          <Badge variant="outline" className="font-mono text-[10px]">{hit.type}</Badge>
                        </TableCell>
                        <TableCell className="max-w-[160px] truncate font-mono text-xs">{hit.value}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{hit.category}</TableCell>
                        <TableCell className="max-w-[140px] truncate text-xs">
                          {hit.event_title ?? hit.event_id ?? "—"}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {(hit.tags ?? []).slice(0, 2).map((t: string) => (
                              <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </div>
      </RptSection>

      {/* ── 4. Noticias RSS y Menciones ──────────────────────────────────────── */}
      <RptSection
        title="Noticias RSS y Menciones"
        icon={<Newspaper className="h-4 w-4" />}
        count={allMentions.length || undefined}
      >
        {!rss ? (
          <NoResults message="Datos RSS no disponibles. Consulta la pestaña Noticias RSS para cargarlos." />
        ) : allMentions.length === 0 ? (
          <NoResults message={`Sin menciones directas de "${data.domain}" en los feeds consultados.`} />
        ) : (
          <div className="space-y-2">
            {allMentions.slice(0, 15).map((item, i) => (
              <div
                key={`rpt-news-${i}`}
                className="flex items-start gap-3 rounded-xl border border-l-4 border-amber-500/20 border-l-amber-500 bg-amber-500/[0.03] p-3"
              >
                <div className="flex-1 space-y-0.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <NewsSourceBadge source={item.source} />
                    {item.publishedAt && (
                      <span className="text-[10px] text-muted-foreground">
                        {formatDatePy(item.publishedAt)}
                      </span>
                    )}
                    <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-400">
                      mención directa
                    </span>
                  </div>
                  <p className="text-sm font-medium leading-snug">{item.title}</p>
                  {item.snippet && (
                    <p className="line-clamp-2 text-xs text-muted-foreground">{item.snippet}</p>
                  )}
                </div>
                {item.url && (
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-0.5 shrink-0 text-muted-foreground hover:text-foreground"
                  >
                    <ExternalLink className="h-4 w-4" />
                  </a>
                )}
              </div>
            ))}
          </div>
        )}

        {rssGeneral.length > 0 && (
          <details className="rounded-xl border border-border/50">
            <summary className="flex cursor-pointer items-center gap-1.5 px-4 py-3 text-xs font-medium text-muted-foreground hover:text-foreground">
              <Shield className="h-3.5 w-3.5" />
              Noticias de seguridad generales ({rssGeneral.length})
            </summary>
            <div className="space-y-2 px-4 pb-4">
              {rssGeneral.map((item, i) => (
                <div key={`rpt-gen-${i}`} className="flex items-start gap-3 rounded-lg border border-border/40 p-3">
                  <div className="flex-1 space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <NewsSourceBadge source={item.source} />
                      {item.publishedAt && (
                        <span className="text-[10px] text-muted-foreground">
                          {formatDatePy(item.publishedAt)}
                        </span>
                      )}
                    </div>
                    <p className="text-sm font-medium leading-snug">{item.title}</p>
                  </div>
                  {item.url && (
                    <a href={item.url} target="_blank" rel="noopener noreferrer"
                      className="mt-0.5 shrink-0 text-muted-foreground hover:text-foreground">
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  )}
                </div>
              ))}
            </div>
          </details>
        )}

        {rss && (
          <p className="text-[11px] text-muted-foreground/60">
            Última consulta RSS:{" "}
            <span className="font-mono">{new Date(rss.fetchedAt).toLocaleTimeString("es-ES", { timeZone: PY_TZ })}</span>
            {rss.fromCache && " · desde caché"}
            {" · "}Google News · SANS ISC · THN · Bleeping Computer + feeds configurados
          </p>
        )}
      </RptSection>

      {/* ── 5. Vigilancia de Marca & Menciones ──────────────────────────────── */}
      <RptSection title="Vigilancia de Marca & Menciones" icon={<Megaphone className="h-4 w-4" />}>
        {!brand24.configured ? (
          <div className="space-y-3">
            <SourceNotConfigured name="Brand24 (Social Listening)" envKey="BRAND24_API_KEY" />
            <p className="text-xs text-muted-foreground">
              Brand24 monitorea menciones en redes sociales, noticias y foros con análisis de sentimiento
              en tiempo real. Configura{" "}
              <code className="rounded bg-muted px-1 font-mono">BRAND24_API_KEY</code> para activar este módulo.
            </p>
          </div>
        ) : (
          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="flex items-start gap-3 p-4">
              <Settings className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <p className="text-sm text-muted-foreground">
                Brand24 configurado — integración de menciones y análisis de sentimiento en desarrollo.
              </p>
            </CardContent>
          </Card>
        )}
      </RptSection>

      {/* ── 6. Credenciales filtradas (condicional) ──────────────────────────── */}
      {hasCoverage && snapshot && (
        <RptSection title="Credenciales Filtradas" icon={<KeyRound className="h-4 w-4" />}>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { label: "Emails detectados",  value: emailCount },
              { label: "Usuarios en riesgo", value: snapshot.riskyUsersCount ?? 0 },
              { label: "Contraseñas débiles", value: `${snapshot.weakPwdRate ?? 0}%` },
              { label: "Filas infraestructura", value: infraCount },
            ].map((k) => (
              <Card key={k.label} className="border-border/70">
                <CardContent className="p-4">
                  <p className="text-xs text-muted-foreground">{k.label}</p>
                  <p className="text-2xl font-bold tabular-nums">{k.value}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {(snapshot.criticalServices ?? []).length > 0 && (
            <Card className="border-red-500/20 bg-red-500/[0.02]">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm text-destructive">
                  <AlertTriangle className="h-4 w-4" />
                  Servicios críticos comprometidos
                </CardTitle>
              </CardHeader>
              <CardContent className="overflow-x-auto p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Servicio</TableHead>
                      <TableHead className="text-right">Registros</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(snapshot.criticalServices ?? []).map((s) => (
                      <TableRow key={s.service}>
                        <TableCell className="text-xs font-medium">{s.service}</TableCell>
                        <TableCell className="text-right tabular-nums text-xs">{s.hits}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {(snapshot.perUserExposure ?? []).length > 0 && (
            <Card className="border-border/70">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Top usuarios expuestos</CardTitle>
              </CardHeader>
              <CardContent className="overflow-x-auto p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Email</TableHead>
                      <TableHead className="text-right">Registros</TableHead>
                      <TableHead className="text-right">Pwds únicas</TableHead>
                      <TableHead>Servicios</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(snapshot.perUserExposure ?? []).slice(0, 15).map((u) => (
                      <TableRow key={u.email}>
                        <TableCell className="max-w-[180px] truncate font-mono text-xs">{u.email}</TableCell>
                        <TableCell className="text-right tabular-nums text-xs">{u.hits}</TableCell>
                        <TableCell className="text-right tabular-nums text-xs">{u.uniquePwds}</TableCell>
                        <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                          {u.topServices.slice(0, 3).join(", ")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          <p className="text-[11px] text-muted-foreground/60">
            Fuente: <span className="font-mono">{snapshot.sourceLabel}</span>
          </p>
        </RptSection>
      )}
    </div>
  );
}
