/**
 * SurveillanceCorrelations — vista cross-watchlist "Campañas".
 *
 * Backend: GET /api/surveillance/watchlist/correlations. Agrupa findings
 * por (kind + evidence_lower) y devuelve los clusters de ≥2 dominios.
 *
 * UI: lista priorizada por severity > domainCount. Cada campaña expone los
 * dominios afectados como chips clickeables que navegan al análisis
 * individual con el dominio pre-cargado vía prefetch.
 */

import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  Loader2,
  Network,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useWatchlistCorrelations, type WatchlistCampaign } from "@/hooks/useSurveillanceWorkspace";
import { useSurveillancePrefetch } from "@/hooks/useSurveillancePrefetch";
import { KIND_ICON, KIND_LABEL, KIND_TINT, SEVERITY_BADGE, SEVERITY_LABEL } from "@/components/digital-surveillance/findings/finding-styles";
import { cn } from "@/lib/utils";

export function SurveillanceCorrelationsPage() {
  const q = useWatchlistCorrelations();
  const prefetch = useSurveillancePrefetch();

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6 px-1 pb-12 sm:px-0">
      <motion.header
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className="space-y-2"
      >
        <div className="flex flex-wrap items-center gap-2">
          <Network className="h-7 w-7 text-primary" aria-hidden />
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">Campañas detectadas</h1>
          <Badge variant="cyber" className="font-normal">Cross-watchlist</Badge>
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
          Agrupa hallazgos que aparecen en{" "}
          <strong>≥2 dominios</strong> de la watchlist. Cluster por (tipo de
          finding + evidencia exacta) — IOC compartido, IP/host común, mismo
          email expuesto en credenciales. Si una "campaña" abarca varios dominios
          es indicio de un threat actor con foco específico.
        </p>
        {q.data && (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <CalendarClock className="h-3.5 w-3.5" aria-hidden />
            Analizados {q.data.analyzedDomains} / {q.data.totalDomains} dominio(s) bajo vigilancia.
          </p>
        )}
      </motion.header>

      {q.isLoading && (
        <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          Computando correlaciones cross-watchlist…
        </div>
      )}

      {q.isError && (
        <Card className="border-destructive/40 bg-destructive/5">
          <CardContent className="flex items-start gap-3 p-4 text-sm text-destructive">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
            <div>
              <p className="font-medium">Error al consultar correlaciones</p>
              <p className="text-destructive/80">
                {String(q.error?.message ?? q.error ?? "Error desconocido")}
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {q.data && q.data.totalDomains < 2 && (
        <Card className="border-dashed border-border/60">
          <CardContent className="flex items-start gap-3 p-5 text-sm text-muted-foreground">
            <Network className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
            <div className="space-y-1">
              <p className="font-medium text-foreground">Watchlist insuficiente para correlación</p>
              <p className="text-xs">
                Necesitás al menos 2 dominios bajo vigilancia para que aparezcan
                campañas. Agregá dominios desde{" "}
                <Link to="/vigilancia" className="text-primary hover:underline">
                  Vigilancia Digital
                </Link>.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {q.data && q.data.campaigns.length === 0 && q.data.totalDomains >= 2 && (
        <Card className="border-emerald-500/20 bg-emerald-500/[0.03]">
          <CardContent className="flex items-start gap-3 p-5">
            <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-500" aria-hidden />
            <div className="space-y-1">
              <p className="text-sm font-semibold">Sin campañas detectadas</p>
              <p className="text-xs leading-relaxed text-muted-foreground">
                Los {q.data.totalDomains} dominio(s) bajo vigilancia no comparten
                evidencias cruzadas hoy. Cada uno tiene findings particulares.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {q.data && q.data.campaigns.length > 0 && (
        <div className="space-y-3">
          {q.data.campaigns.map((c, i) => (
            <CampaignCard key={i} c={c} onHoverDomain={prefetch} />
          ))}
        </div>
      )}
    </div>
  );
}

function CampaignCard({
  c,
  onHoverDomain,
}: {
  c: WatchlistCampaign;
  onHoverDomain: (d: string) => void;
}) {
  const Icon = KIND_ICON[c.kind];
  return (
    <Card
      className={cn(
        "border-l-4",
        c.severity === "critical" ? "border-l-red-500 bg-red-500/[0.03]" :
        c.severity === "high"     ? "border-l-amber-500 bg-amber-500/[0.03]" :
                                    "border-l-border bg-card",
      )}
    >
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-start gap-3">
          <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted/50", KIND_TINT[c.kind])}>
            <Icon className="h-4 w-4" aria-hidden />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className={cn("h-5 text-[10px] font-bold uppercase tracking-wider", SEVERITY_BADGE[c.severity])}>
                {SEVERITY_LABEL[c.severity]}
              </Badge>
              <Badge variant="outline" className={cn("h-5 text-[10px]", KIND_TINT[c.kind])}>
                {KIND_LABEL[c.kind]}
              </Badge>
              <Badge variant="outline" className="h-5 border-primary/40 bg-primary/10 text-[10px] font-semibold text-primary">
                {c.domainCount} dominio(s)
              </Badge>
            </div>
            <h3 className="mt-1.5 text-sm font-semibold text-foreground">
              {c.sampleTitle ?? `Evidencia compartida ${c.kind}`}
            </h3>
            <p className="mt-0.5 break-all text-xs leading-relaxed text-muted-foreground">
              <span className="font-medium text-foreground/80">Evidencia:</span>{" "}
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">{c.evidence}</code>
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 border-t border-border/40 pt-3">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Dominios afectados
          </span>
          {c.domains.map((d) => (
            <Link
              key={d}
              to={`/vigilancia?domain=${encodeURIComponent(d)}`}
              onMouseEnter={() => onHoverDomain(d)}
              onFocus={() => onHoverDomain(d)}
              className="inline-flex items-center gap-1 rounded-md border border-border/60 bg-muted/30 px-2 py-0.5 font-mono text-[11px] font-medium text-foreground/80 transition-colors hover:border-primary/50 hover:bg-primary/5 hover:text-foreground"
            >
              {d}
            </Link>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
