/**
 * BrandThreatsBlock — feed unificado "Amenazas en Tiempo Real" (Fase 3 §9.5).
 *

 * Muestra las correlaciones cross-source primero (cuando aplican), luego el
 * feed plano de threats individuales agrupados visualmente por kind. Cada
 * item incluye severity badge, kind label, target, detectedAt relativo y
 * source.
 *
 * El componente es shared porque puede consumirse desde TabBrand (sección
 * principal) o desde el TabEjecutivo si se quiere insertar abajo en el futuro.
 */

import {
  AlertTriangle,
  ExternalLink,
  Globe2,
  KeyRound,
  Radar,
  Skull,
  TrendingUp,
} from "lucide-react";
import { useState } from "react";
import {
  OpenSocCaseButton,
} from "@/components/digital-surveillance/shared/OpenSocCaseButton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type {
  BrandThreat,
  CorrelationFinding,
  SurveillanceBrandThreats,
  ThreatKind,
  ThreatSeverity,
} from "@/types/digital-surveillance";
import { formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Estilos por severity / kind
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<ThreatSeverity, string> = {
  critical: "border-red-500/50 bg-red-500/10 text-red-700 dark:text-red-400",
  high:     "border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-400",
  medium:   "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-400",
  low:      "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
};

const SEVERITY_BORDER: Record<ThreatSeverity, string> = {
  critical: "border-l-red-500    bg-red-500/[0.04]",
  high:     "border-l-orange-500 bg-orange-500/[0.03]",
  medium:   "border-l-amber-500  bg-amber-500/[0.03]",
  low:      "border-l-emerald-500 bg-emerald-500/[0.02]",
};

const SEVERITY_LABEL: Record<ThreatSeverity, string> = {
  critical: "Crítico",
  high:     "Alto",
  medium:   "Medio",
  low:      "Bajo",
};

const KIND_ICON: Record<ThreatKind, React.ComponentType<{ className?: string }>> = {
  "ct-impersonation":          Radar,
  "typosquatting":              Globe2,
  "leak-velocity":              KeyRound,
  "phishing-kit":               Skull,
  "impersonation-confidence":   AlertTriangle,
};

const KIND_LABEL: Record<ThreatKind, string> = {
  "ct-impersonation":          "CT cert",
  "typosquatting":              "Typosquatting",
  "leak-velocity":              "Leak velocity",
  "phishing-kit":               "Phishing kit",
  "impersonation-confidence":   "Impersonation IA",
};

// ─────────────────────────────────────────────────────────────────────────────
// Componente principal
// ─────────────────────────────────────────────────────────────────────────────

export function BrandThreatsBlock({
  domain,
  threats,
}: {
  domain: string;
  threats: SurveillanceBrandThreats;
}) {
  const [expanded, setExpanded] = useState(false);

  if (threats.threats.length === 0 && threats.correlations.length === 0) {
    return null;
  }

  const kinds = Object.entries(threats.byKind)
    .filter(([, n]) => n > 0) as [ThreatKind, number][];

  // Mostrar las 5 primeras por defecto, "Ver todas" expande.
  const visibleThreats = expanded ? threats.threats : threats.threats.slice(0, 5);
  const hasMore = threats.threats.length > visibleThreats.length;

  return (
    <Card className={cn(
      "border-orange-500/30",
      threats.hasActiveCampaign && "border-red-500/40 bg-red-500/[0.02]",
    )}>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Radar className={cn(
              "h-4 w-4",
              threats.hasActiveCampaign ? "text-red-500 animate-pulse" : "text-orange-500",
            )} aria-hidden />
            Amenazas en Tiempo Real
            <Badge variant="outline" className="text-[10px]">
              {threats.threats.length}
            </Badge>
          </CardTitle>

          {/* Contadores por kind */}
          <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-muted-foreground">
            {kinds.map(([kind, n]) => {
              const Icon = KIND_ICON[kind];
              return (
                <span key={kind} className="inline-flex items-center gap-1 rounded-md border border-border/50 px-1.5 py-0.5">
                  <Icon className="h-3 w-3" aria-hidden />
                  <span className="font-mono tabular-nums">{n}</span>
                  <span>{KIND_LABEL[kind]}</span>
                </span>
              );
            })}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Correlaciones cross-source primero (las más urgentes) */}
        {threats.correlations.length > 0 && (
          <div className="space-y-2">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-red-600 dark:text-red-400">
              <TrendingUp className="h-3 w-3" aria-hidden />
              Correlaciones activas ({threats.correlations.length})
            </p>
            <div className="space-y-2">
              {threats.correlations.map((c) => (
                <CorrelationCard key={c.id} domain={domain} correlation={c} />
              ))}
            </div>
          </div>
        )}

        {/* Feed plano de threats */}
        {threats.threats.length > 0 && (
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Feed individual
            </p>
            <div className="space-y-2">
              {visibleThreats.map((t) => (
                <ThreatCard key={t.id} domain={domain} threat={t} />
              ))}
            </div>

            {hasMore && (
              <div className="flex justify-center">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs"
                  onClick={() => setExpanded(true)}
                >
                  Ver todas ({threats.threats.length - visibleThreats.length} más)
                </Button>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-componentes
// ─────────────────────────────────────────────────────────────────────────────

function CorrelationCard({
  domain,
  correlation: c,
}: {
  domain: string;
  correlation: CorrelationFinding;
}) {
  return (
    <div
      className={cn(
        "rounded-xl border border-l-4 p-4",
        SEVERITY_BORDER[c.severity],
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className={cn("text-[10px]", SEVERITY_BADGE[c.severity])}>
              {SEVERITY_LABEL[c.severity]}
            </Badge>
            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              correlación · {c.evidenceIds.length} evidencia(s)
            </span>
          </div>
          <p className="mt-1 text-sm font-bold">{c.title}</p>
          <p className="mt-1 text-xs text-muted-foreground">{c.detail}</p>
        </div>

        <OpenSocCaseButton
          domain={domain}
          forceShow
          buttonClassName="h-7 px-2.5 text-[10px] shrink-0"
          finding={{
            id: c.id,
            title: c.title,
            detail: c.detail,
            score: c.severity === "critical" ? 45 : c.severity === "high" ? 35 : 20,
          }}
        />
      </div>
    </div>
  );
}

function ThreatCard({
  domain,
  threat: t,
}: {
  domain: string;
  threat: BrandThreat;
}) {
  const Icon = KIND_ICON[t.kind];
  const eligible = t.severity === "critical" || t.severity === "high";

  return (
    <div
      className={cn(
        "rounded-lg border border-l-4 p-3 transition-colors hover:bg-muted/30",
        SEVERITY_BORDER[t.severity],
      )}
    >
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        <Icon className="h-3.5 w-3.5" aria-hidden />
        <Badge variant="outline" className={cn("text-[10px]", SEVERITY_BADGE[t.severity])}>
          {SEVERITY_LABEL[t.severity]}
        </Badge>
        <span className="font-mono uppercase tracking-wider">{KIND_LABEL[t.kind]}</span>
        <span aria-hidden>·</span>
        <span>{formatRelativeTimeEs(t.detectedAt)}</span>
        <span aria-hidden>·</span>
        <span className="text-[10px]">{t.source}</span>
      </div>
      <p className="mt-1 text-sm font-semibold">{t.title}</p>
      <p className="mt-0.5 text-xs text-muted-foreground">{t.detail}</p>

      <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
        <span className="font-mono text-muted-foreground">target: {t.target}</span>
        {(t.target.startsWith("http://") || t.target.startsWith("https://")) && (
          <a
            href={t.target}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-primary hover:underline"
          >
            ver original <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        )}
        {eligible && (
          <OpenSocCaseButton
            domain={domain}
            forceShow
            buttonClassName="h-6 px-2 text-[10px] ml-auto"
            finding={{
              id: t.id,
              title: t.title,
              detail: `${t.detail} (target: ${t.target})`,
              score: t.severity === "critical" ? 40 : 25,
            }}
          />
        )}
      </div>
    </div>
  );
}
