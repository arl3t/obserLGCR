/**
 * ExecutiveHero — bloque unificado de cabecera del informe ejecutivo.
 *
 * Funde lo que antes vivía en 3 componentes separados (ExecutivePortada +
 * RiskGauge + CTAs sueltas) en una sola pieza visual densa pensada para
 * lectura ejecutiva rápida:
 *
 *   ┌─ banda CONFIDENCIAL ────────────────────────────────────────────┐
 *   │ [I]  ips.gov.py             ▲+5 score  ▲+2 críticos  ━ high     │
 *   │      Informe ejecutivo · 09/05 14:32                            │
 *   ├─────────────────────────────────────────────────────────────────┤
 *   │  73 / 100        ████████░░░░  Postura crítica       ⊙ 4/4      │
 *   │  ALTO            0──40──70─100  acción inmediata     fuentes    │
 *   ├─────────────────────────────────────────────────────────────────┤
 *   │  [Watchlist]  [Export PDF]  [Abrir Caso Ejecutivo]               │
 *   └─────────────────────────────────────────────────────────────────┘
 *
 * Lee del Provider — sólo recibe `onExportPdf` como prop (mismo patrón
 * que TabReporte). El delta vs análisis previo viene de
 * `useAnalysisHistory(domain, 2)` — si hay menos de 2 puntos, oculta los
 * deltas en lugar de mostrar ceros engañosos.
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  BellPlus,
  Download,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { useWatchlistStore } from "@/store/surveillance-watchlist-store";
import { useAnalysisHistory } from "@/hooks/useSurveillanceWorkspace";
import {
  OpenSocCaseForm,
  SocCaseOpenedNote,
} from "@/components/digital-surveillance/shared/OpenSocCaseButton";
import { Button } from "@/components/ui/button";
import { riskLabelEs } from "@/lib/digital-surveillance-api";
import { PY_TZ } from "@/lib/format";
import type { RiskBand } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

const BAND_TEXT: Record<RiskBand, string> = {
  high:   "text-red-500",
  medium: "text-amber-500",
  low:    "text-emerald-500",
};

const BAND_BAR: Record<RiskBand, string> = {
  high:   "from-red-500 via-red-400 to-red-500",
  medium: "from-amber-500 via-amber-400 to-amber-500",
  low:    "from-emerald-500 via-emerald-400 to-emerald-500",
};

const BAND_GLOW: Record<RiskBand, string> = {
  high:   "shadow-red-500/30",
  medium: "shadow-amber-500/30",
  low:    "shadow-emerald-500/20",
};

const BAND_NARRATIVE: Record<RiskBand, string> = {
  high:   "acción inmediata",
  medium: "vigilancia activa",
  low:    "monitoreo rutinario",
};

function domainInitial(domain: string): string {
  const first = domain.split(".")[0] ?? domain;
  const ch = first.match(/[a-z0-9]/i)?.[0];
  return (ch ?? "?").toUpperCase();
}

function formatGeneratedAt(date: Date): string {
  const fecha = new Intl.DateTimeFormat("es-PY", {
    timeZone: PY_TZ,
    day: "numeric", month: "long", year: "numeric",
  }).format(date);
  const hora = new Intl.DateTimeFormat("es-PY", {
    timeZone: PY_TZ,
    hour: "2-digit", minute: "2-digit", hour12: false,
  }).format(date);
  return `${fecha} · ${hora}`;
}

function sourcesActiveCount(
  data: ReturnType<typeof useSurveillance>["data"],
): number {
  if (!data) return 0;
  return [
    data.shodan.configured && !data.shodan.error,
    data.misp.configured && !data.misp.error,
    data.brand24.configured,
    true,  // RSS no se config-flagea por dominio.
  ].filter(Boolean).length;
}

export function ExecutiveHero({ onExportPdf }: { onExportPdf: () => void }) {
  const { domain, data, riskScore, riskBand, openWatchlist } = useSurveillance();
  const isWatching = useWatchlistStore((s) =>
    Boolean(s.entries[domain.toLowerCase()]),
  );

  // Delta vs análisis previo — sólo cuando hay >=2 análisis registrados.
  const historyQ = useAnalysisHistory(domain, 2);
  const sortedHist = (historyQ.data ?? []).slice().sort(
    (a, b) => +new Date(a.queried_at) - +new Date(b.queried_at),
  );
  const haveDelta = sortedHist.length >= 2;
  const delta = haveDelta
    ? {
        score:    sortedHist[1].risk_score        - sortedHist[0].risk_score,
        critical: sortedHist[1].findings_critical - sortedHist[0].findings_critical,
        high:     sortedHist[1].findings_high     - sortedHist[0].findings_high,
      }
    : null;

  // Caso ejecutivo expandible.
  const [caseOpen, setCaseOpen] = useState(false);
  const [createdCaseId, setCreatedCaseId] = useState<string | null>(null);

  if (!domain) return null;

  const initial = domainInitial(domain);
  const generatedAt = data?.queriedAt ? new Date(data.queriedAt) : new Date();
  const sourcesActive = sourcesActiveCount(data);

  return (
    <header className="overflow-hidden rounded-2xl border border-emerald-500/20 bg-card shadow-sm">
      {/* ── Banda superior — clasificación + deltas ─────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 bg-muted/30 px-6 py-2 text-[10px] font-semibold uppercase tracking-[0.25em]">
        <span className="flex items-center gap-2 text-emerald-500">
          <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
          CONFIDENCIAL — Uso interno
        </span>
        {haveDelta && delta && (
          <div className="flex items-center gap-1.5">
            <DeltaPill label="score"    value={delta.score} />
            <DeltaPill label="críticos" value={delta.critical} />
            <DeltaPill label="high"     value={delta.high} />
          </div>
        )}
      </div>

      {/* ── Identidad + risk principal ──────────────────────────────────── */}
      <div className="grid gap-6 px-6 py-6 sm:px-10 sm:py-8 lg:grid-cols-[auto,1fr,auto] lg:items-center lg:gap-10">
        {/* Sello + dominio */}
        <div className="flex items-center gap-4">
          <div
            aria-hidden
            className="relative flex h-16 w-16 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-emerald-400 to-emerald-600 shadow-lg shadow-emerald-500/40 ring-4 ring-emerald-500/10 sm:h-20 sm:w-20"
          >
            <span className="text-2xl font-black tracking-tight text-emerald-950 sm:text-3xl">
              {initial}
            </span>
            <span className="absolute -bottom-1 -right-1 h-3.5 w-3.5 rounded-full border-2 border-background bg-emerald-400" />
          </div>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-[0.3em] text-emerald-500/80">
              Informe Ejecutivo · Postura Digital
            </p>
            <h1 className="font-mono text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
              {domain}
            </h1>
            <p className="mt-1 text-[11px] text-muted-foreground">
              Generado {formatGeneratedAt(generatedAt)}
              <span className="mx-2 text-muted-foreground/60">·</span>
              v2.0
            </p>
          </div>
        </div>

        {/* Risk score grande + barra + leyenda banda */}
        <div className="space-y-3 lg:px-4">
          <div className="flex items-baseline gap-3">
            <span
              className={cn(
                "font-mono text-6xl font-black tabular-nums leading-none",
                BAND_TEXT[riskBand],
              )}
            >
              {riskScore}
            </span>
            <span className="text-xl font-medium text-muted-foreground">/100</span>
            <div className="ml-auto text-right">
              <p
                className={cn(
                  "text-sm font-semibold uppercase tracking-wider",
                  BAND_TEXT[riskBand],
                )}
              >
                {riskLabelEs(riskBand)}
              </p>
              <p className="text-[11px] text-muted-foreground">
                {BAND_NARRATIVE[riskBand]}
              </p>
            </div>
          </div>

          {/* Barra animada */}
          <div className="relative">
            <div className="h-2.5 w-full overflow-hidden rounded-full bg-muted ring-1 ring-inset ring-border">
              <motion.div
                className={cn(
                  "h-full rounded-full bg-gradient-to-r shadow-lg",
                  BAND_BAR[riskBand],
                  BAND_GLOW[riskBand],
                )}
                initial={{ width: 0 }}
                animate={{ width: `${riskScore}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
            </div>
            <div
              className="pointer-events-none absolute inset-y-0 left-[40%] w-px bg-amber-500/40"
              aria-hidden
            />
            <div
              className="pointer-events-none absolute inset-y-0 left-[70%] w-px bg-red-500/40"
              aria-hidden
            />
          </div>

          <div className="flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
            <span className={riskBand === "low"    ? "text-emerald-500 font-semibold" : ""}>0—39 bajo</span>
            <span className={riskBand === "medium" ? "text-amber-500 font-semibold"   : ""}>40—69 medio</span>
            <span className={riskBand === "high"   ? "text-red-500 font-semibold"     : ""}>70—100 alto</span>
          </div>
        </div>

        {/* Sources coverage donut */}
        <SourcesRing active={sourcesActive} total={4} />
      </div>

      {/* ── CTAs ejecutivas ─────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border/50 bg-muted/20 px-6 py-3">
        <Button
          size="sm"
          variant={isWatching ? "secondary" : "outline"}
          className={cn(
            "h-9 gap-1.5 text-xs",
            isWatching &&
              "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 hover:bg-emerald-500/15 dark:text-emerald-300",
          )}
          onClick={openWatchlist}
          aria-label={
            isWatching
              ? `Editar vigilancia de ${domain}`
              : `Añadir ${domain} a Watchlist`
          }
        >
          <BellPlus className="h-3.5 w-3.5" aria-hidden />
          {isWatching ? "Vigilancia activa" : "Agregar a Watchlist"}
        </Button>

        <Button
          size="sm"
          variant="outline"
          className="h-9 gap-1.5 text-xs"
          onClick={onExportPdf}
        >
          <Download className="h-3.5 w-3.5" aria-hidden />
          Exportar PDF
        </Button>

        {!createdCaseId && (
          <Button
            size="sm"
            variant="outline"
            className={cn(
              "h-9 gap-1.5 text-xs",
              riskBand === "high"
                ? "border-red-500/40 bg-red-500/10 text-red-700 hover:bg-red-500/15 dark:text-red-300"
                : "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 hover:bg-emerald-500/15 dark:text-emerald-300",
            )}
            onClick={() => setCaseOpen((v) => !v)}
            aria-expanded={caseOpen}
          >
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
            {caseOpen ? "Cancelar caso" : "Abrir Caso Ejecutivo"}
          </Button>
        )}
      </div>

      {/* Form expandible (cuando se abre el caso) */}
      {(caseOpen || createdCaseId) && (
        <div className="border-t border-border/50 bg-muted/10 px-6 py-4">
          {caseOpen && !createdCaseId && (
            <OpenSocCaseForm
              domain={domain}
              factor={{
                id: `executive-snapshot-${riskBand}`,
                title: `Apertura ejecutiva — ${domain}`,
                detail:
                  `Caso disparado desde portada ejecutiva. Risk score ${riskScore}/100 ` +
                  `(${riskBand}). Ver tabs de detalle para evidencia completa.`,
                score: riskScore,
              }}
              onClose={() => setCaseOpen(false)}
              onSuccess={(id) => {
                setCreatedCaseId(id);
                setCaseOpen(false);
              }}
            />
          )}
          {createdCaseId && <SocCaseOpenedNote caseId={createdCaseId} />}
        </div>
      )}
    </header>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SourcesRing — donut compacto con cobertura de fuentes activas
// ─────────────────────────────────────────────────────────────────────────────

function SourcesRing({ active, total }: { active: number; total: number }) {
  const pct = total > 0 ? active / total : 0;
  const radius = 26;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - pct);
  const tone = pct >= 1 ? "text-emerald-500" : pct >= 0.5 ? "text-amber-500" : "text-red-500";

  return (
    <div className="flex items-center gap-3 lg:flex-col lg:items-end lg:gap-2">
      <div className="relative h-16 w-16 shrink-0">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 64 64" aria-hidden>
          <circle
            cx="32" cy="32" r={radius}
            className="fill-none stroke-muted"
            strokeWidth="6"
          />
          <motion.circle
            cx="32" cy="32" r={radius}
            className={cn("fill-none", tone)}
            stroke="currentColor"
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 0.8, ease: "easeOut" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("font-mono text-base font-bold tabular-nums leading-none", tone)}>
            {active}/{total}
          </span>
        </div>
      </div>
      <div className="text-right">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Fuentes
        </p>
        <p className="text-[10px] text-muted-foreground/80">
          activas
        </p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// DeltaPill — badge compacto de Δ vs análisis anterior
// ─────────────────────────────────────────────────────────────────────────────

function DeltaPill({ label, value }: { label: string; value: number }) {
  const dir = value === 0 ? "flat" : value > 0 ? "up" : "down";
  // Convención: Δ positivo = peor (rojo), Δ negativo = mejor (emerald).
  const tone =
    dir === "flat" ? "border-border/60 bg-muted/40 text-muted-foreground" :
    dir === "up"   ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400" :
                     "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400";
  const Icon = dir === "flat" ? ArrowRight : dir === "up" ? ArrowUpRight : ArrowDownRight;
  const sign = value > 0 ? "+" : "";

  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1 rounded-md border px-1.5 font-mono text-[10px]",
        tone,
      )}
      title={`Δ ${label} vs análisis anterior: ${sign}${value}`}
    >
      <Icon className="h-2.5 w-2.5" aria-hidden />
      {sign}{value} {label}
    </span>
  );
}
