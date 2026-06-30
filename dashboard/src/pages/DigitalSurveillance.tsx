import { motion } from "framer-motion";
import {
  AlertCircle,
  BellPlus,
  Download,
  Loader2,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { DomainSearchBar } from "@/components/digital-surveillance";
import { SurveillanceTabs } from "@/components/digital-surveillance/tabs/SurveillanceTabs";
import {
  SurveillanceProvider,
  useSurveillance,
  type SurveillanceTabId,
} from "@/components/digital-surveillance/SurveillanceProvider";
import { SituationalStrip } from "@/components/digital-surveillance/shared/SituationalStrip";
import { WatchlistModal } from "@/components/digital-surveillance/shared/WatchlistModal";
import { useWatchlistStore } from "@/store/surveillance-watchlist-store";
import { useHydrateWatchlist } from "@/hooks/useSurveillanceWorkspace";
import { useLeakIntelHubStore } from "@/store/leak-intel-hub-store";
import { LandingHero } from "@/components/digital-surveillance/landing/LandingHero";
import { WatchlistPanel } from "@/components/digital-surveillance/landing/WatchlistPanel";
import {
  SourcesPanel,
  countActiveSources,
  totalSurveillanceSources,
} from "@/components/digital-surveillance/landing/SourcesPanel";
import { CapabilitiesPanel } from "@/components/digital-surveillance/landing/CapabilitiesPanel";
import { useIntegrationsStatus } from "@/hooks/useIntegrationsStatus";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { WorkspaceSkeleton } from "@/components/digital-surveillance/shared/WorkspaceSkeleton";
import { exportSurveillancePdf } from "@/lib/surveillance-pdf-export";
import { normalizeSurveillanceDomain } from "@/lib/digital-surveillance-api";

// TODO M1 (docs/MEJORA-VIGILANCIA.md §6): mover a /api/surveillance/configured-domains
const FALLBACK_CONFIGURED = ["legacy-roots.net"];

const VALID_TABS: SurveillanceTabId[] = [
  "ejecutivo", "resumen", "analisis", "darkweb", "credenciales",
  "noticias", "marca", "reporte",
];

/** Aliases legacy de bookmarks anteriores al Sprint 4 (TabBrand unifica
 *  Marca + Menciones en un solo tab `marca`). */
const TAB_ALIASES: Record<string, SurveillanceTabId> = {
  menciones: "marca",
  brand:     "marca",
};

function parseTabParam(raw: string | null): SurveillanceTabId | undefined {
  if (!raw) return undefined;
  if (TAB_ALIASES[raw]) return TAB_ALIASES[raw];
  return (VALID_TABS as string[]).includes(raw) ? (raw as SurveillanceTabId) : undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// Página principal
// ─────────────────────────────────────────────────────────────────────────────

export function DigitalSurveillancePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const paramDomain = searchParams.get("domain")?.trim();
  const paramTab = parseTabParam(searchParams.get("tab"));

  const [draft, setDraft] = useState(() => paramDomain || "");
  const [committed, setCommitted] = useState(() => {
    if (!paramDomain) return "";
    return normalizeSurveillanceDomain(paramDomain) || "";
  });

  // Sincronizar cuando el ?domain de la URL cambia desde fuera
  useEffect(() => {
    if (!paramDomain) return;
    const n = normalizeSurveillanceDomain(paramDomain);
    if (!n) return;
    setCommitted((c) => (c === n ? c : n));
    setDraft(n);
  }, [paramDomain]);

  const runSearch = useCallback(() => {
    const n = normalizeSurveillanceDomain(draft);
    if (!n) return;
    setCommitted(n);
    // Preservar ?tab al actualizar el dominio
    const next = new URLSearchParams(searchParams);
    next.set("domain", n);
    setSearchParams(next);
  }, [draft, searchParams, setSearchParams]);

  const pickConfigured = useCallback(
    (d: string) => {
      setDraft(d);
      setCommitted(d);
      const next = new URLSearchParams(searchParams);
      next.set("domain", d);
      setSearchParams(next);
    },
    [searchParams, setSearchParams],
  );

  // Hidrata la watchlist desde el backend al montar la página — la fuente de
  // verdad es `surveillance_watchlist_subs`. localStorage actúa como cache.
  useHydrateWatchlist();

  // Stats inline para el LandingHero — sin pre-fetch, sólo lo que ya está en stores.
  const watchlistEntries = useWatchlistStore((s) => s.entries);
  const watchlistCount = useMemo(() => Object.keys(watchlistEntries).length, [watchlistEntries]);
  const lastIngestAt = useLeakIntelHubStore((s) => s.snapshot?.updatedAt ?? null);
  const integrationsQ = useIntegrationsStatus();
  const heroStats = useMemo(
    () => ({
      lastIngestAt,
      watchlistCount,
      sourcesActive: countActiveSources(integrationsQ.data),
      sourcesTotal: totalSurveillanceSources(),
    }),
    [lastIngestAt, watchlistCount, integrationsQ.data],
  );

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6 px-1 pb-12 sm:px-0">
      {/* ── Hero con stats globales del módulo ──────────────────────────── */}
      <LandingHero stats={heroStats} />

      {/* ── Buscador ─────────────────────────────────────────────────────── */}
      <DomainSearchBar
        value={draft}
        onChange={setDraft}
        onSubmit={runSearch}
        lastIngestLabel="Datos en tiempo real"
        configuredDomains={FALLBACK_CONFIGURED}
      />

      {/* ── Landing SOC console: sin dominio buscado ───────────────────── */}
      {!committed && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="grid gap-4 lg:grid-cols-3"
        >
          <WatchlistPanel onPickDomain={pickConfigured} />
          <SourcesPanel />
          <CapabilitiesPanel />
        </motion.div>
      )}

      {/* ── Vista con dominio comprometido ────────────────────────────────── */}
      {committed && (
        <SurveillanceProvider domain={committed} initialTab={paramTab ?? "resumen"}>
          <SurveillanceWorkspace />
        </SurveillanceProvider>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Workspace — vive dentro del Provider para poder usar `useSurveillance()`
// ─────────────────────────────────────────────────────────────────────────────

function SurveillanceWorkspace() {
  const {
    domain,
    data,
    rss,
    snapshot,
    hasCoverage,
    emailCount,
    infraCount,
    isLoading,
    isFetching,
    isError,
    errors,
    activeTab,
    watchlistOpen,
    openWatchlist,
    closeWatchlist,
  } = useSurveillance();

  // Indica si el dominio actual ya está bajo vigilancia (cambia el label del CTA)
  const isWatching = useWatchlistStore((s) => Boolean(s.entries[domain.toLowerCase()]));

  const handleExportPdf = useCallback(() => {
    if (!data) return;
    void exportSurveillancePdf(
      data,
      rss ?? null,
      hasCoverage ? snapshot : null,
      emailCount,
      infraCount,
    );
  }, [data, rss, snapshot, hasCoverage, emailCount, infraCount]);

  // Sincronizar ?tab cuando el usuario cambia de tab desde la UI
  const [, setSearchParams] = useSearchParams();
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set("tab", activeTab);
        return next;
      },
      { replace: true },
    );
  }, [activeTab, setSearchParams]);

  // Estado: error en el snapshot principal
  if (isError && errors.domain) {
    return (
      <Card className="border-destructive/40 bg-destructive/5">
        <CardContent className="flex items-start gap-3 p-4 text-sm text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <div className="space-y-0.5">
            <p className="font-medium">Error al consultar el dominio</p>
            <p className="text-destructive/80">{errors.domain.message}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Estado: cargando snapshot principal — skeleton estructural espejo de
  // TabResumen para evitar layout shift cuando llega data.
  if (isLoading || !data) {
    return <WorkspaceSkeleton />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-4"
    >
      {/* Indicador de revalidación silenciosa */}
      {isFetching && (
        <p className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          Actualizando vista…
        </p>
      )}

      {/* Postura general — sticky en el viewport, top-6 según spec del rediseño */}
      <div className="sticky top-6 z-30">
        <SituationalStrip />
      </div>

      {/* Acciones rápidas (vigilar dominio + exportar) */}
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button
          size="sm"
          variant={isWatching ? "secondary" : "outline"}
          className="h-8 gap-1.5 text-xs"
          onClick={openWatchlist}
          aria-label={isWatching ? `Editar vigilancia de ${domain}` : `Añadir ${domain} a Watchlist`}
        >
          <BellPlus className="h-3.5 w-3.5" aria-hidden />
          {isWatching ? "Vigilancia activa" : "Vigilar dominio"}
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="h-8 gap-1.5 text-xs"
          onClick={handleExportPdf}
        >
          <Download className="h-3.5 w-3.5" aria-hidden />
          Exportar PDF
        </Button>
      </div>

      <SurveillanceTabs onExportPdf={handleExportPdf} />

      <WatchlistModal domain={domain} open={watchlistOpen} onClose={closeWatchlist} />
    </motion.div>
  );
}
