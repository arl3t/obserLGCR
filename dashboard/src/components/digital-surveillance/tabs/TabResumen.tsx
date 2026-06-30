/**
 * TabResumen — Workspace del Analista (rediseño 2026-05).
 *
 * Reemplaza la antigua vista de KPIs+alertas+factores por un feed unificado
 * de hallazgos con cross-references y recomendaciones. Estructura:
 *
 *   1. Banda compacta de KPIs (5 fuentes en una fila — lectura rápida).
 *   2. FindingsFeed: cards SOC playbook con 5 campos (qué/dónde/por qué/refs/
 *      acción), filtrables por severity y kind, ordenadas por severidad y
 *      fecha de detección.
 *
 * Los handlers de acción se centralizan acá: open-case dispara
 * `OpenSocCaseForm`, add-watchlist abre `WatchlistModal` (vía Provider),
 * navigate-tab cambia `activeTab`, block-ioc/rotate-creds copian al
 * clipboard, external-link abre URL en nueva pestaña.
 */

import { useCallback, useEffect, useState } from "react";
import {
  KeyRound,
  Megaphone,
  Network,
  Newspaper,
  ShieldAlert,
  Wand2,
} from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { FindingsFeed } from "@/components/digital-surveillance/findings/FindingsFeed";
import { EnrichDrawer } from "@/components/digital-surveillance/findings/EnrichDrawer";
import { detectIocType } from "@/hooks/useEnrichment";
import {
  useAutoRecordAnalysis,
  useExportFindings,
  type ExportFormat,
} from "@/hooks/useSurveillanceWorkspace";
import { MITRE_BY_KIND } from "@/components/digital-surveillance/risk-engine/mitre-attack-map";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  OpenSocCaseForm,
  SocCaseOpenedNote,
  type Finding as SocFinding,
} from "@/components/digital-surveillance/shared/OpenSocCaseButton";
import { KpiStrip, type KpiItem } from "@/components/digital-surveillance/shared/KpiStrip";
import { WebPushToggle } from "@/components/digital-surveillance/shared/WebPushToggle";
import {
  BRAND24_MIN_CLASSIFIED,
  BRAND24_NEG_RATIO_CRITICAL,
  BRAND24_VOL_DELTA_WARN_PERCENT,
  CREDS_MASS_LEAK_THRESHOLD,
  RSS_COVERAGE_SPIKE,
} from "@/components/digital-surveillance/risk-engine/thresholds";
import type {
  AnalystFinding,
  AnalystFindingAction,
  AnalystFindingRef,
} from "@/types/digital-surveillance";

// ─────────────────────────────────────────────────────────────────────────────
// Helper compacto de números
// ─────────────────────────────────────────────────────────────────────────────

function formatCompact(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(Math.round(n));
}

// ─────────────────────────────────────────────────────────────────────────────
// Componente
// ─────────────────────────────────────────────────────────────────────────────

/** Intervalo del live-tail en milisegundos (60s — alineado con el staleTime
 *  más corto del módulo, surveillance-domain). */
const LIVE_TAIL_INTERVAL_MS = 60_000;

export function TabResumen() {
  const {
    domain,
    data,
    rss,
    brand24,
    snapshot,
    emailCount,
    findings,
    riskScore,
    riskBand,
    setActiveTab,
    openWatchlist,
    refetchAll,
  } = useSurveillance();

  // Estado local del modal de apertura de caso desde un finding.
  const [caseFor, setCaseFor] = useState<AnalystFinding | null>(null);
  const [openedCaseId, setOpenedCaseId] = useState<string | null>(null);

  // Live tail — cuando está activo, dispara refetchAll() cada
  // LIVE_TAIL_INTERVAL_MS. Útil durante incidentes activos.
  const [liveTail, setLiveTail] = useState(false);
  useEffect(() => {
    if (!liveTail) return;
    const id = setInterval(() => refetchAll(), LIVE_TAIL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [liveTail, refetchAll]);
  const toggleLiveTail = useCallback(() => setLiveTail((v) => !v), []);

  // OSINT enrichment drawer — pre-cargado con un IOC opcional cuando se
  // dispara desde el botón global del toolbar.
  const [enrichOpen, setEnrichOpen] = useState(false);
  const [enrichValue, setEnrichValue] = useState("");

  // Export drawer/menu state.
  const exportFindings = useExportFindings();
  function handleExport(format: ExportFormat) {
    if (!data) return;
    if (format === "navigator") {
      // El backend mapea via mitreByKind + mitreCatalog provistos.
      const byKind: Record<string, number> = {};
      for (const f of findings) byKind[f.kind] = (byKind[f.kind] ?? 0) + 1;
      exportFindings.mutate({ domain, findings, format, mitreByKind: byKind, mitreCatalog: MITRE_BY_KIND });
      return;
    }
    exportFindings.mutate({ domain, findings, format });
  }

  // Auto-record snapshot del análisis cuando llegan datos (Ola B #1 histórico).
  // El hook usa una ref interna para emitir solo una vez por (domain, queriedAt).
  useAutoRecordAnalysis({ domain, data, findings, riskScore, riskBand });

  // Handlers de acción — se pasan a FindingsFeed/FindingCard.
  const handleAction = useCallback(
    (action: AnalystFindingAction, finding: AnalystFinding) => {
      switch (action.kind) {
        case "open-case":
          setOpenedCaseId(null);
          setCaseFor(finding);
          break;
        case "add-watchlist":
          openWatchlist();
          break;
        case "navigate-tab": {
          const tab = action.payload?.tab;
          if (typeof tab === "string") setActiveTab(tab as never);
          break;
        }
        case "block-ioc":
        case "rotate-creds": {
          const value = action.payload?.iocs ?? action.payload?.ioc ?? action.payload?.service ?? "";
          if (typeof value === "string" && value.length > 0) {
            void navigator.clipboard?.writeText(value);
          }
          break;
        }
        case "external-link": {
          const url = action.payload?.url;
          if (typeof url === "string") window.open(url, "_blank", "noopener,noreferrer");
          break;
        }
      }
    },
    [openWatchlist, setActiveTab],
  );

  const handleRefClick = useCallback(
    (ref: AnalystFindingRef) => {
      setActiveTab(ref.tab);
    },
    [setActiveTab],
  );

  if (!data) return null;

  const { shodan, misp, brand24: brand24Cfg } = data;

  const shodanCount = shodan.configured ? (shodan.total ?? 0) : null;
  const mispCount   = misp.configured ? (misp.count ?? 0) : null;
  const brandTotal  = brand24?.summary?.volumeMentions ?? null;
  const rssCount = rss
    ? (rss.items?.length ?? 0) + ((rss.custom ?? []).filter((i) => i.matched).length)
    : null;

  // KPI strip — 5 fuentes en banda compacta.
  const kpiItems: KpiItem[] = [
    {
      key: "shodan",
      label: "Hosts Shodan",
      value: shodanCount ?? "—",
      icon: Network,
      tone: shodanCount && shodanCount > 0 ? "warn" : "muted",
      unconfigured: !shodan.configured,
    },
    {
      key: "misp",
      label: "IOCs MISP",
      value: mispCount ?? "—",
      icon: ShieldAlert,
      tone: mispCount && mispCount > 0 ? "critical" : "muted",
      unconfigured: !misp.configured,
    },
    {
      key: "brand24",
      label: "Menciones",
      value: brandTotal != null ? formatCompact(brandTotal) : "—",
      icon: Megaphone,
      tone: (() => {
        if (!brand24?.summary) return "muted";
        const s = brand24.summary;
        const total = s.positiveCount + s.negativeCount;
        if (total >= BRAND24_MIN_CLASSIFIED && s.negativeCount / total >= BRAND24_NEG_RATIO_CRITICAL) return "critical";
        if (Math.abs(s.volumeDeltaPercent) >= BRAND24_VOL_DELTA_WARN_PERCENT) return "warn";
        return "neutral";
      })(),
      hint: brand24?.summary
        ? (() => {
            const s = brand24.summary;
            const total = s.positiveCount + s.negativeCount;
            const pct = total > 0 ? Math.round((s.negativeCount / total) * 100) : 0;
            return total > 0
              ? `${pct}% neg`
              : "sin clasificar";
          })()
        : undefined,
      unconfigured: !brand24Cfg.configured && brandTotal === null,
    },
    {
      key: "rss",
      label: "Cobertura RSS",
      value: rssCount ?? "—",
      icon: Newspaper,
      tone:
        rssCount && rssCount >= RSS_COVERAGE_SPIKE ? "warn" :
        rssCount && rssCount > 0                   ? "neutral" :
                                                      "muted",
      hint: rssCount === 0 ? "sin menciones" : undefined,
    },
    {
      key: "creds",
      label: "Correos en fuga",
      value: snapshot ? formatCompact(emailCount) : "—",
      icon: KeyRound,
      tone:
        emailCount >= CREDS_MASS_LEAK_THRESHOLD ? "critical" :
        emailCount > 0                          ? "warn" :
                                                  "muted",
      hint: snapshot
        ? snapshot.weakPwdRate
          ? `${Math.round(snapshot.weakPwdRate * 100)}% débiles`
          : snapshot.sourceLabel
        : "sin dump",
      unconfigured: !snapshot,
    },
  ];

  // Construye un SocFinding desde el AnalystFinding cuando se abre el caso.
  const socFinding: SocFinding | null = caseFor
    ? {
        id:     caseFor.id,
        title:  caseFor.title,
        detail: `${caseFor.evidence}\n\n${caseFor.why}`,
        score:  scoreFromSeverity(caseFor.severity),
      }
    : null;

  return (
    <div className="space-y-5">
      {/* ── 1. KPI strip — banda compacta de 5 fuentes ───────────────────── */}
      <KpiStrip items={kpiItems} columns={5} />

      {/* ── 2. Caso ejecutivo recién abierto (si aplica) ─────────────────── */}
      {openedCaseId && <SocCaseOpenedNote caseId={openedCaseId} />}

      {/* ── Toolbar global del Workspace ─────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-1">
        <p className="text-xs text-muted-foreground">
          Dominio analizado: <span className="font-mono text-foreground">{domain}</span>
        </p>
        <div className="flex items-center gap-1.5">
          {/* Export — JSON / CSV / STIX */}
          <div className="flex overflow-hidden rounded-md border border-border">
            <Button
              size="sm"
              variant="ghost"
              className="h-8 rounded-none border-r border-border px-2.5 text-xs hover:bg-muted/50"
              disabled={findings.length === 0 || exportFindings.isPending}
              onClick={() => handleExport("json")}
              title="Exportar findings como JSON"
            >
              <Download className="mr-1 h-3.5 w-3.5" aria-hidden />
              JSON
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-8 rounded-none border-r border-border px-2.5 text-xs hover:bg-muted/50"
              disabled={findings.length === 0 || exportFindings.isPending}
              onClick={() => handleExport("csv")}
              title="Exportar findings como CSV (para hojas de cálculo)"
            >
              CSV
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-8 rounded-none border-r border-border px-2.5 text-xs hover:bg-muted/50"
              disabled={findings.length === 0 || exportFindings.isPending}
              onClick={() => handleExport("stix")}
              title="Exportar findings como STIX 2.1 bundle (TIP/SIEM)"
            >
              STIX
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-8 rounded-none px-2.5 text-xs hover:bg-muted/50"
              disabled={findings.length === 0 || exportFindings.isPending}
              onClick={() => handleExport("navigator")}
              title="Exportar como MITRE ATT&CK Navigator layer (.json)"
            >
              ATT&CK
            </Button>
          </div>
          <WebPushToggle />
          <Button
            size="sm"
            variant="outline"
            className="h-8 gap-1.5 text-xs"
            onClick={() => { setEnrichValue(""); setEnrichOpen(true); }}
            title="OSINT lookup multi-fuente sobre un IOC"
          >
            <Wand2 className="h-3.5 w-3.5" aria-hidden />
            Enriquecer IOC
          </Button>
        </div>
      </div>

      {/* ── 3. Feed unificado de hallazgos ───────────────────────────────── */}
      <FindingsFeed
        findings={findings}
        domain={domain}
        onAction={handleAction}
        onRefClick={handleRefClick}
        liveTailActive={liveTail}
        onToggleLiveTail={toggleLiveTail}
      />

      {/* ── Drawer OSINT enrichment ──────────────────────────────────────── */}
      <EnrichDrawer
        open={enrichOpen}
        onOpenChange={setEnrichOpen}
        initialValue={enrichValue}
        initialType={enrichValue ? (detectIocType(enrichValue) ?? undefined) : undefined}
      />

      {/* ── Modal de apertura de caso ────────────────────────────────────── */}
      {caseFor && socFinding && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4"
          onClick={() => setCaseFor(null)}
        >
          <div
            className="w-full max-w-2xl rounded-xl border border-border/80 bg-card p-5 shadow-2xl"
            onClick={(ev) => ev.stopPropagation()}
          >
            <OpenSocCaseForm
              domain={domain}
              factor={socFinding}
              onClose={() => setCaseFor(null)}
              onSuccess={(id) => {
                setOpenedCaseId(id);
                setCaseFor(null);
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Mapea severity de finding al score 0-100 esperado por OpenSocCaseForm —
 * que internamente lo usa para inicializar SOC severity (LOW/MED/HIGH).
 */
function scoreFromSeverity(s: AnalystFinding["severity"]): number {
  switch (s) {
    case "critical": return 90;
    case "high":     return 70;
    case "medium":   return 40;
    case "low":      return 20;
    case "info":     return 5;
  }
}
