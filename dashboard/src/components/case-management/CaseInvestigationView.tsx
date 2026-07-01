/**
 * CaseInvestigationView.tsx
 * DFIR-IRIS inspired full case investigation UI.
 * Tabs: Summary | Timeline | Assets | IOCs | Evidences | Tasks | Notes | Report
 */

import { Fragment, lazy, memo, Suspense, useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Sentry from "@sentry/react";
import {
  AlertTriangle, BookOpen, Bug, CheckSquare, Clock, Cpu,
  ExternalLink, FileText, FolderOpen, Layers, Link2, Plus, RefreshCw, Shield,
  Tag, Users, X,
} from "lucide-react";
import { Badge }       from "@/components/ui/badge";
import { Button }      from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input }       from "@/components/ui/input";
import { Skeleton }    from "@/components/ui/skeleton";
import { cn }          from "@/lib/utils";
import {
  useFullCase, useAddTimelineEvent, useTemplates,
  type FullCase, type TaskPhase,
} from "./useCaseInvestigation";
import {
  WhyIncidentBanner, SignalsCards, NistClassCards,
  RawEventPanel, TraceabilityPanel,
  PlaybookPanel, QuickActionsPanel, SuppressionPanel, SlaChip,
  HuntPivotSnapshotPanel,
} from "./InvestigationPanels";
import { CloseCaseModal, ReportPreviewModal, NotifyClientModal } from "./InvestigationModals";
import { IncidentVerdictCard } from "./IncidentVerdictCard";
import { HuntVerdictCard } from "./HuntVerdictCard";
import { GeoOriginCard } from "./GeoOriginCard";
import { ViewersStack } from "./ViewersStack";
import { useCaseViewers } from "./useCaseViewers";
import { useViewport } from "@/hooks/useViewport";
import { parseShodanSummary, caseCode } from "./case-normalize";
import { IocVerdictBanner, IocExtraSourceCards } from "./IocIntelExtras";
import type { IocVerdict, SourceStatus, ExtraSources } from "./IocIntelExtras";
import { api } from "@/api/client";
import { useSocOperators } from "@/hooks/useSocWorkflow";
import { C, alpha } from "@/lib/cm-theme";
import { formatDateTimePy, formatDatePy } from "@/lib/format";
import { anonymizeTables } from "@/lib/anonymize-tables";
import { ScoringDetailPanel } from "./ScoringDetailPanel";

// Fix #11: tabs Timeline/Tasks/Assets/Evidences/IOCs cargados bajo demanda.
// El bundle del Resumen (default) ya no arrastra el código de los demás tabs
// → ~30-40% menos JS en el primer render de la vista de investigación.
// Vite dedupe los chunks: las 5 lazy() apuntan al mismo módulo y comparten
// el bundle resultante.
const TimelineTab  = lazy(() => import("./CaseInvestigationTabsLazy").then(m => ({ default: m.TimelineTab  })));
const TasksTab     = lazy(() => import("./CaseInvestigationTabsLazy").then(m => ({ default: m.TasksTab     })));
const AssetsTab    = lazy(() => import("./CaseInvestigationTabsLazy").then(m => ({ default: m.AssetsTab    })));
const EvidencesTab = lazy(() => import("./CaseInvestigationTabsLazy").then(m => ({ default: m.EvidencesTab })));
const IocsTab      = lazy(() => import("./CaseInvestigationTabsLazy").then(m => ({ default: m.IocsTab      })));
const CvesTab      = lazy(() => import("./CaseInvestigationTabsLazy").then(m => ({ default: m.CvesTab      })));
const EventsTab    = lazy(() => import("./CaseInvestigationTabsLazy").then(m => ({ default: m.EventsTab    })));

const TabFallback = () => (
  <div className="space-y-3 py-6">
    <Skeleton className="h-6 w-48" />
    <Skeleton className="h-32 w-full" />
  </div>
);

// Nota: la normalización de arrays (shodanPorts/shodanVulns/mispTags/…)
// ahora vive en case-normalize.ts y se aplica en useFullCase ANTES de que
// los datos lleguen a estos componentes. Los consumers pueden confiar en
// que `ioc.tags`, `iocEnrichment.shodan*` y `iocSources.*` ya son arrays.

// ── Constants ────────────────────────────────────────────────────────────────

const PHASE_LABEL: Record<string, string> = {
  DETECTION:     "Detection & Analysis",
  CONTAINMENT:   "Containment",
  ERADICATION:   "Eradication",
  RECOVERY:      "Recovery",
  POST_INCIDENT: "Post-Incident",
};
const PHASE_COLOR: Record<string, string> = {
  DETECTION:     "bg-blue-500/10 text-blue-400 border-blue-500/30",
  CONTAINMENT:   "bg-orange-500/10 text-orange-400 border-orange-500/30",
  ERADICATION:   "bg-red-500/10 text-red-400 border-red-500/30",
  RECOVERY:      "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  POST_INCIDENT: "bg-purple-500/10 text-purple-400 border-purple-500/30",
};
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-emerald-400",
};
const STATUS_COLOR: Record<string, string> = {
  NUEVO:          "bg-blue-500/10 text-blue-400",
  EN_ANALISIS:    "bg-yellow-500/10 text-yellow-400",
  CONFIRMADO:     "bg-red-500/10 text-red-400",
  ESCALADO:       "bg-orange-500/10 text-orange-400",
  MONITOREADO:    "bg-purple-500/10 text-purple-400",
  FALSO_POSITIVO: "bg-emerald-500/10 text-emerald-400",
  CERRADO:        "bg-muted/40 text-muted-foreground",
};
// Orden alineado con el flujo real del operador:
//   Resumen → Assets (¿quiénes están afectados?) → IOCs (¿qué indicadores?)
//   → Intel (enrichment) → Timeline (auditoría) → Tareas → Evidencias → Notas → Reporte.
// "Pipeline" (diagrama técnico del stack) era operativo para devs, no para el SOC;
// se quita del navigator. El componente PipelineTab queda en el archivo por si
// se re-expone como panel de admin en el futuro.
// Tabs agrupados por intención (se renderiza un separador al cambiar de grupo):
//   resumen    → Resumen
//   inteligencia → Intel · Eventos (contexto de amenaza)
//   entidades  → IOCs · CVEs · Assets (entidades del caso)
//   gestion    → Timeline · Tareas
//   registro   → Evidencias · Notas
const TABS = [
  { id: "summary",   label: "Resumen",    icon: FileText,      group: "resumen"      },
  { id: "intel",     label: "Intel",      icon: Cpu,           group: "inteligencia" },
  { id: "events",    label: "Eventos",    icon: FileText,      group: "inteligencia" },
  { id: "iocs",      label: "IOCs",       icon: Shield,        group: "entidades"    },
  { id: "cves",      label: "CVEs",       icon: Bug,           group: "entidades"    },
  { id: "assets",    label: "Assets",     icon: AlertTriangle, group: "entidades"    },
  { id: "timeline",  label: "Timeline",   icon: Clock,         group: "gestion"      },
  { id: "tasks",     label: "Tareas",     icon: CheckSquare,   group: "gestion"      },
  { id: "evidences", label: "Evidencias", icon: FolderOpen,    group: "registro"     },
  { id: "notes",     label: "Notas",      icon: BookOpen,      group: "registro"     },
] as const;

type TabId = typeof TABS[number]["id"];

// ── Main component ────────────────────────────────────────────────────────────

export function CaseInvestigationView({
  caseId,
  operatorCi,
  onClose,
}: {
  caseId: string;
  operatorCi: string;
  onClose: () => void;
}) {
  const [activeTab, setActiveTab] = useState<TabId>("summary");
  const [focusMode, setFocusMode] = useState(false); // oculta columnas laterales
  const [showClose, setShowClose] = useState(false);
  const [showReport, setShowReport] = useState(false);
  const [showNotifyClient, setShowNotifyClient] = useState(false);
  // C4 — Bloqueo en móvil. La vista tiene 8 tabs + modales complejos que no
  // se adaptan razonablemente a viewport <800px. Decisión documentada en
  // docs/SOC-UX-BACKLOG.md: "Investigación completa solo en desktop".
  const { isMobile } = useViewport();
  const { data: c, isLoading, error, refetch } = useFullCase(caseId);
  // Para mostrar el nombre del operador en lugar del CI en el header.
  // El CI sigue disponible en el tooltip para auditoría.
  const { data: operators = [] } = useSocOperators();
  // C3 — Presencia en tiempo real: avatar stack en el header + aviso si
  // alguien más ya está mirando el caso al momento de abrirlo.
  const { viewers, othersOnly } = useCaseViewers(caseId, activeTab);
  const otherViewers = othersOnly(operatorCi);

  // C4 — Guard mobile: corre antes del loading state para no flashear el
  // skeleton mientras se decide. Devuelve un mensaje claro + acción única
  // (volver a la lista) en lugar de mostrar una UI rota.
  if (isMobile) return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 p-6 text-center">
      <div className="text-3xl">🖥️</div>
      <div className="text-base font-semibold">
        Investigación requiere desktop
      </div>
      <p className="max-w-xs text-xs text-muted-foreground">
        Esta vista usa 8 pestañas, paneles laterales y modales complejos
        que no están optimizados para pantallas &lt; 800&nbsp;px. Abrí el caso
        desde una laptop o monitor para investigar.
      </p>
      <Button
        size="sm"
        variant="outline"
        onClick={onClose}
        className="mt-2"
      >
        Volver a la lista
      </Button>
    </div>
  );

  if (isLoading) return (
    <div className="space-y-3 p-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-40 w-full" />
    </div>
  );
  if (error || !c) return (
    <div className="p-6 text-sm text-destructive">
      {error instanceof Error ? error.message : "Error al cargar el caso"}
    </div>
  );

  const sevColor = SEV_COLOR[c.severity] ?? "text-muted-foreground";
  const statusCls = STATUS_COLOR[c.status] ?? "bg-muted/20 text-muted-foreground";

  const tasksDone = c.tasks.filter(t => t.status === "DONE").length;
  const tasksTotal = c.tasks.length;

  return (
    <div className="flex h-full flex-col bg-background">
      {/* ══════════════════════ HEADER STICKY ══════════════════════ */}
      <div className="sticky top-0 z-40 border-b-2 border-red-500/60 bg-background/95 shadow-[0_8px_32px_-12px_rgba(239,68,68,.35)] backdrop-blur">
        <div className="flex flex-wrap items-center gap-3 px-6 py-3">
          {/* Severity editor badge — click para reclasificar la criticidad */}
          <SeverityEditor
            caseId={c.id}
            severity={c.severity}
            operatorCi={operatorCi}
            escalationLevel={c.escalation_level ?? null}
            onChanged={() => { void refetch(); }}
          />
          <span className={cn("rounded px-2 py-0.5 text-[11px]", statusCls)}>{c.status}</span>

          {/* Chips identidad */}
          <ChipKV label="Caso" value={caseCode(c as never)} mono valueClass="font-bold" />
          <ChipKV label="ID" value={c.id.slice(0, 8)} mono />
          {c.ioc_value && <ChipKV label="IOC" value={c.ioc_value} mono valueClass={cn("font-bold", sevColor)} />}
          <ChipKV label="Score" value={<><span className={cn("font-bold", sevColor)}>{c.score}</span><span className="text-muted-foreground">/200</span></>} />
          {c.mitre_tactic_id && (
            <ChipKV label="MITRE" value={<>{c.mitre_tactic_id}{c.mitre_tactic_name ? ` · ${c.mitre_tactic_name}` : ""}</>} />
          )}
          {c.incidentClass && (
            <ChipKV
              label="Clase"
              value={<span title={`eCSIRT/MISP · ${c.incidentClass.misp}${c.incidentClass.subclass ? ` · ${c.incidentClass.subclass}` : ""}`}>
                {c.incidentClass.label}{c.incidentClass.subclass ? ` · ${c.incidentClass.subclass}` : ""}
              </span>}
            />
          )}
          {c.operator_id && (() => {
            const name = operators.find((o) => o.id === c.operator_id)?.name ?? c.operator_id;
            return <ChipKV label="Operador" value={<span title={`CI ${c.operator_id}`}>{name}</span>} />;
          })()}
          {c.template_id && (
            <Badge variant="outline" className="text-[10px]">Plantilla</Badge>
          )}

          {/* SLA chip + acciones — empujado a la derecha */}
          <div className="ml-auto flex items-center gap-2">
            {/* C3 — Presencia en vivo: avatar stack de quién más mira el caso */}
            {otherViewers.length > 0 && (
              <ViewersStack viewers={viewers} selfOperatorId={operatorCi} />
            )}
            <SlaChip c={c} />
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setFocusMode(f => !f)}
              className="text-xs"
              title="Oculta columnas laterales para incidentes críticos"
            >
              {focusMode ? "Salir Focus" : "Modo Focus"}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowReport(true)}
              className="text-xs"
            >
              <FileText className="mr-1 h-3 w-3" />
              Generar informe
            </Button>
            <Button
              size="sm"
              onClick={() => setShowClose(true)}
              className="bg-red-500 text-xs font-bold text-white hover:bg-red-600"
              disabled={c.status === "CERRADO" || c.status === "FALSO_POSITIVO"}
            >
              <X className="mr-1 h-3 w-3" />
              Cerrar caso
            </Button>
            <Button size="sm" variant="ghost" onClick={() => void refetch()} title="Refrescar">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
            <Button size="sm" variant="ghost" onClick={onClose} title="Cerrar vista">
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 overflow-x-auto border-t border-border/40 px-4 py-1">
          {TABS.map(({ id, label, icon: Icon, group }, i) => (
            <Fragment key={id}>
              {/* Separador al cambiar de grupo lógico */}
              {i > 0 && TABS[i - 1].group !== group && (
                <div className="mx-1 h-4 w-px shrink-0 bg-border/60" aria-hidden />
              )}
            <button
              onClick={() => setActiveTab(id)}
              className={cn(
                "flex items-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-xs transition-colors",
                activeTab === id
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:bg-muted/40 hover:text-foreground",
              )}
            >
              <Icon className="h-3 w-3 shrink-0" />
              {label}
              {id === "tasks" && tasksTotal > 0 && (
                <span className={cn(
                  "ml-1 rounded px-1 text-[10px] font-semibold",
                  tasksDone === tasksTotal ? "bg-emerald-500/20 text-emerald-400" : "bg-muted/50 text-muted-foreground"
                )}>
                  {tasksDone}/{tasksTotal}
                </span>
              )}
            </button>
            </Fragment>
          ))}
        </div>

        {/* C3 — Aviso de presencia: si abrís un caso y alguien más ya lo está
            mirando, banner sutil que coordina antes de duplicar el trabajo. */}
        {otherViewers.length > 0 && (
          <div className="flex items-center gap-2 border-t border-amber-500/30 bg-amber-500/5 px-4 py-1.5 text-[11px] text-amber-300">
            <span>👁️</span>
            <span>
              {otherViewers.length === 1
                ? <>{otherViewers[0].operatorName ?? otherViewers[0].operatorId} también está mirando este caso{otherViewers[0].activeTab ? ` (${otherViewers[0].activeTab})` : ""}.</>
                : <>{otherViewers.length} operadores más están mirando este caso.</>
              }
            </span>
            <span className="ml-auto text-amber-400/70">Coordiná antes de cerrar/escalar.</span>
          </div>
        )}

        {/* Barra contextual: próxima acción sugerida + progreso de playbook,
            visible desde cualquier tab. Antes sólo aparecía en Resumen → LEFT
            aside (PlaybookPanel), invisible mientras el operador trabajaba en
            Assets/IOCs/Intel/etc. Sólo se renderiza si hay contenido. */}
        {(c.recommended_action || tasksTotal > 0) && (
          <div className="flex items-center gap-3 border-t border-border/40 bg-muted/10 px-4 py-1.5 text-xs">
            {c.recommended_action && (
              <div className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
                <span className="text-[11px]" aria-hidden>💡</span>
                <span className="text-[10px] font-bold uppercase tracking-wider">Siguiente</span>
                <span className="truncate text-foreground/90" title={c.recommended_action}>
                  {c.recommended_action}
                </span>
              </div>
            )}
            {tasksTotal > 0 && (
              <button
                onClick={() => setActiveTab("tasks")}
                className={cn(
                  "ml-auto flex shrink-0 items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] transition-colors",
                  tasksDone === tasksTotal
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                    : "border-border/60 bg-background hover:bg-muted/40",
                )}
                title="Ir a la pestaña Tareas"
              >
                <CheckSquare className="h-3 w-3" />
                <span className="font-mono">{tasksDone}/{tasksTotal}</span>
                <span>tareas</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* ══════════════════════ BODY ══════════════════════ */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === "summary" ? (
          // Layout 3-col del mockup. En <lg se stackea (aside pasa a full width).
          <div className={cn(
            "grid gap-4",
            focusMode
              ? "grid-cols-1"
              : "grid-cols-1 lg:grid-cols-12",
          )}>
            {/* ── LEFT (25%) ── */}
            {!focusMode && (
              <aside className="space-y-4 lg:col-span-3">
                <PlaybookPanel c={c} operatorCi={operatorCi} />
                <QuickActionsPanel
                  c={c}
                  onNotifySlack={() => {
                    // api client adjunta el Bearer via interceptor — requerido
                    // tras requireAuth() en /api/incidents.
                    void api.post(`/api/incidents/${c.id}/notify-slack`, { reason: "manual", operatorCi })
                      .then(() => void refetch())
                      .catch(() => {/* silencioso: si Slack falla no rompemos la UX */});
                  }}
                  onEscalate={() => setActiveTab("tasks")}
                  onOpenReport={() => setShowReport(true)}
                  onCloseCase={() => setShowClose(true)}
                  onNotifyClient={() => setShowNotifyClient(true)}
                />
              </aside>
            )}

            {/* ── CENTER (50%) ── */}
            <section className={cn("space-y-4", focusMode ? "" : "lg:col-span-6")}>
              <SummaryTab c={c} />
            </section>

            {/* ── RIGHT (25%) ── */}
            {!focusMode && (
              <aside className="space-y-4 lg:col-span-3">
                <IncidentVerdictCard c={c} />
                <HuntVerdictCard c={c} />
                <GeoOriginCard c={c} />
                <SimilarCasesCard caseId={caseId} />
                <HuntingInsights c={c} />
                <IocList c={c} onOpenIocs={() => setActiveTab("iocs")} />
                <SuppressionPanel c={c} />
              </aside>
            )}
          </div>
        ) : (
          // ErrorBoundary local — P4 M7 (2026-05-13). Si un tab lazy throws
          // (chunk load failed, runtime error), aísla el fallo a este panel
          // en lugar de tumbar toda la vista de investigación. `key`
          // resetea el boundary cuando el operador cambia de tab.
          <Sentry.ErrorBoundary
            key={activeTab}
            fallback={({ resetError }) => (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-6 text-center space-y-3">
                <AlertTriangle className="mx-auto h-8 w-8 text-destructive" />
                <p className="text-sm font-medium">Este tab falló al cargar</p>
                <p className="text-xs text-muted-foreground">
                  El resto del caso sigue accesible. El error fue reportado.
                </p>
                <Button size="sm" variant="outline" onClick={resetError}>
                  Reintentar
                </Button>
              </div>
            )}
          >
            <Suspense fallback={<TabFallback />}>
              {activeTab === "intel"     && <IntelTab      caseId={caseId} c={c} onEnriched={() => void refetch()} />}
              {activeTab === "events"    && <EventsTab     caseId={caseId} />}
              {activeTab === "timeline"  && <TimelineTab   caseId={caseId} c={c} operatorCi={operatorCi} />}
              {activeTab === "cves"      && <CvesTab       caseId={caseId} />}
              {activeTab === "tasks"     && <TasksTab      caseId={caseId} c={c} operatorCi={operatorCi} />}
              {activeTab === "assets"    && <AssetsTab     caseId={caseId} c={c} operatorCi={operatorCi} />}
              {activeTab === "iocs"      && <IocsTab       caseId={caseId} c={c} operatorCi={operatorCi} />}
              {activeTab === "evidences" && <EvidencesTab  caseId={caseId} c={c} operatorCi={operatorCi} />}
              {activeTab === "notes"     && <NotesTab      caseId={caseId} operatorCi={operatorCi} />}
            </Suspense>
          </Sentry.ErrorBoundary>
        )}
      </div>

      {/* Modales */}
      {showClose && (
        <CloseCaseModal
          c={c}
          operatorCi={operatorCi}
          onClose={() => setShowClose(false)}
          onDone={() => void refetch()}
        />
      )}
      {showReport && (
        <ReportPreviewModal c={c} onClose={() => setShowReport(false)} />
      )}
      {showNotifyClient && (
        <NotifyClientModal
          c={c}
          operatorCi={operatorCi}
          onClose={() => setShowNotifyClient(false)}
          onDone={() => void refetch()}
        />
      )}
    </div>
  );
}

// ── Chip KV del header ────────────────────────────────────────────────────────

function ChipKV({
  label, value, mono, valueClass,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  valueClass?: string;
}) {
  return (
    <div className="flex min-w-0 items-baseline gap-1.5">
      <span className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className={cn("truncate text-xs", mono && "font-mono", valueClass ?? "text-foreground")}>
        {value}
      </span>
    </div>
  );
}

// ── Hunting Insights (derecha) ────────────────────────────────────────────────

const HuntingInsights = memo(function HuntingInsights({ c }: { c: FullCase }) {
  const enr = (c.enrichment_data as Record<string, unknown> | undefined)?.iocEnrichment as Record<string, unknown> | undefined
    ?? (c.enrichment_data as Record<string, unknown> | undefined)
    ?? {};
  const vt     = Number(enr.vtMalicious ?? 0) || 0;
  const abuse  = Number(enr.abuseConfidence ?? 0) || 0;
  const reports = Number(enr.abuseTotalReports ?? 0) || 0;
  const org    = String(enr.shodanOrg ?? "");
  const ports  = Array.isArray(enr.openPorts) ? (enr.openPorts as number[]) : [];

  const tone = vt >= 5 || abuse >= 75 ? "red" : vt > 0 || abuse >= 25 ? "orange" : "emerald";

  return (
    <div className={cn(
      "rounded-lg border p-3 space-y-3",
      tone === "red"     && "border-red-500/40 bg-red-500/5",
      tone === "orange"  && "border-orange-500/40 bg-orange-500/5",
      tone === "emerald" && "border-emerald-500/40 bg-emerald-500/5",
    )}>
      <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
        <Shield className="h-3.5 w-3.5" />
        Hunting insights
      </div>
      <div className="grid grid-cols-2 gap-2 text-[11px]">
        <div className="rounded bg-background/40 p-2">
          <div className="text-[9px] uppercase text-muted-foreground">VirusTotal</div>
          <div className={cn("text-base font-bold", vt > 0 ? "text-red-400" : "text-emerald-400")}>
            {vt}<span className="text-xs text-muted-foreground">/94</span>
          </div>
        </div>
        <div className="rounded bg-background/40 p-2">
          <div className="text-[9px] uppercase text-muted-foreground">AbuseIPDB</div>
          <div className={cn("text-base font-bold", abuse >= 50 ? "text-red-400" : abuse > 0 ? "text-orange-400" : "text-emerald-400")}>
            {abuse}<span className="text-xs text-muted-foreground">%</span>
          </div>
          <div className="text-[10px] text-muted-foreground">{reports} reportes</div>
        </div>
      </div>
      {ports.length > 0 && (
        <div className="text-[11px]">
          <span className="text-muted-foreground">Puertos Shodan: </span>
          <span className="font-mono text-foreground/90">{ports.join(", ")}</span>
        </div>
      )}
      {org && (
        <div className="text-[11px] text-muted-foreground">
          Org: <span className="font-mono text-foreground/90">{org}</span>
        </div>
      )}
    </div>
  );
});

// ── IOC list (derecha) ────────────────────────────────────────────────────────

// R5 (2026-06-16): el listado completo de IOCs vive en el tab "IOCs" (con
// veredicto por-IOC inline). Acá, en el aside del Resumen, sólo un resumen de 1
// línea (cantidad + principal + nº maliciosos) que enlaza al tab — evita
// duplicar la lista.
const IocList = memo(function IocList({ c, onOpenIocs }: { c: FullCase; onOpenIocs?: () => void }) {
  const iocs = c.iocs ?? [];
  if (!iocs.length) return null;
  const primary = iocs.find(i => i.is_primary) ?? iocs[0];
  const malicious = iocs.filter(i =>
    (i.vt_malicious ?? 0) > 0 || (i.abuse_score ?? 0) >= 50 || i.in_misp).length;
  return (
    <button
      onClick={onOpenIocs}
      className="flex w-full items-center gap-2 rounded-lg border border-border/60 bg-background/40 px-3 py-2 text-left text-[11px] transition hover:bg-muted/30"
      title="Ver todos los IOCs (con veredicto por-IOC) en la pestaña IOCs"
    >
      <Tag className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      <span className="font-bold uppercase tracking-wider text-muted-foreground">IOCs</span>
      <span className="font-mono text-foreground/90">{iocs.length}</span>
      {primary && (
        <span className="min-w-0 truncate font-mono text-foreground/80" title={primary.ioc_value}>
          · ★ {primary.ioc_value}
        </span>
      )}
      <span className="ml-auto flex shrink-0 items-center gap-1.5">
        {malicious > 0 && (
          <span className="rounded border border-red-500/40 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400">
            {malicious} malicioso{malicious > 1 ? "s" : ""}
          </span>
        )}
        <span className="text-[10px] text-sky-400">ver →</span>
      </span>
    </button>
  );
});

// ── Summary Tab ────────────────────────────────────────────────────────────────

function SummaryTab({ c }: { c: ReturnType<typeof useFullCase>["data"] & object }) {
  const templates = useTemplates();

  const tplName = templates.data?.find(t => t.id === c.template_id)?.name;

  // Detection flow timeline (se mantiene del diseño anterior).
  const detectionFlow = (c.timeline ?? [])
    .filter(ev => ["DETECTION","ADOPT","STATUS_CHANGE","ESCALATE","CONTAINMENT"].includes(ev.event_type))
    .sort((a, b) => new Date(a.event_ts).getTime() - new Date(b.event_ts).getTime())
    .slice(0, 8);

  const iocHistory = c.iocs ?? [];

  const FLOW_LABELS: Record<string, string> = {
    DETECTION:     "Detección",
    ADOPT:         "Adopción",
    STATUS_CHANGE: "Cambio estado",
    ESCALATE:      "Escalación",
    CONTAINMENT:   "Contención",
  };

  // Datos compactos para la tarjeta "Información del caso" (queda al final
  // como referencia — la mayoría de campos ya están en el header y en los
  // paneles nuevos arriba).
  const fields: Array<[string, string]> = [
    ["ID del caso",   c.id],
    ["Apertura",      c.created_at ? formatDateTimePy(c.created_at) : "—"],
    ["Adopción",      c.adopted_at ? formatDateTimePy(c.adopted_at) : "Pendiente"],
    ["Última activ.", c.updated_at ? formatDateTimePy(c.updated_at) : "—"],
    ["Operador",      c.operator_id ?? "Sin asignar"],
    ["Escalación",    c.escalation_level ?? "—"],
    ["Escalado a",    c.escalated_to ?? "—"],
    ["Fuente",        c.source_log ?? "—"],
  ];

  return (
    <div className="space-y-4">
      {/* Banner: por qué es incidente */}
      <WhyIncidentBanner c={c} />

      {/* Señales detectadas (4 cards) */}
      <SignalsCards c={c} />

      {/* Snapshot del Hunt — sólo cuando el caso vino del flujo /hunt
          (enrichment_data.huntPivotSnapshot existe). El propio panel
          devuelve null para casos que no fueron abiertos vía Hunt Pivots. */}
      <HuntPivotSnapshotPanel c={c} />

      {/* Panel raw event (Fase 2 cargará JSON completo desde Iceberg) */}
      <RawEventPanel c={c} />

      {/* Diagrama origen → destino (Fase 2 añadirá correlación Trino) */}
      <TraceabilityPanel c={c} />

      {/* Clasificación NIST SP 800-61 (4 cards) */}
      <NistClassCards c={c} />

      {/* Template banner — informativo, pequeño */}
      {tplName && (
        <div className="flex items-center gap-2 rounded-md border border-primary/20 bg-primary/5 px-3 py-2 text-xs text-primary">
          <BookOpen className="h-3.5 w-3.5 shrink-0" />
          Plantilla aplicada: <span className="font-semibold">{tplName}</span>
        </div>
      )}

      {/* Causa raíz / lecciones — sólo si existen */}
      {(c.root_cause || c.lessons_learned) && (
        <div className="grid gap-2 sm:grid-cols-2">
          {c.root_cause && (
            <Card className="border-border/60">
              <CardHeader className="pb-1">
                <CardTitle className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  Causa raíz
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-xs leading-relaxed">{c.root_cause}</p>
              </CardContent>
            </Card>
          )}
          {c.lessons_learned && (
            <Card className="border-border/60">
              <CardHeader className="pb-1">
                <CardTitle className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  Lecciones aprendidas
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-xs leading-relaxed">{c.lessons_learned}</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Información del caso — compacta, al final */}
      <Card className="border-border/70">
        <CardHeader className="pb-2">
          <CardTitle className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
            Información del caso
          </CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-xs">
            <tbody>
              {fields.map(([label, value]) => (
                <tr key={label} className="border-b border-border/30 last:border-0">
                  <td className="whitespace-nowrap py-1 pr-3 text-muted-foreground">{label}</td>
                  <td className="break-all py-1 font-mono">{value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* ── IOC History ── */}
      {iocHistory.length > 0 && (
        <Card className="border-border/70">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
              Historial de IOCs ({iocHistory.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {iocHistory.map((ioc) => (
                <div key={ioc.id} className="rounded border border-border/50 bg-muted/10 px-3 py-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0">
                      <span className="font-mono text-xs break-all">{ioc.ioc_value}</span>
                      <div className="mt-0.5 flex flex-wrap gap-1.5">
                        <span className="rounded bg-muted/40 px-1.5 py-0 text-[10px] text-muted-foreground">{ioc.ioc_type}</span>
                        <span className={cn(
                          "rounded px-1.5 py-0 text-[10px] font-medium",
                          ioc.tlp === "RED"   ? "bg-red-500/20 text-red-400" :
                          ioc.tlp === "AMBER" ? "bg-amber-500/20 text-amber-400" :
                          ioc.tlp === "GREEN" ? "bg-emerald-500/20 text-emerald-400" :
                          "bg-muted/40 text-muted-foreground"
                        )}>TLP:{ioc.tlp}</span>
                        {ioc.is_primary && (
                          <span className="rounded bg-primary/20 px-1.5 py-0 text-[10px] text-primary">Principal</span>
                        )}
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-0.5 text-[10px] text-muted-foreground">
                      {ioc.vt_malicious != null && (
                        <span className={ioc.vt_malicious > 0 ? "text-red-400" : "text-emerald-400"}>
                          VT: {ioc.vt_malicious}
                        </span>
                      )}
                      {ioc.abuse_score != null && <span>Abuse: {ioc.abuse_score}%</span>}
                      {ioc.in_misp && <span className="text-violet-400">MISP ✓</span>}
                    </div>
                  </div>
                  {ioc.description && (
                    <p className="mt-1 text-[11px] text-muted-foreground">{ioc.description}</p>
                  )}
                  {ioc.shodan_summary && (
                    <p className="mt-0.5 font-mono text-[10px] text-muted-foreground/70 line-clamp-1">{ioc.shodan_summary}</p>
                  )}
                  {ioc.tags.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {ioc.tags.map(tag => (
                        <span key={tag} className="rounded bg-muted/30 px-1.5 py-0 text-[10px] text-muted-foreground">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Detection Flow ── */}
      {detectionFlow.length > 0 && (
        <Card className="border-border/70">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
              Flujo de Detección → Apertura del Caso
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="relative">
              {/* connecting line */}
              <div className="absolute left-[10px] top-2 bottom-2 w-px bg-border/50" />
              <div className="space-y-3 pl-7">
                {detectionFlow.map((ev, i) => (
                  <div key={ev.id} className="relative">
                    {/* dot */}
                    <div className={cn(
                      "absolute -left-7 flex h-5 w-5 items-center justify-center rounded-full border text-[9px] font-bold",
                      i === 0 ? "border-blue-500/50 bg-blue-500/20 text-blue-400" :
                      ev.event_type === "ESCALATE" ? "border-orange-500/50 bg-orange-500/20 text-orange-400" :
                      ev.event_type === "CONTAINMENT" ? "border-red-500/50 bg-red-500/20 text-red-400" :
                      "border-border/60 bg-muted/20 text-muted-foreground"
                    )}>
                      {i + 1}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium">
                          {FLOW_LABELS[ev.event_type] ?? ev.event_type}
                          {ev.title ? `: ${ev.title}` : ""}
                        </span>
                        <span className="ml-auto text-[10px] text-muted-foreground">
                          {formatDateTimePy(ev.event_ts)}
                        </span>
                      </div>
                      {ev.description && (
                        <p className="text-[11px] text-muted-foreground">{ev.description}</p>
                      )}
                      {ev.operator_ci && (
                        <p className="text-[10px] text-muted-foreground/60">@{ev.operator_ci}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Progress summary */}
      {c.tasks.length > 0 && (
        <Card className="border-border/70">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
              Progreso de tareas por fase
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              {(["DETECTION","CONTAINMENT","ERADICATION","RECOVERY","POST_INCIDENT"] as TaskPhase[]).map(phase => {
                const phaseTasks = c.tasks.filter(t => t.phase === phase);
                if (!phaseTasks.length) return null;
                const done = phaseTasks.filter(t => t.status === "DONE").length;
                return (
                  <div key={phase} className={cn("rounded-md border px-3 py-2 text-xs", PHASE_COLOR[phase] ?? "")}>
                    <p className="font-semibold">{PHASE_LABEL[phase]}</p>
                    <p className="mt-0.5 opacity-80">{done}/{phaseTasks.length} completadas</p>
                    <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-current/20">
                      <div className="h-full rounded-full bg-current" style={{ width: `${Math.round((done/phaseTasks.length)*100)}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recommended action */}
      {c.recommended_action && (
        <Card className="border-amber-500/20 bg-amber-500/5">
          <CardHeader className="pb-1">
            <CardTitle className="text-xs font-medium text-amber-400">Acción recomendada</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-amber-300/90">{c.recommended_action}</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── Notes Tab ─────────────────────────────────────────────────────────────────

function NotesTab({ caseId, operatorCi }: { caseId: string; operatorCi: string }) {
  const { data: c, refetch } = useFullCase(caseId);
  const [note, setNote]      = useState("");
  const addEvent             = useAddTimelineEvent(caseId);

  async function submit() {
    if (!note.trim()) return;
    await addEvent.mutateAsync({ eventType: "NOTE", title: note.trim(), operatorCi });
    setNote("");
    void refetch();
  }

  const notes = (c?.timeline ?? []).filter(e => e.event_type === "NOTE");

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <Input
          value={note}
          onChange={e => setNote(e.target.value)}
          placeholder="Añadir nota de investigación…"
          className="text-xs"
          onKeyDown={e => { if (e.key === "Enter") void submit(); }}
        />
        <Button size="sm" onClick={() => void submit()} disabled={addEvent.isPending || !note.trim()}>
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>
      {notes.length === 0 ? (
        <div className="rounded-md border border-dashed border-border/50 bg-muted/10 px-4 py-6 text-center">
          <BookOpen className="mx-auto mb-2 h-6 w-6 text-muted-foreground/50" aria-hidden />
          <p className="text-sm text-muted-foreground">Sin notas todavía.</p>
          <p className="mt-1 text-xs text-muted-foreground/70">
            Escribí arriba para registrar observaciones, hipótesis o el contexto
            que necesite el próximo turno. Cada nota queda en el timeline del caso.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {[...notes].reverse().map(n => (
            <div key={n.id} className="rounded-md border border-border/60 bg-card/50 px-3 py-2 text-xs">
              <p className="font-medium">{n.title}</p>
              {n.description && <p className="text-muted-foreground">{n.description}</p>}
              <p className="mt-1 text-[10px] text-muted-foreground/60">
                @{n.operator_ci ?? "system"} · {formatDateTimePy(n.event_ts)}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// (Tab "Reporte" eliminado de investigación 2026-06-16 — el informe sigue
//  disponible vía la quick action "Generar informe" → ReportPreviewModal.)

// ── Pipeline Tab ──────────────────────────────────────────────────────────────
// Workflow completo ingesta → lake → scoring → casos → evidencias.
// Incluye diagrama Mermaid copiable + descripción end-to-end.

const PIPELINE_DIAGRAM = `flowchart LR
    A["📡 Sensor\nOPNsense/Wazuh\n0–60 s"] --> B["📄 Raw log\nMinIO Iceberg\n~1 min"]
    B --> C["🧲 IOC extraído\nenriched_ioc\n1–5 min"]
    C --> D["🧪 Enriquecido\nVT · Abuse · Shodan\n5–30 min"]
    D --> E["⚖️ Score v2\n≥30 → caso\n1×/día"]
    E --> F["📁 Caso creado\nPostgreSQL\n~15 min"]
    F --> G["🔍 Analista SOC\nDashboard / Trino"]`;

// ── Severidad y prioridad ─────────────────────────────────────────────────────

const SEV_CLR: Record<string, string> = {
  CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.orange,
  LOW: C.green,    NEGLIGIBLE: C.textDim,
};

const PRIO_STYLE: Record<string, { bg: string; border: string; text: string; dot: string }> = {
  critical: { bg: alpha(C.red,    4), border: alpha(C.red,    21), text: C.red,    dot: C.red    },
  high:     { bg: alpha(C.orange, 4), border: alpha(C.orange, 21), text: C.orange, dot: C.orange },
  medium:   { bg: alpha(C.orange, 4), border: alpha(C.orange, 21), text: C.orange, dot: C.orange },
  info:     { bg: alpha(C.blue,   4), border: alpha(C.blue,   21), text: C.blue,   dot: C.blue   },
};

// ── Construcción de queries de verificación ───────────────────────────────────

interface VerifyGroup {
  group: string; icon: string;
  queries: Array<{ desc: string; sql: string }>;
}

function buildVerifyQueries(ioc: string, caseId: string): VerifyGroup[] {
  const Q = ioc || "{IOC}";
  const CID = caseId || "{CASE_ID}";
  return [
    {
      group: "¿El IOC aparece en logs crudos?", icon: "🔍",
      queries: [
        { desc: "Wazuh — alertas del IOC (últimos 7 días)",
          sql: `SELECT timestamp, rule_description, agent_name, rule_level, srcip\nFROM eventos_siem\nWHERE (srcip = '${Q}' OR dstip = '${Q}')\n  AND dt >= current_date - INTERVAL '7' DAY\nORDER BY timestamp DESC LIMIT 50` },
        { desc: "OPNsense — conexiones del IOC",
          sql: `SELECT timestamp, src, dst, proto, action\nFROM logs_perimetro\nWHERE (src = '${Q}' OR dst = '${Q}')\n  AND dt >= current_date - INTERVAL '7' DAY\nORDER BY timestamp DESC LIMIT 50` },
      ],
    },
    {
      group: "¿Qué dijo el enriquecimiento?", icon: "🧪",
      queries: [
        { desc: "VirusTotal — detecciones",
          sql: `SELECT vt_malicious, vt_suspicious, vt_harmless, vt_permalink, query_ts\nFROM reputacion_vt\nWHERE ioc_value = '${Q}'\nORDER BY query_ts DESC LIMIT 5` },
        { desc: "AbuseIPDB — reportes",
          sql: `SELECT abuse_confidence_score, total_reports, country_code, isp, last_reported_at\nFROM reputacion_ip\nWHERE ioc_value = '${Q}'\nORDER BY query_ts DESC LIMIT 3` },
        { desc: "Shodan — servicios expuestos",
          sql: `SELECT org, isp, open_ports, vulns, country_code, query_ts\nFROM exposicion_red\nWHERE ioc_value = '${Q}'\nORDER BY query_ts DESC LIMIT 3` },
      ],
    },
    {
      group: "¿Cómo se calculó el score?", icon: "⚖️",
      queries: [
        { desc: "Score v2 — desglose por componente",
          sql: `SELECT ioc_value, total_score, mitre_score, evidence_score,\n  wazuh_score, geo_score, bonus_score, source_log, dt\nFROM motor_scoring\nWHERE ioc_value = '${Q}'\nORDER BY dt DESC LIMIT 5` },
        { desc: "IOC base — estado de enriquecimiento",
          sql: `SELECT ioc_value, ioc_type, source_log, mitre_tactic_id,\n  enrichment_failed, enrichment_fail_source, dt\nFROM ioc_enriquecido\nWHERE ioc_value = '${Q}'\nORDER BY dt DESC LIMIT 5` },
      ],
    },
    {
      group: "¿Hay más actividad de este IOC?", icon: "🔗",
      queries: [
        { desc: "Otros casos con el mismo IOC",
          sql: `SELECT id, severity, status, score, adopted_at, created_at\nFROM incident_cases_pg\nWHERE ioc_value = '${Q}' AND id != '${CID}'\nORDER BY created_at DESC LIMIT 20` },
        { desc: "IOC visto en múltiples sensores",
          sql: `SELECT source_log, COUNT(*) AS hits, MAX(dt) AS last_seen\nFROM ioc_enriquecido\nWHERE ioc_value = '${Q}'\n  AND dt >= current_date - INTERVAL '30' DAY\nGROUP BY source_log ORDER BY hits DESC` },
      ],
    },
    {
      group: "Auditoría del caso", icon: "📋",
      queries: [
        { desc: "Timeline NIST SP800-61 completo",
          sql: `SELECT event_type, actor_ci, detail, nist_phase, created_at\nFROM case_timeline_events\nWHERE case_id = '${CID}'\nORDER BY created_at` },
        { desc: "IOCs confirmados del caso",
          sql: `SELECT ioc_value, ioc_type, tlp, confidence, added_by, created_at\nFROM case_iocs WHERE case_id = '${CID}'` },
        { desc: "Tareas DFIR del caso",
          sql: `SELECT phase, title, status, assigned_to, completed_at\nFROM case_tasks WHERE case_id = '${CID}'\nORDER BY phase, created_at` },
      ],
    },
  ];
}

// ── Recomendaciones dinámicas según señales ───────────────────────────────────

type RecommendationPrio = "critical" | "high" | "medium" | "info";
interface Recommendation { prio: RecommendationPrio; label: string; action: string }

function buildRecommendations(opts: {
  vtMalicious: number | null; abuseConf: number | null;
  inUrlhaus: boolean; inMisp: boolean;
  shodanPorts: number[]; shodanVulns: string[];
  mitreTacticId: string | null; mitreTacticName: string | null;
  wazuhLevelRaw: number | null;
  enrichmentFailed: boolean;
  score: number; severity: string;
}): Recommendation[] {
  const { vtMalicious, abuseConf, inUrlhaus, inMisp,
          shodanPorts, shodanVulns, mitreTacticId, mitreTacticName,
          wazuhLevelRaw, enrichmentFailed, score, severity } = opts;
  const recs: Recommendation[] = [];

  if (inUrlhaus) {
    recs.push({ prio: "critical", label: "URLhaus — URL de distribución de malware activo",
      action: "Este IOC está confirmado en el feed URLhaus como distribución de malware. Aislar inmediatamente los endpoints que hayan resuelto o conectado a esta URL. Revisar proxy logs y registros DNS internos de las últimas 24h." });
  }

  if (vtMalicious != null && vtMalicious >= 5) {
    recs.push({ prio: "critical", label: `VirusTotal — ${vtMalicious} motores AV detectaron actividad maliciosa`,
      action: "Abrir el permalink de VT para identificar familias de malware y YARA rules asociadas. Buscar el hash de las muestras en el endpoint afectado. Correlacionar con la táctica MITRE detectada para entender el vector de ataque." });
  } else if (vtMalicious != null && vtMalicious > 0) {
    recs.push({ prio: "high", label: `VirusTotal — ${vtMalicious} motor(es) detectaron actividad`,
      action: "Detecciones parciales. Verificar el contexto en el permalink de VT (¿es un CDN, proxy o IP compartida?). Revisar si el activo interno generó conexiones salientes a esta IP." });
  }

  if (abuseConf != null && abuseConf >= 70) {
    recs.push({ prio: "critical", label: `AbuseIPDB — ${abuseConf}% de confianza, IP ampliamente reportada`,
      action: "IP con historial sólido de actividad maliciosa. Bloquear en OPNsense (Firewall → Aliases → Blocklist) si no está ya bloqueada. Verificar si hay conexiones activas desde la red interna. Revisar si es compartida (CG-NAT, CDN) antes de bloquear en producción." });
  } else if (abuseConf != null && abuseConf >= 30) {
    recs.push({ prio: "high", label: `AbuseIPDB — ${abuseConf}% de confianza`,
      action: "IP con reportes previos. Revisar el historial en AbuseIPDB (tipos de abuso, frecuencia). Evaluar bloqueo preventivo y configurar alerta de seguimiento si el tráfico continúa." });
  }

  if (shodanVulns.length > 0) {
    const top = shodanVulns.slice(0, 4).join(", ");
    recs.push({ prio: "high", label: `Shodan — ${shodanVulns.length} CVE(s) expuesto(s) en el host remoto`,
      action: `CVEs detectados: ${top}${shodanVulns.length > 4 ? "…" : ""}. Verificar si alguno de estos CVEs es explotable contra los servicios internos que se comunican con este host. Priorizar según CVSS y compatibilidad con el stack del entorno.` });
  } else if (shodanPorts.length > 5) {
    recs.push({ prio: "medium", label: `Shodan — ${shodanPorts.length} puertos expuestos: ${shodanPorts.slice(0, 6).join(", ")}`,
      action: "El host remoto tiene muchos servicios expuestos. Evaluar si el tráfico interno va a puertos inusuales (no 80/443). Considerar que puede ser un servidor VPS de C2 o un escáner masivo." });
  }

  if (mitreTacticId) {
    const TACTIC_ACTION: Record<string, string> = {
      TA0001: "Initial Access — Verificar si la brecha tuvo éxito revisando logs de autenticación del activo afectado. Buscar sesiones activas de usuarios comprometidos. Revisar VPN, RDP y SSH logs.",
      TA0002: "Execution — Buscar procesos hijo sospechosos con auditd/Sysmon en el endpoint. Verificar scripts descargados y comandos ejecutados en la ventana temporal del evento.",
      TA0003: "Persistence — Revisar crontabs, servicios systemd, llaves SSH autorizadas y configuración de sudo en el activo afectado.",
      TA0004: "Privilege Escalation — Verificar cambios en sudoers, grupos privilegiados y tokens elevados. Revisar logs de su/sudo.",
      TA0005: "Defense Evasion — Revisar procesos con nombres camuflados, logs de AV/EDR y ofuscación en comandos. Verificar integridad de binarios clave.",
      TA0006: "Credential Access — Cambiar credenciales del activo afectado preventivamente. Revisar accesos a /etc/shadow, LSASS o Active Directory.",
      TA0007: "Discovery — Buscar escaneos de red internos desde el activo. Correlacionar con alertas Wazuh de reconocimiento (reglas 40xxx). Revisar nmap o ARP broadcasts.",
      TA0008: "Lateral Movement — Analizar conexiones SMB, RDP y SSH desde el activo comprometido hacia otros hosts internos. Revisar eventos de autenticación en los hosts destino.",
      TA0009: "Collection — Revisar accesos a archivos sensibles y movimientos de datos. Verificar volúmenes de lectura inusuales en shares de red.",
      TA0010: "Exfiltration — Verificar tráfico saliente inusual por volumen o destino. Revisar DNS tunneling y conexiones a servicios cloud no autorizados.",
      TA0011: "Command and Control — Bloquear el C2 en firewall y buscar beaconing periódico (conexiones regulares cada N segundos/minutos). Analizar el patrón de tráfico.",
      TA0040: "Impact — Evaluar integridad de datos y disponibilidad de sistemas. Activar protocolo de recuperación. Documentar alcance del daño.",
    };
    const action = TACTIC_ACTION[mitreTacticId]
      ?? `Táctica ${mitreTacticId} (${mitreTacticName ?? "—"}) detectada — revisar el playbook MITRE correspondiente y las contramedidas recomendadas en ATT&CK Navigator.`;
    recs.push({ prio: "high", label: `MITRE ${mitreTacticId} — ${mitreTacticName ?? "Táctica detectada"}`, action });
  }

  if (wazuhLevelRaw != null && wazuhLevelRaw >= 12) {
    recs.push({ prio: "high", label: `Wazuh nivel ${wazuhLevelRaw}/15 — alerta de alta criticidad`,
      action: `Nivel ≥12 en Wazuh indica evento crítico (escala 0–15). Abrir el agente Wazuh del host origen para ver las reglas correladas y el contexto completo. Verificar si hay alertas relacionadas en la misma ventana temporal.` });
  }

  if (inMisp) {
    recs.push({ prio: "medium", label: "MISP — IOC correlacionado en inteligencia compartida",
      action: "Este IOC tiene correspondencia en MISP. Revisar el evento MISP para obtener contexto adicional: actor de amenaza, campaña, TTPs relacionados y otros IOCs de la misma familia. Puede revelar el objetivo real del ataque." });
  }

  if (enrichmentFailed) {
    recs.push({ prio: "medium", label: "Enriquecimiento incompleto — circuit breaker activado",
      action: "Una o más fuentes de enriquecimiento fallaron (VT, Shodan, AbuseIPDB o RDNS). El score puede estar subestimado. Verificar manualmente en las fuentes antes de descartar como falso positivo. Revisar EnrichedScore para ver qué fuente falló." });
  }

  if (recs.length === 0) {
    const isLowScore = score < 50;
    recs.push({ prio: "info",
      label: isLowScore ? "Señales moderadas — verificar contexto del activo" : "Revisar correlación con otros eventos",
      action: `Score ${score} → ${severity}. Las señales individuales son moderadas pero el conjunto superó el umbral. Investigar el activo afectado, verificar si el IOC tiene historial previo en el entorno y correlacionar con otros eventos en la misma ventana temporal (±30 min).` });
  }

  return recs;
}

// ── SignalCard ─────────────────────────────────────────────────────────────────

function SignalCard({ label, value, color, fired, sub }: {
  label: string; value: string; color: string; fired: boolean; sub?: string;
}) {
  return (
    <div style={{
      background: fired ? alpha(color, 5) : C.bg,
      border: `1px solid ${fired ? alpha(color, 27) : C.border}`,
      borderRadius: 8, padding: "10px 12px", display: "flex", flexDirection: "column", gap: 3,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        <div style={{ width: 5, height: 5, borderRadius: "50%", background: fired ? color : C.textDim, flexShrink: 0 }} />
        <span style={{ fontSize: 9, color: C.textDim, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase" }}>{label}</span>
      </div>
      <p style={{ fontSize: 12, fontWeight: 700, color: fired ? color : C.textDim, margin: 0 }}>{value}</p>
      {sub && <p style={{ fontSize: 9, color: C.textDim, fontFamily: "monospace", margin: 0 }}>{sub}</p>}
    </div>
  );
}

// ── PipelineTab ───────────────────────────────────────────────────────────────
// Exportado para un eventual panel de admin/diagnóstico: la tab fue retirada
// del navigator del operador SOC (A7), pero el componente vale la pena
// preservarlo por el diagrama Mermaid del workflow completo.
export function PipelineTab({ c }: { c: NonNullable<ReturnType<typeof useFullCase>["data"]> }) {
  const [expandedQ, setExpandedQ]     = useState<number | null>(null);
  const [copiedSql, setCopiedSql]     = useState<string | null>(null);
  const [showDiagram, setShowDiagram] = useState(false);

  const ioc      = c.ioc_value ?? "";
  const caseId   = c.id ?? "";
  const severity = String(c.severity ?? "MEDIUM").toUpperCase();
  const score    = Number(c.score ?? 0);
  const sevColor = SEV_CLR[severity] ?? C.textDim;

  // Enrichment data sources
  const ed         = (c.enrichment_data ?? {}) as Record<string, unknown>;
  const iocEnr     = ((ed.iocEnrichment ?? ed) as Record<string, unknown>);
  const iocSrc     = (ed.iocSources ?? {}) as Record<string, unknown>;
  const primaryIoc = c.iocs?.find((i) => i.is_primary) ?? c.iocs?.[0] ?? null;

  const vtMalicious  = (primaryIoc?.vt_malicious  ?? (iocSrc.virustotal as Record<string,unknown>)?.malicious  ?? iocEnr.vtMalicious  ?? null) as number | null;
  const abuseConf    = (primaryIoc?.abuse_score    ?? (iocSrc.abuseipdb as Record<string,unknown>)?.abuseConfidenceScore ?? iocEnr.abuseConfidence ?? null) as number | null;
  const inUrlhaus    = Boolean(iocEnr.inUrlhaus ?? iocSrc.urlhaus);
  const inMisp       = Boolean(primaryIoc?.in_misp ?? iocEnr.inMisp);
  const vtPermalink  = (primaryIoc?.vt_permalink ?? (iocSrc.virustotal as Record<string,unknown>)?.permalink ?? null) as string | null;

  // shodan: prefer iocSources.shodan (normalizado en el hook) > parse del
  // shodan_summary (string JSONB en IOC). parseShodanSummary también aplica
  // normalización a los arrays internos (ports/vulns/services).
  const shodanData: Record<string, unknown> | null =
    (iocSrc.shodan as Record<string, unknown> | undefined) ?? parseShodanSummary(primaryIoc?.shodan_summary);
  const shodanPorts = (shodanData?.ports ?? iocEnr.shodanPorts ?? []) as number[];
  const shodanVulns = (shodanData?.vulns ?? iocEnr.shodanVulns ?? []) as string[];
  const shodanOrg   = (shodanData?.org ?? null) as string | null;

  const wazuhLevelRaw   = (ed.wazuh_level ?? iocEnr.wazuhLevel ?? null) as number | null;
  const enrichmentFailed = Boolean(ed.enrichment_failed ?? iocEnr.enrichmentFailed
    ?? (primaryIoc as unknown as Record<string,unknown> | null)?.enrichment_failed);

  const vtTotal    = ((iocSrc.virustotal as Record<string,unknown>)?.total ?? null) as number | null;
  const abuseISP   = ((iocSrc.abuseipdb as Record<string,unknown>)?.isp   ?? null) as string | null;
  const abuseCC    = ((iocSrc.abuseipdb as Record<string,unknown>)?.countryCode ?? null) as string | null;

  // Signal count for the summary pill
  const activeSignals = [
    (vtMalicious ?? 0) > 0,
    (abuseConf ?? 0) >= 30,
    inUrlhaus,
    inMisp,
    shodanVulns.length > 0,
    Boolean(c.mitre_tactic_id),
  ].filter(Boolean).length;

  const recs = buildRecommendations({
    vtMalicious, abuseConf, inUrlhaus, inMisp,
    shodanPorts, shodanVulns,
    mitreTacticId: c.mitre_tactic_id, mitreTacticName: c.mitre_tactic_name,
    wazuhLevelRaw, enrichmentFailed, score, severity,
  });

  const verifyGroups = buildVerifyQueries(ioc, caseId);

  function copySql(sql: string) {
    void navigator.clipboard.writeText(sql).then(() => {
      setCopiedSql(sql);
      setTimeout(() => setCopiedSql(null), 2000);
    });
  }

  // Pipeline journey steps
  const journey = [
    { icon: "📡", label: "Sensor",        detail: c.source_log ?? "Wazuh / OPNsense",           latency: "0–60 s",  ok: true,            warn: false },
    { icon: "📄", label: "Raw log",       detail: "MinIO Iceberg Parquet",                        latency: "~1 min",  ok: true,            warn: false },
    { icon: "🧲", label: "IOC extraído",  detail: `${c.ioc_type ?? "ip"}: ${ioc || "—"}`,        latency: "1–5 min", ok: Boolean(ioc),    warn: !ioc },
    { icon: enrichmentFailed ? "⚠️" : "✅", label: "Enriquecido", detail: enrichmentFailed ? "Parcial (CB)" : "VT · Abuse · Shodan · RDNS", latency: "5–30 min", ok: !enrichmentFailed, warn: enrichmentFailed },
    { icon: "⚖️", label: "Score ≥ 30",   detail: `${score} → ${severity}`,                      latency: "1×/día",  ok: score >= 30,     warn: false },
    { icon: "📁", label: "Caso creado",   detail: c.status ?? "NUEVO",                            latency: "~15 min", ok: true,            warn: false },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* ── VEREDICTO ───────────────────────────────────────────────────────── */}
      <div style={{
        position: "relative", background: C.bg,
        border: `1px solid ${alpha(sevColor, 21)}`, borderRadius: 12,
        padding: "18px 20px 16px 24px", overflow: "hidden",
      }}>
        <div style={{ position: "absolute", top: 0, left: 0, bottom: 0, width: 4, background: sevColor, borderRadius: "12px 0 0 12px" }} />

        {/* Title row */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
          <div>
            <p style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 5 }}>¿Por qué es un incidente?</p>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <code style={{ fontSize: 14, fontWeight: 700, color: sevColor, background: alpha(sevColor, 8), padding: "2px 8px", borderRadius: 4 }}>
                {ioc || "IOC no disponible"}
              </code>
              <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 700, background: alpha(sevColor, 12), color: sevColor, border: `1px solid ${alpha(sevColor, 31)}` }}>
                {severity}
              </span>
              {c.mitre_tactic_id && (
                <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, background: alpha(C.purple, 12), color: C.purple, border: `1px solid ${alpha(C.purple, 25)}` }}>
                  {c.mitre_tactic_id}{c.mitre_tactic_name ? ` — ${c.mitre_tactic_name}` : ""}
                </span>
              )}
            </div>
            {(c.source_log || c.mitre_technique_id) && (
              <p style={{ fontSize: 11, color: C.textDim, marginTop: 6 }}>
                {c.source_log && <>Fuente: <span style={{ color: C.textDim }}>{c.source_log}</span></>}
                {c.mitre_technique_id && <> · Técnica: <code style={{ color: C.purple }}>{c.mitre_technique_id}</code></>}
                {shodanOrg && <> · Org: <span style={{ color: C.textDim }}>{shodanOrg}</span></>}
              </p>
            )}
          </div>
          {/* Score */}
          <div style={{ textAlign: "right", flexShrink: 0 }}>
            <p style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.08em", textTransform: "uppercase" }}>Score</p>
            <p style={{ fontSize: 40, fontWeight: 900, color: sevColor, lineHeight: 1, margin: "2px 0" }}>{score}</p>
            <p style={{ fontSize: 9, color: C.textDim }}>umbral: 30 · escala: 0–200</p>
          </div>
        </div>

        {/* Active signals pill */}
        {activeSignals > 0 && (
          <div style={{ marginTop: 12, padding: "7px 12px", borderRadius: 6, background: alpha(sevColor, 4), border: `1px solid ${alpha(sevColor, 15)}`, fontSize: 11, color: C.textDim, display: "inline-flex", gap: 6, alignItems: "center" }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: sevColor }} />
            <span>
              <strong style={{ color: sevColor }}>{activeSignals} fuente{activeSignals !== 1 ? "s" : ""} de inteligencia</strong>
              {" "}confirmaron actividad maliciosa — score {score} supera el umbral de apertura (30).
            </span>
          </div>
        )}

        {/* VT permalink */}
        {vtPermalink && (
          <div style={{ marginTop: 8 }}>
            <a href={vtPermalink} target="_blank" rel="noopener noreferrer"
              style={{ fontSize: 10, color: C.blue, display: "inline-flex", alignItems: "center", gap: 4 }}>
              <ExternalLink className="h-3 w-3" style={{ display: "inline" }} />
              Ver análisis completo en VirusTotal
            </a>
          </div>
        )}
      </div>

      {/* ── SEÑALES DETECTADAS ───────────────────────────────────────────────── */}
      <div>
        <p style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8, fontWeight: 600 }}>
          Señales detectadas
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(185px, 1fr))", gap: 8 }}>
          {vtMalicious != null && (
            <SignalCard label="VirusTotal"
              value={vtMalicious > 0 ? `${vtMalicious}${vtTotal ? `/${vtTotal}` : ""} motores` : "Sin detecciones"}
              color={vtMalicious >= 5 ? C.red : vtMalicious > 0 ? C.orange : C.green}
              fired={vtMalicious > 0}
              sub={vtMalicious > 0 ? "AV engines detectaron actividad maliciosa" : undefined} />
          )}
          {abuseConf != null && (
            <SignalCard label="AbuseIPDB"
              value={`${abuseConf}% confianza`}
              color={abuseConf >= 70 ? C.red : abuseConf >= 30 ? C.orange : C.green}
              fired={abuseConf >= 30}
              sub={abuseISP ? `${abuseCC ?? ""} · ${abuseISP}`.trim() : undefined} />
          )}
          {inUrlhaus && (
            <SignalCard label="URLhaus" value="URL maliciosa activa" color={C.red} fired
              sub="Distribución de malware confirmada" />
          )}
          {inMisp && (
            <SignalCard label="MISP Threat Intel" value="Correlación encontrada" color={C.orange} fired
              sub="IOC en inteligencia compartida" />
          )}
          {shodanVulns.length > 0 && (
            <SignalCard label="Shodan CVEs"
              value={`${shodanVulns.length} vulnerabilidad${shodanVulns.length !== 1 ? "es" : ""}`}
              color={C.orange} fired
              sub={shodanVulns.slice(0, 3).join(", ")} />
          )}
          {shodanPorts.length > 0 && shodanVulns.length === 0 && (
            <SignalCard label="Shodan puertos"
              value={`${shodanPorts.length} puerto${shodanPorts.length !== 1 ? "s" : ""} expuesto${shodanPorts.length !== 1 ? "s" : ""}`}
              color={C.orange} fired={shodanPorts.length > 4}
              sub={shodanPorts.slice(0, 6).map(String).join(", ")} />
          )}
          {c.mitre_tactic_id && (
            <SignalCard label={`MITRE ${c.mitre_tactic_id}`}
              value={c.mitre_tactic_name ?? "Táctica detectada"}
              color={C.purple} fired
              sub={c.mitre_technique_id ?? undefined} />
          )}
          {wazuhLevelRaw != null && (
            <SignalCard label="Wazuh"
              value={`Nivel ${wazuhLevelRaw}/15`}
              color={wazuhLevelRaw >= 12 ? C.red : wazuhLevelRaw >= 9 ? C.orange : C.textDim}
              fired={wazuhLevelRaw >= 9} />
          )}
          {enrichmentFailed && (
            <SignalCard label="Enriquecimiento" value="Circuit breaker activado"
              color={C.orange} fired={false} sub="Datos pueden estar incompletos" />
          )}
        </div>
      </div>

      {/* ── CADENA INGESTA → CASO ────────────────────────────────────────────── */}
      <div>
        <p style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 10, fontWeight: 600 }}>
          Cadena ingesta → caso
        </p>
        <div style={{ display: "flex", alignItems: "flex-start", overflowX: "auto", paddingBottom: 4 }}>
          {journey.map((s, i) => (
            <div key={i} style={{ display: "flex", alignItems: "flex-start", minWidth: 0 }}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 100, padding: "6px 4px" }}>
                <div style={{
                  width: 34, height: 34, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                  background: s.warn ? alpha(C.orange, 9) : s.ok ? alpha(sevColor, 13) : C.border,
                  border: `2px solid ${s.warn ? alpha(C.orange, 33) : s.ok ? alpha(sevColor, 40) : C.border}`,
                  fontSize: 15, flexShrink: 0,
                }}>{s.icon}</div>
                <span style={{ fontSize: 10, fontWeight: 600, color: C.text, marginTop: 5, textAlign: "center" }}>{s.label}</span>
                <span style={{ fontSize: 9, color: C.textDim, textAlign: "center", marginTop: 2, lineHeight: 1.3, maxWidth: 90 }}>{s.detail}</span>
                <span style={{ fontSize: 8, color: C.textDim, marginTop: 3 }}>{s.latency}</span>
              </div>
              {i < journey.length - 1 && (
                <div style={{ flex: 1, height: 2, minWidth: 12, marginTop: 22, background: `linear-gradient(90deg, ${alpha(sevColor, 33)}, ${C.border})` }} />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── RECOMENDACIONES PRÁCTICAS ────────────────────────────────────────── */}
      <div>
        <p style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8, fontWeight: 600 }}>
          Recomendaciones prácticas
        </p>
        {/* Recommended action from playbook if available */}
        {c.recommended_action && (
          <div style={{ marginBottom: 10, padding: "10px 14px", borderRadius: 8, background: alpha(C.orange, 3), border: `1px solid ${alpha(C.orange, 19)}`, fontSize: 11, color: C.orange, lineHeight: 1.5 }}>
            <span style={{ fontSize: 9, fontWeight: 700, color: C.orange, letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 4 }}>Playbook generado automáticamente</span>
            {c.recommended_action}
          </div>
        )}
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {recs.map((r, i) => {
            const ps = PRIO_STYLE[r.prio];
            return (
              <div key={i} style={{ background: ps.bg, border: `1px solid ${ps.border}`, borderRadius: 8, padding: "10px 14px", display: "flex", gap: 10 }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: ps.dot, marginTop: 5, flexShrink: 0 }} />
                <div>
                  <p style={{ fontSize: 12, fontWeight: 600, color: ps.text, marginBottom: 3, margin: "0 0 3px" }}>{r.label}</p>
                  <p style={{ fontSize: 11, color: C.textDim, lineHeight: 1.55, margin: 0 }}>{r.action}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── QUERIES DE VERIFICACIÓN ──────────────────────────────────────────── */}
      <div>
        <p style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8, fontWeight: 600 }}>
          Queries de verificación (Trino)
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {verifyGroups.map((group, gi) => (
            <div key={gi} style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
              <button
                onClick={() => setExpandedQ(expandedQ === gi ? null : gi)}
                style={{
                  width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
                  padding: "10px 14px", background: "none", border: "none", cursor: "pointer",
                  fontSize: 12, color: C.text, fontWeight: 500, textAlign: "left",
                }}
              >
                <span>{group.icon} {group.group}</span>
                <span style={{ fontSize: 10, color: C.textDim, flexShrink: 0 }}>{expandedQ === gi ? "▲" : "▼"} {group.queries.length} queries</span>
              </button>
              {expandedQ === gi && (
                <div style={{ borderTop: `1px solid ${C.border}` }}>
                  {group.queries.map((q, qi) => {
                    // Anonimiza los nombres internos de tablas del lake antes de
                    // mostrar/copiar el SQL al operador (no expone el stack).
                    const shownSql = anonymizeTables(q.sql);
                    return (
                    <div key={qi} style={{ borderBottom: qi < group.queries.length - 1 ? `1px solid ${C.border}` : "none" }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 14px 4px", background: C.bg }}>
                        <span style={{ fontSize: 10, color: C.textDim }}>{q.desc}</span>
                        <button
                          onClick={() => copySql(shownSql)}
                          style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, flexShrink: 0,
                            background: copiedSql === shownSql ? alpha(C.green, 12) : C.border,
                            border: `1px solid ${copiedSql === shownSql ? alpha(C.green, 25) : C.border}`,
                            color: copiedSql === shownSql ? C.green : C.textDim, cursor: "pointer" }}
                        >
                          {copiedSql === shownSql ? "✓" : "Copiar"}
                        </button>
                      </div>
                      <pre style={{ margin: 0, padding: "6px 14px 10px", fontSize: 9, lineHeight: 1.6, color: C.textDim, overflowX: "auto", background: C.bg, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                        {shownSql}
                      </pre>
                    </div>
                    );
                  })}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── DIAGRAMA TÉCNICO (colapsable) ────────────────────────────────────── */}
      <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
        <button
          onClick={() => setShowDiagram(!showDiagram)}
          style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "9px 14px", background: "none", border: "none", cursor: "pointer", fontSize: 11, color: C.textDim }}
        >
          <span>🔧 Diagrama técnico del pipeline completo</span>
          <span style={{ fontSize: 10 }}>{showDiagram ? "▲ Ocultar" : "▼ Ver Mermaid"}</span>
        </button>
        {showDiagram && (
          <div style={{ borderTop: `1px solid ${C.border}`, padding: 14 }}>
            <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
              <button onClick={() => void navigator.clipboard.writeText(PIPELINE_DIAGRAM)}
                style={{ fontSize: 10, padding: "3px 10px", borderRadius: 4, background: C.border, border: `1px solid ${C.border}`, color: C.textDim, cursor: "pointer" }}>
                Copiar Mermaid
              </button>
              <button onClick={() => { const e = btoa(JSON.stringify({ code: PIPELINE_DIAGRAM, mermaid: { theme: "dark" } })); window.open(`https://mermaid.live/edit#base64:${e}`, "_blank", "noopener,noreferrer"); }}
                style={{ fontSize: 10, padding: "3px 10px", borderRadius: 4, background: C.border, border: `1px solid ${C.border}`, color: C.textDim, cursor: "pointer" }}>
                Mermaid Live ↗
              </button>
            </div>
            <pre style={{ fontSize: 9, lineHeight: 1.5, color: C.textDim, overflowX: "auto", margin: 0 }}>
              {PIPELINE_DIAGRAM}
            </pre>
          </div>
        )}
      </div>

    </div>
  );
}

// ── Intel Tab ─────────────────────────────────────────────────────────────────

type IocEnrichSummary = {
  vtMalicious?: number | null;
  vtSuspicious?: number | null;
  abuseConfidence?: number | null;
  inUrlhaus?: boolean;
  inOpenphish?: boolean;
  inMisp?: boolean;
  country?: string | null;
  shodanPorts?: number[];
  shodanVulns?: string[];
  mispThreatLevel?: string | null;
  mispTags?: string[];
};

type IocSources = {
  virustotal?: {
    malicious?: number; suspicious?: number; harmless?: number; total?: number;
    reputation?: number | null; country?: string | null; asOwner?: string | null;
    tags?: string[]; lastAnalysis?: string | null; permalink?: string;
  } | null;
  shodan?: {
    ip?: string; org?: string | null; isp?: string | null; country?: string | null;
    city?: string | null; asn?: string | null; os?: string | null;
    ports?: number[]; hostnames?: string[]; tags?: string[]; vulns?: string[]; kevVulns?: string[];
    lastUpdate?: string | null;
    services?: Array<{ port?: number; transport?: string; product?: string | null; version?: string | null }>;
  } | null;
  abuseipdb?: {
    abuseConfidenceScore?: number; totalReports?: number; numDistinctUsers?: number;
    countryCode?: string | null; isp?: string | null; domain?: string | null;
    isWhitelisted?: boolean; lastReportedAt?: string | null; usageType?: string | null;
  } | null;
  misp?: {
    events?: Array<{ event_id?: string; event_title?: string; threat_level?: string; tags?: string[] }>;
    tags?: string[]; threatLevel?: string | null;
    firstSeen?: string | null; lastSeen?: string | null; sightings?: number;
  } | null;
  urlhaus?: { inFeed?: boolean; urlCount?: number; tags?: string[] } | null;
};

// ── I2 (audit 2026-06-05): pivote de correlación por IOC ──────────────────────
type RelatedCase = {
  id: string;
  severity: string | null;
  status: string | null;
  operator_id: string | null;
  created_at: string;
  age_days: number | null;
};
type RelatedResponse = {
  case_id: string;
  ioc_value: string | null;
  ioc_type: string | null;
  open: RelatedCase[];
  open_count: number;
  closed_count: number;
  total: number;
};

/**
 * Panel "otros casos con este IOC". Consume GET /api/cases/:id/related.
 * Sólo se muestra si hay correlación (total > 0). Los abiertos son accionables
 * (link deep al caso); los terminales se resumen como conteo (recurrencias).
 */
function RelatedCasesPanel({ caseId }: { caseId: string }) {
  const { data } = useQuery<RelatedResponse>({
    queryKey: ["case-related", caseId],
    queryFn: async () => {
      const { data } = await api.get<RelatedResponse>(
        `/api/cases/${encodeURIComponent(caseId)}/related`,
      );
      return data;
    },
    enabled: Boolean(caseId),
    staleTime: 60_000,
  });

  if (!data || !data.ioc_value || data.total === 0) return null;

  return (
    <div className="rounded border border-amber-500/30 bg-amber-500/[0.06] p-3">
      <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-amber-300">
        <Link2 className="h-3.5 w-3.5" aria-hidden />
        Correlación por IOC — {data.total} otro{data.total !== 1 ? "s" : ""} caso{data.total !== 1 ? "s" : ""} con este IOC
        {data.closed_count > 0 && (
          <span className="font-normal text-muted-foreground">
            ({data.open_count} abierto{data.open_count !== 1 ? "s" : ""} · {data.closed_count} cerrado{data.closed_count !== 1 ? "s" : ""}/recurrencias)
          </span>
        )}
      </div>
      {data.open.length === 0 ? (
        <p className="text-[11px] text-muted-foreground">
          Sin casos abiertos — {data.closed_count} aparición(es) previa(s) ya resueltas o suprimidas.
        </p>
      ) : (
        <ul className="space-y-1">
          {data.open.map((rc) => (
            <li key={rc.id}>
              <a
                href={`/gestion?investigate=${encodeURIComponent(rc.id)}`}
                className="flex items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-amber-500/10"
              >
                <span className={cn("font-semibold uppercase", SEV_COLOR[rc.severity ?? ""] ?? "text-muted-foreground")}>
                  {rc.severity ?? "—"}
                </span>
                <span className="rounded border border-border/50 px-1 py-0.5 text-[10px] text-muted-foreground">
                  {rc.status ?? "—"}
                </span>
                <code className="font-mono text-foreground/80">{rc.id.slice(0, 8)}</code>
                {rc.age_days != null && (
                  <span className="text-muted-foreground/70">hace {rc.age_days}d</span>
                )}
                {rc.operator_id && (
                  <span className="text-muted-foreground/70">· {rc.operator_id}</span>
                )}
                <ExternalLink className="ml-auto h-3 w-3 text-amber-400/70" aria-hidden />
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ── Tarjeta "Casos similares" (clase eCSIRT) ──────────────────────────────────
// Consume GET /api/cases/:id/similar: cuántos casos de la MISMA clase eCSIRT hay
// abiertos ahora y, sobre los resueltos recientes, QUÉ hicieron los analistas
// con ellos (disposición, MTTR, % escalado/auto, quién los maneja). Orienta el
// triage del caso actual sin salir de la investigación.
type SimilarDisposition = { key: string; label: string; count: number; pct: number };
type SimilarExample = {
  id: string;
  severity: string | null;
  dispositionKey: string;
  dispositionLabel: string;
  action: string | null;
  operatorId: string | null;
  ageDays: number | null;
};
type SimilarResponse = {
  case_id: string;
  basis: {
    incidentClass: string | null;
    label: string;
    short: string;
    sourceLog: string | null;
    iocType: string | null;
    windowDays: number;
  };
  openCount: number;
  handled: null | {
    total: number;
    mttrHours: number | null;
    escalatedPct: number;
    dispositions: SimilarDisposition[];
    topOperators: Array<{ operatorId: string; count: number }>;
  };
  examples: SimilarExample[];
  recommendation: string | null;
};

// Color por disposición: FP es el desenlace "bueno" (verde), TP el de riesgo
// (rojo), el resto neutro/ámbar. Coherente con la semántica de la cola.
const DISP_COLOR: Record<string, string> = {
  TRUE_POSITIVE:  "bg-red-500",
  FALSE_POSITIVE: "bg-emerald-500",
  NO_ACTIONABLE:  "bg-amber-500",
  DUPLICATE:      "bg-slate-500",
  OTHER:          "bg-slate-400",
};

function SimilarCasesCard({ caseId }: { caseId: string }) {
  const { data, isLoading } = useQuery<SimilarResponse>({
    queryKey: ["case-similar", caseId],
    queryFn: async () => {
      const { data } = await api.get<SimilarResponse>(
        `/api/cases/${encodeURIComponent(caseId)}/similar`,
      );
      return data;
    },
    enabled: Boolean(caseId),
    staleTime: 120_000,
  });

  if (isLoading) {
    return (
      <div className="rounded border border-border/40 bg-muted/10 p-3">
        <div className="h-3 w-32 animate-pulse rounded bg-muted-foreground/20" />
        <div className="mt-2 h-2 w-full animate-pulse rounded bg-muted-foreground/10" />
        <div className="mt-1.5 h-2 w-3/4 animate-pulse rounded bg-muted-foreground/10" />
      </div>
    );
  }

  // Sin clase persistida (caso pre-backfill) o sin nada accionable → no ocupamos
  // espacio en el aside.
  if (!data || !data.basis.incidentClass) return null;
  const h = data.handled;
  if (data.openCount === 0 && !h && data.examples.length === 0) return null;

  const fmtMttr = (hrs: number) => (hrs < 48 ? `${hrs}h` : `${Math.round(hrs / 24)}d`);

  return (
    <div className="rounded border border-cyan-500/30 bg-cyan-500/[0.05] p-3">
      <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-cyan-300">
        <Layers className="h-3.5 w-3.5" aria-hidden />
        Casos similares
        <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1 py-0.5 text-[9px] font-bold uppercase tracking-wider text-cyan-200">
          {data.basis.short}
        </span>
      </div>
      <p className="mb-2 text-[10px] text-muted-foreground">
        Misma clase eCSIRT · cómo se trataron · últimos {data.basis.windowDays}d
      </p>

      {/* Abiertos ahora */}
      <div className="mb-2 flex items-baseline gap-1.5 text-[11px]">
        <span className="text-base font-bold tabular-nums text-foreground">{data.openCount}</span>
        <span className="text-muted-foreground">
          abierto{data.openCount !== 1 ? "s" : ""} ahora con esta clase
        </span>
      </div>

      {/* Recomendación (desenlace dominante entre trabajados por analistas) */}
      {data.recommendation && (
        <div className="mb-2 rounded border border-cyan-500/20 bg-cyan-500/[0.07] px-2 py-1.5 text-[11px] leading-snug text-cyan-100/90">
          {data.recommendation}
        </div>
      )}

      {/* Disposición de los casos trabajados por analistas */}
      {h && h.dispositions.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground">
            Cómo se resolvieron ({h.total} por analistas)
          </div>
          {h.dispositions.map((d) => (
            <div key={d.key} className="flex items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted-foreground/15">
                <div
                  className={cn("h-full rounded-full", DISP_COLOR[d.key] ?? "bg-slate-400")}
                  style={{ width: `${d.pct}%` }}
                />
              </div>
              <span className="w-28 shrink-0 text-[10px] text-muted-foreground">{d.label}</span>
              <span className="w-9 shrink-0 text-right text-[10px] font-semibold tabular-nums text-foreground">
                {d.pct}%
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Ejemplos accionables: precedentes que un analista ya resolvió. El
          objetivo es que el operador los abra y replique la acción. */}
      {data.examples.length > 0 && (
        <div className="mt-2.5 space-y-1.5">
          <div className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground">
            Ejemplos — qué hizo el analista
          </div>
          {data.examples.map((ex) => (
            <a
              key={ex.id}
              href={`/gestion?investigate=${encodeURIComponent(ex.id)}`}
              className="block rounded border border-border/40 bg-background/40 px-2 py-1.5 transition-colors hover:border-cyan-500/40 hover:bg-cyan-500/[0.06]"
            >
              <div className="flex items-center gap-1.5">
                <span className={cn(
                  "h-1.5 w-1.5 shrink-0 rounded-full",
                  DISP_COLOR[ex.dispositionKey] ?? "bg-slate-400",
                )} />
                <span className="text-[11px] font-semibold text-foreground">{ex.dispositionLabel}</span>
                {ex.severity && (
                  <span className={cn(
                    "text-[9px] font-bold uppercase",
                    SEV_COLOR[ex.severity] ?? "text-muted-foreground",
                  )}>
                    {ex.severity}
                  </span>
                )}
                <ExternalLink className="ml-auto h-3 w-3 shrink-0 text-cyan-400/60" aria-hidden />
              </div>
              {ex.action && (
                <p className="mt-0.5 line-clamp-2 text-[10px] leading-snug text-muted-foreground">
                  {ex.action}
                </p>
              )}
              <div className="mt-0.5 flex items-center gap-1.5 text-[9px] text-muted-foreground/70">
                {ex.operatorId && <span>{ex.operatorId}</span>}
                {ex.ageDays != null && <span>· hace {ex.ageDays < 1 ? "<1" : Math.round(ex.ageDays)}d</span>}
              </div>
            </a>
          ))}
        </div>
      )}

      {/* Métricas + quién los maneja */}
      {h && (
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border/30 pt-2 text-[10px] text-muted-foreground">
          {h.mttrHours != null && (
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" aria-hidden />
              MTTR med. {fmtMttr(h.mttrHours)}
            </span>
          )}
          <span>escalado {h.escalatedPct}%</span>
          {h.topOperators.length > 0 && (
            <span className="flex items-center gap-1 truncate">
              <Users className="h-3 w-3 shrink-0" aria-hidden />
              {h.topOperators.map((o) => `${o.operatorId} (${o.count})`).join(" · ")}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function IntelTab({
  caseId,
  c,
  onEnriched,
}: {
  caseId: string;
  c: FullCase;
  onEnriched: () => void;
}) {
  const [enriching, setEnriching]   = useState(false);
  const [enrichError, setEnrichError] = useState<string | null>(null);

  const enrData    = c.enrichment_data as Record<string, unknown> | undefined;
  const iocEnr     = (enrData?.iocEnrichment ?? enrData) as IocEnrichSummary | undefined;
  const iocSources = enrData?.iocSources as IocSources | undefined;
  const enrichedAt = enrData?.enrichedAt as string | undefined;
  // Veredicto agregado + estado por-fuente + fuentes nuevas (audit intel 2026-06-05).
  const iocVerdict = enrData?.iocVerdict as IocVerdict | undefined;
  const iocStatus  = enrData?.iocStatus as Record<string, SourceStatus> | undefined;
  const extraSources = iocSources as ExtraSources | undefined;

  const primaryIoc = c.iocs?.find((i) => i.is_primary) ?? c.iocs?.[0];

  // Resolved values — prefer primary IOC (DB) > detailed sources > summary
  const vtMalicious  = primaryIoc?.vt_malicious  ?? iocSources?.virustotal?.malicious  ?? iocEnr?.vtMalicious  ?? null;
  const vtSuspicious = iocSources?.virustotal?.suspicious ?? iocEnr?.vtSuspicious ?? null;
  const vtTotal      = iocSources?.virustotal?.total      ?? null;
  const vtPermalink  = primaryIoc?.vt_permalink ?? iocSources?.virustotal?.permalink ?? null;
  const vtLastAnal   = iocSources?.virustotal?.lastAnalysis ?? null;

  const abuseConf         = primaryIoc?.abuse_score ?? iocSources?.abuseipdb?.abuseConfidenceScore ?? iocEnr?.abuseConfidence ?? null;
  const abuseTotalReports = iocSources?.abuseipdb?.totalReports   ?? null;
  const abuseLastReported = iocSources?.abuseipdb?.lastReportedAt ?? null;
  const abuseIsp          = iocSources?.abuseipdb?.isp            ?? null;
  const abuseUsageType    = iocSources?.abuseipdb?.usageType      ?? null;
  const abuseWhitelisted  = iocSources?.abuseipdb?.isWhitelisted  ?? false;
  const abuseDistinct     = iocSources?.abuseipdb?.numDistinctUsers ?? null;
  const vtReputation      = iocSources?.virustotal?.reputation    ?? null;

  // Shodan: prefer iocSources.shodan (normalizado en el hook) > parse del
  // shodan_summary del IOC. parseShodanSummary también normaliza sus arrays.
  const shodanData =
    (iocSources?.shodan as NonNullable<IocSources["shodan"]> | undefined) ??
    (parseShodanSummary(primaryIoc?.shodan_summary) as NonNullable<IocSources["shodan"]> | null);
  const shodanPorts = (shodanData?.ports ?? iocEnr?.shodanPorts ?? []) as number[];
  const shodanVulns = (shodanData?.vulns ?? iocEnr?.shodanVulns ?? []) as string[];
  const shodanKev   = new Set((shodanData?.kevVulns ?? []) as string[]);

  const inMisp         = Boolean(primaryIoc?.in_misp ?? iocEnr?.inMisp);
  const mispThreatLvl  = iocSources?.misp?.threatLevel ?? iocEnr?.mispThreatLevel ?? null;
  const mispTags       = (iocSources?.misp?.tags ?? iocEnr?.mispTags ?? []) as string[];
  const mispEvents     = (iocSources?.misp?.events ?? []) as Array<Record<string, unknown>>;
  const mispSightings  = iocSources?.misp?.sightings   ?? null;

  const inUrlhaus   = iocSources?.urlhaus?.inFeed ?? iocEnr?.inUrlhaus   ?? false;
  const inOpenphish = iocEnr?.inOpenphish ?? false;

  const country = shodanData?.country ?? iocSources?.virustotal?.country ?? iocEnr?.country ?? null;

  const hasExtraData = Boolean(
    extraSources?.greynoise ||
    (extraSources?.threatfox?.count ?? 0) > 0 ||
    (extraSources?.otx?.pulseCount ?? 0) > 0 ||
    extraSources?.spamhaus?.listed,
  );
  const hasAnyData = vtMalicious != null || abuseConf != null || shodanPorts.length > 0
    || inMisp || inUrlhaus || inOpenphish || hasExtraData || Boolean(iocVerdict);

  async function handleEnrichNow() {
    setEnriching(true);
    setEnrichError(null);
    try {
      await api.post(`/api/cases/${caseId}/enrich-now`);
      onEnriched();
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
               ?? (e as Error)?.message
               ?? "Error desconocido";
      setEnrichError(msg);
    } finally {
      setEnriching(false);
    }
  }

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs font-medium">Inteligencia del IOC — {c.ioc_value ?? "Sin IOC"}</p>
          {enrichedAt ? (
            <p className="text-[10px] text-muted-foreground">
              Actualizado: {formatDateTimePy(enrichedAt)}
            </p>
          ) : (
            <p className="text-[10px] text-muted-foreground">Sin datos de enriquecimiento todavía</p>
          )}
        </div>
        <Button
          size="sm"
          variant="outline"
          disabled={enriching || !c.ioc_value}
          onClick={() => void handleEnrichNow()}
          className="gap-1.5 text-xs"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", enriching && "animate-spin")} />
          {enriching ? "Consultando…" : "Actualizar intel"}
        </Button>
      </div>

      {enrichError && (
        <div className="rounded border border-destructive/30 bg-destructive/10 p-2 text-xs text-destructive">
          {enrichError}
        </div>
      )}

      {/* Veredicto agregado + estado por-fuente (audit intel 2026-06-05) */}
      {(iocVerdict || iocStatus) && (
        <IocVerdictBanner verdict={iocVerdict} status={iocStatus} />
      )}

      {/* Desglose COMPLETO del score (base + bonos + multiplicadores geo/novelty +
          taxonomía, escala /200) — antes solo estaba en el sheet de la lista. */}
      <ScoringDetailPanel caseId={caseId} baseScore={c.score} />

      {/* Correlación por IOC — otros casos con el mismo IOC (I2 audit 2026-06-05) */}
      <RelatedCasesPanel caseId={caseId} />

      {!hasAnyData && !enriching && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-border/50 bg-muted/10 px-4 py-10 text-center">
          <Cpu className="h-9 w-9 text-muted-foreground/30" />
          <div>
            <p className="text-sm font-medium text-muted-foreground">Sin datos de inteligencia</p>
            <p className="mt-0.5 text-xs text-muted-foreground/60">
              Pulsa "Actualizar intel" para consultar VT, Shodan, AbuseIPDB, MISP, GreyNoise,
              ThreatFox, OTX, URLhaus, OpenPhish y Spamhaus en tiempo real.
            </p>
          </div>
        </div>
      )}

      {hasAnyData && (
        <div className="grid gap-3 sm:grid-cols-2">

          {/* ── VirusTotal ── */}
          <Card className={cn(
            "border",
            vtMalicious != null && vtMalicious > 0  ? "border-red-500/30 bg-red-500/5"
            : vtMalicious === 0                     ? "border-emerald-500/30 bg-emerald-500/5"
            :                                         "border-border/60",
          )}>
            <CardHeader className="pb-1.5">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
                  <span className="inline-block h-2 w-2 rounded-full bg-[#3b5af5]" />
                  VirusTotal
                </CardTitle>
                {vtPermalink && (
                  <a
                    href={vtPermalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-0.5 text-[10px] text-primary hover:underline"
                  >
                    Ver <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-1">
              {vtMalicious != null ? (
                <>
                  <div className="flex items-baseline gap-1.5">
                    <span className={cn("text-2xl font-bold tabular-nums",
                      vtMalicious > 0 ? "text-red-400" : "text-emerald-400"
                    )}>
                      {vtMalicious}
                    </span>
                    {vtTotal != null && (
                      <span className="text-xs text-muted-foreground">/{vtTotal} motores</span>
                    )}
                    {vtSuspicious != null && vtSuspicious > 0 && (
                      <span className="text-[11px] text-orange-400">+{vtSuspicious} sosp.</span>
                    )}
                  </div>
                  <p className="text-[10px] text-muted-foreground">
                    {vtMalicious > 0 ? "Detectado como malicioso" : "Sin detecciones"}
                  </p>
                </>
              ) : (
                <p className="text-xs text-muted-foreground italic">Sin datos VT</p>
              )}
              {vtLastAnal && (
                <p className="text-[10px] text-muted-foreground">
                  Análisis: {formatDatePy(vtLastAnal)}
                </p>
              )}
              {vtReputation != null && vtReputation !== 0 && (
                <p className="text-[10px] text-muted-foreground">
                  Reputación comunidad: <span className={cn(vtReputation < 0 ? "text-red-400" : "text-emerald-400")}>{vtReputation}</span>
                </p>
              )}
            </CardContent>
          </Card>

          {/* ── AbuseIPDB ── */}
          <Card className={cn(
            "border",
            abuseConf != null && abuseConf > 75  ? "border-red-500/30 bg-red-500/5"
            : abuseConf != null && abuseConf > 25 ? "border-orange-500/30 bg-orange-500/5"
            :                                        "border-border/60",
          )}>
            <CardHeader className="pb-1.5">
              <CardTitle className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
                <span className="inline-block h-2 w-2 rounded-full bg-[#e03434]" />
                AbuseIPDB
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              {abuseConf != null ? (
                <>
                  <div className="flex items-baseline gap-1.5">
                    <span className={cn("text-2xl font-bold tabular-nums",
                      abuseConf > 75 ? "text-red-400" : abuseConf > 25 ? "text-orange-400" : "text-emerald-400"
                    )}>
                      {abuseConf}%
                    </span>
                    <span className="text-xs text-muted-foreground">confianza</span>
                  </div>
                  {abuseTotalReports != null && (
                    <p className="text-[10px] text-muted-foreground">
                      {abuseTotalReports} reportes{abuseDistinct != null ? ` · ${abuseDistinct} reporteros` : ""}
                    </p>
                  )}
                  {abuseIsp && <p className="text-[10px] text-muted-foreground">ISP: {abuseIsp}</p>}
                  {abuseUsageType && <p className="text-[10px] text-muted-foreground">Tipo: {abuseUsageType}</p>}
                  {abuseWhitelisted && (
                    <span className="inline-block rounded bg-emerald-500/15 px-1.5 py-0 text-[10px] font-bold text-emerald-400">
                      en allowlist
                    </span>
                  )}
                  {abuseLastReported && (
                    <p className="text-[10px] text-muted-foreground">
                      Último reporte: {formatDatePy(abuseLastReported)}
                    </p>
                  )}
                </>
              ) : (
                <p className="text-xs text-muted-foreground italic">Sin datos AbuseIPDB</p>
              )}
            </CardContent>
          </Card>

          {/* ── Shodan ── */}
          {(shodanPorts.length > 0 || shodanData?.country || shodanData?.org) && (
            <Card className="col-span-full border border-orange-500/20 bg-orange-500/5 sm:col-span-1">
              <CardHeader className="pb-1.5">
                <CardTitle className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
                  <span className="inline-block h-2 w-2 rounded-full bg-[#f90]" />
                  Shodan
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(country ?? shodanData?.org) && (
                  <p className="text-xs">
                    {country && <span>{country}{shodanData?.city ? `, ${shodanData.city}` : ""}</span>}
                    {shodanData?.org && <span className="text-muted-foreground"> · {shodanData.org}</span>}
                    {shodanData?.isp && shodanData.isp !== shodanData.org && (
                      <span className="text-muted-foreground"> · {shodanData.isp}</span>
                    )}
                  </p>
                )}
                {(shodanData?.os || (shodanData?.hostnames?.length ?? 0) > 0) && (
                  <p className="text-[10px] text-muted-foreground">
                    {shodanData?.os && <span>OS: {shodanData.os}</span>}
                    {shodanData?.os && (shodanData?.hostnames?.length ?? 0) > 0 && " · "}
                    {(shodanData?.hostnames?.length ?? 0) > 0 && (
                      <span>{shodanData!.hostnames!.slice(0, 3).join(", ")}</span>
                    )}
                  </p>
                )}
                {shodanPorts.length > 0 && (
                  <div>
                    <p className="mb-1 text-[10px] text-muted-foreground uppercase tracking-wide">Puertos abiertos</p>
                    <div className="flex flex-wrap gap-1">
                      {shodanPorts.map((p) => (
                        <span key={p} className="rounded bg-orange-500/15 px-1.5 py-0.5 font-mono text-[11px] text-orange-400">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {shodanVulns.length > 0 && (
                  <div>
                    <p className="mb-1 text-[10px] text-muted-foreground uppercase tracking-wide">
                      CVEs{shodanKev.size > 0 && <span className="ml-1 text-red-400">· {shodanKev.size} en KEV</span>}
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {shodanVulns.map((v) => {
                        const isKev = shodanKev.has(v);
                        return (
                          <a
                            key={v}
                            href={`https://nvd.nist.gov/vuln/detail/${v}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            title={isKev ? "En CISA KEV — explotación activa conocida" : "Ver en NVD"}
                            className={cn(
                              "rounded px-1.5 py-0.5 font-mono text-[11px] hover:underline",
                              isKev ? "bg-red-500/25 font-bold text-red-300 ring-1 ring-red-500/40" : "bg-red-500/15 text-red-400",
                            )}
                          >
                            {isKev && "🚨 "}{v}
                          </a>
                        );
                      })}
                    </div>
                  </div>
                )}
                {shodanData?.services && shodanData.services.length > 0 && (
                  <div>
                    <p className="mb-1 text-[10px] text-muted-foreground uppercase tracking-wide">Servicios</p>
                    <div className="space-y-0.5">
                      {shodanData.services.map((svc) => (
                        <p key={svc.port} className="font-mono text-[11px]">
                          <span className="text-orange-400">{svc.port}/{svc.transport ?? "tcp"}</span>
                          {svc.product && (
                            <span className="text-muted-foreground"> · {svc.product}{svc.version ? ` ${svc.version}` : ""}</span>
                          )}
                        </p>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* ── MISP ── */}
          <Card className={cn(
            "border",
            inMisp ? "border-violet-500/30 bg-violet-500/5" : "border-border/60",
          )}>
            <CardHeader className="pb-1.5">
              <CardTitle className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
                <span className="inline-block h-2 w-2 rounded-full bg-[#a855f7]" />
                MISP
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className={cn(
                  "rounded px-2 py-0.5 text-xs font-semibold",
                  inMisp ? "bg-violet-500/20 text-violet-300" : "bg-muted/30 text-muted-foreground",
                )}>
                  {inMisp ? "Encontrado en MISP" : "No encontrado en MISP"}
                </span>
                {mispThreatLvl && (
                  <span className="text-[11px] text-muted-foreground">Nivel: {mispThreatLvl}</span>
                )}
                {mispSightings != null && mispSightings > 0 && (
                  <span className="text-[11px] text-muted-foreground">{mispSightings} sightings</span>
                )}
              </div>
              {mispEvents.length > 0 && (
                <div className="space-y-1">
                  {mispEvents.slice(0, 4).map((ev, i) => (
                    <div key={String(ev.event_id ?? i)} className="rounded border border-violet-500/20 bg-muted/10 px-2 py-1.5">
                      <p className="text-[11px] font-medium leading-tight line-clamp-2">
                        {String(ev.event_title ?? `Evento ${ev.event_id ?? ""}`)}
                      </p>
                      {ev.threat_level != null && (
                        <p className="mt-0.5 text-[10px] text-muted-foreground">Nivel: {String(ev.threat_level)}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {mispTags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {mispTags.slice(0, 10).map((tag) => (
                    <span key={tag} className="rounded bg-violet-500/10 px-1.5 py-0 text-[10px] text-violet-300">
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* ── Feeds de abuso (URLhaus / OpenPhish) ── */}
          {(inUrlhaus || inOpenphish) && (
            <Card className="border border-red-500/25 bg-red-500/5">
              <CardHeader className="pb-1.5">
                <CardTitle className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
                  Feeds de Abuso
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {inUrlhaus && (
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-red-500/20 px-2 py-0.5 text-xs font-bold text-red-400">URLhaus</span>
                    <span className="text-xs text-muted-foreground">Listado en feed activo</span>
                  </div>
                )}
                {inOpenphish && (
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-orange-500/20 px-2 py-0.5 text-xs font-bold text-orange-400">OpenPhish</span>
                    <span className="text-xs text-muted-foreground">Campaña de phishing activa</span>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* ── Fuentes nuevas: GreyNoise / ThreatFox / OTX / Spamhaus ── */}
          <IocExtraSourceCards sources={extraSources} />

        </div>
      )}
    </div>
  );
}

// ── SeverityEditor ────────────────────────────────────────────────────────────
// Convierte el badge de severidad en un control editable. Click → popover con
// dropdown de severities; al confirmar, POST /api/incidents/:id/severity con
// la razón (motivo de la reclasificación). El backend audita el cambio en
// case_timeline_events (event_type=SEVERITY_CHANGE) y emite socket.io.
type Sev = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE";

const SEV_LIST: Sev[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"];

const SEV_BADGE: Record<Sev, string> = {
  CRITICAL:    "border-red-500 bg-red-500/20 text-red-400 animate-pulse",
  HIGH:        "border-orange-500 bg-orange-500/20 text-orange-400",
  MEDIUM:      "border-yellow-500 bg-yellow-500/20 text-yellow-400",
  LOW:         "border-emerald-500 bg-emerald-500/20 text-emerald-400",
  NEGLIGIBLE:  "border-slate-500 bg-slate-500/20 text-slate-400",
};

function SeverityEditor({
  caseId,
  severity,
  operatorCi,
  escalationLevel,
  onChanged,
}: {
  caseId: string;
  severity: string;
  operatorCi: string;
  escalationLevel: string | null;
  onChanged: () => void;
}) {
  const [open, setOpen]       = useState(false);
  const [target, setTarget]   = useState<Sev>((severity as Sev) ?? "MEDIUM");
  const [reason, setReason]   = useState("");
  const [busy, setBusy]       = useState(false);
  const [err, setErr]         = useState<string | null>(null);
  const current = (severity as Sev) ?? "MEDIUM";

  const onConfirm = useCallback(async () => {
    if (target === current) { setOpen(false); return; }
    if (!reason.trim()) { setErr("Indica brevemente el motivo del cambio."); return; }
    setBusy(true); setErr(null);
    try {
      await api.post(`/api/incidents/${caseId}/severity`, {
        severity:   target,
        reason:     reason.trim(),
        operatorCi: operatorCi || undefined,
      });
      setOpen(false);
      setReason("");
      onChanged();
    } catch (e: unknown) {
      const ax = e as { response?: { data?: { error?: string } }; message?: string };
      setErr(ax.response?.data?.error ?? ax.message ?? "Error al actualizar severidad");
    } finally {
      setBusy(false);
    }
  }, [caseId, current, target, reason, operatorCi, onChanged]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => { setTarget(current); setReason(""); setErr(null); setOpen((v) => !v); }}
        title="Click para cambiar la criticidad del caso"
        className={cn(
          "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-bold transition-colors hover:brightness-110",
          SEV_BADGE[current] ?? SEV_BADGE.MEDIUM,
        )}
      >
        <span className={cn("h-2 w-2 rounded-full", current === "CRITICAL" ? "bg-red-500" : "bg-current")} />
        {current}
        {escalationLevel && <span className="text-[10px] opacity-80">· {escalationLevel}</span>}
        <span className="ml-1 text-[10px] opacity-70">▾</span>
      </button>

      {open && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => !busy && setOpen(false)}
          />
          <div className="absolute left-0 top-full z-50 mt-1.5 w-72 rounded-lg border border-border/80 bg-card p-3 shadow-2xl">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Reclasificar criticidad
            </p>
            <div className="mb-2 space-y-1">
              {SEV_LIST.map((s) => (
                <label
                  key={s}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded border px-2 py-1.5 text-xs",
                    target === s
                      ? SEV_BADGE[s].replace("animate-pulse", "")
                      : "border-border/40 hover:bg-muted/30",
                  )}
                >
                  <input
                    type="radio"
                    name={`sev-${caseId}`}
                    value={s}
                    checked={target === s}
                    onChange={() => setTarget(s)}
                    className="h-3 w-3"
                  />
                  <span className="font-semibold">{s}</span>
                  {s === current && (
                    <span className="ml-auto text-[10px] text-muted-foreground">actual</span>
                  )}
                </label>
              ))}
            </div>
            <label className="mb-2 block">
              <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                Motivo del cambio (auditoría)
              </span>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Ej: revisión confirmó impacto crítico en O365"
                rows={2}
                className="w-full resize-none rounded-md border border-border bg-background px-2 py-1.5 text-xs"
              />
            </label>
            {err && (
              <p className="mb-2 text-[11px] text-red-500">{err}</p>
            )}
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={() => setOpen(false)} disabled={busy} className="h-7 text-xs">
                Cancelar
              </Button>
              <Button
                size="sm"
                onClick={() => void onConfirm()}
                disabled={busy || target === current}
                className="h-7 text-xs"
              >
                {busy ? "Guardando…" : "Confirmar"}
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
