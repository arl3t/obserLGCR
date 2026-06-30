/**
 * PivotPreviewModal — Sprint 2 de docs/HUNT-PIVOTS.md.
 *
 * Recibe un pivote (IP, agente, CVE) seleccionado en el ranking de
 * `/hunt`, llama a POST /api/hunt/preview para agregar evidencia 24h,
 * la muestra, y al confirmar abre el OpenCaseModal ya existente
 * pre-poblado con el `suggestedCase` que devuelve el backend.
 *
 * No duplica la lógica de creación: delega a OpenCaseModal, que ya
 * maneja dedup/supresión/force/redirect.
 */
import { useMemo, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Loader2, Search, X } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { formatDateTimePy } from "@/lib/format";
import { OpenCaseModal, type OpenCasePayload } from "@/components/case-management/OpenCaseModal";
import type { Severity } from "@/components/case-management/types";

export type HuntPivot = "src_ip" | "agent_name" | "cve" | "sender_ip" | "sender_domain" | "outlier";

export interface PivotSelection {
  pivot: HuntPivot;
  value: string;
  label: string;
  /** Cuando la selección viene de la tab "Outliers", incluimos la entidad
   *  original para que post-creación el backend pueda enlazar
   *  outliers.related_case_id (D4 del docs/HUNT-PIVOTS.md). */
  outlierEntity?: { entity_type: string; entity_value: string };
}

interface PreviewResponse {
  ok: true;
  evidence: {
    pivot: HuntPivot;
    totalEvents24h: number;
    /** true cuando el backend agregó 0 eventos en 24h. La UI muestra
     *  empty-state + deshabilita el botón de investigar. */
    isEmpty?: boolean;
    bySource: Record<string, number>;
    severityBreakdown: Record<Severity, number>;
    topRules: Array<{ id: string; hits: number; desc: string | null }>;
    mitreTactics: string[];
    lastSeen: string | null;
    representativeEvent: {
      lvl: Severity;
      ts: string | null;
      ruleId: string | null;
      ruleDesc: string | null;
    } | null;
    defaultSourceLog: string;
    defaultIocType: OpenCasePayload["iocType"];
    // Pivot-specific extras
    kev?: boolean;
    affectedHostsCount?: number;
    recipientsCount?: number;
    outlier?: { outlierId: string; entityType: string; entityValue: string; zScore: number };
    iocValue?: string;
  };
  /** null cuando evidence.isEmpty=true (no hay base para abrir caso). */
  suggestedCase: null | {
    iocValue: string;
    iocType: OpenCasePayload["iocType"];
    sourceLog: string;
    severity: Severity;
    score: number;
    mitreTacticId: string | null;
    rawContext: Record<string, unknown>;
    huntPivot: { pivot: HuntPivot; value: string };
  };
  existingCase: null | {
    caseId: string;
    status: string;
    severity: Severity;
    score: number;
    lastSeen: string;
    occurrenceCount: number;
  };
}

interface Props {
  selection: PivotSelection;
  onClose:   () => void;
}

export function PivotPreviewModal({ selection, onClose }: Props) {
  const [showOpenCase, setShowOpenCase] = useState(false);

  const { data, isLoading, isError, error } = useQuery<PreviewResponse>({
    queryKey: ["hunt", "preview", selection.pivot, selection.value],
    queryFn: async () => {
      const res = await api.post<PreviewResponse>("/api/hunt/preview", {
        pivot: selection.pivot,
        value: selection.value,
      });
      return res.data;
    },
    staleTime: 60_000,
  });

  // Payload para OpenCaseModal cuando el operador confirma.
  const openCasePayload = useMemo<OpenCasePayload | null>(() => {
    if (!data?.suggestedCase) return null;
    const s = data.suggestedCase;
    return {
      iocValue:  s.iocValue,
      iocType:   s.iocType,
      sourceLog: s.sourceLog,
      severity:  s.severity,
      score:     s.score,
      mitreTacticId: s.mitreTacticId ?? undefined,
    };
  }, [data]);

  // Callback que dispara post-creación del caso. Hace:
  //   1. Audit row en incident_case_audit (tracking adopción).
  //   2. Si la selección vino con outlierEntity, link de related_case_id
  //      en minio_iceberg.hunting.outliers (D4).
  // El endpoint /api/hunt/case-opened nunca tira 5xx — perder el tracking
  // no debe romper la UI.
  const handleCaseCreated = async (caseId: string) => {
    try {
      await api.post("/api/hunt/case-opened", {
        caseId,
        pivot: selection.pivot,
        value: selection.value,
        outlierEntityType:  selection.outlierEntity?.entity_type,
        outlierEntityValue: selection.outlierEntity?.entity_value,
        // Snapshot del preview — el backend lo persiste en enrichment_data
        // para que la investigación muestre los agregados sin re-correr la
        // query de 20s.
        evidence: data?.evidence ?? null,
      });
    } catch {
      // Silencioso — el caso ya está creado, el tracking puede perderse.
    }
  };

  // Si el usuario abrió el OpenCaseModal, ocultamos este (no se ven los
  // dos overlays apilados).
  if (showOpenCase && openCasePayload) {
    return (
      <OpenCaseModal
        open
        onOpenChange={(v) => {
          if (!v) {
            setShowOpenCase(false);
            onClose();
          }
        }}
        payload={openCasePayload}
        sourceLabel={`Hunt: ${selection.pivot} = ${selection.label}`}
        onCaseCreated={handleCaseCreated}
      />
    );
  }

  return (
    <Dialog.Root open onOpenChange={(v) => !v && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-md border border-border bg-background shadow-xl">
          <header className="flex items-center justify-between border-b border-border px-5 py-3">
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-cyan-400" />
              <Dialog.Title className="text-sm font-semibold">
                Preview · {selection.pivot}
              </Dialog.Title>
              <code className="rounded bg-muted/40 px-1.5 py-0.5 text-[11px]">
                {selection.label}
              </code>
            </div>
            <Dialog.Close asChild>
              <button className="text-muted-foreground hover:text-foreground">
                <X className="h-4 w-4" />
              </button>
            </Dialog.Close>
          </header>

          <div className="space-y-3 px-5 py-4">
            {isLoading && (
              <div className="space-y-2">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-4 w-1/2" />
                <Skeleton className="h-20 w-full" />
              </div>
            )}

            {isError && (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-xs text-destructive">
                Error al obtener evidencia: {(error as Error)?.message ?? "desconocido"}
              </div>
            )}

            {data && <EvidencePanel data={data} />}

            {data?.existingCase && (
              <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs text-amber-300">
                <AlertTriangle className="mt-0.5 h-4 w-4 flex-none" />
                <div className="flex-1">
                  Ya existe caso <code className="font-mono">{data.existingCase.caseId.slice(0, 8)}</code> ·
                  status <strong>{data.existingCase.status}</strong> · severity{" "}
                  <strong>{data.existingCase.severity}</strong> · {data.existingCase.occurrenceCount} ocurrencias.
                  <br />
                  <a
                    href={`/gestion?investigate=${data.existingCase.caseId}`}
                    className="underline hover:text-amber-200"
                  >
                    Ir al caso existente →
                  </a>
                </div>
              </div>
            )}
          </div>

          <footer className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
            <Button variant="outline" size="sm" onClick={onClose}>
              Cerrar
            </Button>
            <Button
              size="sm"
              disabled={!openCasePayload || !!data?.evidence?.isEmpty}
              onClick={() => setShowOpenCase(true)}
              title={
                data?.evidence?.isEmpty
                  ? "Sin eventos en 24h — no hay base para abrir caso desde acá"
                  : openCasePayload
                    ? "Abrir caso con suggestedCase"
                    : "Esperando evidencia..."
              }
            >
              {isLoading ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : null}
              Investigar ahora
            </Button>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Panel de evidencia ──────────────────────────────────────────────────────────

const SEV_TEXT: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-zinc-400",
  NEGLIGIBLE: "text-zinc-500",
};

function EvidencePanel({ data }: { data: PreviewResponse }) {
  const ev = data.evidence;
  const sc = data.suggestedCase;
  const sevs = (["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] as Severity[])
    .filter((s) => (ev.severityBreakdown[s] ?? 0) > 0);
  const sources = Object.entries(ev.bySource).filter(([, n]) => n > 0);

  // Empty-state: cuando 0 eventos en 24h, no mostrar buckets/reglas vacías
  // ni un suggestedCase artificial. El operador entiende que no hay base.
  if (ev.isEmpty) {
    return (
      <div className="space-y-2 rounded-md border border-dashed border-muted-foreground/40 bg-muted/10 p-3 text-xs">
        <div className="font-semibold text-foreground">Sin eventos en las últimas 24 h.</div>
        <p className="text-muted-foreground">
          Este pivote apareció en el ranking pero no agregó evidencia útil para
          abrir un caso ahora. Posibles causas: actividad transitoria que ya
          cesó, ruido de baja severidad, o consulta que necesita ventana más
          amplia. Si querés investigarlo igual, abrí el caso desde{" "}
          <code className="rounded bg-muted/40 px-1">/gestion</code> manualmente.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 text-xs">
      <div>
        <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
          Eventos 24h
        </div>
        <div className="text-lg font-bold">{ev.totalEvents24h.toLocaleString("es-AR")}</div>
      </div>

      {sources.length > 0 && (
        <Row label="Fuentes">
          {sources.map(([src, n]) => (
            <span key={src} className="mr-2 inline-flex items-center gap-1">
              <code className="rounded bg-muted/40 px-1 py-0.5 text-[10px]">{src}</code>
              <span className="font-mono text-foreground">{n}</span>
            </span>
          ))}
        </Row>
      )}

      {sevs.length > 0 && (
        <Row label="Severities">
          {sevs.map((s) => (
            <span key={s} className={cn("mr-3 inline-block font-mono", SEV_TEXT[s])}>
              {s} · {ev.severityBreakdown[s]}
            </span>
          ))}
        </Row>
      )}

      {ev.topRules.length > 0 && (
        <Row label="Top reglas">
          <ul className="list-inside list-disc text-foreground/80">
            {ev.topRules.slice(0, 5).map((r) => (
              <li key={r.id}>
                <code className="font-mono">{r.id}</code>
                {r.desc && <span className="text-muted-foreground"> — {r.desc}</span>}
                <span className="ml-1 font-mono">×{r.hits}</span>
              </li>
            ))}
          </ul>
        </Row>
      )}

      {ev.mitreTactics.length > 0 && (
        <Row label="MITRE">
          {ev.mitreTactics.map((t) => (
            <code key={t} className="mr-2 rounded bg-muted/40 px-1 py-0.5 text-[10px]">
              {t}
            </code>
          ))}
        </Row>
      )}

      {ev.lastSeen && (
        <Row label="Último visto">
          <span className="font-mono">{formatDateTimePy(ev.lastSeen)}</span>
        </Row>
      )}

      {ev.kev !== undefined && (
        <Row label="CISA KEV">
          {ev.kev ? (
            <span className="font-mono text-red-400">Sí — known exploited</span>
          ) : (
            <span className="font-mono text-muted-foreground">no listado</span>
          )}
        </Row>
      )}

      {ev.affectedHostsCount !== undefined && (
        <Row label="Hosts afectados">
          <span className="font-mono">{ev.affectedHostsCount}</span>
        </Row>
      )}

      {sc && (
        <>
          <hr className="border-border/40" />
          <div className="rounded-md border border-border/60 bg-muted/20 p-2">
            <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
              Caso sugerido (editable en el siguiente paso)
            </div>
            <div className="mt-1 space-y-0.5 font-mono text-[12px]">
              <div>
                severity{" "}
                <span className={cn("font-bold", SEV_TEXT[sc.severity])}>{sc.severity}</span> ·
                score <span className="font-bold">{sc.score}</span>
              </div>
              <div className="text-muted-foreground">
                ioc <span className="text-foreground">{sc.iocValue}</span> ({sc.iocType}) ·
                source <span className="text-foreground">{sc.sourceLog}</span>
              </div>
              {sc.mitreTacticId && (
                <div className="text-muted-foreground">
                  mitre <span className="text-foreground">{sc.mitreTacticId}</span>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5">{children}</div>
    </div>
  );
}
