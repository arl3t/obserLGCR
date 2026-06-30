/**
 * WorkflowStatusBar.tsx
 * Barra de estado del flujo de trabajo SOC.
 * Muestra: Shift Manager activo | cola por nivel | candidatos a auto-acción.
 * Incluye botones de automatización manual (solo LEADER/ADMIN).
 */

import { useState } from "react";
import {
  Shield, Zap, Clock, UserCheck,
  RefreshCw, ChevronDown, ChevronUp, Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  useWorkflowHealth,
  useAutomationCandidates,
  useTriggerAutoClose,
  useTriggerAutoAssign,
  type WorkflowQueueItem,
} from "@/hooks/useSocWorkflow";

// ── Lifecycle stage badge ─────────────────────────────────────────────────────

const STAGE_STYLE: Record<string, { label: string; cls: string }> = {
  DETECTION:        { label: "Detección",    cls: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
  TRIAGE_L1:        { label: "Triaje L1",    cls: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
  INVESTIGATION_L2: { label: "Invest. L2",  cls: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  RESPONSE_L3:      { label: "Respuesta L3", cls: "bg-red-500/15 text-red-400 border-red-500/30" },
  CLOSURE:          { label: "Cierre",       cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" },
};

export function LifecycleStageBadge({ stage }: { stage: string }) {
  const s = STAGE_STYLE[stage] ?? { label: stage, cls: "bg-muted/30 text-muted-foreground border-border/50" };
  return (
    <span className={cn("rounded border px-1.5 py-0 text-[9px] font-semibold uppercase tracking-wide", s.cls)}>
      {s.label}
    </span>
  );
}

// ── Main WorkflowStatusBar ────────────────────────────────────────────────────

interface WorkflowStatusBarProps {
  operatorCi: string;
  operatorRole?: string | null;
}

export function WorkflowStatusBar({ operatorCi, operatorRole }: WorkflowStatusBarProps) {
  const [expanded, setExpanded] = useState(false);
  const health     = useWorkflowHealth();
  const candidates = useAutomationCandidates();
  const triggerClose  = useTriggerAutoClose(operatorCi);
  const triggerAssign = useTriggerAutoAssign(operatorCi);

  const h = health.data;
  const isLeader = operatorRole === "LEADER" || operatorRole === "ADMIN";

  const pendingClose  = candidates.data?.autoCloseCandidates.length ?? h?.pendingAutoClose ?? 0;
  const pendingAssign = candidates.data?.timeoutCases.length        ?? h?.pendingAutoAssign ?? 0;

  return (
    <div className="border-b border-border/60 bg-card/60">
      {/* ── Barra principal ── */}
      <div className="flex flex-wrap items-center gap-3 px-4 py-2">
        {/* Scheduler status */}
        <div className="flex items-center gap-1.5">
          <Activity className="h-3 w-3 text-emerald-400" />
          <span className="text-[10px] text-muted-foreground">
            {h?.scheduler.length ?? 0} tareas activas
          </span>
        </div>

        <div className="h-3 w-px bg-border/60" />

        {/* Shift Manager */}
        <div className="flex items-center gap-1.5">
          <Shield className="h-3 w-3 text-amber-400" />
          <span className="text-[10px]">
            {h?.shiftManager
              ? <span><span className="text-muted-foreground">SM:</span> <span className="font-medium">{h.shiftManager.name}</span></span>
              : <span className="text-muted-foreground/60">Sin Shift Manager</span>
            }
          </span>
        </div>

        <div className="h-3 w-px bg-border/60" />

        {/* Auto-acciones pendientes */}
        {pendingClose > 0 && (
          <div className="flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5">
            <Zap className="h-2.5 w-2.5 text-emerald-400" />
            <span className="text-[10px] text-emerald-400">{pendingClose} para auto-cerrar</span>
          </div>
        )}

        {pendingAssign > 0 && (
          <div className="flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5">
            <Clock className="h-2.5 w-2.5 text-amber-400" />
            <span className="text-[10px] text-amber-400">{pendingAssign} timeout 30 min</span>
          </div>
        )}

        {/* Actions (solo LEADER/ADMIN) */}
        {isLeader && (
          <div className="ml-auto flex items-center gap-2">
            {pendingClose > 0 && (
              <button
                onClick={() => void triggerClose.mutateAsync()}
                disabled={triggerClose.isPending}
                className={cn(
                  "flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] transition-colors",
                  "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
                  "hover:bg-emerald-500/20 disabled:opacity-50",
                )}
              >
                <RefreshCw className={cn("h-2.5 w-2.5", triggerClose.isPending && "animate-spin")} />
                Cerrar LOW/NEG
              </button>
            )}
            {pendingAssign > 0 && (
              <button
                onClick={() => void triggerAssign.mutateAsync()}
                disabled={triggerAssign.isPending}
                className={cn(
                  "flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] transition-colors",
                  "border-amber-500/30 bg-amber-500/10 text-amber-400",
                  "hover:bg-amber-500/20 disabled:opacity-50",
                )}
              >
                <UserCheck className={cn("h-2.5 w-2.5", triggerAssign.isPending && "animate-spin")} />
                Auto-asignar
              </button>
            )}
          </div>
        )}

        {/* Expand */}
        {candidates.data && (pendingClose > 0 || pendingAssign > 0) && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="ml-1 text-muted-foreground/40 hover:text-muted-foreground"
          >
            {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
        )}
      </div>

      {/* ── Panel expandible: detalle de candidatos ── */}
      {expanded && candidates.data && (
        <div className="border-t border-border/40 px-4 py-2 space-y-2">
          {/* Auto-close candidates */}
          {candidates.data.autoCloseCandidates.length > 0 && (
            <div>
              <p className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground/60 mb-1">
                Candidatos a auto-cierre (LOW/NEGLIGIBLE)
              </p>
              <div className="flex flex-wrap gap-1.5">
                {candidates.data.autoCloseCandidates.slice(0, 6).map((c) => (
                  <span key={c.id} className="rounded border border-border/50 bg-muted/20 px-2 py-0.5 font-mono text-[10px]">
                    #{c.id.slice(0,7)} · {c.severity} · {c.score}
                  </span>
                ))}
                {candidates.data.autoCloseCandidates.length > 6 && (
                  <span className="text-[10px] text-muted-foreground">
                    +{candidates.data.autoCloseCandidates.length - 6} más
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Timeout cases */}
          {candidates.data.timeoutCases.length > 0 && (
            <div>
              <p className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground/60 mb-1">
                Sin adopción {">"} 30 min
              </p>
              <div className="flex flex-wrap gap-1.5">
                {candidates.data.timeoutCases.slice(0, 6).map((c) => (
                  <span key={c.id} className={cn(
                    "rounded border px-2 py-0.5 font-mono text-[10px]",
                    c.severity === "CRITICAL"
                      ? "border-red-500/30 bg-red-500/10 text-red-400"
                      : c.severity === "HIGH"
                      ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                      : "border-border/50 bg-muted/20",
                  )}>
                    #{c.id.slice(0,7)} · {c.severity} · {(c as WorkflowQueueItem & { minutes_unadopted?: number }).minutes_unadopted ?? "?"}m
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
