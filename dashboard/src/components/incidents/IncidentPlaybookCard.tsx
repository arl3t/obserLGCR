import { useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RotateCcw } from "lucide-react";
import type { IncidentPlaybookEntry, IncidentPlaybookSeverity } from "@/lib/incident-playbooks";

const SEVERITY_COLOR: Record<IncidentPlaybookSeverity, string> = {
  CRITICAL: "text-red-500",
  HIGH: "text-orange-500",
  MEDIUM: "text-yellow-500",
  LOW: "text-emerald-500",
};

const SEVERITY_BG: Record<IncidentPlaybookSeverity, string> = {
  CRITICAL: "bg-red-500/10 border-red-500/30",
  HIGH: "bg-orange-500/10 border-orange-500/30",
  MEDIUM: "bg-yellow-500/10 border-yellow-500/30",
  LOW: "bg-emerald-500/10 border-emerald-500/30",
};

function severityColor(sev: string): string {
  return SEVERITY_COLOR[sev as IncidentPlaybookSeverity] ?? "text-muted-foreground";
}

function severityBg(sev: string): string {
  return SEVERITY_BG[sev as IncidentPlaybookSeverity] ?? "bg-muted/20 border-border";
}

// P2 #14: playbooks accionables. El progreso (pasos completados) se guarda en
// localStorage por severidad, así el analista va tildando los pasos mientras
// responde, y se resalta el "siguiente paso" pendiente (next best action).
function progressKey(sev: string): string {
  return `lh_playbook_progress_${sev}`;
}

export function IncidentPlaybookCard({ pb }: { pb: IncidentPlaybookEntry }) {
  const Icon = pb.icon;
  const [done, setDone] = useState<Set<number>>(new Set());

  useEffect(() => {
    try {
      const raw = localStorage.getItem(progressKey(pb.severity));
      if (raw) setDone(new Set(JSON.parse(raw) as number[]));
    } catch { /* ignore */ }
  }, [pb.severity]);

  function toggle(i: number) {
    setDone((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      try { localStorage.setItem(progressKey(pb.severity), JSON.stringify([...next])); } catch { /* ignore */ }
      return next;
    });
  }

  function reset() {
    setDone(new Set());
    try { localStorage.removeItem(progressKey(pb.severity)); } catch { /* ignore */ }
  }

  // "Siguiente paso" = primer índice no completado.
  const nextStep = useMemo(() => {
    for (let i = 0; i < pb.steps.length; i++) if (!done.has(i)) return i;
    return -1;
  }, [done, pb.steps.length]);

  const completed = done.size;
  const total = pb.steps.length;
  const allDone = completed === total && total > 0;

  return (
    <div className={`rounded-lg border p-4 ${severityBg(pb.severity)}`}>
      <div className="mb-3 flex items-center gap-2">
        <Icon className={`h-4 w-4 shrink-0 ${severityColor(pb.severity)}`} aria-hidden />
        <span className={`text-sm font-semibold ${severityColor(pb.severity)}`}>{pb.severity}</span>
        <Badge variant="outline" className="ml-auto text-[10px]">{pb.sla}</Badge>
      </div>

      {/* Barra de progreso + contador */}
      <div className="mb-2 flex items-center gap-2">
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted/40">
          <div
            className={`h-full rounded-full transition-all ${allDone ? "bg-emerald-500" : "bg-foreground/40"}`}
            style={{ width: total ? `${Math.round((completed / total) * 100)}%` : "0%" }}
          />
        </div>
        <span className="shrink-0 text-[10px] tabular-nums text-muted-foreground">{completed}/{total}</span>
        {completed > 0 && (
          <Button variant="ghost" size="sm" className="h-5 px-1" onClick={reset} title="Reiniciar progreso">
            <RotateCcw className="h-3 w-3" />
          </Button>
        )}
      </div>

      <ol className="space-y-1">
        {pb.steps.map((step, i) => {
          const isDone = done.has(i);
          const isNext = i === nextStep;
          return (
            <li key={i}>
              <button
                type="button"
                onClick={() => toggle(i)}
                className={`flex w-full items-start gap-2 rounded px-1 py-1 text-left text-xs transition-colors hover:bg-foreground/5 ${
                  isNext ? "ring-1 ring-inset ring-foreground/20" : ""
                }`}
              >
                <input
                  type="checkbox"
                  checked={isDone}
                  readOnly
                  className="mt-0.5 h-3 w-3 shrink-0 cursor-pointer"
                  aria-label={`Paso ${i + 1}`}
                />
                <span className={isDone ? "text-muted-foreground line-through" : "text-foreground/80"}>
                  {step}
                </span>
                {isNext && (
                  <span className="ml-auto shrink-0 text-[9px] font-semibold uppercase text-foreground/50">
                    siguiente
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
