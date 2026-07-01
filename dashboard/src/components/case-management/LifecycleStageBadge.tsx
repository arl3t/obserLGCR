import { cn } from "@/lib/utils";

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
