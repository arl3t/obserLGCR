/**
 * IncidentVerdictCard.tsx — Tarjeta "Resumen del incidente · veredicto automático".
 *
 * Se monta en la columna derecha de la Investigación, ENCIMA de Hunting insights.
 * Toda la lógica vive en lib/incident-verdict.ts (compartida con el informe);
 * acá solo se renderiza.
 */
import { memo } from "react";
import { ShieldAlert, ShieldCheck, ShieldQuestion, Gavel } from "lucide-react";
import { cn } from "@/lib/utils";
import { buildIncidentVerdict, type VerdictTile, type VerdictTone } from "@/lib/incident-verdict";
import type { FullCase } from "./useCaseInvestigation";

const TONE_TEXT: Record<VerdictTone, string> = {
  red:     "text-red-400",
  orange:  "text-orange-400",
  emerald: "text-emerald-400",
  muted:   "text-muted-foreground",
};
const TONE_RING: Record<VerdictTone, string> = {
  red:     "border-red-500/40 bg-red-500/5",
  orange:  "border-orange-500/40 bg-orange-500/5",
  emerald: "border-emerald-500/40 bg-emerald-500/5",
  muted:   "border-border/60 bg-muted/10",
};

function Tile({ title, tile }: { title: string; tile: VerdictTile }) {
  return (
    <div className="rounded bg-background/40 p-2">
      <div className="text-[9px] uppercase tracking-wider text-muted-foreground">{title}</div>
      <div className={cn("text-sm font-bold leading-tight", TONE_TEXT[tile.tone])} title={tile.label}>
        {tile.label}
      </div>
      {tile.detail && <div className="mt-0.5 text-[10px] text-muted-foreground">{tile.detail}</div>}
    </div>
  );
}

export const IncidentVerdictCard = memo(function IncidentVerdictCard({ c }: { c: FullCase }) {
  const v = buildIncidentVerdict(c);
  const Icon =
    v.verdict === "MALICIOUS"  ? ShieldAlert
    : v.verdict === "BENIGN"   ? ShieldCheck
    : v.verdict === "SUSPICIOUS" ? Gavel
    : ShieldQuestion;

  return (
    <div className={cn("rounded-lg border p-3 space-y-3", TONE_RING[v.tone])}>
      {/* Encabezado */}
      <div className="flex items-start gap-2">
        <div className={cn("mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-background/50", TONE_TEXT[v.tone])}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
            Veredicto del caso
          </div>
          <div className="flex items-center gap-1.5 text-[11px]">
            <span className={cn("font-semibold", TONE_TEXT[v.tone])}>automático · disposición</span>
            <span className="text-muted-foreground">· confianza {v.confidence}</span>
          </div>
        </div>
      </div>

      {/* Frase NL */}
      <p className="text-[11px] leading-relaxed text-foreground/85">{v.summary}</p>

      {/* Dimensiones */}
      <div className="grid grid-cols-2 gap-2">
        <Tile title="Reputación" tile={v.reputation} />
        <Tile title="Alcance"    tile={v.scope} />
        <Tile title="Origen"     tile={v.origin} />
        <Tile title="Detección"  tile={v.detection} />
      </div>
    </div>
  );
});
