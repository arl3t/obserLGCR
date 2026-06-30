/**
 * HuntVerdictCard.tsx — Tarjeta "Caza de Amenazas LLM".
 *
 * Se monta en la columna derecha de la Investigación, DEBAJO de "Veredicto del
 * caso". Trae los hallazgos del Centro de Inteligencia de Caza Externa asociados
 * a este caso (GET /api/cases/:id/hunt-findings — por link explícito o por
 * coincidencia de IOC) y muestra el veredicto razonado del analista LLM (F2).
 * Si no hay ningún hallazgo de caza para el caso, la tarjeta NO se renderiza.
 */
import { memo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Radar, Brain, ExternalLink } from "lucide-react";
import { api } from "@/api/client";
import { cn } from "@/lib/utils";
import { formatDateTimePy } from "@/lib/format";
import type { FullCase } from "./useCaseInvestigation";

interface HuntFinding {
  finding_id: string;
  pattern_key: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  title: string;
  external_entity: string | null;
  internal_asset: string | null;
  status: string;
  last_seen: string | null;
  llm_verdict: "benign" | "suspicious" | "malicious" | "inconclusive" | null;
  llm_confidence: number | null;
  llm_narrative: string | null;
  llm_recommended_action: string | null;
  llm_analyzed_at: string | null;
}

type Tone = "red" | "amber" | "emerald" | "muted";
const VERDICT_TONE: Record<string, Tone> = {
  malicious: "red", suspicious: "amber", benign: "emerald", inconclusive: "muted",
};
const TONE_RING: Record<Tone, string> = {
  red:     "border-red-500/40 bg-red-500/5",
  amber:   "border-amber-500/40 bg-amber-500/5",
  emerald: "border-emerald-500/40 bg-emerald-500/5",
  muted:   "border-border/60 bg-muted/10",
};
const TONE_TEXT: Record<Tone, string> = {
  red: "text-red-400", amber: "text-amber-400", emerald: "text-emerald-400", muted: "text-muted-foreground",
};
const VERDICT_LABEL: Record<string, string> = {
  malicious: "Malicioso", suspicious: "Sospechoso", benign: "Benigno", inconclusive: "Inconcluso",
};
const PATTERN_LABEL: Record<string, string> = {
  ot_egress_foreign_cloud:  "Egress a nube foránea",
  beaconing_cadence:        "Beaconing por cadencia",
  permitido_intel_negativa: "Permitido a IP con intel negativa",
  auth_bruteforce:          "Brute-force de login",
};

export const HuntVerdictCard = memo(function HuntVerdictCard({ c }: { c: FullCase }) {
  const q = useQuery({
    queryKey: ["case-hunt-findings", c.id],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; findings: HuntFinding[] }>(
        `/api/cases/${c.id}/hunt-findings`,
      );
      return data.findings ?? [];
    },
    staleTime: 60_000,
  });

  const findings = q.data ?? [];
  if (q.isLoading || findings.length === 0) return null; // sin caza → no estorba

  const top = findings[0];
  const tone: Tone = VERDICT_TONE[top.llm_verdict ?? "inconclusive"] ?? "muted";

  return (
    <div className={cn("rounded-lg border p-3 space-y-3", TONE_RING[tone])}>
      {/* Encabezado */}
      <div className="flex items-start gap-2">
        <div className={cn("mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-background/50", TONE_TEXT[tone])}>
          <Radar className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
            Caza de Amenazas LLM
          </div>
          <div className="flex items-center gap-1.5 text-[11px]">
            <span className={cn("font-semibold", TONE_TEXT[tone])}>
              {top.llm_verdict ? VERDICT_LABEL[top.llm_verdict] ?? top.llm_verdict : "Sin veredicto"}
            </span>
            {typeof top.llm_confidence === "number" && (
              <span className="text-muted-foreground">· confianza {top.llm_confidence}%</span>
            )}
          </div>
        </div>
        <Link to="/caza-externa" className="text-muted-foreground hover:text-foreground" title="Ver en Caza Externa">
          <ExternalLink className="h-3.5 w-3.5" />
        </Link>
      </div>

      {/* Patrón + destino */}
      <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
        <span className="rounded border bg-muted/30 px-1.5 py-0.5 text-muted-foreground">
          {PATTERN_LABEL[top.pattern_key] ?? top.pattern_key}
        </span>
        {top.external_entity && (
          <span className="rounded border bg-muted/30 px-1.5 py-0.5 text-muted-foreground">
            → {top.external_entity}
          </span>
        )}
        {top.llm_recommended_action && (
          <span className="rounded border bg-muted/30 px-1.5 py-0.5 text-muted-foreground">
            acción: {top.llm_recommended_action}
          </span>
        )}
      </div>

      {/* Narrativa del analista */}
      {top.llm_narrative && (
        <p className="text-[11px] leading-relaxed text-foreground/85">{top.llm_narrative}</p>
      )}

      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <span className="inline-flex items-center gap-1"><Brain className="h-3 w-3" /> analista qwen3.5</span>
        {top.llm_analyzed_at && <span>{formatDateTimePy(top.llm_analyzed_at)}</span>}
      </div>

      {findings.length > 1 && (
        <div className="text-[10px] text-muted-foreground">
          +{findings.length - 1} hallazgo(s) de caza más sobre este caso.
        </div>
      )}
    </div>
  );
});
