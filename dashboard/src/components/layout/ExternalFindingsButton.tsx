/**
 * ExternalFindingsButton.tsx
 * Botón "Caza externa" en la barra superior (reemplaza al antiguo "Incidentes").
 * Muestra los últimos 10 hallazgos de Caza de Amenazas Externas (hunt_findings),
 * con su veredicto del analista LLM. El badge cuenta los hallazgos MALICIOSOS.
 *
 * Fuente: GET /api/intel/findings?sort=recent&limit=10 (refresco 30s).
 * "Ver todos" → /caza-externa (panel completo).
 */

import { Crosshair } from "lucide-react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { formatTimePy } from "@/lib/format";

interface Finding {
  finding_id: string;
  pattern_key: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  title: string;
  external_entity: string | null;
  evidence: { country?: string; asn_org?: string; dst_port?: number } | null;
  event_count: number;
  last_seen: string | null;
  status: "NEW" | "ANALYZED" | "TRIAGED" | "ACTIONED" | "SUPPRESSED";
  llm_verdict: "benign" | "suspicious" | "malicious" | "inconclusive" | null;
  llm_confidence: number | null;
  linked_case_id: string | null;
  case_number: number | null;
  created_at: string;
}
interface FindingsResponse {
  ok: boolean;
  summary?: { total: number; high: number; new: number; malicious: number };
  findings: Finding[];
}

const SEV_BADGE: Record<string, string> = {
  HIGH:   "bg-red-500/15 text-red-400 border-red-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  LOW:    "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};
const VERDICT_BADGE: Record<string, string> = {
  malicious:    "bg-red-500/15 text-red-400 border-red-500/30",
  suspicious:   "bg-amber-500/15 text-amber-400 border-amber-500/30",
  benign:       "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  inconclusive: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};
const PATTERN_LABEL: Record<string, string> = {
  ot_egress_foreign_cloud:  "Egress a nube foránea",
  beaconing_cadence:        "Beaconing por cadencia",
  permitido_intel_negativa: "Permitido a IP con intel negativa",
  auth_bruteforce:          "Brute-force de login",
};
const STATUS_LABEL: Record<string, string> = {
  NEW: "Nuevo", ANALYZED: "Analizado", TRIAGED: "Triajeado",
  ACTIONED: "Accionado", SUPPRESSED: "Suprimido",
};

function fmtTime(iso: string | null) {
  if (!iso) return "—";
  try { return formatTimePy(iso); } catch { return iso.slice(0, 16).replace("T", " "); }
}

export function ExternalFindingsButton() {
  const { data, isLoading } = useQuery<FindingsResponse>({
    queryKey: ["caza-findings", "nav-recent"],
    queryFn: async () => {
      const { data } = await api.get<FindingsResponse>("/api/intel/findings?sort=recent&limit=10");
      return data;
    },
    staleTime: 30_000,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,   // no golpear Trino con la pestaña oculta
    refetchOnWindowFocus: false,
  });

  const findings = data?.findings ?? [];
  const malicious = data?.summary?.malicious ?? 0;

  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="relative gap-2 border-border/60 pr-3 text-xs"
          aria-label={`Caza externa: ${malicious} hallazgo(s) malicioso(s)`}
        >
          <Crosshair className="h-3.5 w-3.5 shrink-0" aria-hidden />
          <span className="hidden sm:inline">Caza externa</span>
          {isLoading ? (
            <Skeleton className="h-4 w-5 rounded-full" />
          ) : malicious > 0 ? (
            <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white tabular-nums">
              {malicious > 99 ? "99+" : malicious}
            </span>
          ) : (
            <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-muted px-1 text-[10px] font-medium text-muted-foreground tabular-nums">
              0
            </span>
          )}
        </Button>
      </SheetTrigger>

      <SheetContent side="right" className="flex w-[min(100vw,27rem)] flex-col gap-0 p-0">
        <SheetHeader className="border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-primary" aria-hidden />
            <SheetTitle className="text-sm font-semibold">Caza externa — últimos hallazgos</SheetTitle>
          </div>
          <p className="text-xs text-muted-foreground">
            {data?.summary
              ? `${data.summary.total} activos · ${data.summary.new} sin analizar · ${malicious} maliciosos`
              : "Hallazgos de caza de amenazas externas"}
          </p>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-4 py-3">
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-24 w-full rounded-lg" />
              ))}
            </div>
          ) : findings.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <Crosshair className="h-10 w-10 text-muted-foreground/40" />
              <p className="text-sm text-muted-foreground">Sin hallazgos de caza externa activos</p>
              <p className="text-xs text-muted-foreground/60">
                Aparecerán aquí a medida que el motor de patrones detecte actividad externa.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {findings.map((f) => {
                const geo = [f.evidence?.country, f.evidence?.asn_org].filter(Boolean).join(" · ");
                return (
                  <div
                    key={f.finding_id}
                    className={`rounded-lg border p-3 text-xs space-y-2 ${f.llm_verdict === "malicious" ? "border-red-500/30 bg-red-500/8" : "border-border bg-muted/20"}`}
                  >
                    {/* Cabecera: severidad + patrón + estado */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${SEV_BADGE[f.severity] ?? ""}`}>
                        {f.severity}
                      </span>
                      <span className="text-muted-foreground">{PATTERN_LABEL[f.pattern_key] ?? f.pattern_key}</span>
                      <span className="ml-auto text-[10px] text-muted-foreground/70">{STATUS_LABEL[f.status] ?? f.status}</span>
                    </div>

                    {/* Título */}
                    <p className="font-medium text-foreground leading-snug">{f.title}</p>

                    {/* Entidad externa + geo */}
                    {f.external_entity && (
                      <div className="flex items-center justify-between gap-2 text-muted-foreground">
                        <span className="truncate font-mono">{f.external_entity}</span>
                        {geo && <span className="shrink-0 text-[10px] text-muted-foreground/70">{geo}</span>}
                      </div>
                    )}

                    {/* Veredicto LLM + eventos + caso */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      {f.llm_verdict ? (
                        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${VERDICT_BADGE[f.llm_verdict] ?? ""}`}>
                          {f.llm_verdict}{f.llm_confidence != null ? ` ${f.llm_confidence}%` : ""}
                        </span>
                      ) : (
                        <span className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground/70">sin analizar</span>
                      )}
                      <span className="text-muted-foreground/70 tabular-nums">{f.event_count} ev.</span>
                      {f.case_number != null && (
                        <span className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                          INC-{String(f.case_number).padStart(6, "0")}
                        </span>
                      )}
                      <span className="ml-auto text-[10px] text-muted-foreground/60 tabular-nums">{fmtTime(f.last_seen ?? f.created_at)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer: ir al panel completo */}
        <div className="border-t border-border p-3">
          <SheetClose asChild>
            <Link
              to="/caza-externa"
              className="flex w-full items-center justify-center rounded-md border border-border bg-muted/30 py-2 text-xs font-medium text-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
            >
              Ver todos los hallazgos →
            </Link>
          </SheetClose>
        </div>
      </SheetContent>
    </Sheet>
  );
}
