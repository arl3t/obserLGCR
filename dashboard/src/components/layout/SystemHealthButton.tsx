/**
 * SystemHealthButton.tsx
 * Botón "Sistema" en la barra superior (junto a Scoring e Incidentes).
 * Semáforo operativo del SOC: estado del Shift Manager + hit-rate del caché Trino.
 * Al hacer clic abre un Sheet con el detalle (scheduler, caché, últimas corridas).
 *
 * Fuente: GET /api/workflow/health (refresco 60s). Reubicado desde la franja
 * "Sistema" que vivía dentro del dashboard de Gestión de Casos.
 */

import { Server } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTimePy } from "@/lib/format";

interface SocHealthData {
  ok: boolean;
  shiftManagerAbsent?: boolean;
  schedulerMetrics?: {
    autoClosedTotal: number;
    autoAssignedTotal: number;
    autoAssignSkipsNoSM: number;
    lastRun: { autoClose: string | null; autoAssign: string | null };
  };
  cacheStats?: { hits: number; misses: number; evictions: number; hitRate: number };
}

function useSocHealth(intervalMs = 60_000): SocHealthData | null {
  const { data } = useQuery<SocHealthData>({
    queryKey: ["workflow-health"],
    queryFn: async () => {
      const { data } = await api.get<SocHealthData>("/api/workflow/health");
      return data;
    },
    staleTime: intervalMs,
    refetchInterval: intervalMs,
    refetchOnWindowFocus: false,
  });
  return data ?? null;
}

function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  try { return formatDateTimePy(iso); } catch { return String(iso).slice(0, 16).replace("T", " "); }
}

export function SystemHealthButton() {
  const health = useSocHealth();
  const smAbsent = health?.shiftManagerAbsent ?? false;
  const cachePct = health?.cacheStats ? Math.round((health.cacheStats.hitRate ?? 0) * 100) : null;
  const sched = health?.schedulerMetrics;

  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="relative gap-2 border-border/60 pr-3 text-xs"
          aria-label={`Sistema: Shift Manager ${smAbsent ? "ausente" : "activo"}${cachePct != null ? `, caché ${cachePct}%` : ""}`}
        >
          <Server className="h-3.5 w-3.5 shrink-0" aria-hidden />
          <span className="hidden sm:inline">Sistema</span>
          {/* Punto de estado del Shift Manager */}
          <span
            className={`h-2 w-2 shrink-0 rounded-full ${
              health == null ? "bg-muted-foreground/40" : smAbsent ? "bg-red-500" : "bg-emerald-500"
            }`}
            aria-hidden
          />
          {cachePct != null && (
            <span className="hidden tabular-nums text-muted-foreground md:inline">
              {cachePct}%
            </span>
          )}
        </Button>
      </SheetTrigger>

      <SheetContent side="right" className="flex w-[min(100vw,24rem)] flex-col gap-0 p-0">
        <SheetHeader className="border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-primary" aria-hidden />
            <SheetTitle className="text-sm font-semibold">Estado del sistema</SheetTitle>
          </div>
          <p className="text-xs text-muted-foreground">
            Salud operativa del SOC · actualiza cada 60 s
          </p>
        </SheetHeader>

        <div className="flex-1 space-y-3 overflow-y-auto px-4 py-4 text-xs">
          {health == null ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full rounded-lg" />
              ))}
            </div>
          ) : (
            <>
              {/* Shift Manager */}
              <div className={`rounded-lg border p-3 ${smAbsent ? "border-red-500/30 bg-red-500/8" : "border-emerald-500/30 bg-emerald-500/8"}`}>
                <div className="flex items-center justify-between">
                  <span className="font-semibold">Shift Manager</span>
                  <span className={`text-[11px] font-bold uppercase ${smAbsent ? "text-red-400" : "text-emerald-400"}`}>
                    {smAbsent ? "Ausente" : "Activo"}
                  </span>
                </div>
                <p className="mt-1 text-muted-foreground">
                  Jefe de turno designado. Si está ausente, la auto-asignación de casos sin adoptar se omite.
                </p>
                {(sched?.autoAssignSkipsNoSM ?? 0) > 0 && (
                  <p className="mt-1 font-medium text-amber-500/90">
                    {sched!.autoAssignSkipsNoSM} ciclo(s) de auto-asignación omitido(s) por falta de SM.
                  </p>
                )}
              </div>

              {/* Caché Trino */}
              {health.cacheStats && (
                <div className="rounded-lg border border-border bg-muted/20 p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">Caché de consultas (Trino)</span>
                    <span className={`text-[11px] font-bold tabular-nums ${cachePct! >= 60 ? "text-emerald-400" : cachePct! >= 30 ? "text-amber-400" : "text-red-400"}`}>
                      {cachePct}% aciertos
                    </span>
                  </div>
                  <p className="mt-1 text-muted-foreground tabular-nums">
                    {health.cacheStats.hits} hits / {health.cacheStats.hits + health.cacheStats.misses} consultas · {health.cacheStats.evictions} evictions
                  </p>
                  <p className="mt-1 text-muted-foreground/70">
                    Protege a Trino (1 nodo) de saturarse. Un hit-rate bajo = más carga directa y respuestas más lentas.
                  </p>
                </div>
              )}

              {/* Scheduler / automatización */}
              {sched && (
                <div className="rounded-lg border border-border bg-muted/20 p-3">
                  <span className="font-semibold">Automatización</span>
                  <div className="mt-1.5 grid grid-cols-2 gap-2 text-muted-foreground tabular-nums">
                    <div>
                      <div className="text-base font-bold text-foreground">{sched.autoClosedTotal}</div>
                      <div className="text-[10px] uppercase tracking-wide">Auto-cerrados (LOW/NEG)</div>
                    </div>
                    <div>
                      <div className="text-base font-bold text-foreground">{sched.autoAssignedTotal}</div>
                      <div className="text-[10px] uppercase tracking-wide">Auto-asignados al SM</div>
                    </div>
                  </div>
                  <div className="mt-2 space-y-0.5 text-[11px] text-muted-foreground/70">
                    <p>Última auto-cierre: {fmtDateTime(sched.lastRun?.autoClose)}</p>
                    <p>Última auto-asignación: {fmtDateTime(sched.lastRun?.autoAssign)}</p>
                  </div>
                </div>
              )}

              <p className="pt-1 text-[10px] text-muted-foreground/60">
                Conteos acumulados desde el último arranque del servidor.
              </p>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
