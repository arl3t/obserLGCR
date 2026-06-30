/**
 * WorkspaceSkeleton — placeholder estructural mientras `useSurveillanceCore`
 * carga el snapshot del dominio.
 *
 * La meta es CERO layout shift al llegar `data`: la jerarquía y alturas
 * coinciden con TabResumen renderizado (header tabs + KPI strip 5 cols +
 * toolbar export + 3 cards de finding placeholder). Cuando data llega, las
 * mismas regiones cambian de placeholder a contenido sin saltos.
 */

import { Skeleton } from "@/components/ui/skeleton";

export function WorkspaceSkeleton() {
  return (
    <div className="space-y-4" aria-busy aria-label="Cargando análisis del dominio">
      {/* Tab triggers (8 tabs) */}
      <div className="flex gap-1.5 overflow-hidden">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-24 shrink-0 rounded-md" />
        ))}
      </div>

      {/* KPI strip 5 columnas */}
      <div className="grid grid-cols-5 gap-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="space-y-1.5 rounded-xl border border-border/40 bg-muted/10 p-3">
            <Skeleton className="h-3 w-16" />
            <Skeleton className="h-6 w-10" />
            <Skeleton className="h-3 w-20" />
          </div>
        ))}
      </div>

      {/* Toolbar: dominio + export + push */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-1">
        <Skeleton className="h-4 w-48" />
        <div className="flex items-center gap-1.5">
          <Skeleton className="h-8 w-44 rounded-md" />
          <Skeleton className="h-8 w-28 rounded-md" />
          <Skeleton className="h-8 w-32 rounded-md" />
        </div>
      </div>

      {/* DiffStrip placeholder */}
      <Skeleton className="h-9 w-full rounded-xl" />

      {/* Toolbar de filtros (filter bar + chips) */}
      <div className="space-y-2 rounded-xl border border-border/40 bg-muted/10 p-3">
        <div className="flex items-center gap-2">
          <Skeleton className="h-7 w-44 rounded-md" />
          <Skeleton className="h-7 w-16 rounded-md" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-5 w-16 rounded-md" />
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {Array.from({ length: 7 }).map((_, i) => (
            <Skeleton key={i} className="h-5 w-20 rounded-md" />
          ))}
        </div>
      </div>

      {/* 3 finding cards estructuradas */}
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="space-y-3 rounded-xl border border-border/40 bg-card p-4">
            <div className="flex items-start gap-3">
              <Skeleton className="h-9 w-9 rounded-lg" />
              <div className="flex-1 space-y-2">
                <div className="flex gap-1.5">
                  <Skeleton className="h-5 w-16 rounded-md" />
                  <Skeleton className="h-5 w-24 rounded-md" />
                  <Skeleton className="h-5 w-14 rounded-md" />
                </div>
                <Skeleton className="h-5 w-3/4" />
              </div>
            </div>
            <div className="grid grid-cols-[88px,1fr] gap-x-3 gap-y-2">
              <Skeleton className="h-3 w-12" />
              <Skeleton className="h-3 w-2/3" />
              <Skeleton className="h-3 w-12" />
              <Skeleton className="h-3 w-1/2" />
            </div>
            <div className="flex gap-2 border-t border-border/30 pt-3">
              <Skeleton className="h-8 w-28 rounded-md" />
              <Skeleton className="h-8 w-24 rounded-md" />
              <Skeleton className="ml-auto h-8 w-20 rounded-md" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
