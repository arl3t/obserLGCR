/**
 * TabEjecutivo — vista por defecto del módulo Vigilancia Digital v2.
 *
 * Portada institucional para gerencia y compliance. Layout rediseñado
 * (mayo 2026) — fusiona portada + risk + CTAs en un único `ExecutiveHero`,
 * y reemplaza la lista de dimensiones por un grid 3×2 con sparklines y
 * status pip de 5 puntos. Añade `MitreHeatMap` con la cobertura ATT&CK
 * derivada de los findings cross-source.
 *
 * Estructura:
 *   1. ExecutiveHero      — sello + dominio + risk score + Δ + sources + CTAs
 *   2. SurfaceGrid         — 6 superficies con sparklines y delta vs prev
 *   3. HistoryTimelineCard — chart de evolución (sin delta badges, ya en hero)
 *   4. MitreHeatMap        — cobertura ATT&CK por táctica (oculto si no hay)
 *   5. Resumen + Acciones  — narrativa ejecutiva + playbook P2/P3/P4
 *   6. ExecutiveFooter     — pie institucional
 *
 * Datos: el componente NO recibe props (consume `useSurveillance()`). El
 * `onExportPdf` se delega al hero (mismo patrón que TabReporte).
 */

import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { ExecutiveHero } from "@/components/digital-surveillance/executive/ExecutiveHero";
import { SurfaceGrid } from "@/components/digital-surveillance/executive/SurfaceGrid";
import { HistoryTimelineCard } from "@/components/digital-surveillance/executive/HistoryTimelineCard";
import { MitreHeatMap } from "@/components/digital-surveillance/executive/MitreHeatMap";
import { ResumenEjecutivo } from "@/components/digital-surveillance/executive/ResumenEjecutivo";
import { AccionesPriorizadas } from "@/components/digital-surveillance/executive/AccionesPriorizadas";
import { ExecutiveFooter } from "@/components/digital-surveillance/executive/ExecutiveFooter";

export function TabEjecutivo({ onExportPdf }: { onExportPdf: () => void }) {
  const { domain } = useSurveillance();
  if (!domain) return null;

  return (
    <div className="space-y-6">
      <ExecutiveHero onExportPdf={onExportPdf} />

      <SurfaceGrid />

      <HistoryTimelineCard />

      <MitreHeatMap />

      <div className="grid gap-6 lg:grid-cols-[3fr,4fr]">
        <ResumenEjecutivo />
        <AccionesPriorizadas />
      </div>

      <ExecutiveFooter />
    </div>
  );
}
