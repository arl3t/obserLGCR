/**
 * ResumenEjecutivo — narrativa breve para gerencia + 3 highlights.
 *
 * El primer párrafo arma un texto institucional adaptado al riskBand del dominio.
 * Los highlights son las 3 alertas top del Provider (`alerts` ordenadas por
 * severidad). Si no hay alertas, se muestra una nota positiva.
 */

import { CheckCircle2, FileText, TrendingUp } from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import type { RiskBand } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

const NARRATIVE: Record<RiskBand, { title: string; body: string }> = {
  high: {
    title: "Postura crítica · acción inmediata requerida",
    body:
      "El dominio presenta exposición alta en múltiples superficies. Se detectaron " +
      "factores de riesgo que requieren respuesta del SOC en los próximos 7 días. " +
      "Los hallazgos de mayor severidad están listados abajo.",
  },
  medium: {
    title: "Postura intermedia · vigilancia activa",
    body:
      "El dominio muestra señales de exposición que ameritan revisión. Las " +
      "fuentes activas reportaron incidentes de severidad media — se recomienda " +
      "atender los puntos priorizados antes del próximo ciclo de revisión.",
  },
  low: {
    title: "Postura saludable · monitoreo rutinario",
    body:
      "El dominio no muestra exposiciones críticas en las fuentes consultadas. " +
      "Se mantiene el monitoreo continuo y se alerta automáticamente ante cualquier " +
      "cambio significativo en las dimensiones definidas.",
  },
};

export function ResumenEjecutivo() {
  const { data, riskBand, alerts } = useSurveillance();
  if (!data) return null;

  const narrative = NARRATIVE[riskBand];
  const topAlerts = alerts.slice(0, 3);

  return (
    <section className="rounded-2xl border border-border bg-card p-6 shadow-sm sm:p-8">
      <header className="mb-4 flex items-center gap-2">
        <FileText className="h-4 w-4 text-emerald-500" aria-hidden />
        <h2 className="text-sm font-semibold uppercase tracking-widest text-foreground">
          Resumen Ejecutivo
        </h2>
      </header>

      {/* Narrativa adaptada al risk band */}
      <div className="space-y-3 border-l-2 border-emerald-500/30 pl-5">
        <p className={cn(
          "text-base font-semibold",
          riskBand === "high"   && "text-red-500",
          riskBand === "medium" && "text-amber-500",
          riskBand === "low"    && "text-emerald-500",
        )}>
          {narrative.title}
        </p>
        <p className="text-sm leading-relaxed text-foreground/80">
          {narrative.body}
        </p>
      </div>

      {/* Highlights */}
      <div className="mt-6 space-y-2">
        <p className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          <TrendingUp className="h-3 w-3" aria-hidden />
          Hallazgos principales
        </p>
        {topAlerts.length === 0 ? (
          <div className="flex items-start gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
            <p className="text-sm text-emerald-700 dark:text-emerald-300">
              Sin alertas activas en las fuentes consultadas.
            </p>
          </div>
        ) : (
          <ul className="space-y-2">
            {topAlerts.map((a, i) => (
              <li
                key={a.id ?? i}
                className="flex items-start gap-3 rounded-xl border border-border/50 bg-muted/30 p-3"
              >
                <span
                  className={cn(
                    "mt-1 h-2 w-2 shrink-0 rounded-full shadow-md",
                    a.severity === "high"   && "bg-red-400 shadow-red-400/40",
                    a.severity === "medium" && "bg-amber-400 shadow-amber-400/40",
                    a.severity === "low"    && "bg-emerald-400 shadow-emerald-400/30",
                  )}
                />
                <div className="flex-1">
                  <p className="text-sm font-semibold text-foreground">{a.title}</p>
                  {a.detail && (
                    <p className="mt-0.5 text-xs text-muted-foreground">{a.detail}</p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
