import { BarChart3, LineChart, PieChart, Target, type LucideIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const items: {
  title: string;
  icon: LucideIcon;
  chart: string;
  why: string;
}[] = [
  {
    title: "Volumen por día",
    icon: LineChart,
    chart: "Barras o línea temporal de IOCs enriquecidos por fecha.",
    why: "Detecta caídas de la extracción, picos de ataque o ventanas vacías antes de culpar al enriquecimiento.",
  },
  {
    title: "Mix por fuente",
    icon: PieChart,
    chart: "Barras o donut: perímetro vs SIEM.",
    why: "Valida que ambos conductos alimentan el lake; los desbalances sugieren un fallo en una rama de ingesta.",
  },
  {
    title: "Histograma del score de prioridad",
    icon: BarChart3,
    chart: "Distribución del score calculado (MITRE + nivel del SIEM) en la ventana.",
    why: "Comprueba cuántos IOCs superan el umbral de prioridad; si casi todos quedan abajo, sube el ruido o baja la señal de reglas/MITRE.",
  },
  {
    title: "Cobertura de reputación",
    icon: Target,
    chart: "KPI: IOCs con reputación el mismo día; subconjunto con detecciones positivas.",
    why: "Mide la salud del enriquecimiento y prioriza el triage: primero los IOCs con detección positiva.",
  },
  {
    title: "Ranking por severidad",
    icon: BarChart3,
    chart: "Top N ordenado por detecciones maliciosas, luego score y fecha.",
    why: "Cuadro de mando operativo: qué observables revisar primero en el SOC.",
  },
  {
    title: "Ampliaciones útiles (siguiente iteración)",
    icon: LineChart,
    chart: "Serie temporal de consultas de reputación; breakdown por tipo de IOC; heatmap de técnicas MITRE.",
    why: "Latencia de enriquecimiento, tipos de IOC más costosos y cobertura de técnicas.",
  },
];

export function EnrichedChartRecommendationsCard() {
  return (
    <Card className="border-border/80">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Gráficos importantes (recomendado SOC)</CardTitle>
        <p className="text-sm text-muted-foreground">
          Los cuatro primeros están implementados en esta página como tarjetas con datos del lake; el
          resto son extensiones naturales del mismo modelo.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {items.map((it) => (
          <div
            key={it.title}
            className="flex gap-3 rounded-lg border border-dashed border-border/80 bg-card/40 p-3"
          >
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
              <it.icon className="h-4 w-4" aria-hidden />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium">{it.title}</p>
              <p className="mt-0.5 text-xs text-muted-foreground">{it.chart}</p>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground/90">
                <span className="font-medium text-foreground/80">Por qué:</span> {it.why}
              </p>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
