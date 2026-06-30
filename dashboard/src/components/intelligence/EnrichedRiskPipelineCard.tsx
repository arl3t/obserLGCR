import {
  CloudUpload,
  Database,
  Filter,
  GitMerge,
  Gauge,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * Flujo end-to-end del pipeline de enriquecimiento (extracción → contexto →
 * priorización → APIs externas → consumo). El score de prioridad se calcula en
 * runtime antes de consultar la reputación externa.
 */
const pipeline: {
  step: number;
  title: string;
  icon: LucideIcon;
  detail: string;
}[] = [
  {
    step: 1,
    title: "Extracción al lake",
    icon: Database,
    detail:
      "Extracción idempotente desde los sensores (firewall/perímetro y SIEM) al lake de IOCs enriquecidos, con clave de deduplicación, contexto crudo del evento y fecha.",
  },
  {
    step: 2,
    title: "Contexto MITRE / NIST",
    icon: GitMerge,
    detail:
      "Se propaga la técnica/táctica MITRE ATT&CK y la categoría NIST desde las dimensiones y las reglas del SIEM — necesario antes de priorizar el enriquecimiento.",
  },
  {
    step: 3,
    title: "Score de prioridad",
    icon: Gauge,
    detail:
      "Score de priorización calculado en tiempo de ejecución: suma puntos si hay técnica MITRE y por la severidad del evento del SIEM (nivel alto). No se persiste — se recalcula al priorizar.",
  },
  {
    step: 4,
    title: "Umbral y candidatos",
    icon: Filter,
    detail:
      "Quedan como candidatos los IOCs por encima del umbral de prioridad configurado y sin reputación reciente en caché (con exclusiones opcionales de feeds de phishing/malware).",
  },
  {
    step: 5,
    title: "Enriquecimiento externo",
    icon: ShieldCheck,
    detail:
      "Consulta a las fuentes externas (VirusTotal, Shodan, AbuseIPDB) y persistencia de la reputación con marca temporal y conteos.",
  },
  {
    step: 6,
    title: "Consumo en dashboard",
    icon: CloudUpload,
    detail:
      "Esta vista cruza los IOCs enriquecidos con su reputación por observable, tipo y fecha para medir cobertura y severidad.",
  },
];

export function EnrichedRiskPipelineCard() {
  return (
    <Card className="border-border/80">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Flujo del score de riesgo y enriquecimiento</CardTitle>
        <p className="text-sm text-muted-foreground">
          De los logs a la reputación externa, en el mismo orden que el pipeline de enriquecimiento:
          extracción → contexto MITRE/NIST → priorización → APIs externas → lake.
        </p>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {pipeline.map((s) => (
            <div
              key={s.step}
              className={cn(
                "flex gap-3 rounded-lg border border-border bg-muted/20 p-3",
              )}
            >
              <div
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/15 text-xs font-bold text-primary"
                aria-hidden
              >
                {s.step}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <s.icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  <h3 className="text-sm font-semibold leading-tight">{s.title}</h3>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{s.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
