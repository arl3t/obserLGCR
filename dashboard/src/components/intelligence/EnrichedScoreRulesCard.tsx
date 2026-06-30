import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Fórmula del score de prioridad de enriquecimiento (refleja el cálculo real del
 * pipeline, no borradores sueltos).
 */
export function EnrichedScoreRulesCard() {
  return (
    <Card className="border-border/80">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Fórmula del score (prioridad VirusTotal)</CardTitle>
        <p className="text-sm text-muted-foreground">
          Se calcula al elegir los candidatos a enriquecer; el umbral de prioridad es configurable
          (por defecto 4). El score no se persiste — se recalcula en cada corrida.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <ul className="space-y-2 text-sm text-muted-foreground">
          <li className="flex gap-2">
            <span className="font-mono text-xs text-primary">+2</span>
            <span>si el IOC tiene una técnica MITRE ATT&amp;CK asignada.</span>
          </li>
          <li className="flex gap-2">
            <span className="font-mono text-xs text-primary">+nivel</span>
            <span>
              si el evento proviene del SIEM con severidad alta (nivel ≥ 9): se suma el nivel
              (p. ej. 12 → +12).
            </span>
          </li>
        </ul>
        <p className="rounded-md border border-border/60 bg-muted/30 p-3 text-xs leading-relaxed text-muted-foreground">
          Tras el score, se filtran los candidatos sin reputación reciente en caché (ventana
          configurable), opcionalmente se excluyen los ya vistos en feeds de phishing/malware, y se
          consulta VirusTotal.
        </p>
      </CardContent>
    </Card>
  );
}
