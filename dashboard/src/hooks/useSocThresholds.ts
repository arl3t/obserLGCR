/**
 * useSocThresholds — Hook React Query para leer los umbrales de severidad
 * publicados desde `/soc?tab=formula` (vía `GET /api/incidents/thresholds`).
 *
 * Por qué existe: hasta G1 (2026-05-20), los buckets CRITICAL/HIGH/MEDIUM
 * se mapeaban en el frontend con constantes hardcoded en `lib/risk-score.ts`
 * (80/55/30) que NO seguían a la fórmula publicada. Al subir critical_min
 * de 80 a 70 desde el lab, el Dashboard seguía mostrando "critical" sólo
 * con score≥80 — diverge del backend.
 *
 * Cache del backend: 30s (services/socThresholds.mjs). `staleTime` aquí lo
 * espejamos. `placeholderData` evita el flash de undefined al primer render.
 *
 * Usado por:
 *   · `lib/risk-score.severityFromScore` para etiquetar el riesgo global.
 *   · Cualquier UI que clasifique score → severidad.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export interface SeverityThresholds {
  critical: number;
  high:     number;
  medium:   number;
}

/** Defaults históricos — si el fetch falla mantenemos el comportamiento previo. */
export const DEFAULT_SEVERITY_THRESHOLDS: SeverityThresholds = {
  critical: 80,
  high:     60,
  medium:   35,
};

interface ApiThresholds {
  auto_escalate_score:   number;
  severity_critical_min: number;
  severity_high_min:     number;
  severity_medium_min:   number;
}

export function useSocThresholds() {
  return useQuery({
    queryKey: ["soc-thresholds"],
    queryFn: async (): Promise<SeverityThresholds> => {
      const { data } = await api.get<{ ok: boolean; thresholds: ApiThresholds }>("/api/incidents/thresholds");
      if (!data.ok) throw new Error("API devolvió ok=false");
      return {
        critical: data.thresholds.severity_critical_min,
        high:     data.thresholds.severity_high_min,
        medium:   data.thresholds.severity_medium_min,
      };
    },
    staleTime: 30_000,
    retry: 1,
    placeholderData: DEFAULT_SEVERITY_THRESHOLDS,
  });
}
