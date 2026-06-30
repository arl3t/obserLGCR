/**
 * useSlaConfig — Hook React Query para leer el SLA por severidad desde el
 * API (`GET /api/incidents/sla`). Devuelve un mapa severity → segundos.
 *
 * Cache del backend: 30s (services/slaConfig.mjs). `staleTime` aquí lo
 * espejamos así no rehacemos fetch antes que el backend pueda devolver
 * algo nuevo. Si la query falla, devolvemos los defaults históricos.
 *
 * Usado por:
 *   · InvestigationPanels.SlaChip → deadline countdown
 *   · cualquier UI que necesite mostrar SLA progress / budget
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export type SlaSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE";

export interface SlaConfigResponse {
  sla_critical_sec:   number;
  sla_high_sec:       number;
  sla_medium_sec:     number;
  sla_low_sec:        number;
  sla_negligible_sec: number;
  updated_by:         string | null;
  updated_at:         string | null;
}

export type SlaSecMap = Record<SlaSeverity, number>;

/** Defaults históricos — si el fetch falla, mantenemos el comportamiento previo. */
export const DEFAULT_SLA_SEC: SlaSecMap = {
  CRITICAL:   900,
  HIGH:       3600,
  MEDIUM:     14400,
  LOW:        86400,
  NEGLIGIBLE: 259200,
};

function toSecMap(r: SlaConfigResponse): SlaSecMap {
  return {
    CRITICAL:   r.sla_critical_sec,
    HIGH:       r.sla_high_sec,
    MEDIUM:     r.sla_medium_sec,
    LOW:        r.sla_low_sec,
    NEGLIGIBLE: r.sla_negligible_sec,
  };
}

export function useSlaConfig() {
  return useQuery({
    queryKey: ["sla-config"],
    queryFn: async (): Promise<SlaSecMap> => {
      const { data } = await api.get<{ ok: boolean; sla: SlaConfigResponse }>("/api/incidents/sla");
      if (!data.ok) throw new Error("API devolvió ok=false");
      return toSecMap(data.sla);
    },
    staleTime: 30_000,
    retry: 1,
    placeholderData: DEFAULT_SLA_SEC,
  });
}

/** Helper sync para casos donde no se quiere meter useQuery: caer al default. */
export function getSlaSecFromMap(map: SlaSecMap | undefined, severity: string | undefined | null): number {
  const sev = String(severity ?? "MEDIUM").toUpperCase() as SlaSeverity;
  return (map ?? DEFAULT_SLA_SEC)[sev] ?? DEFAULT_SLA_SEC.MEDIUM;
}
