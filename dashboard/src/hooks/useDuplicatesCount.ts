/**
 * useDuplicatesCount — KPI ligero de "grupos de casos duplicados pendientes".
 *
 * Empuja al operador hacia el DuplicatePanel cuando hay merges disponibles
 * (audit 2026-05-13 — R8). Consume GET /api/incidents/duplicates/count que
 * cuenta grupos de ≥2 casos abiertos con el mismo ioc_value. La query es
 * PG-only (sub-50ms), apta para hot-poll cada minuto.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export interface DuplicatesCount {
  groupsCount:     number;
  totalDuplicates: number;
}

const EMPTY: DuplicatesCount = { groupsCount: 0, totalDuplicates: 0 };

export function useDuplicatesCount(enabled = true): DuplicatesCount {
  const { data } = useQuery<DuplicatesCount>({
    queryKey: ["incidents", "duplicates-count"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean } & DuplicatesCount>(
        "/api/incidents/duplicates/count",
      );
      if (!data?.ok) throw new Error("duplicates/count ok=false");
      return { groupsCount: data.groupsCount, totalDuplicates: data.totalDuplicates };
    },
    staleTime:        60_000,
    refetchInterval:  120_000,
    refetchOnWindowFocus: false,
    enabled,
  });
  return data ?? EMPTY;
}
