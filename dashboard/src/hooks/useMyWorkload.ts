/**
 * useMyWorkload — KPIs operador-globales para el banner "Mi trabajo hoy".
 *
 * Antes los 4 counters se derivaban del `useMemo myLoad` en
 * CaseManagementDashboard, que iteraba sólo la página actual (50 filas). Eso
 * producía "Mis activos == En riesgo SLA == Tu carga" cuando todos venían del
 * mismo conteo local, y reportaba subcounts muy por debajo del universo real
 * (audit 2026-05-13 — R12).
 *
 * Este hook consume GET /api/incidents/me que cuenta contra `incident_cases_pg`
 * completo, scoped al CI del JWT. Cache 30s en cliente (alineado con
 * Cache-Control private/max-age del backend).
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export interface MyWorkload {
  ci:                string | null;
  mineOpen:          number;
  mineAtRisk:        number;   // 70%–100% del SLA consumido — accionable (aún a tiempo)
  mineBreached:      number;   // >100% — SLA ya vencido
  criticalUnadopted: number;
  newUnassigned24h:  number;
}

const EMPTY: MyWorkload = {
  ci: null, mineOpen: 0, mineAtRisk: 0, mineBreached: 0,
  criticalUnadopted: 0, newUnassigned24h: 0,
};

export function useMyWorkload(enabled = true): MyWorkload {
  const { data } = useQuery<MyWorkload>({
    queryKey: ["incidents", "me"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean } & MyWorkload>("/api/incidents/me");
      if (!data?.ok) throw new Error("incidents/me ok=false");
      return data;
    },
    staleTime:        30_000,
    refetchInterval:  60_000,
    refetchOnWindowFocus: false,
    enabled,
  });
  return data ?? EMPTY;
}
