/**
 * Hooks mínimos de operadores SOC (Postgres vía /api/operators).
 * El fork demo no monta /api/workflow/* — solo lista de operadores, roles y shift manager.
 */

import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export interface SocRole {
  id: string;
  name: string;
  description: string;
  can_adopt: boolean;
  can_escalate_to_l2: boolean;
  can_escalate_to_l3: boolean;
  can_close_fp: boolean;
  can_close_case: boolean;
  can_assign_cases: boolean;
  can_review_kpis: boolean;
  can_post_mortem: boolean;
  can_create_handover: boolean;
  receives_auto_assign: boolean;
  escalation_score_threshold: number | null;
}

export interface SocOperator {
  id: string;
  name: string;
  email: string | null;
  role_id: string;
  role_name: string;
  is_active: boolean;
  is_shift_manager: boolean;
  shift: string;
  cases_adopted: number;
  cases_closed: number;
  fp_count: number;
  avg_mtta_min: number | null;
  avg_mttr_min: number | null;
  last_active_at: string | null;
}

const STALE_2M = { staleTime: 2 * 60_000 } as const;
const STALE_5M = { staleTime: 5 * 60_000 } as const;

const K = {
  operators: ["operators"] as const,
  roles: ["operators", "roles"] as const,
  shiftMgr: ["operators", "shift-manager"] as const,
};

export function useSocRoles() {
  return useQuery<SocRole[]>({
    queryKey: K.roles,
    queryFn: async () => {
      const { data } = await api.get<SocRole[]>("/api/operators/roles");
      return data;
    },
    ...STALE_5M,
    refetchOnWindowFocus: true,
  });
}

export function useSocOperators() {
  return useQuery<SocOperator[]>({
    queryKey: K.operators,
    queryFn: async () => {
      const { data } = await api.get<SocOperator[]>("/api/operators");
      return data;
    },
    ...STALE_2M,
    refetchInterval: 5 * 60_000,
    refetchOnWindowFocus: false,
  });
}

export function useShiftManager() {
  return useQuery<SocOperator | null>({
    queryKey: K.shiftMgr,
    queryFn: async () => {
      const { data } = await api.get<SocOperator | null>("/api/operators/shift-manager/current");
      return data?.id ? data : null;
    },
    ...STALE_5M,
    refetchInterval: 10 * 60_000,
  });
}
