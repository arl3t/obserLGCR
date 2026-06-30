/**
 * useTransitionPolicy — fuente única de VALID_TRANSITIONS + caps requeridos.
 *
 * Antes existían dos copias del mapa (una en routes/incidents.mjs, otra en
 * components/case-management/CaseDetailSheet.tsx). Cada cambio exigía tocar
 * los dos lados o se generaban 422 "transición inválida" porque la UI
 * habilitaba botones que el server rechazaba. Ahora el backend expone el
 * mapa en GET /api/incidents/transitions y este hook lo consume con caché
 * largo (es config estática) y fallback local para no romper el flujo si
 * la red falla o el API aún no se actualizó.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { CaseStatus } from "@/components/case-management/types";

export type RoleCapability =
  | "can_adopt"
  | "can_escalate_to_l2"
  | "can_escalate_to_l3"
  | "can_close_fp"
  | "can_close_case"
  | "can_assign_cases"
  | "can_review_kpis"
  | "can_post_mortem"
  | "can_create_handover";

export type TransitionPolicy = {
  transitions: Record<string, CaseStatus[]>;
  /**
   * Map target status → cap(s) requeridos. Un string = un cap obligatorio,
   * un array = cualquiera alcanza. Targets no presentes no exigen cap extra.
   */
  requiredCaps: Partial<Record<CaseStatus, RoleCapability | RoleCapability[]>>;
};

/**
 * Fallback usado si el fetch al backend falla (lab offline, primer render
 * antes de que resuelva la query, etc.). Debe mantenerse en paralelo con
 * VALID_TRANSITIONS + TRANSITION_CAP en routes/incidents.mjs — si diverge,
 * la UI puede habilitar botones que el server rechaza con 422, así que
 * tratamos este fallback como "best-effort para no bloquear" y el servidor
 * sigue siendo la autoridad.
 */
export const FALLBACK_POLICY: TransitionPolicy = {
  transitions: {
    NUEVO:          ["EN_ANALISIS", "FALSO_POSITIVO", "MONITOREADO", "CERRADO"],
    EN_ANALISIS:    ["CONFIRMADO", "ESCALADO", "FALSO_POSITIVO", "MONITOREADO", "CERRADO"],
    CONFIRMADO:     ["ESCALADO", "CERRADO", "MONITOREADO"],
    MONITOREADO:    ["EN_ANALISIS", "ESCALADO", "FALSO_POSITIVO", "CERRADO"],
    ESCALADO:       ["CONFIRMADO", "CERRADO", "FALSO_POSITIVO"],
    FALSO_POSITIVO: ["CERRADO", "EN_ANALISIS"],
    CERRADO:        [],
  },
  requiredCaps: {
    FALSO_POSITIVO: "can_close_fp",
    CERRADO:        "can_close_case",
    ESCALADO:       ["can_escalate_to_l2", "can_escalate_to_l3"],
  },
};

type ApiResponse = {
  ok: boolean;
  transitions: Record<string, string[]>;
  requiredCaps: Partial<Record<string, string | string[]>>;
};

export function useTransitionPolicy(): TransitionPolicy {
  const { data } = useQuery({
    queryKey: ["incidents", "transitions"],
    queryFn: async () => {
      const { data } = await api.get<ApiResponse>("/api/incidents/transitions");
      if (!data?.ok) throw new Error("transitions endpoint returned ok=false");
      return {
        transitions:  data.transitions as Record<string, CaseStatus[]>,
        requiredCaps: data.requiredCaps as TransitionPolicy["requiredCaps"],
      };
    },
    staleTime:            30 * 60_000,   // 30 min — config prácticamente estática
    refetchOnWindowFocus: false,
    retry:                1,
  });
  return data ?? FALLBACK_POLICY;
}
