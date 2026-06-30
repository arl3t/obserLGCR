/**
 * useSocTier — mapeo del rol Keycloak al "tier" operativo del SOC.
 *
 * Keycloak es la fuente de verdad de acceso (analyst/hunter/manager/admin),
 * pero el flujo operativo del SOC piensa en términos de L1/L2/L3/LEADER.
 * Este helper centraliza la traducción para que la UI (sidebar, vistas
 * especializadas, redirects post-login) no embeba la lógica en cada
 * componente.
 *
 * Mapping (definido en C2 — UX bloque LEADER, 2026-05-21):
 *   admin    → LEADER  (manager con escalación + ops del sistema)
 *   manager  → LEADER  (KPIs del turno, SLA, handover, reportes)
 *   hunter   → L2L3    (análisis profundo + IR; un solo tier para no
 *                        fragmentar UI mientras no haya rol L3 separado en KC)
 *   analyst  → L1      (triage, adopción inicial)
 *   (none)   → null    (no logueado o rol desconocido)
 *
 * No reemplaza `hasMinRole`/`hasRole` — esos siguen siendo la API canónica
 * para gates de acceso. Este helper es para *bifurcar* UI por tier.
 */

import { useAuth } from "./useAuth";

export type SocTier = "L1" | "L2L3" | "LEADER";

/** Mapea un rol Keycloak a tier SOC. Exportado para uso fuera de React
 *  (e.g. helpers de routing puros). */
export function roleToTier(role: string | null | undefined): SocTier | null {
  switch ((role ?? "").toLowerCase()) {
    case "admin":   return "LEADER";
    case "manager": return "LEADER";
    case "hunter":  return "L2L3";
    case "analyst": return "L1";
    default:        return null;
  }
}

/** Resuelve el tier *efectivo* desde una lista de roles. Si el usuario tiene
 *  varios (composite KC), devuelve el más alto: LEADER > L2L3 > L1. */
export function rolesToTier(roles: string[] | null | undefined): SocTier | null {
  if (!roles || roles.length === 0) return null;
  const tiers = roles.map(roleToTier).filter((t): t is SocTier => t != null);
  if (tiers.includes("LEADER")) return "LEADER";
  if (tiers.includes("L2L3"))   return "L2L3";
  if (tiers.includes("L1"))     return "L1";
  return null;
}

/** Vista por defecto al loguearse según tier. Centralizamos acá para que
 *  redirects post-login (LoginCallback) y links del sidebar coincidan. */
export function defaultHomeForTier(tier: SocTier | null): string {
  switch (tier) {
    case "LEADER": return "/gestion?preset=critical";
    case "L2L3":   return "/gestion";
    case "L1":     return "/triage";
    default:       return "/gestion";  // fallback genérico
  }
}

/** Hook React: tier del usuario actual + helpers comunes. */
export function useSocTier(): {
  tier: SocTier | null;
  isLeader: boolean;
  isL2L3:   boolean;
  isL1:     boolean;
  defaultHome: string;
} {
  const { roles } = useAuth();
  const tier = rolesToTier(roles);
  return {
    tier,
    isLeader: tier === "LEADER",
    isL2L3:   tier === "L2L3",
    isL1:     tier === "L1",
    defaultHome: defaultHomeForTier(tier),
  };
}
