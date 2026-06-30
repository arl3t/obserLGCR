/**
 * Heurísticas locales (sin feeds externos de reputación) para priorizar en UI.
 * Sustituir o combinar con APIs (VirusTotal, etc.) cuando existan.
 */

export type IpRepTier = "bajo" | "medio" | "alto" | "crítico";

/** IP bloqueada en perímetro: más eventos → mayor interés analítico. */
export function heuristicBlockedIpReputation(hits: number): {
  tier: IpRepTier;
  score: number;
  note: string;
} {
  const h = Math.max(0, hits);
  if (h >= 2000)
    return { tier: "crítico", score: 95, note: "Volumen extremo de bloqueos" };
  if (h >= 500)
    return { tier: "alto", score: 75, note: "Persistencia / escaneo probable" };
  if (h >= 120) return { tier: "medio", score: 48, note: "Actividad repetida" };
  return { tier: "bajo", score: 22, note: "Ruido puntual" };
}

/** Host interno con muchos destinos de puerto distintos hoy (proxy de exploración lateral). */
export function heuristicLateralMovementNote(
  uniqueDstPorts: number,
  events: number,
): { tier: IpRepTier; note: string } {
  const u = Math.max(0, uniqueDstPorts);
  const e = Math.max(0, events);
  if (u >= 12 || (u >= 8 && e >= 50))
    return { tier: "crítico", note: "Muchos destinos; revisar east-west" };
  if (u >= 6) return { tier: "alto", note: "Posible barrido interno" };
  if (u >= 4) return { tier: "medio", note: "Vigilar correlación Wazuh" };
  return { tier: "bajo", note: "Patrón acotado" };
}
