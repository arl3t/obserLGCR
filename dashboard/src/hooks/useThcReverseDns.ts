import { useQuery } from "@tanstack/react-query";
import { fetchThcReverseDnsWithFallback } from "@/lib/thc-reverse-dns-fetch";
import { classifyIp } from "@/lib/geoip";

export { fetchThcReverseDnsWithFallback as fetchThcReverseDnsLiveRefresh } from "@/lib/thc-reverse-dns-fetch";

/**
 * IPv4 pública (no RFC1918/reservada) — apta para reverse DNS THC.
 * Fuente ÚNICA: `classifyIp` en @/lib/geoip (que usa `isPrivateOrReservedIpv4`).
 * Antes reimplementaba los rangos RFC1918 acá → riesgo de divergencia con el
 * resto del front y con el backend (netClass). Ahora delega.
 */
export function isPublicIpv4ForThc(raw: string | null | undefined): boolean {
  return classifyIp(String(raw ?? "")).source === "public";
}

export const thcReverseDnsQueryKey = (ip: string, live: boolean) =>
  ["thc-reverse-dns", ip, live ? "live" : "auto"] as const;

export function useThcReverseDns(ip: string | null, enabled: boolean) {
  const trimmed = ip?.trim() ?? "";
  const pub = isPublicIpv4ForThc(trimmed);
  return useQuery({
    queryKey: thcReverseDnsQueryKey(trimmed, false),
    queryFn: () => fetchThcReverseDnsWithFallback(trimmed, { live: false }),
    enabled: enabled && pub && trimmed.length > 0,
    staleTime: 10 * 60_000,
    retry: 1,
  });
}

