import { useQuery } from "@tanstack/react-query";
import type { GeoIpInfo } from "@/lib/geoip";

const STALE_MS = 1000 * 60 * 60 * 6; // 6 h

async function fetchGeoIpBatch(ips: string[]): Promise<Record<string, GeoIpInfo>> {
  const res = await fetch("/api/geoip/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips }),
  });
  if (!res.ok) throw new Error(`GeoIP batch HTTP ${res.status}`);
  const data = await res.json();
  return data.result as Record<string, GeoIpInfo>;
}

/**
 * Resuelve país/bandera para una lista de IPs vía proxy del servidor (evita
 * restricciones de red del browser y rate limits del cliente).
 * Un solo fetch agrupa todas las IPs en la misma petición.
 */
export function useGeoIpBatch(ips: string[]) {
  const unique = [...new Set(ips.map((i) => i.trim()).filter(Boolean))];

  const query = useQuery({
    queryKey: ["geoip", "batch", unique.slice().sort().join(",")],
    queryFn: () => fetchGeoIpBatch(unique),
    enabled: unique.length > 0,
    staleTime: STALE_MS,
    gcTime: STALE_MS * 2,
    retry: 1,
  });

  const byIp: Record<string, GeoIpInfo> = query.data ?? {};
  const pending = query.isPending || query.isFetching;

  return { byIp, pending, uniqueIps: unique };
}
