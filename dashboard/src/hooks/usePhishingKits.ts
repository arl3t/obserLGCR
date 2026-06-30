/**
 * usePhishingKits — fetch del endpoint URLhaus / OpenPhish (Fase 3 §9.2).
 *
 * Endpoint: `GET /api/surveillance/phishing-kits?domain=...`
 *
 * Backend pendiente. Sin endpoint disponible devuelve shape vacío. Cache: 15 min.
 */

import { useQuery } from "@tanstack/react-query";
import { STALE_TIME_MS } from "@/components/digital-surveillance/risk-engine/thresholds";
import type { SurveillancePhishingResult } from "@/types/digital-surveillance";

export const phishingKitsKey = (domain: string) =>
  ["surveillance-phishing-kits", domain] as const;

const emptyResult = (domain: string): SurveillancePhishingResult => ({
  domain,
  matches: [],
  fetchedAt: new Date().toISOString(),
  fromCache: false,
});

export function usePhishingKits(domain: string) {
  return useQuery({
    queryKey: phishingKitsKey(domain),
    enabled: domain.length > 0,
    staleTime: STALE_TIME_MS.phishingKits,
    queryFn: async (): Promise<SurveillancePhishingResult> => {
      try {
        const res = await fetch(
          `/api/surveillance/phishing-kits?domain=${encodeURIComponent(domain)}`,
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.ok === false) throw new Error(json.error ?? "Phishing kits error");
        return json as SurveillancePhishingResult;
      } catch (err) {
        if (import.meta.env.DEV) console.warn("[usePhishingKits]", err);
        return emptyResult(domain);
      }
    },
  });
}
