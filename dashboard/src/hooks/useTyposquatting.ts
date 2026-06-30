/**
 * useTyposquatting — fetch del endpoint dnstwist (Fase 3 §9.2).
 *
 * Endpoint: `GET /api/surveillance/typosquatting?domain=...`
 *
 * Backend pendiente. Sin endpoint disponible devuelve shape vacío. Cache: 1h.
 */

import { useQuery } from "@tanstack/react-query";
import { STALE_TIME_MS } from "@/components/digital-surveillance/risk-engine/thresholds";
import type { SurveillanceTypoResult } from "@/types/digital-surveillance";

export const typoKey = (domain: string) =>
  ["surveillance-typosquatting", domain] as const;

const emptyResult = (domain: string): SurveillanceTypoResult => ({
  domain,
  candidates: [],
  fetchedAt: new Date().toISOString(),
  fromCache: false,
});

export function useTyposquatting(domain: string) {
  return useQuery({
    queryKey: typoKey(domain),
    enabled: domain.length > 0,
    staleTime: STALE_TIME_MS.typosquatting,
    queryFn: async (): Promise<SurveillanceTypoResult> => {
      try {
        const res = await fetch(
          `/api/surveillance/typosquatting?domain=${encodeURIComponent(domain)}`,
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.ok === false) throw new Error(json.error ?? "Typo error");
        return json as SurveillanceTypoResult;
      } catch (err) {
        if (import.meta.env.DEV) console.warn("[useTyposquatting]", err);
        return emptyResult(domain);
      }
    },
  });
}
