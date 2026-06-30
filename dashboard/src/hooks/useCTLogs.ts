/**
 * useCTLogs — fetch del endpoint CT logs (Fase 3 §9.2).
 *
 * Endpoint: `GET /api/surveillance/ct-logs?domain=...`
 *
 * Backend pendiente (§9.7). Mientras no exista, el hook devuelve shape vacío
 * sin errar la UI — la columna "Impersonation" del strip pasa a estado
 * `inactive` y el feed DRP del tab Marca queda vacío.
 *
 * Cache: 5 min (`STALE_TIME_MS.ctLogs`).
 */

import { useQuery } from "@tanstack/react-query";
import { STALE_TIME_MS } from "@/components/digital-surveillance/risk-engine/thresholds";
import type { SurveillanceCTResult } from "@/types/digital-surveillance";

export const ctLogsKey = (domain: string) => ["surveillance-ct-logs", domain] as const;

const emptyResult = (domain: string): SurveillanceCTResult => ({
  domain,
  certificates: [],
  fetchedAt: new Date().toISOString(),
  fromCache: false,
});

export function useCTLogs(domain: string) {
  return useQuery({
    queryKey: ctLogsKey(domain),
    enabled: domain.length > 0,
    staleTime: STALE_TIME_MS.ctLogs,
    queryFn: async (): Promise<SurveillanceCTResult> => {
      try {
        const res = await fetch(
          `/api/surveillance/ct-logs?domain=${encodeURIComponent(domain)}`,
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.ok === false) throw new Error(json.error ?? "CT logs error");
        return json as SurveillanceCTResult;
      } catch (err) {
        if (import.meta.env.DEV) console.warn("[useCTLogs]", err);
        return emptyResult(domain);
      }
    },
  });
}
