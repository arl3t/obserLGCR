/**
 * useSurveillancePrefetch — prefetch del snapshot principal de Vigilancia
 * para reducir TTFB cuando el operador hace hover o blur sobre un dominio.
 *
 * Idea:
 *   - Watchlist row → onMouseEnter dispara prefetch en background.
 *   - SearchBar input → onBlur con dominio válido dispara prefetch.
 *   - Configured chip → onMouseEnter / onFocus también prefetcha.
 *
 * react-query deduplica si la query ya está en cache; staleTime grande en
 * `fetchSurveillanceDomain` la mantiene caliente para el siguiente render.
 */

import { useQueryClient } from "@tanstack/react-query";
import { useCallback } from "react";
import { surveillanceQueryKey } from "@/hooks/useDigitalSurveillance";
import {
  fetchSurveillanceDomain,
  normalizeSurveillanceDomain,
} from "@/lib/digital-surveillance-api";

const PREFETCH_STALE_MS = 5 * 60 * 1000; // 5 min — no re-pegar al backend si caliente

export function useSurveillancePrefetch() {
  const qc = useQueryClient();

  return useCallback(
    (rawDomain: string | null | undefined) => {
      if (!rawDomain) return;
      const d = normalizeSurveillanceDomain(rawDomain.trim());
      if (!d || d.length < 3) return;
      void qc.prefetchQuery({
        queryKey: surveillanceQueryKey(d),
        queryFn: () => fetchSurveillanceDomain(d),
        staleTime: PREFETCH_STALE_MS,
      });
    },
    [qc],
  );
}
