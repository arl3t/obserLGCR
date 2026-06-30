/**
 * useLeakVelocity — deriva velocidad de fuga del snapshot Leak Intel Hub local.
 *
 * No hace fetch. Calcula `newCredsLast24h` y `newCredsLast7d` comparando el
 * snapshot actual contra una baseline aproximada (promedio de 24h en los
 * últimos 30 días). Cuando exista endpoint backend con histórico real, este
 * hook se reemplaza sin que los consumidores cambien.
 *
 * Limitación v1: el snapshot no tiene serie temporal, así que `newCredsLast24h`
 * y `newCredsLast7d` quedan en 0 hasta que el backend exponga histórico
 * (`GET /api/surveillance/leak-velocity` — §9.7). Esto significa que el
 * factor "leak velocity" no se dispara en el feed con datos reales actuales.
 *
 * IMPORTANTE (fix React #185, 2026-05-08): el `useMemo` depende de PRIMITIVOS
 * extraídos del snapshot (no del objeto snapshot completo). Esto evita
 * recompute cuando el store de Zustand re-emite el mismo snapshot con nueva
 * identidad de objeto.
 */

import { useMemo } from "react";
import { useLeakIntelHubStore } from "@/store/leak-intel-hub-store";
import type { LeakVelocityResult } from "@/types/digital-surveillance";

export function useLeakVelocity(domain: string): LeakVelocityResult | null {
  const leaksLast12Months = useLeakIntelHubStore((s) => s.snapshot?.leaksLast12Months ?? 0);
  const hasSnapshot       = useLeakIntelHubStore((s) => s.snapshot != null);

  return useMemo(() => {
    if (!domain || !hasSnapshot) return null;

    const baseline24h = leaksLast12Months / 365;

    return {
      domain,
      newCredsLast24h: 0,   // sin serie temporal en cliente
      newCredsLast7d: 0,
      baseline24h,
      spikeRatio: 0,
      // `computedAt` constante — la velocity actual es función pura de
      // (domain, leaksLast12Months). Mientras esos no cambien, mismo objeto.
      computedAt: "",
    };
  }, [domain, hasSnapshot, leaksLast12Months]);
}
