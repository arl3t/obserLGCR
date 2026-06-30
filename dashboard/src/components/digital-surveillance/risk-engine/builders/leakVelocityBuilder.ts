/**
 * leakVelocityBuilder — alerta cuando la tasa de aparición de credenciales
 * sube significativamente sobre baseline (Fase 3 §9.1).
 *
 * Reglas:
 *   - spikeRatio ≥ VELOCITY_SPIKE_CRITICAL → `critical`
 *   - spikeRatio ≥ VELOCITY_SPIKE_WARN     → `high`
 *   - Resto → no alerta
 *
 * Los datos vienen del hook `useLeakVelocity` que deriva del snapshot Leak
 * Intel Hub local (sin red). Si el backend expone luego un endpoint, este
 * builder no cambia.
 */

import {
  VELOCITY_SPIKE_CRITICAL,
  VELOCITY_SPIKE_WARN,
} from "@/components/digital-surveillance/risk-engine/thresholds";
import type {
  BrandThreat,
  LeakVelocityResult,
} from "@/types/digital-surveillance";

export function buildLeakVelocityThreats(
  velocity: LeakVelocityResult | undefined,
): BrandThreat[] {
  if (!velocity) return [];
  const ratio = velocity.spikeRatio;
  if (ratio < VELOCITY_SPIKE_WARN) return [];

  const severity = ratio >= VELOCITY_SPIKE_CRITICAL ? "critical" : "high";
  const ratioLabel = `${ratio.toFixed(1)}x baseline`;
  return [{
    id: `velocity-${velocity.computedAt}`,
    kind: "leak-velocity",
    severity,
    title: `Velocidad de fuga elevada: ${ratioLabel}`,
    detail:
      `${velocity.newCredsLast24h} cuenta(s) nuevas en 24h ` +
      `(baseline ${velocity.baseline24h.toFixed(1)}/24h · ` +
      `${velocity.newCredsLast7d} en 7d).`,
    target: velocity.domain,
    detectedAt: velocity.computedAt,
    source: "Leak Intel Hub (cliente)",
  }];
}
