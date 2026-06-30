import { clamp } from "lodash";
import type { SeverityThresholds } from "@/hooks/useSocThresholds";
import { DEFAULT_SEVERITY_THRESHOLDS } from "@/hooks/useSocThresholds";

export type SeverityLabel = "low" | "medium" | "high" | "critical";

/**
 * Heurística 0–100 para el "Risk Score" global del Centro de Mando.
 * Combina volumen de bloqueos, IPs distintas y alertas críticas Wazuh.
 * Ajusta pesos según tu entorno (documentado para tuning posterior).
 */
export function computeRiskScore(input: {
  blocks24h: number;
  uniqueBlockedIps24h: number;
  wazuhCritical24h: number;
}): number {
  const b = Math.min(input.blocks24h / 5000, 1) * 35;
  const u = Math.min(input.uniqueBlockedIps24h / 200, 1) * 35;
  const w = Math.min(input.wazuhCritical24h / 50, 1) * 30;
  return Math.round(clamp(b + u + w, 0, 100));
}

/**
 * Clasifica un score 0-100 en CRITICAL/HIGH/MEDIUM/LOW usando los umbrales
 * publicados por la fórmula activa. Pasar `thresholds` desde `useSocThresholds`
 * para que el frontend siga al backend; sin argumento usa los defaults
 * históricos (sólo para callers sync donde el hook no es viable).
 */
export function severityFromScore(
  score: number,
  thresholds: SeverityThresholds = DEFAULT_SEVERITY_THRESHOLDS,
): SeverityLabel {
  if (score >= thresholds.critical) return "critical";
  if (score >= thresholds.high)     return "high";
  if (score >= thresholds.medium)   return "medium";
  return "low";
}
