import { clamp } from "lodash";

/** Reputación heurística para UI (no es TI comercial). */
export function perimeterReputationFromHits(hits: number): {
  label: string;
  tone: "ok" | "warn" | "bad";
} {
  if (hits >= 500) return { label: "Muy agresiva", tone: "bad" };
  if (hits >= 120) return { label: "Sospechosa", tone: "warn" };
  if (hits >= 40) return { label: "Elevada", tone: "warn" };
  return { label: "Ruido / escaneo", tone: "ok" };
}

export function ipRiskFromHits(hits: number): number {
  return Math.round(clamp(Math.log10(hits + 1) * 28, 0, 100));
}
