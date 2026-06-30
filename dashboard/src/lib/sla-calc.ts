/**
 * sla-calc.ts — Utilidades compartidas para cálculo de SLA de incidentes.
 *
 * Centraliza la lógica de SLA para evitar duplicación en CaseRow,
 * SlaBar (legacy), y cualquier futuro componente que necesite mostrar
 * el estado del SLA de un caso.
 */

/** Calcula el porcentaje de SLA consumido (0–100). Devuelve null si no hay fecha. */
export function calcSlaPct(
  detectedAt: string | null | undefined,
  slaSec: number,
): number | null {
  if (!detectedAt || slaSec <= 0) return null;
  const elapsedSec = (Date.now() - new Date(detectedAt).getTime()) / 1000;
  return Math.min(100, Math.round((elapsedSec / slaSec) * 100));
}

/** Color semafórico según porcentaje de SLA consumido. */
export function slaColor(pct: number): string {
  if (pct >= 90) return "#ff3b5c";
  if (pct >= 70) return "#ff9500";
  return "#22c55e";
}

/** Tiempo relativo en español ("hace Xm / Xh / Xd"). */
export function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const min  = Math.floor(diff / 60_000);
  if (min < 60)  return `hace ${min}m`;
  const h = Math.floor(min / 60);
  if (h < 24)    return `hace ${h}h`;
  return `hace ${Math.floor(h / 24)}d`;
}

/** Formatea una duración en ms como "Xh Ym" o "Xm". */
export function fmtDuration(ms: number): string {
  const min = Math.floor(ms / 60_000);
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  if (h < 24)   return `${h}h ${min % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/**
 * Tiempo restante de SLA, formateado para la columna de la lista.
 * Devuelve:
 *  - "12m"            → si falta >= 1h (compacto: horas y minutos)
 *  - "12:45"          → si falta < 1h (mm:ss, countdown útil para CRITICAL)
 *  - "−3m" o "−1h"    → breach, con signo negativo
 *  - null             → si no hay detectedAt o slaSec inválido
 */
export function formatSlaRemaining(
  detectedAt: string | null | undefined,
  slaSec: number,
): string | null {
  if (!detectedAt || slaSec <= 0) return null;
  const elapsed = (Date.now() - new Date(detectedAt).getTime()) / 1000;
  const remaining = slaSec - elapsed;
  const abs = Math.abs(remaining);
  const h = Math.floor(abs / 3600);
  const m = Math.floor((abs % 3600) / 60);
  const s = Math.floor(abs % 60);
  const sign = remaining < 0 ? "−" : "";
  if (h > 0) return `${sign}${h}h ${String(m).padStart(2, "0")}m`;
  return `${sign}${m}:${String(s).padStart(2, "0")}`;
}
