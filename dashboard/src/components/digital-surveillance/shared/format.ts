/**
 * Formateo numérico compacto para KPIs y tablas — el módulo Vigilancia muestra
 * volúmenes muy variables (10 menciones vs 2.5M de reach), así que ahorramos
 * caracteres en la UI mientras mantenemos legibilidad.
 *
 * Convención: 1.234 → "1.2K", 1_500_000 → "1.5M", NaN/Infinity → "—".
 */

export function formatCompactNumber(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(Math.round(n));
}
