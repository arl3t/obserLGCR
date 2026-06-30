/**
 * Estilos por banda de riesgo — clases Tailwind canónicas para los 3 niveles.
 *
 * `bandBadge` viste un `<Badge variant="outline">` (border + bg suave + texto
 * con suficiente contraste en light/dark). `bandBorder` se usa como tarjeta
 * con `border-l-4` que comunica la severidad sin dominar el layout.
 *
 * Los consumen TabAnalisis (vía port-band), TabBrand (alertas con SOC), el
 * monolito (TabReporte, RiskFactor cards) y futuros tabs.
 */

import type { RiskBand } from "@/types/digital-surveillance";

export const bandBadge: Record<RiskBand, string> = {
  high:   "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-400",
  low:    "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-400",
};

export const bandBorder: Record<RiskBand, string> = {
  high:   "border-l-red-500 bg-red-500/[0.04]",
  medium: "border-l-amber-500 bg-amber-500/[0.04]",
  low:    "border-l-emerald-600 bg-emerald-600/[0.03]",
};
