/**
 * Tema compartido para componentes de Case Management que usan inline styles.
 *
 * `C` resuelve a CSS variables `--cm-*` definidas en `index.css`, que cambian
 * automáticamente con el tema activo (light, dark, nexus-dark, cyber-tactical).
 *
 * `alpha(color, pct)` produce un `color-mix(in srgb, …)` válido sobre CSS vars.
 * Necesario porque `${C.cyan}30` (alpha-hex concatenado) sólo funciona con hex
 * literales — al usar `var()` el navegador descarta la declaración.
 *
 * Mapeo de roles:
 *   red      → critical / SLA vencido / errores
 *   orange   → escalado / pendiente / warning ámbar
 *   green    → resuelto / FP / éxito
 *   blue     → primary / L1 / sidebar activo
 *   cyan     → secundario / L1L2 / "mis casos"
 *   purple   → L2 / archivado
 *   info     → monitoreado (alias de cyan)
 *   neutral  → auto-cerrado / cerrado (alias de purple)
 *   text     → texto principal
 *   textDim  → texto secundario / muted
 *   bg/card  → fondos principal y de tarjetas
 *   border   → bordes default
 */
export const C = {
  bg:      "var(--cm-bg)",
  card:    "var(--cm-card)",
  border:  "var(--cm-border)",
  text:    "var(--cm-text)",
  textDim: "var(--cm-text-dim)",
  red:     "var(--cm-red)",
  orange:  "var(--cm-orange)",
  cyan:    "var(--cm-cyan)",
  green:   "var(--cm-green)",
  blue:    "var(--cm-blue)",
  purple:  "var(--cm-purple)",
  info:    "var(--cm-info)",
  neutral: "var(--cm-neutral)",
};

/** Mezcla un color con transparente usando `color-mix(in srgb, …)`. Reemplaza
 *  el patrón `${C.x}NN` (alpha-hex) que sólo funciona con hex literales — al
 *  usar CSS vars el navegador descarta la declaración entera.
 *
 *  pct: porcentaje de opacidad del color base (0–100).
 *  Ejemplos:
 *    alpha(C.red, 5)   → ~5% rose → bg suave de fila crítica (light: #fff1f2-ish)
 *    alpha(C.cyan, 22) → chip bg con saturación moderada
 *    alpha(C.text, 4)  → hover tint adaptativo (oscurece en claro, aclara en oscuro)
 */
export const alpha = (c: string, pct: number) =>
  `color-mix(in srgb, ${c} ${pct}%, transparent)`;
