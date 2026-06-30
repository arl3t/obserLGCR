/**
 * useViewport — hook reactivo de breakpoints del SOC.
 *
 * Breakpoints (consistentes con docs/SOC-UX-BACKLOG.md — bloque C4):
 *   desktop  ≥ 1200
 *   tablet   800–1199
 *   mobile   < 800
 *
 * Implementación: matchMedia con listeners ligeros (sin resize spam). SSR-safe:
 * en entornos donde `window` no existe (build estático) devuelve desktop por
 * defecto.
 *
 * El hook re-renderiza solo cuando se cruza un breakpoint — no en cada
 * cambio de píxel del viewport. Suficiente para layout responsive y libre
 * de jank.
 */

import { useEffect, useState } from "react";

export interface Viewport {
  isMobile:  boolean;
  isTablet:  boolean;
  isDesktop: boolean;
  /** Ancho actual en píxeles. Snapshot en el momento de re-render. */
  width:     number;
}

const MOBILE_MAX  = 799;
const TABLET_MAX  = 1199;

function computeViewport(): Viewport {
  if (typeof window === "undefined") {
    return { isMobile: false, isTablet: false, isDesktop: true, width: 1920 };
  }
  const w = window.innerWidth;
  return {
    isMobile:  w <= MOBILE_MAX,
    isTablet:  w > MOBILE_MAX && w <= TABLET_MAX,
    isDesktop: w > TABLET_MAX,
    width:     w,
  };
}

export function useViewport(): Viewport {
  const [vp, setVp] = useState<Viewport>(computeViewport);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const mqMobile = window.matchMedia(`(max-width: ${MOBILE_MAX}px)`);
    const mqTablet = window.matchMedia(`(min-width: ${MOBILE_MAX + 1}px) and (max-width: ${TABLET_MAX}px)`);
    const recompute = () => setVp(computeViewport());
    mqMobile.addEventListener("change", recompute);
    mqTablet.addEventListener("change", recompute);
    // Sincronizar en el primer mount por si computeViewport corrió en SSR.
    recompute();
    return () => {
      mqMobile.removeEventListener("change", recompute);
      mqTablet.removeEventListener("change", recompute);
    };
  }, []);

  return vp;
}
