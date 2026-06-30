/**
 * useEscapeKey.ts
 * Dispara un callback cuando el operador pulsa Escape a nivel de documento.
 * Pensado para cerrar modales/overlays sin forzar clicks en la X.
 *
 * Uso:
 *   useEscapeKey(onClose);          // siempre activo
 *   useEscapeKey(onClose, !busy);   // solo si no hay op en curso
 */
import { useEffect } from "react";

export function useEscapeKey(callback: () => void, enabled: boolean = true): void {
  useEffect(() => {
    if (!enabled) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        callback();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [callback, enabled]);
}
