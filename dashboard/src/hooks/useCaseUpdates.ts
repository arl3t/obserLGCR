/**
 * useCaseUpdates.ts — Escucha eventos Socket.io de casos SOC en tiempo real.
 *
 * Cuando otro operador adopta, cambia estado o escala un caso, llama a `onUpdate`
 * para que el componente padre haga refetch. Gestiona conexión/desconexión del socket
 * de forma limpia en el ciclo de vida del componente.
 *
 * Uso:
 *   useCaseUpdates(refetch);  // refetch = función del hook useCaseManagement
 */

import { useCallback, useEffect } from "react";
import { socket } from "@/lib/socket";

const CASE_EVENTS = [
  "case:adopted",
  "case:status-changed",
  "case:escalated",
  "case:created",
  "new-critical-incident",
] as const;

/**
 * @param onUpdate  Función llamada cuando llega cualquier evento de caso.
 *                  Debe ser estable (useCallback) para no re-conectar en cada render.
 */
export function useCaseUpdates(onUpdate: () => void): void {
  const stableUpdate = useCallback(onUpdate, [onUpdate]);

  useEffect(() => {
    socket.connect();

    CASE_EVENTS.forEach((ev) => socket.on(ev, stableUpdate));

    return () => {
      CASE_EVENTS.forEach((ev) => socket.off(ev, stableUpdate));
      // No desconectar el singleton global; otros hooks pueden estar usándolo.
    };
  }, [stableUpdate]);
}
