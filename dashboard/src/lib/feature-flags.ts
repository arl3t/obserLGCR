/**
 * feature-flags.ts — flags de funcionalidad del dashboard, leídos de las VITE_*
 * en build (Vite inyecta import.meta.env en el bundle). Convención: el valor es
 * la cadena "true" para activar; cualquier otra cosa (vacío/ausente) = apagado.
 *
 * Para activar una flag hay que (1) poner VITE_<FLAG>=true en el .env del
 * dashboard y (2) reconstruir el bundle con `docker compose build` (un build a
 * secas pierde los VITE_* — ver memoria dashboard-build-oidc-args).
 */
function flag(v: unknown): boolean {
  return String(v ?? "").trim().toLowerCase() === "true";
}

/**
 * Asistente de Tickets — launcher flotante (copiloto de triage). Apagado por
 * defecto; es una capa fina sobre /api/tickets, no sustituye la página /tickets.
 */
export const FEATURE_TICKET_ASSISTANT = flag(import.meta.env.VITE_ASISTENTE_TICKETS);
