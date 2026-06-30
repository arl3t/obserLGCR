/**
 * ticket-format.ts — helpers de presentación del Sistema de Tickets.
 */
import { C } from "@/lib/cm-theme";
import type { TicketPriority, TicketStatus, WaitingOn, ActionStatus } from "@/components/tickets/types";
import type { SlaKind } from "@/components/tickets/ticket-sla";

/** Segundos → duración legible (es). Acepta number|string|null de PG. */
export function fmtDuration(sec: number | string | null | undefined): string {
  if (sec == null) return "—";
  const s = Number(sec);
  if (!Number.isFinite(s) || s < 0) return "—";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86400).toFixed(1)}d`;
}

/** Number() defensivo para agregados que PG devuelve como string. */
export function num(v: number | string | null | undefined): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

export const PRIORITY_COLOR: Record<TicketPriority, string> = {
  URGENT: C.red, HIGH: C.orange, MEDIUM: C.cyan, LOW: C.green,
};

export const STATUS_COLOR: Record<TicketStatus, string> = {
  ABIERTO: C.blue, EN_ATENCION: C.cyan, ESPERANDO_CLIENTE: C.orange,
  RESUELTO: C.green, REABIERTO: C.purple, CERRADO: C.textDim,
};

export const WAITING_COLOR: Record<WaitingOn, string> = {
  SOC: C.orange, CLIENT: C.blue, NONE: C.textDim,
};

export const ACTION_STATUS_COLOR: Record<ActionStatus, string> = {
  PENDIENTE: C.orange, EJECUTADA: C.green, RECHAZADA: C.red,
  RIESGO_ACEPTADO: C.purple, DIFERIDA: C.cyan, CANCELADA: C.textDim,
};

// ── Paleta SLA centralizada (#7) ───────────────────────────────────────────────
// Antes vivía duplicada con hex crudos en TicketsPage y TicketKanban. Unificada
// acá sobre los tokens de tema (C.*) para coherencia claro/oscuro.
export const SLA_COLOR: Record<SlaKind, string> = {
  ok: C.green, warn: C.orange, breach: C.red, client: C.textDim, done: C.textDim,
};
/** Tinte de fondo de fila por estado de SLA (clases Tailwind). */
export const SLA_ROW_BG: Record<SlaKind, string> = {
  breach: "bg-red-500/[0.07]", warn: "bg-amber-500/[0.07]", ok: "", client: "", done: "opacity-60",
};
/** Color del acento (borde-izq) de fila/tarjeta por SLA. Vencido/por-vencer
 *  resaltan; en tiempo y sin-reloj quedan neutros para no saturar. */
export function slaAccent(kind: SlaKind): string {
  return kind === "breach" ? C.red : kind === "warn" ? C.orange : "transparent";
}
