/**
 * ticket-sla.ts — cálculo del estado de SLA de comunicación de un ticket y el
 * orden profesional de la cola (por apertura / SLA con cuenta regresiva).
 *
 * El reloj corre del lado del SOC: si el ticket aún no tuvo primera respuesta se
 * mide FRT (desde la apertura); si ya respondimos y la pelota volvió al SOC se mide
 * NRT (desde la última actualización). Si la pelota la tiene el cliente o el ticket
 * está cerrado/resuelto, no hay cuenta regresiva contra el SOC.
 */
import type { TicketRow, TicketPriority, CommSlaConfig, SortRule } from "./types";

export type SlaKind = "ok" | "warn" | "breach" | "client" | "done";

export interface SlaState {
  kind: SlaKind;
  remainingSec: number | null;   // >0 quedan; <0 vencido; null no aplica
  pct: number;                    // fracción consumida 0..>1
  metric: "FRT" | "NRT" | null;
  label: string;
}

const PRIORITY_WEIGHT: Record<TicketPriority, number> = { URGENT: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const TERMINAL = new Set(["RESUELTO", "CERRADO"]);

function slaSec(cfg: CommSlaConfig | null, metric: "frt" | "nrt", priority: TicketPriority): number {
  const k = `${metric}_${priority.toLowerCase()}_sec`;
  const v = cfg ? Number(cfg[k]) : NaN;
  if (Number.isFinite(v) && v > 0) return v;
  // Defaults (espejo de migración 102) por si la config no cargó.
  const DEF: Record<string, number> = {
    frt_urgent_sec: 1800, frt_high_sec: 7200, frt_medium_sec: 28800, frt_low_sec: 86400,
    nrt_urgent_sec: 3600, nrt_high_sec: 14400, nrt_medium_sec: 86400, nrt_low_sec: 172800,
  };
  return DEF[k] ?? 28800;
}

export function computeSla(t: TicketRow, cfg: CommSlaConfig | null, nowMs: number): SlaState {
  if (TERMINAL.has(t.status)) return { kind: "done", remainingSec: null, pct: 0, metric: null, label: "—" };
  if (t.waiting_on !== "SOC") return { kind: "client", remainingSec: null, pct: 0, metric: null, label: "Espera cliente" };

  const isFrt = !t.first_response_at;
  const metric: "FRT" | "NRT" = isFrt ? "FRT" : "NRT";
  const limit = slaSec(cfg, isFrt ? "frt" : "nrt", t.priority);
  const anchorMs = new Date(isFrt ? t.created_at : t.updated_at).getTime();
  const elapsed = Math.max(0, (nowMs - anchorMs) / 1000);
  const remaining = Math.round(limit - elapsed);
  const pct = elapsed / limit;
  const kind: SlaKind = remaining <= 0 ? "breach" : pct >= 0.75 ? "warn" : "ok";
  return { kind, remainingSec: remaining, pct, metric, label: metric };
}

// Cuenta regresiva legible: "2h 05m", "12m", o "vencido 8m".
export function fmtCountdown(remainingSec: number | null): string {
  if (remainingSec == null) return "—";
  const overdue = remainingSec < 0;
  let s = Math.abs(remainingSec);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60);
  let body: string;
  if (d > 0) body = `${d}d ${h}h`;
  else if (h > 0) body = `${h}h ${String(m).padStart(2, "0")}m`;
  else body = `${m}m`;
  return overdue ? `vencido ${body}` : body;
}

// Orden profesional de la cola: activos primero, con la pelota del SOC arriba,
// ordenados por urgencia de SLA (vencidos primero), luego prioridad, luego apertura.
export function compareTickets(
  a: TicketRow, b: TicketRow,
  slaOf: (t: TicketRow) => SlaState,
): number {
  const aTerm = TERMINAL.has(a.status) ? 1 : 0;
  const bTerm = TERMINAL.has(b.status) ? 1 : 0;
  if (aTerm !== bTerm) return aTerm - bTerm;                       // terminales al final

  const sa = slaOf(a), sb = slaOf(b);
  const aSoc = a.waiting_on === "SOC" ? 0 : 1;
  const bSoc = b.waiting_on === "SOC" ? 0 : 1;
  if (aSoc !== bSoc) return aSoc - bSoc;                           // pelota del SOC arriba

  if (aSoc === 0) {
    // Ambos con reloj del SOC: el de menor tiempo restante primero (vencidos = negativos).
    const ra = sa.remainingSec ?? Infinity, rb = sb.remainingSec ?? Infinity;
    if (ra !== rb) return ra - rb;
  }
  // Desempate: prioridad desc, luego apertura asc.
  const pw = (PRIORITY_WEIGHT[b.priority] ?? 0) - (PRIORITY_WEIGHT[a.priority] ?? 0);
  if (pw !== 0) return pw;
  return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
}

// ── (#9) Score de cola inteligente ────────────────────────────────────────────
// Número ordenable que combina: urgencia de SLA (incl. vencidos) + prioridad +
// antigüedad + reaperturas. Más alto = atender antes. Los pins/terminales los
// maneja el orden de la cola, no el score.
export function queueScore(t: TicketRow, sla: SlaState): number {
  let score = 0;
  // SLA: vencido pesa muchísimo; por-vencer escala con el % consumido.
  if (sla.kind === "breach") score += 1000 + Math.min(1000, Math.abs(sla.remainingSec ?? 0) / 60);
  else if (sla.metric) score += Math.min(600, sla.pct * 600);
  else if (sla.kind === "client") score += 0;            // pelota del cliente: no corre contra el SOC
  // Prioridad.
  score += (PRIORITY_WEIGHT[t.priority] ?? 1) * 50;
  // Antigüedad (horas, tope 7 días).
  const ageH = Math.min(168, (Date.now() - new Date(t.created_at).getTime()) / 3.6e6);
  score += ageH * 2;
  // Reaperturas (fricción): cada reapertura suma.
  score += (Number(t.reopened_count) || 0) * 40;
  return Math.round(score);
}

// ── (#15) Bucket por SLA ───────────────────────────────────────────────────────
export type SlaBucket = "breach" | "soon" | "ontime" | "other";
export const SLA_BUCKET_LABEL: Record<SlaBucket, string> = {
  breach: "Vencidos", soon: "Por vencer (<1h)", ontime: "En tiempo", other: "Sin reloj SOC",
};
export function slaBucket(sla: SlaState): SlaBucket {
  if (sla.kind === "breach") return "breach";
  if (sla.metric && sla.remainingSec != null && sla.remainingSec <= 3600) return "soon";
  if (sla.metric) return "ontime";
  return "other";
}

// ── (#12) Orden multi-columna configurable ────────────────────────────────────
// Devuelve un comparador a partir de una lista de reglas {col,dir}. Las columnas
// soportadas mapean a campos de TicketRow / score derivado.
export function makeMultiSort(
  rules: SortRule[],
  slaOf: (t: TicketRow) => SlaState,
): (a: TicketRow, b: TicketRow) => number {
  const val = (t: TicketRow, col: string): number | string => {
    switch (col) {
      case "priority": return PRIORITY_WEIGHT[t.priority] ?? 0;
      case "created_at": return new Date(t.created_at).getTime();
      case "updated_at": return new Date(t.updated_at).getTime();
      case "sla": { const s = slaOf(t); return s.remainingSec ?? Infinity; }
      case "score": return queueScore(t, slaOf(t));
      case "status": return t.status;
      case "subject": return t.subject.toLowerCase();
      case "reopened": return Number(t.reopened_count) || 0;
      default: return 0;
    }
  };
  return (a, b) => {
    for (const r of rules) {
      const va = val(a, r.col), vb = val(b, r.col);
      let cmp = 0;
      if (typeof va === "string" || typeof vb === "string") cmp = String(va).localeCompare(String(vb));
      else cmp = (va as number) - (vb as number);
      if (cmp !== 0) return r.dir === "desc" ? -cmp : cmp;
    }
    return 0;
  };
}
