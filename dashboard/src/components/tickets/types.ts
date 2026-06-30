/**
 * types.ts — Tipos del Sistema de Tickets Público (F3/F4).
 * Espejo de las filas que devuelve la API interna /api/tickets (snake_case crudo
 * de PG). Ver docs/PROPUESTA-TICKETING-PUBLICO.md y routes/tickets.mjs.
 */

export type TicketStatus =
  | "ABIERTO" | "EN_ATENCION" | "ESPERANDO_CLIENTE"
  | "RESUELTO" | "REABIERTO" | "CERRADO";

export type TicketPriority = "LOW" | "MEDIUM" | "HIGH" | "URGENT";
export type WaitingOn = "SOC" | "CLIENT" | "NONE";

// ── Clasificación / orden (bloque 20 mejoras) ────────────────────────────────
export type TicketType =
  | "INCIDENTE" | "CONSULTA" | "CAMBIO" | "REPORTE_FP" | "ACEPTACION_RIESGO";
export type TechnicalSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Sentiment = "POSITIVO" | "NEUTRAL" | "FRUSTRADO" | "ENOJADO";

export interface TicketService {
  id: string; name: string; slug: string; description?: string | null;
  color?: string | null; active: boolean; open_tickets?: number;
}
export interface AiSuggestion {
  type?: TicketType; priority?: TicketPriority; sentiment?: Sentiment;
  service_slug?: string; tags?: string[]; confidence?: number;
  summary?: string; source?: "llm" | "heuristic"; at?: string;
}
export interface TicketWatcher {
  operator_ci: string; operator_name?: string | null; added_at: string;
}
export interface SavedView {
  id: string; operator_ci: string; name: string;
  filters: Record<string, string>; sort: SortRule[]; is_shared: boolean; created_at: string;
}
export interface SortRule { col: string; dir: "asc" | "desc" }
export interface UserPrefs {
  operator_ci: string; sort: SortRule[]; default_view: string | null; layout: "table" | "kanban";
}
export interface TicketRuleCondition {
  type?: TicketType; priority?: TicketPriority; channel?: string;
  service_slug?: string; tag?: string; subject_contains?: string;
}
export interface TicketRuleAction {
  assign_tier?: string; assign_ci?: string; set_priority?: TicketPriority;
  add_tag?: string; set_type?: TicketType; notify_sm?: boolean;
}
export interface TicketRule {
  id: string; name: string; enabled: boolean; ordering: number;
  conditions: TicketRuleCondition; actions: TicketRuleAction;
  created_by?: string | null; created_at: string;
}
export interface TagCount { tag: string; n: number }
// Config de SLA de comunicación (singleton): frt_urgent_sec, nrt_high_sec, etc.
export type CommSlaConfig = Record<string, number | boolean | string>;
export type AuthorType = "CLIENT" | "SOC" | "SYSTEM";
export type Visibility = "PUBLIC" | "INTERNAL";

export type ActionType =
  | "CONTENCION_FIREWALL" | "AISLAR_HOST" | "BLOQUEO_IOC" | "RESET_CREDENCIALES"
  | "APLICAR_PARCHE" | "DESHABILITAR_CUENTA" | "DESHABILITAR_SERVICIO" | "OTRO";

export type ActionStatus =
  | "PENDIENTE" | "EJECUTADA" | "RECHAZADA"
  | "RIESGO_ACEPTADO" | "DIFERIDA" | "CANCELADA";

export interface TicketRow {
  id: string;
  public_ref: string;
  org_id: string;
  org_slug?: string;
  org_name?: string;
  /** Contacto del cliente que abrió/atiende el ticket. JSONB en PG ({name?, email?}),
   *  default '{}'. NUNCA renderizar el objeto directo (React error #31). */
  requester_contact?: { name?: string | null; email?: string | null } | null;
  subject: string;
  status: TicketStatus;
  priority: TicketPriority;
  channel: string;
  waiting_on: WaitingOn;
  assigned_operator: string | null;
  assigned_operator_name?: string | null;
  reopened_count: number;
  created_at: string;
  updated_at: string;
  first_response_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  primary_case_id?: string | null;
  public_msgs?: number | string;
  // Clasificación / orden (mig 111):
  ticket_type: TicketType;
  technical_severity?: TechnicalSeverity | null;
  service_id?: string | null;
  service_slug?: string | null;
  service_name?: string | null;
  tags: string[];
  sentiment?: Sentiment | null;
  ai_suggested?: AiSuggestion | null;
  pinned: boolean;
  snoozed_until?: string | null;
  merged_into?: string | null;
  cc_contacts?: Array<string | { email: string; name?: string }>;
  watcher_count?: number | string;
  // Mensajes nuevos del cliente sin leer por el SOC (mig 113 · soc_last_read_at).
  unread_client?: number | string;
  // Cierre pendiente de confirmación del cliente (mig 114 · sign-off #23).
  closure_requested_at?: string | null;
}

export interface TicketMessage {
  id: string;
  author_type: AuthorType;
  author_ref: string | null;
  /** Nombre humano resuelto del autor (analista SOC ↔ contacto del cliente).
   *  Backend lo computa en getTicket; fallback al author_ref/etiqueta genérica. */
  author_name?: string | null;
  visibility: Visibility;
  body: string;
  attachments: unknown[];
  is_first_response: boolean;
  turnaround_seconds: number | null;
  created_at: string;
  has_report?: boolean;
  has_playbook?: boolean;
}

export interface TicketCaseLink {
  case_id: string;
  link_type: "PRIMARY" | "RELATED";
  linked_by: string | null;
  linked_at: string;
}

export interface ActionRequest {
  id: string;
  ticket_id: string;
  case_id: string | null;
  requested_by: string;
  action_type: ActionType;
  title: string;
  rationale: string;
  recommended_steps: string | null;
  urgency: TicketPriority;
  due_at: string | null;
  status: ActionStatus;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  risk_accepted_by: string | null;
  risk_acceptance_scope: string | null;
  risk_review_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TicketDetail extends TicketRow {
  messages: TicketMessage[];
  links: TicketCaseLink[];
  actionRequests: ActionRequest[];
  watchers: TicketWatcher[];
}

export interface CommMetrics {
  tickets: number | string;
  open_tickets: number | string;
  waiting_on_soc: number | string;
  waiting_on_client: number | string;
  frt_avg_sec: number | string | null;
  res_avg_sec: number | string | null;
  reopens: number | string | null;
  nrt_avg_sec: number | string | null;
  crt_avg_sec: number | string | null;
  round_trips_avg: number | string | null;
  csat_avg: number | string | null;
  csat_count: number | string | null;
}

export interface TicketTemplate {
  id: string;
  title: string;
  body: string;
  category: string | null;
}

export interface ActionMetrics {
  total: number | string;
  pending: number | string;
  executed: number | string;
  risk_accepted: number | string;
  rejected: number | string;
  overdue: number | string;
  ttd_avg_sec: number | string | null;
}

// ── Etiquetas en español (no hay i18n; convención del repo) ──────────────────
export const STATUS_LABEL: Record<TicketStatus, string> = {
  ABIERTO: "Abierto", EN_ATENCION: "En atención", ESPERANDO_CLIENTE: "Esperando cliente",
  RESUELTO: "Resuelto", REABIERTO: "Reabierto", CERRADO: "Cerrado",
};

export const WAITING_LABEL: Record<WaitingOn, string> = {
  SOC: "Espera SOC", CLIENT: "Espera cliente", NONE: "—",
};

export const PRIORITY_LABEL: Record<TicketPriority, string> = {
  URGENT: "Urgente", HIGH: "Alta", MEDIUM: "Media", LOW: "Baja",
};

export const ACTION_TYPE_LABEL: Record<ActionType, string> = {
  CONTENCION_FIREWALL: "Contención en firewall", AISLAR_HOST: "Aislar host",
  BLOQUEO_IOC: "Bloquear IOC", RESET_CREDENCIALES: "Resetear credenciales",
  APLICAR_PARCHE: "Aplicar parche", DESHABILITAR_CUENTA: "Deshabilitar cuenta",
  DESHABILITAR_SERVICIO: "Deshabilitar servicio", OTRO: "Otro",
};

export const ACTION_STATUS_LABEL: Record<ActionStatus, string> = {
  PENDIENTE: "Pendiente", EJECUTADA: "Ejecutada", RECHAZADA: "Rechazada",
  RIESGO_ACEPTADO: "Riesgo aceptado", DIFERIDA: "Diferida", CANCELADA: "Cancelada",
};

export const TYPE_LABEL: Record<TicketType, string> = {
  INCIDENTE: "Incidente", CONSULTA: "Consulta", CAMBIO: "Cambio",
  REPORTE_FP: "Reporte FP", ACEPTACION_RIESGO: "Aceptación de riesgo",
};
export const TYPE_COLOR: Record<TicketType, string> = {
  INCIDENTE: "#ef4444", CONSULTA: "#38bdf8", CAMBIO: "#a78bfa",
  REPORTE_FP: "#f59e0b", ACEPTACION_RIESGO: "#ec4899",
};
export const TECH_SEVERITY_LABEL: Record<TechnicalSeverity, string> = {
  LOW: "Baja", MEDIUM: "Media", HIGH: "Alta", CRITICAL: "Crítica",
};
export const TECH_SEVERITY_COLOR: Record<TechnicalSeverity, string> = {
  LOW: "#10b981", MEDIUM: "#f59e0b", HIGH: "#f97316", CRITICAL: "#ef4444",
};
export const SENTIMENT_LABEL: Record<Sentiment, string> = {
  POSITIVO: "Positivo", NEUTRAL: "Neutral", FRUSTRADO: "Frustrado", ENOJADO: "Enojado",
};
export const SENTIMENT_EMOJI: Record<Sentiment, string> = {
  POSITIVO: "🙂", NEUTRAL: "😐", FRUSTRADO: "😟", ENOJADO: "😠",
};
export const CHANNEL_LABEL: Record<string, string> = {
  PORTAL: "Portal", EMAIL: "Email", API: "API", SOC_INITIATED: "SOC",
};
