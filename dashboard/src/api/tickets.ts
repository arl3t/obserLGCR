/**
 * tickets.ts — Cliente API tipado del Sistema de Tickets Público (superficie
 * interna, /api/tickets). Ver routes/tickets.mjs §8.1.
 */
import { api } from "@/api/client";
import type {
  TicketRow, TicketDetail, ActionRequest, CommMetrics, ActionMetrics,
  TicketStatus, TicketPriority, Visibility, ActionType, CommSlaConfig,
  TicketType, TechnicalSeverity, TicketService, AiSuggestion, SavedView,
  SortRule, UserPrefs, TicketRule, TicketRuleCondition, TicketRuleAction, TagCount,
} from "@/components/tickets/types";

export interface TicketFilters {
  status?: TicketStatus | "";
  waitingOn?: "SOC" | "CLIENT" | "NONE" | "";
  operator?: string;
  org?: string;
  limit?: number;
  type?: TicketType | "";
  tag?: string;
  service?: string;
  mine?: boolean;
  pinned?: boolean;
  includeSnoozed?: boolean;
}

export async function listTickets(f: TicketFilters = {}): Promise<TicketRow[]> {
  const p = new URLSearchParams();
  if (f.status) p.set("status", f.status);
  if (f.waitingOn) p.set("waitingOn", f.waitingOn);
  if (f.operator) p.set("operator", f.operator);
  if (f.org) p.set("org", f.org);
  if (f.type) p.set("type", f.type);
  if (f.tag) p.set("tag", f.tag);
  if (f.service) p.set("service", f.service);
  if (f.mine) p.set("mine", "true");
  if (f.pinned) p.set("pinned", "true");
  if (f.includeSnoozed) p.set("includeSnoozed", "true");
  p.set("limit", String(f.limit ?? 200));
  const { data } = await api.get<{ ok: boolean; tickets: TicketRow[] }>(`/api/tickets?${p.toString()}`);
  return data.tickets ?? [];
}

export async function getCommSlaConfig(): Promise<CommSlaConfig> {
  const { data } = await api.get<{ ok: boolean; config: CommSlaConfig }>("/api/tickets/sla-com");
  return data.config ?? {};
}

export interface TicketActivity {
  id: string; public_ref: string; subject: string; priority: TicketPriority;
  channel: string; status: TicketStatus;
  assigned_operator: string | null; assigned_operator_name?: string | null;
  created_at: string; updated_at: string; org_name: string | null;
}
export async function getTicketActivity(limit = 25): Promise<TicketActivity[]> {
  const { data } = await api.get<{ ok: boolean; activity: TicketActivity[] }>(`/api/tickets/activity?limit=${limit}`);
  return data.activity ?? [];
}

export async function getTicket(id: string): Promise<TicketDetail> {
  const { data } = await api.get<{ ok: boolean; ticket: TicketDetail }>(`/api/tickets/${id}`);
  return data.ticket;
}

export async function replyTicket(
  id: string,
  body: { body: string; visibility?: Visibility; expectsReply?: boolean },
): Promise<void> {
  await api.post(`/api/tickets/${id}/messages`, body);
}

export async function transitionTicket(
  id: string,
  body: { toStatus: TicketStatus; note?: string },
): Promise<TicketRow> {
  const { data } = await api.patch<{ ok: boolean; ticket: TicketRow }>(`/api/tickets/${id}/status`, body);
  return data.ticket;
}

export async function linkCase(
  id: string,
  body: { caseId: string; linkType?: "PRIMARY" | "RELATED" },
): Promise<void> {
  await api.post(`/api/tickets/${id}/link-case`, body);
}

/** Solicita la confirmación de cierre al cliente (sign-off #23). Devuelve el
 *  vínculo single-use que el cliente debe abrir para CERRAR el ticket. */
export async function requestClosure(
  id: string,
): Promise<{ link: string; expiresAt: string; ticket: TicketRow }> {
  const { data } = await api.post<{ ok: boolean; link: string; expiresAt: string; ticket: TicketRow }>(
    `/api/tickets/${id}/request-closure`, {},
  );
  return { link: data.link, expiresAt: data.expiresAt, ticket: data.ticket };
}

export async function assignTicket(id: string, operatorCi?: string): Promise<void> {
  await api.post(`/api/tickets/${id}/assign`, operatorCi ? { operatorCi } : {});
}

export interface CreateActionRequestInput {
  ticketId?: string;
  caseId?: string;
  orgSlug?: string;
  actionType: ActionType;
  title: string;
  rationale: string;
  recommendedSteps?: string;
  urgency?: TicketPriority;
  dueAt?: string;
}

export interface ActiveOrg { id: string; slug: string; name: string }

export async function listActiveOrgs(): Promise<ActiveOrg[]> {
  const { data } = await api.get<{ ok: boolean; organizations: ActiveOrg[] }>("/api/tickets/orgs");
  return data.organizations ?? [];
}

// ── Informe del caso (HTML) en el ticket ─────────────────────────────────────
export async function getCaseReportHtml(caseId: string): Promise<string> {
  const { data } = await api.get<string>(`/api/cases/${caseId}/report?format=html`, { responseType: "text" });
  return data;
}
export async function getMessageReportHtml(msgId: string): Promise<string> {
  const { data } = await api.get<string>(`/api/tickets/messages/${msgId}/report`, { responseType: "text" });
  return data;
}
// "Enviar informe" SOLO adjunta a un ticket existente (ticketId); nunca abre uno.
export async function sendReportToTicket(caseId: string, body: { note?: string; ticketId: string }): Promise<{ ticketId: string }> {
  const { data } = await api.post<{ ok: boolean; ticketId: string }>(`/api/cases/${caseId}/send-report-to-ticket`, body);
  return { ticketId: data.ticketId };
}

// ── Playbook del caso (HTML) en el ticket ────────────────────────────────────
// Vista previa: consulta la KB (reutiliza) o genera (LLM + fallback). forceNew
// fuerza uno nuevo ignorando la base de conocimiento.
export async function getCasePlaybookHtml(caseId: string, forceNew = false): Promise<string> {
  const { data } = await api.get<string>(
    `/api/cases/${caseId}/playbook.html${forceNew ? "?forceNew=true" : ""}`, { responseType: "text" });
  return data;
}
export async function getMessagePlaybookHtml(msgId: string): Promise<string> {
  const { data } = await api.get<string>(`/api/tickets/messages/${msgId}/playbook`, { responseType: "text" });
  return data;
}
// "Enviar playbook" SOLO adjunta a un ticket existente; espejo de sendReportToTicket.
export async function sendPlaybookToTicket(
  caseId: string, body: { note?: string; ticketId: string; forceNew?: boolean },
): Promise<{ ticketId: string; source: string; reused: boolean }> {
  const { data } = await api.post<{ ok: boolean; ticketId: string; source: string; reused: boolean }>(
    `/api/cases/${caseId}/send-playbook-to-ticket`, body);
  return { ticketId: data.ticketId, source: data.source, reused: data.reused };
}

// Marca el ticket como leído por el SOC → apaga el resaltado de no-leídos.
export async function markTicketRead(id: string): Promise<void> {
  await api.post(`/api/tickets/${id}/mark-read`, {});
}

// ── Plantillas de respuesta ───────────────────────────────────────────────────
import type { TicketTemplate } from "@/components/tickets/types";

export async function listTemplates(): Promise<TicketTemplate[]> {
  const { data } = await api.get<{ ok: boolean; templates: TicketTemplate[] }>("/api/tickets/templates");
  return data.templates ?? [];
}
export async function createTemplate(body: { title: string; body: string; category?: string }): Promise<TicketTemplate> {
  const { data } = await api.post<{ ok: boolean; template: TicketTemplate }>("/api/tickets/templates", body);
  return data.template;
}
export async function deleteTemplate(id: string): Promise<void> {
  await api.delete(`/api/tickets/templates/${id}`);
}

export async function createActionRequest(input: CreateActionRequestInput): Promise<ActionRequest> {
  const { data } = await api.post<{ ok: boolean; actionRequest: ActionRequest }>(
    `/api/tickets/action-requests`, input,
  );
  return data.actionRequest;
}

export async function getCommMetrics(days = 30, operator?: string): Promise<CommMetrics> {
  const p = new URLSearchParams({ days: String(days) });
  if (operator) p.set("operator", operator);
  const { data } = await api.get<{ ok: boolean; metrics: CommMetrics }>(`/api/tickets/metrics?${p.toString()}`);
  return data.metrics;
}

export async function getActionMetrics(days = 30): Promise<ActionMetrics> {
  const { data } = await api.get<{ ok: boolean; metrics: ActionMetrics }>(
    `/api/tickets/action-requests/metrics?days=${days}`,
  );
  return data.metrics;
}

export async function getRiskAcceptances(): Promise<ActionRequest[]> {
  const { data } = await api.get<{ ok: boolean; riskAcceptances: ActionRequest[] }>(
    `/api/tickets/risk-acceptances`,
  );
  return data.riskAcceptances ?? [];
}

export type TicketWithActions = TicketRow & { link_type: "PRIMARY" | "RELATED"; actionRequests: ActionRequest[] };

export async function getTicketsByCase(caseId: string): Promise<TicketWithActions[]> {
  const { data } = await api.get<{ ok: boolean; tickets: TicketWithActions[] }>(
    `/api/tickets/by-case/${caseId}`,
  );
  return data.tickets ?? [];
}

// ═══ Bloque clasificación / orden / workflow (20 mejoras) ═════════════════════

// (#1/#4/#5) Reclasificar
export async function setClassification(id: string, body: {
  ticketType?: TicketType; technicalSeverity?: TechnicalSeverity | null;
  serviceSlug?: string | null; priority?: TicketPriority; sentiment?: string | null;
}): Promise<TicketRow> {
  const { data } = await api.patch<{ ok: boolean; ticket: TicketRow }>(`/api/tickets/${id}/classification`, body);
  return data.ticket;
}

// (#2) Etiquetas + nube
export async function setTags(id: string, tags: string[]): Promise<void> {
  await api.put(`/api/tickets/${id}/tags`, { tags });
}
export async function getTagCloud(limit = 50): Promise<TagCount[]> {
  const { data } = await api.get<{ ok: boolean; tags: TagCount[] }>(`/api/tickets/tag-cloud?limit=${limit}`);
  return data.tags ?? [];
}

// (#3/#7) IA
export async function classifyTicket(id: string): Promise<AiSuggestion> {
  const { data } = await api.post<{ ok: boolean; suggestion: AiSuggestion }>(`/api/tickets/${id}/classify`, {});
  return data.suggestion;
}
export async function applyAiSuggestion(id: string, fields: AiSuggestion): Promise<TicketRow> {
  const { data } = await api.post<{ ok: boolean; ticket: TicketRow }>(`/api/tickets/${id}/ai-apply`, fields);
  return data.ticket;
}

// (#5) Catálogo de servicios
export async function listServices(activeOnly = false): Promise<TicketService[]> {
  const { data } = await api.get<{ ok: boolean; services: TicketService[] }>(`/api/tickets/services${activeOnly ? "?active=true" : ""}`);
  return data.services ?? [];
}
export async function createService(body: { name: string; slug: string; description?: string; color?: string }): Promise<TicketService> {
  const { data } = await api.post<{ ok: boolean; service: TicketService }>(`/api/tickets/services`, body);
  return data.service;
}
export async function updateService(id: string, body: Partial<TicketService>): Promise<TicketService> {
  const { data } = await api.patch<{ ok: boolean; service: TicketService }>(`/api/tickets/services/${id}`, body);
  return data.service;
}
export async function deleteService(id: string): Promise<void> {
  await api.delete(`/api/tickets/services/${id}`);
}

// (#14) Fijar  ·  (#18) Posponer
export async function pinTicket(id: string, pinned: boolean): Promise<void> {
  await api.post(`/api/tickets/${id}/pin`, { pinned });
}
export async function snoozeTicket(id: string, until: string | null): Promise<void> {
  await api.post(`/api/tickets/${id}/snooze`, { until });
}

// (#6) Duplicados + merge
export interface DuplicateCandidate {
  id: string; public_ref: string; subject: string; status: TicketStatus;
  priority: TicketPriority; created_at: string; primary_case_id?: string | null; sim?: number | null;
}
export async function getDuplicates(id: string): Promise<DuplicateCandidate[]> {
  const { data } = await api.get<{ ok: boolean; candidates: DuplicateCandidate[] }>(`/api/tickets/${id}/duplicates`);
  return data.candidates ?? [];
}
export async function mergeTicket(id: string, intoId: string): Promise<void> {
  await api.post(`/api/tickets/${id}/merge`, { intoId });
}

// (#17) Acciones masivas
export async function bulkUpdate(ids: string[], body: {
  assignedOperator?: string; priority?: TicketPriority; addTag?: string; status?: TicketStatus;
}): Promise<{ affected: number; total: number }> {
  const { data } = await api.post<{ ok: boolean; affected: number; total: number }>(`/api/tickets/bulk`, { ids, ...body });
  return { affected: data.affected, total: data.total };
}

// (#20) Watchers + CC
export async function addWatcher(id: string, operatorCi?: string): Promise<void> {
  await api.post(`/api/tickets/${id}/watchers`, operatorCi ? { operatorCi } : {});
}
export async function removeWatcher(id: string, ci: string): Promise<void> {
  await api.delete(`/api/tickets/${id}/watchers/${ci}`);
}
export async function setCcContacts(id: string, ccContacts: string[]): Promise<void> {
  await api.put(`/api/tickets/${id}/cc`, { ccContacts });
}

// (#10) Vistas guardadas
export async function listSavedViews(): Promise<SavedView[]> {
  const { data } = await api.get<{ ok: boolean; views: SavedView[] }>(`/api/tickets/saved-views`);
  return data.views ?? [];
}
export async function createSavedView(body: { name: string; filters: Record<string, string>; sort: SortRule[]; isShared?: boolean }): Promise<SavedView> {
  const { data } = await api.post<{ ok: boolean; view: SavedView }>(`/api/tickets/saved-views`, body);
  return data.view;
}
export async function deleteSavedView(id: string): Promise<void> {
  await api.delete(`/api/tickets/saved-views/${id}`);
}

// (#12/#16) Preferencias del usuario
export async function getUserPrefs(): Promise<UserPrefs> {
  const { data } = await api.get<{ ok: boolean; prefs: UserPrefs }>(`/api/tickets/prefs`);
  return data.prefs;
}
export async function setUserPrefs(body: { sort?: SortRule[]; defaultView?: string | null; layout?: "table" | "kanban" }): Promise<UserPrefs> {
  const { data } = await api.put<{ ok: boolean; prefs: UserPrefs }>(`/api/tickets/prefs`, body);
  return data.prefs;
}

// (#19) Reglas de negocio
export async function listRules(): Promise<TicketRule[]> {
  const { data } = await api.get<{ ok: boolean; rules: TicketRule[] }>(`/api/tickets/rules`);
  return data.rules ?? [];
}
export async function createRule(body: { name: string; conditions: TicketRuleCondition; actions: TicketRuleAction; ordering?: number; enabled?: boolean }): Promise<TicketRule> {
  const { data } = await api.post<{ ok: boolean; rule: TicketRule }>(`/api/tickets/rules`, body);
  return data.rule;
}
export async function updateRule(id: string, body: Partial<TicketRule>): Promise<TicketRule> {
  const { data } = await api.patch<{ ok: boolean; rule: TicketRule }>(`/api/tickets/rules/${id}`, body);
  return data.rule;
}
export async function deleteRule(id: string): Promise<void> {
  await api.delete(`/api/tickets/rules/${id}`);
}
