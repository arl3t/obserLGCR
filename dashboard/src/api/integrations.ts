/**
 * integrations.ts — F7: cliente API de las integraciones de tickets
 * (webhooks salientes + tokens de API). Superficie INTERNA /api/integrations
 * (manager). Ver routes/ticketIntegrations.mjs.
 */
import { api } from "@/api/client";

export type WebhookEvent =
  | "ticket.created" | "ticket.message" | "ticket.status_changed" | "action_request.decided";
export type ApiScope = "tickets:read" | "tickets:write";

export interface WebhookEndpoint {
  id: string; org_id: string; org_slug: string; org_name: string;
  url: string; events: (WebhookEvent | "*")[]; description: string | null;
  enabled: boolean; failure_count: number; last_delivery_at: string | null;
  created_at: string; updated_at: string;
}
export interface WebhookDelivery {
  id: string; event_type: string; status: "PENDING" | "DELIVERED" | "FAILED";
  attempts: number; response_code: number | null; error: string | null;
  created_at: string; delivered_at: string | null; next_retry_at: string;
}
export interface ApiToken {
  id: string; org_id: string; org_slug: string; org_name: string; name: string;
  token_prefix: string; scopes: ApiScope[]; enabled: boolean;
  expires_at: string | null; last_used_at: string | null;
  created_at: string; revoked_at: string | null;
}

export async function getIntegrationsMeta(): Promise<{ events: WebhookEvent[]; scopes: ApiScope[] }> {
  const { data } = await api.get<{ ok: boolean; events: WebhookEvent[]; scopes: ApiScope[] }>("/api/integrations/meta");
  return { events: data.events ?? [], scopes: data.scopes ?? [] };
}

// ── Webhooks ──
export async function listWebhooks(org?: string): Promise<WebhookEndpoint[]> {
  const { data } = await api.get<{ ok: boolean; endpoints: WebhookEndpoint[] }>(`/api/integrations/webhooks${org ? `?org=${org}` : ""}`);
  return data.endpoints ?? [];
}
export async function createWebhook(body: { orgId: string; url: string; events: (WebhookEvent | "*")[]; description?: string }): Promise<{ id: string; secret: string }> {
  const { data } = await api.post<{ ok: boolean; id: string; secret: string }>("/api/integrations/webhooks", body);
  return { id: data.id, secret: data.secret };
}
export async function updateWebhook(id: string, body: Partial<{ url: string; events: (WebhookEvent | "*")[]; description: string; enabled: boolean }>): Promise<void> {
  await api.patch(`/api/integrations/webhooks/${id}`, body);
}
export async function rotateWebhookSecret(id: string): Promise<{ secret: string }> {
  const { data } = await api.post<{ ok: boolean; secret: string }>(`/api/integrations/webhooks/${id}/rotate-secret`, {});
  return { secret: data.secret };
}
export async function deleteWebhook(id: string): Promise<void> {
  await api.delete(`/api/integrations/webhooks/${id}`);
}
export async function listDeliveries(id: string): Promise<WebhookDelivery[]> {
  const { data } = await api.get<{ ok: boolean; deliveries: WebhookDelivery[] }>(`/api/integrations/webhooks/${id}/deliveries`);
  return data.deliveries ?? [];
}

// ── Tokens de API ──
export async function listApiTokens(org?: string): Promise<ApiToken[]> {
  const { data } = await api.get<{ ok: boolean; tokens: ApiToken[] }>(`/api/integrations/tokens${org ? `?org=${org}` : ""}`);
  return data.tokens ?? [];
}
export async function createApiToken(body: { orgId: string; name: string; scopes: ApiScope[]; expiresAt?: string | null }): Promise<{ id: string; token: string }> {
  const { data } = await api.post<{ ok: boolean; id: string; token: string }>("/api/integrations/tokens", body);
  return { id: data.id, token: data.token };
}
export async function revokeApiToken(id: string): Promise<void> {
  await api.post(`/api/integrations/tokens/${id}/revoke`, {});
}
export async function deleteApiToken(id: string): Promise<void> {
  await api.delete(`/api/integrations/tokens/${id}`);
}
