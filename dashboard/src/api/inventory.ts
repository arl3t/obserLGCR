import { api } from "@/api/client";

export type MatchType = "exact" | "prefix" | "suffix" | "regex" | "cpe";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface InventoryHost {
  id: string;
  hostname: string | null;
  os_name: string | null;
  os_version: string | null;
  ip_address: string | null;
  software_count: number;
  last_report_at: string | null;
  report_count: number;
  cpu_cores: number | null;
  ram_mb: number | null;
  manufacturer: string | null;
  model: string | null;
}

export interface InventorySoftware {
  name: string;
  version: string | null;
  publisher: string | null;
  install_date: string | null;
}

export interface ServerSoftware {
  id: string;
  name: string;
  version: string | null;
  publisher: string | null;
  install_date: string | null;
  package_manager: string | null;
  is_whitelisted: boolean | null;
  is_blacklisted: boolean;
  collected_at: string;
}

export interface BlacklistRule {
  id: string;
  software_name: string;
  match_type: MatchType;
  pattern: string;
  publisher: string | null;
  severity: Severity;
  mitre_technique: string | null;
  enabled: boolean;
  auto_incident: boolean;
  notes: string | null;
  created_at: string;
}

export interface WhitelistRule {
  id: string;
  software_name: string;
  match_type: MatchType;
  pattern: string;
  publisher: string | null;
  enabled: boolean;
  notes: string | null;
  created_at: string;
}

export interface GovernanceConfig {
  strict_whitelist: boolean;
  updated_at?: string;
}

export interface IncidentsQueueItem {
  id: string;
  created_at: string;
  incident_type: string;
  severity: string;
  hostname: string;
  status: string;
  case_id: string | null;
  payload: Record<string, unknown>;
}

function unwrap<T>(data: { success?: boolean; data?: T }): T {
  return (data.data ?? []) as T;
}

export async function getInventoryHostByNocDevice(deviceId: string): Promise<InventoryHost | null> {
  const { data } = await api.get<{ success: boolean; data: InventoryHost | null }>(
    `/api/inventory/hosts/by-noc-device/${deviceId}`,
  );
  return data.data ?? null;
}

export async function listInventoryHosts(): Promise<InventoryHost[]> {
  const { data } = await api.get<{ success: boolean; data: InventoryHost[] }>("/api/inventory/hosts");
  return unwrap(data);
}

export async function listHostSoftware(hostId: string): Promise<InventorySoftware[]> {
  const { data } = await api.get<{ success: boolean; data: InventorySoftware[] }>(
    `/api/inventory/hosts/${hostId}/software`,
  );
  return unwrap(data);
}

export async function listHostServerSoftware(hostId: string): Promise<ServerSoftware[]> {
  const { data } = await api.get<{ success: boolean; data: ServerSoftware[] }>(
    `/api/inventory/hosts/${hostId}/server-software`,
  );
  return unwrap(data);
}

export async function listBlacklist(): Promise<BlacklistRule[]> {
  const { data } = await api.get<{ success: boolean; data: BlacklistRule[] }>(
    "/api/inventory/governance/blacklist",
  );
  return unwrap(data);
}

export async function createBlacklist(body: {
  software_name: string;
  pattern: string;
  match_type?: MatchType;
  publisher?: string;
  severity?: Severity;
  mitre_technique?: string;
  notes?: string;
}): Promise<BlacklistRule> {
  const { data } = await api.post<{ success: boolean; data: BlacklistRule }>(
    "/api/inventory/governance/blacklist",
    body,
  );
  return data.data;
}

export async function deleteBlacklist(id: string): Promise<void> {
  await api.delete(`/api/inventory/governance/blacklist/${id}`);
}

export async function listWhitelist(): Promise<WhitelistRule[]> {
  const { data } = await api.get<{ success: boolean; data: WhitelistRule[] }>(
    "/api/inventory/governance/whitelist",
  );
  return unwrap(data);
}

export async function createWhitelist(body: {
  software_name: string;
  pattern: string;
  match_type?: MatchType;
  publisher?: string;
  notes?: string;
}): Promise<WhitelistRule> {
  const { data } = await api.post<{ success: boolean; data: WhitelistRule }>(
    "/api/inventory/governance/whitelist",
    body,
  );
  return data.data;
}

export async function deleteWhitelist(id: string): Promise<void> {
  await api.delete(`/api/inventory/governance/whitelist/${id}`);
}

export async function getGovernanceConfig(): Promise<GovernanceConfig> {
  const { data } = await api.get<{ success: boolean; data: GovernanceConfig }>(
    "/api/inventory/governance/config",
  );
  return data.data ?? { strict_whitelist: false };
}

export async function updateGovernanceConfig(strict_whitelist: boolean): Promise<GovernanceConfig> {
  const { data } = await api.patch<{ success: boolean; data: GovernanceConfig }>(
    "/api/inventory/governance/config",
    { strict_whitelist },
  );
  return data.data;
}

export async function listIncidentsQueue(status = "pending"): Promise<IncidentsQueueItem[]> {
  const { data } = await api.get<{ success: boolean; data: IncidentsQueueItem[] }>(
    "/api/inventory/governance/incidents-queue",
    { params: { status } },
  );
  return unwrap(data);
}
