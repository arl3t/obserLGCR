import { api } from "@/api/client";

export interface SnmpSettings {
  default_community: string;
  default_port: number;
  default_version: string;
  poll_interval_sec: number;
  discovery_communities?: string[];
}

export interface SnmpDiscoveryHit {
  ip: string;
  community: string;
  sys_name: string | null;
  sys_descr: string | null;
  sys_object_id: string | null;
  device_type: string;
  registered: boolean;
  device_id: string | null;
  hostname: string;
  created: boolean;
}

export interface SnmpDiscoveryResult {
  cidr: string;
  communities_tried: string[];
  hosts_scanned: number;
  hosts_found: number;
  hosts_registered: number;
  duration_ms: number;
  results: SnmpDiscoveryHit[];
}

export async function getSnmpSettings(): Promise<SnmpSettings> {
  const { data } = await api.get<{ success: boolean; data: SnmpSettings }>("/api/noc/settings/snmp");
  return data.data;
}

export async function updateSnmpSettings(body: Partial<SnmpSettings>): Promise<SnmpSettings> {
  const { data } = await api.patch<{ success: boolean; data: SnmpSettings }>(
    "/api/noc/settings/snmp",
    body,
  );
  return data.data;
}

export async function runSnmpDiscovery(body: {
  cidr: string;
  communities?: string[];
  port?: number;
  site?: string;
  register?: boolean;
}): Promise<SnmpDiscoveryResult> {
  const { data } = await api.post<{ success: boolean; data: SnmpDiscoveryResult }>(
    "/api/noc/snmp/discover",
    body,
    { timeout: 300_000 },
  );
  return data.data;
}

export async function deleteNocDevice(id: string): Promise<void> {
  await api.delete(`/api/noc/devices/${id}`);
}
