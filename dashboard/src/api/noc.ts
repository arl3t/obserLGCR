import { isAxiosError } from "axios";
import { api } from "@/api/client";
import type { NocAlert, NocDevice } from "@/components/noc/types";

function apiErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError(err)) {
    const body = err.response?.data as { error?: string; detail?: string } | undefined;
    return body?.error ?? body?.detail ?? err.message ?? fallback;
  }
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}

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

export interface NocMetricPoint {
  t: string;
  v: number;
}

export interface NocDeviceDetail extends NocDevice {
  mac_address: string | null;
  description: string | null;
  agent_version: string | null;
  cpu_threshold_pct: number;
  mem_threshold_pct: number;
  rtt_threshold_ms: number;
  ssh_host: string | null;
  ssh_port: number;
  ssh_user: string | null;
  inventory_ack_by?: string | null;
}

export async function fetchNocDevices(): Promise<NocDevice[]> {
  const { data } = await api.get<{ data?: NocDevice[]; devices?: NocDevice[] }>("/api/noc/devices");
  return data.data ?? data.devices ?? [];
}

export async function fetchNocAlerts(params?: {
  status?: string;
  device_id?: string;
  limit?: number;
}): Promise<NocAlert[]> {
  const { data } = await api.get<{ data?: NocAlert[]; alerts?: NocAlert[] }>("/api/noc/alerts", {
    params,
  });
  return data.data ?? data.alerts ?? [];
}

export async function fetchNocDevice(id: string): Promise<NocDeviceDetail> {
  const { data } = await api.get<{ data?: NocDeviceDetail; device?: NocDeviceDetail }>(
    `/api/noc/devices/${id}`,
  );
  const row = data.data ?? data.device;
  if (!row) throw new Error("Dispositivo no encontrado");
  return row;
}

export async function acknowledgeNocInventory(deviceId: string, notes?: string): Promise<NocDeviceDetail> {
  try {
    const { data } = await api.post<{ data?: NocDeviceDetail; device?: NocDeviceDetail }>(
      `/api/noc/devices/${deviceId}/inventory-ack`,
      notes ? { notes } : {},
    );
    const row = data.data ?? data.device;
    if (!row) throw new Error("Error al reconocer activo");
    return row;
  } catch (err) {
    throw new Error(apiErrorMessage(err, "No se pudo reconocer el activo en inventario"));
  }
}

export async function patchNocDevice(
  id: string,
  body: Partial<{
    hostname: string;
    heartbeat_timeout_secs: number;
    cpu_threshold_pct: number;
    mem_threshold_pct: number;
    rtt_threshold_ms: number;
    description: string;
    site: string;
    device_type: string;
    tags: string[];
  }>,
): Promise<NocDeviceDetail> {
  const { data } = await api.patch<{ data?: NocDeviceDetail; device?: NocDeviceDetail }>(
    `/api/noc/devices/${id}`,
    body,
  );
  const row = data.data ?? data.device;
  if (!row) throw new Error("Error al actualizar");
  return row;
}

export async function fetchNocMetrics(
  deviceId: string,
  metric: "rtt_ms" | "cpu_pct" | "mem_pct",
  window = "24h",
): Promise<NocMetricPoint[]> {
  const { data } = await api.get<{ data?: NocMetricPoint[] }>(
    `/api/noc/devices/${deviceId}/metrics`,
    { params: { metric, window } },
  );
  return data.data ?? [];
}

export async function ackNocAlert(id: string): Promise<void> {
  await api.patch(`/api/noc/alerts/${id}`, { action: "ack" });
}

export async function resolveNocAlert(id: string): Promise<void> {
  await api.patch(`/api/noc/alerts/${id}`, { action: "resolve" });
}

export interface NocOpenIncidentResult {
  outcome: string;
  caseId?: string;
  alertId?: string;
  hostname?: string;
}

export async function openIncidentFromNocAlert(id: string): Promise<NocOpenIncidentResult> {
  const { data } = await api.post<NocOpenIncidentResult & { success: boolean; error?: string }>(
    `/api/noc/alerts/${id}/open-incident`,
  );
  if (!data.success && data.error) {
    throw new Error(data.error);
  }
  return {
    outcome: data.outcome ?? "created",
    caseId: data.caseId,
    alertId: data.alertId ?? id,
    hostname: data.hostname,
  };
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
