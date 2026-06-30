import { api } from "./client";

export type IpamAddressStatus = "Offline" | "Online" | "Reserved" | "Free" | "DHCP";

export interface IpamRegion {
  id: number;
  name: string;
  description: string | null;
  contact_name?: string | null;
  contact_email?: string | null;
  rack_notes?: string | null;
  internal_asn?: string | null;
  subnet_count?: number;
  address_count?: number;
}

export interface IpamRegionCreate {
  name: string;
  description?: string;
  contact_name?: string;
  contact_email?: string;
  rack_notes?: string;
  internal_asn?: string;
}

export interface IpamRegionUpdate {
  name?: string;
  description?: string | null;
  contact_name?: string | null;
  contact_email?: string | null;
  rack_notes?: string | null;
  internal_asn?: string | null;
}

export interface IpamSubnet {
  id: number;
  region_id: number;
  region_name: string | null;
  vlan_id: number | null;
  vlan_name: string | null;
  cidr_block: string;
  broadcast_domain: string | null;
  description: string | null;
  created_at: string | null;
  deleted_at?: string | null;
  scan_enabled?: boolean;
  scan_cron?: string | null;
  utilization_alert_pct?: number;
  utilization_webhook_url?: string | null;
  overlap_warnings?: { id: number; cidr_block: string }[];
  vlan_warnings?: { id: number; cidr_block: string; region_name: string }[];
  rfc1918_scope: string;
}

export interface IpamSubnetCreate {
  region_id: number;
  cidr_block: string;
  vlan_id?: number;
  vlan_name?: string;
  broadcast_domain?: string;
  description?: string;
  scan_enabled?: boolean;
  scan_cron?: string;
  utilization_alert_pct?: number;
  utilization_webhook_url?: string;
}

export interface IpamSubnetUpdate {
  region_id?: number;
  vlan_id?: number | null;
  vlan_name?: string | null;
  broadcast_domain?: string | null;
  description?: string | null;
  scan_enabled?: boolean;
  scan_cron?: string | null;
  utilization_alert_pct?: number;
  utilization_webhook_url?: string | null;
}

export interface IpamSubnetStatistics {
  subnet_id: number;
  cidr_block: string;
  region_id: number;
  vlan_id: number | null;
  total_host_capacity: number;
  occupied: number;
  free_tracked: number;
  free_remaining: number;
  utilization_percent: number;
  by_status: Record<string, number>;
  alert_threshold?: number;
  alert_triggered?: boolean;
}

export interface IpamAddress {
  id: number;
  subnet_id: number;
  ip_address: string;
  status: IpamAddressStatus;
  hostname: string | null;
  mac_address: string | null;
  description: string | null;
  last_seen: string | null;
  is_discovered_by_nmap: boolean;
  expires_at?: string | null;
  noc_device_id?: string | null;
  noc_hostname?: string | null;
  dhcp_lease_expires?: string | null;
  reservation_expired?: boolean;
  updated_at: string | null;
}

export interface IpamAddressPage {
  total: number;
  limit: number;
  offset: number;
  data: IpamAddress[];
}

export interface IpamAuditEntry {
  id: number;
  entity_type: string;
  entity_id: string;
  action: string;
  actor: string | null;
  changes: Record<string, unknown> | null;
  created_at: string;
}

export interface IpamHeatmap {
  subnet_id: number;
  cidr_block: string;
  prefixlen: number;
  cells: { ip: string; status: string; last_octet: number }[];
}

export interface IpamNmapDiscoverResult {
  subnet_id: number;
  cidr_block: string;
  hosts_capacity: number;
  hosts_up: number;
  created: number;
  updated: number;
  marked_offline: number;
  duration_ms: number;
  nmap_summary: string | null;
  noc_linked?: number;
}

export async function fetchIpamRegions() {
  const { data } = await api.get<IpamRegion[]>("/api/v1/ipam/regions");
  return data;
}

export async function createIpamRegion(body: IpamRegionCreate) {
  const { data } = await api.post<IpamRegion>("/api/v1/ipam/regions", body);
  return data;
}

export async function updateIpamRegion(id: number, body: IpamRegionUpdate) {
  const { data } = await api.patch<IpamRegion>(`/api/v1/ipam/regions/${id}`, body);
  return data;
}

export async function deleteIpamRegion(id: number) {
  await api.delete(`/api/v1/ipam/regions/${id}`);
}

export async function fetchIpamSubnets(regionId?: number) {
  const { data } = await api.get<IpamSubnet[]>("/api/v1/ipam/subnets", {
    params: regionId ? { region_id: regionId } : undefined,
  });
  return data;
}

export async function createIpamSubnet(body: IpamSubnetCreate) {
  const { data } = await api.post<IpamSubnet>("/api/v1/ipam/subnets", body);
  return data;
}

export async function updateIpamSubnet(id: number, body: IpamSubnetUpdate) {
  const { data } = await api.patch<IpamSubnet>(`/api/v1/ipam/subnets/${id}`, body);
  return data;
}

export async function deleteIpamSubnet(id: number) {
  await api.delete(`/api/v1/ipam/subnets/${id}`);
}

export async function fetchIpamSubnetStatistics(subnetId: number) {
  const { data } = await api.get<IpamSubnetStatistics>(`/api/v1/ipam/subnets/${subnetId}/statistics`);
  return data;
}

export async function fetchIpamSubnetAddresses(subnetId: number, page = 0, limit = 100) {
  const { data } = await api.get<IpamAddressPage>(`/api/v1/ipam/subnets/${subnetId}/addresses`, {
    params: { offset: page * limit, limit },
  });
  return data;
}

export async function searchIpam(q: string, offset = 0, limit = 50) {
  const { data } = await api.get<{ total: number; data: IpamAddress[] }>("/api/v1/ipam/search", {
    params: { q, offset, limit },
  });
  return data;
}

export async function fetchIpamHeatmap(subnetId: number) {
  const { data } = await api.get<IpamHeatmap>(`/api/v1/ipam/subnets/${subnetId}/heatmap`);
  return data;
}

export async function fetchIpamAudit(limit = 100) {
  const { data } = await api.get<IpamAuditEntry[]>("/api/v1/ipam/audit", { params: { limit } });
  return data;
}

export async function exportIpam(format: "json" | "csv", regionId?: number) {
  const { data } = await api.get("/api/v1/ipam/export", {
    params: { format, region_id: regionId },
    responseType: format === "csv" ? "text" : "json",
  });
  return data;
}

export async function importIpamSubnet(subnetId: number, rows: Record<string, unknown>[]) {
  const { data } = await api.post(`/api/v1/ipam/subnets/${subnetId}/import`, rows);
  return data as { created: number; updated: number; skipped: number };
}

export async function bulkReserveIpam(
  subnetId: number,
  body: { start_ip: string; end_ip: string; status?: IpamAddressStatus; description?: string; expires_at?: string },
) {
  const { data } = await api.post(`/api/v1/ipam/subnets/${subnetId}/addresses/bulk`, body);
  return data as { created: number; updated: number };
}

export async function syncDhcpIpam(subnetId: number, leases: Record<string, unknown>[]) {
  const { data } = await api.post(`/api/v1/ipam/subnets/${subnetId}/dhcp/sync`, leases);
  return data as { synced: number };
}

export async function linkNocAddress(addressId: number) {
  const { data } = await api.post(`/api/v1/ipam/addresses/${addressId}/link-noc`);
  return data;
}

export async function linkNocSubnet(subnetId: number) {
  const { data } = await api.post(`/api/v1/ipam/subnets/${subnetId}/link-noc-all`);
  return data as { linked: number };
}

export async function createIpamAddress(subnetId: number, body: Record<string, unknown>) {
  const { data } = await api.post<IpamAddress>(`/api/v1/ipam/subnets/${subnetId}/addresses`, body);
  return data;
}

export async function patchIpamAddress(addressId: number, body: Record<string, unknown>) {
  const { data } = await api.patch<IpamAddress>(`/api/v1/ipam/addresses/${addressId}`, body);
  return data;
}

export async function deleteIpamAddress(addressId: number) {
  await api.delete(`/api/v1/ipam/addresses/${addressId}`);
}

export async function discoverIpamSubnetNmap(subnetId: number, body = {}) {
  const { data } = await api.post<IpamNmapDiscoverResult>(
    `/api/v1/ipam/subnets/${subnetId}/discover`,
    { mark_offline: true, preserve_reserved: true, ...body },
    { timeout: 600_000 },
  );
  return data;
}
