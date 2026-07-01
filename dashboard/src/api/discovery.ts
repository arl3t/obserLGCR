import { api } from "./client";

export type ScanProfile = "discovery" | "quick" | "standard" | "full" | "stealth" | "vulnerabilities" | "custom";
export type RunStatus = "pending" | "running" | "completed" | "failed";

export interface DiscoveryProfile {
  id: ScanProfile;
  label: string;
}

export interface DiscoveryStatus {
  scan_available: boolean;
  runner_configured: boolean;
  runner_ok: boolean | null;
}

export interface DiscoveryJob {
  id: number;
  name: string;
  description: string | null;
  targets: string;
  scan_profile: ScanProfile;
  custom_args: string | null;
  schedule_cron: string | null;
  schedule_enabled: boolean;
  auto_sync_ipam: boolean;
  scan_cves: boolean;
  ipam_subnet_id: number | null;
  last_run_at: string | null;
  last_run_id: number | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface DiscoveryJobCreate {
  name: string;
  description?: string;
  targets: string;
  scan_profile?: ScanProfile;
  custom_args?: string;
  schedule_cron?: string;
  schedule_enabled?: boolean;
  auto_sync_ipam?: boolean;
  scan_cves?: boolean;
  ipam_subnet_id?: number;
}

export interface DiscoveryRun {
  id: number;
  job_id: number | null;
  name: string | null;
  targets: string;
  scan_profile: ScanProfile;
  nmap_command: string | null;
  status: RunStatus;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  hosts_up: number;
  hosts_total: number;
  ports_open: number;
  scan_cves?: boolean;
  nmap_summary: string | null;
  error_message: string | null;
  triggered_by: string | null;
  created_at: string | null;
}

export interface DiscoveryPort {
  id: number;
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
}

export interface DiscoveryVulnerability {
  id: number;
  cve_id: string;
  severity: string | null;
  cvss_score: number | null;
  title: string | null;
  port: number | null;
  protocol: string | null;
  script_id: string | null;
  details: string | null;
}

export interface DiscoveryHost {
  id: number;
  run_id: number;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  status: string;
  os_guess: string | null;
  notes: string | null;
  documented: boolean;
  documented_at: string | null;
  documented_by: string | null;
  tags: string[] | null;
  ports: DiscoveryPort[];
  vulnerabilities?: DiscoveryVulnerability[];
  cve_count?: number;
}

export interface DiscoveryHostPage {
  total: number;
  limit: number;
  offset: number;
  data: DiscoveryHost[];
}

export interface DiscoveryStats {
  run_id: number;
  hosts_up: number;
  hosts_total: number;
  ports_open: number;
  documented: number;
  cves_total?: number;
  hosts_with_cves?: number;
  by_cve?: { cve_id: string; count: number }[];
  by_service: { service: string; count: number }[];
  by_port: { port: number; count: number }[];
  by_os: { os: string; count: number }[];
  by_status: Record<string, number>;
}

export interface DiscoveryTopologyNode {
  id: string;
  label: string;
  ip: string;
  hostname: string | null;
  status: string;
  port_count: number;
  documented: boolean;
  subnet: string;
  x: number | null;
  y: number | null;
  node_type: "host" | "gateway" | "subnet";
  gateway_inferred: boolean | null;
  host_id: number | null;
  mac_address: string | null;
  os_guess: string | null;
  open_ports: number[];
  has_critical_ports: boolean;
  noc_device_id: string | null;
  noc_status: string | null;
  noc_open_alerts: number;
  delta: "new" | "removed" | "unchanged" | null;
  region_name: string | null;
}

export interface DiscoveryTopologyEdge {
  source: string;
  target: string;
  label: string;
  edge_type: "gateway" | "inferred_gateway" | "same_mac";
}

export interface DiscoveryTopologyCluster {
  id: string;
  subnet: string;
  label: string;
  host_count: number;
  documented: number;
  ports_open: number;
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface DiscoveryTopology {
  run_id: number;
  compare_run_id: number | null;
  mode: "detail" | "summary" | "auto";
  nodes: DiscoveryTopologyNode[];
  edges: DiscoveryTopologyEdge[];
  subnets: string[];
  clusters: DiscoveryTopologyCluster[];
  meta: {
    total_hosts?: number;
    shown_hosts?: number;
    ipam_cidr?: string | null;
    region_name?: string | null;
    critical_ports?: number[];
  };
}

export type TopologyMode = "auto" | "detail" | "summary";

export interface AdHocRunRequest {
  name?: string;
  targets: string;
  scan_profile?: ScanProfile;
  custom_args?: string;
  scan_cves?: boolean;
  auto_sync_ipam?: boolean;
  ipam_subnet_id?: number;
}

export async function fetchDiscoveryStatus() {
  const { data } = await api.get<DiscoveryStatus>("/api/v1/ipam/discovery/status");
  return data;
}

export async function fetchDiscoveryProfiles() {
  const { data } = await api.get<DiscoveryProfile[]>("/api/v1/ipam/discovery/profiles");
  return data;
}

export async function fetchDiscoveryJobs() {
  const { data } = await api.get<DiscoveryJob[]>("/api/v1/ipam/discovery/jobs");
  return data;
}

export async function createDiscoveryJob(body: DiscoveryJobCreate) {
  const { data } = await api.post<DiscoveryJob>("/api/v1/ipam/discovery/jobs", body);
  return data;
}

export async function updateDiscoveryJob(id: number, body: Partial<DiscoveryJobCreate>) {
  const { data } = await api.patch<DiscoveryJob>(`/api/v1/ipam/discovery/jobs/${id}`, body);
  return data;
}

export async function deleteDiscoveryJob(id: number) {
  await api.delete(`/api/v1/ipam/discovery/jobs/${id}`);
}

export async function runDiscoveryJob(id: number) {
  const { data } = await api.post<DiscoveryRun>(`/api/v1/ipam/discovery/jobs/${id}/run`);
  return data;
}

export async function runAdHocDiscovery(body: AdHocRunRequest) {
  const { data } = await api.post<DiscoveryRun>("/api/v1/ipam/discovery/runs", body);
  return data;
}

export async function fetchDiscoveryRuns(jobId?: number) {
  const { data } = await api.get<DiscoveryRun[]>("/api/v1/ipam/discovery/runs", {
    params: jobId ? { job_id: jobId } : undefined,
  });
  return data;
}

export async function fetchDiscoveryRun(id: number) {
  const { data } = await api.get<DiscoveryRun>(`/api/v1/ipam/discovery/runs/${id}`);
  return data;
}

export async function fetchDiscoveryHosts(runId: number, offset = 0, limit = 100) {
  const { data } = await api.get<DiscoveryHostPage>(`/api/v1/ipam/discovery/runs/${runId}/hosts`, {
    params: { offset, limit },
  });
  return data;
}

export async function updateDiscoveryHost(id: number, body: { notes?: string; documented?: boolean; tags?: string[]; os_guess?: string }) {
  const { data } = await api.patch<DiscoveryHost>(`/api/v1/ipam/discovery/hosts/${id}`, body);
  return data;
}

export async function fetchDiscoveryVulnerabilities(runId: number, offset = 0, limit = 500) {
  const { data } = await api.get<{ total: number; limit: number; offset: number; data: DiscoveryVulnerability[] }>(
    `/api/v1/ipam/discovery/runs/${runId}/vulnerabilities`,
    { params: { offset, limit } },
  );
  return data;
}

export async function fetchDiscoveryStats(runId: number) {
  const { data } = await api.get<DiscoveryStats>(`/api/v1/ipam/discovery/runs/${runId}/stats`);
  return data;
}

export async function fetchDiscoveryTopology(
  runId: number,
  params?: { mode?: TopologyMode; compare?: boolean; compare_run_id?: number | null },
) {
  const { data } = await api.get<DiscoveryTopology>(`/api/v1/ipam/discovery/runs/${runId}/topology`, {
    params: {
      mode: params?.mode ?? "auto",
      compare: params?.compare ?? true,
      ...(params?.compare_run_id != null ? { compare_run_id: params.compare_run_id } : {}),
    },
  });
  return data;
}

export async function downloadDiscoveryExport(runId: number, format: "json" | "csv" | "xml") {
  const res = await api.get(`/api/v1/ipam/discovery/runs/${runId}/export`, {
    params: { format },
    responseType: format === "json" ? "json" : "blob",
  });
  const blob =
    format === "json"
      ? new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" })
      : (res.data as Blob);
  const ext = format === "xml" ? "xml" : format;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `discovery-run-${runId}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}
