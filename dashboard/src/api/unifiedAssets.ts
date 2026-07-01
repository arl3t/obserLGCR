import { api } from "./client";

export interface UnifiedAsset {
  unified_id: string;
  noc_device_id: string | null;
  ipam_address_id: number | null;
  hostname: string | null;
  ip_address: string | null;
  mac_address: string | null;
  device_type: string | null;
  site: string | null;
  noc_status: string | null;
  ipam_status: string | null;
  region_name: string | null;
  cidr_block: string | null;
  os_guess: string | null;
  discovery_documented: boolean | null;
  discovery_open_ports: number;
  discovery_meta: Record<string, unknown> | null;
  criticality: string | null;
  registry_type: string | null;
  registry_sensor_key: string | null;
  ipam_linked: boolean;
  last_seen_at: string | null;
}

export interface UnifiedAssetPage {
  total: number;
  limit: number;
  offset: number;
  data: UnifiedAsset[];
}

export async function fetchUnifiedAssets(params?: {
  search?: string;
  linked_only?: boolean;
  limit?: number;
  offset?: number;
}) {
  const { data } = await api.get<UnifiedAssetPage>("/api/v1/ipam/assets/unified", { params });
  return data;
}
