import { api } from "./client";

export interface DetectionFamilyKpi {
  family: string;
  label: string;
  category: string;
  enabled: boolean;
  source_logs: string[];
  events_24h: number;
  critical_24h: number;
  warn_24h: number;
  hosts_24h: number;
  last_event_at: string | null;
}

export interface DetectionLogType {
  source_log: string;
  sensor_name: string;
  sensor_family: string;
  source_category: string;
  network_zone: string;
  iceberg_table: string | null;
  enabled: boolean;
  notes: string | null;
}

export interface DetectionEvent {
  id: string;
  source_log: string;
  sensor_family: string;
  severity: string;
  hostname: string | null;
  source: string | null;
  message: string;
  raw: Record<string, unknown> | null;
  src_ip: string | null;
  dst_ip: string | null;
  rule_id: string | null;
  event_time: string;
  ingested_at: string;
  agent_id: string | null;
}

export interface DetectionSourceDetail {
  source_log: string;
  sensor_name: string;
  network_zone: string;
  iceberg_table: string | null;
  enabled: boolean;
  events_24h: number;
  last_event_at: string | null;
}

export interface DetectionFamilySources {
  family: string;
  label: string;
  category: string;
  enabled: boolean;
  sourceLogs: string[];
  sources: DetectionSourceDetail[];
}

export interface DetectionTimelineBucket {
  bucket: string;
  total: number;
  critical: number;
}

export interface DetectionStats {
  hours: number;
  total: number;
  critical: number;
  warn: number;
  hosts: number;
  source_logs: number;
  last_event_at: string | null;
  severity: { severity: string; count: number }[];
  timeline: DetectionTimelineBucket[];
  top_families: { family: string; count: number }[];
}

export async function fetchDetectionStats(hours = 24) {
  const { data } = await api.get<{ ok: boolean } & DetectionStats>("/api/detection/stats", {
    params: { hours },
  });
  return data;
}

export async function fetchDetectionKpis() {
  const { data } = await api.get<{ ok: boolean; families: DetectionFamilyKpi[] }>(
    "/api/detection/kpis",
  );
  return data.families ?? [];
}

export async function fetchDetectionSources() {
  const { data } = await api.get<{ ok: boolean; sources: DetectionFamilySources[] }>(
    "/api/detection/sources",
  );
  return data.sources ?? [];
}

export async function fetchDetectionLogTypes() {
  const { data } = await api.get<{ ok: boolean; log_types: DetectionLogType[] }>(
    "/api/detection/log-types",
  );
  return data.log_types ?? [];
}

export async function fetchDetectionEvents(params: {
  hours?: number;
  limit?: number;
  offset?: number;
  source_log?: string;
  family?: string;
  severity?: string;
  q?: string;
}) {
  const { data } = await api.get<{
    ok: boolean;
    data: DetectionEvent[];
    total: number;
    limit: number;
    offset: number;
  }>("/api/detection/events", { params });
  return data;
}

export async function patchDetectionFamily(family: string, enabled: boolean) {
  const { data } = await api.patch<{ ok: boolean; affected: number; enabled: boolean }>(
    `/api/detection/sources/${encodeURIComponent(family)}`,
    { enabled },
  );
  return data;
}
