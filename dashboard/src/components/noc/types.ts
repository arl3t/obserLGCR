export interface NocDevice {
  id: string;
  hostname: string;
  ip_address: string | null;
  device_type: string;
  site: string | null;
  status: string;
  last_seen_at: string | null;
  cpu_pct: number | null;
  mem_pct: number | null;
  rtt_ms: number | null;
  open_alerts: number;
  heartbeat_timeout_secs: number;
  inventory_ack?: boolean;
  inventory_ack_at?: string | null;
  discovered_via?: string | null;
}

export interface NocAlert {
  id: string;
  device_id: string;
  hostname: string;
  ip_address?: string | null;
  alert_type: string;
  status: string;
  triggered_at: string;
  resolved_at?: string | null;
  ack_by?: string | null;
  ack_at?: string | null;
  details: Record<string, unknown>;
}

export type NocHubView = "wallboard" | "activos" | "alerts" | "sites";

export interface NocSiteSummary {
  site: string;
  total: number;
  online: number;
  offline: number;
  alerting: number;
}
