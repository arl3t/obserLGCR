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
}

export interface NocAlert {
  id: string;
  device_id: string;
  hostname: string;
  alert_type: string;
  status: string;
  triggered_at: string;
  resolved_at?: string | null;
  details: Record<string, unknown>;
}
