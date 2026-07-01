export type BarSegment = "up" | "down" | "unknown";

export interface MetricPoint {
  t: string;
  v: number;
}

export interface NocAlertLike {
  alert_type: string;
  status: string;
  triggered_at: string;
  resolved_at?: string | null;
}

export function stripCidr(ip: string | null | undefined): string {
  const s = String(ip ?? "").trim();
  if (!s) return "";
  const i = s.indexOf("/");
  return i > 0 ? s.slice(0, i) : s;
}

export function formatAgo(ts: string | null | undefined): string {
  if (!ts) return "—";
  const secs = Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (secs < 3600) return s > 0 ? `${m}m, ${s}s ago` : `${m}m ago`;
  const h = Math.floor(secs / 3600);
  const rm = Math.floor((secs % 3600) / 60);
  return rm > 0 ? `${h}h, ${rm}m ago` : `${h}h ago`;
}

export function formatDuration(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)} min`;
  if (secs < 86400) {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return m > 0 ? `${h} h, ${m} min` : `${h} h`;
  }
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  return h > 0 ? `${d} días, ${h} h` : `${d} días`;
}

export function statusWord(status: string): { label: string; tone: "success" | "warning" | "danger" | "muted" } {
  if (status === "online") return { label: "Up", tone: "success" };
  if (status === "offline") return { label: "Down", tone: "danger" };
  if (status === "degraded") return { label: "Degraded", tone: "warning" };
  return { label: "Unknown", tone: "muted" };
}

export function fleetStatusWord(online: number, total: number): { label: string; tone: "success" | "warning" | "danger" | "muted" } {
  if (total === 0) return { label: "—", tone: "muted" };
  if (online === total) return { label: "Up", tone: "success" };
  if (online === 0) return { label: "Down", tone: "danger" };
  return { label: "Partial", tone: "warning" };
}

/** Segmentos de disponibilidad 24h a partir del último heartbeat y estado actual. */
export function buildUptimeBars(
  status: string,
  lastSeenAt: string | null,
  segments = 48,
): BarSegment[] {
  const bars: BarSegment[] = Array(segments).fill("up");
  if (!lastSeenAt) return Array(segments).fill("unknown");

  const msPerSeg = (24 * 3600 * 1000) / segments;
  const lastMs = new Date(lastSeenAt).getTime();
  const now = Date.now();

  if (status === "offline" || status === "degraded") {
    const downSince = now - lastMs;
    const downSegs = Math.min(segments, Math.ceil(downSince / msPerSeg));
    for (let i = segments - downSegs; i < segments; i++) {
      bars[i] = status === "degraded" ? "down" : "down";
    }
  }
  return bars;
}

/** Uptime 24h desde historial de alertas `down` (preferido cuando hay datos). */
export function buildUptimeBarsFromAlerts(
  alerts: NocAlertLike[],
  lastSeenAt: string | null,
  segments = 48,
): BarSegment[] {
  const downAlerts = alerts.filter((a) => a.alert_type === "down");
  if (downAlerts.length === 0 && !lastSeenAt) {
    return Array(segments).fill("unknown");
  }

  const now = Date.now();
  const windowMs = 24 * 3600 * 1000;
  const msPerSeg = windowMs / segments;
  const bars: BarSegment[] = [];

  for (let i = 0; i < segments; i++) {
    const segStart = now - windowMs + i * msPerSeg;
    const segEnd = segStart + msPerSeg;
    const inDown = downAlerts.some((a) => {
      const start = new Date(a.triggered_at).getTime();
      const end =
        a.resolved_at != null
          ? new Date(a.resolved_at).getTime()
          : a.status === "open" || a.status === "ack"
            ? now
            : start;
      return start < segEnd && end > segStart;
    });
    bars.push(inDown ? "down" : "up");
  }
  return bars;
}

export function computeFleetSla(devices: { status: string }[]): number {
  if (devices.length === 0) return 100;
  const online = devices.filter((d) => d.status === "online").length;
  return Math.round((online / devices.length) * 1000) / 10;
}

export function groupDevicesBySite(
  devices: { site: string | null; status: string; open_alerts?: number }[],
): { site: string; total: number; online: number; offline: number; alerting: number }[] {
  const map = new Map<string, { total: number; online: number; offline: number; alerting: number }>();
  for (const d of devices) {
    const site = (d.site?.trim() || "Sin sitio");
    const cur = map.get(site) ?? { total: 0, online: 0, offline: 0, alerting: 0 };
    cur.total += 1;
    if (d.status === "online") cur.online += 1;
    if (d.status === "offline") cur.offline += 1;
    if ((d.open_alerts ?? 0) > 0 || d.status === "offline") cur.alerting += 1;
    map.set(site, cur);
  }
  return [...map.entries()]
    .map(([site, stats]) => ({ site, ...stats }))
    .sort((a, b) => b.alerting - a.alerting || a.site.localeCompare(b.site));
}

export function alertSeverityRank(type: string): number {
  if (type === "down") return 0;
  if (type === "high_cpu" || type === "high_mem") return 1;
  if (type === "high_rtt") return 2;
  return 3;
}

export function uptimePercentFromBars(bars: BarSegment[]): number {
  if (bars.length === 0) return 100;
  const up = bars.filter((b) => b === "up").length;
  return Math.round((up / bars.length) * 1000) / 10;
}

export function computeWindowUptime(
  alerts: NocAlertLike[],
  windowDays: number,
  isCurrentlyDown: boolean,
  lastSeenAt: string | null,
): { pct: number; incidents: number; downtimeSecs: number } {
  const windowMs = windowDays * 86400 * 1000;
  const since = Date.now() - windowMs;
  const downAlerts = alerts.filter((a) => a.alert_type === "down");

  let downtimeSecs = 0;
  let incidents = 0;

  for (const a of downAlerts) {
    const start = new Date(a.triggered_at).getTime();
    if (start < since) continue;
    incidents++;
    const end = a.resolved_at ? new Date(a.resolved_at).getTime() : Date.now();
    downtimeSecs += Math.max(0, (end - start) / 1000);
  }

  if (isCurrentlyDown && lastSeenAt) {
    const extra = (Date.now() - new Date(lastSeenAt).getTime()) / 1000;
    if (!downAlerts.some((a) => a.status === "open" || a.status === "ack")) {
      incidents += 1;
      downtimeSecs += extra;
    }
  }

  const windowSecs = windowDays * 86400;
  const pct = Math.max(0, Math.min(100, ((windowSecs - downtimeSecs) / windowSecs) * 100));
  return {
    pct: Math.round(pct * 1000) / 1000,
    incidents,
    downtimeSecs: Math.round(downtimeSecs),
  };
}

export function computeMtbfDays(alerts: NocAlertLike[]): number | null {
  const downs = alerts
    .filter((a) => a.alert_type === "down")
    .sort((a, b) => new Date(a.triggered_at).getTime() - new Date(b.triggered_at).getTime());
  if (downs.length < 2) return null;
  let totalGap = 0;
  for (let i = 1; i < downs.length; i++) {
    totalGap += new Date(downs[i].triggered_at).getTime() - new Date(downs[i - 1].triggered_at).getTime();
  }
  return Math.round((totalGap / (downs.length - 1) / 86400000) * 100) / 100;
}

export function rttStats(points: MetricPoint[]): { avg: number; min: number; max: number } | null {
  if (points.length === 0) return null;
  const vals = points.map((p) => p.v);
  const sum = vals.reduce((a, b) => a + b, 0);
  return {
    avg: Math.round(sum / vals.length),
    min: Math.round(Math.min(...vals)),
    max: Math.round(Math.max(...vals)),
  };
}

export function buildChartPath(points: MetricPoint[], height = 200, padY = 8): string {
  if (points.length < 2) return "";
  const vals = points.map((p) => p.v);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const range = max - min || 1;
  const w = 400;

  return points
    .map((p, i) => {
      const x = (i / (points.length - 1)) * w;
      const y = height - padY - ((p.v - min) / range) * (height - padY * 2);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

export function chartYTicks(maxVal: number): number[] {
  const top = Math.ceil(maxVal / 50) * 50 + 50;
  return [top, Math.round(top * 0.6), Math.round(top * 0.3), 0];
}
