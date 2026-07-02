import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import type { NocAlert } from "../types";
import {
  buildUptimeBarsFromAlerts,
  computeMtbfDays,
  computeWindowUptime,
  formatAgo,
  formatDuration,
  statusWord,
  stripCidr,
  uptimePercentFromBars,
  type MetricPoint,
} from "./helpers";
import { MetricChart } from "./MetricChart";
import { UptimeBars } from "./UptimeBars";
import { UptimeSidebar } from "./UptimeSidebar";
import { cn } from "@/lib/utils";

export interface DeviceDetail {
  id: string;
  hostname: string;
  ip_address: string | null;
  device_type: string;
  site: string | null;
  status: string;
  last_seen_at: string | null;
  heartbeat_timeout_secs: number;
  agent_version: string | null;
  description: string | null;
}

interface DeviceUptimeMonitorProps {
  device: DeviceDetail;
  alerts: NocAlert[];
  rttPoints: MetricPoint[];
  cpuPoints: MetricPoint[];
  memPoints: MetricPoint[];
  rttLoading: boolean;
  cpuLoading: boolean;
  memLoading: boolean;
  onRefresh: () => void;
  refreshing: boolean;
  thresholds?: ReactNode;
  operations?: ReactNode;
  hideOperations?: boolean;
  hideHeader?: boolean;
  compact?: boolean;
}

export function DeviceUptimeMonitor({
  device,
  alerts,
  rttPoints,
  cpuPoints,
  memPoints,
  rttLoading,
  cpuLoading,
  memLoading,
  onRefresh,
  refreshing,
  thresholds,
  operations,
  hideOperations = false,
  hideHeader = false,
  compact = false,
}: DeviceUptimeMonitorProps) {
  const st = statusWord(device.status);
  const bars = buildUptimeBarsFromAlerts(
    alerts.map((a) => ({
      alert_type: a.alert_type,
      status: a.status,
      triggered_at: a.triggered_at,
      resolved_at: a.resolved_at,
    })),
    device.last_seen_at,
  );
  const pct24 = uptimePercentFromBars(bars);
  const isDown = device.status === "offline" || device.status === "degraded";
  const openCount = alerts.filter((a) => a.status === "open").length;

  const deviceAlerts = alerts.map((a) => ({
    alert_type: a.alert_type,
    status: a.status,
    triggered_at: a.triggered_at,
    resolved_at: a.resolved_at,
  }));

  const w7 = computeWindowUptime(deviceAlerts, 7, isDown, device.last_seen_at);
  const w30 = computeWindowUptime(deviceAlerts, 30, isDown, device.last_seen_at);
  const mtbf = computeMtbfDays(deviceAlerts);

  const upSince =
    device.last_seen_at && device.status === "online"
      ? formatDuration(Math.floor((Date.now() - new Date(device.last_seen_at).getTime()) / 1000))
      : isDown && device.last_seen_at
        ? `Caído desde ${formatAgo(device.last_seen_at)}`
        : "—";

  const sidebarDevices = [
    {
      id: device.id,
      hostname: device.hostname,
      ip_address: device.ip_address,
      device_type: device.device_type,
      site: device.site,
      status: device.status,
      last_seen_at: device.last_seen_at,
      cpu_pct: null,
      mem_pct: null,
      rtt_ms: null,
      open_alerts: openCount,
      heartbeat_timeout_secs: device.heartbeat_timeout_secs,
    },
  ];

  const sidebarAlerts = alerts.map((a) => ({
    ...a,
    hostname: device.hostname,
    device_id: device.id,
  }));

  const useCompact = compact || hideHeader;

  return (
    <>
      {!hideHeader && (
        <div className="ut-toolbar">
          <header className="ut-header" style={{ marginBottom: 0 }}>
            <Link to="/noc" className="ut-header__back">
              ← Centro NOC
            </Link>
            <h1 className="ut-header__title">{device.hostname}</h1>
            <p className="ut-header__subtitle">
              {[stripCidr(device.ip_address), device.device_type, device.site, device.agent_version && `agente v${device.agent_version}`]
                .filter(Boolean)
                .join(" · ")}
            </p>
          </header>
          <button
            type="button"
            className="ut-btn ut-btn--outline ut-btn--sm"
            onClick={onRefresh}
            disabled={refreshing}
          >
            <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} aria-hidden />
            Actualizar
          </button>
        </div>
      )}

      <div className={cn("ut-layout", useCompact && "ut-layout--salud-compact")}>
        <div className={cn("ut-main", useCompact && "ut-main--salud-compact")}>
          {thresholds}

          <section className="ut-card ut-card--compact noc-salud-status" aria-labelledby="device-status">
            <h2 id="device-status" className="ut-visually-hidden">
              Métricas de estado
            </h2>

            <div className="noc-salud-status__primary">
              <div className="noc-salud-status__cell">
                <p className="ut-card__label">Estado</p>
                <p className={cn("noc-salud-status__value", `noc-salud-status__value--${st.tone}`)}>
                  {st.label}
                </p>
                <p className="noc-salud-status__sub">{upSince}</p>
              </div>
              <div className="noc-salud-status__cell">
                <p className="ut-card__label">Último chequeo</p>
                <p className="noc-salud-status__value noc-salud-status__value--sm">
                  {formatAgo(device.last_seen_at)}
                </p>
                <p className="noc-salud-status__sub">
                  Timeout {device.heartbeat_timeout_secs}s · HB 5 min
                </p>
              </div>
              <div className="noc-salud-status__cell noc-salud-status__cell--uptime">
                <p className="ut-card__label">24 h</p>
                <p
                  className={cn(
                    "noc-salud-status__value",
                    pct24 >= 99.5 ? "noc-salud-status__value--success" : "noc-salud-status__value--warning",
                  )}
                >
                  {pct24}%
                </p>
                <UptimeBars bars={bars} compact />
              </div>
            </div>

            <div className="noc-salud-pills" aria-label="Historial">
              <span className="noc-salud-pill">
                <span className="noc-salud-pill__label">7 d</span>
                <span className={cn("noc-salud-pill__val", w7.pct >= 99.5 ? "text-emerald-400" : "text-amber-400")}>
                  {w7.pct}%
                </span>
                <span className="noc-salud-pill__meta">{w7.incidents} inc.</span>
              </span>
              <span className="noc-salud-pill">
                <span className="noc-salud-pill__label">30 d</span>
                <span className={cn("noc-salud-pill__val", w30.pct >= 99 ? "text-emerald-400" : "text-amber-400")}>
                  {w30.pct}%
                </span>
                <span className="noc-salud-pill__meta">
                  {w30.incidents > 0
                    ? `${w30.incidents} caídas · ${formatDuration(w30.downtimeSecs)}`
                    : "sin caídas"}
                </span>
              </span>
              <span className="noc-salud-pill">
                <span className="noc-salud-pill__label">Alertas</span>
                <span className={cn("noc-salud-pill__val", openCount > 0 ? "text-amber-400" : "text-emerald-400")}>
                  {openCount}
                </span>
                <span className="noc-salud-pill__meta">abiertas</span>
              </span>
              <span className="noc-salud-pill">
                <span className="noc-salud-pill__label">MTBF</span>
                <span className="noc-salud-pill__val">{mtbf != null ? `${mtbf}d` : "—"}</span>
              </span>
            </div>
          </section>

          <div className={cn("noc-metrics-grid", useCompact && "noc-metrics-grid--compact")}>
            <section className="ut-card ut-card--compact">
              <MetricChart
                title="Latencia"
                unit="ms"
                points={rttPoints}
                loading={rttLoading}
                gradientId="utRttGrad"
                lineColor="#60a5fa"
                compact={useCompact}
              />
            </section>
            <section className="ut-card ut-card--compact">
              <MetricChart
                title="CPU"
                unit="%"
                points={cpuPoints}
                loading={cpuLoading}
                gradientId="utCpuGrad"
                lineColor="#34d399"
                yTickFormatter={(v) => `${v}%`}
                compact={useCompact}
              />
            </section>
            <section className="ut-card ut-card--compact">
              <MetricChart
                title="Memoria"
                unit="%"
                points={memPoints}
                loading={memLoading}
                gradientId="utMemGrad"
                lineColor="#a78bfa"
                yTickFormatter={(v) => `${v}%`}
                compact={useCompact}
              />
            </section>
          </div>

          {!hideOperations && operations && (
            <section className="ut-card ut-card--compact ut-ops" aria-labelledby="device-ops">
              <h2 id="device-ops" className="ut-chart-head__title" style={{ marginBottom: "0.5rem" }}>
                Operaciones
              </h2>
              {operations}
            </section>
          )}
        </div>

        <UptimeSidebar
          devices={sidebarDevices}
          alerts={sidebarAlerts}
          showAgentCta={false}
          compact={useCompact}
        />
      </div>
    </>
  );
}
