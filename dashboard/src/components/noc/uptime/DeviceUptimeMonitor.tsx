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
      open_alerts: alerts.filter((a) => a.status === "open").length,
      heartbeat_timeout_secs: device.heartbeat_timeout_secs,
    },
  ];

  const sidebarAlerts = alerts.map((a) => ({
    ...a,
    hostname: device.hostname,
    device_id: device.id,
  }));

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

      <div className="ut-layout">
        <div className="ut-main">
          <section className="ut-metrics" aria-labelledby="device-status">
            <h2 id="device-status" className="ut-visually-hidden">
              Métricas de estado
            </h2>

            <article className="ut-card">
              <p className="ut-card__label">Estado actual</p>
              <p
                className={`ut-metric__value ut-metric__value--${st.tone === "muted" ? "success" : st.tone}`}
              >
                {st.label}
              </p>
              <p className="ut-metric__sub">{upSince}</p>
            </article>

            <article className="ut-card">
              <p className="ut-card__label">Último chequeo</p>
              <p className="ut-metric__value">{formatAgo(device.last_seen_at)}</p>
              <p className="ut-metric__sub">
                Timeout <strong>{device.heartbeat_timeout_secs}s</strong> · heartbeat cada{" "}
                <strong>5 min</strong>
              </p>
            </article>

            <article className="ut-card">
              <p className="ut-card__label">Últimas 24 h</p>
              <p
                className={`ut-metric__value ${pct24 >= 99.5 ? "ut-metric__value--success" : "ut-metric__value--warning"}`}
              >
                {pct24}%
              </p>
              <UptimeBars bars={bars} />
            </article>
          </section>

          <section aria-labelledby="device-history">
            <h2 id="device-history" className="ut-visually-hidden">
              Historial
            </h2>
            <div className="ut-history">
              <article className="ut-card">
                <p className="ut-card__label">7 días</p>
                <p
                  className={`ut-history__value ${w7.pct >= 99.5 ? "ut-metric__value--success" : "ut-metric__value--warning"}`}
                >
                  {w7.pct}%
                </p>
                <p className="ut-history__detail">
                  {w7.incidents} incidente{w7.incidents !== 1 ? "s" : ""}
                </p>
              </article>
              <article className="ut-card">
                <p className="ut-card__label">30 días</p>
                <p
                  className={`ut-history__value ${w30.pct >= 99 ? "ut-metric__value--success" : "ut-metric__value--warning"}`}
                >
                  {w30.pct}%
                </p>
                <p
                  className={`ut-history__detail ${w30.incidents > 0 ? "ut-history__detail--warning" : ""}`}
                >
                  {w30.incidents > 0
                    ? `${w30.incidents} caída${w30.incidents !== 1 ? "s" : ""} · ${formatDuration(w30.downtimeSecs)}`
                    : "Sin caídas registradas"}
                </p>
              </article>
              <article className="ut-card">
                <p className="ut-card__label">Alertas abiertas</p>
                <p
                  className={`ut-history__value ${alerts.filter((a) => a.status === "open").length > 0 ? "ut-metric__value--warning" : "ut-metric__value--success"}`}
                >
                  {alerts.filter((a) => a.status === "open").length}
                </p>
                <p className="ut-history__detail">{device.description ?? "Sin descripción"}</p>
              </article>
            </div>
            <div className="ut-mtbf" role="status">
              <p className="ut-mtbf__label">MTBF (Mean Time Between Failures)</p>
              <p className="ut-mtbf__value">{mtbf != null ? `${mtbf} días` : "—"}</p>
            </div>
          </section>

          {thresholds}

          <div className="noc-metrics-grid">
            <section className="ut-card">
              <MetricChart
                title="Latencia (RTT)"
                unit="ms"
                points={rttPoints}
                loading={rttLoading}
                gradientId="utRttGrad"
                lineColor="#60a5fa"
              />
            </section>
            <section className="ut-card">
              <MetricChart
                title="CPU"
                unit="%"
                points={cpuPoints}
                loading={cpuLoading}
                gradientId="utCpuGrad"
                lineColor="#34d399"
                yTickFormatter={(v) => `${v}%`}
              />
            </section>
            <section className="ut-card">
              <MetricChart
                title="Memoria"
                unit="%"
                points={memPoints}
                loading={memLoading}
                gradientId="utMemGrad"
                lineColor="#a78bfa"
                yTickFormatter={(v) => `${v}%`}
              />
            </section>
          </div>

          {!hideOperations && operations && (
            <section className="ut-card ut-ops" aria-labelledby="device-ops">
              <h2 id="device-ops" className="ut-chart-head__title" style={{ marginBottom: "0.75rem" }}>
                Operaciones
              </h2>
              {operations}
            </section>
          )}
        </div>

        <UptimeSidebar devices={sidebarDevices} alerts={sidebarAlerts} showAgentCta={false} />
      </div>
    </>
  );
}
