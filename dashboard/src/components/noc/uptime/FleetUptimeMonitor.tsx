import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Plus, RefreshCw } from "lucide-react";
import type { NocDevice } from "../types";
import { formatAgo } from "./helpers";

interface FleetUptimeMonitorProps {
  devices: NocDevice[];
  search: string;
  onSearchChange: (v: string) => void;
  onRefresh: () => void;
  refreshing: boolean;
  canAddDevices: boolean;
  onAddDevice: () => void;
  lastRefresh: Date;
  children?: ReactNode;
}

export function FleetUptimeMonitor({
  devices,
  search,
  onSearchChange,
  onRefresh,
  refreshing,
  canAddDevices,
  onAddDevice,
  lastRefresh,
  children,
}: FleetUptimeMonitorProps) {
  const filtered = devices.filter(
    (d) =>
      !search ||
      d.hostname.toLowerCase().includes(search.toLowerCase()) ||
      (d.ip_address ?? "").includes(search) ||
      (d.site ?? "").toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <div className="ut-toolbar">
        <header className="ut-header" style={{ marginBottom: 0 }}>
          <h1 className="ut-header__title">Centro de operaciones</h1>
          <p className="ut-header__subtitle">
            Actualizado hace {Math.round((Date.now() - lastRefresh.getTime()) / 1000)}s
          </p>
        </header>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onRefresh} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} aria-hidden />
            Actualizar
          </button>
          {canAddDevices && (
            <button type="button" className="ut-btn ut-btn--sm" onClick={onAddDevice}>
              <Plus size={14} aria-hidden /> Agregar
            </button>
          )}
        </div>
      </div>

      <article className="ut-card" style={{ maxWidth: "16rem", marginBottom: "1.25rem" }}>
        <p className="ut-card__label">Activos monitoreados</p>
        <p className="ut-metric__value" aria-label={`${devices.length} activos monitoreados`}>
          {devices.length}
        </p>
      </article>

      <section className="ut-card" aria-labelledby="fleet-devices">
        <div className="ut-chart-head">
          <h2 id="fleet-devices" className="ut-chart-head__title">Activos monitoreados</h2>
          <input
            className="ut-input"
            style={{ width: "12rem" }}
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Buscar…"
            aria-label="Buscar dispositivos"
          />
        </div>
        <div className="ut-table-wrap">
          <table className="ut-table">
            <thead>
              <tr>
                <th>Estado</th>
                <th>Hostname</th>
                <th>IP</th>
                <th>CPU</th>
                <th>RTT</th>
                <th>Último HB</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", padding: "2rem" }}>
                    Sin dispositivos registrados
                  </td>
                </tr>
              ) : (
                filtered.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <span
                        className={
                          d.status === "online"
                            ? "ut-metric__value--success"
                            : d.status === "offline"
                              ? "ut-metric__value--danger"
                              : "ut-metric__value--warning"
                        }
                      >
                        {d.status === "online" ? "Up" : d.status === "offline" ? "Down" : d.status}
                      </span>
                    </td>
                    <td className="ut-table__host">{d.hostname}</td>
                    <td>{d.ip_address?.replace(/\/32$/, "") ?? "—"}</td>
                    <td>{d.cpu_pct != null ? `${d.cpu_pct.toFixed(1)}%` : "—"}</td>
                    <td>{d.rtt_ms != null ? `${d.rtt_ms.toFixed(0)} ms` : "—"}</td>
                    <td>{formatAgo(d.last_seen_at)}</td>
                    <td>
                      <Link to={`/noc/${d.id}`} className="ut-table__link">
                        Detalle →
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {children}
    </>
  );
}
