import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Plus, RefreshCw, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import type { NocDevice } from "../types";
import { NocStatusBadge } from "@/components/ui/NocStatusBadge";
import { formatAgo } from "./helpers";

export type FleetStatusFilter = "all" | "online" | "offline" | "alerting";

interface FleetUptimeMonitorProps {
  devices: NocDevice[];
  search: string;
  onSearchChange: (v: string) => void;
  onRefresh: () => void;
  refreshing: boolean;
  canAddDevices: boolean;
  canDeleteDevices?: boolean;
  onDeleteDevice?: (device: NocDevice) => void | Promise<void>;
  onAddDevice: () => void;
  lastRefresh: Date;
  initialSiteFilter?: string | null;
  children?: ReactNode;
}

export function FleetUptimeMonitor({
  devices,
  search,
  onSearchChange,
  onRefresh,
  refreshing,
  canAddDevices,
  canDeleteDevices = false,
  onDeleteDevice,
  onAddDevice,
  lastRefresh,
  initialSiteFilter = null,
  children,
}: FleetUptimeMonitorProps) {
  const [statusFilter, setStatusFilter] = useState<FleetStatusFilter>("all");
  const [siteFilter, setSiteFilter] = useState<string>(initialSiteFilter ?? "all");
  const [typeFilter, setTypeFilter] = useState("all");

  const sites = useMemo(() => {
    const set = new Set(devices.map((d) => d.site?.trim() || "Sin sitio"));
    return ["all", ...[...set].sort()];
  }, [devices]);

  const types = useMemo(() => {
    const set = new Set(devices.map((d) => d.device_type || "other"));
    return ["all", ...[...set].sort()];
  }, [devices]);

  const filtered = useMemo(() => {
    return devices.filter((d) => {
      const site = d.site?.trim() || "Sin sitio";
      if (siteFilter !== "all" && site !== siteFilter) return false;
      if (typeFilter !== "all" && d.device_type !== typeFilter) return false;
      if (statusFilter === "online" && d.status !== "online") return false;
      if (statusFilter === "offline" && d.status !== "offline") return false;
      if (statusFilter === "alerting" && (d.open_alerts ?? 0) === 0 && d.status !== "offline") {
        return false;
      }
      if (
        search &&
        !d.hostname.toLowerCase().includes(search.toLowerCase()) &&
        !(d.ip_address ?? "").includes(search) &&
        !(d.site ?? "").toLowerCase().includes(search.toLowerCase())
      ) {
        return false;
      }
      return true;
    });
  }, [devices, search, siteFilter, typeFilter, statusFilter]);

  const online = devices.filter((d) => d.status === "online").length;
  const offline = devices.filter((d) => d.status === "offline").length;
  const alerting = devices.filter(
    (d) => (d.open_alerts ?? 0) > 0 || d.status === "offline",
  ).length;

  return (
    <>
      <div className="ut-toolbar">
        <header className="ut-header" style={{ marginBottom: 0 }}>
          <h2 className="ut-header__title" style={{ fontSize: "1.1rem" }}>
            Activos monitoreados
          </h2>
          <p className="ut-header__subtitle">
            Actualizado hace {Math.round((Date.now() - lastRefresh.getTime()) / 1000)}s ·{" "}
            {filtered.length} de {devices.length}
          </p>
        </header>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button
            type="button"
            className="ut-btn ut-btn--outline ut-btn--sm"
            onClick={onRefresh}
            disabled={refreshing}
          >
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

      <div style={{ display: "flex", gap: "1rem", marginBottom: "1.25rem", flexWrap: "wrap" }}>
        <article
          className="ut-card"
          style={{ minWidth: "7rem", cursor: "pointer" }}
          onClick={() => setStatusFilter("all")}
        >
          <p className="ut-card__label">Activos</p>
          <p className="ut-metric__value">{devices.length}</p>
        </article>
        <article
          className="ut-card"
          style={{ minWidth: "7rem", cursor: "pointer" }}
          onClick={() => setStatusFilter("online")}
        >
          <p className="ut-card__label">Online</p>
          <p className="ut-metric__value ut-metric__value--success">{online}</p>
        </article>
        <article
          className={`ut-card ${offline > 0 ? "noc-metric--critical" : ""}`}
          style={{ minWidth: "7rem", cursor: "pointer" }}
          onClick={() => setStatusFilter("offline")}
        >
          <p className="ut-card__label">Offline</p>
          <p className="ut-metric__value ut-metric__value--danger">{offline}</p>
        </article>
        <article
          className={`ut-card ${alerting > 0 ? "noc-metric--critical" : ""}`}
          style={{ minWidth: "7rem", cursor: "pointer" }}
          onClick={() => setStatusFilter("alerting")}
        >
          <p className="ut-card__label">En alerta</p>
          <p className="ut-metric__value ut-metric__value--warning">{alerting}</p>
        </article>
      </div>

      <section className="ut-card" aria-labelledby="fleet-devices">
        <div className="ut-chart-head">
          <h2 id="fleet-devices" className="ut-chart-head__title">
            Activos monitoreados
          </h2>
          <div className="noc-fleet-filters">
            <input
              className="ut-input"
              style={{ width: "10rem" }}
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Buscar…"
              aria-label="Buscar dispositivos"
            />
            <select
              className="ut-input"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as FleetStatusFilter)}
              aria-label="Filtrar por estado"
            >
              <option value="all">Todos los estados</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="alerting">En alerta</option>
            </select>
            <select
              className="ut-input"
              value={siteFilter}
              onChange={(e) => setSiteFilter(e.target.value)}
              aria-label="Filtrar por sitio"
            >
              {sites.map((s) => (
                <option key={s} value={s}>
                  {s === "all" ? "Todos los sitios" : s}
                </option>
              ))}
            </select>
            <select
              className="ut-input"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              aria-label="Filtrar por tipo"
            >
              {types.map((t) => (
                <option key={t} value={t}>
                  {t === "all" ? "Todos los tipos" : t}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="ut-table-wrap">
          <table className="ut-table">
            <thead>
              <tr>
                <th>Estado</th>
                <th>Hostname</th>
                <th>IP</th>
                <th>Sitio</th>
                <th>Tipo</th>
                <th>CPU</th>
                <th>Mem</th>
                <th>RTT</th>
                <th>Último HB</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{ textAlign: "center", padding: "2rem" }}>
                    Sin dispositivos que coincidan
                  </td>
                </tr>
              ) : (
                filtered.map((d) => (
                  <tr
                    key={d.id}
                    className={
                      d.status === "offline" || (d.open_alerts ?? 0) > 0
                        ? "noc-row--alerting"
                        : undefined
                    }
                  >
                    <td>
                      <NocStatusBadge
                        status={d.status}
                        label={
                          d.status === "online"
                            ? "Online"
                            : d.status === "offline"
                              ? "Offline"
                              : d.status
                        }
                      />
                    </td>
                    <td className="ut-table__host">
                      {d.hostname}
                      {(d.open_alerts ?? 0) > 0 && (
                        <span className="noc-fleet-alert-chip">{d.open_alerts}</span>
                      )}
                    </td>
                    <td>{d.ip_address?.replace(/\/32$/, "") ?? "—"}</td>
                    <td>{d.site ?? "—"}</td>
                    <td>{d.device_type}</td>
                    <td>{d.cpu_pct != null ? `${d.cpu_pct.toFixed(1)}%` : "—"}</td>
                    <td>{d.mem_pct != null ? `${d.mem_pct.toFixed(1)}%` : "—"}</td>
                    <td>{d.rtt_ms != null ? `${d.rtt_ms.toFixed(0)} ms` : "—"}</td>
                    <td>{formatAgo(d.last_seen_at)}</td>
                    <td>
                      <div
                        style={{
                          display: "flex",
                          gap: "0.5rem",
                          alignItems: "center",
                          justifyContent: "flex-end",
                        }}
                      >
                        <Link to={`/noc/${d.id}`} className="ut-table__link">
                          Detalle →
                        </Link>
                        {canDeleteDevices && onDeleteDevice && (
                          <button
                            type="button"
                            className="ut-btn ut-btn--outline ut-btn--sm"
                            title={`Eliminar ${d.hostname}`}
                            aria-label={`Eliminar ${d.hostname}`}
                            onClick={() => void onDeleteDevice(d)}
                            style={{ color: "var(--ut-danger, #f87171)" }}
                          >
                            <Trash2 size={14} aria-hidden /> Eliminar
                          </button>
                        )}
                      </div>
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
