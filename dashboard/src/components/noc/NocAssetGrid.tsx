import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ChevronDown,
  LayoutGrid,
  List,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import type { NocDevice } from "./types";
import { DEVICE_FAMILIES, familyFor } from "./deviceFamilies";
import { NocAssetEditModal } from "./NocAssetEditModal";
import { formatAgo } from "./uptime/helpers";

type StatusFilter = "all" | "online" | "offline" | "alerting";
type GroupMode = "family" | "site" | "none";

interface Props {
  devices: NocDevice[];
  search: string;
  onSearchChange: (v: string) => void;
  onRefresh: () => void;
  refreshing: boolean;
  canManage: boolean;
  canDelete: boolean;
  onDelete?: (device: NocDevice) => void | Promise<void>;
  onAdd: () => void;
  onSaved: () => void;
  lastRefresh: Date;
}

function statusTone(d: NocDevice): "online" | "offline" | "alerting" {
  if ((d.open_alerts ?? 0) > 0) return "alerting";
  if (d.status === "offline") return "offline";
  return d.status === "online" ? "online" : "alerting";
}

function AssetCard({
  device,
  onEdit,
  onDelete,
  canManage,
  canDelete,
}: {
  device: NocDevice;
  onEdit: () => void;
  onDelete?: () => void;
  canManage: boolean;
  canDelete: boolean;
}) {
  const family = familyFor(device.device_type);
  const Icon = family.icon;
  const tone = statusTone(device);

  return (
    <article className={`noc-asset-card noc-asset-card--${tone}`} style={{ "--fam-accent": family.accent } as React.CSSProperties}>
      <div className="noc-asset-card__top">
        <span className="noc-asset-card__icon">
          <Icon size={18} aria-hidden />
        </span>
        <span className={`noc-asset-card__status noc-asset-card__status--${tone}`} title={device.status} />
        <div className="noc-asset-card__actions">
          {canManage && (
            <button type="button" className="noc-asset-icon-btn" title="Editar" onClick={onEdit}>
              <Pencil size={13} />
            </button>
          )}
          {canDelete && onDelete && (
            <button type="button" className="noc-asset-icon-btn noc-asset-icon-btn--danger" title="Eliminar" onClick={onDelete}>
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </div>

      <Link to={`/noc/${device.id}`} className="noc-asset-card__name" title={device.hostname}>
        {device.hostname}
      </Link>
      <p className="noc-asset-card__ip">{device.ip_address?.replace(/\/32$/, "") ?? "sin IP"}</p>

      <div className="noc-asset-card__meta">
        <span className="noc-asset-tag">{family.label.replace(/s$/, "")}</span>
        {device.site && <span className="noc-asset-tag noc-asset-tag--muted">{device.site}</span>}
        {!device.inventory_ack && <span className="noc-asset-tag noc-asset-tag--warn">ACK</span>}
        {(device.open_alerts ?? 0) > 0 && (
          <span className="noc-asset-tag noc-asset-tag--danger">{device.open_alerts} alertas</span>
        )}
      </div>

      <div className="noc-asset-card__metrics">
        <div className="noc-asset-metric">
          <span className="noc-asset-metric__label">CPU</span>
          <span className="noc-asset-metric__val">{device.cpu_pct != null ? `${device.cpu_pct.toFixed(0)}%` : "—"}</span>
        </div>
        <div className="noc-asset-metric">
          <span className="noc-asset-metric__label">MEM</span>
          <span className="noc-asset-metric__val">{device.mem_pct != null ? `${device.mem_pct.toFixed(0)}%` : "—"}</span>
        </div>
        <div className="noc-asset-metric">
          <span className="noc-asset-metric__label">RTT</span>
          <span className="noc-asset-metric__val">{device.rtt_ms != null ? `${device.rtt_ms.toFixed(0)}ms` : "—"}</span>
        </div>
      </div>
      <p className="noc-asset-card__seen">HB {formatAgo(device.last_seen_at)}</p>
    </article>
  );
}

export function NocAssetGrid({
  devices,
  search,
  onSearchChange,
  onRefresh,
  refreshing,
  canManage,
  canDelete,
  onDelete,
  onAdd,
  onSaved,
  lastRefresh,
}: Props) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [groupMode, setGroupMode] = useState<GroupMode>("family");
  const [layout, setLayout] = useState<"grid" | "table">("grid");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<NocDevice | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return devices.filter((d) => {
      if (statusFilter === "online" && d.status !== "online") return false;
      if (statusFilter === "offline" && d.status !== "offline") return false;
      if (statusFilter === "alerting" && (d.open_alerts ?? 0) === 0 && d.status !== "offline") return false;
      if (q) {
        const hay = `${d.hostname} ${d.ip_address ?? ""} ${d.site ?? ""} ${d.device_type}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [devices, search, statusFilter]);

  const groups = useMemo(() => {
    if (groupMode === "none") {
      return [{ key: "all", label: "Todos los activos", accent: "#22d3ee", devices: filtered }];
    }
    if (groupMode === "site") {
      const map = new Map<string, NocDevice[]>();
      for (const d of filtered) {
        const site = d.site?.trim() || "Sin sitio";
        map.set(site, [...(map.get(site) ?? []), d]);
      }
      return [...map.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([key, devs]) => ({ key, label: key, accent: "#a78bfa", devices: devs }));
    }
    return DEVICE_FAMILIES.map((f) => ({
      key: f.id,
      label: f.label,
      accent: f.accent,
      devices: filtered.filter((d) => familyFor(d.device_type).id === f.id),
    })).filter((g) => g.devices.length > 0);
  }, [filtered, groupMode]);

  const online = devices.filter((d) => d.status === "online").length;
  const offline = devices.filter((d) => d.status === "offline").length;
  const alerting = devices.filter((d) => (d.open_alerts ?? 0) > 0 || d.status === "offline").length;

  function toggle(key: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <div className="noc-asset-view">
      <div className="ut-toolbar">
        <header className="ut-header" style={{ marginBottom: 0 }}>
          <h2 className="ut-header__title" style={{ fontSize: "1.1rem" }}>Gestión de activos</h2>
          <p className="ut-header__subtitle">
            Actualizado hace {Math.round((Date.now() - lastRefresh.getTime()) / 1000)}s · {filtered.length} de {devices.length}
          </p>
        </header>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onRefresh} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} aria-hidden /> Actualizar
          </button>
          {canManage && (
            <button type="button" className="ut-btn ut-btn--sm" onClick={onAdd}>
              <Plus size={14} aria-hidden /> Agregar
            </button>
          )}
        </div>
      </div>

      <div className="noc-asset-kpis">
        <button type="button" className="noc-asset-kpi" onClick={() => setStatusFilter("all")} data-active={statusFilter === "all"}>
          <span className="noc-asset-kpi__val">{devices.length}</span>
          <span className="noc-asset-kpi__label">Total</span>
        </button>
        <button type="button" className="noc-asset-kpi noc-asset-kpi--ok" onClick={() => setStatusFilter("online")} data-active={statusFilter === "online"}>
          <span className="noc-asset-kpi__val">{online}</span>
          <span className="noc-asset-kpi__label">Online</span>
        </button>
        <button type="button" className="noc-asset-kpi noc-asset-kpi--down" onClick={() => setStatusFilter("offline")} data-active={statusFilter === "offline"}>
          <span className="noc-asset-kpi__val">{offline}</span>
          <span className="noc-asset-kpi__label">Offline</span>
        </button>
        <button type="button" className="noc-asset-kpi noc-asset-kpi--warn" onClick={() => setStatusFilter("alerting")} data-active={statusFilter === "alerting"}>
          <span className="noc-asset-kpi__val">{alerting}</span>
          <span className="noc-asset-kpi__label">En alerta</span>
        </button>
      </div>

      <div className="noc-asset-controls">
        <input
          className="ut-input"
          style={{ maxWidth: "14rem" }}
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Buscar por nombre, IP, sitio…"
          aria-label="Buscar activos"
        />
        <div className="noc-asset-seg">
          <span className="noc-asset-seg__label">Agrupar:</span>
          {(["family", "site", "none"] as GroupMode[]).map((m) => (
            <button
              key={m}
              type="button"
              className={`noc-asset-seg__btn ${groupMode === m ? "noc-asset-seg__btn--active" : ""}`}
              onClick={() => setGroupMode(m)}
            >
              {m === "family" ? "Familia" : m === "site" ? "Sitio" : "Ninguno"}
            </button>
          ))}
        </div>
        <div className="noc-asset-seg">
          <button
            type="button"
            className={`noc-asset-seg__btn ${layout === "grid" ? "noc-asset-seg__btn--active" : ""}`}
            onClick={() => setLayout("grid")}
            title="Cuadrícula"
          >
            <LayoutGrid size={14} />
          </button>
          <button
            type="button"
            className={`noc-asset-seg__btn ${layout === "table" ? "noc-asset-seg__btn--active" : ""}`}
            onClick={() => setLayout("table")}
            title="Tabla"
          >
            <List size={14} />
          </button>
        </div>
      </div>

      {groups.length === 0 && (
        <p className="noc-asset-empty">Sin activos que coincidan con los filtros.</p>
      )}

      {groups.map((g) => {
        const isCollapsed = collapsed.has(g.key);
        return (
          <section key={g.key} className="noc-asset-group">
            <button type="button" className="noc-asset-group__header" onClick={() => toggle(g.key)}>
              <ChevronDown size={16} className={isCollapsed ? "noc-asset-group__chev noc-asset-group__chev--closed" : "noc-asset-group__chev"} />
              <span className="noc-asset-group__dot" style={{ background: g.accent }} />
              <h3 className="noc-asset-group__title">{g.label}</h3>
              <span className="noc-asset-group__count">{g.devices.length}</span>
            </button>

            {!isCollapsed && layout === "grid" && (
              <div className="noc-asset-grid">
                {g.devices.map((d) => (
                  <AssetCard
                    key={d.id}
                    device={d}
                    canManage={canManage}
                    canDelete={canDelete}
                    onEdit={() => setEditing(d)}
                    onDelete={onDelete ? () => void onDelete(d) : undefined}
                  />
                ))}
              </div>
            )}

            {!isCollapsed && layout === "table" && (
              <div className="ut-table-wrap">
                <table className="ut-table">
                  <thead>
                    <tr>
                      <th>Estado</th><th>Hostname</th><th>IP</th><th>Sitio</th>
                      <th>CPU</th><th>MEM</th><th>RTT</th><th>HB</th><th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {g.devices.map((d) => {
                      const tone = statusTone(d);
                      return (
                        <tr key={d.id} className={tone !== "online" ? "noc-row--alerting" : undefined}>
                          <td><span className={`noc-asset-card__status noc-asset-card__status--${tone}`} /></td>
                          <td className="ut-table__host">{d.hostname}</td>
                          <td>{d.ip_address?.replace(/\/32$/, "") ?? "—"}</td>
                          <td>{d.site ?? "—"}</td>
                          <td>{d.cpu_pct != null ? `${d.cpu_pct.toFixed(0)}%` : "—"}</td>
                          <td>{d.mem_pct != null ? `${d.mem_pct.toFixed(0)}%` : "—"}</td>
                          <td>{d.rtt_ms != null ? `${d.rtt_ms.toFixed(0)}ms` : "—"}</td>
                          <td>{formatAgo(d.last_seen_at)}</td>
                          <td>
                            <div style={{ display: "flex", gap: "0.35rem", justifyContent: "flex-end" }}>
                              <Link to={`/noc/${d.id}`} className="ut-table__link">Detalle</Link>
                              {canManage && (
                                <button type="button" className="noc-asset-icon-btn" onClick={() => setEditing(d)} title="Editar">
                                  <Pencil size={13} />
                                </button>
                              )}
                              {canDelete && onDelete && (
                                <button type="button" className="noc-asset-icon-btn noc-asset-icon-btn--danger" onClick={() => void onDelete(d)} title="Eliminar">
                                  <Trash2 size={13} />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        );
      })}

      {editing && (
        <NocAssetEditModal
          device={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            onSaved();
          }}
        />
      )}
    </div>
  );
}
