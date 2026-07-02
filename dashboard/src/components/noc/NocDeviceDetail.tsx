import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";
import { authFetch } from "@/lib/auth-fetch";
import { useAuth } from "@/auth/useAuth";
import {
  deleteNocDevice,
  fetchNocDevice,
  fetchNocMetrics,
  type NocDeviceDetail,
} from "@/api/noc";
import { DeviceNetworkIdentity } from "@/components/noc/DeviceNetworkIdentity";
import { DeviceOperationsPanel } from "@/components/noc/DeviceOperationsPanel";
import { DeviceSoftwarePanel } from "@/components/noc/asset/DeviceSoftwarePanel";
import { DeviceInventoryAckPanel } from "@/components/noc/DeviceInventoryAckPanel";
import { DeviceThresholdsPanel } from "@/components/noc/DeviceThresholdsPanel";
import { DeviceUptimeMonitor } from "./uptime/DeviceUptimeMonitor";
import type { MetricPoint } from "./uptime/helpers";
import type { NocAlert } from "./types";

interface Log {
  id: string;
  ts: string;
  severity: string;
  source: string | null;
  message: string;
}

interface Action {
  id: string;
  action_type: string;
  payload: Record<string, unknown>;
  status: string;
  output: string | null;
  requested_by: string;
  requested_at: string;
  completed_at: string | null;
}

type AssetTab = "salud" | "inventario" | "respuesta";

export function NocDeviceDetail() {
  const { id: deviceId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { isLabMode, isAuthenticated } = useAuth();
  const canDelete = isLabMode || isAuthenticated;

  const [tab, setTab] = useState<AssetTab>("salud");
  const [device, setDevice] = useState<NocDeviceDetail | null>(null);
  const [logs, setLogs] = useState<Log[]>([]);
  const [alerts, setAlerts] = useState<NocAlert[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [rttPoints, setRttPoints] = useState<MetricPoint[]>([]);
  const [cpuPoints, setCpuPoints] = useState<MetricPoint[]>([]);
  const [memPoints, setMemPoints] = useState<MetricPoint[]>([]);
  const [metricsLoading, setMetricsLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (silent = false) => {
    if (!deviceId) return;
    if (!silent) setRefreshing(true);
    try {
      const [lr, ar, acr, dev, rtt, cpu, mem] = await Promise.all([
        authFetch(`/api/noc/devices/${deviceId}/logs`),
        authFetch(`/api/noc/alerts?device_id=${deviceId}&limit=100`),
        authFetch(`/api/noc/actions?device_id=${deviceId}`),
        fetchNocDevice(deviceId),
        fetchNocMetrics(deviceId, "rtt_ms", "24h"),
        fetchNocMetrics(deviceId, "cpu_pct", "24h"),
        fetchNocMetrics(deviceId, "mem_pct", "24h"),
      ]);
      const [lrJ, arJ, acrJ] = await Promise.all([lr.json(), ar.json(), acr.json()]);
      setLogs((lrJ.data ?? lrJ.logs) ?? []);
      setAlerts((arJ.data ?? arJ.alerts) ?? []);
      setActions((acrJ.data ?? acrJ.actions) ?? []);
      setDevice(dev);
      setRttPoints(rtt);
      setCpuPoints(cpu);
      setMemPoints(mem);
    } catch (e) {
      console.error(e);
    } finally {
      setMetricsLoading(false);
      if (!silent) setRefreshing(false);
    }
  }, [deviceId]);

  useEffect(() => {
    void load(true);
  }, [load]);

  useEffect(() => {
    if (!deviceId) return;
    const t = setInterval(() => void load(true), 20_000);
    return () => clearInterval(t);
  }, [deviceId, load]);

  async function handleDelete() {
    if (!device) return;
    const label = device.hostname || device.ip_address || device.id;
    if (!window.confirm(`¿Eliminar el activo "${label}"?\n\nSe borrarán métricas, alertas y logs asociados.`)) {
      return;
    }
    try {
      await deleteNocDevice(device.id);
      toast.success("Activo eliminado");
      navigate("/noc");
    } catch {
      toast.error("No se pudo eliminar el activo");
    }
  }

  if (!deviceId) {
    return (
      <>
        <p className="ut-sidebar__text">ID no especificado.</p>
        <Link to="/noc" className="ut-header__back">
          ← Volver
        </Link>
      </>
    );
  }

  if (!device) {
    return <p className="ut-sidebar__text px-6">Cargando dispositivo…</p>;
  }

  const openAlerts = alerts.filter((a) => a.status === "open" || a.status === "ack").length;

  return (
    <div className="px-6 pb-6">
      <div className="ut-toolbar">
        <header className="ut-header" style={{ marginBottom: 0 }}>
          <Link to="/noc" className="ut-header__back">
            ← Centro NOC
          </Link>
          <h1 className="ut-header__title">{device.hostname}</h1>
          <p className="ut-header__subtitle">
            {[device.ip_address?.replace(/\/32$/, ""), device.device_type, device.site]
              .filter(Boolean)
              .join(" · ")}
            {device.agent_version ? ` · agente v${device.agent_version}` : " · sin agente"}
          </p>
        </header>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <button
            type="button"
            className="ut-btn ut-btn--outline ut-btn--sm"
            onClick={() => void load()}
            disabled={refreshing}
          >
            Actualizar
          </button>
          {canDelete && (
            <button
              type="button"
              className="ut-btn ut-btn--outline ut-btn--sm"
              onClick={() => void handleDelete()}
              style={{ color: "var(--ut-danger)" }}
            >
              <Trash2 size={14} aria-hidden /> Eliminar activo
            </button>
          )}
        </div>
      </div>

      <nav className="noc-asset-tabs" aria-label="Secciones del activo">
        {(
          [
            ["salud", "Salud"],
            ["inventario", "Inventario"],
            ["respuesta", `Respuesta${openAlerts > 0 ? ` (${openAlerts})` : ""}`],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={`noc-asset-tabs__btn ${tab === id ? "noc-asset-tabs__btn--active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === "salud" && (
        <DeviceUptimeMonitor
          device={device}
          alerts={alerts}
          rttPoints={rttPoints}
          cpuPoints={cpuPoints}
          memPoints={memPoints}
          rttLoading={metricsLoading}
          cpuLoading={metricsLoading}
          memLoading={metricsLoading}
          onRefresh={() => void load()}
          refreshing={refreshing}
          hideOperations
          hideHeader
          compact
          thresholds={
            <DeviceThresholdsPanel
              device={device}
              onSaved={(updated) => setDevice(updated)}
            />
          }
        />
      )}

      {tab === "inventario" && (
        <div className="space-y-4">
          <DeviceInventoryAckPanel device={device} onAcknowledged={() => void load(true)} />
          <DeviceNetworkIdentity
            nocDeviceId={device.id}
            hostname={device.hostname}
            ipAddress={device.ip_address}
          />
          <DeviceSoftwarePanel nocDeviceId={device.id} hostname={device.hostname} />
        </div>
      )}

      {tab === "respuesta" && (
        <section className="ut-card ut-ops">
          <DeviceOperationsPanel
            device={device}
            logs={logs}
            alerts={alerts}
            actions={actions}
            onChanged={() => void load(true)}
          />
        </section>
      )}
    </div>
  );
}
