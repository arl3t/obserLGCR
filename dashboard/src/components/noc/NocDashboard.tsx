import { FormEvent, useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "@/auth/useAuth";
import { deleteNocDevice, fetchNocAlerts, fetchNocDevices } from "@/api/noc";
import type { NocAlert, NocDevice } from "./types";
import { FleetUptimeMonitor } from "./uptime/FleetUptimeMonitor";
import { NocFleetAlerts } from "./NocFleetAlerts";
import { NocHubNav, useNocHubView } from "./NocHubNav";
import { NocSitesView } from "./NocSitesView";
import { NocWallboard } from "./NocWallboard";

export type { NocDevice, NocAlert } from "./types";

function AddDeviceModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [form, setForm] = useState({
    hostname: "",
    ip_address: "",
    device_type: "server",
    site: "",
    description: "",
    heartbeat_timeout_secs: "120",
    cpu_threshold_pct: "90",
    mem_threshold_pct: "90",
    rtt_threshold_ms: "500",
    ssh_host: "",
    ssh_port: "22",
    ssh_user: "",
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    const { authFetch } = await import("@/lib/auth-fetch");
    const res = await authFetch("/api/noc/devices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...form,
        heartbeat_timeout_secs: Number(form.heartbeat_timeout_secs),
        cpu_threshold_pct: Number(form.cpu_threshold_pct),
        mem_threshold_pct: Number(form.mem_threshold_pct),
        rtt_threshold_ms: Number(form.rtt_threshold_ms),
        ssh_port: Number(form.ssh_port),
      }),
    });
    const data = await res.json();
    setSaving(false);
    if (!res.ok) {
      setError(data.error ?? "Error");
      return;
    }
    onAdded();
    onClose();
  }

  const uf = (field: string, value: string) => setForm((p) => ({ ...p, [field]: value }));
  const inp = "ut-input";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-md border border-[var(--ut-border)] bg-[var(--ut-bg-card)] shadow-xl">
        <div className="flex items-center justify-between border-b border-[var(--ut-border)] px-5 py-4">
          <h2 className="text-sm font-semibold">Agregar dispositivo</h2>
          <button type="button" onClick={onClose} className="ut-btn ut-btn--outline ut-btn--sm" aria-label="Cerrar">
            ✕
          </button>
        </div>
        <form onSubmit={submit} className="space-y-4 p-5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="ut-card__label">Hostname *</label>
              <input required value={form.hostname} onChange={(e) => uf("hostname", e.target.value)} className={inp} />
            </div>
            <div>
              <label className="ut-card__label">IP</label>
              <input value={form.ip_address} onChange={(e) => uf("ip_address", e.target.value)} className={inp} />
            </div>
            <div>
              <label className="ut-card__label">Tipo</label>
              <select value={form.device_type} onChange={(e) => uf("device_type", e.target.value)} className={inp}>
                {["server", "router", "switch", "workstation", "firewall", "other"].map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="ut-card__label">Sitio</label>
              <input value={form.site} onChange={(e) => uf("site", e.target.value)} className={inp} />
            </div>
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="ut-btn ut-btn--outline ut-btn--sm">Cancelar</button>
            <button type="submit" disabled={saving} className="ut-btn ut-btn--sm">{saving ? "Guardando…" : "Agregar"}</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function NocDashboard() {
  const { isLabMode, hasMinRole, isAuthenticated } = useAuth();
  const canAddDevices = isLabMode || hasMinRole("manager");
  const canDeleteDevices = isLabMode || isAuthenticated;
  const view = useNocHubView();
  const [params, setParams] = useSearchParams();

  const [devices, setDevices] = useState<NocDevice[]>([]);
  const [alerts, setAlerts] = useState<NocAlert[]>([]);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [refreshing, setRefreshing] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [search, setSearch] = useState("");
  const [siteDrill, setSiteDrill] = useState<string | null>(null);

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [devs, alts] = await Promise.all([
        fetchNocDevices(),
        fetchNocAlerts({ limit: 200 }),
      ]);
      setDevices(devs);
      setAlerts(alts);
      setLastRefresh(new Date());
    } finally {
      if (!silent) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refresh(true);
  }, [refresh]);

  useEffect(() => {
    const t = setInterval(() => void refresh(true), 15_000);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    const siteParam = params.get("site");
    if (siteParam && view === "sites") {
      setSiteDrill(siteParam);
    }
  }, [params, view]);

  const openAlerts = alerts.filter((a) => a.status === "open" || a.status === "ack").length;

  async function deleteDevice(device: NocDevice) {
    const label = device.hostname || device.ip_address || device.id;
    if (!window.confirm(`¿Eliminar el activo "${label}"?\n\nSe borrarán métricas, alertas y logs asociados.`)) {
      return;
    }
    try {
      await deleteNocDevice(device.id);
      toast.success(`Activo "${label}" eliminado`);
      void refresh(true);
    } catch {
      toast.error("No se pudo eliminar el activo.");
    }
  }

  function handleSiteFilter(site: string | null) {
    setSiteDrill(site);
    const next = new URLSearchParams(params);
    if (site) next.set("site", site);
    else next.delete("site");
    setParams(next, { replace: true });
  }

  return (
    <div className="noc-hub px-6 pb-6">
      <NocHubNav openAlerts={openAlerts} />

      {view === "wallboard" && <NocWallboard devices={devices} alerts={alerts} />}

      {view === "activos" && (
        <FleetUptimeMonitor
          devices={devices}
          search={search}
          onSearchChange={setSearch}
          onRefresh={() => void refresh()}
          refreshing={refreshing}
          canAddDevices={canAddDevices}
          canDeleteDevices={canDeleteDevices}
          onDeleteDevice={deleteDevice}
          onAddDevice={() => setShowAdd(true)}
          lastRefresh={lastRefresh}
        />
      )}

      {view === "alerts" && (
        <NocFleetAlerts alerts={alerts} onChanged={() => void refresh(true)} />
      )}

      {view === "sites" && (
        <NocSitesView
          devices={devices}
          siteFilter={siteDrill}
          onSiteFilter={handleSiteFilter}
        />
      )}

      {showAdd && <AddDeviceModal onClose={() => setShowAdd(false)} onAdded={() => void refresh()} />}
    </div>
  );
}
