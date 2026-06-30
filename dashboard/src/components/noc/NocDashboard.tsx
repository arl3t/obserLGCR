import { FormEvent, useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { authFetch } from "@/lib/auth-fetch";
import { useAuth } from "@/auth/useAuth";
import type { NocDevice } from "./types";
import { FleetUptimeMonitor } from "./uptime/FleetUptimeMonitor";
import { NocGlobalPolicies } from "./NocGlobalPolicies";

// Re-export types for backwards compatibility
export type { NocDevice, NocAlert } from "./types";

// ─── Add Device Modal (sin cambios funcionales) ───────────────────────────────

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

// ─── Agent panel ──────────────────────────────────────────────────────────────

function AgentDownloadPanel() {
  const agents = [
    { os: "Linux", file: "/agents/obserlgcr-noc-agent-linux.sh", name: "obserlgcr-noc-agent-linux.sh", setup: "chmod +x … && sudo ./obserlgcr-noc-agent-linux.sh --setup" },
    { os: "macOS", file: "/agents/obserlgcr-noc-agent-macos.sh", name: "obserlgcr-noc-agent-macos.sh", setup: "chmod +x … && ./obserlgcr-noc-agent-macos.sh --setup" },
    { os: "Windows", file: "/agents/obserlgcr-noc-agent-windows.ps1", name: "obserlgcr-noc-agent-windows.ps1", setup: "powershell -ExecutionPolicy Bypass -File .\\… -Setup" },
  ];

  return (
    <section id="noc-agents" className="ut-card" aria-labelledby="agents-title">
      <h2 id="agents-title" className="ut-chart-head__title">Instalación del agente</h2>
      <p className="ut-sidebar__text" style={{ marginBottom: "1rem" }}>
        Heartbeat cada 5 min · credencial lab: <code>noc-agent@obserlgcr.local</code>
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {agents.map((a) => (
          <div key={a.os} className="rounded border border-[var(--ut-border-subtle)] p-3">
            <p className="ut-sidebar__title" style={{ marginBottom: "0.35rem" }}>{a.os}</p>
            <a href={a.file} download={a.name} className="ut-btn ut-btn--sm" style={{ width: "100%" }}>
              Descargar
            </a>
            <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 text-[10px] text-emerald-400">{a.setup}</pre>
          </div>
        ))}
      </div>
    </section>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export function NocDashboard() {
  const { isLabMode, hasMinRole, isAuthenticated } = useAuth();
  const canAddDevices = isLabMode || hasMinRole("manager");
  const canDeleteDevices = isLabMode || isAuthenticated;

  const [devices, setDevices] = useState<NocDevice[]>([]);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [refreshing, setRefreshing] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [search, setSearch] = useState("");

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const dr = await authFetch("/api/noc/devices");
      const drJson = await dr.json();
      const drPayload = (drJson.data ?? drJson.devices) as NocDevice[] | undefined;
      setDevices(drPayload ?? []);
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

  async function deleteDevice(device: NocDevice) {
    const label = device.hostname || device.ip_address || device.id;
    if (!window.confirm(`¿Eliminar el activo "${label}"?\n\nSe borrarán métricas, alertas y logs asociados.`)) {
      return;
    }
    const res = await authFetch(`/api/noc/devices/${device.id}`, { method: "DELETE" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      toast.error(data.error ?? "No se pudo eliminar el activo.");
      return;
    }
    toast.success(`Activo "${label}" eliminado`);
    void refresh(true);
  }

  return (
    <>
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
      >
        <AgentDownloadPanel />
      </FleetUptimeMonitor>
      <NocGlobalPolicies />
      {showAdd && <AddDeviceModal onClose={() => setShowAdd(false)} onAdded={() => void refresh()} />}
    </>
  );
}
