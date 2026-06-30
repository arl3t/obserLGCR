import {
  AlertCircle,
  CheckCircle2,
  Edit2,
  Loader2,
  Plus,
  RefreshCw,
  Router,
  Save,
  Shield,
  Trash2,
  X,
  Wifi,
  WifiOff,
  Zap,
  ZapOff,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { formatDateTimePy, formatTimePy } from "@/lib/format";
import { authFetch } from "@/lib/auth-fetch";

/* ─── Types ─────────────────────────────────────────────────────────────── */

interface SensorRow {
  sensor_ip: string;
  sensor_name: string;
  location: string;
  sensor_type: string;
  notes: string;
  enabled: boolean;
  updated_by: string;
  updated_at: string;
  network_zone: string;
  sensor_group: string;
  asset_tier: string;
  ip_address: string;
  os_platform: string;
}

interface SenderRow {
  source_ip: string;
  hostname?: string;
  log_family?: string;
  appname?: string;
  cnt?: number;
  c?: number;
}

interface WazuhAgentRow {
  agent_name: string;
  agent_id: string;
  agent_ip: string | null;
  hits: number;
}

interface FortigateDeviceRow {
  device: string;        // devname — FortiGate no expone IP de emisor (vía Vector)
  hits: number;
  unique_src_ips?: number;
  last_seen?: string;
}

interface RegistryResponse {
  ok: boolean;
  rows: SensorRow[];
  env_labels: Record<string, string>;
  error?: string;
}

interface SendersResponse {
  ok?: boolean;
  rows?: SenderRow[];
  error?: string;
}

/* ─── Constants ─────────────────────────────────────────────────────────── */

const SENSOR_TYPES = ["opnsense", "pfsense", "wazuh-agent", "vector", "otro"];

const NETWORK_ZONES = ["perimeter", "endpoint", "email", "internal", ""];
const OS_PLATFORMS  = ["linux", "windows", "freebsd", "opnsense", "fortios", "otro", ""];

const EMPTY_FORM: Omit<SensorRow, "updated_at"> = {
  sensor_ip: "",
  sensor_name: "",
  location: "",
  sensor_type: "opnsense",
  notes: "",
  enabled: true,
  updated_by: "dashboard",
  network_zone: "",
  sensor_group: "",
  asset_tier: "",
  ip_address: "",
  os_platform: "",
};

/* ─── Helpers ────────────────────────────────────────────────────────────── */

function fmtCount(n: number) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

/** Mapea log_family de Vector al tipo de sensor del registro. */
function logFamilyToSensorType(logFamily?: string): string {
  if (!logFamily) return "otro";
  if (logFamily.startsWith("opnsense")) return "opnsense";
  if (logFamily.startsWith("pfsense"))  return "pfsense";
  if (logFamily.startsWith("wazuh"))    return "wazuh-agent";
  if (logFamily.startsWith("suricata")) return "vector";
  if (logFamily.startsWith("fortigate")) return "otro";
  return "otro";
}

/** Badge de color según log_family. */
function LogFamilyBadge({ family, listener }: { family?: string; listener?: string; }) {
  const label = family ?? "—";
  const color =
    label.startsWith("opnsense") ? "text-sky-400 bg-sky-500/10 border-sky-500/20" :
    label.startsWith("wazuh")    ? "text-violet-400 bg-violet-500/10 border-violet-500/20" :
    label.startsWith("suricata") ? "text-orange-400 bg-orange-500/10 border-orange-500/20" :
    label.startsWith("fortigate")? "text-red-400 bg-red-500/10 border-red-500/20" :
                                   "text-muted-foreground bg-muted/40 border-border";
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] ${color}`}>
      {label}
      {listener && <span className="opacity-60">· {listener}</span>}
    </span>
  );
}

function fmtDate(s: string) {
  if (!s) return "—";
  try {
    return formatDateTimePy(s, {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: undefined,
    });
  } catch {
    return s;
  }
}

/* ─── SensorForm (nuevo / editar completo) ───────────────────────────────── */

function SensorForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial: typeof EMPTY_FORM;
  onSave: (data: typeof EMPTY_FORM) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const [form, setForm] = useState(initial);

  function set(key: keyof typeof EMPTY_FORM, value: string | boolean) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  return (
    <Card className="border-primary/30 bg-primary/5">
      <CardHeader className="pb-3 pt-4">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          <Router className="h-4 w-4 text-primary" />
          {initial.sensor_ip ? `Editar sensor — ${initial.sensor_ip}` : "Registrar nuevo sensor"}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">IP del sensor *</span>
            <Input
              value={form.sensor_ip}
              onChange={(e) => set("sensor_ip", e.target.value)}
              placeholder="192.168.1.1"
              disabled={!!initial.sensor_ip || saving}
              className="font-mono text-xs"
            />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">Nombre *</span>
            <Input
              value={form.sensor_name}
              onChange={(e) => set("sensor_name", e.target.value)}
              placeholder="FW-PRINCIPAL"
              disabled={saving}
              className="text-xs"
              autoFocus={!!initial.sensor_ip}
            />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">Ubicación</span>
            <Input
              value={form.location}
              onChange={(e) => set("location", e.target.value)}
              placeholder="Sede central / DMZ"
              disabled={saving}
              className="text-xs"
            />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">Tipo</span>
            <select
              value={form.sensor_type}
              onChange={(e) => set("sensor_type", e.target.value)}
              disabled={saving}
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
            >
              {SENSOR_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">Zona de red</span>
            <select
              value={form.network_zone}
              onChange={(e) => set("network_zone", e.target.value)}
              disabled={saving}
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
            >
              {NETWORK_ZONES.map((z) => (
                <option key={z} value={z}>{z || "— sin zona —"}</option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">Grupo</span>
            <Input
              value={form.sensor_group}
              onChange={(e) => set("sensor_group", e.target.value)}
              placeholder="CORE / DMZ / SUCURSAL…"
              disabled={saving}
              className="text-xs"
            />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">IP real (si difiere de sensor_ip)</span>
            <Input
              value={form.ip_address}
              onChange={(e) => set("ip_address", e.target.value)}
              placeholder="10.0.0.1"
              disabled={saving}
              className="font-mono text-xs"
            />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-medium leading-none">Tier de activo (1–3)</span>
            <Input
              value={form.asset_tier}
              onChange={(e) => set("asset_tier", e.target.value)}
              placeholder="1 = crítico, 2 = alto, 3 = medio"
              disabled={saving}
              className="font-mono text-xs"
              type="number"
              min={1}
              max={3}
            />
          </div>
          <div className="space-y-1 sm:col-span-2">
            <span className="text-xs font-medium leading-none">Plataforma OS</span>
            <select
              value={form.os_platform}
              onChange={(e) => set("os_platform", e.target.value)}
              disabled={saving}
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
            >
              {OS_PLATFORMS.map((p) => (
                <option key={p} value={p}>{p || "— no especificado —"}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="space-y-1">
          <span className="text-xs font-medium leading-none">Notas</span>
          <Input
            value={form.notes}
            onChange={(e) => set("notes", e.target.value)}
            placeholder="Descripción adicional..."
            disabled={saving}
            className="text-xs"
          />
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => set("enabled", !form.enabled)}
            disabled={saving}
            className="flex items-center gap-1.5 rounded px-2 py-1 text-xs transition-colors hover:bg-muted"
          >
            {form.enabled ? (
              <Wifi className="h-3.5 w-3.5 text-emerald-500" />
            ) : (
              <WifiOff className="h-3.5 w-3.5 text-muted-foreground" />
            )}
            {form.enabled ? "Activo" : "Inactivo"}
          </button>
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={onCancel}
            disabled={saving}
            className="h-7 gap-1 text-xs"
          >
            <X className="h-3 w-3" />
            Cancelar
          </Button>
          <Button
            size="sm"
            onClick={() => onSave(form)}
            disabled={saving || !form.sensor_ip || !form.sensor_name}
            className="h-7 gap-1 text-xs"
          >
            {saving ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <Save className="h-3 w-3" />
            )}
            Guardar
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

/* ─── InlineRename — edición rápida del nombre desde la tabla ─────────────── */

function InlineRename({
  row,
  onSave,
  onCancel,
  saving,
}: {
  row: SensorRow;
  onSave: (data: typeof EMPTY_FORM) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const [name, setName] = useState(row.sensor_name);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  function submit() {
    const trimmed = name.trim();
    if (!trimmed || trimmed === row.sensor_name) { onCancel(); return; }
    onSave({
      sensor_ip:    row.sensor_ip,
      sensor_name:  trimmed,
      location:     row.location,
      sensor_type:  row.sensor_type,
      notes:        row.notes,
      enabled:      row.enabled,
      updated_by:   "dashboard",
      network_zone: row.network_zone ?? "",
      sensor_group: row.sensor_group ?? "",
      asset_tier:   row.asset_tier   ?? "",
      ip_address:   row.ip_address   ?? "",
      os_platform:  row.os_platform  ?? "",
    });
  }

  return (
    <div className="flex items-center gap-1">
      <Input
        ref={inputRef}
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") submit();
          if (e.key === "Escape") onCancel();
        }}
        disabled={saving}
        className="h-6 w-36 py-0 text-xs font-medium"
      />
      <Button
        variant="ghost"
        size="icon"
        className="h-6 w-6 text-emerald-600 hover:bg-emerald-500/10"
        onClick={submit}
        disabled={saving || !name.trim()}
        title="Confirmar nombre"
      >
        {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
      </Button>
      <Button
        variant="ghost"
        size="icon"
        className="h-6 w-6"
        onClick={onCancel}
        disabled={saving}
        title="Cancelar"
      >
        <X className="h-3 w-3" />
      </Button>
    </div>
  );
}

/* ─── Main component ─────────────────────────────────────────────────────── */

const AUTO_DISCOVERY_INTERVAL_MS = 60_000;

export function SensorsManager() {
  const [registry, setRegistry] = useState<SensorRow[]>([]);
  const [envLabels, setEnvLabels] = useState<Record<string, string>>({});
  const [senders, setSenders] = useState<SenderRow[]>([]);
  const [wazuhAgents, setWazuhAgents] = useState<WazuhAgentRow[]>([]);
  const [fortigateDevices, setFortigateDevices] = useState<FortigateDeviceRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingIp, setEditingIp] = useState<string | null>(null);
  const [renamingIp, setRenamingIp] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [deletingIp, setDeletingIp] = useState<string | null>(null);
  const [wazuhPrefill, setWazuhPrefill] = useState<{ key: string; name: string; type: string } | null>(null);
  const [autoDiscovery, setAutoDiscovery] = useState(false);
  const [lastScan, setLastScan] = useState<Date | null>(null);
  const [registeringAll, setRegisteringAll] = useState(false);
  const autoIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  /* ── Fetch registry + senders ── */
  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const trinoPost = (id: string, params = {}) =>
        authFetch("/api/trino/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id, params }),
        });

      const [regRes, sndRes, wazuhRes, fgRes] = await Promise.all([
        authFetch("/api/sensors/registry"),
        trinoPost("lh.syslog.senders_24h", { limit: 20 }),
        trinoPost("lh.wazuh_alerts.active_agents_24h", { limit: 30 }),
        trinoPost("lh.fortigate.active_devices_24h", { limit: 30 }),
      ]);

      const reg: RegistryResponse = await regRes.json();
      const snd: SendersResponse = await sndRes.json();
      const wazuh: { rows?: WazuhAgentRow[] } = await wazuhRes.json();
      const fg: { rows?: FortigateDeviceRow[] } = await fgRes.json();

      if (reg.ok) {
        setRegistry(reg.rows ?? []);
        setEnvLabels(reg.env_labels ?? {});
      }
      if (snd.rows) setSenders(snd.rows);
      if (wazuh.rows) setWazuhAgents(wazuh.rows);
      if (fg.rows) setFortigateDevices(fg.rows);
      setLastScan(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  /* ── Auto-discovery polling ── */
  useEffect(() => {
    if (autoIntervalRef.current) {
      clearInterval(autoIntervalRef.current);
      autoIntervalRef.current = null;
    }
    if (autoDiscovery) {
      autoIntervalRef.current = setInterval(() => { void load(); }, AUTO_DISCOVERY_INTERVAL_MS);
    }
    return () => {
      if (autoIntervalRef.current) clearInterval(autoIntervalRef.current);
    };
  }, [autoDiscovery, load]);

  /* ── Flash message helper ── */
  function flash(ok: boolean, text: string) {
    setSaveMsg({ ok, text });
    setTimeout(() => setSaveMsg(null), 4000);
  }

  /* ── Save (upsert) ── */
  async function handleSave(form: typeof EMPTY_FORM) {
    setSaving(true);
    try {
      const res = await authFetch("/api/sensors/upsert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (data.ok) {
        flash(true, `Sensor ${form.sensor_ip} guardado correctamente.`);
        setShowForm(false);
        setEditingIp(null);
        setRenamingIp(null);
        setWazuhPrefill(null);
        await load();
      } else {
        flash(false, data.error ?? "Error desconocido.");
      }
    } catch (e) {
      flash(false, e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  /* ── Delete ── */
  async function handleDelete(ip: string) {
    if (!confirm(`¿Eliminar el sensor ${ip} del registro?`)) return;
    setDeletingIp(ip);
    try {
      const res = await authFetch(`/api/sensors/${encodeURIComponent(ip)}`, { method: "DELETE" });
      const data = await res.json();
      if (data.ok) {
        flash(true, `Sensor ${ip} eliminado.`);
        await load();
      } else {
        flash(false, data.error ?? "Error al eliminar.");
      }
    } catch (e) {
      flash(false, e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingIp(null);
    }
  }

  /* ── Register all unregistered senders at once ── */
  async function handleRegisterAll(unregistered: SenderRow[]) {
    if (!unregistered.length) return;
    setRegisteringAll(true);
    let ok = 0, fail = 0;
    for (const s of unregistered) {
      const autoName = s.hostname && s.hostname !== "—"
        ? s.hostname
        : `SENSOR-${s.source_ip}`;
      try {
        const res = await authFetch("/api/sensors/upsert", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            sensor_ip:   s.source_ip,
            sensor_name: autoName,
            location:    "",
            sensor_type: logFamilyToSensorType(s.log_family),
            notes:       "Registrado automáticamente",
            enabled:     true,
            updated_by:  "autodiscovery",
          }),
        });
        const data = await res.json();
        if (data.ok) ok++; else fail++;
      } catch { fail++; }
    }
    await load();
    flash(fail === 0, fail === 0
      ? `${ok} sensor${ok !== 1 ? "es" : ""} registrado${ok !== 1 ? "s" : ""} automáticamente.`
      : `${ok} registrado${ok !== 1 ? "s" : ""}, ${fail} fallo${fail !== 1 ? "s" : ""}.`
    );
    setRegisteringAll(false);
  }

  /* ── Derived ── */
  const registeredKeys = new Set(registry.map((r) => r.sensor_ip));
  const detectedUnregistered = senders.filter((s) => !registeredKeys.has(s.source_ip));
  // Agentes Wazuh cuyo nombre Y cuya IP (si existe) no están en el registro
  const wazuhUnregistered = wazuhAgents.filter(
    (a) => !registeredKeys.has(a.agent_name) && !(a.agent_ip && registeredKeys.has(a.agent_ip)),
  );
  // Dispositivos FortiGate (devname) que no están en el registro. FortiGate no
  // expone IP de emisor (llega vía Vector) → se identifica/registra por devname.
  const fortigateUnregistered = fortigateDevices.filter(
    (d) => !registeredKeys.has(d.device),
  );

  function getFormInitial(prefillKey?: string, opts?: { defaultName?: string; type?: string }): typeof EMPTY_FORM {
    if (!prefillKey) return { ...EMPTY_FORM };
    const existing = registry.find((r) => r.sensor_ip === prefillKey);
    if (existing) {
      return {
        sensor_ip:    existing.sensor_ip,
        sensor_name:  existing.sensor_name,
        location:     existing.location,
        sensor_type:  existing.sensor_type,
        notes:        existing.notes,
        enabled:      existing.enabled,
        updated_by:   "dashboard",
        network_zone: existing.network_zone ?? "",
        sensor_group: existing.sensor_group ?? "",
        asset_tier:   existing.asset_tier   ?? "",
        ip_address:   existing.ip_address   ?? "",
        os_platform:  existing.os_platform  ?? "",
      };
    }
    const envName = envLabels[prefillKey] ?? opts?.defaultName ?? "";
    return { ...EMPTY_FORM, sensor_ip: prefillKey, sensor_name: envName, sensor_type: opts?.type ?? "opnsense" };
  }

  const formInitial = editingIp !== null
    ? getFormInitial(editingIp, wazuhPrefill?.key === editingIp
        ? { defaultName: wazuhPrefill.name, type: wazuhPrefill.type }
        : undefined)
    : EMPTY_FORM;

  /* ─── Render ─────────────────────────────────────────────────────────── */

  function fmtLastScan(d: Date | null) {
    if (!d) return "nunca";
    const diff = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diff < 60) return `hace ${diff} s`;
    if (diff < 3600) return `hace ${Math.floor(diff / 60)} min`;
    return formatTimePy(d);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold">Registro de sensores</h2>
          <p className="text-xs text-muted-foreground">
            Asigna nombres y metadatos a las IPs que envían logs (OPNsense, pfSense, agentes
            Wazuh…). Los nombres aparecen en "Top atacantes — perímetro" y en el panel de
            investigación.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            className="h-8 gap-1.5 text-xs"
            onClick={() => void load()}
            disabled={loading}
            title="Explorar ahora"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
            Explorar
          </Button>
          <Button
            size="sm"
            className="h-8 gap-1 text-xs"
            onClick={() => {
              setEditingIp(null);
              setRenamingIp(null);
              setShowForm(true);
            }}
          >
            <Plus className="h-3.5 w-3.5" />
            Nuevo sensor
          </Button>
        </div>
      </div>

      {/* ── Auto-discovery panel ───────────────────────────────────────────── */}
      <Card className={cn(
        "border transition-colors",
        autoDiscovery ? "border-emerald-500/40 bg-emerald-500/5" : "border-dashed border-muted-foreground/30",
      )}>
        <CardContent className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="flex items-center gap-3 min-w-0">
            {autoDiscovery
              ? <Zap className="h-4 w-4 shrink-0 text-emerald-400" />
              : <ZapOff className="h-4 w-4 shrink-0 text-muted-foreground" />}
            <div className="min-w-0">
              <p className={cn("text-xs font-semibold leading-tight", autoDiscovery ? "text-emerald-300" : "text-muted-foreground")}>
                Autodescubrimiento {autoDiscovery ? "activo" : "inactivo"}
              </p>
              <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">
                {autoDiscovery
                  ? `Explorando cada 60 s · última exploración: ${fmtLastScan(lastScan)}`
                  : "Actívalo para explorar nuevos sensores automáticamente cada 60 s"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {lastScan && (
              <span className="text-[10px] text-muted-foreground">
                {fmtLastScan(lastScan)}
              </span>
            )}
            <button
              onClick={() => setAutoDiscovery((v) => !v)}
              className={cn(
                "relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus-visible:outline-none",
                autoDiscovery ? "bg-emerald-500" : "bg-muted-foreground/30",
              )}
              title={autoDiscovery ? "Desactivar autodescubrimiento" : "Activar autodescubrimiento"}
            >
              <span className={cn(
                "inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform",
                autoDiscovery ? "translate-x-4" : "translate-x-0.5",
              )} />
            </button>
          </div>
        </CardContent>
      </Card>

      {/* Flash message */}
      {saveMsg && (
        <div
          className={cn(
            "flex items-center gap-2 rounded-md border px-4 py-2 text-xs",
            saveMsg.ok
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
              : "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
          )}
        >
          {saveMsg.ok ? (
            <CheckCircle2 className="h-3.5 w-3.5" />
          ) : (
            <AlertCircle className="h-3.5 w-3.5" />
          )}
          {saveMsg.text}
        </div>
      )}

      {/* Form — nuevo o edición completa */}
      {(showForm || editingIp !== null) && (
        <SensorForm
          key={editingIp ?? "__new__"}
          initial={formInitial}
          onSave={handleSave}
          onCancel={() => {
            setShowForm(false);
            setEditingIp(null);
            setWazuhPrefill(null);
          }}
          saving={saving}
        />
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs text-red-700 dark:text-red-400">
          <AlertCircle className="h-3.5 w-3.5" />
          {error}
        </div>
      )}

      {loading && (
        <div className="flex items-center justify-center py-12 text-muted-foreground">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          Cargando…
        </div>
      )}

      {!loading && (
        <>
          {/* ── Auto-detected (not registered) ─────────────────────────── */}
          {(autoDiscovery || detectedUnregistered.length > 0) && (
            <Card className="border-amber-500/30">
              <CardHeader className="pb-2 pt-4">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <AlertCircle className="h-4 w-4 text-amber-500" />
                  Sensores detectados sin registrar
                  <Badge variant="outline" className="ml-auto text-xs">
                    {detectedUnregistered.length}
                  </Badge>
                  {detectedUnregistered.length > 1 && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-6 gap-1 border-amber-500/40 text-xs hover:bg-amber-500/10"
                      disabled={registeringAll}
                      onClick={() => void handleRegisterAll(detectedUnregistered)}
                    >
                      {registeringAll
                        ? <Loader2 className="h-3 w-3 animate-spin" />
                        : <Zap className="h-3 w-3 text-amber-500" />}
                      Registrar todos
                    </Button>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="pb-4">
                {detectedUnregistered.length === 0 ? (
                  <div className="flex items-center gap-2 py-3 text-xs text-muted-foreground">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                    Sin sensores nuevos detectados en las últimas 24 h.
                  </div>
                ) : (
                  <>
                    <p className="mb-3 text-xs text-muted-foreground">
                      Estas IPs han enviado logs en las últimas 24 h pero no tienen nombre
                      asignado. Registra individualmente o usa "Registrar todos" para asignar
                      nombres automáticos.
                    </p>
                    <div className="space-y-2">
                      {detectedUnregistered.map((s) => (
                        <div
                          key={s.source_ip}
                          className="flex flex-wrap items-center gap-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2"
                        >
                          <Router className="h-4 w-4 shrink-0 text-amber-500" />
                          <div className="flex-1 min-w-0">
                            <span className="block font-mono text-xs">{s.source_ip}</span>
                            {s.hostname && s.hostname !== "—" && (
                              <span className="text-xs text-muted-foreground">{s.hostname}</span>
                            )}
                          </div>
                          <LogFamilyBadge family={s.log_family} listener={s.appname} />
                          <span className="text-xs text-muted-foreground">
                            {fmtCount(s.cnt ?? s.c ?? 0)} eventos/24h
                          </span>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-6 gap-1 border-amber-500/40 text-xs hover:bg-amber-500/10"
                            onClick={() => {
                              setShowForm(false);
                              setRenamingIp(null);
                              setWazuhPrefill({
                                key: s.source_ip,
                                name: s.hostname && s.hostname !== "—" ? s.hostname : s.source_ip,
                                type: logFamilyToSensorType(s.log_family),
                              });
                              setEditingIp(s.source_ip);
                            }}
                          >
                            <Plus className="h-3 w-3" />
                            Registrar
                          </Button>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          )}

          {/* ── Wazuh agents unregistered ───────────────────────────────── */}
          {wazuhUnregistered.length > 0 && (
            <Card className="border-violet-500/30">
              <CardHeader className="pb-2 pt-4">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Shield className="h-4 w-4 text-violet-400" />
                  Agentes Wazuh activos sin registrar
                  <Badge variant="outline" className="ml-auto text-xs">
                    {wazuhUnregistered.length}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="pb-4">
                <p className="mb-3 text-xs text-muted-foreground">
                  Agentes Wazuh con alertas en las últimas 24 h. Regístralos para que su nombre
                  aparezca en la columna <strong>Sensor</strong> de Gestión de Casos.
                </p>
                <div className="space-y-2">
                  {wazuhUnregistered.map((a) => {
                    // Clave preferida: IP real si existe, si no el nombre del agente
                    const key = a.agent_ip ?? a.agent_name;
                    return (
                      <div
                        key={a.agent_name}
                        className="flex items-center gap-3 rounded-md border border-violet-500/20 bg-violet-500/5 px-3 py-2"
                      >
                        <Shield className="h-4 w-4 shrink-0 text-violet-400" />
                        <div className="flex-1 min-w-0">
                          <span className="block font-mono text-xs">{a.agent_name}</span>
                          <span className="text-xs text-muted-foreground">
                            ID: {a.agent_id}
                            {a.agent_ip && ` · IP: ${a.agent_ip}`}
                          </span>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {fmtCount(a.hits)} alertas/24h
                        </span>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 gap-1 border-violet-500/40 text-xs hover:bg-violet-500/10"
                          onClick={() => {
                            setShowForm(false);
                            setRenamingIp(null);
                            setEditingIp(key);
                            // Guarda el contexto Wazuh para pre-rellenar el formulario
                            setWazuhPrefill({ key, name: a.agent_name, type: "wazuh-agent" });
                          }}
                        >
                          <Plus className="h-3 w-3" />
                          Registrar
                        </Button>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

          {/* ── FortiGate devices unregistered ──────────────────────────── */}
          {fortigateUnregistered.length > 0 && (
            <Card className="border-orange-500/30">
              <CardHeader className="pb-2 pt-4">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Shield className="h-4 w-4 text-orange-400" />
                  Dispositivos FortiGate activos sin registrar
                  <Badge variant="outline" className="ml-auto text-xs">
                    {fortigateUnregistered.length}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="pb-4">
                <p className="mb-3 text-xs text-muted-foreground">
                  FortiGate que enviaron logs (bloqueos/UTM) en las últimas 24 h. Se
                  identifican por <strong>devname</strong> (la appliance no expone una IP de
                  emisor). Regístralos para nombrarlos en Gestión de Casos e investigación.
                </p>
                <div className="space-y-2">
                  {fortigateUnregistered.map((d) => (
                    <div
                      key={d.device}
                      className="flex items-center gap-3 rounded-md border border-orange-500/20 bg-orange-500/5 px-3 py-2"
                    >
                      <Shield className="h-4 w-4 shrink-0 text-orange-400" />
                      <div className="flex-1 min-w-0">
                        <span className="block font-mono text-xs">{d.device}</span>
                        <span className="text-xs text-muted-foreground">
                          FortiGate
                          {typeof d.unique_src_ips === "number" && ` · ${fmtCount(d.unique_src_ips)} IPs distintas`}
                        </span>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {fmtCount(d.hits)} eventos/24h
                      </span>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-6 gap-1 border-orange-500/40 text-xs hover:bg-orange-500/10"
                        onClick={() => {
                          setShowForm(false);
                          setRenamingIp(null);
                          setEditingIp(d.device);
                          setWazuhPrefill({ key: d.device, name: d.device, type: "fortigate" });
                        }}
                      >
                        <Plus className="h-3 w-3" />
                        Registrar
                      </Button>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* ── Registered sensors ──────────────────────────────────────── */}
          <Card>
            <CardHeader className="pb-2 pt-4">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Router className="h-4 w-4 text-primary" />
                Sensores registrados
                <Badge variant="outline" className="ml-auto text-xs">
                  {registry.length}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-4">
              {registry.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  No hay sensores registrados aún.
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">IP</TableHead>
                      <TableHead className="text-xs">Nombre</TableHead>
                      <TableHead className="hidden text-xs sm:table-cell">Tipo</TableHead>
                      <TableHead className="hidden text-xs xl:table-cell">Zona</TableHead>
                      <TableHead className="hidden text-xs xl:table-cell">Grupo</TableHead>
                      <TableHead className="hidden text-xs lg:table-cell">Ubicación</TableHead>
                      <TableHead className="hidden text-xs lg:table-cell">Actualizado</TableHead>
                      <TableHead className="text-xs">Estado</TableHead>
                      <TableHead className="text-right text-xs">Acciones</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {registry.map((row) => (
                      <TableRow key={row.sensor_ip}>
                        <TableCell className="font-mono text-xs">{row.sensor_ip}</TableCell>

                        {/* ── Nombre: inline rename o texto ── */}
                        <TableCell className="text-xs font-medium">
                          {renamingIp === row.sensor_ip ? (
                            <InlineRename
                              row={row}
                              onSave={handleSave}
                              onCancel={() => setRenamingIp(null)}
                              saving={saving}
                            />
                          ) : (
                            <button
                              className="group flex items-center gap-1 rounded px-1 py-0.5 text-left hover:bg-muted"
                              title="Haz clic para renombrar"
                              onClick={() => {
                                setShowForm(false);
                                setEditingIp(null);
                                setRenamingIp(row.sensor_ip);
                              }}
                            >
                              {row.sensor_name}
                              <Edit2 className="h-2.5 w-2.5 opacity-0 transition-opacity group-hover:opacity-50" />
                            </button>
                          )}
                        </TableCell>

                        <TableCell className="hidden text-xs text-muted-foreground sm:table-cell">
                          {row.sensor_type}
                        </TableCell>
                        <TableCell className="hidden text-xs text-muted-foreground xl:table-cell">
                          {row.network_zone || "—"}
                        </TableCell>
                        <TableCell className="hidden text-xs text-muted-foreground xl:table-cell">
                          {row.sensor_group || "—"}
                        </TableCell>
                        <TableCell className="hidden max-w-[160px] truncate text-xs text-muted-foreground lg:table-cell">
                          {row.location || "—"}
                        </TableCell>
                        <TableCell className="hidden text-xs text-muted-foreground lg:table-cell">
                          {fmtDate(row.updated_at)}
                        </TableCell>
                        <TableCell>
                          {row.enabled ? (
                            <span className="flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                              <Wifi className="h-3 w-3" />
                              Activo
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-xs text-muted-foreground">
                              <WifiOff className="h-3 w-3" />
                              Inactivo
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6"
                              title="Editar todos los campos"
                              onClick={() => {
                                setShowForm(false);
                                setRenamingIp(null);
                                setEditingIp(row.sensor_ip);
                              }}
                            >
                              <Edit2 className="h-3 w-3" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6 text-destructive hover:bg-destructive/10 hover:text-destructive"
                              title="Eliminar"
                              disabled={deletingIp === row.sensor_ip}
                              onClick={() => handleDelete(row.sensor_ip)}
                            >
                              {deletingIp === row.sensor_ip ? (
                                <Loader2 className="h-3 w-3 animate-spin" />
                              ) : (
                                <Trash2 className="h-3 w-3" />
                              )}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* ── .env hint ───────────────────────────────────────────────── */}
          {Object.keys(envLabels).length > 0 && (
            <Card className="border-dashed border-muted-foreground/30">
              <CardHeader className="pb-2 pt-3">
                <CardTitle className="text-xs text-muted-foreground">
                  Etiquetas base (.env · SENSOR_LABELS)
                </CardTitle>
              </CardHeader>
              <CardContent className="pb-3">
                <p className="mb-2 text-xs text-muted-foreground">
                  Estos nombres provienen del archivo <code>.env</code> y se usan como fallback
                  cuando la IP no está en el registro de Iceberg.
                </p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(envLabels).map(([ip, name]) => (
                    <div
                      key={ip}
                      className="flex items-center gap-1.5 rounded border border-border bg-muted/40 px-2 py-1 font-mono text-xs"
                    >
                      <span className="text-muted-foreground">{ip}</span>
                      <span className="text-foreground/70">→</span>
                      <span className="font-semibold">{name}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
