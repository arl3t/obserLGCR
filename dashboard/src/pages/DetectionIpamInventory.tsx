/**
 * DetectionIpamInventory — inventario IPAM RFC 1918 (rediseño operativo).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import {
  AlertCircle,
  BarChart3,
  Globe,
  Link2,
  Loader2,
  Map,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Settings2,
  Wrench,
} from "lucide-react";
import { toast } from "sonner";
import {
  createIpamAddress,
  createIpamSubnet,
  deleteIpamAddress,
  deleteIpamSubnet,
  discoverIpamSubnetNmap,
  fetchIpamRegions,
  fetchIpamSubnetAddresses,
  fetchIpamSubnetStatistics,
  fetchIpamSubnets,
  linkNocAddress,
  linkNocSubnet,
  patchIpamAddress,
  updateIpamSubnet,
  type IpamAddress,
  type IpamAddressStatus,
  type IpamNmapDiscoverResult,
  type IpamSubnet,
} from "@/api/ipam";
import { IpamHeatmap } from "@/components/ipam/IpamHeatmap";
import { IpamRegionPanel } from "@/components/ipam/IpamRegionPanel";
import { IpamSearchPanel } from "@/components/ipam/IpamSearchPanel";
import { IpamToolsPanel } from "@/components/ipam/IpamToolsPanel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { formatNumber } from "@/lib/format";

type Tab = "inventory" | "heatmap" | "search" | "tools";

const STATUS_OPTIONS: IpamAddressStatus[] = ["Free", "Online", "Offline", "Reserved", "DHCP"];

const STATUS_PILL: Record<IpamAddressStatus, string> = {
  Online: "ipam-status-pill ipam-status-pill--online",
  Offline: "ipam-status-pill ipam-status-pill--offline",
  Reserved: "ipam-status-pill ipam-status-pill--reserved",
  Free: "ipam-status-pill ipam-status-pill--free",
  DHCP: "ipam-status-pill ipam-status-pill--dhcp",
};

const TABS: { id: Tab; label: string; icon: typeof BarChart3 }[] = [
  { id: "inventory", label: "Inventario", icon: Globe },
  { id: "heatmap", label: "Mapa calor", icon: Map },
  { id: "search", label: "Búsqueda", icon: Search },
  { id: "tools", label: "Herramientas", icon: Wrench },
];

function errMsg(e: unknown): string {
  if (isAxiosError(e)) {
    const status = e.response?.status;
    const d = e.response?.data;
    if (status === 404) {
      return "IPAM no disponible (404). Ejecute: docker compose up -d ipam dashboard";
    }
    if (d && typeof d === "object" && "detail" in d) {
      const detail = d.detail;
      if (typeof detail === "string") return detail;
      if (typeof detail === "object" && detail !== null && "message" in detail) {
        return String((detail as { message: string }).message);
      }
      if (Array.isArray(detail)) return detail.map((x) => x.msg ?? String(x)).join("; ");
    }
    return e.message;
  }
  return e instanceof Error ? e.message : "Error";
}

function IpamErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-red-500/35 bg-red-500/10 px-4 py-3 text-[13px] text-red-300">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <p className="font-medium">{message}</p>
        <p className="mt-1 text-[11px] text-red-300/80">
          Servicios: <code className="text-red-200">docker compose up -d ipam dashboard</code> · health:{" "}
          <code className="text-red-200">/api/v1/ipam/regions</code>
        </p>
      </div>
    </div>
  );
}

function UtilBar({ pct, alertPct }: { pct: number; alertPct?: number }) {
  const threshold = alertPct ?? 85;
  const tone = pct >= threshold ? "bg-red-500" : pct >= threshold * 0.8 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-muted/40">
      <div className={cn("h-full rounded-full", tone)} style={{ width: `${Math.min(pct, 100)}%` }} />
    </div>
  );
}

function SubnetChip({
  subnet,
  selected,
  onSelect,
}: {
  subnet: IpamSubnet;
  selected: boolean;
  onSelect: () => void;
}) {
  const statsQ = useQuery({
    queryKey: ["ipam", "stats", subnet.id],
    queryFn: () => fetchIpamSubnetStatistics(subnet.id),
    staleTime: 30_000,
  });

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn("ipam-subnet-chip", selected && "ipam-subnet-chip--active")}
    >
      <p className="obser-mono text-[12px] font-semibold text-cyan-300">{subnet.cidr_block}</p>
      <p className="mt-0.5 truncate text-[10px] text-muted-foreground">
        {subnet.region_name ?? `región #${subnet.region_id}`}
      </p>
      {statsQ.data && (
        <>
          <UtilBar pct={statsQ.data.utilization_percent} alertPct={statsQ.data.alert_threshold} />
          <p className="mt-1 text-[10px] text-muted-foreground">
            {statsQ.data.utilization_percent.toFixed(0)}% · {formatNumber(statsQ.data.occupied)} ocupadas
          </p>
        </>
      )}
    </button>
  );
}

function AddressRow({
  addr,
  onUpdated,
  onDelete,
}: {
  addr: IpamAddress;
  onUpdated: () => void;
  onDelete: () => void;
}) {
  const [status, setStatus] = useState(addr.status);
  const [hostname, setHostname] = useState(addr.hostname ?? "");

  const saveMut = useMutation({
    mutationFn: () =>
      patchIpamAddress(addr.id, {
        status,
        hostname: hostname.trim() || null,
      }),
    onSuccess: () => {
      toast.success(`${addr.ip_address} actualizada`);
      onUpdated();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const delMut = useMutation({
    mutationFn: () => deleteIpamAddress(addr.id),
    onSuccess: () => {
      toast.success(`${addr.ip_address} eliminada`);
      onDelete();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const linkMut = useMutation({
    mutationFn: () => linkNocAddress(addr.id),
    onSuccess: () => {
      toast.success(`NOC enlazado para ${addr.ip_address}`);
      onUpdated();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <tr className={cn("border-b border-border/50 hover:bg-cyan-500/5", addr.reservation_expired && "bg-red-500/5")}>
      <td className="obser-mono px-3 py-2.5 text-[12px]">
        {addr.ip_address}
        {addr.is_discovered_by_nmap && (
          <span className="ml-1 rounded bg-violet-500/15 px-1 text-[9px] text-violet-400">nmap</span>
        )}
        {addr.noc_device_id && (
          <span className="ml-1 rounded bg-blue-500/15 px-1 text-[9px] text-blue-400">NOC</span>
        )}
      </td>
      <td className="px-3 py-2.5">
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value as IpamAddressStatus)}
          className={cn(
            "rounded-md border border-border/60 bg-background/80 px-2 py-1 text-[11px] font-semibold",
            STATUS_PILL[status],
          )}
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </td>
      <td className="px-3 py-2.5">
        <Input value={hostname} onChange={(e) => setHostname(e.target.value)} className="h-8 text-[12px]" />
      </td>
      <td className="obser-mono hidden px-3 py-2.5 text-[11px] text-muted-foreground sm:table-cell">
        {addr.mac_address ?? "—"}
      </td>
      <td className="px-3 py-2.5">
        <div className="flex gap-1">
          <Button size="sm" variant="outline" className="h-7 text-[10px]" disabled={saveMut.isPending} onClick={() => saveMut.mutate()}>
            Guardar
          </Button>
          {!addr.noc_device_id && (
            <Button size="sm" variant="ghost" className="h-7 px-2" disabled={linkMut.isPending} onClick={() => linkMut.mutate()}>
              <Link2 className="h-3 w-3" />
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            className="h-7 text-[10px] text-red-400"
            disabled={delMut.isPending}
            onClick={() => {
              if (window.confirm(`¿Eliminar ${addr.ip_address}?`)) delMut.mutate();
            }}
          >
            Borrar
          </Button>
        </div>
      </td>
    </tr>
  );
}

export function DetectionIpamInventoryPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("inventory");
  const [selectedSubnetId, setSelectedSubnetId] = useState<number | null>(null);
  const [regionFilter, setRegionFilter] = useState<number | "">("");
  const [addrPage, setAddrPage] = useState(0);
  const [showSubnetForm, setShowSubnetForm] = useState(false);
  const [showSubnetEdit, setShowSubnetEdit] = useState(false);
  const [showAddIp, setShowAddIp] = useState(false);
  const [lastScan, setLastScan] = useState<IpamNmapDiscoverResult | null>(null);

  const [subnetForm, setSubnetForm] = useState({
    region_id: "",
    cidr_block: "192.168.200.0/24",
    vlan_id: "",
    vlan_name: "",
    description: "",
    scan_enabled: false,
    scan_cron: "",
    utilization_alert_pct: "85",
  });

  const [editForm, setEditForm] = useState({
    region_id: "",
    vlan_id: "",
    vlan_name: "",
    broadcast_domain: "",
    description: "",
    scan_enabled: false,
    scan_cron: "",
    utilization_alert_pct: "85",
  });

  const [newIp, setNewIp] = useState({
    ip: "",
    hostname: "",
    status: "Free" as IpamAddressStatus,
    expires_at: "",
  });

  const regionsQ = useQuery({ queryKey: ["ipam", "regions"], queryFn: fetchIpamRegions, retry: 1 });
  const subnetsQ = useQuery({
    queryKey: ["ipam", "subnets", regionFilter],
    queryFn: () => fetchIpamSubnets(regionFilter === "" ? undefined : regionFilter),
    retry: 1,
  });
  const addressesQ = useQuery({
    queryKey: ["ipam", "addresses", selectedSubnetId, addrPage],
    queryFn: () => fetchIpamSubnetAddresses(selectedSubnetId!, addrPage, 100),
    enabled: selectedSubnetId != null,
  });

  const selectedSubnet = useMemo(
    () => (subnetsQ.data ?? []).find((s) => s.id === selectedSubnetId) ?? null,
    [subnetsQ.data, selectedSubnetId],
  );

  const kpis = useMemo(() => {
    const regions = regionsQ.data ?? [];
    const subnets = subnetsQ.data ?? [];
    return {
      regions: regions.length,
      subnets: subnets.length,
      addresses: regions.reduce((n, r) => n + (r.address_count ?? 0), 0),
    };
  }, [regionsQ.data, subnetsQ.data]);

  const loadError = regionsQ.error ?? subnetsQ.error;
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["ipam"] });

  const createSubnetMut = useMutation({
    mutationFn: () =>
      createIpamSubnet({
        region_id: Number(subnetForm.region_id),
        cidr_block: subnetForm.cidr_block.trim(),
        vlan_id: subnetForm.vlan_id ? Number(subnetForm.vlan_id) : undefined,
        vlan_name: subnetForm.vlan_name.trim() || undefined,
        description: subnetForm.description.trim() || undefined,
        scan_enabled: subnetForm.scan_enabled,
        scan_cron: subnetForm.scan_cron.trim() || undefined,
        utilization_alert_pct: Number(subnetForm.utilization_alert_pct),
      }),
    onSuccess: (s) => {
      toast.success(`Subred ${s.cidr_block} registrada`);
      setShowSubnetForm(false);
      setSelectedSubnetId(s.id);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const updateSubnetMut = useMutation({
    mutationFn: () =>
      updateIpamSubnet(selectedSubnetId!, {
        region_id: editForm.region_id ? Number(editForm.region_id) : undefined,
        vlan_id: editForm.vlan_id ? Number(editForm.vlan_id) : null,
        vlan_name: editForm.vlan_name.trim() || null,
        broadcast_domain: editForm.broadcast_domain.trim() || null,
        description: editForm.description.trim() || null,
        scan_enabled: editForm.scan_enabled,
        scan_cron: editForm.scan_cron.trim() || null,
        utilization_alert_pct: Number(editForm.utilization_alert_pct),
      }),
    onSuccess: () => {
      toast.success("Subred actualizada");
      setShowSubnetEdit(false);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const deleteSubnetMut = useMutation({
    mutationFn: () => deleteIpamSubnet(selectedSubnetId!),
    onSuccess: () => {
      toast.success("Subred eliminada");
      setSelectedSubnetId(null);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const discoverMut = useMutation({
    mutationFn: () => discoverIpamSubnetNmap(selectedSubnetId!),
    onSuccess: (data) => {
      setLastScan(data);
      toast.success(`${data.hosts_up} activos · ${data.created} nuevos · ${data.updated} actualizados`);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const linkNocMut = useMutation({
    mutationFn: () => linkNocSubnet(selectedSubnetId!),
    onSuccess: (r) => toast.success(`${r.linked} direcciones enlazadas a NOC`),
    onError: (e) => toast.error(errMsg(e)),
  });

  const addIpMut = useMutation({
    mutationFn: () =>
      createIpamAddress(selectedSubnetId!, {
        ip_address: newIp.ip.trim(),
        status: newIp.status,
        hostname: newIp.hostname.trim() || null,
        expires_at: newIp.expires_at ? new Date(newIp.expires_at).toISOString() : null,
      }),
    onSuccess: () => {
      toast.success("IP registrada");
      setShowAddIp(false);
      setNewIp({ ip: "", hostname: "", status: "Free", expires_at: "" });
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const openSubnetEdit = () => {
    if (!selectedSubnet) return;
    setEditForm({
      region_id: String(selectedSubnet.region_id),
      vlan_id: selectedSubnet.vlan_id != null ? String(selectedSubnet.vlan_id) : "",
      vlan_name: selectedSubnet.vlan_name ?? "",
      broadcast_domain: selectedSubnet.broadcast_domain ?? "",
      description: selectedSubnet.description ?? "",
      scan_enabled: selectedSubnet.scan_enabled ?? false,
      scan_cron: selectedSubnet.scan_cron ?? "",
      utilization_alert_pct: String(selectedSubnet.utilization_alert_pct ?? 85),
    });
    setShowSubnetEdit(true);
  };

  const addrTotal = addressesQ.data?.total ?? 0;
  const addrPages = Math.max(1, Math.ceil(addrTotal / 100));

  return (
    <div className="ipam-shell mx-auto max-w-7xl p-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400/90">Detección · IPAM</p>
          <h1 className="text-xl font-semibold tracking-tight">Inventario RFC 1918</h1>
          <p className="mt-1 max-w-xl text-sm text-muted-foreground">
            Regiones, subredes privadas, descubrimiento nmap y reservas de direcciones.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="h-8 gap-1" onClick={invalidate}>
            <RefreshCw className="h-3.5 w-3.5" /> Actualizar
          </Button>
          {tab === "inventory" && (
            <Button size="sm" className="h-8 gap-1" onClick={() => setShowSubnetForm((v) => !v)}>
              <Plus className="h-3.5 w-3.5" /> Subred
            </Button>
          )}
        </div>
      </header>

      {loadError && <IpamErrorBanner message={errMsg(loadError)} />}

      <div className="ipam-kpi-grid">
        {[
          { label: "Regiones", value: kpis.regions },
          { label: "Subredes", value: kpis.subnets },
          { label: "Direcciones", value: kpis.addresses },
          { label: "Alcance", value: "RFC 1918" },
        ].map((k) => (
          <div key={k.label} className="ipam-kpi">
            <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{k.label}</p>
            <p className="obser-mono mt-1 text-lg font-semibold text-cyan-300">
              {typeof k.value === "number" ? formatNumber(k.value) : k.value}
            </p>
          </div>
        ))}
      </div>

      <nav className="ipam-tab-bar">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={cn("ipam-tab flex items-center gap-1.5", tab === id && "ipam-tab--active")}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </nav>

      {tab === "search" && <IpamSearchPanel />}
      {tab === "tools" && (
        <IpamToolsPanel subnetId={selectedSubnetId} regionId={regionFilter} errMsg={errMsg} onDone={invalidate} />
      )}

      {(tab === "inventory" || tab === "heatmap") && (
        <>
          {tab === "inventory" && showSubnetForm && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                createSubnetMut.mutate();
              }}
              className="obser-panel grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3"
            >
              <div>
                <label className="mb-1 block text-[11px] text-muted-foreground">Región</label>
                <select
                  required
                  value={subnetForm.region_id}
                  onChange={(e) => setSubnetForm((f) => ({ ...f, region_id: e.target.value }))}
                  className="w-full rounded-lg border border-border bg-background/80 px-2 py-1.5 text-[13px]"
                >
                  <option value="">Seleccionar…</option>
                  {(regionsQ.data ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-muted-foreground">CIDR</label>
                <Input
                  required
                  value={subnetForm.cidr_block}
                  onChange={(e) => setSubnetForm((f) => ({ ...f, cidr_block: e.target.value }))}
                  className="obser-mono h-9 text-[13px]"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-muted-foreground">VLAN</label>
                <Input
                  type="number"
                  value={subnetForm.vlan_id}
                  onChange={(e) => setSubnetForm((f) => ({ ...f, vlan_id: e.target.value }))}
                  className="h-9 text-[13px]"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-muted-foreground">Alerta uso %</label>
                <Input
                  type="number"
                  min={1}
                  max={100}
                  value={subnetForm.utilization_alert_pct}
                  onChange={(e) => setSubnetForm((f) => ({ ...f, utilization_alert_pct: e.target.value }))}
                  className="h-9 text-[13px]"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-muted-foreground">Cron nmap</label>
                <Input
                  placeholder="0 2 * * *"
                  value={subnetForm.scan_cron}
                  onChange={(e) => setSubnetForm((f) => ({ ...f, scan_cron: e.target.value }))}
                  className="h-9 text-[13px]"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="scan-new"
                  checked={subnetForm.scan_enabled}
                  onChange={(e) => setSubnetForm((f) => ({ ...f, scan_enabled: e.target.checked }))}
                />
                <label htmlFor="scan-new" className="text-[12px] text-muted-foreground">
                  Scan programado
                </label>
              </div>
              <div className="sm:col-span-2 lg:col-span-3 flex gap-2">
                <Button type="submit" disabled={createSubnetMut.isPending}>
                  Registrar
                </Button>
                <Button type="button" variant="outline" onClick={() => setShowSubnetForm(false)}>
                  Cancelar
                </Button>
              </div>
            </form>
          )}

          <div className="ipam-layout">
            <IpamRegionPanel
              regions={regionsQ.data ?? []}
              regionFilter={regionFilter}
              onFilter={setRegionFilter}
              errMsg={errMsg}
            />

            <div className="space-y-4">
              {subnetsQ.isLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : !(subnetsQ.data ?? []).length ? (
                <div className="obser-panel py-12 text-center text-sm text-muted-foreground">
                  Sin subredes. Cree una con «+ Subred».
                </div>
              ) : (
                <div className="ipam-subnet-rail">
                  {(subnetsQ.data ?? []).map((s) => (
                    <SubnetChip
                      key={s.id}
                      subnet={s}
                      selected={selectedSubnetId === s.id}
                      onSelect={() => {
                        setSelectedSubnetId(s.id);
                        setAddrPage(0);
                        setShowSubnetEdit(false);
                      }}
                    />
                  ))}
                </div>
              )}

              {tab === "heatmap" && selectedSubnet && (
                <div className="ipam-detail-panel">
                  <div className="ipam-detail-toolbar">
                    <p className="obser-mono text-[13px] font-medium text-cyan-300">{selectedSubnet.cidr_block}</p>
                  </div>
                  <IpamHeatmap subnetId={selectedSubnet.id} cidr={selectedSubnet.cidr_block} />
                </div>
              )}

              {tab === "inventory" && selectedSubnet && (
                <div className="ipam-detail-panel">
                  <div className="ipam-detail-toolbar">
                    <div>
                      <p className="obser-mono text-[14px] font-semibold text-cyan-300">{selectedSubnet.cidr_block}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {selectedSubnet.region_name}
                        {selectedSubnet.vlan_id != null && ` · VLAN ${selectedSubnet.vlan_id}`}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      <Button size="sm" variant="outline" className="h-8 gap-1 text-[11px]" onClick={openSubnetEdit}>
                        <Settings2 className="h-3.5 w-3.5" /> Editar
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8 gap-1 border-violet-500/40 text-[11px] text-violet-300"
                        disabled={discoverMut.isPending}
                        onClick={() => discoverMut.mutate()}
                      >
                        {discoverMut.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Radar className="h-3.5 w-3.5" />
                        )}
                        nmap
                      </Button>
                      <Button size="sm" variant="outline" className="h-8 gap-1 text-[11px]" disabled={linkNocMut.isPending} onClick={() => linkNocMut.mutate()}>
                        <Link2 className="h-3.5 w-3.5" /> NOC
                      </Button>
                      <Button size="sm" className="h-8 text-[11px]" onClick={() => setShowAddIp((v) => !v)}>
                        + IP
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-8 text-[11px] text-red-400"
                        disabled={deleteSubnetMut.isPending}
                        onClick={() => {
                          if (window.confirm(`¿Eliminar ${selectedSubnet.cidr_block}?`)) deleteSubnetMut.mutate();
                        }}
                      >
                        Eliminar
                      </Button>
                    </div>
                  </div>

                  {showSubnetEdit && (
                    <form
                      className="grid gap-2 border-b border-border/60 p-4 sm:grid-cols-2 lg:grid-cols-3"
                      onSubmit={(e) => {
                        e.preventDefault();
                        updateSubnetMut.mutate();
                      }}
                    >
                      <div>
                        <label className="mb-1 block text-[10px] text-muted-foreground">Región</label>
                        <select
                          value={editForm.region_id}
                          onChange={(e) => setEditForm((f) => ({ ...f, region_id: e.target.value }))}
                          className="w-full rounded border border-border bg-background/80 px-2 py-1 text-[12px]"
                        >
                          {(regionsQ.data ?? []).map((r) => (
                            <option key={r.id} value={r.id}>
                              {r.name}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] text-muted-foreground">VLAN</label>
                        <Input value={editForm.vlan_id} onChange={(e) => setEditForm((f) => ({ ...f, vlan_id: e.target.value }))} className="h-8 text-[12px]" />
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] text-muted-foreground">Alerta uso %</label>
                        <Input value={editForm.utilization_alert_pct} onChange={(e) => setEditForm((f) => ({ ...f, utilization_alert_pct: e.target.value }))} className="h-8 text-[12px]" />
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] text-muted-foreground">Cron nmap</label>
                        <Input value={editForm.scan_cron} onChange={(e) => setEditForm((f) => ({ ...f, scan_cron: e.target.value }))} className="h-8 text-[12px]" />
                      </div>
                      <div className="flex items-center gap-2">
                        <input type="checkbox" id="scan-edit" checked={editForm.scan_enabled} onChange={(e) => setEditForm((f) => ({ ...f, scan_enabled: e.target.checked }))} />
                        <label htmlFor="scan-edit" className="text-[11px] text-muted-foreground">
                          Scan programado
                        </label>
                      </div>
                      <div className="flex gap-2 sm:col-span-2 lg:col-span-3">
                        <Button type="submit" size="sm" disabled={updateSubnetMut.isPending}>
                          Guardar
                        </Button>
                        <Button type="button" size="sm" variant="outline" onClick={() => setShowSubnetEdit(false)}>
                          Cancelar
                        </Button>
                      </div>
                    </form>
                  )}

                  {showAddIp && (
                    <form
                      className="flex flex-wrap items-end gap-2 border-b border-border/60 p-4"
                      onSubmit={(e) => {
                        e.preventDefault();
                        addIpMut.mutate();
                      }}
                    >
                      <Input required placeholder="192.168.200.10" value={newIp.ip} onChange={(e) => setNewIp((f) => ({ ...f, ip: e.target.value }))} className="obser-mono h-8 w-36 text-[12px]" />
                      <Input placeholder="hostname" value={newIp.hostname} onChange={(e) => setNewIp((f) => ({ ...f, hostname: e.target.value }))} className="h-8 w-32 text-[12px]" />
                      <select value={newIp.status} onChange={(e) => setNewIp((f) => ({ ...f, status: e.target.value as IpamAddressStatus }))} className="h-8 rounded border border-border bg-background/80 px-2 text-[12px]">
                        {STATUS_OPTIONS.map((s) => (
                          <option key={s} value={s}>
                            {s}
                          </option>
                        ))}
                      </select>
                      <Button type="submit" size="sm" disabled={addIpMut.isPending}>
                        Añadir
                      </Button>
                    </form>
                  )}

                  {lastScan?.subnet_id === selectedSubnet.id && (
                    <div className="border-b border-border/60 px-4 py-2 text-[11px] text-muted-foreground">
                      Último nmap: {lastScan.hosts_up} activos · {(lastScan.duration_ms / 1000).toFixed(1)}s
                    </div>
                  )}

                  <div className="overflow-x-auto">
                    {addressesQ.isLoading ? (
                      <p className="p-4 text-sm text-muted-foreground">Cargando direcciones…</p>
                    ) : !(addressesQ.data?.data ?? []).length ? (
                      <p className="p-8 text-center text-[12px] text-muted-foreground">
                        Sin direcciones. Ejecute nmap o añada una IP manual.
                      </p>
                    ) : (
                      <>
                        <table className="w-full text-left">
                          <thead>
                            <tr className="border-b border-border/60 text-[10px] uppercase tracking-wide text-muted-foreground">
                              <th className="px-3 py-2">IP</th>
                              <th className="px-3 py-2">Estado</th>
                              <th className="px-3 py-2">Hostname</th>
                              <th className="hidden px-3 py-2 sm:table-cell">MAC</th>
                              <th className="px-3 py-2" />
                            </tr>
                          </thead>
                          <tbody>
                            {(addressesQ.data?.data ?? []).map((a) => (
                              <AddressRow key={a.id} addr={a} onUpdated={invalidate} onDelete={invalidate} />
                            ))}
                          </tbody>
                        </table>
                        {addrTotal > 100 && (
                          <div className="flex items-center justify-between border-t border-border/60 px-4 py-2">
                            <span className="text-[11px] text-muted-foreground">
                              {addrTotal} direcciones · pág. {addrPage + 1}/{addrPages}
                            </span>
                            <div className="flex gap-2">
                              <Button size="sm" variant="outline" className="h-7 text-[10px]" disabled={addrPage === 0} onClick={() => setAddrPage((p) => p - 1)}>
                                Anterior
                              </Button>
                              <Button size="sm" variant="outline" className="h-7 text-[10px]" disabled={addrPage + 1 >= addrPages} onClick={() => setAddrPage((p) => p + 1)}>
                                Siguiente
                              </Button>
                            </div>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              )}

              {tab === "heatmap" && !selectedSubnet && (
                <div className="obser-panel py-10 text-center text-sm text-muted-foreground">
                  Seleccione una subred en la barra superior.
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
