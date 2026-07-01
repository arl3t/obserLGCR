/**
 * DetectionNetworkDiscovery — módulo nmap completo: jobs, automatización, export, documentación, mapas.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import {
  Download,
  FileText,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Save,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import {
  createDiscoveryJob,
  deleteDiscoveryJob,
  downloadDiscoveryExport,
  fetchDiscoveryHosts,
  fetchDiscoveryJobs,
  fetchDiscoveryProfiles,
  fetchDiscoveryRun,
  fetchDiscoveryRuns,
  fetchDiscoveryStats,
  fetchDiscoveryStatus,
  fetchDiscoveryTopology,
  runAdHocDiscovery,
  runDiscoveryJob,
  updateDiscoveryHost,
  type DiscoveryHost,
  type DiscoveryRun,
  type ScanProfile,
} from "@/api/discovery";
import { fetchIpamSubnets } from "@/api/ipam";
import { DiscoveryHostGrid } from "@/components/discovery/DiscoveryHostGrid";
import { DiscoveryKpiCharts } from "@/components/discovery/DiscoveryKpiCharts";
import { DiscoveryNetworkMap } from "@/components/discovery/DiscoveryNetworkMap";
import { DiscoveryRoadmap } from "@/components/discovery/DiscoveryRoadmap";
import { DiscoveryVulnTable } from "@/components/discovery/DiscoveryVulnTable";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

type SubTab = "dashboard" | "scans" | "results" | "map" | "docs" | "roadmap";

const SUB_TABS: { id: SubTab; label: string }[] = [
  { id: "dashboard", label: "Panel" },
  { id: "scans", label: "Escaneos" },
  { id: "results", label: "Resultados" },
  { id: "map", label: "Mapa red" },
  { id: "docs", label: "Documentación" },
  { id: "roadmap", label: "Roadmap" },
];

function errMsg(e: unknown): string {
  if (isAxiosError(e)) {
    const d = e.response?.data;
    if (d && typeof d === "object" && "detail" in d) {
      const detail = d.detail;
      if (typeof detail === "string") return detail;
    }
    return e.message;
  }
  return e instanceof Error ? e.message : "Error";
}

function statusPill(status: string) {
  const cls =
    status === "completed"
      ? "discovery-status-pill discovery-status-pill--completed"
      : status === "running"
        ? "discovery-status-pill discovery-status-pill--running"
        : status === "failed"
          ? "discovery-status-pill discovery-status-pill--failed"
          : "discovery-status-pill discovery-status-pill--pending";
  return <span className={cls}>{status}</span>;
}

export function DetectionNetworkDiscoveryPage() {
  const qc = useQueryClient();
  const [subTab, setSubTab] = useState<SubTab>("dashboard");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [selectedHost, setSelectedHost] = useState<DiscoveryHost | null>(null);
  const [mapMode, setMapMode] = useState<"auto" | "detail" | "summary">("auto");
  const [mapCompare, setMapCompare] = useState(true);
  const [docNotes, setDocNotes] = useState("");
  const [showJobForm, setShowJobForm] = useState(false);

  const [adhoc, setAdhoc] = useState({
    targets: "192.168.200.0/24",
    profile: "discovery" as ScanProfile,
    custom_args: "",
    name: "",
    scan_cves: false,
  });

  const [jobForm, setJobForm] = useState({
    name: "",
    description: "",
    targets: "192.168.200.0/24",
    scan_profile: "discovery" as ScanProfile,
    schedule_cron: "0 2 * * *",
    schedule_enabled: false,
    auto_sync_ipam: false,
    scan_cves: false,
    ipam_subnet_id: "",
  });

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["discovery"] });

  const statusQ = useQuery({ queryKey: ["discovery", "status"], queryFn: fetchDiscoveryStatus, refetchInterval: 30_000 });
  const profilesQ = useQuery({ queryKey: ["discovery", "profiles"], queryFn: fetchDiscoveryProfiles });
  const jobsQ = useQuery({ queryKey: ["discovery", "jobs"], queryFn: fetchDiscoveryJobs });
  const runsQ = useQuery({ queryKey: ["discovery", "runs"], queryFn: () => fetchDiscoveryRuns(), refetchInterval: 5_000 });
  const subnetsQ = useQuery({ queryKey: ["ipam", "subnets"], queryFn: () => fetchIpamSubnets() });

  const runQ = useQuery({
    queryKey: ["discovery", "run", selectedRunId],
    queryFn: () => fetchDiscoveryRun(selectedRunId!),
    enabled: selectedRunId != null,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "pending" || s === "running" ? 3000 : false;
    },
  });

  const hostsQ = useQuery({
    queryKey: ["discovery", "hosts", selectedRunId],
    queryFn: () => fetchDiscoveryHosts(selectedRunId!, 0, 200),
    enabled: selectedRunId != null && runQ.data?.status === "completed",
  });

  const statsQ = useQuery({
    queryKey: ["discovery", "stats", selectedRunId],
    queryFn: () => fetchDiscoveryStats(selectedRunId!),
    enabled: selectedRunId != null && runQ.data?.status === "completed",
  });

  const topoQ = useQuery({
    queryKey: ["discovery", "topology", selectedRunId, mapMode, mapCompare],
    queryFn: () =>
      fetchDiscoveryTopology(selectedRunId!, {
        mode: mapMode,
        compare: mapCompare,
      }),
    enabled: selectedRunId != null && runQ.data?.status === "completed",
  });

  useEffect(() => {
    const runs = runsQ.data ?? [];
    if (!selectedRunId && runs.length) {
      setSelectedRunId(runs[0].id);
    }
  }, [runsQ.data, selectedRunId]);

  useEffect(() => {
    if (selectedHost) {
      setDocNotes(selectedHost.notes ?? "");
    }
  }, [selectedHost]);

  const adhocMut = useMutation({
    mutationFn: () =>
      runAdHocDiscovery({
        name: adhoc.name.trim() || undefined,
        targets: adhoc.targets.trim(),
        scan_profile: adhoc.profile,
        custom_args: adhoc.custom_args.trim() || undefined,
        scan_cves: adhoc.scan_cves || adhoc.profile === "vulnerabilities",
      }),
    onSuccess: (r) => {
      toast.success(`Escaneo #${r.id} iniciado`);
      setSelectedRunId(r.id);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const createJobMut = useMutation({
    mutationFn: () =>
      createDiscoveryJob({
        name: jobForm.name.trim(),
        description: jobForm.description.trim() || undefined,
        targets: jobForm.targets.trim(),
        scan_profile: jobForm.scan_profile,
        schedule_cron: jobForm.schedule_cron.trim() || undefined,
        schedule_enabled: jobForm.schedule_enabled,
        auto_sync_ipam: jobForm.auto_sync_ipam,
        scan_cves: jobForm.scan_cves || jobForm.scan_profile === "vulnerabilities",
        ipam_subnet_id: jobForm.ipam_subnet_id ? Number(jobForm.ipam_subnet_id) : undefined,
      }),
    onSuccess: () => {
      toast.success("Job creado");
      setShowJobForm(false);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const runJobMut = useMutation({
    mutationFn: runDiscoveryJob,
    onSuccess: (r) => {
      toast.success(`Job ejecutado → run #${r.id}`);
      setSelectedRunId(r.id);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const deleteJobMut = useMutation({
    mutationFn: deleteDiscoveryJob,
    onSuccess: () => {
      toast.success("Job eliminado");
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const docMut = useMutation({
    mutationFn: () =>
      updateDiscoveryHost(selectedHost!.id, {
        notes: docNotes.trim() || undefined,
        documented: true,
      }),
    onSuccess: (h) => {
      toast.success("Host documentado");
      setSelectedHost(h);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const runnerOk = statusQ.data?.runner_ok;
  const scanOk = statusQ.data?.scan_available;

  const latestCompleted = useMemo(
    () => (runsQ.data ?? []).find((r) => r.status === "completed"),
    [runsQ.data],
  );

  const vulnRows = useMemo(
    () =>
      (hostsQ.data?.data ?? []).flatMap((h) =>
        (h.vulnerabilities ?? []).map((v) => ({ ...v, host_ip: h.ip_address })),
      ),
    [hostsQ.data],
  );

  const exportMut = useMutation({
    mutationFn: ({ runId, format }: { runId: number; format: "json" | "csv" | "xml" }) =>
      downloadDiscoveryExport(runId, format),
    onSuccess: () => toast.success("Export descargado"),
    onError: (e) => toast.error(errMsg(e)),
  });

  const exportRun = (format: "json" | "csv" | "xml") => {
    if (!selectedRunId) return;
    exportMut.mutate({ runId: selectedRunId, format });
  };

  return (
    <div className="discovery-shell mx-auto max-w-7xl p-6">
      <header className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-violet-400/90">Detección · Descubrimiento</p>
          <h1 className="text-xl font-semibold tracking-tight">nmap — descubrimiento de red</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Escaneos completos, automatización cron, exportación de resultados, documentación de activos y visualización.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" className="h-8 gap-1" onClick={invalidate}>
            <RefreshCw className="h-3.5 w-3.5" /> Actualizar
          </Button>
          <Button
            size="sm"
            className="h-8 gap-1"
            disabled={adhocMut.isPending || !scanOk}
            onClick={() => adhocMut.mutate()}
          >
            {adhocMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            Escanear ahora
          </Button>
        </div>
      </header>

      <div className="mb-4 flex flex-wrap gap-2 text-[11px]">
        <span className={cn("rounded-full px-2 py-0.5", scanOk ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400")}>
          nmap {scanOk ? "OK" : "no disponible"}
        </span>
        {statusQ.data?.runner_configured && (
          <span className={cn("rounded-full px-2 py-0.5", runnerOk ? "bg-cyan-500/15 text-cyan-300" : "bg-amber-500/15 text-amber-300")}>
            host runner {runnerOk ? "conectado" : "sin conexión — python3 scripts/nmap-host-runner.py"}
          </span>
        )}
      </div>

      <nav className="discovery-tab-bar">
        {SUB_TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setSubTab(t.id)}
            className={cn("discovery-tab", subTab === t.id && "discovery-tab--active")}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {subTab === "dashboard" && (
        <div className="space-y-4">
          <form
            className="obser-panel grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4"
            onSubmit={(e) => {
              e.preventDefault();
              adhocMut.mutate();
            }}
          >
            <div className="sm:col-span-2">
              <label className="mb-1 block text-[11px] text-muted-foreground">Objetivos (IP, CIDR, lista)</label>
              <Input value={adhoc.targets} onChange={(e) => setAdhoc((f) => ({ ...f, targets: e.target.value }))} className="h-8 text-[12px]" />
            </div>
            <div>
              <label className="mb-1 block text-[11px] text-muted-foreground">Perfil nmap</label>
              <select
                value={adhoc.profile}
                onChange={(e) => setAdhoc((f) => ({ ...f, profile: e.target.value as ScanProfile }))}
                className="h-8 w-full rounded-lg border border-border bg-background/80 px-2 text-[12px]"
              >
                {(profilesQ.data ?? []).map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-[11px] text-muted-foreground">Nombre (opcional)</label>
              <Input value={adhoc.name} onChange={(e) => setAdhoc((f) => ({ ...f, name: e.target.value }))} placeholder="Scan LAN casa" className="h-8 text-[12px]" />
            </div>
            {adhoc.profile === "custom" && (
              <div className="sm:col-span-2 lg:col-span-4">
                <label className="mb-1 block text-[11px] text-muted-foreground">Args custom</label>
                <Input value={adhoc.custom_args} onChange={(e) => setAdhoc((f) => ({ ...f, custom_args: e.target.value }))} placeholder="-T4 -sV -p 80,443" className="h-8 text-[12px]" />
              </div>
            )}
            <div className="sm:col-span-2 lg:col-span-4">
              <label className="flex items-center gap-2 text-[11px]">
                <input
                  type="checkbox"
                  checked={adhoc.scan_cves || adhoc.profile === "vulnerabilities"}
                  disabled={adhoc.profile === "vulnerabilities"}
                  onChange={(e) => setAdhoc((f) => ({ ...f, scan_cves: e.target.checked }))}
                />
                Detectar CVEs (nmap --script vuln)
              </label>
              <p className="mt-1 text-[10px] text-muted-foreground">
                Con «descubrimiento» usa el perfil CVE automáticamente. Requiere scripts NSE de nmap instalados.
              </p>
            </div>
          </form>

          <DiscoveryKpiCharts stats={statsQ.data} loading={statsQ.isLoading && selectedRunId != null} />

          {latestCompleted && (
            <p className="text-[11px] text-muted-foreground">
              Último completado: #{latestCompleted.id} · {latestCompleted.targets} · {latestCompleted.hosts_up} hosts · {latestCompleted.ports_open} puertos
              {(statsQ.data?.cves_total ?? 0) > 0 && ` · ${statsQ.data?.cves_total} CVE`}
            </p>
          )}
        </div>
      )}

      {subTab === "scans" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="obser-panel p-4">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-medium">Jobs automatizados</h3>
              <Button variant="ghost" size="sm" className="h-7 gap-1 text-[11px]" onClick={() => setShowJobForm((v) => !v)}>
                <Plus className="h-3 w-3" /> Job
              </Button>
            </div>

            {showJobForm && (
              <form
                className="mb-4 space-y-2 rounded-lg border border-border/50 p-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  createJobMut.mutate();
                }}
              >
                <Input required value={jobForm.name} onChange={(e) => setJobForm((f) => ({ ...f, name: e.target.value }))} placeholder="Nombre job" className="h-8 text-[12px]" />
                <Input value={jobForm.targets} onChange={(e) => setJobForm((f) => ({ ...f, targets: e.target.value }))} placeholder="192.168.200.0/24" className="h-8 text-[12px]" />
                <select value={jobForm.scan_profile} onChange={(e) => setJobForm((f) => ({ ...f, scan_profile: e.target.value as ScanProfile }))} className="h-8 w-full rounded-lg border border-border bg-background/80 px-2 text-[12px]">
                  {(profilesQ.data ?? []).map((p) => (
                    <option key={p.id} value={p.id}>{p.label}</option>
                  ))}
                </select>
                <Input value={jobForm.schedule_cron} onChange={(e) => setJobForm((f) => ({ ...f, schedule_cron: e.target.value }))} placeholder="Cron: 0 2 * * *" className="h-8 text-[12px]" />
                <label className="flex items-center gap-2 text-[11px]">
                  <input type="checkbox" checked={jobForm.schedule_enabled} onChange={(e) => setJobForm((f) => ({ ...f, schedule_enabled: e.target.checked }))} />
                  Programar cron
                </label>
                <label className="flex items-center gap-2 text-[11px]">
                  <input
                    type="checkbox"
                    checked={jobForm.scan_cves || jobForm.scan_profile === "vulnerabilities"}
                    disabled={jobForm.scan_profile === "vulnerabilities"}
                    onChange={(e) => setJobForm((f) => ({ ...f, scan_cves: e.target.checked }))}
                  />
                  Detectar CVEs (--script vuln)
                </label>
                <label className="flex items-center gap-2 text-[11px]">
                  <input type="checkbox" checked={jobForm.auto_sync_ipam} onChange={(e) => setJobForm((f) => ({ ...f, auto_sync_ipam: e.target.checked }))} />
                  Sincronizar con IPAM
                </label>
                {jobForm.auto_sync_ipam && (
                  <select value={jobForm.ipam_subnet_id} onChange={(e) => setJobForm((f) => ({ ...f, ipam_subnet_id: e.target.value }))} className="h-8 w-full rounded-lg border border-border bg-background/80 px-2 text-[12px]">
                    <option value="">Subred IPAM…</option>
                    {(subnetsQ.data ?? []).map((s) => (
                      <option key={s.id} value={s.id}>{s.cidr_block} · {s.region_name}</option>
                    ))}
                  </select>
                )}
                <Button type="submit" size="sm" disabled={createJobMut.isPending} className="h-7 w-full text-[11px]">Crear job</Button>
              </form>
            )}

            <div className="space-y-2">
              {(jobsQ.data ?? []).map((j) => (
                <div key={j.id} className="flex items-start justify-between gap-2 rounded-lg border border-border/40 p-2">
                  <div>
                    <p className="text-[12px] font-medium">{j.name}</p>
                    <p className="text-[10px] text-muted-foreground">{j.targets} · {j.scan_profile}</p>
                    {j.schedule_enabled && <p className="text-[10px] text-cyan-400/80">cron: {j.schedule_cron}</p>}
                  </div>
                  <div className="flex gap-1">
                    <Button variant="outline" size="sm" className="h-7 px-2" disabled={runJobMut.isPending} onClick={() => runJobMut.mutate(j.id)}>
                      <Play className="h-3 w-3" />
                    </Button>
                    <Button variant="ghost" size="sm" className="h-7 px-2 text-red-400" onClick={() => deleteJobMut.mutate(j.id)}>
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              ))}
              {!jobsQ.data?.length && <p className="text-[11px] text-muted-foreground">Sin jobs. Cree uno para automatizar.</p>}
            </div>
          </div>

          <div className="obser-panel p-4">
            <h3 className="mb-3 text-sm font-medium">Historial de runs</h3>
            <div className="max-h-96 space-y-1 overflow-y-auto">
              {(runsQ.data ?? []).map((r: DiscoveryRun) => (
                <button
                  key={r.id}
                  type="button"
                  onClick={() => setSelectedRunId(r.id)}
                  className={cn(
                    "flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-left hover:bg-muted/20",
                    selectedRunId === r.id && "bg-cyan-500/10",
                  )}
                >
                  <div>
                    <p className="text-[11px] font-medium">#{r.id} {r.name ?? r.scan_profile}</p>
                    <p className="text-[10px] text-muted-foreground truncate max-w-[220px]">{r.targets}</p>
                  </div>
                  {statusPill(r.status)}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {subTab === "results" && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedRunId ?? ""}
              onChange={(e) => setSelectedRunId(Number(e.target.value))}
              className="h-8 rounded-lg border border-border bg-background/80 px-2 text-[12px]"
            >
              {(runsQ.data ?? []).map((r) => (
                <option key={r.id} value={r.id}>#{r.id} · {r.status} · {r.targets.slice(0, 40)}</option>
              ))}
            </select>
            {selectedRunId && runQ.data?.status === "completed" && (
              <>
                <Button variant="outline" size="sm" className="h-8 gap-1 text-[11px]" onClick={() => exportRun("json")}>
                  <Download className="h-3 w-3" /> JSON
                </Button>
                <Button variant="outline" size="sm" className="h-8 gap-1 text-[11px]" onClick={() => exportRun("csv")}>
                  <Download className="h-3 w-3" /> CSV
                </Button>
                <Button variant="outline" size="sm" className="h-8 gap-1 text-[11px]" onClick={() => exportRun("xml")}>
                  <Download className="h-3 w-3" /> XML nmap
                </Button>
              </>
            )}
          </div>

          {runQ.data?.status === "running" || runQ.data?.status === "pending" ? (
            <div className="flex items-center gap-2 py-12 text-sm text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              Escaneo en curso…
            </div>
          ) : runQ.data?.status === "failed" ? (
            <p className="text-sm text-red-400">{runQ.data.error_message ?? "Escaneo fallido"}</p>
          ) : (
            <div className="grid gap-4 lg:grid-cols-2">
              <DiscoveryHostGrid
                hosts={hostsQ.data?.data ?? []}
                loading={hostsQ.isLoading}
                selectedId={selectedHost?.id ?? null}
                onSelect={setSelectedHost}
              />
              <div className="space-y-3">
                <h3 className="text-sm font-medium">CVE detectados</h3>
                <DiscoveryVulnTable
                  rows={vulnRows}
                  loading={hostsQ.isLoading}
                  selectedHost={selectedHost}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {subTab === "map" && (
        <DiscoveryNetworkMap
          topology={topoQ.data}
          loading={topoQ.isLoading}
          mode={mapMode}
          onModeChange={setMapMode}
          compareEnabled={mapCompare}
          onCompareChange={setMapCompare}
        />
      )}

      {subTab === "docs" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <DiscoveryHostGrid
            hosts={hostsQ.data?.data ?? []}
            loading={hostsQ.isLoading}
            selectedId={selectedHost?.id ?? null}
            onSelect={setSelectedHost}
          />
          <div className="obser-panel p-4">
            <h3 className="mb-2 flex items-center gap-1.5 text-sm font-medium">
              <FileText className="h-4 w-4 text-cyan-400" />
              Documentar activo
            </h3>
            {selectedHost ? (
              <>
                <p className="obser-mono text-[13px] text-cyan-300">{selectedHost.ip_address}</p>
                {selectedHost.hostname && <p className="text-[11px] text-muted-foreground">{selectedHost.hostname}</p>}
                <div className="mt-3 space-y-2">
                  <label className="block text-[11px] text-muted-foreground">Notas / documentación</label>
                  <textarea
                    value={docNotes}
                    onChange={(e) => setDocNotes(e.target.value)}
                    rows={6}
                    className="w-full rounded-lg border border-border bg-background/80 p-2 text-[12px]"
                    placeholder="Función del activo, owner, criticidad, observaciones…"
                  />
                  <Button size="sm" className="gap-1" disabled={docMut.isPending} onClick={() => docMut.mutate()}>
                    {docMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                    Guardar documentación
                  </Button>
                </div>
                {selectedHost.ports.length > 0 && (
                  <div className="mt-4">
                    <p className="mb-1 text-[11px] text-muted-foreground">Puertos abiertos</p>
                    <div className="max-h-40 overflow-y-auto text-[10px]">
                      {selectedHost.ports.filter((p) => p.state === "open").map((p) => (
                        <div key={p.id} className="border-b border-border/30 py-1">
                          {p.port}/{p.protocol} · {p.service} {p.product} {p.version}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <p className="text-[12px] text-muted-foreground">Seleccione un host del grid para documentarlo.</p>
            )}
          </div>
        </div>
      )}

      {subTab === "roadmap" && <DiscoveryRoadmap />}
    </div>
  );
}
