/**
 * DetectionNetworkDiscovery — módulo nmap GUI (estilo Zenmap): consola, análisis, topología, informes.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { FileText, Loader2, RefreshCw, Save } from "lucide-react";
import { toast } from "sonner";
import {
  createDiscoveryJob,
  deleteDiscoveryJob,
  downloadDiscoveryExport,
  fetchDiscoveryAlerts,
  fetchDiscoveryDelta,
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
  type ExportFormat,
  type ScanProfile,
} from "@/api/discovery";
import { fetchIpamSubnets } from "@/api/ipam";
import { DiscoveryAlertsPanel } from "@/components/discovery/DiscoveryAlertsPanel";
import { DiscoveryDeltaPanel } from "@/components/discovery/DiscoveryDeltaPanel";
import { DiscoveryHostGrid } from "@/components/discovery/DiscoveryHostGrid";
import { DiscoveryInsightsDashboard } from "@/components/discovery/DiscoveryInsightsDashboard";
import { DiscoveryJobsPanel, type JobFormState } from "@/components/discovery/DiscoveryJobsPanel";
import { DiscoveryNetworkMap } from "@/components/discovery/DiscoveryNetworkMap";
import { DiscoveryReportsPanel } from "@/components/discovery/DiscoveryReportsPanel";
import { DiscoveryRoadmap } from "@/components/discovery/DiscoveryRoadmap";
import { DiscoveryRunSidebar, type DiscoveryView } from "@/components/discovery/DiscoveryRunSidebar";
import { DiscoveryScanConsole } from "@/components/discovery/DiscoveryScanConsole";
import { DiscoveryVulnTable } from "@/components/discovery/DiscoveryVulnTable";
import { Button } from "@/components/ui/button";

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

export function DetectionNetworkDiscoveryPage() {
  const qc = useQueryClient();
  const [view, setView] = useState<DiscoveryView>("console");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [selectedHost, setSelectedHost] = useState<DiscoveryHost | null>(null);
  const [mapMode, setMapMode] = useState<"auto" | "detail" | "summary">("auto");
  const [mapCompare, setMapCompare] = useState(true);
  const [docNotes, setDocNotes] = useState("");
  const [showJobForm, setShowJobForm] = useState(false);
  const [deltaBaseId, setDeltaBaseId] = useState<number | null>(null);

  const [adhoc, setAdhoc] = useState({
    targets: "192.168.200.0/24",
    profile: "discovery" as ScanProfile,
    custom_args: "",
    name: "",
    scan_cves: false,
  });

  const [jobForm, setJobForm] = useState<JobFormState>({
    name: "",
    description: "",
    targets: "192.168.200.0/24",
    scan_profile: "discovery",
    schedule_mode: "interval",
    schedule_interval_minutes: 60,
    schedule_cron: "0 2 * * *",
    schedule_enabled: true,
    detect_new_assets: true,
    open_incidents_on_unacked: true,
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

  const alertsQ = useQuery({
    queryKey: ["discovery", "alerts", selectedRunId],
    queryFn: () => fetchDiscoveryAlerts(selectedRunId!),
    enabled: selectedRunId != null && runQ.data?.status === "completed" && view === "alerts",
  });

  const deltaQ = useQuery({
    queryKey: ["discovery", "delta", selectedRunId, deltaBaseId],
    queryFn: () => fetchDiscoveryDelta(selectedRunId!, deltaBaseId ?? undefined),
    enabled: selectedRunId != null && runQ.data?.status === "completed" && view === "delta",
  });

  useEffect(() => {
    const runs = runsQ.data ?? [];
    if (!selectedRunId && runs.length) {
      setSelectedRunId(runs[0].id);
    }
  }, [runsQ.data, selectedRunId]);

  useEffect(() => {
    if (selectedHost) setDocNotes(selectedHost.notes ?? "");
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
      setView("analytics");
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
        schedule_enabled: jobForm.schedule_mode !== "off",
        schedule_interval_minutes:
          jobForm.schedule_mode === "interval" ? jobForm.schedule_interval_minutes : undefined,
        schedule_cron:
          jobForm.schedule_mode === "cron" ? jobForm.schedule_cron.trim() || undefined : undefined,
        detect_new_assets: jobForm.detect_new_assets,
        open_incidents_on_unacked: jobForm.open_incidents_on_unacked,
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
      setView("analytics");
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

  const exportMut = useMutation({
    mutationFn: ({ runId, format }: { runId: number; format: ExportFormat }) =>
      downloadDiscoveryExport(runId, format),
    onSuccess: () => toast.success("Export descargado"),
    onError: (e) => toast.error(errMsg(e)),
  });

  const runnerOk = statusQ.data?.runner_ok;
  const scanOk = statusQ.data?.scan_available ?? false;

  const recentTargets = useMemo(
    () => [...new Set((runsQ.data ?? []).map((r) => r.targets).filter(Boolean))],
    [runsQ.data],
  );

  const vulnRows = useMemo(
    () =>
      (hostsQ.data?.data ?? []).flatMap((h) =>
        (h.vulnerabilities ?? []).map((v) => ({ ...v, host_ip: h.ip_address })),
      ),
    [hostsQ.data],
  );

  const exportRun = (format: ExportFormat) => {
    if (!selectedRunId) return;
    exportMut.mutate({ runId: selectedRunId, format });
  };

  const runInProgress = runQ.data?.status === "running" || runQ.data?.status === "pending";
  const runFailed = runQ.data?.status === "failed";
  const runCompleted = runQ.data?.status === "completed";

  return (
    <div className="discovery-nmap-gui">
      <DiscoveryRunSidebar
        view={view}
        onViewChange={setView}
        runs={runsQ.data ?? []}
        selectedRunId={selectedRunId}
        onSelectRun={setSelectedRunId}
        scanOk={scanOk}
        runnerOk={runnerOk}
        runnerConfigured={!!statusQ.data?.runner_configured}
      />

      <main className="discovery-main">
        <header className="discovery-main__header">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Descubrimiento de red</h1>
            <p className="text-[12px] text-muted-foreground">
              Escaneo nmap, análisis de superficie, topología, CVE e informes — módulo completo de reconocimiento.
            </p>
          </div>
          <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={invalidate}>
            <RefreshCw className="h-3.5 w-3.5" /> Actualizar
          </Button>
        </header>

        <div className="discovery-main__content">
          {view === "console" && (
            <DiscoveryScanConsole
              adhoc={adhoc}
              onChange={(patch) => setAdhoc((f) => ({ ...f, ...patch }))}
              profiles={profilesQ.data ?? []}
              scanAvailable={scanOk}
              pending={adhocMut.isPending}
              onScan={() => adhocMut.mutate()}
              recentTargets={recentTargets}
            />
          )}

          {view === "history" && (
            <div className="discovery-history-grid">
              <DiscoveryJobsPanel
                jobs={jobsQ.data ?? []}
                jobForm={jobForm}
                onJobFormChange={(patch) => setJobForm((f) => ({ ...f, ...patch }))}
                showForm={showJobForm}
                onToggleForm={() => setShowJobForm((v) => !v)}
                subnets={subnetsQ.data ?? []}
                pendingCreate={createJobMut.isPending}
                pendingRun={runJobMut.isPending}
                onCreate={() => createJobMut.mutate()}
                onRun={(id) => runJobMut.mutate(id)}
                onDelete={(id) => deleteJobMut.mutate(id)}
              />
              <div className="discovery-timeline">
                <h3 className="text-sm font-semibold">Timeline de escaneos</h3>
                <p className="mb-3 text-[11px] text-muted-foreground">Historial completo con duración y resultados</p>
                <div className="discovery-timeline__list">
                  {(runsQ.data ?? []).map((r) => (
                    <button
                      key={r.id}
                      type="button"
                      className={`discovery-timeline__item discovery-timeline__item--${r.status}`}
                      onClick={() => {
                        setSelectedRunId(r.id);
                        setView("analytics");
                      }}
                    >
                      <span className="discovery-timeline__dot" />
                      <div>
                        <p className="text-[12px] font-medium">#{r.id} · {r.name ?? r.scan_profile}</p>
                        <p className="obser-mono text-[10px] text-muted-foreground">{r.targets}</p>
                        <p className="text-[10px] text-muted-foreground">
                          {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                          {r.duration_ms != null && ` · ${(r.duration_ms / 1000).toFixed(1)}s`}
                          {r.status === "completed" && ` · ${r.hosts_up} hosts · ${r.ports_open} puertos`}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {view === "analytics" && (
            <>
              {runInProgress && (
                <div className="discovery-progress">
                  <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
                  <div>
                    <p className="text-sm font-medium">Escaneo #{selectedRunId} en curso</p>
                    <p className="text-[11px] text-muted-foreground">Los resultados se actualizarán automáticamente…</p>
                  </div>
                </div>
              )}
              {runFailed && (
                <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                  {runQ.data?.error_message ?? "Escaneo fallido"}
                </p>
              )}
              {!runInProgress && !runFailed && (
                <DiscoveryInsightsDashboard stats={statsQ.data} run={runQ.data} loading={statsQ.isLoading && selectedRunId != null} />
              )}
            </>
          )}

          {view === "hosts" && (
            <>
              {runInProgress ? (
                <div className="discovery-progress">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span className="text-sm text-muted-foreground">Esperando resultados…</span>
                </div>
              ) : runCompleted ? (
                <DiscoveryHostGrid
                  hosts={hostsQ.data?.data ?? []}
                  loading={hostsQ.isLoading}
                  selectedId={selectedHost?.id ?? null}
                  onSelect={setSelectedHost}
                />
              ) : (
                <p className="text-sm text-muted-foreground">Seleccione un escaneo completado.</p>
              )}
            </>
          )}

          {view === "topology" && (
            <DiscoveryNetworkMap
              topology={topoQ.data}
              loading={topoQ.isLoading}
              mode={mapMode}
              onModeChange={setMapMode}
              compareEnabled={mapCompare}
              onCompareChange={setMapCompare}
            />
          )}

          {view === "alerts" && (
            <DiscoveryAlertsPanel alerts={alertsQ.data} loading={alertsQ.isLoading && selectedRunId != null} />
          )}

          {view === "delta" && (
            <DiscoveryDeltaPanel
              delta={deltaQ.data}
              loading={deltaQ.isLoading && selectedRunId != null}
              runs={runsQ.data ?? []}
              baseRunId={deltaBaseId}
              onBaseChange={setDeltaBaseId}
              currentRunId={selectedRunId}
            />
          )}

          {view === "vulnerabilities" && (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold">Vulnerabilidades CVE</h3>
              <DiscoveryVulnTable rows={vulnRows} loading={hostsQ.isLoading} selectedHost={selectedHost} />
            </div>
          )}

          {view === "reports" && (
            <DiscoveryReportsPanel
              run={runQ.data}
              stats={statsQ.data}
              onExport={exportRun}
              exporting={exportMut.isPending}
            />
          )}

          {view === "docs" && (
            <div className="discovery-docs-grid">
              <DiscoveryHostGrid
                hosts={hostsQ.data?.data ?? []}
                loading={hostsQ.isLoading}
                selectedId={selectedHost?.id ?? null}
                onSelect={setSelectedHost}
              />
              <div className="discovery-docs-panel">
                <h3 className="mb-2 flex items-center gap-1.5 text-sm font-medium">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  Documentar activo
                </h3>
                {selectedHost ? (
                  <>
                    <p className="obser-mono text-[13px] text-cyan-300">{selectedHost.ip_address}</p>
                    {selectedHost.hostname && <p className="text-[11px] text-muted-foreground">{selectedHost.hostname}</p>}
                    <textarea
                      value={docNotes}
                      onChange={(e) => setDocNotes(e.target.value)}
                      rows={6}
                      className="discovery-textarea mt-3"
                      placeholder="Función del activo, owner, criticidad…"
                    />
                    <Button size="sm" className="mt-2 gap-1" disabled={docMut.isPending} onClick={() => docMut.mutate()}>
                      {docMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                      Guardar
                    </Button>
                  </>
                ) : (
                  <p className="text-[12px] text-muted-foreground">Seleccione un host del grid.</p>
                )}
              </div>
            </div>
          )}

          {view === "roadmap" && <DiscoveryRoadmap />}
        </div>
      </main>
    </div>
  );
}
