import { Clock, Loader2, Play, Plus, ShieldAlert, Trash2 } from "lucide-react";
import type { DiscoveryJob, ScanProfile } from "@/api/discovery";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NMAP_PROFILES } from "./discoveryProfiles";
import { SCHEDULE_INTERVALS, scheduleLabel, type ScheduleMode } from "./scheduleIntervals";

export type JobFormState = {
  name: string;
  description: string;
  targets: string;
  scan_profile: ScanProfile;
  schedule_mode: ScheduleMode;
  schedule_interval_minutes: number;
  schedule_cron: string;
  schedule_enabled: boolean;
  detect_new_assets: boolean;
  open_incidents_on_unacked: boolean;
  auto_sync_ipam: boolean;
  scan_cves: boolean;
  ipam_subnet_id: string;
};

type Subnet = { id: number; cidr_block: string; region_name?: string | null };

type Props = {
  jobs: DiscoveryJob[];
  jobForm: JobFormState;
  onJobFormChange: (patch: Partial<JobFormState>) => void;
  showForm: boolean;
  onToggleForm: () => void;
  subnets: Subnet[];
  pendingCreate: boolean;
  pendingRun: boolean;
  onCreate: () => void;
  onRun: (id: number) => void;
  onDelete: (id: number) => void;
};

export function DiscoveryJobsPanel({
  jobs,
  jobForm,
  onJobFormChange,
  showForm,
  onToggleForm,
  subnets,
  pendingCreate,
  pendingRun,
  onCreate,
  onRun,
  onDelete,
}: Props) {
  const scheduledJobs = jobs.filter((j) => j.schedule_enabled);

  return (
    <div className="discovery-jobs">
      <div className="discovery-jobs__header">
        <div>
          <h3 className="text-sm font-semibold">Vigilancia programada</h3>
          <p className="text-[11px] text-muted-foreground">
            Escaneos periódicos · detecta activos nuevos · abre incidentes si falta ACK de inventario
          </p>
        </div>
        <Button variant="outline" size="sm" className="h-8 gap-1" onClick={onToggleForm}>
          <Plus className="h-3.5 w-3.5" /> Nuevo job
        </Button>
      </div>

      {scheduledJobs.length > 0 && (
        <div className="discovery-schedule-active">
          <Clock className="h-4 w-4 text-cyan-400 shrink-0" />
          <div>
            <p className="text-[11px] font-medium text-cyan-300">{scheduledJobs.length} job(s) activos</p>
            <p className="text-[10px] text-muted-foreground">
              Los escaneos programados comparan con el anterior y encolan casos <code>unknown_asset</code> para hosts sin ACK.
            </p>
          </div>
        </div>
      )}

      {showForm && (
        <form
          className="discovery-jobs__form"
          onSubmit={(e) => {
            e.preventDefault();
            onCreate();
          }}
        >
          <Input required value={jobForm.name} onChange={(e) => onJobFormChange({ name: e.target.value })} placeholder="Nombre — ej. Vigilancia LAN producción" className="h-8 text-[12px]" />
          <Input value={jobForm.targets} onChange={(e) => onJobFormChange({ targets: e.target.value })} placeholder="192.168.1.0/24" className="discovery-input obser-mono h-8 text-[12px]" />
          <select
            value={jobForm.scan_profile}
            onChange={(e) => onJobFormChange({ scan_profile: e.target.value as ScanProfile })}
            className="discovery-select h-8 text-[12px]"
          >
            {NMAP_PROFILES.map((p) => (
              <option key={p.id} value={p.id}>{p.label} — {p.short}</option>
            ))}
          </select>

          <div className="discovery-schedule-block">
            <label className="discovery-field-label">Programación</label>
            <div className="discovery-schedule-modes">
              {([
                ["interval", "Cada X tiempo"],
                ["cron", "Cron avanzado"],
                ["off", "Manual"],
              ] as const).map(([mode, label]) => (
                <button
                  key={mode}
                  type="button"
                  className={`discovery-schedule-mode ${jobForm.schedule_mode === mode ? "discovery-schedule-mode--active" : ""}`}
                  onClick={() => onJobFormChange({
                    schedule_mode: mode,
                    schedule_enabled: mode !== "off",
                  })}
                >
                  {label}
                </button>
              ))}
            </div>

            {jobForm.schedule_mode === "interval" && (
              <select
                value={jobForm.schedule_interval_minutes}
                onChange={(e) => onJobFormChange({ schedule_interval_minutes: Number(e.target.value) })}
                className="discovery-select h-8 text-[12px] mt-2"
              >
                {SCHEDULE_INTERVALS.map((i) => (
                  <option key={i.minutes} value={i.minutes}>{i.label}</option>
                ))}
              </select>
            )}

            {jobForm.schedule_mode === "cron" && (
              <Input
                value={jobForm.schedule_cron}
                onChange={(e) => onJobFormChange({ schedule_cron: e.target.value })}
                placeholder="0 2 * * *"
                className="obser-mono h-8 text-[12px] mt-2"
              />
            )}
          </div>

          <div className="discovery-governance-options">
            <label className="discovery-check">
              <input
                type="checkbox"
                checked={jobForm.detect_new_assets}
                onChange={(e) => onJobFormChange({ detect_new_assets: e.target.checked })}
              />
              Detectar activos nuevos (comparar vs escaneo anterior)
            </label>
            <label className="discovery-check">
              <input
                type="checkbox"
                checked={jobForm.open_incidents_on_unacked}
                onChange={(e) => onJobFormChange({ open_incidents_on_unacked: e.target.checked })}
              />
              <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
              Abrir incidente si activo sin ACK de inventario
            </label>
          </div>

          <label className="discovery-check">
            <input
              type="checkbox"
              checked={jobForm.scan_cves || jobForm.scan_profile === "vulnerabilities"}
              disabled={jobForm.scan_profile === "vulnerabilities"}
              onChange={(e) => onJobFormChange({ scan_cves: e.target.checked })}
            />
            Detección CVE (--script vuln)
          </label>
          <label className="discovery-check">
            <input type="checkbox" checked={jobForm.auto_sync_ipam} onChange={(e) => onJobFormChange({ auto_sync_ipam: e.target.checked })} />
            Sincronizar con IPAM
          </label>
          {jobForm.auto_sync_ipam && (
            <select value={jobForm.ipam_subnet_id} onChange={(e) => onJobFormChange({ ipam_subnet_id: e.target.value })} className="discovery-select h-8 text-[12px]">
              <option value="">Subred IPAM…</option>
              {subnets.map((s) => (
                <option key={s.id} value={s.id}>{s.cidr_block} · {s.region_name}</option>
              ))}
            </select>
          )}
          <Button type="submit" size="sm" disabled={pendingCreate} className="h-8 w-full">
            {pendingCreate ? <Loader2 className="h-4 w-4 animate-spin" /> : "Crear job de vigilancia"}
          </Button>
        </form>
      )}

      <div className="discovery-jobs__list">
        {jobs.map((j) => {
          const sched = scheduleLabel(j);
          return (
            <div key={j.id} className="discovery-job-card">
              <div>
                <p className="text-[13px] font-medium">{j.name}</p>
                <p className="obser-mono text-[10px] text-muted-foreground">{j.targets}</p>
                <p className="text-[10px] text-cyan-400/80">
                  {j.scan_profile}
                  {sched && ` · ${sched}`}
                </p>
                <div className="discovery-job-badges">
                  {j.detect_new_assets && <span className="discovery-job-badge">Delta activos</span>}
                  {j.open_incidents_on_unacked && <span className="discovery-job-badge discovery-job-badge--warn">Incidentes sin ACK</span>}
                  {j.last_run_at && (
                    <span className="discovery-job-badge discovery-job-badge--muted">
                      Último: {new Date(j.last_run_at).toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex gap-1">
                <Button variant="outline" size="sm" className="h-7 w-7 p-0" disabled={pendingRun} onClick={() => onRun(j.id)} title="Ejecutar ahora">
                  <Play className="h-3.5 w-3.5" />
                </Button>
                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-400" onClick={() => onDelete(j.id)} title="Eliminar">
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          );
        })}
        {!jobs.length && <p className="text-[11px] text-muted-foreground">Sin jobs. Cree uno para vigilancia continua de la red.</p>}
      </div>
    </div>
  );
}
