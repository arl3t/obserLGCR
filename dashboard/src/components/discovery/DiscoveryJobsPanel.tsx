import { Loader2, Play, Plus, Trash2 } from "lucide-react";
import type { DiscoveryJob, ScanProfile } from "@/api/discovery";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NMAP_PROFILES } from "./discoveryProfiles";

export type JobFormState = {
  name: string;
  description: string;
  targets: string;
  scan_profile: ScanProfile;
  schedule_cron: string;
  schedule_enabled: boolean;
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
  return (
    <div className="discovery-jobs">
      <div className="discovery-jobs__header">
        <div>
          <h3 className="text-sm font-semibold">Jobs automatizados</h3>
          <p className="text-[11px] text-muted-foreground">Programación cron, sync IPAM, perfiles reutilizables</p>
        </div>
        <Button variant="outline" size="sm" className="h-8 gap-1" onClick={onToggleForm}>
          <Plus className="h-3.5 w-3.5" /> Nuevo job
        </Button>
      </div>

      {showForm && (
        <form
          className="discovery-jobs__form"
          onSubmit={(e) => {
            e.preventDefault();
            onCreate();
          }}
        >
          <Input required value={jobForm.name} onChange={(e) => onJobFormChange({ name: e.target.value })} placeholder="Nombre del job" className="h-8 text-[12px]" />
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
          <Input value={jobForm.schedule_cron} onChange={(e) => onJobFormChange({ schedule_cron: e.target.value })} placeholder="Cron: 0 2 * * *" className="obser-mono h-8 text-[12px]" />
          <label className="discovery-check">
            <input type="checkbox" checked={jobForm.schedule_enabled} onChange={(e) => onJobFormChange({ schedule_enabled: e.target.checked })} />
            Activar programación cron
          </label>
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
            {pendingCreate ? <Loader2 className="h-4 w-4 animate-spin" /> : "Crear job"}
          </Button>
        </form>
      )}

      <div className="discovery-jobs__list">
        {jobs.map((j) => (
          <div key={j.id} className="discovery-job-card">
            <div>
              <p className="text-[13px] font-medium">{j.name}</p>
              <p className="obser-mono text-[10px] text-muted-foreground">{j.targets}</p>
              <p className="text-[10px] text-cyan-400/80">{j.scan_profile}{j.schedule_enabled && ` · cron ${j.schedule_cron}`}</p>
            </div>
            <div className="flex gap-1">
              <Button variant="outline" size="sm" className="h-7 w-7 p-0" disabled={pendingRun} onClick={() => onRun(j.id)}>
                <Play className="h-3.5 w-3.5" />
              </Button>
              <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-400" onClick={() => onDelete(j.id)}>
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        ))}
        {!jobs.length && <p className="text-[11px] text-muted-foreground">Sin jobs programados.</p>}
      </div>
    </div>
  );
}
