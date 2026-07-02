import { Loader2, Play, Terminal } from "lucide-react";
import type { DiscoveryProfile } from "@/api/discovery";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { NMAP_PROFILES, buildCommandPreview, type ProfileMeta } from "./discoveryProfiles";
import type { ScanProfile } from "@/api/discovery";

export interface AdhocScanState {
  targets: string;
  profile: ScanProfile;
  custom_args: string;
  name: string;
  scan_cves: boolean;
}

type Props = {
  adhoc: AdhocScanState;
  onChange: (patch: Partial<AdhocScanState>) => void;
  profiles: DiscoveryProfile[];
  scanAvailable: boolean;
  pending: boolean;
  onScan: () => void;
  recentTargets?: string[];
};

export function DiscoveryScanConsole({
  adhoc,
  onChange,
  profiles,
  scanAvailable,
  pending,
  onScan,
  recentTargets = [],
}: Props) {
  const command = buildCommandPreview(
    adhoc.profile,
    adhoc.targets,
    adhoc.custom_args,
    adhoc.scan_cves || adhoc.profile === "vulnerabilities",
  );

  const profileList = profiles.length
    ? profiles.map((p) => NMAP_PROFILES.find((m) => m.id === p.id) ?? {
        id: p.id,
        label: p.label,
        short: p.label,
        args: "—",
        duration: "medio" as const,
        icon: "•",
        useCase: "",
      })
    : NMAP_PROFILES;

  return (
    <div className="discovery-console">
      <div className="discovery-console__header">
        <div>
          <h2 className="discovery-console__title">Consola de escaneo</h2>
          <p className="discovery-console__subtitle">
            Perfiles nmap preconfigurados · vista previa del comando · un clic para ejecutar
          </p>
        </div>
        <Button
          size="sm"
          className="discovery-console__run-btn gap-1.5"
          disabled={pending || !scanAvailable || !adhoc.targets.trim()}
          onClick={onScan}
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4 fill-current" />}
          Iniciar escaneo
        </Button>
      </div>

      <div className="discovery-console__targets">
        <label className="discovery-field-label">Objetivos</label>
        <Input
          value={adhoc.targets}
          onChange={(e) => onChange({ targets: e.target.value })}
          placeholder="192.168.1.0/24, 10.0.0.5, host.lan"
          className="discovery-input obser-mono h-9 text-[13px]"
        />
        {recentTargets.length > 0 && (
          <div className="discovery-target-chips">
            {recentTargets.slice(0, 4).map((t) => (
              <button
                key={t}
                type="button"
                className="discovery-target-chip"
                onClick={() => onChange({ targets: t })}
              >
                {t}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="discovery-profile-grid">
        {profileList.map((p: ProfileMeta) => (
          <button
            key={p.id}
            type="button"
            className={cn("discovery-profile-card", adhoc.profile === p.id && "discovery-profile-card--active")}
            onClick={() => onChange({ profile: p.id })}
          >
            <span className="discovery-profile-card__icon">{p.icon}</span>
            <span className="discovery-profile-card__label">{p.label}</span>
            <span className="discovery-profile-card__short">{p.short}</span>
            <code className="discovery-profile-card__args">{p.args}</code>
            <span className={cn("discovery-profile-card__dur", `discovery-profile-card__dur--${p.duration.replace(" ", "-")}`)}>
              {p.duration}
            </span>
          </button>
        ))}
      </div>

      {adhoc.profile === "custom" && (
        <div className="discovery-console__custom">
          <label className="discovery-field-label">Argumentos nmap</label>
          <Input
            value={adhoc.custom_args}
            onChange={(e) => onChange({ custom_args: e.target.value })}
            placeholder="-T4 -sV -p 22,80,443,3389"
            className="discovery-input obser-mono h-8 text-[12px]"
          />
        </div>
      )}

      <div className="discovery-console__options">
        <label className="discovery-check">
          <input
            type="checkbox"
            checked={adhoc.scan_cves || adhoc.profile === "vulnerabilities"}
            disabled={adhoc.profile === "vulnerabilities"}
            onChange={(e) => onChange({ scan_cves: e.target.checked })}
          />
          Añadir detección CVE (<code>--script vuln</code>)
        </label>
        <div className="discovery-console__name">
          <label className="discovery-field-label">Etiqueta del escaneo</label>
          <Input
            value={adhoc.name}
            onChange={(e) => onChange({ name: e.target.value })}
            placeholder="Opcional — ej. LAN producción"
            className="discovery-input h-8 text-[12px]"
          />
        </div>
      </div>

      <div className="discovery-command-preview">
        <Terminal className="h-4 w-4 shrink-0 text-emerald-400/80" aria-hidden />
        <code className="obser-mono text-[11px] leading-relaxed text-emerald-200/90">{command}</code>
      </div>
      {profileList.find((p) => p.id === adhoc.profile)?.useCase && (
        <p className="discovery-console__hint">
          {profileList.find((p) => p.id === adhoc.profile)?.useCase}
        </p>
      )}
    </div>
  );
}
