import {
  Activity,
  BarChart3,
  Bell,
  FileText,
  GitCompareArrows,
  History,
  LayoutGrid,
  Map,
  Radar,
  ShieldAlert,
  Sparkles,
  Terminal,
} from "lucide-react";
import type { DiscoveryRun } from "@/api/discovery";
import { cn } from "@/lib/utils";

export type DiscoveryView =
  | "console"
  | "history"
  | "analytics"
  | "hosts"
  | "topology"
  | "vulnerabilities"
  | "alerts"
  | "delta"
  | "reports"
  | "docs"
  | "roadmap";

export const DISCOVERY_VIEWS: { id: DiscoveryView; label: string; icon: typeof Terminal }[] = [
  { id: "console", label: "Consola", icon: Terminal },
  { id: "history", label: "Historial", icon: History },
  { id: "analytics", label: "Análisis", icon: BarChart3 },
  { id: "hosts", label: "Hosts", icon: LayoutGrid },
  { id: "topology", label: "Topología", icon: Map },
  { id: "alerts", label: "Alertas", icon: Bell },
  { id: "delta", label: "Comparar", icon: GitCompareArrows },
  { id: "vulnerabilities", label: "CVE", icon: ShieldAlert },
  { id: "reports", label: "Informes", icon: FileText },
  { id: "docs", label: "Documentación", icon: Activity },
  { id: "roadmap", label: "Roadmap", icon: Sparkles },
];

type Props = {
  view: DiscoveryView;
  onViewChange: (v: DiscoveryView) => void;
  runs: DiscoveryRun[];
  selectedRunId: number | null;
  onSelectRun: (id: number) => void;
  scanOk: boolean;
  runnerOk: boolean | null | undefined;
  runnerConfigured: boolean;
};

function statusDot(status: string) {
  const cls =
    status === "completed"
      ? "discovery-run-dot discovery-run-dot--completed"
      : status === "running"
        ? "discovery-run-dot discovery-run-dot--running"
        : status === "failed"
          ? "discovery-run-dot discovery-run-dot--failed"
          : "discovery-run-dot discovery-run-dot--pending";
  return <span className={cls} aria-hidden />;
}

export function DiscoveryRunSidebar({
  view,
  onViewChange,
  runs,
  selectedRunId,
  onSelectRun,
  scanOk,
  runnerOk,
  runnerConfigured,
}: Props) {
  return (
    <aside className="discovery-sidebar">
      <div className="discovery-sidebar__brand">
        <Radar className="h-5 w-5 text-cyan-400" />
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400/90">Network Scan</p>
          <p className="text-[10px] text-muted-foreground">nmap GUI · obserLGCR</p>
        </div>
      </div>

      <div className="discovery-sidebar__status">
        <span className={cn("discovery-status-chip", scanOk ? "discovery-status-chip--ok" : "discovery-status-chip--err")}>
          nmap {scanOk ? "OK" : "off"}
        </span>
        {runnerConfigured && (
          <span className={cn("discovery-status-chip", runnerOk ? "discovery-status-chip--ok" : "discovery-status-chip--warn")}>
            runner {runnerOk ? "OK" : "down"}
          </span>
        )}
      </div>

      <nav className="discovery-sidebar__nav">
        {DISCOVERY_VIEWS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            className={cn("discovery-sidebar__nav-btn", view === id && "discovery-sidebar__nav-btn--active")}
            onClick={() => onViewChange(id)}
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </button>
        ))}
      </nav>

      <div className="discovery-sidebar__runs">
        <p className="discovery-sidebar__runs-title">Escaneos recientes</p>
        <div className="discovery-sidebar__runs-list">
          {runs.length === 0 && (
            <p className="px-2 py-4 text-[10px] text-muted-foreground">Sin escaneos. Use la consola para iniciar.</p>
          )}
          {runs.slice(0, 12).map((r) => (
            <button
              key={r.id}
              type="button"
              className={cn("discovery-run-item", selectedRunId === r.id && "discovery-run-item--active")}
              onClick={() => onSelectRun(r.id)}
            >
              {statusDot(r.status)}
              <div className="discovery-run-item__body">
                <span className="discovery-run-item__title">#{r.id} · {r.scan_profile}</span>
                <span className="discovery-run-item__meta truncate">{r.targets}</span>
                {r.status === "completed" && (
                  <span className="discovery-run-item__stats">
                    {r.hosts_up}↑ · {r.ports_open}p
                    {r.duration_ms != null && ` · ${(r.duration_ms / 1000).toFixed(0)}s`}
                  </span>
                )}
              </div>
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
}
