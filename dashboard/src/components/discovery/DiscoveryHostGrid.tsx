import { Loader2 } from "lucide-react";
import type { DiscoveryHost } from "@/api/discovery";
import { cn } from "@/lib/utils";

type Props = {
  hosts: DiscoveryHost[];
  loading: boolean;
  selectedId: number | null;
  onSelect: (h: DiscoveryHost) => void;
};

export function DiscoveryHostGrid({ hosts, loading, selectedId, onSelect }: Props) {
  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!hosts.length) {
    return <p className="py-8 text-center text-sm text-muted-foreground">Sin hosts en este escaneo.</p>;
  }

  return (
    <div className="discovery-host-grid">
      {hosts.map((h) => {
        const openPorts = h.ports.filter((p) => p.state === "open").length;
        return (
          <button
            key={h.id}
            type="button"
            onClick={() => onSelect(h)}
            className={cn(
              "discovery-host-card text-left",
              h.status === "up" && "discovery-host-card--up",
              h.documented && "discovery-host-card--documented",
              selectedId === h.id && "ring-1 ring-cyan-400/50",
            )}
          >
            <p className="obser-mono text-[12px] font-medium text-cyan-300">{h.ip_address}</p>
            {h.hostname && <p className="truncate text-[10px] text-muted-foreground">{h.hostname}</p>}
            <div className="mt-1 flex flex-wrap gap-1 text-[9px]">
              <span className="rounded bg-emerald-500/15 px-1 text-emerald-400">{h.status}</span>
              {openPorts > 0 && (
                <span className="rounded bg-violet-500/15 px-1 text-violet-300">{openPorts} puertos</span>
              )}
              {h.documented && <span className="rounded bg-cyan-500/15 px-1 text-cyan-300">doc</span>}
            </div>
            {h.os_guess && (
              <p className="mt-1 truncate text-[9px] text-muted-foreground/80">{h.os_guess}</p>
            )}
          </button>
        );
      })}
    </div>
  );
}
