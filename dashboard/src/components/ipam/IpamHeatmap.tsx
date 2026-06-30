import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { fetchIpamHeatmap } from "@/api/ipam";
import { cn } from "@/lib/utils";

const CELL_CLASS: Record<string, string> = {
  Online: "bg-emerald-500/80 hover:bg-emerald-400",
  Offline: "bg-muted/60 hover:bg-muted",
  Reserved: "bg-amber-500/70 hover:bg-amber-400",
  Free: "bg-cyan-500/40 hover:bg-cyan-400/60",
  DHCP: "bg-violet-500/70 hover:bg-violet-400",
  empty: "bg-background/40 border border-border/40 hover:bg-muted/30",
};

type Props = { subnetId: number; cidr: string };

export function IpamHeatmap({ subnetId, cidr }: Props) {
  const q = useQuery({
    queryKey: ["ipam", "heatmap", subnetId],
    queryFn: () => fetchIpamHeatmap(subnetId),
    staleTime: 15_000,
  });

  if (q.isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (q.isError || !q.data) {
    return <p className="p-6 text-center text-sm text-red-400">No se pudo cargar el mapa de calor.</p>;
  }

  const { cells } = q.data;

  return (
    <div className="p-4">
      <p className="mb-3 text-[11px] text-muted-foreground">
        Mapa de calor · {cidr} · {cells.length} celdas
      </p>
      <div className="mb-3 flex flex-wrap gap-3 text-[10px] text-muted-foreground">
        {(["Online", "Offline", "Reserved", "Free", "DHCP", "empty"] as const).map((s) => {
          const label = s === "empty" ? "Sin registro" : s;
          return (
            <span key={s} className="flex items-center gap-1">
              <span className={cn("inline-block h-3 w-3 rounded-sm", CELL_CLASS[s])} />
              {label}
            </span>
          );
        })}
      </div>
      <div
        className="grid gap-0.5"
        style={{ gridTemplateColumns: "repeat(16, minmax(0, 1fr))" }}
      >
        {cells.map((cell) => {
          const key = cell.status in CELL_CLASS ? cell.status : "empty";
          return (
            <div
              key={cell.ip}
              title={`${cell.ip} · ${cell.status}`}
              className={cn(
                "aspect-square rounded-sm transition-colors cursor-default",
                CELL_CLASS[key],
              )}
            />
          );
        })}
      </div>
    </div>
  );
}
