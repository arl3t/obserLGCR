import { Loader2 } from "lucide-react";
import type { DiscoveryTopology } from "@/api/discovery";

type Props = { topology: DiscoveryTopology | undefined; loading: boolean };

export function DiscoveryNetworkMap({ topology, loading }: Props) {
  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!topology?.nodes.length) {
    return <p className="py-8 text-center text-sm text-muted-foreground">Sin nodos para el mapa (escaneo vacío o pendiente).</p>;
  }

  const nodes = topology.nodes;
  const edges = topology.edges;
  const maxX = Math.max(...nodes.map((n) => n.x ?? 0), 400) + 60;
  const maxY = Math.max(...nodes.map((n) => n.y ?? 0), 300) + 60;

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-muted-foreground">
        Mapa lógico · {topology.subnets.length} subred(es) · {nodes.length} nodos
      </p>
      <svg viewBox={`0 0 ${maxX} ${maxY}`} className="discovery-map-svg">
        {edges.map((e, i) => {
          const s = nodes.find((n) => n.id === e.source);
          const t = nodes.find((n) => n.id === e.target);
          if (!s?.x || !t?.x || s.y == null || t.y == null) return null;
          return (
            <line
              key={i}
              x1={s.x}
              y1={s.y}
              x2={t.x}
              y2={t.y}
              stroke="rgba(56,189,248,0.25)"
              strokeWidth={1}
            />
          );
        })}
        {nodes.map((n) => {
          const isGw = n.id.startsWith("gw-");
          const cx = n.x ?? 0;
          const cy = n.y ?? 0;
          const r = isGw ? 14 : 8 + Math.min(n.port_count, 6);
          const fill = isGw
            ? "rgba(167,139,250,0.5)"
            : n.documented
              ? "rgba(52,211,153,0.65)"
              : n.port_count > 5
                ? "rgba(251,191,36,0.65)"
                : "rgba(56,189,248,0.55)";
          return (
            <g key={n.id}>
              <circle cx={cx} cy={cy} r={r} fill={fill} stroke="rgba(255,255,255,0.2)" strokeWidth={1} />
              <title>{`${n.ip} · ${n.hostname ?? ""} · ${n.port_count} puertos`}</title>
              <text x={cx} y={cy + r + 12} textAnchor="middle" fill="rgba(255,255,255,0.55)" fontSize={9}>
                {isGw ? "GW" : n.ip.split(".").pop()}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
