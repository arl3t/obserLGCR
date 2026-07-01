import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Download,
  ExternalLink,
  Loader2,
  Maximize2,
  Minimize2,
  Minus,
  Plus,
  RotateCcw,
} from "lucide-react";
import type { DiscoveryTopology, DiscoveryTopologyNode, TopologyMode } from "@/api/discovery";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  DEFAULT_MAP_FILTERS,
  edgeDash,
  edgeStroke,
  filterEdges,
  filterNodes,
  nodeFill,
  nodeRadius,
  nodeStroke,
  runForceLayout,
  type MapFilters,
  type SimNode,
} from "./discoveryMapUtils";

type Props = {
  topology: DiscoveryTopology | undefined;
  loading: boolean;
  mode: TopologyMode;
  onModeChange: (m: TopologyMode) => void;
  compareEnabled: boolean;
  onCompareChange: (v: boolean) => void;
};

function nodeLabel(n: SimNode | DiscoveryTopologyNode): string {
  if (n.node_type === "subnet") return n.subnet.split("/")[0].split(".").slice(-2).join(".");
  if (n.node_type === "gateway") return n.gateway_inferred ? "GW*" : "GW";
  return n.ip.split(".").pop() ?? n.ip;
}

export function DiscoveryNetworkMap({
  topology,
  loading,
  mode,
  onModeChange,
  compareEnabled,
  onCompareChange,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [filters, setFilters] = useState<MapFilters>(DEFAULT_MAP_FILTERS);
  const [selected, setSelected] = useState<SimNode | null>(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });
  const [fullscreen, setFullscreen] = useState(false);
  const dragRef = useRef<{ px: number; py: number; ox: number; oy: number } | null>(null);

  const W = 1200;
  const H = 720;

  const filtered = useMemo(() => {
    if (!topology) return { nodes: [] as DiscoveryTopologyNode[], edges: [], clusters: [] };
    const nodes = filterNodes(topology.nodes, filters);
    const ids = new Set(nodes.map((n) => n.id));
    const edges = filterEdges(topology.edges, ids);
    const clusters =
      filters.subnet === "all"
        ? topology.clusters
        : topology.clusters.filter((c) => c.subnet === filters.subnet);
    return { nodes, edges, clusters };
  }, [topology, filters]);

  const layoutNodes = useMemo(() => {
    if (!filtered.nodes.length) return [] as SimNode[];
    return runForceLayout(filtered.nodes, filtered.edges, W, H);
  }, [filtered.nodes, filtered.edges]);

  const bounds = useMemo(() => {
    if (!layoutNodes.length) return { minX: 0, minY: 0, maxX: W, maxY: H };
    let minX = Infinity,
      minY = Infinity,
      maxX = -Infinity,
      maxY = -Infinity;
    for (const n of layoutNodes) {
      const x = n.x ?? 0;
      const y = n.y ?? 0;
      const r = nodeRadius(n);
      minX = Math.min(minX, x - r);
      minY = Math.min(minY, y - r);
      maxX = Math.max(maxX, x + r);
      maxY = Math.max(maxY, y + r);
    }
    return { minX: minX - 40, minY: minY - 40, maxX: maxX + 40, maxY: maxY + 40 };
  }, [layoutNodes]);

  const fitView = useCallback(() => {
    const bw = bounds.maxX - bounds.minX;
    const bh = bounds.maxY - bounds.minY;
    const k = Math.min(0.95, (W * 0.9) / bw, (H * 0.9) / bh);
    const cx = (bounds.minX + bounds.maxX) / 2;
    const cy = (bounds.minY + bounds.maxY) / 2;
    setTransform({ k, x: W / 2 - cx * k, y: H / 2 - cy * k });
  }, [bounds]);

  useEffect(() => {
    fitView();
  }, [topology?.run_id, layoutNodes.length, fitView]);

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform((t) => ({ ...t, k: Math.min(4, Math.max(0.15, t.k * delta)) }));
  };

  const onPointerDown = (e: React.PointerEvent) => {
    if ((e.target as Element).closest(".discovery-map-node")) return;
    dragRef.current = { px: e.clientX, py: e.clientY, ox: transform.x, oy: transform.y };
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    if (!dragRef.current) return;
    const d = dragRef.current;
    setTransform((t) => ({
      ...t,
      x: d.ox + (e.clientX - d.px),
      y: d.oy + (e.clientY - d.py),
    }));
  };

  const onPointerUp = () => {
    dragRef.current = null;
  };

  const toggleFullscreen = async () => {
    const el = containerRef.current;
    if (!el) return;
    if (!document.fullscreenElement) {
      await el.requestFullscreen();
      setFullscreen(true);
    } else {
      await document.exitFullscreen();
      setFullscreen(false);
    }
  };

  const exportSvg = () => {
    const svg = svgRef.current;
    if (!svg) return;
    const blob = new Blob([svg.outerHTML], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `discovery-map-run-${topology?.run_id ?? "export"}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportPng = () => {
    const svg = svgRef.current;
    if (!svg) return;
    const xml = new XMLSerializer().serializeToString(svg);
    const img = new Image();
    const url = URL.createObjectURL(new Blob([xml], { type: "image/svg+xml" }));
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = W * 2;
      canvas.height = H * 2;
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#0a0f14";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        canvas.toBlob((b) => {
          if (!b) return;
          const pu = URL.createObjectURL(b);
          const a = document.createElement("a");
          a.href = pu;
          a.download = `discovery-map-run-${topology?.run_id ?? "export"}.png`;
          a.click();
          URL.revokeObjectURL(pu);
        });
      }
      URL.revokeObjectURL(url);
    };
    img.src = url;
  };

  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!topology?.nodes.length) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">
        Sin nodos para el mapa (escaneo vacío o pendiente).
      </p>
    );
  }

  const nodeById = new Map(layoutNodes.map((n) => [n.id, n]));

  return (
    <div
      ref={containerRef}
      className={cn("discovery-map-shell space-y-3", fullscreen && "discovery-map-shell--fs")}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] text-muted-foreground">
          {topology.mode === "summary" ? "Vista resumen" : "Vista detalle"} ·{" "}
          {topology.subnets.length} subred(es) · {layoutNodes.length} nodos visibles
          {topology.meta.region_name ? ` · ${topology.meta.region_name}` : ""}
          {topology.compare_run_id && compareEnabled
            ? ` · delta vs #${topology.compare_run_id}`
            : ""}
        </p>
        <div className="flex flex-wrap gap-1">
          {(["auto", "detail", "summary"] as TopologyMode[]).map((m) => (
            <Button
              key={m}
              variant={mode === m ? "default" : "outline"}
              size="sm"
              className="h-7 text-[10px]"
              onClick={() => onModeChange(m)}
            >
              {m}
            </Button>
          ))}
          <Button
            variant={compareEnabled ? "default" : "outline"}
            size="sm"
            className="h-7 text-[10px]"
            onClick={() => onCompareChange(!compareEnabled)}
          >
            Delta
          </Button>
          <Button variant="outline" size="sm" className="h-7 px-2" onClick={() => setTransform((t) => ({ ...t, k: t.k * 1.2 }))}>
            <Plus className="h-3 w-3" />
          </Button>
          <Button variant="outline" size="sm" className="h-7 px-2" onClick={() => setTransform((t) => ({ ...t, k: t.k / 1.2 }))}>
            <Minus className="h-3 w-3" />
          </Button>
          <Button variant="outline" size="sm" className="h-7 px-2" onClick={fitView}>
            <RotateCcw className="h-3 w-3" />
          </Button>
          <Button variant="outline" size="sm" className="h-7 px-2" onClick={() => void toggleFullscreen()}>
            {fullscreen ? <Minimize2 className="h-3 w-3" /> : <Maximize2 className="h-3 w-3" />}
          </Button>
          <Button variant="outline" size="sm" className="h-7 text-[10px]" onClick={exportSvg}>
            <Download className="mr-1 h-3 w-3" /> SVG
          </Button>
          <Button variant="outline" size="sm" className="h-7 text-[10px]" onClick={exportPng}>
            <Download className="mr-1 h-3 w-3" /> PNG
          </Button>
        </div>
      </div>

      <div className="discovery-map-filters">
        <select
          className="discovery-map-select"
          value={filters.subnet}
          onChange={(e) => setFilters((f) => ({ ...f, subnet: e.target.value }))}
          aria-label="Filtrar subred"
        >
          <option value="all">Todas las subredes</option>
          {topology.subnets.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          className="discovery-map-select"
          value={filters.documented}
          onChange={(e) =>
            setFilters((f) => ({ ...f, documented: e.target.value as MapFilters["documented"] }))
          }
        >
          <option value="all">Documentación: todas</option>
          <option value="yes">Solo documentados</option>
          <option value="no">Sin documentar</option>
        </select>
        <input
          className="discovery-map-select"
          placeholder="Filtrar OS…"
          value={filters.osQuery}
          onChange={(e) => setFilters((f) => ({ ...f, osQuery: e.target.value }))}
        />
        <label className="discovery-map-check">
          <input
            type="checkbox"
            checked={filters.criticalOnly}
            onChange={(e) => setFilters((f) => ({ ...f, criticalOnly: e.target.checked }))}
          />
          Puertos críticos
        </label>
        <label className="discovery-map-check">
          <input
            type="checkbox"
            checked={filters.deltaOnly}
            onChange={(e) => setFilters((f) => ({ ...f, deltaOnly: e.target.checked }))}
          />
          Solo cambios (delta)
        </label>
        <label className="discovery-map-check">
          <input
            type="checkbox"
            checked={filters.nocAlertsOnly}
            onChange={(e) => setFilters((f) => ({ ...f, nocAlertsOnly: e.target.checked }))}
          />
          NOC alerta/offline
        </label>
      </div>

      <div className="discovery-map-layout">
        <div
          className="discovery-map-canvas-wrap"
          onWheel={onWheel}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          role="application"
          aria-label="Mapa de red interactivo. Arrastre para mover, rueda para zoom."
        >
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            className="discovery-map-svg"
            xmlns="http://www.w3.org/2000/svg"
          >
            <rect width={W} height={H} fill="#0a0f14" />
            <g transform={`translate(${transform.x} ${transform.y}) scale(${transform.k})`}>
              {filtered.clusters.map((c) => (
                <g key={c.id}>
                  <rect
                    x={c.x}
                    y={c.y}
                    width={c.width}
                    height={c.height}
                    rx={8}
                    fill="rgba(56,189,248,0.04)"
                    stroke="rgba(56,189,248,0.15)"
                    strokeWidth={1}
                  />
                  <text x={c.x + 8} y={c.y + 14} fill="rgba(103,232,249,0.7)" fontSize={10}>
                    {c.label} · {c.host_count} hosts
                  </text>
                </g>
              ))}
              {filtered.edges.map((e, i) => {
                const s = nodeById.get(e.source);
                const t = nodeById.get(e.target);
                if (s?.x == null || t?.x == null || s.y == null || t.y == null) return null;
                return (
                  <line
                    key={i}
                    x1={s.x}
                    y1={s.y}
                    x2={t.x}
                    y2={t.y}
                    stroke={edgeStroke(e)}
                    strokeWidth={e.edge_type === "same_mac" ? 1.5 : 1}
                    strokeDasharray={edgeDash(e)}
                  />
                );
              })}
              {layoutNodes.map((n) => (
                <g
                  key={n.id}
                  className="discovery-map-node"
                  transform={`translate(${n.x ?? 0}, ${n.y ?? 0})`}
                  style={{ cursor: "pointer" }}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setSelected(n);
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`${n.ip} ${n.hostname ?? ""}`}
                  onKeyDown={(ev) => {
                    if (ev.key === "Enter") setSelected(n);
                  }}
                >
                  <circle
                    r={nodeRadius(n)}
                    fill={nodeFill(n)}
                    stroke={selected?.id === n.id ? "#67e8f9" : nodeStroke(n)}
                    strokeWidth={selected?.id === n.id ? 2.5 : 1.2}
                  />
                  {n.delta === "new" && (
                    <circle r={nodeRadius(n) + 4} fill="none" stroke="#4ade80" strokeWidth={1} />
                  )}
                  <text y={nodeRadius(n) + 11} textAnchor="middle" fill="rgba(255,255,255,0.55)" fontSize={9}>
                    {nodeLabel(n)}
                  </text>
                </g>
              ))}
            </g>
          </svg>

          <div className="discovery-map-minimap" aria-hidden>
            <svg viewBox={`${bounds.minX} ${bounds.minY} ${bounds.maxX - bounds.minX} ${bounds.maxY - bounds.minY}`}>
              {layoutNodes.map((n) => (
                <circle key={n.id} cx={n.x ?? 0} cy={n.y ?? 0} r={2} fill="rgba(56,189,248,0.6)" />
              ))}
            </svg>
          </div>
        </div>

        <aside className="discovery-map-legend" aria-label="Leyenda del mapa">
          <p className="text-[11px] font-medium text-cyan-300">Leyenda</p>
          <ul className="discovery-map-legend__list">
            <li><span className="discovery-map-swatch" style={{ background: "rgba(56,189,248,0.55)" }} /> Host</li>
            <li><span className="discovery-map-swatch" style={{ background: "rgba(52,211,153,0.65)" }} /> Documentado</li>
            <li><span className="discovery-map-swatch" style={{ background: "rgba(251,191,36,0.75)" }} /> Puertos críticos / muchos puertos</li>
            <li><span className="discovery-map-swatch" style={{ background: "rgba(167,139,250,0.55)" }} /> Gateway detectado</li>
            <li><span className="discovery-map-swatch discovery-map-swatch--dashed" /> Gateway inferido (línea punteada)</li>
            <li><span className="discovery-map-swatch" style={{ background: "rgba(52,211,153,0.75)" }} /> Nuevo (delta)</li>
            <li><span className="discovery-map-swatch" style={{ background: "rgba(248,113,113,0.65)" }} /> NOC offline / removido</li>
          </ul>
          <p className="mt-2 text-[10px] text-muted-foreground">
            Tamaño del nodo ∝ puertos abiertos. Borde rojo = alerta NOC.
          </p>
        </aside>

        {selected && (
          <aside className="discovery-map-panel" aria-label="Detalle del nodo">
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="obser-mono text-sm font-medium text-cyan-300">{selected.ip}</p>
                {selected.hostname && (
                  <p className="text-[11px] text-muted-foreground">{selected.hostname}</p>
                )}
              </div>
              <button type="button" className="text-[11px] text-muted-foreground" onClick={() => setSelected(null)}>
                ✕
              </button>
            </div>
            <dl className="discovery-map-panel__dl">
              <dt>Tipo</dt><dd>{selected.node_type}{selected.gateway_inferred ? " (inferido)" : ""}</dd>
              <dt>Subred</dt><dd>{selected.subnet}</dd>
              <dt>Estado</dt><dd>{selected.status}</dd>
              {selected.os_guess && <><dt>OS</dt><dd>{selected.os_guess}</dd></>}
              {selected.mac_address && <><dt>MAC</dt><dd className="obser-mono">{selected.mac_address}</dd></>}
              <dt>Puertos</dt><dd>{selected.port_count}{selected.has_critical_ports ? " · críticos" : ""}</dd>
              {selected.delta && <><dt>Delta</dt><dd>{selected.delta}</dd></>}
              {selected.noc_status && (
                <><dt>NOC</dt><dd>{selected.noc_status}{selected.noc_open_alerts ? ` · ${selected.noc_open_alerts} alertas` : ""}</dd></>
              )}
            </dl>
            {selected.open_ports.length > 0 && (
              <p className="mt-2 text-[10px] text-muted-foreground">
                Abiertos: {selected.open_ports.slice(0, 12).join(", ")}
                {selected.open_ports.length > 12 ? "…" : ""}
              </p>
            )}
            <div className="mt-3 flex flex-wrap gap-1">
              {selected.noc_device_id && (
                <Link to={`/noc/${selected.noc_device_id}`} className="discovery-map-link">
                  <ExternalLink className="h-3 w-3" /> NOC
                </Link>
              )}
              <Link
                to={`/detection?tab=assets`}
                className="discovery-map-link"
              >
                <ExternalLink className="h-3 w-3" /> Activos
              </Link>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
