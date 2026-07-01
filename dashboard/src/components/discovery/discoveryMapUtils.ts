import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
} from "d3-force";
import type { DiscoveryTopologyEdge, DiscoveryTopologyNode } from "@/api/discovery";

export const CRITICAL_PORTS = new Set([21, 23, 135, 139, 161, 445, 3389, 5900, 6379, 27017]);

export interface MapFilters {
  documented: "all" | "yes" | "no";
  criticalOnly: boolean;
  deltaOnly: boolean;
  nocAlertsOnly: boolean;
  osQuery: string;
  subnet: string;
}

export const DEFAULT_MAP_FILTERS: MapFilters = {
  documented: "all",
  criticalOnly: false,
  deltaOnly: false,
  nocAlertsOnly: false,
  osQuery: "",
  subnet: "all",
};

export function filterNodes(
  nodes: DiscoveryTopologyNode[],
  filters: MapFilters,
): DiscoveryTopologyNode[] {
  return nodes.filter((n) => {
    if (n.node_type === "subnet") return true;
    if (filters.subnet !== "all" && n.subnet !== filters.subnet) return false;
    if (filters.documented === "yes" && !n.documented) return false;
    if (filters.documented === "no" && n.documented) return false;
    if (filters.criticalOnly && !n.has_critical_ports) return false;
    if (filters.deltaOnly && n.delta !== "new" && n.delta !== "removed") return false;
    if (filters.nocAlertsOnly && (n.noc_open_alerts ?? 0) === 0 && n.noc_status !== "offline") {
      return false;
    }
    if (filters.osQuery.trim()) {
      const q = filters.osQuery.toLowerCase();
      if (!(n.os_guess ?? "").toLowerCase().includes(q)) return false;
    }
    return true;
  });
}

export function filterEdges(
  edges: DiscoveryTopologyEdge[],
  visibleIds: Set<string>,
): DiscoveryTopologyEdge[] {
  return edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));
}

export interface SimNode extends Omit<DiscoveryTopologyNode, "x" | "y"> {
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

type MapNode = DiscoveryTopologyNode | SimNode;

export function nodeFill(n: MapNode): string {
  if (n.node_type === "subnet") return "rgba(167,139,250,0.45)";
  if (n.delta === "removed") return "rgba(248,113,113,0.35)";
  if (n.delta === "new") return "rgba(52,211,153,0.75)";
  if (n.noc_status === "offline") return "rgba(248,113,113,0.65)";
  if (n.has_critical_ports) return "rgba(251,191,36,0.75)";
  if (n.documented) return "rgba(52,211,153,0.65)";
  if (n.node_type === "gateway") {
    return n.gateway_inferred ? "rgba(167,139,250,0.35)" : "rgba(167,139,250,0.55)";
  }
  if (n.port_count > 5) return "rgba(251,191,36,0.65)";
  return "rgba(56,189,248,0.55)";
}

export function nodeRadius(n: MapNode): number {
  if (n.node_type === "subnet") return 22;
  if (n.node_type === "gateway") return 14;
  if (n.delta === "removed") return 7;
  return 8 + Math.min(n.port_count, 8);
}

export function nodeStroke(n: MapNode): string {
  if ((n.noc_open_alerts ?? 0) > 0) return "rgba(248,113,113,0.9)";
  if (n.noc_status === "online") return "rgba(74,222,128,0.6)";
  return "rgba(255,255,255,0.2)";
}

export function edgeStroke(e: DiscoveryTopologyEdge): string {
  if (e.edge_type === "same_mac") return "rgba(251,191,36,0.35)";
  if (e.edge_type === "inferred_gateway") return "rgba(167,139,250,0.2)";
  return "rgba(56,189,248,0.28)";
}

export function edgeDash(e: DiscoveryTopologyEdge): string | undefined {
  if (e.edge_type === "inferred_gateway") return "4 3";
  if (e.edge_type === "same_mac") return "2 2";
  return undefined;
}

export function runForceLayout(
  nodes: DiscoveryTopologyNode[],
  edges: DiscoveryTopologyEdge[],
  width: number,
  height: number,
): SimNode[] {
  const simNodes: SimNode[] = nodes.map((n) => ({
    ...n,
    x: n.x ?? width / 2,
    y: n.y ?? height / 2,
  }));
  const nodeById = new Map(simNodes.map((n) => [n.id, n]));

  const links = edges
    .map((e) => ({
      source: nodeById.get(e.source)!,
      target: nodeById.get(e.target)!,
    }))
    .filter((l) => l.source && l.target);

  const sim = forceSimulation(simNodes)
    .force(
      "link",
      forceLink(links)
        .id((d) => (d as SimNode).id)
        .distance(48)
        .strength(0.35),
    )
    .force("charge", forceManyBody().strength(-120))
    .force("center", forceCenter(width / 2, height / 2))
    .force(
      "collide",
      forceCollide<SimNode>().radius((d) => nodeRadius(d) + 6),
    )
    .stop();

  for (let i = 0; i < 180; i++) sim.tick();

  return simNodes;
}
