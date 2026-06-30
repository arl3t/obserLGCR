/**
 * GeoOriginMap — mapa mundial compacto (SVG, offline) que ubica el origen
 * geográfico de una IP pública. Proyección equirectangular propia (sin d3 ni
 * tiles ni red): lon[-180,180] → x[0,360], lat[90,-90] → y[0,180]. El contorno
 * de tierra sale de world-atlas (topojson 110m, ~55 KB) decodificado una sola
 * vez a un path SVG cacheado a nivel de módulo.
 */
import { useMemo } from "react";
import { feature } from "topojson-client";
import landTopo from "world-atlas/land-110m.json";
import { cn } from "@/lib/utils";

const W = 360;
const H = 180;

function project(lon: number, lat: number): [number, number] {
  return [lon + 180, 90 - lat];
}

// Path de tierra: caro de construir una vez, trivial de reusar.
let LAND_PATH: string | null = null;
function landPath(): string {
  if (LAND_PATH !== null) return LAND_PATH;
  const fc = feature(landTopo, (landTopo.objects as Record<string, unknown>).land);
  const feats = fc.features ?? (fc.geometry ? [{ geometry: fc.geometry }] : []);
  let d = "";
  const addRing = (ring: number[][]) => {
    for (let i = 0; i < ring.length; i++) {
      const [lon, lat] = ring[i];
      const [x, y] = project(lon, lat);
      d += `${i === 0 ? "M" : "L"}${x.toFixed(2)} ${y.toFixed(2)}`;
    }
    d += "Z";
  };
  for (const f of feats) {
    const g = f.geometry;
    if (!g) continue;
    if (g.type === "Polygon") {
      for (const ring of g.coordinates as number[][][]) addRing(ring);
    } else if (g.type === "MultiPolygon") {
      for (const poly of g.coordinates as number[][][][]) {
        for (const ring of poly) addRing(ring);
      }
    }
  }
  LAND_PATH = d;
  return d;
}

export function GeoOriginMap({
  lat, lon, className,
}: {
  lat: number | null | undefined;
  lon: number | null | undefined;
  className?: string;
}) {
  const d = useMemo(() => landPath(), []);
  const hasPoint = Number.isFinite(lat) && Number.isFinite(lon);
  const [px, py] = hasPoint ? project(lon as number, lat as number) : [0, 0];

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className={cn("h-auto w-full rounded-md border border-border/50", className)}
      role="img"
      aria-label={hasPoint ? `Origen geográfico aproximado en ${lat}, ${lon}` : "Mapa de origen sin coordenadas"}
      preserveAspectRatio="xMidYMid meet"
    >
      <rect x={0} y={0} width={W} height={H} className="fill-muted/20" />
      <path d={d} className="fill-muted-foreground/25 stroke-border" strokeWidth={0.2} />
      {hasPoint && (
        <g>
          <circle cx={px} cy={py} r={5} className="fill-red-500/30">
            <animate attributeName="r" values="3;8;3" dur="2s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.6;0;0.6" dur="2s" repeatCount="indefinite" />
          </circle>
          <circle cx={px} cy={py} r={2.4} className="fill-red-500 stroke-background" strokeWidth={0.6} />
        </g>
      )}
    </svg>
  );
}
