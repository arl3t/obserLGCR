/**
 * world-countries-geo.ts — Geometría de países proyectada y cacheada.
 *
 * Decodifica `world-atlas/countries-110m.json` (topojson, ~110 KB) UNA vez y
 * deja cada país como una lista de anillos proyectados (equirectangular, misma
 * proyección que GeoOriginMap: lon[-180,180]→x[0,360], lat[90,-90]→y[0,180]).
 *
 * Consumido por:
 *   · WorldChoropleth.tsx  — render SVG interactivo en la UI.
 *   · choropleth-canvas.ts — rasteriza a PNG dataURL para incrustar en el PDF.
 *
 * Sin d3, sin red, sin tiles: todo offline.
 */
import { feature } from "topojson-client";
import countriesTopo from "world-atlas/countries-110m.json";
import { ISO_NUM_TO_A2 } from "./iso-country-codes";

export const MAP_W = 360;
export const MAP_H = 180;

export function project(lon: number, lat: number): [number, number] {
  return [lon + 180, 90 - lat];
}

export interface CountryShape {
  cc: string | null;          // alpha-2 (o null si el código no mapea)
  name: string;               // nombre del topojson (inglés)
  rings: Array<Array<[number, number]>>;  // anillos proyectados
}

let CACHE: CountryShape[] | null = null;

export function countryShapes(): CountryShape[] {
  if (CACHE) return CACHE;
  const fc = feature(countriesTopo, (countriesTopo.objects as Record<string, unknown>).countries);
  const feats = fc.features ?? [];
  const out: CountryShape[] = [];

  for (const f of feats) {
    const g = f.geometry;
    if (!g) continue;
    const id = f.id != null ? String(f.id) : "";
    const cc = ISO_NUM_TO_A2[id] ?? ISO_NUM_TO_A2[id.padStart(3, "0")] ?? null;
    const name = f.properties?.name ?? cc ?? "—";
    const rings: Array<Array<[number, number]>> = [];

    const addRing = (ring: number[][]) => {
      const pts: Array<[number, number]> = [];
      for (const [lon, lat] of ring) pts.push(project(lon, lat));
      if (pts.length > 1) rings.push(pts);
    };
    if (g.type === "Polygon") {
      for (const ring of g.coordinates as number[][][]) addRing(ring);
    } else if (g.type === "MultiPolygon") {
      for (const poly of g.coordinates as number[][][][]) {
        for (const ring of poly) addRing(ring);
      }
    }
    if (rings.length) out.push({ cc, name, rings });
  }
  CACHE = out;
  return out;
}

let CENTROIDS: Map<string, [number, number]> | null = null;
/**
 * Centroide representativo por país (alpha-2) en coords proyectadas, calculado
 * como el promedio de los puntos del anillo más grande (mayor masa terrestre).
 * Suficiente para posicionar nodos de "país de origen" en el mapa radar.
 */
export function countryCentroids(): Map<string, [number, number]> {
  if (CENTROIDS) return CENTROIDS;
  const m = new Map<string, [number, number]>();
  for (const s of countryShapes()) {
    if (!s.cc) continue;
    let best: Array<[number, number]> | null = null;
    for (const ring of s.rings) if (!best || ring.length > best.length) best = ring;
    if (!best) continue;
    let sx = 0, sy = 0;
    for (const [x, y] of best) { sx += x; sy += y; }
    m.set(s.cc, [sx / best.length, sy / best.length]);
  }
  CENTROIDS = m;
  return m;
}

/** Path SVG (`d`) de un conjunto de anillos ya proyectados. */
export function ringsToPath(rings: Array<Array<[number, number]>>): string {
  let d = "";
  for (const ring of rings) {
    for (let i = 0; i < ring.length; i++) {
      const [x, y] = ring[i];
      d += `${i === 0 ? "M" : "L"}${x.toFixed(2)} ${y.toFixed(2)}`;
    }
    d += "Z";
  }
  return d;
}
