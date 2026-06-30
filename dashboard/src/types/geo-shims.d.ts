// Shims para las dependencias de datos del mapa de origen geo.
// `world-atlas` envía topojson sin tipos; `topojson-client` no trae .d.ts.
// Tipamos lo mínimo que usamos (feature) — el resto es topología opaca.
declare module "world-atlas/land-110m.json" {
  const topology: {
    type: "Topology";
    objects: Record<string, unknown>;
    arcs: unknown;
    transform?: unknown;
  };
  export default topology;
}

declare module "world-atlas/countries-110m.json" {
  const topology: {
    type: "Topology";
    objects: Record<string, unknown>;
    arcs: unknown;
    transform?: unknown;
  };
  export default topology;
}

declare module "topojson-client" {
  // feature() decodifica un objeto de la topología a GeoJSON (Feature | FeatureCollection).
  // Los features de countries-110m traen `id` (ISO 3166-1 numérico) y `properties.name`.
  export function feature(topology: unknown, object: unknown): {
    type: string;
    features?: Array<{
      id?: string | number;
      properties?: { name?: string };
      geometry?: { type: string; coordinates: unknown };
    }>;
    geometry?: { type: string; coordinates: unknown };
  };
}
