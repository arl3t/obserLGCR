declare module "topojson-client" {
  export function feature(
    topology: unknown,
    object: unknown,
  ): { type: string; features?: Array<{ geometry?: { type: string; coordinates: unknown } }>; geometry?: { type: string; coordinates: unknown } };
}

declare module "world-atlas/land-110m.json" {
  const value: { objects: Record<string, unknown> };
  export default value;
}

declare module "world-atlas/countries-110m.json" {
  const value: unknown;
  export default value;
}
