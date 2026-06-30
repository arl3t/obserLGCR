/**
 * radar-canvas.ts — Rasteriza el mapa mundial estilo "radar táctico" a un PNG
 * dataURL para incrustarlo en el PDF del informe técnico.
 *
 * Estilo: fondo negro profundo, cuadrícula (graticula lat/lon) verde oliva,
 * continentes como siluetas verdes translúcidas, nodo central parpadeante (la
 * sede monitoreada) y nodos de país de origen como puntos de luz verde neón con
 * brillo proporcional al volumen de contacto.
 *
 * (La versión interactiva del panel —WorldRadarMap.tsx— añade tilt en perspectiva
 * 3D y animación ping; el PDF usa la variante plana, estática.)
 */
import { MAP_W, MAP_H, countryShapes, countryCentroids, project } from "./world-countries-geo";

export interface RadarDatum { cc: string; total: number; }

// Sede monitoreada (nodo central) — InfraGov / lgcrBL = Paraguay (Asunción aprox).
const HOME: [number, number] = project(-57.6, -25.3);

export function renderRadarDataUrl(
  countries: RadarDatum[],
  opts?: { scale?: number },
): string | null {
  if (typeof document === "undefined") return null;
  const scale = opts?.scale ?? 4; // 360×180 × 4 = 1440×720 px
  const canvas = document.createElement("canvas");
  canvas.width = MAP_W * scale;
  canvas.height = MAP_H * scale;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  const S = (v: number) => v * scale;

  const metric = new Map<string, number>();
  let max = 0;
  for (const c of countries) {
    if (!c.cc) continue;
    metric.set(c.cc, c.total);
    if (c.total > max) max = c.total;
  }
  max = Math.max(1, max);

  // Fondo negro profundo.
  ctx.fillStyle = "#04070a";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Cuadrícula (graticula) verde oliva — meridianos/paralelos cada 15°.
  ctx.lineWidth = Math.max(0.4, scale * 0.1);
  ctx.strokeStyle = "rgba(120,140,45,0.20)";
  ctx.beginPath();
  for (let lon = -180; lon <= 180; lon += 15) {
    const x = S(lon + 180);
    ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height);
  }
  for (let lat = -90; lat <= 90; lat += 15) {
    const y = S(90 - lat);
    ctx.moveTo(0, y); ctx.lineTo(canvas.width, y);
  }
  ctx.stroke();
  // Ecuador y meridiano de Greenwich, más marcados.
  ctx.strokeStyle = "rgba(150,170,60,0.32)";
  ctx.beginPath();
  ctx.moveTo(0, S(90)); ctx.lineTo(canvas.width, S(90));
  ctx.moveTo(S(180), 0); ctx.lineTo(S(180), canvas.height);
  ctx.stroke();

  // Continentes: siluetas verdes translúcidas.
  ctx.beginPath();
  for (const s of countryShapes()) {
    for (const ring of s.rings) {
      for (let i = 0; i < ring.length; i++) {
        const px = S(ring[i][0]), py = S(ring[i][1]);
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
    }
  }
  ctx.fillStyle = "rgba(38,180,96,0.13)";
  ctx.fill("evenodd");
  ctx.lineWidth = Math.max(0.3, scale * 0.08);
  ctx.strokeStyle = "rgba(70,230,120,0.35)";
  ctx.stroke();

  // Nodos de país de origen: brillo neón ∝ sqrt(volumen).
  ctx.globalCompositeOperation = "lighter";
  const centroids = countryCentroids();
  for (const [cc, value] of metric) {
    if (value <= 0) continue;
    const c = centroids.get(cc);
    if (!c) continue;
    const t = Math.sqrt(value / max);
    const glow = S(2 + 11 * t);
    const cx = S(c[0]), cy = S(c[1]);
    const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, glow);
    g.addColorStop(0, "rgba(80,255,140,0.95)");
    g.addColorStop(0.35, "rgba(57,255,110,0.45)");
    g.addColorStop(1, "rgba(57,255,110,0)");
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.arc(cx, cy, glow, 0, Math.PI * 2); ctx.fill();
    // Núcleo.
    ctx.fillStyle = "rgba(190,255,210,0.95)";
    ctx.beginPath(); ctx.arc(cx, cy, Math.max(S(0.6), scale * 0.5), 0, Math.PI * 2); ctx.fill();
  }

  // Nodo central (sede monitoreada) — anillos de ping + núcleo brillante.
  const hx = S(HOME[0]), hy = S(HOME[1]);
  for (const rr of [S(9), S(6), S(3.5)]) {
    ctx.strokeStyle = "rgba(120,255,180,0.5)";
    ctx.lineWidth = Math.max(0.5, scale * 0.12);
    ctx.beginPath(); ctx.arc(hx, hy, rr, 0, Math.PI * 2); ctx.stroke();
  }
  const hg = ctx.createRadialGradient(hx, hy, 0, hx, hy, S(7));
  hg.addColorStop(0, "rgba(180,255,210,1)");
  hg.addColorStop(0.4, "rgba(90,255,160,0.6)");
  hg.addColorStop(1, "rgba(90,255,160,0)");
  ctx.fillStyle = hg;
  ctx.beginPath(); ctx.arc(hx, hy, S(7), 0, Math.PI * 2); ctx.fill();
  ctx.globalCompositeOperation = "source-over";
  ctx.fillStyle = "#eafff2";
  ctx.beginPath(); ctx.arc(hx, hy, Math.max(S(1), scale * 0.8), 0, Math.PI * 2); ctx.fill();

  return canvas.toDataURL("image/png");
}
