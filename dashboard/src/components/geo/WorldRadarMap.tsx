/**
 * WorldRadarMap — mapa mundial estilo "radar táctico" (SVG, offline).
 *
 * Diseño: fondo negro con cuadrícula (graticula lat/lon) verde oliva sobre un
 * plano inclinado en perspectiva 3D; continentes como siluetas verdes
 * translúcidas; nodo central = SEDE (Paraguay) con etiqueta + anillo de cobertura
 * + barrido de radar; trayectorias animadas origen→sede; y nodos de país de
 * origen coloreados por RIESGO (rojo/ámbar/verde) y dimensionados por volumen.
 *
 * Tamaño: el contenedor mantiene la relación 2:1 del mapa y se acota a 2×height
 * centrado → nunca se estira en monitores anchos.
 */
import { useMemo, useState } from "react";
import {
  MAP_W, MAP_H, countryShapes, countryCentroids, ringsToPath, project,
} from "@/lib/world-countries-geo";
import { cn } from "@/lib/utils";

export interface RadarCountry {
  cc: string;
  name: string;
  total: number;
  risk?: "high" | "elevated" | "normal" | string;
  unique_ips?: number;
}

const HOME = project(-57.6, -25.3); // Paraguay (sede / lgcrBL)

// Color por riesgo (R3): id de gradiente + color de núcleo + trazo.
const RISK = {
  high: { grad: "radarHigh", core: "rgba(255,180,180,0.95)", stroke: "rgba(255,90,90,0.75)" },
  elevated: { grad: "radarElev", core: "rgba(255,225,160,0.95)", stroke: "rgba(255,190,70,0.7)" },
  normal: { grad: "radarNode", core: "rgba(200,255,215,0.95)", stroke: "rgba(90,255,150,0.7)" },
} as const;
function riskKey(r?: string): keyof typeof RISK {
  return r === "high" ? "high" : r === "elevated" ? "elevated" : "normal";
}

export function WorldRadarMap({
  countries,
  className,
  height = 300,
  onSelectCountry,
}: {
  countries: RadarCountry[];
  className?: string;
  height?: number;
  onSelectCountry?: (cc: string) => void;
}) {
  const continents = useMemo(
    () => countryShapes().map((s) => ringsToPath(s.rings)).join(""),
    [],
  );
  const centroids = useMemo(() => countryCentroids(), []);
  const nodes = useMemo(() => {
    let mx = 0;
    for (const c of countries) if (c.total > mx) mx = c.total;
    mx = Math.max(1, mx);
    return countries
      .filter((c) => c.cc && c.total > 0 && centroids.has(c.cc))
      .map((c) => {
        const [x, y] = centroids.get(c.cc)!;
        const t = Math.sqrt(c.total / mx);
        return { cc: c.cc, name: c.name, value: c.total, risk: riskKey(c.risk), x, y, r: 1.4 + 9 * t, t };
      })
      .sort((a, b) => b.value - a.value);
  }, [countries, centroids]);

  // R1: trayectorias origen→sede (arco cuadrático). Sólo top-12 para no saturar.
  const trails = useMemo(() => nodes.slice(0, 12).map((n) => {
    const mx = (n.x + HOME[0]) / 2;
    const my = (n.y + HOME[1]) / 2 - Math.hypot(n.x - HOME[0], n.y - HOME[1]) * 0.22; // arco hacia arriba
    return { cc: n.cc, risk: n.risk, d: `M ${n.x} ${n.y} Q ${mx} ${my} ${HOME[0]} ${HOME[1]}` };
  }), [nodes]);

  const [hover, setHover] = useState<{ name: string; value: number } | null>(null);

  const meridians = [];
  for (let lon = -180; lon <= 180; lon += 15) meridians.push(lon + 180);
  const parallels = [];
  for (let lat = -90; lat <= 90; lat += 15) parallels.push(90 - lat);

  const maxW = Math.round(height * (MAP_W / MAP_H)); // acota ancho a 2×height

  return (
    <div className={cn("relative overflow-hidden rounded-lg", className)} style={{ background: "#04070a" }}>
      <div style={{ width: "100%", maxWidth: maxW, margin: "0 auto", perspective: 900 }}>
        <svg
          viewBox={`0 0 ${MAP_W} ${MAP_H}`}
          style={{
            display: "block", width: "100%", aspectRatio: `${MAP_W} / ${MAP_H}`,
            transform: "rotateX(30deg) scale(1.02)",
            transformOrigin: "center 55%",
          }}
          role="img"
          aria-label="Mapa radar táctico: sede Paraguay al centro, países atacantes coloreados por riesgo con trayectorias hacia la sede"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <radialGradient id="radarNode" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(120,255,160,0.95)" />
              <stop offset="35%" stopColor="rgba(57,255,110,0.5)" />
              <stop offset="100%" stopColor="rgba(57,255,110,0)" />
            </radialGradient>
            <radialGradient id="radarElev" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(255,225,150,0.95)" />
              <stop offset="35%" stopColor="rgba(255,190,70,0.5)" />
              <stop offset="100%" stopColor="rgba(255,190,70,0)" />
            </radialGradient>
            <radialGradient id="radarHigh" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(255,170,170,0.95)" />
              <stop offset="35%" stopColor="rgba(255,80,80,0.5)" />
              <stop offset="100%" stopColor="rgba(255,80,80,0)" />
            </radialGradient>
            <radialGradient id="radarHome" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(190,255,215,1)" />
              <stop offset="40%" stopColor="rgba(90,255,160,0.65)" />
              <stop offset="100%" stopColor="rgba(90,255,160,0)" />
            </radialGradient>
            {/* R6: gradiente del barrido (cono) */}
            <linearGradient id="radarSweep" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="rgba(120,255,170,0.28)" />
              <stop offset="100%" stopColor="rgba(120,255,170,0)" />
            </linearGradient>
          </defs>

          {/* Cuadrícula olive */}
          <g stroke="rgba(120,140,45,0.22)" strokeWidth={0.18}>
            {meridians.map((x, i) => <line key={`m${i}`} x1={x} y1={0} x2={x} y2={MAP_H} />)}
            {parallels.map((y, i) => <line key={`p${i}`} x1={0} y1={y} x2={MAP_W} y2={y} />)}
          </g>
          <g stroke="rgba(150,170,60,0.36)" strokeWidth={0.3}>
            <line x1={0} y1={90} x2={MAP_W} y2={90} />
            <line x1={180} y1={0} x2={180} y2={MAP_H} />
          </g>

          {/* Continentes translúcidos */}
          <path d={continents} fill="rgba(38,180,96,0.13)" stroke="rgba(70,230,120,0.34)" strokeWidth={0.12} fillRule="evenodd" />

          {/* A: anillos de cobertura de la sede (estáticos) */}
          <g fill="none" stroke="rgba(90,255,160,0.16)" strokeWidth={0.2}>
            <circle cx={HOME[0]} cy={HOME[1]} r={18} />
            <circle cx={HOME[0]} cy={HOME[1]} r={34} strokeDasharray="1.5 2" />
          </g>

          {/* R6: barrido de radar desde la sede */}
          <g style={{ mixBlendMode: "screen" }}>
            <path d={`M ${HOME[0]} ${HOME[1]} L ${HOME[0] + 34} ${HOME[1]} A 34 34 0 0 1 ${HOME[0] + 33} ${HOME[1] + 8} Z`} fill="url(#radarSweep)">
              <animateTransform attributeName="transform" type="rotate"
                from={`0 ${HOME[0]} ${HOME[1]}`} to={`360 ${HOME[0]} ${HOME[1]}`} dur="6s" repeatCount="indefinite" />
            </path>
          </g>

          {/* R1: trayectorias origen→sede + disparo de luz que viaja */}
          <g style={{ mixBlendMode: "screen" }}>
            {trails.map((tr, i) => (
              <g key={`t${tr.cc}`}>
                <path d={tr.d} fill="none" stroke={RISK[tr.risk].stroke} strokeWidth={0.18} opacity={0.5} />
                <circle r={0.7} fill={RISK[tr.risk].core}>
                  <animateMotion dur={`${3 + (i % 4) * 0.7}s`} repeatCount="indefinite" path={tr.d} rotate="auto" />
                  <animate attributeName="opacity" values="0;1;0" dur={`${3 + (i % 4) * 0.7}s`} repeatCount="indefinite" />
                </circle>
              </g>
            ))}
          </g>

          {/* Nodos de país de origen (color por riesgo) */}
          <g style={{ mixBlendMode: "screen" }}>
            {nodes.map((n, i) => (
              <g key={n.cc}
                 onMouseEnter={() => setHover({ name: n.name, value: n.value })}
                 onMouseLeave={() => setHover(null)}
                 onClick={() => onSelectCountry?.(n.cc)}
                 style={{ cursor: onSelectCountry ? "pointer" : "default" }}>
                <circle cx={n.x} cy={n.y} r={n.r * 2} fill={`url(#${RISK[n.risk].grad})`} />
                <circle cx={n.x} cy={n.y} r={Math.max(0.5, n.r * 0.35)} fill={RISK[n.risk].core} />
                {i < 8 && (
                  <circle cx={n.x} cy={n.y} r={n.r} fill="none" stroke={RISK[n.risk].stroke} strokeWidth={0.25}>
                    <animate attributeName="r" values={`${n.r};${n.r * 3.2}`} dur="2.4s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.7;0" dur="2.4s" repeatCount="indefinite" />
                  </circle>
                )}
              </g>
            ))}
          </g>

          {/* A: nodo central (sede Paraguay) con ping + etiqueta */}
          <g style={{ mixBlendMode: "screen" }}>
            <circle cx={HOME[0]} cy={HOME[1]} r={7} fill="url(#radarHome)" />
            {[0, 0.8, 1.6].map((delay, i) => (
              <circle key={i} cx={HOME[0]} cy={HOME[1]} r={2} fill="none" stroke="rgba(150,255,200,0.85)" strokeWidth={0.35}>
                <animate attributeName="r" values="2;11" dur="2.4s" begin={`${delay}s`} repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.85;0" dur="2.4s" begin={`${delay}s`} repeatCount="indefinite" />
              </circle>
            ))}
            <circle cx={HOME[0]} cy={HOME[1]} r={1} fill="#eafff2" />
          </g>
          {/* Etiqueta de la sede (sin tilt: contrarresta el rotateX) */}
          <g transform={`translate(${HOME[0]} ${HOME[1]})`}>
            <text x={4} y={-3} fontSize={4.2} fontWeight={700} fill="#d8fff0"
              style={{ paintOrder: "stroke", stroke: "rgba(4,7,10,0.9)", strokeWidth: 1.1 }}>🇵🇾 PARAGUAY</text>
            <text x={4} y={1.4} fontSize={2.8} fill="rgba(150,255,200,0.85)"
              style={{ paintOrder: "stroke", stroke: "rgba(4,7,10,0.9)", strokeWidth: 0.9 }}>SEDE · monitoreo</text>
          </g>
        </svg>
      </div>

      {/* Leyenda */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-2 py-1 text-[10px]" style={{ color: "rgba(120,200,150,0.8)" }}>
        <span>🇵🇾 Sede Paraguay · trayectorias = origen→sede</span>
        <span className="flex items-center gap-2">
          <span style={{ color: "rgba(255,120,120,0.9)" }}>● alto</span>
          <span style={{ color: "rgba(255,200,90,0.9)" }}>● elevado</span>
          <span style={{ color: "rgba(120,255,160,0.9)" }}>● normal</span>
          <span>· {nodes.length} países</span>
        </span>
      </div>

      {hover && (
        <div className="pointer-events-none absolute left-2 top-2 rounded px-2 py-1 text-xs"
             style={{ background: "rgba(4,12,8,0.9)", color: "#aaffcc", border: "1px solid rgba(70,230,120,0.4)" }}>
          <span className="font-medium">{hover.name}</span>
          <span className="ml-1.5" style={{ color: "rgba(120,200,150,0.8)" }}>{hover.value} incidentes</span>
        </div>
      )}
    </div>
  );
}
