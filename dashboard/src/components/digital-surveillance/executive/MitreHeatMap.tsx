/**
 * MitreHeatMap — vista de cobertura MITRE ATT&CK derivada de los findings.
 *
 * Toma el feed unificado del Provider (`findings: AnalystFinding[]`) y los
 * agrupa por táctica MITRE ATT&CK usando `MITRE_BY_KIND`. Cada táctica
 * muestra:
 *   - nombre canónico (ej. "Credential Access")
 *   - conteo de findings que mapean a esa táctica
 *   - chips de técnicas concretas (T1078, T1110.004, …) coloreadas por
 *     intensidad relativa (cuán frecuentes son comparado con el resto)
 *
 * No muestra tácticas sin findings — el heatmap es de cobertura observada,
 * no del catálogo completo de ATT&CK. Si no hay findings, el bloque se oculta
 * (en lugar de mostrar un "sin datos" gigante).
 *
 * Dependencias: `MITRE_BY_KIND` ya existente en
 * `risk-engine/mitre-attack-map.ts`. Si se decide ampliar TTPs, sólo hay que
 * tocar ese mapeo.
 */

import { useMemo } from "react";
import { Crosshair, ExternalLink } from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import {
  MITRE_BY_KIND,
  type MitreTtp,
} from "@/components/digital-surveillance/risk-engine/mitre-attack-map";
import type { AnalystFinding, AnalystFindingKind } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

type TacticRow = {
  tactic: string;             // TA0006
  tacticName: string;         // "Credential Access"
  count: number;              // total findings mapeados a esta táctica
  techniques: Array<{
    technique: string;        // T1078
    techniqueName: string;
    count: number;
    url: string;
  }>;
};

/** Agrega los findings por táctica MITRE ATT&CK. Cada finding contribuye 1
 *  por TÉCNICA distinta del kind (no se cuentan duplicados de la misma TTP
 *  desde el mismo finding). Tácticas sin findings se omiten. */
function aggregateByTactic(findings: AnalystFinding[]): TacticRow[] {
  const tactics = new Map<string, TacticRow>();

  for (const f of findings) {
    const ttps = MITRE_BY_KIND[f.kind] ?? [];
    for (const ttp of ttps) {
      // El kind "correlation" tiene placeholder "Multiple" — lo agrupamos como
      // contribución multi-táctica de severidad alta, pero no creamos una
      // entry "Multiple". Lo tratamos como aporte +1 a cada táctica detectada
      // por OTROS findings — es decir, lo saltamos en este loop y se contará
      // implícitamente vía las demás referencias.
      if (ttp.tactic === "Multiple") continue;

      const existing = tactics.get(ttp.tactic);
      if (existing) {
        existing.count += 1;
        const tx = existing.techniques.find((t) => t.technique === ttp.technique);
        if (tx) tx.count += 1;
        else
          existing.techniques.push({
            technique: ttp.technique,
            techniqueName: ttp.techniqueName,
            count: 1,
            url: ttp.url,
          });
      } else {
        tactics.set(ttp.tactic, {
          tactic: ttp.tactic,
          tacticName: ttp.tacticName,
          count: 1,
          techniques: [
            {
              technique: ttp.technique,
              techniqueName: ttp.techniqueName,
              count: 1,
              url: ttp.url,
            },
          ],
        });
      }
    }
  }

  return Array.from(tactics.values())
    .sort((a, b) => b.count - a.count)
    .map((row) => ({
      ...row,
      techniques: row.techniques.sort((a, b) => b.count - a.count),
    }));
}

/** Mapea intensidad 0-1 → clase de color tailwind para el chip de técnica. */
function intensityClass(intensity: number): string {
  if (intensity >= 0.8) return "border-red-500/50 bg-red-500/15 text-red-700 dark:text-red-300";
  if (intensity >= 0.5) return "border-amber-500/50 bg-amber-500/15 text-amber-700 dark:text-amber-300";
  if (intensity >= 0.2) return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  return "border-border/60 bg-muted/40 text-muted-foreground";
}

/** Top contributing kinds — para el resumen "X kinds aportaron a Y técnicas". */
function topKindsByCount(findings: AnalystFinding[], topN = 3): Array<{ kind: AnalystFindingKind; count: number }> {
  const map = new Map<AnalystFindingKind, number>();
  for (const f of findings) {
    if ((MITRE_BY_KIND[f.kind] ?? []).length === 0) continue;
    map.set(f.kind, (map.get(f.kind) ?? 0) + 1);
  }
  return Array.from(map.entries())
    .map(([kind, count]) => ({ kind, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, topN);
}

const KIND_LABEL: Record<AnalystFindingKind, string> = {
  "credential-leak":        "Fugas de credenciales",
  "shodan-exposure":        "Exposición Shodan",
  "misp-ioc":               "IOCs MISP",
  "brand-mention-negative": "Menciones negativas",
  "news-coverage":          "Cobertura RSS",
  "brand-threat":           "Amenazas DRP",
  "correlation":            "Correlaciones",
};

export function MitreHeatMap() {
  const { findings } = useSurveillance();

  const rows = useMemo(() => aggregateByTactic(findings), [findings]);
  const topKinds = useMemo(() => topKindsByCount(findings), [findings]);

  // Sin cobertura ATT&CK observada — ocultamos el bloque (evita pantalla de
  // "no hay datos" inflada en dominios saludables / poco analizados).
  if (rows.length === 0) return null;

  const maxCount = Math.max(...rows.map((r) => r.count), 1);
  const totalTechniques = rows.reduce(
    (acc, r) => acc + r.techniques.length,
    0,
  );

  return (
    <section className="rounded-2xl border border-border bg-card shadow-sm">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 px-6 py-4">
        <div className="flex items-center gap-2">
          <Crosshair className="h-4 w-4 text-emerald-500" aria-hidden />
          <h2 className="text-sm font-semibold uppercase tracking-widest text-foreground">
            Cobertura MITRE ATT&CK
          </h2>
          <span className="text-[11px] text-muted-foreground">
            {rows.length} táctica{rows.length === 1 ? "" : "s"} · {totalTechniques} técnicas observadas
          </span>
        </div>
        <a
          href="https://mitre-attack.github.io/attack-navigator/"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
          title="Para visualizar en ATT&CK Navigator, exportar layer desde Workspace → ATT&CK"
        >
          <ExternalLink className="h-3 w-3" aria-hidden />
          Navigator
        </a>
      </header>

      <ul className="divide-y divide-border/50">
        {rows.map((row) => (
          <li key={row.tactic} className="px-6 py-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  {row.tactic}
                </span>
                <span className="text-sm font-semibold text-foreground">
                  {row.tacticName}
                </span>
              </div>
              <span className="font-mono text-xs tabular-nums text-muted-foreground">
                {row.count} {row.count === 1 ? "finding" : "findings"}
              </span>
            </div>

            {/* Bar — intensidad relativa al máximo observado en la pantalla */}
            <div className="mt-2 flex items-center gap-3">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500"
                  style={{ width: `${(row.count / maxCount) * 100}%` }}
                  aria-hidden
                />
              </div>
            </div>

            {/* Chips de técnicas concretas */}
            <div className="mt-2 flex flex-wrap gap-1.5">
              {row.techniques.map((tx) => {
                const intensity = tx.count / maxCount;
                return (
                  <a
                    key={tx.technique}
                    href={tx.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={cn(
                      "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[10px] transition-colors hover:opacity-80",
                      intensityClass(intensity),
                    )}
                    title={`${tx.technique} · ${tx.techniqueName} · ${tx.count} finding(s)`}
                  >
                    <span className="font-bold tabular-nums">{tx.technique}</span>
                    <span className="opacity-70">·</span>
                    <span className="truncate max-w-[180px] sm:max-w-none">
                      {tx.techniqueName}
                    </span>
                    {tx.count > 1 && (
                      <span className="ml-1 rounded-sm bg-background/60 px-1 text-[9px] font-bold tabular-nums">
                        ×{tx.count}
                      </span>
                    )}
                  </a>
                );
              })}
            </div>
          </li>
        ))}
      </ul>

      {topKinds.length > 0 && (
        <footer className="flex flex-wrap items-center gap-2 border-t border-border/50 px-6 py-3 text-[10px] text-muted-foreground">
          <span className="uppercase tracking-wider">Aportan principalmente:</span>
          {topKinds.map((k, i) => (
            <span key={k.kind} className="inline-flex items-center">
              {i > 0 && <span className="mx-1 text-muted-foreground/50">·</span>}
              <span className="font-medium text-foreground/80">{KIND_LABEL[k.kind]}</span>
              <span className="ml-1 font-mono tabular-nums">({k.count})</span>
            </span>
          ))}
        </footer>
      )}
    </section>
  );
}

/** Indica si hay cobertura ATT&CK no-vacía dado un set de findings. Útil para
 *  decidir si vale la pena renderizar `<MitreHeatMap />` desde un padre. */
export function hasMitreCoverage(findings: AnalystFinding[]): boolean {
  for (const f of findings) {
    const ttps = (MITRE_BY_KIND[f.kind] ?? []) as MitreTtp[];
    if (ttps.some((t) => t.tactic !== "Multiple")) return true;
  }
  return false;
}
