/**
 * HistoryTimelineCard — visualización del histórico de análisis del dominio.
 *
 * Line chart con últimos 20 risk scores. Bandas horizontales por thresholds
 * (40 medio · 70 alto). Tooltip muestra (queriedAt, score, count crit/high)
 * por punto. Los badges de Δ vs análisis previo viven ahora en el
 * `ExecutiveHero` — esta card sólo muestra el chart + nota de origen.
 *
 * Si solo hay 1 análisis (la primera vez), se oculta — no hay nada que
 * comparar y el chart de 1 punto no aporta.
 */

import { useMemo } from "react";
import { History, Loader2 } from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { useAnalysisHistory, type AnalysisRow } from "@/hooks/useSurveillanceWorkspace";
import { PY_TZ } from "@/lib/format";

export function HistoryTimelineCard() {
  const { domain } = useSurveillance();
  const historyQ = useAnalysisHistory(domain, 20);

  const sorted = useMemo<AnalysisRow[]>(
    () => (historyQ.data ?? []).slice().sort(
      (a, b) => +new Date(a.queried_at) - +new Date(b.queried_at),
    ),
    [historyQ.data],
  );

  // Mientras esperamos el primer fetch o si nunca hubo análisis: oculto.
  if (historyQ.isLoading) {
    return (
      <section className="rounded-2xl border border-border bg-card p-6 shadow-sm">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          Cargando histórico…
        </div>
      </section>
    );
  }
  if (sorted.length < 2) return null;

  const chartData = sorted.map((row) => ({
    queriedAt: row.queried_at,
    queriedAtLabel: new Date(row.queried_at).toLocaleString("es-PY", {
      timeZone: PY_TZ,
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    }),
    score: row.risk_score,
    critical: row.findings_critical,
    high: row.findings_high,
    band: row.risk_band,
  }));

  return (
    <section className="rounded-2xl border border-border bg-card p-6 shadow-sm">
      <header className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-emerald-500" aria-hidden />
          <h2 className="text-sm font-semibold uppercase tracking-widest text-foreground">
            Evolución histórica
          </h2>
          <span className="text-[11px] text-muted-foreground">
            {sorted.length} análisis registrados
          </span>
        </div>
      </header>

      {/* Chart */}
      <div className="h-44 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-border/40" />
            {/* Bandas horizontales por riskBand */}
            <ReferenceArea y1={0}  y2={40}  fill="rgba(16,185,129,0.05)" stroke="none" />
            <ReferenceArea y1={40} y2={70}  fill="rgba(245,158,11,0.05)" stroke="none" />
            <ReferenceArea y1={70} y2={100} fill="rgba(239,68,68,0.06)"  stroke="none" />
            <XAxis
              dataKey="queriedAtLabel"
              tick={{ fontSize: 9 }}
              interval="preserveStartEnd"
              minTickGap={32}
            />
            <YAxis
              domain={[0, 100]}
              ticks={[0, 40, 70, 100]}
              tick={{ fontSize: 9 }}
              width={28}
            />
            <Tooltip
              contentStyle={{ fontSize: 11, padding: "6px 10px" }}
              labelFormatter={(l) => `Análisis: ${l}`}
              formatter={(_v, _name, p) => {
                const d = p?.payload as typeof chartData[number] | undefined;
                if (!d) return null;
                return [
                  `${d.score}/100 (${d.band}) · ${d.critical} crit · ${d.high} high`,
                  "Risk",
                ];
              }}
            />
            <Line
              type="monotone"
              dataKey="score"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={{ r: 3, strokeWidth: 1 }}
              activeDot={{ r: 5 }}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Footer: nota de origen */}
      <p className="mt-3 border-t border-border/50 pt-2 text-[11px] text-muted-foreground">
        Snapshot automático cada vez que un analista carga el Workspace de este dominio.
        Cobertura limitada por la frecuencia con la que se consulta — vacíos largos
        indican períodos sin actividad SOC sobre <span className="font-mono">{domain}</span>.
      </p>
    </section>
  );
}
