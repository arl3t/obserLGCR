import type { MetricPoint } from "./helpers";
import { buildChartPath, chartYTicks, rttStats } from "./helpers";

interface MetricChartProps {
  title: string;
  rangeLabel?: string;
  unit: string;
  points: MetricPoint[];
  loading?: boolean;
  valueFormatter?: (v: number) => string;
  yTickFormatter?: (v: number) => string;
  gradientId: string;
  lineColor?: string;
}

export function MetricChart({
  title,
  rangeLabel = "Últimas 24 horas",
  unit,
  points,
  loading,
  valueFormatter = (v) => String(Math.round(v)),
  yTickFormatter = (v) => `${v}${unit}`,
  gradientId,
  lineColor = "#60a5fa",
}: MetricChartProps) {
  const stats = rttStats(points);
  const yTicks = chartYTicks(stats?.max ?? (unit === "%" ? 100 : 800));
  const linePath = buildChartPath(points);
  const areaPath =
    linePath && points.length >= 2 ? `${linePath} L400,200 L0,200 Z` : "";

  const ariaLabel = stats
    ? `${title}: promedio ${valueFormatter(stats.avg)} ${unit}`
    : `Sin datos de ${title}`;

  return (
    <>
      <div className="ut-chart-head">
        <h2 className="ut-chart-head__title">{title}</h2>
        <span className="ut-chart-head__range">{rangeLabel}</span>
      </div>

      {loading ? (
        <p className="ut-sidebar__text">Cargando métricas…</p>
      ) : points.length < 2 ? (
        <p className="ut-sidebar__text">Sin muestras en las últimas 24 h.</p>
      ) : (
        <div className="ut-chart">
          <ol className="ut-chart__y" aria-hidden="true">
            {yTicks.map((t) => (
              <li key={t}>{yTickFormatter(t)}</li>
            ))}
          </ol>
          <div className="ut-chart__plot">
            <div className="ut-chart__grid" aria-hidden="true">
              {yTicks.map((t) => (
                <span key={t} className="ut-chart__grid-line" />
              ))}
            </div>
            <svg
              className="ut-chart__svg"
              viewBox="0 0 400 200"
              preserveAspectRatio="none"
              role="img"
              aria-label={ariaLabel}
            >
              <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={lineColor} stopOpacity="0.25" />
                  <stop offset="100%" stopColor={lineColor} stopOpacity="0" />
                </linearGradient>
              </defs>
              {areaPath && <path fill={`url(#${gradientId})`} d={areaPath} />}
              {linePath && (
                <path className="ut-chart__line" d={linePath} style={{ stroke: lineColor }} />
              )}
            </svg>
          </div>
        </div>
      )}

      {stats && (
        <div className="ut-perf-stats">
          <div className="ut-perf-stat">
            <div>
              <p className="ut-perf-stat__label">Promedio</p>
              <p className="ut-perf-stat__value">
                {valueFormatter(stats.avg)} {unit}
              </p>
            </div>
          </div>
          <div className="ut-perf-stat">
            <div>
              <p className="ut-perf-stat__label">Mínimo</p>
              <p className="ut-perf-stat__value">
                {valueFormatter(stats.min)} {unit}
              </p>
            </div>
          </div>
          <div className="ut-perf-stat">
            <div>
              <p className="ut-perf-stat__label">Máximo</p>
              <p className="ut-perf-stat__value">
                {valueFormatter(stats.max)} {unit}
              </p>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
