import type { MetricPoint } from "./helpers";
import { buildChartPath, chartYTicks, rttStats } from "./helpers";

interface ResponseChartProps {
  points: MetricPoint[];
  loading?: boolean;
}

export function ResponseChart({ points, loading }: ResponseChartProps) {
  const stats = rttStats(points);
  const yTicks = chartYTicks(stats?.max ?? 800);
  const linePath = buildChartPath(points);
  const areaPath =
    linePath && points.length >= 2
      ? `${linePath} L400,200 L0,200 Z`
      : "";

  const ariaLabel = stats
    ? `Tiempos de respuesta: promedio ${stats.avg} ms, mínimo ${stats.min} ms, máximo ${stats.max} ms`
    : "Sin datos de tiempos de respuesta";

  return (
    <>
      <div className="ut-chart-head">
        <h2 className="ut-chart-head__title">Response Times</h2>
        <span className="ut-chart-head__range">Últimas 24 horas</span>
      </div>

      {loading ? (
        <p className="ut-sidebar__text">Cargando métricas…</p>
      ) : points.length < 2 ? (
        <p className="ut-sidebar__text">Sin muestras de RTT en las últimas 24 h.</p>
      ) : (
        <div className="ut-chart">
          <ol className="ut-chart__y" aria-hidden="true">
            {yTicks.map((t) => (
              <li key={t}>{t}ms</li>
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
                <linearGradient id="utAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#60a5fa" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#60a5fa" stopOpacity="0" />
                </linearGradient>
              </defs>
              {areaPath && <path fill="url(#utAreaGrad)" d={areaPath} />}
              {linePath && <path className="ut-chart__line" d={linePath} />}
            </svg>
          </div>
        </div>
      )}

      {stats && (
        <div className="ut-perf-stats">
          <div className="ut-perf-stat">
            <span className="ut-perf-stat__icon" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 20V10M18 20V4M6 20v-4" />
              </svg>
            </span>
            <div>
              <p className="ut-perf-stat__label">Average</p>
              <p className="ut-perf-stat__value">{stats.avg} ms</p>
            </div>
          </div>
          <div className="ut-perf-stat">
            <span className="ut-perf-stat__icon" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 19V5M5 12l7-7 7 7" />
              </svg>
            </span>
            <div>
              <p className="ut-perf-stat__label">Minimum</p>
              <p className="ut-perf-stat__value">{stats.min} ms</p>
            </div>
          </div>
          <div className="ut-perf-stat">
            <span className="ut-perf-stat__icon" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12l7 7 7-7" />
              </svg>
            </span>
            <div>
              <p className="ut-perf-stat__label">Maximum</p>
              <p className="ut-perf-stat__value">{stats.max} ms</p>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
