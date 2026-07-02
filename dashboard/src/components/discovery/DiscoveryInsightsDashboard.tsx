import { AlertTriangle, CheckCircle2, Shield } from "lucide-react";
import type { DiscoveryRun, DiscoveryStats } from "@/api/discovery";
import { DiscoveryKpiCharts } from "./DiscoveryKpiCharts";

type Props = {
  stats: DiscoveryStats | undefined;
  run: DiscoveryRun | undefined;
  loading: boolean;
};

function computeRiskScore(stats: DiscoveryStats): { score: number; level: "low" | "medium" | "high" | "critical"; hints: string[] } {
  const hints: string[] = [];
  let score = 0;

  const cves = stats.cves_total ?? 0;
  const undocumented = Math.max(0, stats.hosts_up - stats.documented);
  const docRatio = stats.hosts_up > 0 ? stats.documented / stats.hosts_up : 1;

  score += Math.min(40, cves * 8);
  if (cves > 0) hints.push(`${cves} CVE detectados en el segmento`);

  score += Math.min(25, undocumented * 3);
  if (undocumented > 0) hints.push(`${undocumented} hosts activos sin documentar`);

  score += Math.min(20, stats.ports_open / 5);
  if (stats.ports_open > 50) hints.push(`${stats.ports_open} puertos abiertos — superficie amplia`);

  if (docRatio < 0.5 && stats.hosts_up > 3) {
    score += 15;
    hints.push("Cobertura de documentación por debajo del 50%");
  }

  score = Math.min(100, Math.round(score));

  let level: "low" | "medium" | "high" | "critical" = "low";
  if (score >= 75) level = "critical";
  else if (score >= 50) level = "high";
  else if (score >= 25) level = "medium";

  if (hints.length === 0) hints.push("Sin hallazgos críticos en este escaneo");

  return { score, level, hints };
}

export function DiscoveryInsightsDashboard({ stats, run, loading }: Props) {
  const risk = stats ? computeRiskScore(stats) : null;

  return (
    <div className="discovery-insights">
      {run && (
        <div className="discovery-insights__run-bar">
          <div>
            <span className="text-[11px] text-muted-foreground">Análisis del escaneo</span>
            <p className="obser-mono text-sm font-medium text-cyan-300">#{run.id} · {run.targets}</p>
          </div>
          {run.nmap_command && (
            <code className="discovery-insights__cmd obser-mono hidden text-[10px] text-emerald-300/80 lg:block">
              {run.nmap_command}
            </code>
          )}
          {run.duration_ms != null && (
            <span className="text-[11px] text-muted-foreground">{(run.duration_ms / 1000).toFixed(1)}s</span>
          )}
        </div>
      )}

      {risk && stats && (
        <div className={`discovery-risk-card discovery-risk-card--${risk.level}`}>
          <div className="discovery-risk-card__score">
            <Shield className="h-5 w-5" />
            <div>
              <p className="text-[10px] uppercase tracking-wider opacity-70">Índice de riesgo</p>
              <p className="obser-mono text-2xl font-bold">{risk.score}<span className="text-sm font-normal opacity-60">/100</span></p>
            </div>
          </div>
          <ul className="discovery-risk-card__hints">
            {risk.hints.map((h) => (
              <li key={h}>
                {risk.level === "low" ? (
                  <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-400" />
                ) : (
                  <AlertTriangle className="h-3 w-3 shrink-0" />
                )}
                {h}
              </li>
            ))}
          </ul>
        </div>
      )}

      <DiscoveryKpiCharts stats={stats} loading={loading} />
    </div>
  );
}
