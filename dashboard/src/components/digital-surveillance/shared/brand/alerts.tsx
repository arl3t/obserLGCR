/**
 * Alertas accionables de marca (§3.2.2 del rediseño).
 *
 * Lógica de cómputo (`computeBrandAlerts`) + UI (`BrandAlertsBlock`). Las que
 * van con `socFinding` se renderizan vía `RiskFactorWithSocAction` para
 * permitir abrir caso SOC en un click; las demás (anomalías de volumen) son
 * tarjetas informativas con border lateral por severidad.
 *
 * Reglas:
 *   1. Spike negativo: ratio negativo ≥ 60% con n ≥ 20 muestras.
 *   2. Anomalía de volumen: |delta| ≥ 100% vs período anterior.
 *   3. Top N menciones de alto reach + sentimiento negativo (n=3, reach ≥ 100k).
 */

import { AlertTriangle, ExternalLink } from "lucide-react";
import { RiskFactorWithSocAction } from "@/components/digital-surveillance/shared/RiskFactorWithSocAction";
import { bandBorder } from "@/components/digital-surveillance/shared/band-styles";
import { formatCompactNumber } from "@/components/digital-surveillance/shared/format";
import type {
  Brand24Mention,
  RiskBand,
  SurveillanceBrand24Result,
} from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

export type BrandAlertSeverity = "high" | "medium" | "low";

export type BrandAlert = {
  id: string;
  severity: BrandAlertSeverity;
  title: string;
  detail: string;
  mention?: Brand24Mention;
  socFinding?: { id: string; title: string; detail: string; score: number };
};

const HIGH_REACH_THRESHOLD = 100_000;
const NEG_RATIO_THRESHOLD = 0.6;
const NEG_RATIO_MIN_SAMPLE = 20;
const VOLUME_ANOMALY_PCT = 100;
const HIGH_REACH_ALERTS_TOP_N = 3;

function truncateSnippet(text: string, max = 80): string {
  if (!text) return "";
  return text.length <= max ? text : `${text.slice(0, max)}…`;
}

export function computeBrandAlerts(b24: SurveillanceBrand24Result): BrandAlert[] {
  const alerts: BrandAlert[] = [];
  const s = b24.summary;
  if (!s) return alerts;

  // 1) Spike de sentimiento negativo (n≥20, ratio≥60%)
  const total = s.positiveCount + s.negativeCount;
  if (total >= NEG_RATIO_MIN_SAMPLE) {
    const negRatio = s.negativeCount / total;
    if (negRatio >= NEG_RATIO_THRESHOLD) {
      const pct = Math.round(negRatio * 100);
      const score = Math.min(20, Math.round(negRatio * 25));
      alerts.push({
        id: "neg-ratio",
        severity: "high",
        title: "Spike de menciones negativas",
        detail: `${pct}% negativas (${s.negativeCount}/${total} clasificadas).`,
        socFinding: {
          id: "brand24-neg-ratio",
          title: "Spike de sentimiento negativo en marca",
          detail: `${pct}% negativas (${s.negativeCount}/${total}). Brand24.`,
          score,
        },
      });
    }
  }

  // 2) Anomalía de volumen (|delta| ≥ 100%)
  if (Number.isFinite(s.volumeDeltaPercent) && Math.abs(s.volumeDeltaPercent) >= VOLUME_ANOMALY_PCT) {
    const delta = Math.round(s.volumeDeltaPercent);
    const sev: BrandAlertSeverity = s.volumeDeltaPercent > 0 ? "medium" : "low";
    alerts.push({
      id: "vol-anomaly",
      severity: sev,
      title: `Anomalía de volumen: ${delta > 0 ? "+" : ""}${delta}%`,
      detail: `${s.volumeMentions.toLocaleString("es-PY")} menciones vs período anterior.`,
    });
  }

  // 3) Top N menciones de alto reach + negativas
  const highReach = b24.mentions
    .filter((m) => m.sentiment === "negative" && (m.reach ?? 0) >= HIGH_REACH_THRESHOLD)
    .sort((a, b) => (b.reach ?? 0) - (a.reach ?? 0))
    .slice(0, HIGH_REACH_ALERTS_TOP_N);

  for (const m of highReach) {
    const reachLabel = formatCompactNumber(m.reach ?? 0);
    alerts.push({
      id: `high-reach-${m.id}`,
      severity: "high",
      title: "Mención de alto reach con sentimiento negativo",
      detail: `${m.author} · ${m.source} · alcance ${reachLabel} · "${truncateSnippet(m.snippet)}"`,
      mention: m,
      socFinding: {
        id: `brand24-mention-${m.id}`,
        title: `Mención negativa de alto reach (${m.source})`,
        detail: `${m.author} · alcance ${reachLabel} · "${truncateSnippet(m.snippet, 200)}"`,
        score: 18,
      },
    });
  }

  return alerts;
}

export function BrandAlertsBlock({ domain, alerts }: { domain: string; alerts: BrandAlert[] }) {
  if (alerts.length === 0) return null;
  return (
    <div className="space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <AlertTriangle className="h-4 w-4 text-amber-500" aria-hidden />
        Alertas accionables ({alerts.length})
      </h3>
      <div className="space-y-2">
        {alerts.map((a) => {
          if (a.socFinding) {
            return (
              <div key={a.id} className="space-y-1">
                <RiskFactorWithSocAction domain={domain} factor={a.socFinding} />
                {a.mention?.url && (
                  <a
                    href={a.mention.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-4 inline-flex items-center gap-1 text-[11px] text-primary hover:underline"
                  >
                    Ver original <ExternalLink className="h-3 w-3" aria-hidden />
                  </a>
                )}
              </div>
            );
          }
          // Alertas sin SOC CTA (anomalía de volumen): tarjeta simple
          const band: RiskBand =
            a.severity === "high" ? "high" : a.severity === "medium" ? "medium" : "low";
          return (
            <div
              key={a.id}
              className={cn(
                "rounded-xl border border-border/60 border-l-4 p-4",
                bandBorder[band],
              )}
            >
              <p className="text-sm font-semibold">{a.title}</p>
              <p className="mt-1 text-xs text-muted-foreground">{a.detail}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
