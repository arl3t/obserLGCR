import { useMemo } from "react";
import { ExternalLink, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useTrinoNamed } from "@/hooks/useTrinoQuery";
import { playbookForSeverity } from "@/lib/incident-playbooks";
import { ThcRdnsEnrichment } from "./ThcRdnsEnrichment";
import { IncidentPlaybookCard } from "./IncidentPlaybookCard";
import { isPublicIpv4ForThc } from "@/hooks/useThcReverseDns";

function num(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") {
    const n = Number(v);
    return Number.isNaN(n) ? 0 : n;
  }
  return 0;
}

function str(v: unknown): string {
  return v == null ? "—" : String(v);
}

function isIpForBreakdown(s: string): boolean {
  const t = s.trim();
  return t.length >= 7 && t.length <= 45 && /^[0-9a-fA-F.:]+$/.test(t);
}

function truthyFeed(v: unknown): boolean {
  return v === true || v === "true";
}

function BreakdownScoreBar({
  label,
  value,
  max,
  color,
}: {
  label: string;
  value: number;
  max: number;
  color: string;
}) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px]">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium tabular-nums">
          {value} / {max}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-border">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function mergeRows(
  base: Record<string, unknown> | null | undefined,
  latest: Record<string, unknown> | null | undefined,
): Record<string, unknown> | null {
  if (!base && !latest) return null;
  if (!base) return latest ?? null;
  if (!latest) return base;
  return { ...base, ...latest };
}

export type IncidentScoringBreakdownProps = {
  /** Fila con campos de scoring (motor_scoring o incident_classifications). */
  summaryRow?: Record<string, unknown> | null;
  /** IOC para historial en Trino; por defecto `summaryRow.ioc_value`. */
  queryIoc?: string | null;
  skipHistoryQuery?: boolean;
  /** Nivel numérico Wazuh de la alerta en vivo (p. ej. force-ack) si no hay fila lake. */
  wazuhLevelHint?: number | null;
  showPlaybook?: boolean;
  /** Severidad para el playbook si no hay fila merged (p. ej. modal). */
  playbookSeverityFallback?: string | null;
  compact?: boolean;
};

export function IncidentScoringBreakdown({
  summaryRow = null,
  queryIoc = null,
  skipHistoryQuery = false,
  wazuhLevelHint = null,
  showPlaybook = true,
  playbookSeverityFallback = null,
  compact = false,
}: IncidentScoringBreakdownProps) {
  const iocRaw =
    queryIoc != null && String(queryIoc).trim() !== ""
      ? String(queryIoc).trim()
      : summaryRow?.ioc_value != null
        ? str(summaryRow.ioc_value)
        : "";
  const runQuery = !skipHistoryQuery && isIpForBreakdown(iocRaw);

  const breakdown = useTrinoNamed(
    ["incidents", "score-breakdown-ui", iocRaw],
    "lh.incidents.score_breakdown",
    { ip: iocRaw, hours: 168 },
    { enabled: runQuery, staleTime: 2 * 60_000 },
  );

  // Multiplicadores v4 (geo/novelty/killchain) — fuente aislada (v4_mat).
  const mult = useTrinoNamed(
    ["incidents", "score-multipliers-ui", iocRaw],
    "lh.incidents.score_multipliers",
    { ip: iocRaw, hours: 168 },
    { enabled: runQuery, staleTime: 2 * 60_000 },
  );
  const v4 = (mult.data?.[0] ?? null) as Record<string, unknown> | null;

  const merged = useMemo(() => {
    const latest = breakdown.data?.[0] as Record<string, unknown> | undefined;
    return mergeRows(summaryRow ?? null, latest ?? null);
  }, [summaryRow, breakdown.data]);

  const history = breakdown.data ?? [];
  const sevForPlaybook = str(merged?.severity || playbookSeverityFallback || "MEDIUM");
  const pb = playbookForSeverity(sevForPlaybook);

  if (!merged && wazuhLevelHint == null && !runQuery) {
    return (
      <p className="text-xs text-muted-foreground">
        Sin datos de scoring para este IOC. Indica una IP válida o carga una fila desde el lake.
      </p>
    );
  }

  if (!merged && runQuery && breakdown.isLoading) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
        Cargando desglose desde <code className="text-[10px]">motor_scoring</code>…
      </div>
    );
  }

  if (!merged && runQuery && breakdown.error) {
    return (
      <div className="space-y-2">
        <p className="text-xs text-destructive" role="alert">
          {breakdown.error.message}
        </p>
        {showPlaybook && pb && <IncidentPlaybookCard pb={pb} />}
      </div>
    );
  }

  if (!merged && wazuhLevelHint != null) {
    return (
      <div className="space-y-3">
        <p className="text-[11px] text-muted-foreground">
          Sin fila en <code className="text-[10px]">motor_scoring</code> para{" "}
          <span className="font-mono text-foreground">{iocRaw || "—"}</span>. Datos solo de la
          alerta en vivo:
        </p>
        <div className="rounded-md border border-border bg-muted/20 p-3 text-xs">
          <span className="text-muted-foreground">Nivel Wazuh (alerta): </span>
          <span className="font-mono font-semibold">{wazuhLevelHint}</span>
        </div>
        {showPlaybook && pb && <IncidentPlaybookCard pb={pb} />}
      </div>
    );
  }

  if (!merged) {
    return (
      <div className="space-y-2">
        {breakdown.error && (
          <p className="text-xs text-destructive" role="alert">
            {breakdown.error.message}
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          No hay coincidencias en <code className="text-[10px]">motor_scoring</code> para esta IP
          en los últimos días.
        </p>
        {showPlaybook && pb && <IncidentPlaybookCard pb={pb} />}
      </div>
    );
  }

  const sm = num(merged.score_mitre);
  const se = num(merged.score_evidence);
  const sw = num(merged.score_wazuh);
  const total = num(merged.score);
  const sev = str(merged.severity);

  const showThcRdns =
    str(merged.ioc_type).toLowerCase() === "ip" || isPublicIpv4ForThc(iocRaw);

  return (
    <div className={compact ? "space-y-3" : "space-y-4"}>
      {showThcRdns && (
        <ThcRdnsEnrichment ip={iocRaw} enabled className={compact ? "text-[10px]" : undefined} />
      )}
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            Última actividad en vista
          </p>
          <p className="mt-0.5 font-mono text-sm text-foreground">
            Día IOC (partición): <span className="font-semibold">{str(merged.dt)}</span>
          </p>
          {runQuery && history.length > 1 && (
            <p className="mt-1 text-[10px] text-muted-foreground">
              {history.length} apariciones recientes en{" "}
              <code className="text-[9px]">motor_scoring</code> (misma IP).
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <Badge variant={sev === "CRITICAL" ? "destructive" : "outline"} className="text-[10px]">
            {sev}
          </Badge>
          <Badge variant="secondary" className="font-mono text-[10px]">
            {total} / 100
          </Badge>
        </div>
      </div>

      {runQuery && history.length > 1 && (
        <div className="rounded-md border border-border/80 bg-muted/15 p-2">
          <p className="mb-1.5 text-[10px] font-medium text-muted-foreground">
            Historial reciente (fecha en vista → score)
          </p>
          <ul className="max-h-24 space-y-0.5 overflow-y-auto font-mono text-[10px] text-foreground/90">
            {history.slice(0, 8).map((h, idx) => (
              <li key={idx} className="flex justify-between gap-2 border-b border-border/30 py-0.5 last:border-0">
                <span>{str(h.dt)}</span>
                <span className="tabular-nums">
                  {num(h.score)} · {str(h.severity)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className={`rounded-md border border-border bg-muted/20 ${compact ? "p-2.5" : "p-3"}`}>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          Desglose de puntuación
        </p>
        <div className="space-y-2.5">
          <BreakdownScoreBar label="MITRE (táctica)" value={sm} max={40} color="bg-violet-500" />
          <BreakdownScoreBar label="Evidencia (VT, Abuse, Shodan, feeds)" value={se} max={35} color="bg-blue-500" />
          <BreakdownScoreBar label="Severidad por fuente (Wazuh / IDS / FW)" value={sw} max={25} color="bg-orange-500" />
        </div>
        {wazuhLevelHint != null && (
          <p className="mt-2 text-[10px] text-muted-foreground">
            Nivel en alerta en vivo: <span className="font-mono text-foreground">{wazuhLevelHint}</span>
            {" "}(la severidad por fuente arriba viene del lake, 7 días).
          </p>
        )}
      </div>

      {/* Multiplicadores y kill-chain del scoring v4 (geo/novelty/killchain). */}
      {v4 && (
        <div className={`rounded-md border border-border bg-muted/20 ${compact ? "p-2.5" : "p-3"}`}>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            Multiplicadores y kill-chain (v4)
          </p>
          <div className="space-y-1 text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Base + kill-chain</span>
              <span className="font-mono tabular-nums text-foreground">
                {num(v4.score_base)} + {num(v4.score_killchain)}
                {num(v4.n_kc_phases) > 0 ? ` · ${num(v4.n_kc_phases)} fases ATT&CK` : ""}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">× Novedad temporal</span>
              <span className={`font-mono tabular-nums ${Number(v4.novelty_mult ?? 1) > 1 ? "text-orange-400" : "text-foreground"}`}>
                ×{Number(v4.novelty_mult ?? 1).toFixed(2)}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">× Riesgo geográfico</span>
              <span className={`font-mono tabular-nums ${Number(v4.geo_mult ?? 1) > 1 ? "text-red-400" : "text-foreground"}`}>
                ×{Number(v4.geo_mult ?? 1).toFixed(2)}{str(v4.country_code) ? ` · ${str(v4.country_code)}` : ""}
              </span>
            </div>
            <div className="mt-1.5 flex items-center justify-between border-t border-border/40 pt-1.5 font-semibold">
              <span>Score v4</span>
              <span className="font-mono tabular-nums">{num(v4.score_v4)} / 200</span>
            </div>
          </div>
          <p className="mt-1.5 text-[9px] text-muted-foreground">
            Fórmula: (base + kill-chain) × novedad × geo + bonos · cap 200.
          </p>
        </div>
      )}

      <div>
        <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          MITRE ATT&amp;CK
        </p>
        <div className="rounded-md border border-border/80 bg-background/50 px-3 py-2 text-xs">
          <p>
            <span className="text-muted-foreground">Táctica: </span>
            {str(merged.mitre_tactic_name)}{" "}
            <span className="font-mono text-[10px] text-muted-foreground">
              {str(merged.mitre_tactic_id)}
            </span>
          </p>
          <p className="mt-1">
            <span className="text-muted-foreground">Técnica: </span>
            <span className="font-mono">{str(merged.mitre_technique_id)}</span>
          </p>
        </div>
      </div>

      <Separator />

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-md border border-border/80 bg-background/50 p-3 text-xs">
          <p className="text-[10px] font-semibold uppercase text-muted-foreground">VirusTotal</p>
          <p className="mt-1">
            Maliciosos: <span className="font-mono font-medium">{str(merged.vt_malicious)}</span> ·
            Sospechosos: <span className="font-mono">{str(merged.vt_suspicious)}</span>
          </p>
          {str(merged.vt_permalink).startsWith("http") && (
            <a
              href={str(merged.vt_permalink)}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-[10px] text-primary hover:underline"
            >
              Abrir informe VT <ExternalLink className="h-3 w-3" aria-hidden />
            </a>
          )}
        </div>
        <div className="rounded-md border border-border/80 bg-background/50 p-3 text-xs">
          <p className="text-[10px] font-semibold uppercase text-muted-foreground">AbuseIPDB</p>
          <p className="mt-1">
            Confianza:{" "}
            <span className="font-mono font-medium">{str(merged.abuse_confidence)}%</span>
          </p>
        </div>
        <div className="rounded-md border border-border/80 bg-background/50 p-3 text-xs sm:col-span-2">
          <p className="text-[10px] font-semibold uppercase text-muted-foreground">Shodan</p>
          <p className="mt-1 line-clamp-3 break-all font-mono text-[10px] text-muted-foreground">
            Puertos: {str(merged.shodan_ports)}
          </p>
          <p className="mt-1 line-clamp-2 break-all font-mono text-[10px] text-muted-foreground">
            Vulns: {str(merged.shodan_vulns)}
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-1">
        {truthyFeed(merged.in_urlhaus) && (
          <Badge variant="outline" className="text-[10px]">
            URLhaus
          </Badge>
        )}
        {truthyFeed(merged.in_openphish) && (
          <Badge variant="outline" className="text-[10px]">
            OpenPhish
          </Badge>
        )}
      </div>

      {str(merged.recommended_action) !== "—" && str(merged.recommended_action) !== "" && (
        <div className="rounded-md border border-dashed border-border bg-muted/10 p-3 text-xs text-foreground/85">
          <p className="text-[10px] font-semibold text-muted-foreground">Acción sugerida (vista)</p>
          <p className="mt-1 leading-snug">{str(merged.recommended_action)}</p>
        </div>
      )}

      {showPlaybook && pb && (
        <>
          <Separator />
          <div>
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
              Playbook de respuesta
            </p>
            <IncidentPlaybookCard pb={pb} />
          </div>
        </>
      )}
    </div>
  );
}
