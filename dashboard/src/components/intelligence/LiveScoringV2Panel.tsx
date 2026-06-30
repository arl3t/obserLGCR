import { keepPreviousData, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, FolderOpen, RefreshCw, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { loadOperatorCi, saveOperatorCi } from "@/lib/operator-ci";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useTrinoNamed } from "@/hooks/useTrinoQuery";
import { cn } from "@/lib/utils";

const LIVE_OPTS = {
  staleTime: 30 * 1000,
  gcTime: 5 * 60 * 1000,
  placeholderData: keepPreviousData,
  refetchOnWindowFocus: false,
  retry: 1,
} as const;

function num(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") { const n = Number(v); return Number.isNaN(n) ? 0 : n; }
  return 0;
}
function str(v: unknown): string { return v == null ? "—" : String(v); }

// ── Severity badge v2 (nuevos umbrales) ──────────────────────────────
const SEV_STYLE: Record<string, string> = {
  CRITICAL:   "bg-red-600/15 text-red-500 border-red-500/40",
  HIGH:       "bg-orange-500/15 text-orange-400 border-orange-400/40",
  MEDIUM:     "bg-yellow-500/15 text-yellow-400 border-yellow-400/40",
  LOW:        "bg-emerald-500/15 text-emerald-400 border-emerald-400/40",
  NEGLIGIBLE: "bg-muted/20 text-muted-foreground border-border",
};
function SevBadge({ sev }: { sev: string }) {
  return (
    <span
      className={cn(
        "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
        SEV_STYLE[sev] ?? SEV_STYLE.NEGLIGIBLE,
      )}
    >
      {sev}
    </span>
  );
}

// ── Confidence badge ──────────────────────────────────────────────────
const CONF_STYLE: Record<string, string> = {
  HIGH:   "bg-sky-500/10 text-sky-400 border-sky-400/30",
  MEDIUM: "bg-indigo-500/10 text-indigo-400 border-indigo-400/30",
  LOW:    "bg-muted/20 text-muted-foreground border-border",
};
const ORIGIN_STYLE: Record<string, string> = {
  WAZUH: "border-sky-500/30 bg-sky-500/10 text-sky-400",
  OPNSENSE: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  SYSLOG: "border-violet-500/30 bg-violet-500/10 text-violet-400",
};
function ConfBadge({ level }: { level: string }) {
  return (
    <span
      className={cn(
        "rounded border px-1.5 py-0.5 text-[10px] font-medium",
        CONF_STYLE[level] ?? CONF_STYLE.LOW,
      )}
    >
      conf {level}
    </span>
  );
}

// ── Mini score bar ────────────────────────────────────────────────────
function ScoreBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = Math.round((Math.min(value, max) / max) * 100);
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-12 shrink-0 text-right font-mono text-[9px] text-muted-foreground">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted/30">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-5 shrink-0 text-right font-mono text-[9px] tabular-nums text-muted-foreground">
        {value}
      </span>
    </div>
  );
}

// ── Adopt button (Scoring v2) ─────────────────────────────────────────
function AdoptButtonV2({
  r,
  operatorCi,
  onAdopted,
}: {
  r: Record<string, unknown>;
  operatorCi: string;
  onAdopted: (caseId: string) => void;
}) {
  const [busy, setBusy]     = useState(false);
  const [result, setResult] = useState<{ ok: boolean; caseId?: string; existing?: boolean; msg?: string } | null>(null);

  async function handleAdopt() {
    const ci = operatorCi.trim();
    if (!ci) { setResult({ ok: false, msg: "Introduce tu CI" }); return; }
    setBusy(true);
    try {
      const resp = await fetch("/api/incidents/open-from-flow", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          iocValue:    str(r.ioc_value),
          iocType:     str(r.ioc_type),
          sourceLog:   str(r.source_log),
          score:       num(r.score),
          severity:    str(r.severity),
          mitreTacticId:   r.mitre_tactic_id != null ? str(r.mitre_tactic_id)   : undefined,
          mitreTacticName: r.mitre_tactic_name != null ? str(r.mitre_tactic_name) : undefined,
          // Desglose del score (lo guardamos en enrichment_data para que las 5
          // barras del panel de gestión de casos no salgan en 0/X).
          scoreBreakdown: {
            score_mitre:    num(r.score_mitre),
            score_evidence: num(r.score_evidence),
            score_wazuh:    num(r.score_wazuh),
            score_misp:     num(r.score_misp),
            score_context:  num(r.score_context),
          },
          operatorCi:  ci,
        }),
      });
      const json = await resp.json() as {
        ok?: boolean; caseId?: string; error?: string;
        existingCaseId?: string; existingStatus?: string;
      };
      if (resp.status === 409 && json.existingCaseId) {
        // Case already exists — surface it instead of showing an error
        setResult({ ok: true, caseId: json.existingCaseId, existing: true });
        onAdopted(json.existingCaseId);
      } else if (!resp.ok) {
        setResult({ ok: false, msg: json.error ?? `HTTP ${resp.status}` });
      } else {
        setResult({ ok: true, caseId: json.caseId });
        onAdopted(json.caseId!);
      }
    } catch (e) {
      setResult({ ok: false, msg: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  if (result?.ok) {
    return (
      <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${result.existing ? "border-sky-500/40 bg-sky-500/10 text-sky-400" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"}`}>
        {result.existing ? "Existente" : "Abierto"} #{result.caseId?.slice(0, 8)}…
      </span>
    );
  }
  return (
    <div className="flex flex-col gap-0.5">
      <Button
        size="sm"
        variant="outline"
        className="h-6 gap-1 border-emerald-500/40 px-2 text-[10px] text-emerald-400 hover:bg-emerald-500/10"
        disabled={busy}
        onClick={handleAdopt}
      >
        <FolderOpen className="h-3 w-3" aria-hidden />
        {busy ? "Abriendo…" : "Abrir caso"}
      </Button>
      {result?.msg && (
        <span className="text-[10px] text-destructive">{result.msg}</span>
      )}
    </div>
  );
}

// ── IOC card ─────────────────────────────────────────────────────────
function IocCard({
  r,
  idx,
  operatorCi,
  onAdopted,
}: {
  r: Record<string, unknown>;
  idx: number;
  operatorCi: string;
  onAdopted: (caseId: string) => void;
}) {
  const sev   = str(r.severity);
  const score = num(r.score);
  const conf  = str(r.confidence_level);
  const sources = num(r.n_sources);
  const origen = str(r.origen_sistema);
  const srcIp = str(r.ip_origen_log);
  const dstIp = str(r.ip_destino_log);
  const sm      = num(r.score_mitre);
  const se      = num(r.score_evidence);
  const sw      = num(r.score_wazuh);
  const sc      = num(r.score_context);
  const st      = num(r.score_tor);
  const sm_misp = num(r.score_misp);
  const in_misp = r.in_misp === true || r.in_misp === "true";
  const cat     = r.source_category ? str(r.source_category) : null;
  const vt      = num(r.vt_malicious);
  const caseId  = r.case_id != null ? str(r.case_id) : null;
  const caseSt  = r.case_status != null ? str(r.case_status) : null;

  return (
    <div
      className={cn(
        "flex flex-col gap-2.5 rounded-lg border p-3",
        sev === "CRITICAL" ? "border-red-500/25 bg-red-500/5"
          : sev === "HIGH" ? "border-orange-400/20 bg-orange-400/5"
          : "border-border/70 bg-card/60",
      )}
    >
      {/* IP + severidad + case badge */}
      <div className="flex items-start justify-between gap-2">
        <p className="min-w-0 flex-1 truncate font-mono text-xs font-semibold" title={str(r.ioc_value)}>
          {idx + 1}. {str(r.ioc_value)}
        </p>
        <div className="flex shrink-0 items-center gap-1">
          {caseId && (
            <span
              className="rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-sky-400"
              title={`Caso: ${caseId}`}
            >
              #{caseId.slice(0, 6)} {caseSt ? `· ${caseSt}` : ""}
            </span>
          )}
          <SevBadge sev={sev} />
          <span className="font-mono text-xs font-bold tabular-nums">{score}</span>
        </div>
      </div>

      {/* Fuente + táctica + origen */}
      <p className="truncate text-[11px] text-muted-foreground">
        {origen} · {str(r.source_log)}
        {r.mitre_technique_id != null && (
          <> · <span className="font-mono">{str(r.mitre_technique_id)}</span></>
        )}
        {cat && <> · <span className="opacity-70">{cat}</span></>}
      </p>
      <p className="truncate text-[11px] text-muted-foreground/90">
        src {srcIp}{dstIp !== "—" ? ` -> dst ${dstIp}` : ""}
      </p>

      {/* Score breakdown */}
      <div className="space-y-1">
        <ScoreBar label="MITRE"    value={sm}      max={40} color="bg-violet-500"  />
        <ScoreBar label="Evidencia" value={se}     max={35} color="bg-sky-500"     />
        <ScoreBar label="Wazuh"    value={sw}      max={25} color="bg-amber-500"   />
        <ScoreBar label="Contexto" value={sc}      max={10} color="bg-emerald-500" />
        {st > 0 && (
          <ScoreBar label="Tor"    value={st}      max={25} color="bg-rose-500"    />
        )}
        {sm_misp > 0 && (
          <ScoreBar label="MISP"   value={sm_misp} max={20} color="bg-fuchsia-500" />
        )}
      </div>

      {/* Badges inferiores */}
      <div className="flex flex-wrap items-center gap-1">
        <span className={cn(
          "rounded border px-1.5 py-0.5 text-[10px] font-semibold",
          ORIGIN_STYLE[origen] ?? "border-primary/30 bg-primary/10 text-primary",
        )}>
          {origen}
          {srcIp !== "—" ? ` · src ${srcIp}` : ""}
        </span>
        <ConfBadge level={conf} />
        {sources > 1 && (
          <span className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
            {sources} fuentes
          </span>
        )}
        {st > 0 && (
          <span className="rounded border border-rose-500/40 bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-rose-400">
            TOR +{st}
          </span>
        )}
        {in_misp && (
          <span className="rounded border border-fuchsia-500/40 bg-fuchsia-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-fuchsia-400">
            MISP +{sm_misp}
          </span>
        )}
        {vt > 0 && (
          <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400">
            VT {vt}
          </span>
        )}
        {(r.in_urlhaus === true || r.in_urlhaus === "true") && (
          <span className="rounded border border-orange-400/30 bg-orange-400/10 px-1.5 py-0.5 text-[10px] text-orange-400">
            URLhaus
          </span>
        )}
        <span className="ml-auto font-mono text-[10px] text-muted-foreground/60">{str(r.dt)}</span>
      </div>

      {/* Adopt button — always shown for actionable severities; backend deduplicates */}
      {(sev === "CRITICAL" || sev === "HIGH" || sev === "MEDIUM") && (
        <AdoptButtonV2 r={r} operatorCi={operatorCi} onAdopted={onAdopted} />
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
export function LiveScoringV2Panel() {
  const queryClient = useQueryClient();
  const [operatorCi, setOperatorCi] = useState(loadOperatorCi);
  const [adoptedCaseIds, setAdoptedCaseIds] = useState<Set<string>>(new Set());

  // Usa la tabla materializada (t_materialize_score_v2 DAG diario) en vez de
  // la vista live. Latencia ~200ms vs 5-15s, y no satura Trino cuando hay
  // carga concurrente. Fresh window: dt=current_date (DAG corre madrugada).
  const liveTop = useTrinoNamed(
    ["incidents-v2", "live-top"],
    "lh.incidents.live_top_v2_mat",
    { limit: 200, days: 30 },
    LIVE_OPTS,
  );

  function handleAdopted(caseId: string) {
    saveOperatorCi(operatorCi);
    setAdoptedCaseIds((prev) => new Set(prev).add(caseId));
    void queryClient.invalidateQueries({ queryKey: ["incidents-v2", "live-top"] });
  }

  const rows = liveTop.data ?? [];
  const actionable = rows.filter((r) => {
    const s = str(r.severity);
    return s === "CRITICAL" || s === "HIGH" || s === "MEDIUM";
  });

  return (
    <Card className="border-border/80">
      <CardHeader className="space-y-1 pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-primary" aria-hidden />
            <CardTitle className="text-base">Scoring v2 — tiempo casi real</CardTitle>
            <Badge variant="cyber" className="text-[10px]">incident_score_v2_mat</Badge>
          </div>
          <div className="flex items-center gap-2">
            <Input
              value={operatorCi}
              onChange={(e) => setOperatorCi(e.target.value)}
              placeholder="CI operador"
              className="h-7 w-32 text-[11px]"
            />
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1 text-[11px]"
              onClick={() => void liveTop.refetch()}
              disabled={liveTop.isFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", liveTop.isFetching && "animate-spin")} aria-hidden />
              {liveTop.isFetching ? "Actualizando..." : "Refrescar"}
            </Button>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          Top IOCs · últimos 30 días · score = MITRE + Evidencia + Wazuh + Contexto + Tor + MISP (max 100) ·
          CRITICAL≥80 · HIGH 55–79 · MEDIUM 30–54 · LOW 10–29
        </p>
        {/* Resumen de severidades */}
        {!liveTop.isLoading && rows.length > 0 && (
          <div className="flex flex-wrap gap-2 pt-1">
            {(["CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE"] as const).map((s) => {
              const n = rows.filter((r) => str(r.severity) === s).length;
              if (n === 0) return null;
              return (
                <span key={s} className={cn("rounded border px-2 py-0.5 text-[10px] font-semibold", SEV_STYLE[s])}>
                  {s} {n}
                </span>
              );
            })}
            <span className="ml-auto text-[11px] text-muted-foreground">
              {actionable.length} accionables de {rows.length} total
            </span>
          </div>
        )}
      </CardHeader>

      <CardContent>
        {/* Carga inicial: nunca hubo datos — mostrar skeletons */}
        {liveTop.isLoading && (
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-36 w-full rounded-lg" />
            ))}
          </div>
        )}

        {/* Error en carga inicial (sin datos previos) */}
        {!liveTop.isLoading && liveTop.error && rows.length === 0 && (
          <p className="text-sm text-destructive" role="alert">
            {(liveTop.error as Error).message}
          </p>
        )}

        {/* FIX: error en refetch de fondo — datos anteriores siguen visibles. */}
        {liveTop.error && rows.length > 0 && (
          <div
            role="alert"
            className="mb-3 flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-400"
          >
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
            <span>
              Error al actualizar — mostrando datos anteriores.{" "}
              <span className="opacity-70">({(liveTop.error as Error).message})</span>
            </span>
          </div>
        )}

        {!liveTop.isLoading && !liveTop.error && rows.length === 0 && (
          <p className="text-sm text-muted-foreground">
            Sin IOCs en los últimos 30 días. Ejecuta el DAG de enriquecimiento y el script{" "}
            <code className="text-xs">21_v2_view_incident_score.sql</code>.
          </p>
        )}

        {!liveTop.isLoading && rows.length > 0 && (
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {rows.map((r, i) => {
              const key = `${str(r.ioc_value)}-${str(r.dt)}-${i}`;
              // If adopted in this session, treat as having a case already
              const adoptedId = [...adoptedCaseIds].find((_id) =>
                str(r.ioc_value) !== "—" && key.startsWith(str(r.ioc_value))
              );
              const rWithAdopted = adoptedId
                ? { ...r, case_id: adoptedId, case_status: "EN_ANALISIS" }
                : r;
              return (
                <IocCard
                  key={key}
                  r={rWithAdopted}
                  idx={i}
                  operatorCi={operatorCi}
                  onAdopted={handleAdopted}
                />
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
