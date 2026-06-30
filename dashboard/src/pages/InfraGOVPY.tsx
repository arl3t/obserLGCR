/**
 * InfraGOVPYPage — watchlist con ventana deslizante de 7 días (2026-04-20)
 *
 * La lista outbound se materializa en la tabla PG
 * `legacyhunt_soc.infragovpy_watchlist`. Cada IP ingresa por 7 días; si vuelve
 * a reportarse durante ese periodo, sus 7 días se reinician y report_count se
 * incrementa (penalización efectiva). La ingesta corre cada 10 min desde
 * `incident_cases_pg` últimas 24 h.
 *
 * Fuentes de datos:
 *   · GET /api/intel/infragovpy/watchlist  → lista activa (expires_at > NOW)
 *   · GET /api/intel/infragovpy/kpis       → contadores agregados
 *   · lh.infragovpy.source_coverage_7d     → panel cobertura (Trino, cached)
 *   · lh.infragovpy.source_breakdown_24h   → panel MITRE/fuente (Trino)
 */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  AlarmClock, Ban, Crosshair, Download, ExternalLink, Flag, Globe2, Plus,
  RefreshCw, Repeat, Send, Settings, Shield, ShieldAlert, ShieldOff, Skull,
  Trash2, TrendingUp, Upload, X, Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { executeTrinoRun } from "@/api/trino-run";
import { normalizeRows } from "@/api/types";
import { formatNumber, formatDatePy } from "@/lib/format";
import { useInvestigationStore } from "@/store/investigation-store";
import { api } from "@/api/client";

// ── Helpers visuales ─────────────────────────────────────────────────────────

const SEV_VARIANT: Record<string, "destructive" | "secondary" | "outline" | "cyber"> = {
  CRITICAL: "destructive",
  HIGH:     "secondary",
  MEDIUM:   "outline",
  LOW:      "outline",
};

const SEV_ICON: Record<string, React.ReactNode> = {
  CRITICAL: <Skull       className="h-3 w-3" aria-hidden />,
  HIGH:     <ShieldAlert className="h-3 w-3" aria-hidden />,
  MEDIUM:   <Shield      className="h-3 w-3" aria-hidden />,
  LOW:      <Shield      className="h-3 w-3 opacity-50" aria-hidden />,
};

function SevBadge({ sev }: { sev: string }) {
  return (
    <Badge variant={SEV_VARIANT[sev] ?? "outline"} className="gap-1 text-[10px] uppercase">
      {SEV_ICON[sev]}
      {sev}
    </Badge>
  );
}

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(Math.max(score, 0), 100);
  const color =
    pct >= 80 ? "bg-destructive" :
    pct >= 60 ? "bg-orange-500"  :
    pct >= 40 ? "bg-yellow-500"  : "bg-muted-foreground";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-muted">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="tabular-nums text-xs font-semibold">{score}</span>
    </div>
  );
}

// ── Named queries — sólo los paneles auxiliares (Cobertura / Desglose) ──────

const SPECS = [
  { key: "sources", id: "lh.infragovpy.source_breakdown_24h", params: { hours: 24 } },
] as const satisfies BatchSpec[];

const COVERAGE_ID = "lh.infragovpy.source_coverage_7d";
const COVERAGE_PARAMS = { hours: 24 } as const;
const COVERAGE_TIMEOUT_MS = 180_000;

const STALE = { staleTime: 5 * 60 * 1000, gcTime: 15 * 60 * 1000 } as const;
const COVERAGE_STALE = { staleTime: 10 * 60 * 1000, gcTime: 30 * 60 * 1000 } as const;

// ── Tipos de filas ───────────────────────────────────────────────────────────

interface WatchlistRow {
  ip:                       string;
  first_seen:               string;
  last_seen:                string;
  expires_at:               string;
  report_count:             number | string;
  first_score:              number | string;
  last_score:               number | string;
  max_score:                number | string;
  last_severity:            string | null;
  last_source_log:          string | null;
  last_mitre_tactic_id:     string | null;
  last_mitre_tactic_name:   string | null;
  last_mitre_technique_id:  string | null;
  last_case_id:             string | null;
  origin:                   "auto" | "manual";
  added_by:                 string | null;
  reason:                   string | null;
  seconds_to_expire:        number | string;
  seconds_since_first:      number | string;
  /** Enriquecido on-the-fly desde v_incident_score_v2_runtime vía JOIN por
   *  lote en /api/intel/infragovpy/watchlist. Puede ser null si la IP no
   *  aparece en tv2 en los últimos 30d o si Trino está caído. */
  country_code:             string | null;
}

interface WatchlistKpis {
  active_total:     number | string;
  active_critical:  number | string;
  active_high:      number | string;
  active_medium:    number | string;
  new_24h:          number | string;
  penalized:        number | string;
  active_manual:    number | string;
  avg_max_score:    number | string;
  max_max_score:    number | string;
  avg_days_in_list: number | string;
}

function toNum(v: number | string | null | undefined, d = 0): number {
  if (v == null) return d;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : d;
}

function fmtDuration(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d >= 1) return `${d}d ${h}h`;
  if (h >= 1) return `${h}h ${m}m`;
  return `${m}m`;
}

function fmtSince(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  if (d >= 1) return `hace ${d} d`;
  if (h >= 1) return `hace ${h} h`;
  return "hace < 1 h";
}

interface SourceRow {
  source_log:         string;
  mitre_tactic_name:  string;
  distinct_ips:       number;
  cases:              number;
  avg_score:          number;
}

interface CoverageRow {
  source_log:         string;
  enriched_iocs_7d:   number;
  cases_7d:           number;
  cases_ip_window:    number;
  feed_eligible:      number;
}

interface ExclusionRow {
  id:         number | string;
  pattern:    string;
  kind:       "exact" | "cidr";
  reason:     string | null;
  added_by:   string | null;
  created_at: string;
  expires_at: string | null;
  permanent?: boolean;
}

// ── Page ─────────────────────────────────────────────────────────────────────

export function InfraGOVPYPage() {
  const openIp = useInvestigationStore((s) => s.openIp);

  // Watchlist activa — fuente de verdad para tabla + KPIs
  const watchlistQuery = useQuery<WatchlistRow[]>({
    queryKey: ["igpy-watchlist"],
    queryFn: async () => {
      const { data } = await api.get<{ rows: WatchlistRow[] }>(
        "/api/intel/infragovpy/watchlist?limit=2000",
      );
      return data.rows ?? [];
    },
    ...STALE,
  });
  const kpisQuery = useQuery<WatchlistKpis>({
    queryKey: ["igpy-watchlist-kpis"],
    queryFn: async () => {
      const { data } = await api.get<{ kpis: WatchlistKpis }>("/api/intel/infragovpy/kpis");
      return data.kpis;
    },
    ...STALE,
  });

  // Panel "Desglose por fuente / MITRE" — sigue vía Trino (tabla sana)
  const { results, refetch: refetchSources } = useTrinoNamedBatch(["igpy-sources"], SPECS, STALE);
  const sources = (results.sources?.data ?? []) as unknown as SourceRow[];

  // Cobertura 7d — query pesada cacheada por el API cada 10 min
  const coverageQuery = useQuery<CoverageRow[]>({
    queryKey: ["igpy-v2", "coverage", COVERAGE_ID, JSON.stringify(COVERAGE_PARAMS)],
    queryFn: async () => {
      const res = await executeTrinoRun(COVERAGE_ID, COVERAGE_PARAMS, { timeoutMs: COVERAGE_TIMEOUT_MS });
      if (res.error) throw new Error(res.error);
      return normalizeRows(res) as unknown as CoverageRow[];
    },
    ...COVERAGE_STALE,
  });

  const rows     = watchlistQuery.data ?? [];
  const coverage = (coverageQuery.data ?? []) as CoverageRow[];
  const isLoading = watchlistQuery.isLoading || kpisQuery.isLoading;
  const error = watchlistQuery.error ?? kpisQuery.error ?? null;

  const kpi = kpisQuery.data;
  const total     = toNum(kpi?.active_total);
  const critical  = toNum(kpi?.active_critical);
  const high      = toNum(kpi?.active_high);
  const medium    = toNum(kpi?.active_medium);
  const new24h    = toNum(kpi?.new_24h);
  const penalized = toNum(kpi?.penalized);
  const manualCnt = toNum(kpi?.active_manual);
  const avgScore  = toNum(kpi?.avg_max_score);
  const maxScore  = toNum(kpi?.max_max_score);
  const avgDaysInList = toNum(kpi?.avg_days_in_list);

  const refetch = () => {
    void watchlistQuery.refetch();
    void kpisQuery.refetch();
    void refetchSources();
    void coverageQuery.refetch();
  };

  const [filter, setFilter] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<
    | { kind: "ok"; rows: number; html_url?: string | null; commit_sha?: string | null }
    | { kind: "err"; message: string }
    | null
  >(null);

  const filteredRows = useMemo(() => {
    if (!filter.trim()) return rows;
    const q = filter.trim().toLowerCase();
    return rows.filter((r) =>
      r.ip.includes(q) ||
      (r.last_mitre_tactic_name ?? "").toLowerCase().includes(q) ||
      (r.last_mitre_technique_id ?? "").toLowerCase().includes(q) ||
      (r.last_source_log ?? "").toLowerCase().includes(q) ||
      (r.last_severity ?? "").toLowerCase().includes(q) ||
      (r.country_code ?? "").toLowerCase().includes(q) ||
      r.origin.toLowerCase().includes(q),
    );
  }, [rows, filter]);

  async function handleSubmit() {
    if (submitting) return;
    if (!confirm(`Enviar ${rows.length} IPs a lgcrBL?\n\nEsto hace PUT del CSV sobre codigo.legacy-roots.com/legacy/lgcrbl (override con LGCRBL_GIT_REPO).`)) {
      return;
    }
    setSubmitting(true);
    setSubmitResult(null);
    try {
      const { data } = await api.post<{
        ok: boolean; rows: number; html_url?: string | null; commit_sha?: string | null;
      }>("/api/intel/infragovpy/submit?hours=24");
      if (data.ok) {
        setSubmitResult({
          kind: "ok",
          rows: data.rows ?? rows.length,
          html_url: data.html_url,
          commit_sha: data.commit_sha,
        });
      } else {
        setSubmitResult({ kind: "err", message: "Respuesta inesperada del servidor" });
      }
    } catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } }).response?.data?.error
        ?? (e instanceof Error ? e.message : "Error");
      setSubmitResult({ kind: "err", message: msg });
    } finally {
      setSubmitting(false);
    }
  }

  // ── Exclusiones (allowlist) ────────────────────────────────────────────────
  const exclusionsQuery = useQuery<ExclusionRow[]>({
    queryKey: ["igpy-exclusions"],
    queryFn: async () => {
      const { data } = await api.get<{ rows: ExclusionRow[] }>("/api/intel/infragovpy/exclusions");
      return data.rows ?? [];
    },
    ...STALE,
  });
  const exclusions = exclusionsQuery.data ?? [];
  const [exclPattern, setExclPattern] = useState("");
  const [exclReason, setExclReason] = useState("");
  const [exclBusy, setExclBusy] = useState(false);
  const [exclMsg, setExclMsg] = useState<string | null>(null);

  function apiErr(e: unknown): string {
    return (e as { response?: { data?: { error?: string } } }).response?.data?.error
      ?? (e instanceof Error ? e.message : "Error");
  }

  // Quitar una IP del feed. `permanent` la agrega también a exclusiones (durable:
  // el sync de 10 min no la vuelve a publicar). Sin permanent, puede reingresar.
  async function handleRemoveIp(ip: string, permanent: boolean) {
    const msg = permanent
      ? `¿Excluir ${ip} del feed lgcrBL de forma permanente?\n\nSe quita ahora y se agrega a la allowlist para que el sync NO la vuelva a publicar.`
      : `¿Quitar ${ip} del feed lgcrBL?\n\nSe expira ahora, pero el sync (cada 10 min) puede reingresarla si sigue puntuando alto. Usá "Excluir" para que no vuelva.`;
    if (!confirm(msg)) return;
    try {
      await api.post("/api/intel/infragovpy/manual-remove", { ip, permanent });
      void watchlistQuery.refetch();
      void kpisQuery.refetch();
      if (permanent) void exclusionsQuery.refetch();
    } catch (e) {
      setExclMsg(apiErr(e));
    }
  }

  async function handleAddExclusion() {
    const pattern = exclPattern.trim();
    if (!pattern || exclBusy) return;
    setExclBusy(true);
    setExclMsg(null);
    try {
      // kind se deriva en el backend: con "/" → cidr, si no → exact.
      await api.post("/api/intel/infragovpy/exclusions", {
        pattern,
        reason: exclReason.trim() || undefined,
      });
      setExclPattern("");
      setExclReason("");
      void exclusionsQuery.refetch();
      void watchlistQuery.refetch();
    } catch (e) {
      setExclMsg(apiErr(e));
    } finally {
      setExclBusy(false);
    }
  }

  async function handleDeleteExclusion(pattern: string) {
    if (!confirm(`¿Eliminar la exclusión ${pattern}?\n\nLa IP/rango volverá a ser elegible para el feed si vuelve a puntuar alto.`)) return;
    try {
      await api.delete(`/api/intel/infragovpy/exclusions?pattern=${encodeURIComponent(pattern)}`);
      void exclusionsQuery.refetch();
    } catch (e) {
      setExclMsg(apiErr(e));
    }
  }

  return (
    <div className="space-y-4">
      {/* ── Header con acciones ──────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border/60 bg-muted/10 p-4">
        <div className="min-w-0 flex-1">
          <h2 className="flex items-center gap-2 text-base font-bold">
            <Flag className="h-4 w-4 text-red-500" />
            lgcrBL — Feed saliente
            <Badge variant="outline" className="ml-1 text-[10px]">v2 · outbound</Badge>
          </h2>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Watchlist con ventana deslizante de <b>7 días</b>. Las IPs detectadas en las últimas
            24 h ingresan (score ≥ 60 o severity HIGH/CRITICAL); si una IP ya listada vuelve a
            reportarse, se le <span className="text-red-400 font-semibold">reinician</span> los
            7 días y sube su contador de reportes (penalización).
            Sync automático cada 10 min · push diario <span className="font-mono">07:00 AR</span> a
            <span className="ml-1 font-mono">codigo.legacy-roots.com/legacy/lgcrbl</span>.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void refetch()}
            disabled={isLoading}
            title="Refrescar desde Trino"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
          </Button>
          <Button asChild variant="outline" size="sm">
            <a
              href="/api/intel/infragovpy/export.csv?hours=24&limit=500"
              download
              title="Descargar CSV (hours=24)"
            >
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Descargar CSV
            </a>
          </Button>
          {/* Acceso al Asset Registry (scoring v2 — criticidad de activos
              RFC1918 + multiplicadores de riesgo geográfico). Vive en /activos
              y tiene tabs "Activos" y "Riesgo Geográfico". */}
          <Button asChild variant="outline" size="sm">
            <Link to="/activos" title="Scoring por Asset Registry · tiers de activos y multiplicadores geo">
              <Settings className="mr-1.5 h-3.5 w-3.5" />
              Scoring · Asset Registry
            </Link>
          </Button>
          <Button
            variant="default"
            size="sm"
            onClick={() => void handleSubmit()}
            disabled={submitting || rows.length === 0}
            title="Push manual a codigo.legacy-roots.com/legacy/lgcrbl"
            className="bg-red-500 hover:bg-red-600 text-white"
          >
            {submitting
              ? <><RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />Enviando…</>
              : <><Send className="mr-1.5 h-3.5 w-3.5" />Enviar a lgcrBL</>
            }
          </Button>
        </div>
      </div>

      {/* ── Resultado del push ──────────────────────────────────────── */}
      {submitResult && (
        <div
          className={`flex items-start gap-2 rounded-md border p-3 text-[12px] ${
            submitResult.kind === "ok"
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
              : "border-red-500/40 bg-red-500/10 text-red-300"
          }`}
        >
          <Upload className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <div className="min-w-0 flex-1">
            {submitResult.kind === "ok" ? (
              <>
                <div className="font-semibold">
                  Push OK · {submitResult.rows} IPs enviadas
                </div>
                {submitResult.html_url && (
                  <a
                    href={submitResult.html_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] underline hover:text-emerald-200"
                  >
                    Ver commit <ExternalLink className="h-3 w-3" />
                  </a>
                )}
                {submitResult.commit_sha && (
                  <span className="ml-2 font-mono text-[10px] opacity-70">
                    {submitResult.commit_sha.slice(0, 10)}
                  </span>
                )}
              </>
            ) : (
              <>
                <div className="font-semibold">Push falló</div>
                <div className="mt-0.5 break-all font-mono text-[11px]">{submitResult.message}</div>
              </>
            )}
          </div>
          <button
            onClick={() => setSubmitResult(null)}
            className="text-[10px] text-muted-foreground hover:text-foreground"
          >
            ✕
          </button>
        </div>
      )}

      {/* ── KPIs ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
        <KpiCard
          label="Activas en feed"
          value={formatNumber(total)}
          icon={<Flag className="h-4 w-4" />}
          tone="base"
          hint={manualCnt > 0 ? `${manualCnt} manual` : undefined}
        />
        <KpiCard
          label="Nuevas (24 h)"
          value={formatNumber(new24h)}
          icon={<AlarmClock className="h-4 w-4" />}
          tone="base"
        />
        <KpiCard
          label="Penalizadas"
          value={formatNumber(penalized)}
          icon={<Repeat className="h-4 w-4" />}
          tone={penalized > 0 ? "crit" : "base"}
          hint="≥ 2 reportes en 7 d"
        />
        <KpiCard
          label="CRITICAL / HIGH"
          value={`${formatNumber(critical)} / ${formatNumber(high)}`}
          icon={<Skull className="h-4 w-4" />}
          tone="crit"
          hint={medium > 0 ? `+ ${medium} MEDIUM` : undefined}
        />
        <KpiCard
          label="Score avg / max"
          value={`${avgScore} / ${maxScore}`}
          icon={<TrendingUp className="h-4 w-4" />}
          tone="base"
        />
        <KpiCard
          label="Días promedio en lista"
          value={avgDaysInList.toFixed(1)}
          icon={<AlarmClock className="h-4 w-4" />}
          tone="base"
        />
      </div>

      {/* Error loud */}
      {error && (
        <div className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-[12px] text-red-300">
          Error al cargar: {error instanceof Error ? error.message : String(error)}
        </div>
      )}

      {/* Empty */}
      {!isLoading && !error && rows.length === 0 && (
        <div className="rounded-md border border-dashed border-border/50 bg-muted/10 p-6 text-center text-[12px] text-muted-foreground">
          La watchlist está vacía. Una IP ingresa cuando aparece en <span className="font-mono">incident_cases</span>
          &nbsp;de las últimas 24 h con score ≥ 60 o severity HIGH/CRITICAL, y permanece activa por 7 días.
        </div>
      )}

      {/* ── Cobertura por fuente (transparencia del pipeline) ─────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
            Cobertura por fuente (7 d)
            {coverageQuery.isFetching && (
              <RefreshCw className="h-3 w-3 animate-spin text-muted-foreground/60" />
            )}
            <span className="ml-auto font-normal normal-case text-[10px] text-muted-foreground/80">
              transparencia del pipeline · columna &quot;feed&quot; = los que llegan al CSV
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {coverageQuery.isLoading && (
            <div className="py-6 text-center text-[11px] text-muted-foreground">
              Calculando cobertura 7 d… (query pesada sobre <span className="font-mono">incident_cases</span>,
              el API la precalienta cada 10 min — la primera carga puede tardar hasta 2 min)
            </div>
          )}
          {coverageQuery.error && !coverageQuery.isLoading && (
            <div className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-[11px] text-red-300">
              Cobertura no disponible: {coverageQuery.error instanceof Error ? coverageQuery.error.message : String(coverageQuery.error)}
            </div>
          )}
          {!coverageQuery.isLoading && !coverageQuery.error && coverage.length === 0 && (
            <div className="py-4 text-center text-[11px] text-muted-foreground">
              Sin datos de cobertura en los últimos 7 días.
            </div>
          )}
          {coverage.length > 0 && (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Fuente (source_log)</TableHead>
                      <TableHead className="text-right">IOCs enriquecidos</TableHead>
                      <TableHead className="text-right">Casos 7 d</TableHead>
                      <TableHead className="text-right">Casos IP (ventana)</TableHead>
                      <TableHead className="text-right">Alimentan feed</TableHead>
                      <TableHead>Estado</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {coverage.map((c) => {
                      const status =
                        c.feed_eligible > 0     ? { label: "alimenta feed",   cls: "text-emerald-400 border-emerald-500/40 bg-emerald-500/10" } :
                        c.cases_ip_window > 0   ? { label: "todo bajo umbral", cls: "text-yellow-400 border-yellow-500/40 bg-yellow-500/10" } :
                        c.enriched_iocs_7d > 0  ? { label: "sin casos abiertos", cls: "text-orange-400 border-orange-500/40 bg-orange-500/10" } :
                                                  { label: "silenciada",        cls: "text-muted-foreground border-border/40 bg-muted/10" };
                      return (
                        <TableRow key={c.source_log}>
                          <TableCell className="font-mono text-[11px]">{c.source_log}</TableCell>
                          <TableCell className="text-right tabular-nums">{formatNumber(c.enriched_iocs_7d)}</TableCell>
                          <TableCell className="text-right tabular-nums">{formatNumber(c.cases_7d)}</TableCell>
                          <TableCell className="text-right tabular-nums">{formatNumber(c.cases_ip_window)}</TableCell>
                          <TableCell className="text-right tabular-nums font-semibold">
                            <span className={c.feed_eligible > 0 ? "text-emerald-400" : "text-muted-foreground"}>
                              {formatNumber(c.feed_eligible)}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${status.cls}`}>
                              {status.label}
                            </span>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
              <div className="mt-2 space-y-0.5 text-[10px] text-muted-foreground">
                <div>
                  <span className="inline-block h-2 w-2 rounded-full bg-emerald-500 mr-1" />
                  <strong>alimenta feed</strong>: tiene IOCs que pasan el umbral (severity HIGH/CRITICAL o score ≥ 60) y aparecen en el CSV.
                </div>
                <div>
                  <span className="inline-block h-2 w-2 rounded-full bg-yellow-500 mr-1" />
                  <strong>todo bajo umbral</strong>: genera casos con IP pero todos MEDIUM/LOW con score {"<"} 60 (excluidos del feed outbound por ruido).
                </div>
                <div>
                  <span className="inline-block h-2 w-2 rounded-full bg-orange-500 mr-1" />
                  <strong>sin casos abiertos</strong>: hay IOCs enriquecidos pero ningún caso — posible gap de opening_profiles o race condition entre DAGs.
                </div>
                <div>
                  <span className="inline-block h-2 w-2 rounded-full bg-muted-foreground/40 mr-1" />
                  <strong>silenciada</strong>: sin actividad en 7 días.
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* ── Desglose por fuente + MITRE ─────────────────────────────── */}
      {sources.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              Desglose por fuente / MITRE (24 h)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Fuente</TableHead>
                    <TableHead>MITRE táctica</TableHead>
                    <TableHead className="text-right">IPs distintas</TableHead>
                    <TableHead className="text-right">Casos</TableHead>
                    <TableHead className="text-right">Score avg</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sources.slice(0, 10).map((s, i) => (
                    <TableRow key={`${s.source_log}-${s.mitre_tactic_name}-${i}`}>
                      <TableCell className="font-mono text-[11px]">{s.source_log}</TableCell>
                      <TableCell>{s.mitre_tactic_name}</TableCell>
                      <TableCell className="text-right tabular-nums font-semibold">{s.distinct_ips}</TableCell>
                      <TableCell className="text-right tabular-nums">{s.cases}</TableCell>
                      <TableCell className="text-right tabular-nums text-muted-foreground">{s.avg_score}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Tabla principal ─────────────────────────────────────────── */}
      {rows.length > 0 && (
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              Watchlist activa · ventana 7 d ({formatNumber(filteredRows.length)} / {formatNumber(rows.length)})
            </CardTitle>
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filtrar IP / MITRE / país / fuente / severidad / origen…"
              className="max-w-xs text-[12px]"
            />
          </CardHeader>
          <CardContent>
            <div className="max-h-[70vh] overflow-auto rounded-md border border-border/40">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-background/95 backdrop-blur">
                  <TableRow>
                    <TableHead className="w-[190px]">IP</TableHead>
                    <TableHead>Score (máx)</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>MITRE</TableHead>
                    <TableHead className="text-center">Reportes</TableHead>
                    <TableHead className="hidden md:table-cell">Primer visto</TableHead>
                    <TableHead>Expira en</TableHead>
                    <TableHead>País</TableHead>
                    <TableHead className="w-[120px] text-right">Acciones</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRows.map((r) => {
                    const reports  = toNum(r.report_count);
                    const scoreMax = toNum(r.max_score);
                    const sev      = (r.last_severity ?? "MEDIUM").toUpperCase();
                    const tExpire  = toNum(r.seconds_to_expire);
                    const tSince   = toNum(r.seconds_since_first);
                    const expireCls =
                      tExpire < 86400 ? "text-orange-300"
                      : tExpire < 3 * 86400 ? "text-yellow-300"
                      : "text-muted-foreground";
                    return (
                      <TableRow key={r.ip}>
                        <TableCell className="font-mono text-[12px]">
                          <div className="flex items-center gap-1.5">
                            <Globe2 className="h-3 w-3 text-muted-foreground" />
                            {r.ip}
                            {r.origin === "manual" && (
                              <Badge variant="outline" className="ml-1 text-[9px] border-blue-500/40 text-blue-300">
                                manual
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell><ScoreBar score={scoreMax} /></TableCell>
                        <TableCell><SevBadge sev={sev} /></TableCell>
                        <TableCell>
                          {r.last_mitre_tactic_id ? (
                            <div className="flex flex-col leading-tight">
                              <span className="text-[11px] font-medium">{r.last_mitre_tactic_name}</span>
                              <span className="font-mono text-[10px] text-muted-foreground">
                                {r.last_mitre_tactic_id}
                                {r.last_mitre_technique_id ? ` · ${r.last_mitre_technique_id}` : ""}
                              </span>
                            </div>
                          ) : (
                            <span className="text-[11px] text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-center">
                          <div className="flex items-center justify-center gap-1">
                            <span className="tabular-nums font-semibold text-[11px]">{reports}</span>
                            {reports >= 2 && (
                              <Badge variant="destructive" className="gap-1 text-[9px] uppercase">
                                <Repeat className="h-2.5 w-2.5" /> penal
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="hidden md:table-cell text-[11px] text-muted-foreground">
                          {fmtSince(tSince)}
                        </TableCell>
                        <TableCell className={`text-[11px] ${expireCls}`}>
                          <div className="flex items-center gap-1">
                            <AlarmClock className="h-3 w-3" />
                            <span className="tabular-nums">{fmtDuration(tExpire)}</span>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {r.country_code
                            ? <span title={r.last_source_log ?? "—"}>{r.country_code}</span>
                            : <span className="text-muted-foreground/60" title={r.last_source_log ?? "—"}>—</span>}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-0.5">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => openIp(r.ip)}
                              title="Investigar IP"
                              className="h-7 w-7 p-0"
                            >
                              <Crosshair className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleRemoveIp(r.ip, false)}
                              title="Quitar del feed (temporal — puede reingresar en el próximo sync)"
                              className="h-7 w-7 p-0 text-muted-foreground hover:text-yellow-500"
                            >
                              <X className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleRemoveIp(r.ip, true)}
                              title="Excluir del feed (permanente — no vuelve a publicarse)"
                              className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                            >
                              <Ban className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Exclusiones (allowlist) ──────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
            <ShieldOff className="h-3.5 w-3.5" />
            Exclusiones del feed ({formatNumber(exclusions.length)})
            {exclusionsQuery.isFetching && (
              <RefreshCw className="h-3 w-3 animate-spin text-muted-foreground/60" />
            )}
            <span className="ml-auto font-normal normal-case text-[10px] text-muted-foreground/80">
              IPs / rangos que NUNCA se publican en lgcrBL
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Form de alta */}
          <div className="flex flex-wrap items-end gap-2">
            <div className="flex flex-col gap-1">
              <label className="text-[10px] uppercase tracking-wider text-muted-foreground">
                IP o rango CIDR
              </label>
              <Input
                value={exclPattern}
                onChange={(e) => setExclPattern(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") void handleAddExclusion(); }}
                placeholder="200.1.2.3  ó  200.1.2.0/24"
                className="w-[200px] font-mono text-[12px]"
              />
            </div>
            <div className="flex flex-1 flex-col gap-1">
              <label className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Motivo (opcional)
              </label>
              <Input
                value={exclReason}
                onChange={(e) => setExclReason(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") void handleAddExclusion(); }}
                placeholder="infra propia / egress NAT / partner / falso positivo crónico…"
                className="min-w-[200px] text-[12px]"
              />
            </div>
            <Button
              size="sm"
              onClick={() => void handleAddExclusion()}
              disabled={exclBusy || !exclPattern.trim()}
              className="h-9 gap-1.5 text-xs"
            >
              <Plus className="h-3.5 w-3.5" />
              {exclBusy ? "Agregando…" : "Excluir"}
            </Button>
          </div>
          {exclMsg && (
            <div className="rounded-md border border-red-500/40 bg-red-500/10 px-2.5 py-1.5 text-[11px] text-red-300">
              {exclMsg}
            </div>
          )}

          {/* Lista */}
          {exclusions.length === 0 ? (
            <div className="rounded-md border border-dashed border-border/50 bg-muted/10 p-4 text-center text-[11px] text-muted-foreground">
              Sin exclusiones. Agregá una IP o rango arriba para que jamás se publique en el feed,
              o usá el botón <Ban className="inline h-3 w-3" /> de cada fila de la watchlist.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-md border border-border/40">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[200px]">Patrón</TableHead>
                    <TableHead>Tipo</TableHead>
                    <TableHead>Motivo</TableHead>
                    <TableHead>Por</TableHead>
                    <TableHead>Vence</TableHead>
                    <TableHead className="w-[48px] text-right"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {exclusions.map((x) => (
                    <TableRow key={String(x.id)}>
                      <TableCell className="font-mono text-[12px]">{x.pattern}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[9px] uppercase">
                          {x.kind === "cidr" ? "rango" : "exacta"}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[280px] truncate text-[11px] text-muted-foreground" title={x.reason ?? ""}>
                        {x.reason || "—"}
                      </TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">{x.added_by || "—"}</TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">
                        {x.expires_at ? formatDatePy(x.expires_at) : (
                          <span className="text-emerald-400/80">permanente</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => void handleDeleteExclusion(x.pattern)}
                          title="Eliminar exclusión"
                          className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Footer: cómo funciona ────────────────────────────────────── */}
      <Card className="border-border/40 bg-muted/5">
        <CardContent className="p-3">
          <div className="flex items-start gap-2 text-[11px] text-muted-foreground">
            <Zap className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <div>
              <div className="font-semibold text-foreground">¿Cómo se genera esta lista?</div>
              <div className="mt-0.5 leading-relaxed">
                La watchlist vive en <span className="font-mono">legacyhunt_soc.infragovpy_watchlist</span>
                (PostgreSQL). Un scheduler corre cada 10 min y escanea <span className="font-mono">incident_cases_pg</span> últimas
                24 h con <span className="font-mono">ioc_type=&apos;ip&apos;</span>, IP pública (no RFC1918),
                severity HIGH/CRITICAL o score ≥ 60, y hace UPSERT:
                <br />· <b>IP nueva</b> → insert con <span className="font-mono">expires_at = NOW() + 7d</span>, report_count = 1.
                <br />· <b>IP ya en lista</b> → se reinicia <span className="font-mono">expires_at = NOW() + 7d</span>, report_count++, max_score actualizado.
                <br />El feed queda <b>persistente</b>: una IP permanece 7 días tras su último reporte. El push
                publica <span className="font-mono">feeds/legacyhunt-24h.csv</span> en
                <span className="font-mono"> codigo.legacy-roots.com/legacy/lgcrbl</span> vía la API GitLab
                <span className="font-mono"> PUT /api/v4/projects/{"{id}"}/repository/files/{"{path}"}</span>.
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ── KPI card pequeño ─────────────────────────────────────────────────────────

type KpiTone = "base" | "crit" | "high";

function KpiCard({
  label, value, icon, tone = "base", hint,
}: {
  label: string;
  value: React.ReactNode;
  icon: React.ReactNode;
  tone?: KpiTone;
  hint?: string;
}) {
  const toneCls =
    tone === "crit" ? "text-red-400 border-red-500/30"    :
    tone === "high" ? "text-orange-400 border-orange-500/30" :
                      "text-foreground border-border/60";
  return (
    <Card className={toneCls}>
      <CardContent className="p-3">
        <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
          {icon}
          {label}
        </div>
        <div className="mt-1 text-2xl font-bold tabular-nums leading-none">{value}</div>
        {hint && <div className="mt-1 text-[10px] text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  );
}
