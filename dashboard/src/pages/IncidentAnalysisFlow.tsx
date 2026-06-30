import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  Copy,
  ExternalLink,
  RefreshCw,
  Search,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { formatDateTimePy } from "@/lib/format";
import { isAxiosError } from "axios";

/** Extrae el mensaje real del backend (axios envuelve el 4xx en err.response.data.error). */
function errMsg(err: unknown, fallback = "Error desconocido"): string {
  if (isAxiosError(err)) {
    const data = err.response?.data as { error?: string; message?: string } | undefined;
    return data?.error ?? data?.message ?? err.message ?? fallback;
  }
  return err instanceof Error ? err.message : String(err);
}

// ── Types ─────────────────────────────────────────────────────────────────────

type FlowState   = "ALL" | "ABIERTO" | "NO_ABIERTO" | "DEDUPLICADO";
type ReasonFilter = "ALL" | "score" | "severidad" | "dedup" | "ok" | "insuficiente";

interface FlowRow {
  ioc_id:              string;
  ioc_value:           string;
  ioc_type:            string;
  timestamp_evento:    string;
  source_log:          string;
  dedup_key:           string;
  score:               number | string;
  severidad:           string;
  mitre_tactic_id:     string | null;
  mitre_tactic_name:   string | null;
  detection_type:      string | null;
  confidence_level:    string | null;
  cumple_score:        boolean | string;
  cumple_severidad:    boolean | string;
  existe_caso_duplicado: boolean | string;
  criterio_fallido:    string;
  flujo_estado:        string;
  incident_case_id:    string | null;
  incident_status:     string | null;
  incident_severity:   string | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function str(v: unknown): string {
  return v == null ? "" : String(v);
}

function bool(v: unknown): boolean {
  if (v === true || v === "true" || v === 1 || v === "1") return true;
  return false;
}

function stateBadgeClass(state: string): string {
  if (state === "ABIERTO")     return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
  if (state === "DEDUPLICADO") return "border-orange-500/40  bg-orange-500/10  text-orange-300";
  return "border-red-500/40 bg-red-500/10 text-red-300";
}

function sevColor(sev: string): string {
  if (sev === "CRITICAL") return "text-red-400";
  if (sev === "HIGH")     return "text-orange-400";
  if (sev === "MEDIUM")   return "text-cyan-400";
  return "text-gray-400";
}

// ── Criterion chip ────────────────────────────────────────────────────────────

function CriterionChip({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-[10px] border ${
        ok
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
          : "border-red-500/30 bg-red-500/10 text-red-300"
      }`}
    >
      {ok ? <CheckCircle2 className="h-2.5 w-2.5" /> : <XCircle className="h-2.5 w-2.5" />}
      {label}
    </span>
  );
}

// ── Per-row adoption button ───────────────────────────────────────────────────

function AdoptButton({
  row,
  operatorCi,
  onAdopted,
}: {
  row: FlowRow;
  operatorCi: string;
  onAdopted: (caseId: string) => void;
}) {
  const [busy, setBusy]   = useState(false);
  const [done, setDone]   = useState(false);
  const [err, setErr]     = useState<string | null>(null);
  const [newId, setNewId] = useState<string | null>(null);

  async function handleOpen() {
    if (!operatorCi.trim() || operatorCi.trim().length < 5) {
      setErr("Introduce tu CI (mín. 5 caracteres) en el campo superior.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const sev = str(row.severidad).toUpperCase();
      const isLowSev = sev === "LOW" || sev === "NEGLIGIBLE" || sev === "";
      const { data } = await api.post<{ caseId: string; error?: string }>("/api/incidents/open-from-flow", {
        iocId:           row.ioc_id,
        iocValue:        row.ioc_value,
        iocType:         row.ioc_type,
        sourceLog:       row.source_log,
        score:           Number(row.score),
        severidad:       sev || "LOW",
        dedupKey:        row.dedup_key,
        mitreTacticId:   row.mitre_tactic_id ?? undefined,
        mitreTacticName: row.mitre_tactic_name ?? undefined,
        operatorCi:      operatorCi.trim(),
        force:           isLowSev,
      });
      setDone(true);
      setNewId(data.caseId);
      onAdopted(data.caseId);
    } catch (e) {
      setErr(errMsg(e, "Error al abrir caso"));
    } finally {
      setBusy(false);
    }
  }

  if (done && newId) {
    return (
      <div className="flex flex-col gap-0.5">
        <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 font-mono">
          <CheckCircle2 className="h-3 w-3" />
          Caso abierto
        </span>
        <button
          onClick={() => navigator.clipboard?.writeText(newId)}
          className="inline-flex items-center gap-0.5 font-mono text-[9px] text-gray-500 hover:text-gray-300"
          title={newId}
        >
          <Copy className="h-2.5 w-2.5" />
          {newId.slice(0, 8)}…
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        onClick={() => void handleOpen()}
        className="h-7 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10 text-[11px] px-2"
      >
        {busy ? (
          <RefreshCw className="h-3 w-3 animate-spin mr-1" />
        ) : (
          <ShieldAlert className="h-3 w-3 mr-1" />
        )}
        {busy ? "Abriendo…" : "Abrir caso"}
      </Button>
      {err && (
        <span className="text-[10px] text-red-400 leading-tight">{err}</span>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

interface FlowStats {
  total:       number;
  abiertos:    number;
  dedup:       number;
  descartados: number;
}

interface FlowApiResponse {
  rows:     FlowRow[];
  total:    number;
  page:     number;
  pageSize: number;
  stats:    FlowStats;
}

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200, 500] as const;

export function IncidentAnalysisFlowPage() {
  const [days, setDays]         = useState(30);
  const [search, setSearch]     = useState("");
  const [flowState, setFlowState] = useState<FlowState>("ALL");
  const [reason, setReason]     = useState<ReasonFilter>("ALL");
  const [page, setPage]         = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [operatorCi, setOperatorCi] = useState(
    () => sessionStorage.getItem("lh_operator_ci") ?? localStorage.getItem("lh_operator_ci") ?? ""
  );
  const [adoptedCaseIds, setAdoptedCaseIds] = useState<Set<string>>(new Set());
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncMsg,  setSyncMsg]  = useState<string | null>(null);
  const [escBusy,  setEscBusy]  = useState(false);
  const [escMsg,   setEscMsg]   = useState<string | null>(null);
  const queryClient = useQueryClient();

  async function handleBulkSync() {
    if (!operatorCi.trim() || operatorCi.trim().length < 5) {
      setSyncMsg("Introduce tu CI antes de sincronizar.");
      return;
    }
    setSyncBusy(true); setSyncMsg(null);
    try {
      const { data } = await api.post<{ ok?: boolean; started?: boolean; total?: number; synced?: number; skipped?: number; error?: string }>(
        "/api/incidents/bulk-sync-pending",
        { operatorCi: operatorCi.trim(), includeLowNegligible: true, days },
      );
      if (data.started) {
        setSyncMsg(`⏳ Sincronizando ${data.total} casos en segundo plano…`);
        setTimeout(() => void queryClient.invalidateQueries({ queryKey: ["incidents-analysis-flow"] }), 15_000);
      } else {
        setSyncMsg(`✓ Sincronizados: ${data.synced} casos nuevos, ${data.skipped} omitidos.`);
        void queryClient.invalidateQueries({ queryKey: ["incidents-analysis-flow"] });
      }
    } catch (e) {
      setSyncMsg(`Error: ${errMsg(e)}`);
    } finally { setSyncBusy(false); }
  }

  async function handleBulkEscalate() {
    if (!operatorCi.trim() || operatorCi.trim().length < 5) {
      setEscMsg("Introduce tu CI antes de escalar.");
      return;
    }
    setEscBusy(true); setEscMsg(null);
    try {
      const { data } = await api.post<{
        ok?: boolean;
        escalated?: number;
        below_threshold?: number;
        error?: string;
        escalated_to?: { label?: string; name?: string; ci?: string; source?: string };
      }>("/api/incidents/bulk-escalate-unadopted", { operatorCi: operatorCi.trim() });
      const target = data.escalated_to?.label ?? "SOC Leader";
      const sourceTag = data.escalated_to?.source === "FALLBACK_LEADER"
        ? " (LEADER fallback, sin Shift Manager designado)"
        : data.escalated_to?.source === "SHIFT_MANAGER" ? " (Shift Manager activo)" : "";
      setEscMsg(`✓ Escalados: ${data.escalated} casos a ${target}${sourceTag}. Sin umbral aún: ${data.below_threshold}.`);
      void queryClient.invalidateQueries({ queryKey: ["incidents-analysis-flow"] });
    } catch (e) {
      setEscMsg(`Error: ${errMsg(e)}`);
    } finally { setEscBusy(false); }
  }

  // Reset página a 1 cuando cambien filtros que afectan el conjunto
  useEffect(() => { setPage(1); }, [days, search, flowState, reason, pageSize]);

  // Debounce de `search` para no pegarle al API en cada tecla
  const [searchDebounced, setSearchDebounced] = useState(search);
  useEffect(() => {
    const t = setTimeout(() => setSearchDebounced(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  const q = useQuery<FlowApiResponse>({
    queryKey: ["incidents-analysis-flow", days, page, pageSize, searchDebounced, flowState, reason],
    queryFn: async () => {
      const params = new URLSearchParams({
        days:      String(days),
        page:      String(page),
        pageSize:  String(pageSize),
        flowState, reason,
      });
      if (searchDebounced.trim()) params.set("search", searchDebounced.trim());
      const { data } = await api.get<FlowApiResponse>(`/api/incidents/analysis-flow?${params.toString()}`);
      return data;
    },
    staleTime:             60_000,
    gcTime:                5 * 60_000,
    placeholderData:       (prev) => prev,    // evita flicker al cambiar de página
  });

  const rows  = q.data?.rows  ?? [];
  const total = q.data?.total ?? 0;
  const stats = q.data?.stats ?? { total: 0, abiertos: 0, dedup: 0, descartados: 0 };
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  function handleAdopted(caseId: string) {
    setAdoptedCaseIds((prev) => new Set(prev).add(caseId));
    sessionStorage.setItem("lh_operator_ci", operatorCi.trim());
    void queryClient.invalidateQueries({ queryKey: ["incidents-analysis-flow"] });
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6 px-1 pb-16 sm:px-0">
      <header className="space-y-1">
        <h2 className="text-2xl font-bold tracking-tight">Flujo de apertura de casos</h2>
        <p className="text-sm text-muted-foreground">
          Explica para cada IOC si cumple score/severidad, si fue deduplicado y por qué no se abrió un caso.
          Los IOCs con estado <span className="text-emerald-400 font-semibold">ABIERTO</span> pueden adoptarse manualmente.
        </p>
      </header>

      {/* ── Filters ── */}
      <Card className="border-border/80 bg-card/90">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Filtros operativos</CardTitle>
          <CardDescription>Filtra por estado del flujo, criterio y texto libre. Introduce tu CI para poder abrir casos.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-6">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar ioc_id, ioc_value, dedup_key, criterio…"
            className="md:col-span-2"
          />
          <div>
            <select
              value={flowState}
              onChange={(e) => setFlowState(e.target.value as FlowState)}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="ALL">Estado: todos</option>
              <option value="ABIERTO">ABIERTO</option>
              <option value="NO_ABIERTO">NO_ABIERTO</option>
              <option value="DEDUPLICADO">DEDUPLICADO</option>
            </select>
          </div>
          <div>
            <select
              value={reason}
              onChange={(e) => setReason(e.target.value as ReasonFilter)}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="ALL">Criterio: todos</option>
              <option value="score">Score insuficiente</option>
              <option value="severidad">Severidad</option>
              <option value="dedup">Deduplicación</option>
              <option value="ok">Todos OK</option>
              <option value="insuficiente">Datos insuficientes</option>
            </select>
          </div>
          <Input
            type="number"
            min={1}
            max={90}
            value={days}
            onChange={(e) => setDays(Math.max(1, Math.min(90, Number(e.target.value) || 7)))}
            placeholder="Días"
          />

          {/* CI para adopción */}
          <Input
            value={operatorCi}
            onChange={(e) => setOperatorCi(e.target.value)}
            placeholder="CI del operador (para abrir casos)"
            className="md:col-span-3"
          />

          <div className="md:col-span-6 flex items-center gap-2 flex-wrap">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void q.refetch()}
              disabled={q.isFetching}
            >
              <RefreshCw className={`mr-2 h-3.5 w-3.5 ${q.isFetching ? "animate-spin" : ""}`} />
              Refrescar
            </Button>
            <span className="text-xs text-muted-foreground">
              Página {page}/{totalPages} · {rows.length} de {total} filas filtradas
            </span>
            <select
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
              className="h-8 rounded-md border border-input bg-background px-2 text-xs"
              title="Filas por página"
            >
              {PAGE_SIZE_OPTIONS.map((n) => (
                <option key={n} value={n}>{n}/pág</option>
              ))}
            </select>
            <Button
              variant="outline" size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || q.isFetching}
            >←</Button>
            <Button
              variant="outline" size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || q.isFetching}
            >→</Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => { setFlowState("NO_ABIERTO"); setReason("ALL"); }}
            >
              Solo descartados
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => { setFlowState("ABIERTO"); setReason("ALL"); }}
              className="border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10"
            >
              Solo ABIERTO
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={syncBusy}
              onClick={() => void handleBulkSync()}
              className="border-blue-500/30 text-blue-300 hover:bg-blue-500/10"
              title="Promueve clasificaciones pendientes (incl. LOW/NEGLIGIBLE) a casos gestionables"
            >
              <RefreshCw className={`mr-1.5 h-3 w-3 ${syncBusy ? "animate-spin" : ""}`} />
              {syncBusy ? "Sincronizando…" : "Sincronizar pendientes"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={escBusy}
              onClick={() => void handleBulkEscalate()}
              className="border-orange-500/30 text-orange-300 hover:bg-orange-500/10"
              title="Escala a SOC Leader todos los casos NUEVO sin adoptar que superaron el umbral por severidad"
            >
              <RefreshCw className={`mr-1.5 h-3 w-3 ${escBusy ? "animate-spin" : ""}`} />
              {escBusy ? "Escalando…" : "Escalar no adoptados"}
            </Button>
          </div>
          {(syncMsg || escMsg) && (
            <div className="md:col-span-6 flex gap-3 flex-wrap">
              {syncMsg && (
                <span className={`text-xs px-2 py-1 rounded border ${syncMsg.startsWith("✓") ? "border-blue-500/30 text-blue-300 bg-blue-500/10" : "border-red-500/30 text-red-300 bg-red-500/10"}`}>
                  {syncMsg}
                </span>
              )}
              {escMsg && (
                <span className={`text-xs px-2 py-1 rounded border ${escMsg.startsWith("✓") ? "border-orange-500/30 text-orange-300 bg-orange-500/10" : "border-red-500/30 text-red-300 bg-red-500/10"}`}>
                  {escMsg}
                </span>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── KPI cards ── */}
      <div className="grid gap-3 md:grid-cols-4">
        <Card className="border-border/80 bg-card/90">
          <CardHeader className="pb-2">
            <CardDescription>Total</CardDescription>
            <CardTitle className="text-xl">{stats.total}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-border/80 bg-card/90">
          <CardHeader className="pb-2">
            <CardDescription>ABIERTO</CardDescription>
            <CardTitle className="text-xl text-emerald-300">{stats.abiertos}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-border/80 bg-card/90">
          <CardHeader className="pb-2">
            <CardDescription>DEDUPLICADO</CardDescription>
            <CardTitle className="text-xl text-orange-300">{stats.dedup}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-border/80 bg-card/90">
          <CardHeader className="pb-2">
            <CardDescription>DESCARTADO (NO_ABIERTO)</CardDescription>
            <CardTitle className="text-xl text-red-300">{stats.descartados}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* ── Error ── */}
      {q.isError && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-semibold">No se pudo consultar el flujo de incidentes</p>
            <p className="mt-0.5 font-mono text-[11px] text-red-300/70">
              {(q.error as Error)?.message ?? "Error desconocido"}
            </p>
          </div>
        </div>
      )}

      {/* ── Table ── */}
      <Card className="border-border/80 bg-card/90">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Resultados</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="max-h-[68vh] overflow-auto rounded-b-lg border-t border-border/60">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="whitespace-nowrap">Timestamp</TableHead>
                  <TableHead>IOC</TableHead>
                  <TableHead>Fuente</TableHead>
                  <TableHead className="text-center">Score</TableHead>
                  <TableHead className="text-center">Sev.</TableHead>
                  <TableHead className="text-center">Criterios</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead>Diagnóstico</TableHead>
                  <TableHead>Acción</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r, i) => {
                  const flujo   = str(r.flujo_estado).toUpperCase();
                  const sev     = str(r.severidad).toUpperCase();
                  const cScore  = bool(r.cumple_score);
                  const cSev    = bool(r.cumple_severidad);
                  const hasDup  = bool(r.existe_caso_duplicado);
                  const alreadyAdopted = adoptedCaseIds.has(str(r.incident_case_id ?? ""));

                  return (
                    <TableRow key={`${str(r.ioc_id)}-${i}`} className="align-top">
                      {/* Timestamp */}
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {formatDateTimePy(str(r.timestamp_evento))}
                      </TableCell>

                      {/* IOC value + type */}
                      <TableCell>
                        <div className="flex flex-col gap-0.5">
                          <span className="max-w-[180px] truncate font-mono text-[11px] text-gray-200">
                            {str(r.ioc_value) || str(r.ioc_id)}
                          </span>
                          <span className="font-mono text-[9px] text-gray-600 uppercase">
                            {str(r.ioc_type)}
                          </span>
                          {r.mitre_tactic_id && (
                            <span className="font-mono text-[9px] text-purple-400">
                              {str(r.mitre_tactic_id)}
                            </span>
                          )}
                        </div>
                      </TableCell>

                      {/* Source */}
                      <TableCell className="text-xs text-muted-foreground max-w-[100px] truncate">
                        {str(r.source_log)}
                      </TableCell>

                      {/* Score */}
                      <TableCell className="text-center">
                        <span className={`font-mono text-sm font-bold ${cScore ? "text-emerald-400" : "text-red-400"}`}>
                          {str(r.score)}
                        </span>
                      </TableCell>

                      {/* Severity */}
                      <TableCell className="text-center">
                        <span className={`font-mono text-xs font-semibold ${sevColor(sev)}`}>
                          {sev || "—"}
                        </span>
                      </TableCell>

                      {/* Criteria chips */}
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <CriterionChip ok={cScore} label="score≥30" />
                          <CriterionChip ok={cSev}   label="sev OK" />
                          <CriterionChip ok={!hasDup} label="sin dup" />
                        </div>
                      </TableCell>

                      {/* Flow state badge */}
                      <TableCell>
                        <Badge variant="outline" className={stateBadgeClass(flujo)}>
                          {flujo || "—"}
                        </Badge>
                      </TableCell>

                      {/* Diagnosis */}
                      <TableCell className="max-w-[320px]">
                        <p className="text-xs leading-snug text-muted-foreground line-clamp-3">
                          {str(r.criterio_fallido)}
                        </p>
                        {flujo === "DEDUPLICADO" && r.incident_case_id && (
                          <div className="mt-1 flex items-center gap-1 font-mono text-[9px] text-orange-300">
                            <ExternalLink className="h-2.5 w-2.5" />
                            caso: {str(r.incident_case_id).slice(0, 12)}…
                            {r.incident_status && (
                              <span className="text-gray-500">({str(r.incident_status)})</span>
                            )}
                          </div>
                        )}
                        {r.dedup_key && (
                          <button
                            onClick={() => navigator.clipboard?.writeText(str(r.dedup_key))}
                            className="mt-1 flex items-center gap-0.5 font-mono text-[9px] text-gray-600 hover:text-gray-400"
                            title="Copiar dedup_key"
                          >
                            <Search className="h-2.5 w-2.5" />
                            {str(r.dedup_key).slice(0, 16)}…
                          </button>
                        )}
                      </TableCell>

                      {/* Action */}
                      <TableCell>
                        {alreadyAdopted ? (
                          <span className="text-[10px] text-emerald-400 font-mono flex items-center gap-1">
                            <CheckCircle2 className="h-3 w-3" />
                            Adoptado
                          </span>
                        ) : flujo === "DEDUPLICADO" ? (
                          <span className="text-[10px] text-orange-300 font-mono flex items-center gap-1">
                            <Circle className="h-3 w-3" />
                            Ver caso
                          </span>
                        ) : flujo !== "ABIERTO" && !hasDup ? (
                          // LOW/NEGLIGIBLE / NO_ABIERTO sin duplicado — permitir apertura manual
                          <AdoptButton row={r} operatorCi={operatorCi} onAdopted={handleAdopted} />
                        ) : flujo === "ABIERTO" ? (
                          <AdoptButton
                            row={r}
                            operatorCi={operatorCi}
                            onAdopted={handleAdopted}
                          />
                        ) : (
                          <span className="text-[10px] text-gray-600 font-mono">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}

                {!q.isLoading && rows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={9} className="py-8 text-center text-sm text-muted-foreground">
                      No hay datos para los filtros seleccionados. Prueba aumentar &ldquo;días&rdquo; (30–90) o quitar filtros.
                    </TableCell>
                  </TableRow>
                )}

                {q.isLoading && (
                  <TableRow>
                    <TableCell colSpan={9} className="py-8 text-center text-sm text-muted-foreground">
                      <span className="inline-flex items-center gap-2">
                        <RefreshCw className="h-4 w-4 animate-spin" />
                        Cargando flujo de incidentes…
                      </span>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* ── Legend ── */}
      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
          <span><strong className="text-emerald-400">ABIERTO</strong> — cumple score ≥ 30, severidad MEDIUM+, sin dedup activo. Puede adoptarse manualmente.</span>
        </div>
        <div className="flex items-center gap-1.5">
          <AlertTriangle className="h-3.5 w-3.5 text-orange-400" />
          <span><strong className="text-orange-400">DEDUPLICADO</strong> — criterios OK pero ya existe caso activo (ventana 15 días).</span>
        </div>
        <div className="flex items-center gap-1.5">
          <XCircle className="h-3.5 w-3.5 text-red-400" />
          <span><strong className="text-red-400">NO_ABIERTO</strong> — descartado por score insuficiente, severidad baja o datos incompletos.</span>
        </div>
      </div>
    </div>
  );
}
