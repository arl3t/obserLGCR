/**
 * CazaExterna.tsx — Panel del Manager: Centro de Inteligencia de Caza de Amenazas
 * Externas (F3).
 *
 * Muestra los `hunt_findings` materializados por el motor de patrones (F1a) y
 * analizados por el LLM (F2): clases de amenaza externa (egress a nube foránea,
 * beaconing por cadencia) sobre pares interno↔externo, NO IOCs sueltos ni casos.
 * El Manager triajea cada hallazgo: lo confirma abriendo un caso real, lo descarta
 * (egress autorizado / FP), lo suprime (no reaparece) o lo deja en monitoreo.
 *
 * Consume (todas requieren rol manager — gateado en router.tsx + backend):
 *   GET  /api/intel/findings?status=&severity=&pattern=&limit=
 *   POST /api/intel/scan                         (re-escanea el lago ahora)
 *   POST /api/intel/analyze?batch=N              (drena NEW por el LLM)
 *   POST /api/intel/findings/:id/analyze         (re-analiza uno)
 *   POST /api/intel/findings/:id/decide          { disposition, linkedCaseId? }
 *   POST /api/incidents/findings/:id/open-case   (sync → Gestión; ver abajo)
 *
 * "Abrir caso" llama a /api/incidents/findings/:id/open-case: el backend mapea
 * server-side el contexto rico del finding (activo interno, evidencia, veredicto +
 * narrativa LLM), dedup por IOC (enlaza si ya existe caso) y enlaza bidireccional
 * en una sola llamada — reemplaza el rodeo OpenCaseModal→open-from-flow→decide.
 */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import {
  Radar, RefreshCw, Brain, FolderOpen, XCircle, ShieldOff, Eye,
  Globe2, Server, Activity, ShieldAlert, Loader2, KeyRound, FileText,
} from "lucide-react";
import { exportCazaExternaPdf } from "@/lib/caza-externa-pdf";
import { useAuth } from "@/auth/useAuth";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { formatDateTimePy } from "@/lib/format";
import { formatCaseNumber } from "@/components/case-management/case-normalize";

// ── Tipos (espejo de hunt_findings / GET /api/intel/findings) ────────────────
interface FindingEvidence {
  patterns?: string[];
  dst_port?: number | null;
  log_family?: string | null;
  event_count?: number;
  allowed_count?: number;
  allowed_ratio?: number;
  is_allowed?: boolean;
  active_hours?: number;
  avg_per_hour?: number;
  std_per_hour?: number;
  cadence_cv?: number;
  country?: string | null;
  asn?: number | null;
  asn_org?: string | null;
  is_foreign?: boolean;
  is_cloud?: boolean;
  is_flat_cadence?: boolean;
  intel_malicious?: boolean;
  intel_reasons?: string[];
  intel_benign?: boolean;
  // P4 brute-force de login
  attack_kind?: string | null;
  fails?: number;
  distinct_users?: number;
  sample_users?: string | null;
  reasons?: string | null;
  device?: string | null;
  is_password_spray?: boolean;
  // permite consumir la evidencia genéricamente (p.ej. generador de PDF)
  [key: string]: unknown;
}
interface Finding {
  finding_id: string;
  pattern_key: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  title: string;
  internal_asset: string | null;
  external_entity: string | null;
  evidence: FindingEvidence;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  status: "NEW" | "ANALYZED" | "TRIAGED" | "ACTIONED" | "SUPPRESSED";
  llm_verdict: "benign" | "suspicious" | "malicious" | "inconclusive" | null;
  llm_confidence: number | null;
  llm_narrative: string | null;
  llm_recommended_action: string | null;
  operator_disposition: string | null;
  linked_case_id: string | null;
  case_number: number | null;   // del caso enlazado (LEFT JOIN incident_cases_pg)
  case_status: string | null;
}
interface PatternSummary { pattern_key: string; count: number; high: number }
interface FindingsSummary { total: number; high: number; new: number; malicious: number }
interface FindingsResponse {
  ok: boolean;
  total: number;
  returned?: number;
  truncated?: boolean;
  summary?: FindingsSummary;
  byPattern: PatternSummary[];
  findings: Finding[];
}

// ── Estilos ──────────────────────────────────────────────────────────────────
const SEV_BADGE: Record<string, string> = {
  HIGH:   "bg-red-500/15 text-red-400 border-red-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  LOW:    "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};
const VERDICT_BADGE: Record<string, string> = {
  malicious:    "bg-red-500/15 text-red-400 border-red-500/30",
  suspicious:   "bg-amber-500/15 text-amber-400 border-amber-500/30",
  benign:       "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  inconclusive: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};
const PATTERN_LABEL: Record<string, string> = {
  ot_egress_foreign_cloud:  "Egress a nube foránea",
  beaconing_cadence:        "Beaconing por cadencia",
  permitido_intel_negativa: "Permitido a IP con intel negativa",
  auth_bruteforce:          "Brute-force de login",
};
const STATUS_LABEL: Record<string, string> = {
  NEW: "Nuevo", ANALYZED: "Analizado", TRIAGED: "Triajeado",
  ACTIONED: "Accionado", SUPPRESSED: "Suprimido",
};
function errMsg(err: unknown): string {
  if (isAxiosError(err)) return (err.response?.data as { error?: string })?.error ?? err.message;
  return err instanceof Error ? err.message : "Error desconocido";
}

// ── Página ─────────────────────────────────────────────────────────────────
export function CazaExternaPage() {
  const qc = useQueryClient();
  const { displayName, preferredUsername } = useAuth();
  const [severity, setSeverity] = useState<"ALL" | "HIGH" | "MEDIUM" | "LOW">("ALL");
  const [status, setStatus] = useState<"" | "NEW" | "ANALYZED" | "ALL">("");
  const [pattern, setPattern] = useState<string>("");

  const listQ = useQuery({
    queryKey: ["caza-findings", severity, status, pattern],
    queryFn: async () => {
      const p = new URLSearchParams();
      if (severity !== "ALL") p.set("severity", severity);
      if (status) p.set("status", status);
      if (pattern) p.set("pattern", pattern);
      p.set("limit", "300");
      const { data } = await api.get<FindingsResponse>(`/api/intel/findings?${p.toString()}`);
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data;
    },
    staleTime: 20_000,
  });

  const scanMut = useMutation({
    mutationFn: async () => (await api.post("/api/intel/scan")).data,
    onSuccess: (r: { upserted?: number }) => {
      toast.success("Escaneo completo", { description: `${r.upserted ?? 0} hallazgos materializados` });
      void qc.invalidateQueries({ queryKey: ["caza-findings"] });
    },
    onError: (e) => toast.error("Escaneo falló", { description: errMsg(e) }),
  });

  const analyzeBatchMut = useMutation({
    mutationFn: async () => (await api.post("/api/intel/analyze")).data,
    onSuccess: (r: { analyzed?: number; skipped?: string }) => {
      if (r.skipped) toast.warning("Analista no disponible", { description: r.skipped });
      else toast.success("Lote analizado", { description: `${r.analyzed ?? 0} veredictos emitidos` });
      void qc.invalidateQueries({ queryKey: ["caza-findings"] });
    },
    onError: (e) => toast.error("Análisis falló", { description: errMsg(e) }),
  });

  const analyzeOneMut = useMutation({
    mutationFn: async (id: string) => (await api.post(`/api/intel/findings/${id}/analyze`)).data,
    onSuccess: (r: { verdict?: string }) => {
      toast.success("Hallazgo analizado", { description: r.verdict ? `Veredicto: ${r.verdict}` : undefined });
      void qc.invalidateQueries({ queryKey: ["caza-findings"] });
    },
    onError: (e) => toast.error("No se pudo analizar", { description: errMsg(e) }),
  });

  const decideMut = useMutation({
    mutationFn: async (v: { id: string; disposition: string; linkedCaseId?: string }) =>
      (await api.post(`/api/intel/findings/${v.id}/decide`, {
        disposition: v.disposition, linkedCaseId: v.linkedCaseId,
      })).data,
    onSuccess: (_d, v) => {
      const lbl: Record<string, string> = {
        dismissed: "descartado", suppressed: "suprimido", monitoring: "en monitoreo", confirmed: "confirmado",
      };
      toast.success(`Hallazgo ${lbl[v.disposition] ?? v.disposition}`);
      void qc.invalidateQueries({ queryKey: ["caza-findings"] });
    },
    onError: (e) => toast.error("No se pudo registrar la decisión", { description: errMsg(e) }),
  });

  // Sincroniza el finding a Gestión: el backend mapea server-side el contexto rico
  // (activo interno, evidencia, veredicto+narrativa LLM), dedup por IOC y enlace
  // bidireccional en una sola llamada (reemplaza OpenCaseModal→open-from-flow→decide).
  const openCaseMut = useMutation({
    mutationFn: async (id: string) =>
      (await api.post(`/api/incidents/findings/${id}/open-case`)).data as {
        caseId: string; created?: boolean; linkedExisting?: boolean; alreadyLinked?: boolean;
      },
    onSuccess: (r) => {
      toast.success(
        r.linkedExisting || r.alreadyLinked ? "Hallazgo enlazado a caso existente" : "Caso abierto desde Caza Externa",
        { description: `Caso ${String(r.caseId).slice(0, 12)}` },
      );
      void qc.invalidateQueries({ queryKey: ["caza-findings"] });
    },
    onError: (e) => toast.error("No se pudo abrir el caso", { description: errMsg(e) }),
  });

  const data = listQ.data;
  const findings = data?.findings ?? [];
  // KPIs desde el agregado del servidor (universo completo, sin tope de página);
  // fallback al conteo de la página si un backend viejo no envía `summary`.
  const kpis = useMemo(() => {
    const s = data?.summary;
    if (s) return { total: s.total, high: s.high, pendientes: s.new, maliciosos: s.malicious };
    const high = findings.filter((f) => f.severity === "HIGH").length;
    const pendientes = findings.filter((f) => f.status === "NEW").length;
    const maliciosos = findings.filter((f) => f.llm_verdict === "malicious").length;
    return { total: findings.length, high, pendientes, maliciosos };
  }, [data?.summary, findings]);
  const truncated = !!data?.truncated;

  return (
    <div className="flex flex-col gap-4 p-6">
      {/* Cabecera */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Radar className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-xl font-semibold">Caza de Amenazas Externas</h1>
            <p className="text-sm text-muted-foreground">
              Clases de amenaza sobre pares interno↔externo · veredicto asistido por LLM · decisión del Manager
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={findings.length === 0}
            onClick={() => exportCazaExternaPdf(findings, { severity, status, pattern, generatedBy: displayName ?? preferredUsername ?? undefined })}
            title="Descargar informe técnico de los veredictos (respeta los filtros)">
            <FileText className="h-4 w-4" /> Informe PDF
          </Button>
          <Button variant="outline" size="sm" disabled={analyzeBatchMut.isPending}
            onClick={() => analyzeBatchMut.mutate()}>
            {analyzeBatchMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
            Analizar pendientes
          </Button>
          <Button variant="outline" size="sm" disabled={scanMut.isPending}
            onClick={() => scanMut.mutate()}>
            {scanMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Escanear ahora
          </Button>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard icon={<Activity className="h-4 w-4" />} label="Hallazgos" value={kpis.total} />
        <KpiCard icon={<ShieldAlert className="h-4 w-4 text-red-400" />} label="Severidad alta" value={kpis.high} />
        <KpiCard icon={<Brain className="h-4 w-4 text-red-400" />} label="LLM: maliciosos" value={kpis.maliciosos} />
        <KpiCard icon={<Eye className="h-4 w-4 text-amber-400" />} label="Pendientes (NEW)" value={kpis.pendientes} />
      </div>

      {/* Filtros */}
      <div className="flex flex-wrap items-center gap-2">
        <FilterGroup label="Severidad" value={severity} onChange={(v) => setSeverity(v as typeof severity)}
          options={[["ALL", "Todas"], ["HIGH", "Alta"], ["MEDIUM", "Media"], ["LOW", "Baja"]]} />
        <FilterGroup label="Estado" value={status} onChange={(v) => setStatus(v as typeof status)}
          options={[["", "Activos"], ["NEW", "Nuevos"], ["ANALYZED", "Analizados"], ["ALL", "Todos"]]} />
        <FilterGroup label="Patrón" value={pattern} onChange={setPattern}
          options={[["", "Todos"], ["auth_bruteforce", "Brute-force"], ["permitido_intel_negativa", "Intel negativa"], ["ot_egress_foreign_cloud", "Egress foráneo"], ["beaconing_cadence", "Beaconing"]]} />
        <Button variant="ghost" size="sm" onClick={() => void listQ.refetch()} className="ml-auto">
          <RefreshCw className={cn("h-4 w-4", listQ.isFetching && "animate-spin")} /> Actualizar
        </Button>
      </div>

      {truncated && (
        <p className="text-xs text-amber-400/90">
          Mostrando {findings.length} de {kpis.total} hallazgos. Acotá con los filtros para ver el resto.
        </p>
      )}

      {/* Lista */}
      {listQ.isLoading ? (
        <div className="space-y-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-40 w-full" />)}</div>
      ) : findings.length === 0 ? (
        <Card><CardContent className="p-8 text-center text-sm text-muted-foreground">
          No hay hallazgos para estos filtros. Probá "Escanear ahora" o relajá los filtros.
        </CardContent></Card>
      ) : (
        <div className="space-y-3">
          {findings.map((f) => (
            <FindingCard key={f.finding_id} f={f}
              onAnalyze={() => analyzeOneMut.mutate(f.finding_id)}
              analyzing={analyzeOneMut.isPending && analyzeOneMut.variables === f.finding_id}
              onOpenCase={() => openCaseMut.mutate(f.finding_id)}
              opening={openCaseMut.isPending && openCaseMut.variables === f.finding_id}
              onDecide={(disposition) => decideMut.mutate({ id: f.finding_id, disposition })}
              deciding={decideMut.isPending && decideMut.variables?.id === f.finding_id}
            />
          ))}
        </div>
      )}

    </div>
  );
}

// ── Subcomponentes ───────────────────────────────────────────────────────────
function KpiCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <Card><CardContent className="flex items-center gap-3 p-4">
      <div className="rounded-md bg-muted/40 p-2">{icon}</div>
      <div>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        <div className="text-xs text-muted-foreground">{label}</div>
      </div>
    </CardContent></Card>
  );
}

function FilterGroup({ label, value, onChange, options }: {
  label: string; value: string; onChange: (v: string) => void; options: [string, string][];
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-xs text-muted-foreground">{label}:</span>
      <div className="flex rounded-md border bg-card p-0.5">
        {options.map(([v, lbl]) => (
          <button key={v} onClick={() => onChange(v)}
            className={cn("rounded px-2 py-1 text-xs transition-colors",
              value === v ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground")}>
            {lbl}
          </button>
        ))}
      </div>
    </div>
  );
}

function Chip({ icon, children }: { icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 rounded border bg-muted/30 px-2 py-0.5 text-xs text-muted-foreground">
      {icon}{children}
    </span>
  );
}

function FindingCard({ f, onAnalyze, analyzing, onOpenCase, opening, onDecide, deciding }: {
  f: Finding;
  onAnalyze: () => void; analyzing: boolean;
  onOpenCase: () => void; opening: boolean;
  onDecide: (disposition: string) => void; deciding: boolean;
  }) {
  const ev = f.evidence ?? {};
  const decided = f.status === "ACTIONED" || f.status === "SUPPRESSED" || f.status === "TRIAGED";
  return (
    <Card className={cn(f.severity === "HIGH" && "border-red-500/30")}>
      <CardContent className="flex flex-col gap-3 p-4">
        {/* fila 1: título + badges */}
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className={SEV_BADGE[f.severity]}>{f.severity}</Badge>
              <Badge variant="outline">{PATTERN_LABEL[f.pattern_key] ?? f.pattern_key}</Badge>
              {ev.is_allowed && (
                <Badge variant="outline" className="border-red-500/30 bg-red-500/10 text-red-400">PERMITIDO</Badge>
              )}
              <Badge variant="secondary">{STATUS_LABEL[f.status] ?? f.status}</Badge>
            </div>
            <p className="mt-1.5 break-words text-sm font-medium">{f.title}</p>
          </div>
        </div>

        {/* fila 2: evidencia cuantificada */}
        <div className="flex flex-wrap gap-1.5">
          <Chip icon={<Server className="h-3 w-3" />}>{f.internal_asset}</Chip>
          <Chip icon={<Globe2 className="h-3 w-3" />}>
            {f.external_entity}{ev.dst_port ? `:${ev.dst_port}` : ""}
          </Chip>
          {ev.country && <Chip>{ev.country}{ev.asn_org ? ` · ${ev.asn_org}` : ""}</Chip>}
          <Chip>{(ev.event_count ?? f.event_count).toLocaleString("es-PY")} ev</Chip>
          {typeof ev.allowed_ratio === "number" && (
            <Chip>permitido {Math.round(ev.allowed_ratio * 100)}%</Chip>
          )}
          {typeof ev.cadence_cv === "number" && <Chip>cadencia CV {ev.cadence_cv}</Chip>}
          {typeof ev.active_hours === "number" && <Chip>{ev.active_hours}h activas</Chip>}
          {f.last_seen && <Chip>visto {formatDateTimePy(f.last_seen)}</Chip>}
        </div>

        {/* brute-force de login (P4) */}
        {f.pattern_key === "auth_bruteforce" && (
          <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 p-2">
            <KeyRound className="h-3.5 w-3.5 text-amber-400" />
            <span className="text-xs font-medium text-amber-400">
              {ev.attack_kind ?? "login"} · {(ev.fails ?? 0).toLocaleString("es-PY")} fallos
            </span>
            {typeof ev.distinct_users === "number" && (
              <span className="text-xs text-amber-300/90">{ev.distinct_users} usuario(s)</span>
            )}
            {ev.is_password_spray && (
              <Badge variant="outline" className="border-amber-500/40 text-amber-400">password spray</Badge>
            )}
            {ev.device && <span className="text-xs text-muted-foreground">→ {ev.device}</span>}
            {ev.sample_users && <span className="text-xs text-muted-foreground">usuarios: {ev.sample_users}</span>}
            {ev.reasons && <span className="text-xs text-muted-foreground">({ev.reasons})</span>}
          </div>
        )}

        {/* intel negativa (P3) */}
        {ev.intel_malicious && (ev.intel_reasons?.length ?? 0) > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-red-500/30 bg-red-500/10 p-2">
            <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
            <span className="text-xs font-medium text-red-400">Intel negativa:</span>
            {ev.intel_reasons!.map((r, i) => (
              <span key={i} className="text-xs text-red-300/90">{r}</span>
            ))}
          </div>
        )}

        {/* fila 3: veredicto LLM */}
        {f.llm_verdict ? (
          <div className="rounded-md border bg-muted/20 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Brain className="h-4 w-4 text-cyan-400" />
              <Badge variant="outline" className={VERDICT_BADGE[f.llm_verdict]}>{f.llm_verdict}</Badge>
              {typeof f.llm_confidence === "number" && (
                <span className="text-xs text-muted-foreground">confianza {f.llm_confidence}%</span>
              )}
              {f.llm_recommended_action && (
                <Badge variant="secondary" className="text-xs">→ {f.llm_recommended_action}</Badge>
              )}
            </div>
            {f.llm_narrative && <p className="mt-2 text-sm text-foreground/90">{f.llm_narrative}</p>}
          </div>
        ) : (
          <div className="text-xs text-muted-foreground">Sin veredicto LLM aún.</div>
        )}

        {/* fila 4: acciones */}
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" disabled={analyzing} onClick={onAnalyze}>
            {analyzing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
            {f.llm_verdict ? "Re-analizar" : "Analizar"}
          </Button>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {f.linked_case_id ? (
              <Link to={`/gestion?investigate=${f.linked_case_id}`} title="Abrir el caso enlazado">
                <Badge variant="outline" className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10">
                  <FolderOpen className="mr-1 h-3 w-3" />
                  {formatCaseNumber(f.case_number) ?? `Caso ${String(f.linked_case_id).slice(0, 12)}`}
                </Badge>
              </Link>
            ) : (
              <Button variant="default" size="sm" onClick={onOpenCase} disabled={opening}>
                {opening ? <Loader2 className="h-4 w-4 animate-spin" /> : <FolderOpen className="h-4 w-4" />} Abrir caso
              </Button>
            )}
            <Button variant="ghost" size="sm" disabled={deciding} onClick={() => onDecide("monitoring")} title="Monitorear">
              <Eye className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" disabled={deciding} onClick={() => onDecide("dismissed")} title="Descartar (autorizado/FP)">
              <XCircle className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" disabled={deciding} onClick={() => onDecide("suppressed")} title="Suprimir clase (no reaparece)">
              <ShieldOff className="h-4 w-4" />
            </Button>
          </div>
        </div>
        {decided && f.operator_disposition && (
          <div className="text-xs text-muted-foreground">Decisión: {f.operator_disposition}</div>
        )}
      </CardContent>
    </Card>
  );
}
