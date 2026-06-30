/**
 * OperatorProfile.tsx — Perfil del operador SOC vinculado a Keycloak.
 *
 * La identidad (nombre, username, email, roles) proviene directamente del
 * token OIDC de Keycloak. Ya no hay wizard de registro manual.
 *
 * Al montar, el KC username se sincroniza a localStorage (lh_operator_ci)
 * para que CaseAdoptionModal y otros componentes lo usen como identificador.
 */

import { useEffect, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  AlertCircle,
  ArrowRight,
  BarChart2,
  CheckCircle2,
  ClipboardList,
  Clock,
  FileBarChart,
  FolderOpen,
  Globe2,
  KeyRound,
  Mail,
  RefreshCw,
  Shield,
  ShieldCheck,
  Star,
  TrendingUp,
  User,
  Users,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDatePy } from "@/lib/format";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { api } from "@/api/client";
import { useAuth } from "@/auth/useAuth";
import { C, alpha } from "@/lib/cm-theme";
import { OPERATOR_CI_KEY, OPERATOR_NAME_KEY } from "@/lib/operator-ci";
import { useSocOperators } from "@/hooks/useSocWorkflow";
import type { SocOperator } from "@/hooks/useSocWorkflow";
import { ExecutiveReportMenu } from "@/components/case-management/ExecutiveReportMenu";
import { TechnicalReportMenu } from "@/components/case-management/TechnicalReportMenu";
import { TechnicalReportPanel } from "@/components/case-management/TechnicalReportPanel";

// ─── constantes ──────────────────────────────────────────────────────────────

const OPERATOR_ID_KEY = "lh_operator_id";
const ANALYST_ID_KEY  = "lh_analyst_id";
const API_BASE        = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

// Jerarquía de roles KC — del más privilegiado al menos
const KC_ROLE_HIERARCHY = ["admin", "manager", "hunter", "analyst"] as const;

const KC_ROLE_DISPLAY: Record<string, { label: string; color: string; desc: string }> = {
  admin:   { label: "Administrador",  color: C.red,     desc: "Acceso completo y gestión de plataforma" },
  manager: { label: "SOC Manager",    color: C.orange,  desc: "Liderazgo de turno y escalaciones" },
  hunter:  { label: "Threat Hunter",  color: C.cyan,    desc: "Hunting activo y correlación avanzada" },
  analyst: { label: "Analista SOC",   color: C.textDim, desc: "Gestión y análisis de casos SOC" },
};

const SEV_COLOR: Record<string, string> = {
  CRITICAL:   C.red,
  HIGH:       C.orange,
  MEDIUM:     C.orange,
  LOW:        C.green,
  NEGLIGIBLE: C.textDim,
};

// ─── tipos ───────────────────────────────────────────────────────────────────

interface OpeningProfile {
  id:          string;
  name:        string;
  description: string;
  enabled:     boolean;
  severities:  string[];
  minScore:    number;
  skipAdopted: boolean;
}

interface CaseSummary {
  case_id:          string;
  ioc_value:        string;
  severity_text:    string;
  status:           string;
  created_at:       string;
  occurrence_count: number;
  operator_ci:      string;
}

// ─── hooks de datos ───────────────────────────────────────────────────────────

function useOpeningProfiles() {
  return useQuery<OpeningProfile[]>({
    queryKey: ["opening-profiles"],
    queryFn: async () => {
      const r = await fetch(`${API_BASE}/api/scoring-profiles/opening`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json() as { profiles?: OpeningProfile[] };
      return d.profiles ?? [];
    },
    staleTime: 120_000,
    retry: 1,
  });
}

function useOperatorCases() {
  return useQuery<CaseSummary[]>({
    queryKey: ["operator-cases-all"],
    queryFn: async () => {
      const r = await fetch(`${API_BASE}/api/incidents/open?pageSize=200&status=ALL`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json() as { cases?: unknown[] };
      return (d.cases ?? []).map((row) => {
        const rec = row as Record<string, unknown>;
        return {
          case_id:          String(rec["id"]          ?? rec["case_id"]       ?? ""),
          ioc_value:        String(rec["srcIp"]       ?? rec["ioc_value"]     ?? ""),
          severity_text:    String(rec["severity"]    ?? rec["severity_text"] ?? ""),
          status:           String(rec["status"]      ?? "NUEVO"),
          created_at:       String(rec["detectedAt"]  ?? rec["created_at"]   ?? ""),
          occurrence_count: Number(rec["alertCount"]  ?? rec["occurrence_count"] ?? 1),
          operator_ci:      String(rec["operatorCi"]  ?? rec["adopted_by"]   ?? rec["operator_ci"] ?? ""),
        } satisfies CaseSummary;
      });
    },
    staleTime: 30_000,
    retry: 1,
  });
}

// ─── sub-componentes ──────────────────────────────────────────────────────────

function KpiCard({
  label, value, sub, icon: Icon, color,
}: {
  label: string; value: string | number; sub?: string;
  icon: React.ElementType; color: string;
}) {
  return (
    <Card className="bg-card border-border">
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold" style={{ color }}>{value}</p>
            {sub && <p className="text-xs text-muted-foreground">{sub}</p>}
          </div>
          <div
            className="flex h-9 w-9 items-center justify-center rounded-lg"
            style={{ background: alpha(color, 8) }}
          >
            <Icon className="h-4 w-4" style={{ color }} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function RoleBadge({ role }: { role: string }) {
  const d = KC_ROLE_DISPLAY[role] ?? { label: role, color: C.textDim };
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium"
      style={{ background: alpha(d.color, 12), color: d.color, border: `1px solid ${alpha(d.color, 25)}` }}
    >
      {d.label}
    </span>
  );
}

// ─── PÁGINA PRINCIPAL ─────────────────────────────────────────────────────────

export function OperatorProfilePage() {
  const navigate = useNavigate();
  const { preferredUsername, displayName, email, roles, isLabMode } = useAuth();

  // Sincronizar identidad KC → localStorage para compatibilidad con
  // CaseAdoptionModal y otros componentes que leen de loadOperatorCi().
  useEffect(() => {
    const username = preferredUsername ?? (isLabMode ? "lab-user" : null);
    if (!username) return;
    try {
      localStorage.setItem(OPERATOR_CI_KEY,  username);
      localStorage.setItem(OPERATOR_NAME_KEY, displayName ?? username);
      localStorage.setItem(OPERATOR_ID_KEY,  username);
      localStorage.setItem(ANALYST_ID_KEY,   username);
    } catch { /* ignore storage errors */ }
  }, [preferredUsername, displayName, isLabMode]);

  // Identificador de operador: KC username o fallback a localStorage
  const ci = preferredUsername ?? (
    (() => { try { return localStorage.getItem(OPERATOR_CI_KEY) ?? ""; } catch { return ""; } })()
  );

  // Rol más alto en la jerarquía
  const topRole = KC_ROLE_HIERARCHY.find((r) => roles.includes(r)) ?? null;
  // LEADER/ADMIN: acceso a informes de gestión (ejecutivo + técnico).
  const isManager = roles.includes("admin") || roles.includes("manager");
  const [showTechPreview, setShowTechPreview] = useState(false);

  // ── Bulk-sync ────────────────────────────────────────────────────────────

  const [syncDays, setSyncDays]               = useState(30);
  const [syncMinScore, setSyncMinScore]       = useState(10);
  const [syncIncludeLow, setSyncIncludeLow]   = useState(true);
  const [syncResult, setSyncResult]           = useState<{ synced: number; skipped: number; total: number } | null>(null);

  const { data: profiles }                       = useOpeningProfiles();
  const { data: cases, refetch: refetchCases }   = useOperatorCases();
  const { data: operators }                      = useSocOperators();

  const bulkSyncMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<{
        ok: boolean; synced: number; skipped: number; total: number;
      }>("/api/incidents/bulk-sync-pending", {
        operatorCi: ci,
        days: syncDays,
        minScore: syncMinScore,
        includeLowNegligible: syncIncludeLow,
      });
      return res.data;
    },
    onSuccess: (data) => {
      setSyncResult({ synced: data.synced, skipped: data.skipped, total: data.total });
      void refetchCases();
    },
  });

  // ── KPIs derivados ───────────────────────────────────────────────────────

  const activeCases     = (cases ?? []).filter((c) => !["CERRADO", "FALSO_POSITIVO"].includes(c.status));
  const critHighCases   = activeCases.filter((c) => ["CRITICAL", "HIGH"].includes(c.severity_text));
  const myCases         = (cases ?? []).filter((c) => ci && c.operator_ci === ci);
  const myActiveCases   = myCases.filter((c) => !["CERRADO", "FALSO_POSITIVO"].includes(c.status));
  const myCritHigh      = myActiveCases.filter((c) => ["CRITICAL", "HIGH"].includes(c.severity_text));

  // ── RENDER ───────────────────────────────────────────────────────────────

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">

      {/* ── Encabezado ── */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">
          Hola, {displayName || preferredUsername || "Operador"}
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Panel de acceso a gestión de incidentes SOC
        </p>
      </div>

      {/* ── Tarjeta de perfil KC ── */}
      <Card className="border-border">
        <CardContent className="p-5">
          <div className="flex items-start gap-4">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary">
              <User className="h-6 w-6" />
            </div>
            <div className="min-w-0 flex-1 space-y-2">
              <p className="font-semibold text-lg leading-tight">
                {displayName ?? preferredUsername ?? "Operador"}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                {preferredUsername && (
                  <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-xs font-mono text-muted-foreground">
                    <KeyRound className="h-3 w-3" />
                    {preferredUsername}
                  </span>
                )}
                {topRole && <RoleBadge role={topRole} />}
              </div>
              {email && (
                <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Mail className="h-3 w-3 shrink-0" />
                  {email}
                </p>
              )}
              <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Shield className="h-3 w-3 shrink-0" />
                Autenticado vía Keycloak
                {topRole && (
                  <span className="text-muted-foreground/70">
                    — {KC_ROLE_DISPLAY[topRole]?.desc}
                  </span>
                )}
              </p>
            </div>
            <div
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full"
              style={{ background: alpha(C.green, 12) }}
              title="Sesión activa"
            >
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── KPIs ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard
          label="Mis casos activos"
          value={cases === undefined ? "…" : myActiveCases.length}
          sub="asignados a mí"
          icon={Activity}
          color={C.cyan}
        />
        <KpiCard
          label="Crit / Alto (míos)"
          value={cases === undefined ? "…" : myCritHigh.length}
          sub="requieren atención"
          icon={ShieldCheck}
          color={C.red}
        />
        <KpiCard
          label="Total en sistema"
          value={cases === undefined ? "…" : activeCases.length}
          sub={`${critHighCases.length} crit/alto`}
          icon={ClipboardList}
          color={C.orange}
        />
        <KpiCard
          label="Perfiles apertura"
          value={profiles === undefined ? "…" : (profiles?.filter((p) => p.enabled).length ?? 0)}
          sub="habilitados"
          icon={Star}
          color={C.purple}
        />
      </div>

      {/* ── Mis casos asignados ── */}
      <Card className="border-border">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <User className="h-4 w-4 text-primary" />
            Mis casos asignados
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {cases === undefined ? (
            <p className="text-sm text-muted-foreground">Cargando casos…</p>
          ) : myCases.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {ci
                ? "No tienes casos asignados actualmente."
                : "Identidad no configurada — inicia sesión para ver tus casos."}
            </p>
          ) : (
            <>
              {/* Distribución por severidad */}
              <div className="flex flex-wrap gap-2">
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] as const).map((sev) => {
                  const count = myCases.filter((c) => c.severity_text === sev).length;
                  if (!count) return null;
                  const sevColor = SEV_COLOR[sev] ?? C.textDim;
                  return (
                    <span
                      key={sev}
                      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium"
                      style={{ background: alpha(sevColor, 12), color: sevColor, border: `1px solid ${alpha(sevColor, 25)}` }}
                    >
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: sevColor }} />
                      {sev} · {count}
                    </span>
                  );
                })}
              </div>
              {/* Estado de mis casos activos */}
              {myActiveCases.length > 0 && (
                <>
                  <Separator />
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                    Activos ({myActiveCases.length})
                  </p>
                  <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                    {myActiveCases.map((c) => (
                      <div
                        key={c.case_id}
                        className="flex items-center gap-2 rounded-md border border-border bg-card/50 px-3 py-2 text-xs"
                      >
                        <div
                          className="h-2 w-2 shrink-0 rounded-full"
                          style={{ background: SEV_COLOR[c.severity_text] ?? C.textDim }}
                        />
                        <code className="font-mono text-[10px] text-muted-foreground shrink-0">
                          {c.case_id ? c.case_id.slice(0, 8) : "—"}
                        </code>
                        <span className="min-w-0 flex-1 truncate text-foreground">{c.ioc_value || "—"}</span>
                        <Badge variant="outline" className="shrink-0 text-[10px] px-1.5 py-0">{c.status}</Badge>
                        {c.created_at && (
                          <span className="text-muted-foreground/60 shrink-0 text-[10px]">
                            {formatDatePy(c.created_at)}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              )}
              <Button
                variant="outline" size="sm" className="gap-1.5 mt-1"
                onClick={() => navigate("/gestion")}
              >
                <ClipboardList className="h-3.5 w-3.5" />
                Gestionar en panel completo
                <ArrowRight className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
        </CardContent>
      </Card>

      {/* ── Acceso a gestión de incidentes ── */}
      <Card className="border-border">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <FolderOpen className="h-4 w-4 text-primary" />
            Acceso a gestión de incidentes
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Administra los casos asignados, adopta nuevos incidentes y cambia su estado desde el panel principal.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button className="gap-2" onClick={() => navigate("/gestion")}>
              <ClipboardList className="h-4 w-4" />
              Ir a gestión de incidentes
              <ArrowRight className="h-4 w-4" />
            </Button>
            <Button variant="outline" className="gap-2" onClick={() => navigate("/soc")}>
              <ShieldCheck className="h-4 w-4" />
              Operaciones SOC
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* ── Informes de gestión (LEADER/ADMIN) ── */}
      {isManager && (
        <Card className="border-border">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <FileBarChart className="h-4 w-4 text-primary" />
              Informes de gestión de incidentes
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Generá informes por día, semana, mes o rango personalizado desde la fuente de
              gestión de incidentes (<code className="text-xs">incident_cases_pg</code>). El
              <strong> informe ejecutivo</strong> resume KPIs NIST y tendencia; el
              <strong> informe técnico</strong> profundiza en países atacantes (con mapa
              mundial), tendencia por severidad, eventos reincidentes, cobertura MITRE y top IOCs.
              Disponible en Markdown y PDF.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <ExecutiveReportMenu visible />
              <TechnicalReportMenu visible />
              <Button
                variant="outline"
                size="sm"
                className="gap-2"
                onClick={() => setShowTechPreview((v) => !v)}
              >
                <Globe2 className="h-4 w-4" />
                {showTechPreview ? "Ocultar vista previa" : "Vista previa técnica"}
              </Button>
            </div>
            {showTechPreview && (
              <div className="mt-2 rounded-lg border border-border/70 bg-muted/20 p-3">
                <TechnicalReportPanel />
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Sincronización en lote ── */}
      <Card className="border-border">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <RefreshCw className="h-4 w-4 text-primary" />
            Sincronización en lote
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Promueve clasificaciones pendientes (LOW/NEGLIGIBLE o score bajo) a casos formales.
            Se ejecuta en segundo plano — puedes continuar trabajando.
          </p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Ventana (días)</label>
              <Input
                type="number" min={1} max={90}
                value={syncDays}
                onChange={(e) => setSyncDays(Number(e.target.value))}
                className="h-8 text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Score mínimo</label>
              <Input
                type="number" min={0} max={100}
                value={syncMinScore}
                onChange={(e) => setSyncMinScore(Number(e.target.value))}
                className="h-8 text-sm"
              />
            </div>
            <div className="flex flex-col gap-1.5 sm:col-span-1">
              <label className="text-xs font-medium text-muted-foreground">LOW / NEGLIGIBLE</label>
              <button
                type="button"
                onClick={() => setSyncIncludeLow((v) => !v)}
                className="flex h-8 items-center gap-2 rounded-md border px-3 text-xs transition-all"
                style={{
                  borderColor: syncIncludeLow ? alpha(C.green, 38) : undefined,
                  background:  syncIncludeLow ? alpha(C.green, 6)  : undefined,
                  color:       syncIncludeLow ? C.green : C.textDim,
                }}
              >
                {syncIncludeLow
                  ? <CheckCircle2 className="h-3.5 w-3.5" />
                  : <AlertCircle  className="h-3.5 w-3.5" />
                }
                {syncIncludeLow ? "Incluir" : "Excluir"}
              </button>
            </div>
          </div>

          {syncResult && (
            <div className="flex items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2.5 text-sm">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
              <span className="text-emerald-500">
                Iniciado: <strong>{syncResult.total}</strong> candidatos —{" "}
                sincronizando en segundo plano
              </span>
            </div>
          )}

          {bulkSyncMutation.isError && (
            <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {(bulkSyncMutation.error as Error)?.message ?? "Error al iniciar sync"}
            </div>
          )}

          <Button
            onClick={() => { setSyncResult(null); bulkSyncMutation.mutate(); }}
            disabled={bulkSyncMutation.isPending}
            variant="outline"
            className="gap-2"
          >
            {bulkSyncMutation.isPending
              ? <RefreshCw className="h-4 w-4 animate-spin" />
              : <Zap className="h-4 w-4" />
            }
            {bulkSyncMutation.isPending ? "Iniciando…" : "Ejecutar bulk-sync"}
          </Button>
        </CardContent>
      </Card>

      {/* ── KPIs del equipo SOC ── */}
      <Card className="border-border">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <BarChart2 className="h-4 w-4 text-primary" />
            Rendimiento del equipo SOC
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {operators === undefined ? (
            <p className="text-sm text-muted-foreground">Cargando operadores…</p>
          ) : operators.length === 0 ? (
            <p className="text-sm text-muted-foreground">Sin operadores registrados en el workflow.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border">
                    <th className="pb-2 text-left font-medium text-muted-foreground">Operador</th>
                    <th className="pb-2 text-left font-medium text-muted-foreground">Turno</th>
                    <th className="pb-2 text-right font-medium text-muted-foreground">Adoptados</th>
                    <th className="pb-2 text-right font-medium text-muted-foreground">Cerrados</th>
                    <th className="pb-2 text-right font-medium text-muted-foreground">FP</th>
                    <th className="pb-2 text-right font-medium text-muted-foreground">MTTA</th>
                    <th className="pb-2 text-right font-medium text-muted-foreground">MTTR</th>
                  </tr>
                </thead>
                <tbody>
                  {operators.map((op: SocOperator) => {
                    const isMe = op.id === ci;
                    return (
                      <tr
                        key={op.id}
                        className="border-b border-border/50 last:border-0"
                        style={{ background: isMe ? "rgba(0,245,255,0.04)" : undefined }}
                      >
                        <td className="py-2 pr-3">
                          <div className="flex items-center gap-2">
                            <div
                              className="h-1.5 w-1.5 rounded-full shrink-0"
                              style={{ background: op.is_active ? C.green : C.textDim }}
                              title={op.is_active ? "Activo" : "Inactivo"}
                            />
                            <div>
                              <div className="flex items-center gap-1.5">
                                <span className={isMe ? "text-primary font-semibold" : "text-foreground"}>
                                  {op.name || op.id}
                                </span>
                                {op.is_shift_manager && (
                                  <span className="rounded px-1 py-0 text-[9px] font-medium" style={{ background: alpha(C.orange, 12), color: C.orange }}>
                                    MGR
                                  </span>
                                )}
                                {isMe && (
                                  <span className="rounded px-1 py-0 text-[9px] font-medium" style={{ background: alpha(C.cyan, 12), color: C.cyan }}>
                                    yo
                                  </span>
                                )}
                              </div>
                              <div className="text-[10px] text-muted-foreground font-mono">{op.id}</div>
                            </div>
                          </div>
                        </td>
                        <td className="py-2 pr-3">
                          <span className="text-muted-foreground">{op.shift || "—"}</span>
                        </td>
                        <td className="py-2 pr-3 text-right">
                          <span className="font-medium text-foreground">{op.cases_adopted}</span>
                        </td>
                        <td className="py-2 pr-3 text-right">
                          <span className="text-emerald-500 font-medium">{op.cases_closed}</span>
                        </td>
                        <td className="py-2 pr-3 text-right">
                          <span className={op.fp_count > 5 ? "text-orange-400" : "text-muted-foreground"}>
                            {op.fp_count}
                          </span>
                        </td>
                        <td className="py-2 pr-3 text-right">
                          {op.avg_mtta_min != null ? (
                            (() => { const v = Number(op.avg_mtta_min); return (
                            <span className={v <= 10 ? "text-emerald-500" : v <= 30 ? "text-yellow-500" : "text-red-400"}>
                              {v.toFixed(1)} min
                            </span>
                            ); })()
                          ) : (
                            <span className="text-muted-foreground/50">—</span>
                          )}
                        </td>
                        <td className="py-2 text-right">
                          {op.avg_mttr_min != null ? (
                            (() => { const v = Number(op.avg_mttr_min); return (
                            <span className={v <= 60 ? "text-emerald-500" : v <= 120 ? "text-yellow-500" : "text-red-400"}>
                              {v >= 60
                                ? `${(v / 60).toFixed(1)} h`
                                : `${v.toFixed(0)} min`}
                            </span>
                            ); })()
                          ) : (
                            <span className="text-muted-foreground/50">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="mt-3 flex flex-wrap gap-3 text-[10px] text-muted-foreground border-t border-border pt-2">
                <span className="flex items-center gap-1">
                  <TrendingUp className="h-3 w-3 text-emerald-500" />
                  MTTA ≤ 10 min — objetivo NIST RS.MA
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3 text-emerald-500" />
                  MTTR ≤ 1 h — objetivo P1 crítico
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Perfiles de apertura activos ── */}
      <Card className="border-border">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Star className="h-4 w-4 text-primary" />
            Perfiles de apertura activos
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Definen qué combinaciones de severidad y score permiten abrir casos manualmente.
          </p>
          {profiles === undefined ? (
            <p className="text-sm text-muted-foreground">Cargando perfiles…</p>
          ) : profiles.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Sin perfiles configurados — todas las aperturas requieren <code className="text-xs">force=true</code>.
            </p>
          ) : (
            <div className="space-y-2">
              {profiles.map((p) => (
                <div
                  key={p.id}
                  className="flex items-start gap-3 rounded-lg border p-3 transition-all"
                  style={{ opacity: p.enabled ? 1 : 0.5 }}
                >
                  <div
                    className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full"
                    style={{ background: p.enabled ? alpha(C.green, 12) : alpha(C.textDim, 12) }}
                  >
                    {p.enabled
                      ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                      : <AlertCircle  className="h-3.5 w-3.5 text-muted-foreground" />
                    }
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium">{p.name}</span>
                      <Badge variant={p.enabled ? "default" : "secondary"} className="text-[10px] px-1.5">
                        {p.enabled ? "Activo" : "Inactivo"}
                      </Badge>
                    </div>
                    {p.description && (
                      <p className="text-xs text-muted-foreground mt-0.5">{p.description}</p>
                    )}
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {p.severities.map((s) => {
                        const sevColor = SEV_COLOR[s] ?? C.textDim;
                        return (
                          <span
                            key={s}
                            className="rounded px-1.5 py-0.5 text-[10px] font-medium"
                            style={{
                              background: alpha(sevColor, 12),
                              color: sevColor,
                            }}
                          >
                            {s}
                          </span>
                        );
                      })}
                      <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        score ≥ {p.minScore}
                      </span>
                      {p.skipAdopted && (
                        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                          omite adoptados
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
          <Button
            variant="ghost" size="sm"
            className="gap-1.5 text-muted-foreground"
            onClick={() => navigate("/settings")}
          >
            <Users className="h-3.5 w-3.5" />
            Ver ajustes
            <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </CardContent>
      </Card>

    </div>
  );
}
