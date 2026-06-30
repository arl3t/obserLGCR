/**
 * TabCredenciales — Vigilancia Digital
 *
 * Expone el análisis completo del snapshot Leak Intel Hub para el dominio
 * consultado: KPIs de volumen, risk score, factores de riesgo, indicadores
 * de amenaza documental (malware/foros/Telegram), patrones de contraseña
 * y enlace al análisis completo en Exposición de Credenciales.
 */

import {
  AlertTriangle,
  CalendarRange,
  Crosshair,
  Download,
  ExternalLink,
  FileKey2,
  KeyRound,
  Mail,
  MessageSquare,
  Server,
  ShieldAlert,
  Skull,
  Store,
  TrendingUp,
  Upload,
  Users,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import { loadOperatorCi, saveOperatorCi } from "@/lib/operator-ci";
import { useSocOperators } from "@/hooks/useSocWorkflow";
import { exportSurveillancePdf, type CtiCachedSnapshotForPdf } from "@/lib/surveillance-pdf-export";
import { FileText, ShieldCheck } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useLeakIntelHubStore,
  type LeakIntelHubSnapshot,
} from "@/store/leak-intel-hub-store";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { CtiDomainLeaksPanel } from "@/components/digital-surveillance/CtiDomainLeaksPanel";
import { bandFromScore } from "@/components/digital-surveillance/risk-engine/calculateRiskScore";
import { formatNumber, PY_TZ } from "@/lib/format";
import { cn } from "@/lib/utils";

// ── helpers ───────────────────────────────────────────────────────────────────

function riskColor(score: number): string {
  const band = bandFromScore(score);
  if (band === "high")   return "text-red-600 dark:text-red-400";
  if (band === "medium") return "text-amber-600 dark:text-amber-400";
  return "text-emerald-600 dark:text-emerald-400";
}

function riskBadge(score: number): string {
  const band = bandFromScore(score);
  if (band === "high")   return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400";
  if (band === "medium") return "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400";
  return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400";
}

function riskVariant(label?: string): "destructive" | "secondary" | "outline" {
  if (label === "High" || label === "Critical") return "destructive";
  if (label === "Medium") return "secondary";
  return "outline";
}

// ── Estado vacío ──────────────────────────────────────────────────────────────

function NoData({ domain, hasSnapshot }: { domain: string; hasSnapshot: boolean }) {
  return (
    <div className="space-y-4">
      <Card className="border-dashed border-amber-500/30 bg-amber-500/[0.03]">
        <CardContent className="flex items-start gap-4 p-6">
          <Upload className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
          <div className="space-y-2">
            <p className="font-semibold text-sm">
              {hasSnapshot
                ? `Sin datos de credenciales para "${domain}" en el dump cargado`
                : "No hay dump de credenciales cargado"}
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              {hasSnapshot
                ? `El dump actual no contiene registros que coincidan con el dominio "${domain}". Carga un archivo que incluya este dominio.`
                : "Carga un ZIP de Leak Intel (CSV o JSON Hub) en Exposición de Credenciales. Los datos quedan en memoria y se cruzan automáticamente con el dominio buscado aquí."}
            </p>
            <div className="flex flex-wrap gap-2 pt-1">
              <Button asChild size="sm" variant="outline" className="gap-1.5 h-8 text-xs">
                <Link to={`/intel?tab=credenciales&domain=${encodeURIComponent(domain)}`}>
                  <Upload className="h-3.5 w-3.5" />
                  Ir a Exposición de Credenciales
                  <ExternalLink className="h-3 w-3 opacity-60" />
                </Link>
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* CTI Cloud & Olé disponible incluso sin dump local cargado. */}
      <CtiDomainLeaksPanel domain={domain} />

      <Card className="border-border/60">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-primary" />
            Fuentes de credenciales compatibles
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2 text-xs text-muted-foreground">
          {[
            { label: "ZIP", detail: "infrastructure_vulnerabilities + employee_data_exposure + password_reuse CSVs" },
            { label: "JSON Hub", detail: "Arrays con campos content, leakName, leakSource, cvssScore" },
            { label: "CSV genérico", detail: "Cualquier CSV con columnas email/username/password/url" },
            { label: "Deep Web Intel", detail: "CSVs de stealers (RedLine, Lumma, Raccoon, etc.)" },
          ].map((s) => (
            <div key={s.label} className="rounded-lg border border-border/50 p-3">
              <p className="font-semibold text-foreground mb-0.5">{s.label}</p>
              <p>{s.detail}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Cuerpo principal ──────────────────────────────────────────────────────────

function CredentialStats({
  domain,
  snapshot,
  emailCount,
  infraCount,
}: {
  domain: string;
  snapshot: LeakIntelHubSnapshot;
  emailCount: number;
  infraCount: number;
}) {
  const { data: surveillanceData, rss } = useSurveillance();
  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfErr, setPdfErr]   = useState<string | null>(null);
  // PDF: reutiliza el exportador completo de Vigilancia Digital (estructura
  // Tecnomyl) — incluye la sección de credenciales además del resto del
  // contexto del módulo (perímetro, RSS, brand, etc.).
  const handleDownloadPdf = useCallback(async () => {
    if (!surveillanceData) {
      setPdfErr("Esperando carga de datos de Vigilancia… reintenta en un instante.");
      return;
    }
    setPdfBusy(true); setPdfErr(null);
    try {
      // Snapshot CTI Cloud & Olé persistido (no toca el API). Si existe, se
      // inyecta en el PDF en la sección "6b. Credenciales filtradas — CTI".
      // Falla silenciosa: el PDF se genera igual con empty-state si no hay.
      let ctiCached: CtiCachedSnapshotForPdf | null = null;
      try {
        const r = await fetch(
          `/api/intel/cti/leaks/domain/cached?domain=${encodeURIComponent(domain.toLowerCase().trim())}`,
        );
        if (r.ok) {
          const j = await r.json();
          if (j?.ok) {
            ctiCached = {
              hits:          Array.isArray(j.hits) ? j.hits : [],
              count:         Number(j.count ?? 0),
              lastQueriedAt: j.lastQueriedAt ?? undefined,
              topLeakNames:  Array.isArray(j.topLeakNames) ? j.topLeakNames : [],
            };
          }
        }
      } catch { /* sin snapshot → empty-state en el PDF */ }

      await exportSurveillancePdf(
        surveillanceData,
        rss ?? null,
        snapshot,
        emailCount,
        infraCount,
        ctiCached,
      );
    } catch (e) {
      setPdfErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPdfBusy(false);
    }
  }, [surveillanceData, rss, snapshot, emailCount, infraCount, domain]);
  const riskScore = snapshot.overallRiskScore ?? 0;
  const riskLabel = snapshot.riskLabel ?? "—";

  // Descarga del informe consolidado Markdown
  const handleDownloadMarkdown = useCallback(() => {
    const lines: string[] = [
      `# Informe de Credenciales — ${domain}`,
      `**Generado:** ${new Date().toLocaleString("es-ES", { timeZone: PY_TZ })}`,
      `**Fuente:** ${snapshot.sourceLabel}`,
      "",
      "## Resumen ejecutivo",
      `- Registros analizados (muestra): **${formatNumber(snapshot.totalRowsSampled)}**`,
      `- Emails únicos: **${formatNumber(snapshot.uniqueEmailsInSample ?? 0)}**`,
      `- Emails detectados para el dominio: **${formatNumber(emailCount)}**`,
      `- Filas de infraestructura: **${formatNumber(infraCount)}**`,
      `- Stealer logs: **${formatNumber(snapshot.stealerRows ?? 0)}**`,
      `- Combo / URL+pass: **${formatNumber(snapshot.comboRows ?? 0)}**`,
      `- Contraseñas muestreadas: **${formatNumber(snapshot.passwordSamples)}** · Débiles: **${formatNumber(snapshot.weakPasswordSample ?? 0)}**`,
      `- Riesgo global: **${riskScore}/100** (${riskLabel})`,
      `- Filtraciones recientes (12m): **${formatNumber(snapshot.leaksLast12Months ?? 0)}** de ${formatNumber(snapshot.leaksAllTime ?? 0)} totales`,
      "",
      "## Factores de riesgo",
      ...(snapshot.riskFactors ?? []).map((f) => `- **${f.title}** (Score ${f.score}): ${f.detail}`),
      "",
      "## Amenazas documentadas",
      `- Familias de malware: **${snapshot.documentThreatSummary?.malwareFamilies ?? 0}**`,
      `- Foros / marketplaces: **${snapshot.documentThreatSummary?.distributionSites ?? 0}**`,
      `- Canales Telegram: **${snapshot.documentThreatSummary?.telegramHandles ?? 0}**`,
      "",
      "## Patrones de contraseña — Top 10",
      ...((snapshot.passwordTop10 ?? []).map(
        (c) => `- Patrón \`${c.fingerprint}\`: ${c.count} ocurrencias (${c.sharePercent}%) — Ej: ${c.exampleMask}`
      )),
    ];

    const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `leak-intel-${domain}-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    // En Firefox/Safari el click() es asíncrono; revocar inmediatamente puede
    // abortar la descarga. Diferimos al siguiente tick.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }, [domain, snapshot, emailCount, infraCount, riskScore, riskLabel]);

  const dth = snapshot.documentThreatSummary;

  // Snapshot stale: si fue producido con una versión anterior del builder, no
  // tendrá los nuevos campos (`weakPasswordSamples`, `ulpUrls`, `links` en
  // riskFactors). Con bump del store v4→v5 esto se purga al recargar, pero
  // si por algún motivo persiste (browser sin refresh, dev mode), avisamos.
  const factorsHaveLinks =
    (snapshot.riskFactors ?? []).some((f) => Array.isArray(f.links));
  const needsReanalysis =
    (!snapshot.perUserExposure && !snapshot.criticalServices) ||
    (!factorsHaveLinks && (snapshot.riskFactors?.length ?? 0) > 0);

  // ── Apertura de caso para el dominio (1 caso = dominio × dump) ─────────────
  // El operador se elige desde un desplegable poblado por /api/workflow/operators
  // — la entrada manual de CI generaba errores cuando el valor no coincidía con
  // ningún `soc_operators.id` activo.
  const [openCase, setOpenCase] = useState(false);
  const [caseOperatorId, setCaseOperatorId] = useState<string>(loadOperatorCi());
  const [caseBusy, setCaseBusy] = useState(false);
  const [caseErr, setCaseErr]   = useState<string | null>(null);
  const [caseRes, setCaseRes]   = useState<{
    caseId: string;
    severity: string;
    score: number;
    existing?: boolean;
    prep?: { tasks: number; iocs: number; assets: number; evidences: number };
  } | null>(null);
  const opsQuery = useSocOperators();
  const activeOperators = useMemo(
    () => (opsQuery.data ?? []).filter((o) => o.is_active !== false),
    [opsQuery.data],
  );
  // Pre-seleccionar el operador previo si todavía está activo; si no, el primero.
  useEffect(() => {
    if (!openCase || activeOperators.length === 0) return;
    setCaseOperatorId((prev) => {
      if (prev && activeOperators.some((o) => o.id === prev)) return prev;
      return activeOperators[0].id;
    });
  }, [openCase, activeOperators]);

  const caseSeverity = useMemo(() => {
    const s = snapshot.overallRiskScore ?? 0;
    return s >= 80 ? "CRITICAL" : s >= 60 ? "HIGH" : s >= 35 ? "MEDIUM" : "LOW";
  }, [snapshot.overallRiskScore]);

  const handleOpenCase = useCallback(async () => {
    if (!caseOperatorId || !caseOperatorId.trim()) {
      setCaseErr("Selecciona un operador SOC para firmar la apertura del caso.");
      return;
    }
    setCaseBusy(true); setCaseErr(null);
    try {
      const payload = {
        domain,
        operatorCi: caseOperatorId.trim(),
        riskScore:  snapshot.overallRiskScore ?? 0,
        riskLabel:  snapshot.riskLabel,
        leakSource: {
          filename:    snapshot.sourceLabel,
          sourceLabel: snapshot.sourceLabel,
        },
        metrics: {
          emailsForOrg:        emailCount,
          emailsForOrgUnique:  (snapshot.emailsForOrg ?? []).length,
          uniqueEmailsInDump:  snapshot.uniqueEmailsInSample ?? 0,
          totalRowsSampled:    snapshot.totalRowsSampled,
          stealerRows:         snapshot.stealerRows ?? 0,
          comboRows:           snapshot.comboRows ?? 0,
          weakPasswordSample:  snapshot.weakPasswordSample ?? 0,
          passwordSamples:     snapshot.passwordSamples,
          weakPwdRate:         snapshot.weakPwdRate,
          leaksLast12Months:   snapshot.leaksLast12Months ?? 0,
          leaksAllTime:        snapshot.leaksAllTime ?? 0,
          firewallOverlapCount: snapshot.firewallOverlapCount,
          infraRowsForDomain:  infraCount,
        },
        topAffectedUsers: (snapshot.perUserExposure ?? []).slice(0, 20).map((u) => ({
          email:         u.email,
          hits:          u.hits,
          uniquePwds: u.uniquePwds,
          topServices:   u.topServices,
        })),
        criticalServices: (snapshot.criticalServices ?? []).slice(0, 20),
        riskFactors:      snapshot.riskFactors ?? [],
      };
      saveOperatorCi(caseOperatorId);
      const { data } = await api.post("/api/incidents/open-from-leak", payload);
      setCaseRes({
        caseId:   data.caseId,
        severity: data.severity,
        score:    data.score,
        prep:     data.prep ?? undefined,
      });
    } catch (e: unknown) {
      // Axios error: 409 ⇒ existente
      const errAny = e as { response?: { status?: number; data?: { error?: string; existingCaseId?: string; existingSeverity?: string; existingScore?: number; hint?: string } }; message?: string };
      const r = errAny.response;
      if (r?.status === 409 && r.data?.existingCaseId) {
        setCaseRes({
          caseId:   r.data.existingCaseId,
          severity: r.data.existingSeverity ?? "—",
          score:    r.data.existingScore    ?? 0,
          existing: true,
        });
        setCaseErr(r.data.hint ?? r.data.error ?? null);
      } else {
        setCaseErr(r?.data?.error ?? errAny.message ?? "Error al abrir caso");
      }
    } finally {
      setCaseBusy(false);
    }
  }, [caseOperatorId, domain, snapshot, emailCount, infraCount]);

  return (
    <div className="space-y-6">
      {/* Aviso de re-análisis si el snapshot es anterior a los nuevos campos */}
      {needsReanalysis && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
          <div className="space-y-1">
            <p className="text-sm font-semibold text-amber-700 dark:text-amber-400">
              Análisis desactualizado — re-analiza el archivo
            </p>
            <p className="text-xs text-amber-600/80 dark:text-amber-400/80">
              El dump fue cargado con una versión anterior. Haz clic en <strong>Analizar</strong> sobre
              el archivo en la sección "Fuentes de inteligencia local" para ver la tabla de usuarios,
              servicios críticos, timeline y canales Telegram.
            </p>
          </div>
        </div>
      )}

      {/* Cabecera / fuente */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs text-muted-foreground">
          Fuente:{" "}
          <span className="font-mono font-medium text-foreground">{snapshot.sourceLabel}</span>
          {" · "}
          {new Date(snapshot.updatedAt).toLocaleString("es-ES", { timeZone: PY_TZ, dateStyle: "short", timeStyle: "short" })}
        </span>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            className={cn(
              "gap-1.5 h-8 text-xs",
              caseSeverity === "CRITICAL" && "bg-red-600 hover:bg-red-700 text-white",
              caseSeverity === "HIGH"     && "bg-orange-600 hover:bg-orange-700 text-white",
              caseSeverity === "MEDIUM"   && "bg-amber-500 hover:bg-amber-600 text-white",
              caseSeverity === "LOW"      && "bg-emerald-600 hover:bg-emerald-700 text-white",
            )}
            onClick={() => { setCaseRes(null); setCaseErr(null); setOpenCase(true); }}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Abrir caso para {domain} ({caseSeverity})
          </Button>
          <Button size="sm" variant="outline" className="gap-1.5 h-8 text-xs" onClick={handleDownloadMarkdown}>
            <Download className="h-3.5 w-3.5" />
            Informe MD
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="gap-1.5 h-8 text-xs"
            onClick={() => void handleDownloadPdf()}
            disabled={pdfBusy || !surveillanceData}
            title={!surveillanceData ? "Esperando datos de Vigilancia" : "Descarga PDF con estructura Tecnomyl (17 secciones)"}
          >
            <FileText className="h-3.5 w-3.5" />
            {pdfBusy ? "Generando…" : "Informe PDF"}
          </Button>
        </div>
      </div>
      {pdfErr && (
        <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-2 text-xs text-destructive">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{pdfErr}</span>
        </div>
      )}

      {/* ── Modal: confirmar apertura de caso para el dominio ─────────────────── */}
      {openCase && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4"
          onClick={() => !caseBusy && setOpenCase(false)}
        >
          <div
            className="w-full max-w-lg rounded-xl border border-border/80 bg-card p-5 shadow-2xl"
            onClick={(ev) => ev.stopPropagation()}
          >
            <div className="mb-3 flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-primary" />
              <h3 className="text-base font-semibold">Abrir caso de gestión de incidentes</h3>
            </div>

            <div className="mb-4 space-y-1.5 rounded-lg border border-border/60 bg-muted/30 p-3 text-xs">
              <p><span className="text-muted-foreground">Dominio:</span> <span className="font-mono font-semibold">{domain}</span></p>
              <p><span className="text-muted-foreground">Fuente:</span> <span className="font-mono">{snapshot.sourceLabel}</span></p>
              <p>
                <span className="text-muted-foreground">Riesgo:</span>{" "}
                <span className="font-semibold">{snapshot.overallRiskScore ?? 0}/100</span>{" "}
                <Badge variant={riskVariant(snapshot.riskLabel)} className="ml-1 text-[10px]">{snapshot.riskLabel ?? caseSeverity}</Badge>
                <span className="ml-2 text-muted-foreground">→ severity</span>{" "}
                <span className="font-semibold">{caseSeverity}</span>
              </p>
              <p>
                <span className="text-muted-foreground">Usuarios afectados:</span>{" "}
                <span className="font-semibold">{formatNumber((snapshot.emailsForOrg ?? []).length || (snapshot.emailsForOrgCount ?? 0))}</span>
                {" · "}
                <span className="text-muted-foreground">menciones:</span>{" "}
                <span className="font-semibold">{formatNumber(emailCount)}</span>
              </p>
              <p className="text-muted-foreground">
                MITRE: <span className="font-mono text-foreground">TA0006 · Credential Access</span>
              </p>
            </div>

            {caseRes ? (
              <div className={cn(
                "mb-3 rounded-lg border p-3 text-xs",
                caseRes.existing
                  ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
                  : "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
              )}>
                <p className="font-semibold mb-1">
                  {caseRes.existing ? "Ya existía un caso activo" : "Caso creado"}
                </p>
                <p>
                  <span className="text-muted-foreground">ID:</span>{" "}
                  <Link to={`/gestion/incidentes?case=${encodeURIComponent(caseRes.caseId)}`} className="font-mono underline">
                    {caseRes.caseId}
                  </Link>
                </p>
                <p>
                  <span className="text-muted-foreground">Severity:</span> {caseRes.severity}
                  {" · "}<span className="text-muted-foreground">Score:</span> {caseRes.score}
                </p>
                {caseRes.prep && !caseRes.existing && (
                  <div className="mt-2 rounded border border-emerald-500/30 bg-emerald-500/5 p-2">
                    <p className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                      Caso pre-cargado para investigación inmediata:
                    </p>
                    <ul className="mt-1 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10px] text-emerald-700/80 dark:text-emerald-300/80">
                      <li>• {caseRes.prep.tasks} tareas NIST 800-61 generadas</li>
                      <li>• {caseRes.prep.iocs} IOCs registrados (dominio + emails)</li>
                      <li>• {caseRes.prep.assets} assets comprometidos</li>
                      <li>• {caseRes.prep.evidences} evidencias en cadena de custodia</li>
                    </ul>
                  </div>
                )}
                {caseErr && <p className="mt-2 text-[11px] opacity-80">{caseErr}</p>}
              </div>
            ) : (
              <>
                <label className="mb-3 block">
                  <span className="mb-1 block text-xs text-muted-foreground">
                    Operador SOC asignado{" "}
                    <span className="text-muted-foreground/60">
                      (registrado en <code className="font-mono">soc_operators</code>)
                    </span>
                  </span>
                  {opsQuery.isLoading ? (
                    <div className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-muted-foreground italic">
                      Cargando operadores…
                    </div>
                  ) : opsQuery.isError ? (
                    <div className="w-full rounded-md border border-destructive/50 bg-destructive/5 px-3 py-1.5 text-sm text-destructive">
                      Error al cargar operadores: {String(opsQuery.error)}
                    </div>
                  ) : activeOperators.length === 0 ? (
                    <div className="w-full rounded-md border border-amber-500/50 bg-amber-500/5 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-400">
                      No hay operadores activos en <code>soc_operators</code>. Pídele al admin
                      que dé de alta operadores antes de abrir el caso.
                    </div>
                  ) : (
                    <select
                      value={caseOperatorId}
                      onChange={(ev) => setCaseOperatorId(ev.target.value)}
                      autoFocus
                      className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm"
                    >
                      {activeOperators.map((o) => (
                        <option key={o.id} value={o.id}>
                          {o.name} · {o.role_name} · CI {o.id}
                          {o.is_shift_manager ? " ★" : ""}
                        </option>
                      ))}
                    </select>
                  )}
                </label>
                {caseErr && (
                  <p className="mb-3 text-xs text-red-600 dark:text-red-400">{caseErr}</p>
                )}
              </>
            )}

            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={() => setOpenCase(false)} disabled={caseBusy}>
                {caseRes ? "Cerrar" : "Cancelar"}
              </Button>
              {!caseRes && (
                <Button
                  size="sm"
                  onClick={() => void handleOpenCase()}
                  disabled={caseBusy || !caseOperatorId || activeOperators.length === 0}
                >
                  {caseBusy ? "Abriendo…" : "Confirmar apertura"}
                </Button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Bloque 1: Resumen del dump ─── */}
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Resumen del dump</p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground">Filas analizadas</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <p className="text-2xl font-bold tabular-nums">{formatNumber(snapshot.totalRowsSampled)}</p>
              <div className="flex gap-3 text-xs text-muted-foreground">
                <span>Stealer: <span className="font-semibold text-foreground">{formatNumber(snapshot.stealerRows ?? 0)}</span></span>
                <span>Combo: <span className="font-semibold text-foreground">{formatNumber(snapshot.comboRows ?? 0)}</span></span>
                <span>Otros: <span className="font-semibold text-foreground">{formatNumber(snapshot.otherRows ?? 0)}</span></span>
              </div>
            </CardContent>
          </Card>
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground">Emails únicos en dump</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <p className="text-2xl font-bold tabular-nums">{formatNumber(snapshot.uniqueEmailsInSample ?? 0)}</p>
              <p className="text-xs text-muted-foreground">Todos los dominios · muestra</p>
            </CardContent>
          </Card>
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground">Contraseñas muestreadas</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <div className="flex items-baseline gap-3">
                <p className="text-2xl font-bold tabular-nums">{formatNumber(snapshot.passwordSamples)}</p>
                <p className="text-lg font-semibold tabular-nums text-amber-500">{formatNumber(snapshot.weakPasswordSample ?? 0)} débiles</p>
              </div>
              <p className="text-xs text-muted-foreground">
                {snapshot.passwordSamples > 0
                  ? `${((snapshot.weakPasswordSample ?? 0) / snapshot.passwordSamples * 100).toFixed(1)}% heurística local`
                  : "—"}
              </p>
            </CardContent>
          </Card>
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground">Cobertura temporal</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <div className="flex items-baseline gap-3">
                <div>
                  <p className="text-xs text-muted-foreground">Últimos 12m</p>
                  <p className="text-2xl font-bold tabular-nums text-amber-500">{formatNumber(snapshot.leaksLast12Months ?? 0)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Total</p>
                  <p className="text-xl font-semibold tabular-nums">{formatNumber(snapshot.leaksAllTime ?? 0)}</p>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">Registros con fecha parseada</p>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* ── Bloque 2: Exposición corporativa @dominio ─── */}
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Exposición corporativa — @{domain}
        </p>
        <div className="grid gap-3 grid-cols-2 sm:grid-cols-4">
          <div className="rounded-xl border border-primary/20 bg-primary/5 p-4 space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Mail className="h-3.5 w-3.5" />Usuarios únicos expuestos
            </div>
            <p className="text-2xl font-bold tabular-nums text-primary">
              {formatNumber((snapshot.emailsForOrg ?? []).length || (snapshot.emailsForOrgCount ?? 0))}
            </p>
            <p className="text-xs text-muted-foreground">
              {formatNumber(emailCount)} menciones en dump
            </p>
          </div>
          <div className="rounded-xl border border-border/60 p-4 space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Users className="h-3.5 w-3.5" />Usuarios con credencial ULP
            </div>
            <p className="text-2xl font-bold tabular-nums">
              {formatNumber((snapshot.perUserExposure ?? []).length)}
            </p>
            <p className="text-xs text-muted-foreground">
              {formatNumber((snapshot.perUserExposure ?? []).filter(u => u.hits > 100).length)} con +100 registros
            </p>
          </div>
          <div className="rounded-xl border border-border/60 p-4 space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Server className="h-3.5 w-3.5" />Servicios comprometidos
            </div>
            <p className="text-2xl font-bold tabular-nums">
              {formatNumber((snapshot.criticalServices ?? []).length)}
            </p>
            <p className="text-xs text-muted-foreground">
              {(snapshot.criticalServices ?? []).slice(0, 1).map(s => s.service).join("") || "—"}
            </p>
          </div>
          <div className={cn(
            "rounded-xl border p-4 space-y-1",
            (snapshot.weakPwdRate ?? 0) > 30 ? "border-l-2 border-l-red-500 bg-red-500/[0.03] border-border/60" : "border-border/60"
          )}>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <KeyRound className="h-3.5 w-3.5" />Contraseñas débiles
            </div>
            <p className="text-2xl font-bold tabular-nums">{snapshot.weakPwdRate ?? 0}%</p>
            <p className="text-xs text-muted-foreground">Heurística local</p>
          </div>
        </div>
      </div>

      {/* ── Overall risk score (card prominente) ─── */}
      <Card className="border-primary/25 bg-card/80">
        <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <FileKey2 className="h-4 w-4 text-primary" />
              Overall risk score
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              Heurística local: dominio, fechas, infra, superposición firewall, contraseñas débiles.
            </p>
          </div>
          <div className="text-right">
            <p className={cn("text-4xl font-bold tabular-nums", riskColor(riskScore))}>
              {riskScore}
              <span className="text-lg font-normal text-muted-foreground">/100</span>
            </p>
            <Badge variant={riskVariant(riskLabel)}>{riskLabel}</Badge>
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${riskScore}%`,
                backgroundColor: riskScore >= 70 ? "#dc2626" : riskScore >= 40 ? "#d97706" : "#16a34a",
              }}
            />
          </div>
        </CardContent>
      </Card>

      {/* ── Credenciales filtradas (CTI Cloud & Olé) ─── */}
      {/* Misma fuente que aparece en "Estado fuentes" → Búsqueda manual CTI.
          Pre-cargada con el dominio del módulo Vigilancia; búsqueda manual
          para no consumir cupo del API en cada navegación. */}
      <CtiDomainLeaksPanel domain={domain} />

      {/* ── Risk factors ─── */}
      {(snapshot.riskFactors ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            Risk factors
          </h3>
          <div className="space-y-2">
            {(snapshot.riskFactors ?? [])
              .sort((a, b) => b.score - a.score)
              .map((f) => {
                const links = f.links ?? [];
                const isWeakPwd = f.id === "weak-passwords";
                const isUrl = f.id === "org-leaks";
                return (
                  <div key={f.id} className="rounded-lg border border-border/80 bg-muted/20 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-medium text-sm">{f.title}</p>
                      {/* riskFactors del leak-intel scoring tienen score 0-25 por factor;
                          escalamos x4 a 0-100 para reusar la paleta de bandas (40/70). */}
                      <Badge variant="outline" className={cn("shrink-0 tabular-nums text-[10px]", riskBadge(f.score * 4))}>
                        Score {f.score}
                      </Badge>
                    </div>
                    <p className="mt-1 text-sm text-muted-foreground">{f.detail}</p>
                    {links.length > 0 && (
                      <div className="mt-2 space-y-1">
                        <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground/70">
                          {f.linksLabel ?? "Evidencias detectadas"} · {links.length}
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {links.map((lk, i) => (
                            <code
                              key={i}
                              title={lk}
                              className={cn(
                                "rounded border px-1.5 py-0.5 font-mono text-[10px] break-all max-w-full",
                                isWeakPwd
                                  ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400"
                                  : isUrl
                                    ? "border-red-500/30 bg-red-500/5 text-red-700 dark:text-red-400"
                                    : "border-border/60 bg-muted/40 text-muted-foreground",
                              )}
                            >
                              {lk}
                            </code>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* ── Contraseñas débiles detectadas (muestra independiente del card) ─── */}
      {((snapshot.weakPasswordSample ?? 0) > 0 || (snapshot.weakPasswordSamples ?? []).length > 0) && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <KeyRound className="h-4 w-4 text-amber-500" />
            Contraseñas débiles detectadas
            <Badge variant="secondary" className="ml-1 tabular-nums text-[10px]">
              {(snapshot.weakPasswordSamples ?? []).length} / {formatNumber(snapshot.weakPasswordSample ?? 0)}
            </Badge>
          </h3>
          <Card className="border-amber-500/30 bg-amber-500/[0.04]">
            <CardContent className="p-3">
              <p className="text-xs text-muted-foreground mb-2">
                Muestra textual de hasta 12 contraseñas detectadas que la heurística clasificó
                como débiles (longitud &lt; 8, patrones comunes <code className="font-mono">12345/admin/qwerty</code>,
                caracteres repetidos). Forzar rotación inmediata si pertenecen a la organización.
              </p>
              {(snapshot.weakPasswordSamples ?? []).length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {(snapshot.weakPasswordSamples ?? []).map((pwd, i) => (
                    <code
                      key={i}
                      className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 font-mono text-xs text-amber-700 dark:text-amber-400 break-all"
                    >
                      {pwd}
                    </code>
                  ))}
                </div>
              ) : (
                <div className="rounded border border-dashed border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-muted-foreground">
                  Se contabilizaron <strong>{formatNumber(snapshot.weakPasswordSample ?? 0)}</strong>{" "}
                  contraseñas débiles pero el dump no incluyó valores textuales (formato
                  agregado o hashes). Carga un dump con triplas <code>user:pass</code> o
                  re-analiza el archivo para capturar la muestra textual.
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── A. Alert banner critical exposures ─── */}
      {(snapshot.criticalServices ?? []).some(
        (s) => (s.service === "Webmail Corporativo" || s.service === "Microsoft / O365") && s.hits > 0
      ) && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/40 bg-red-500/10 p-4">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-red-500" />
          <div>
            <p className="font-semibold text-sm text-red-700 dark:text-red-400">
              Credenciales de sistemas críticos expuestas
            </p>
            <p className="text-xs text-red-600/80 dark:text-red-400/80 mt-0.5">
              Webmail corporativo y/o Microsoft O365 comprometidos. Cambio de contraseña urgente requerido.
            </p>
          </div>
        </div>
      )}

      {/* ── A1. Correos filtrados ─── */}
      {(snapshot.emailsForOrg ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Mail className="h-4 w-4 text-primary" />
            Correos filtrados
            <Badge variant="secondary" className="ml-1 tabular-nums text-[10px]">
              {formatNumber((snapshot.emailsForOrg ?? []).length)}
            </Badge>
          </h3>
          <Card className="border-border/60">
            <CardContent className="p-0">
              <div className="max-h-52 overflow-y-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>#</TableHead>
                      <TableHead>Correo electrónico</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(snapshot.emailsForOrg ?? []).slice(0, 200).map((email, i) => (
                      <TableRow key={i}>
                        <TableCell className="text-xs tabular-nums text-muted-foreground w-10">{i + 1}</TableCell>
                        <TableCell className="font-mono text-xs">{email}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {(snapshot.emailsForOrg ?? []).length > 200 && (
                <p className="px-4 py-2 text-xs text-muted-foreground border-t border-border/50">
                  Mostrando 200 de {formatNumber((snapshot.emailsForOrg ?? []).length)} correos. Descarga el informe MD para la lista completa.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── B. Top usuarios expuestos con contraseñas ─── */}
      {(snapshot.perUserExposure ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Users className="h-4 w-4 text-primary" />
            Usuarios con contraseñas filtradas
          </h3>
          <Card className="border-border/60">
            <CardContent className="overflow-x-auto p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Usuario</TableHead>
                    <TableHead className="text-right">Registros</TableHead>
                    <TableHead>Contraseñas (muestra)</TableHead>
                    <TableHead>Servicios</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(snapshot.perUserExposure ?? []).slice(0, 25).map((u, i) => (
                    <TableRow
                      key={i}
                      className={cn(
                        u.hits > 500
                          ? "bg-red-500/5 hover:bg-red-500/10"
                          : u.hits > 100
                            ? "bg-amber-500/5 hover:bg-amber-500/10"
                            : undefined,
                      )}
                    >
                      <TableCell className="font-mono text-xs">{u.email}</TableCell>
                      <TableCell className={cn(
                        "text-right text-xs tabular-nums font-semibold",
                        u.hits > 500 ? "text-red-600 dark:text-red-400" : u.hits > 100 ? "text-amber-600 dark:text-amber-400" : "",
                      )}>
                        {formatNumber(u.hits)}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-0.5">
                          {(u.topPasswords ?? []).slice(0, 3).map((pwd, pi) => (
                            <code key={pi} className="text-[10px] bg-muted/60 px-1.5 py-0.5 rounded font-mono text-amber-700 dark:text-amber-400">
                              {pwd}
                            </code>
                          ))}
                          {u.uniquePwds > 3 && (
                            <span className="text-[10px] text-muted-foreground">+{u.uniquePwds - 3} más</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {u.topServices.slice(0, 3).map((svc, si) => (
                            <Badge key={si} variant="outline" className="text-[9px] px-1.5 py-0 font-mono">
                              {svc}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── C. Servicios críticos comprometidos ─── */}
      {(snapshot.criticalServices ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Server className="h-4 w-4 text-destructive" />
            Servicios críticos comprometidos
          </h3>
          <div className="space-y-1.5">
            {(() => {
              const maxHits = Math.max(...(snapshot.criticalServices ?? []).map((s) => s.hits), 1);
              return (snapshot.criticalServices ?? []).map((s, i) => (
                <div key={i} className="rounded-lg border border-border/60 bg-muted/20 p-3">
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-sm font-medium">{s.service}</span>
                    <span className={cn(
                      "text-xs font-semibold tabular-nums",
                      s.hits > 500 ? "text-red-600 dark:text-red-400" : s.hits > 100 ? "text-amber-600 dark:text-amber-400" : "text-foreground",
                    )}>
                      {formatNumber(s.hits)} registros
                    </span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${Math.round((s.hits / maxHits) * 100)}%`,
                        backgroundColor: s.hits > 500 ? "#dc2626" : s.hits > 100 ? "#d97706" : "#3b82f6",
                      }}
                    />
                  </div>
                </div>
              ));
            })()}
          </div>
        </div>
      )}

      {/* ── D. Evolución temporal ─── */}
      {(snapshot.monthlyTimeline ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <CalendarRange className="h-4 w-4 text-primary" />
            Evolución temporal
          </h3>
          <Card className="border-border/60">
            <CardContent className="pt-4">
              <ResponsiveContainer width="100%" height={180}>
                <BarChart
                  data={(snapshot.monthlyTimeline ?? []).slice(-18)}
                  margin={{ top: 4, right: 8, left: 0, bottom: 24 }}
                >
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/40" />
                  <XAxis
                    dataKey="period"
                    tick={{ fontSize: 9 }}
                    angle={-45}
                    textAnchor="end"
                  />
                  <YAxis tick={{ fontSize: 9 }} />
                  <Tooltip
                    contentStyle={{ fontSize: 11 }}
                    labelFormatter={(l) => `Período: ${l}`}
                    formatter={(v: number) => [formatNumber(v), "Registros"]}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── E. Canales Telegram ─── */}
      {(snapshot.telegramHandleList ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <MessageSquare className="h-4 w-4 text-primary" />
            Canales de distribución Telegram
          </h3>
          <div className="max-h-36 overflow-y-auto rounded-lg border border-border/60 bg-muted/20 p-3">
            <div className="flex flex-wrap gap-1.5">
              {(snapshot.telegramHandleList ?? []).map((h, i) => (
                <Badge
                  key={i}
                  variant="outline"
                  className="font-mono text-[10px] px-2 py-0.5 text-muted-foreground border-border/50"
                >
                  {h}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── F. Foros / Marketplaces darknet ─── */}
      {(snapshot.distributionSiteList ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Store className="h-4 w-4 text-destructive" />
            Foros / Marketplaces darknet
          </h3>
          <div className="flex flex-wrap gap-1.5 rounded-lg border border-border/60 bg-muted/20 p-3">
            {(snapshot.distributionSiteList ?? []).map((site, i) => (
              <Badge
                key={i}
                variant="outline"
                className="font-mono text-[10px] px-2 py-0.5 border-red-500/30 text-red-700 dark:text-red-400 bg-red-500/5"
              >
                {site}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* ── Amenazas documentadas (Caza externa) ─── */}
      {dth && dth.totalIndicatorHits > 0 && (
        <div className="space-y-3">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Crosshair className="h-4 w-4 text-destructive" />
            Indicadores en texto de fugas (malware / venta)
            <Badge variant="outline" className={cn("ml-auto text-[10px]", riskBadge(80))}>
              Score 100
            </Badge>
          </h3>
          <div className="grid gap-2 sm:grid-cols-3 text-xs">
            <div className="rounded-lg border border-border/50 p-3 space-y-1.5">
              <div className="flex items-center gap-1.5 text-muted-foreground">
                <Skull className="h-3.5 w-3.5" />
                <span className="font-semibold text-foreground">Familias de malware / stealers</span>
                <Badge variant="outline" className="ml-auto text-[9px] tabular-nums">{dth.malwareFamilies}</Badge>
              </div>
              <div className="flex flex-wrap gap-1 pt-0.5">
                {(snapshot.malwareFamilyList ?? []).map((f, i) => (
                  <Badge
                    key={i}
                    variant="outline"
                    className="text-[10px] px-1.5 py-0 font-mono border-red-500/30 text-red-700 dark:text-red-400 bg-red-500/5"
                    title={`${f.count} ocurrencias`}
                  >
                    {f.label}
                  </Badge>
                ))}
                {(snapshot.malwareFamilyList ?? []).length === 0 && (
                  <span className="text-muted-foreground">Re-analiza el archivo para ver nombres</span>
                )}
              </div>
            </div>
            <div className="rounded-lg border border-border/50 p-3 space-y-0.5">
              <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
                <Store className="h-3.5 w-3.5" />Foros / marketplaces
              </div>
              <p className="text-lg font-bold">{dth.distributionSites}</p>
              <p className="text-muted-foreground/70">sitios de distribución</p>
            </div>
            <div className="rounded-lg border border-border/50 p-3 space-y-0.5">
              <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
                <TrendingUp className="h-3.5 w-3.5" />Canales Telegram
              </div>
              <p className="text-lg font-bold">{dth.telegramHandles}</p>
              <p className="text-muted-foreground/70">handles @t.me</p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            {formatNumber(dth.totalIndicatorHits)} coincidencias textuales totales en el dump.
            Para ver el detalle completo (listas, muestras contextuales) accede al análisis completo.
          </p>
        </div>
      )}

      {/* ── Patrones de contraseña Top 10 ─── */}
      {(snapshot.passwordTop10 ?? []).length > 0 && (
        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <KeyRound className="h-4 w-4 text-primary" />
            Patrones de contraseña — Top 10
          </h3>
          <Card className="border-border/60">
            <CardContent className="overflow-x-auto p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Patrón</TableHead>
                    <TableHead>Ejemplo (redactado)</TableHead>
                    <TableHead className="text-right">Ocurrencias</TableHead>
                    <TableHead className="text-right">%</TableHead>
                    <TableHead>Descripción</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(snapshot.passwordTop10 ?? []).map((c, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-[10px]">{c.fingerprint}</TableCell>
                      <TableCell className="font-mono text-xs">{c.exampleMask}</TableCell>
                      <TableCell className="text-right text-xs tabular-nums">{formatNumber(c.count)}</TableCell>
                      <TableCell className="text-right text-xs tabular-nums">{c.sharePercent}%</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{c.semanticSummary}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Enlace al análisis completo ─── */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-primary/20 bg-primary/5 p-4">
        <div className="space-y-0.5">
          <p className="text-sm font-semibold">Análisis completo disponible</p>
          <p className="text-xs text-muted-foreground">
            Usuarios en riesgo · Informe Markdown por dominio · Caza de amenazas externas ·
            Timeline · Correlación perímetro OPNsense · Vista de archivos
          </p>
        </div>
        <Button asChild size="sm" variant="outline" className="gap-1.5 h-8 text-xs shrink-0">
          <Link to={`/intel?tab=credenciales&domain=${encodeURIComponent(domain)}`}>
            Ir a Exposición de Credenciales
            <ExternalLink className="h-3 w-3 opacity-60" />
          </Link>
        </Button>
      </div>
    </div>
  );
}

// ── Export principal ──────────────────────────────────────────────────────────

export function TabCredenciales() {
  const { domain, snapshot, hasCoverage, emailCount, infraCount } = useSurveillance();
  // Snapshot raw del store — distinguimos "no hay dump cargado" vs "hay dump
  // pero no cubre este dominio" para el estado vacío. El `snapshot` del
  // Provider ya viene clamped a `null` cuando `!hasCoverage`.
  const rawSnapshot = useLeakIntelHubStore((s) => s.snapshot);

  if (!domain) return null;

  if (!snapshot || !hasCoverage) {
    return <NoData domain={domain} hasSnapshot={!!rawSnapshot} />;
  }

  return (
    <CredentialStats
      domain={domain}
      snapshot={snapshot}
      emailCount={emailCount}
      infraCount={infraCount}
    />
  );
}
