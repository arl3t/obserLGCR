/**
 * TabDarkWeb — Threat Intel + browser de archivos S3.
 *
 * Sólo MISP (atributos detectados últimos 90 días) y la lista de archivos
 * de inteligencia local indexados en S3 con patrones de búsqueda editables.
 *
 * El antiguo TabDarkWeb embebía a TabCredenciales abajo, lo que mezclaba
 * inteligencia documental con análisis credenciales. Sprint 5 separa: las
 * credenciales tienen ahora un tab dedicado (`tabs/TabCredenciales.tsx`,
 * tab id `credenciales`) — resuelve §7.1.1 del doc de auditoría.
 */

import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  Download,
  FolderOpen,
  KeyRound,
  Loader2,
  Shield,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { authFetch } from "@/lib/auth-fetch";
import { NoResults, SourceError, SourceNotConfigured } from "@/components/digital-surveillance/shared/source-states";
import { bandBadge } from "@/components/digital-surveillance/shared/band-styles";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useLeakIntelHubStore } from "@/store/leak-intel-hub-store";
import {
  autoPatternsFromDomain,
  formatFileSize,
  type IntelFileEntry,
  useIntelFiles,
} from "@/hooks/useDigitalSurveillance";
import {
  buildLeakIntelReport,
  parseLeakCsvText,
  parseLeakJsonHubDump,
  parseLeakZip,
} from "@/lib/leak-intel";
import type { SurveillanceMispHit } from "@/types/digital-surveillance";
import { formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Estilos por tipo de archivo en el browser de S3
// ─────────────────────────────────────────────────────────────────────────────

const FILE_TYPE_BADGE: Record<string, string> = {
  CSV:  "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  PDF:  "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
  JSON: "border-blue-500/40 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  ZIP:  "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
};

// ─────────────────────────────────────────────────────────────────────────────
// Componente
// ─────────────────────────────────────────────────────────────────────────────

export function TabDarkWeb() {
  const { data } = useSurveillance();
  const domain = data?.domain ?? "";

  const defaultPatterns = useMemo(() => autoPatternsFromDomain(domain), [domain]);
  const [patternsInput, setPatternsInput] = useState(defaultPatterns.join(", "));
  const [committedPatterns, setCommittedPatterns] = useState(defaultPatterns);

  const intelFiles = useIntelFiles(domain, committedPatterns, !!domain);

  const handleSearch = useCallback(() => {
    const parsed = patternsInput
      .split(/[\s,]+/)
      .map((p) => p.trim())
      .filter(Boolean);
    setCommittedPatterns(parsed.length ? parsed : defaultPatterns);
  }, [patternsInput, defaultPatterns]);

  // Análisis de archivos S3
  const ingestHub = useLeakIntelHubStore((s) => s.ingestFromReport);
  const [analyzeKey,    setAnalyzeKey]    = useState<string | null>(null);
  const [analyzeResult, setAnalyzeResult] = useState<{
    filename: string; score: number; label: string; emails: number; totalRows: number;
  } | null>(null);
  const [analyzeError, setAnalyzeError] = useState<string | null>(null);

  // Al cambiar de dominio, resetear patrones editados y resultado del análisis:
  // de lo contrario quedaba visible "Análisis completado — acme.csv" sobre la
  // vista de un dominio distinto, y los patrones del dominio anterior seguían
  // disparando la búsqueda en S3.
  useEffect(() => {
    setPatternsInput(defaultPatterns.join(", "));
    setCommittedPatterns(defaultPatterns);
    setAnalyzeKey(null);
    setAnalyzeResult(null);
    setAnalyzeError(null);
  }, [domain, defaultPatterns]);

  const handleAnalyze = useCallback(async (f: IntelFileEntry) => {
    setAnalyzeKey(f.key);
    setAnalyzeResult(null);
    setAnalyzeError(null);
    try {
      const resp = await authFetch(
        `/api/surveillance/intel-files/download?key=${encodeURIComponent(f.key)}`,
      );
      if (!resp.ok) throw new Error(`Error descargando archivo: HTTP ${resp.status}`);
      const blob = await resp.blob();

      let parsedFiles: Awaited<ReturnType<typeof parseLeakZip>>;
      const lower = f.filename.toLowerCase();
      if (lower.endsWith(".zip")) {
        const file = new File([blob], f.filename, { type: blob.type });
        parsedFiles = await parseLeakZip(file);
      } else if (lower.endsWith(".csv") || lower.endsWith(".tsv")) {
        const text = await blob.text();
        parsedFiles = [parseLeakCsvText(f.filename, text)];
      } else if (lower.endsWith(".json") || lower.endsWith(".ndjson")) {
        const text = await blob.text();
        parsedFiles = [parseLeakJsonHubDump(f.filename, text)];
      } else {
        throw new Error("Formato no soportado para análisis (CSV, JSON, ZIP).");
      }

      if (!parsedFiles.length) throw new Error("No se encontraron datos procesables.");

      const report = buildLeakIntelReport(parsedFiles, {
        orgDomains: [domain],
        blockedIpToHits: {},
      });

      ingestHub(report, [domain], f.filename);
      setAnalyzeResult({
        filename: f.filename,
        score:     report.overallRiskScore,
        label:     report.riskLabel,
        emails:    report.emailsForOrg.length,
        totalRows: report.stats.totalRecordsSampled,
      });
    } catch (e) {
      setAnalyzeError(e instanceof Error ? e.message : String(e));
    } finally {
      setAnalyzeKey(null);
    }
  }, [domain, ingestHub]);

  if (!data) return null;
  const { misp } = data;

  return (
    <div className="space-y-6">
      {/* MISP */}
      <div className="space-y-3">
        <h3 className="flex items-center gap-2 text-base font-semibold">
          <Shield className="h-4 w-4 text-primary" />
          MISP Threat Intelligence
        </h3>
        {!misp.configured ? (
          <SourceNotConfigured name="MISP" envKey="MISP_BASE_URL + MISP_API_KEY" />
        ) : misp.error ? (
          <SourceError error={misp.error} />
        ) : (misp.hits ?? []).length === 0 ? (
          <NoResults message={`Sin atributos en MISP para "${domain}" en los últimos 90 días.`} />
        ) : (
          <Card className="border-border/70">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-primary" />
                  {misp.count} atributo(s) encontrado(s)
                </span>
                <Badge variant="outline" className={cn("text-[10px]", bandBadge["high"])}>
                  Amenaza detectada
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Tipo</TableHead>
                    <TableHead>Valor</TableHead>
                    <TableHead>Categoría</TableHead>
                    <TableHead>Evento</TableHead>
                    <TableHead>Tags</TableHead>
                    <TableHead>Fecha</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(misp.hits ?? []).map((hit: SurveillanceMispHit) => (
                    <TableRow key={hit.uuid ?? hit.id}>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-[10px]">{hit.type}</Badge>
                      </TableCell>
                      <TableCell className="max-w-[180px] truncate font-mono text-xs">{hit.value}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{hit.category}</TableCell>
                      <TableCell className="max-w-[160px] truncate text-xs">{hit.event_title ?? hit.event_id ?? "—"}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(hit.tags ?? []).slice(0, 3).map((t: string) => (
                            <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {hit.timestamp ? formatRelativeTimeEs(hit.timestamp) : "—"}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>

      {/* ── Fuentes de inteligencia local ─────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="flex items-center gap-2 text-base font-semibold">
            <Database className="h-4 w-4 text-primary" />
            Fuentes de inteligencia local
          </h3>
          <span className="text-xs text-muted-foreground">
            CSV · PDF · JSON · ZIP cargados en el sistema
          </span>
        </div>

        {/* Patrones de búsqueda */}
        <div className="flex gap-2">
          <Input
            value={patternsInput}
            onChange={(e) => setPatternsInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder="itti*, itti.com.py, dimabel*"
            className="h-8 font-mono text-xs"
          />
          <Button
            size="sm"
            variant="outline"
            className="h-8 shrink-0 gap-1.5 text-xs"
            onClick={handleSearch}
            disabled={intelFiles.isFetching}
          >
            {intelFiles.isFetching ? <Loader2 className="h-3 w-3 animate-spin" /> : <FolderOpen className="h-3 w-3" />}
            Buscar
          </Button>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Patrones separados por comas o espacios. Usa <code className="rounded bg-muted px-1 font-mono">*</code> como wildcard. Busca en nombre de archivo y organización.
        </p>

        {/* Estado de carga */}
        {intelFiles.isLoading && (
          <div className="flex items-center gap-3 py-8 text-sm text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" />
            Buscando en fuentes de inteligencia…
          </div>
        )}

        {/* Error */}
        {intelFiles.isError && (
          <SourceError error={intelFiles.error instanceof Error ? intelFiles.error.message : "Error al buscar en fuentes de inteligencia."} />
        )}

        {/* Resultados */}
        {intelFiles.data && (
          <>
            {intelFiles.data.files.length === 0 ? (
              <Card className="border-dashed border-border/60">
                <CardContent className="flex items-start gap-4 p-5">
                  <FolderOpen className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground/50" />
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">
                      Sin archivos que coincidan con los patrones
                    </p>
                    <p className="text-xs text-muted-foreground/70">
                      Patrones buscados: <code className="rounded bg-muted px-1 font-mono text-[11px]">{committedPatterns.join(", ")}</code>
                    </p>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card className="border-border/70">
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center justify-between text-sm">
                    <span className="flex items-center gap-2">
                      <Database className="h-4 w-4 text-primary" />
                      {intelFiles.data.total} archivo(s) encontrado(s)
                    </span>
                    <div className="flex items-center gap-2">
                      {intelFiles.data.truncated && (
                        <Badge variant="outline" className="text-[10px] text-amber-600 border-amber-500/40">
                          truncado a 200
                        </Badge>
                      )}
                      <span className="text-[11px] text-muted-foreground font-normal">
                        Patrones: <code className="rounded bg-muted px-1 font-mono">{committedPatterns.join(", ")}</code>
                      </span>
                    </div>
                  </CardTitle>
                </CardHeader>
                <CardContent className="overflow-x-auto p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Tipo</TableHead>
                        <TableHead>Archivo</TableHead>
                        <TableHead>Organización</TableHead>
                        <TableHead>Fecha</TableHead>
                        <TableHead className="text-right">Tamaño</TableHead>
                        <TableHead></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {intelFiles.data.files.map((f) => (
                        <TableRow key={f.key}>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={cn(
                                "font-mono text-[10px]",
                                FILE_TYPE_BADGE[f.type] ?? "border-border/50 text-muted-foreground",
                              )}
                            >
                              {f.type}
                            </Badge>
                          </TableCell>
                          <TableCell className="max-w-[200px]">
                            <span className="block truncate text-xs font-medium" title={f.filename}>
                              {f.filename}
                            </span>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">{f.orgSlug || "—"}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatRelativeTimeEs(f.lastModified)}
                            </span>
                          </TableCell>
                          <TableCell className="text-right text-xs tabular-nums text-muted-foreground">
                            {formatFileSize(f.size)}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <button
                                type="button"
                                onClick={async () => {
                                  // Descarga autenticada: authFetch para incluir JWT,
                                  // blob → object URL → click sintético → revoke.
                                  // Un <a href> directo no adjunta Authorization.
                                  try {
                                    const r = await authFetch(
                                      `/api/surveillance/intel-files/download?key=${encodeURIComponent(f.key)}`,
                                    );
                                    if (!r.ok) throw new Error(`HTTP ${r.status}`);
                                    const blob = await r.blob();
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement("a");
                                    a.href = url;
                                    a.download = f.filename;
                                    a.click();
                                    setTimeout(() => URL.revokeObjectURL(url), 0);
                                  } catch (err) {
                                    setAnalyzeError(
                                      `Error descargando archivo: ${err instanceof Error ? err.message : String(err)}`,
                                    );
                                  }
                                }}
                                className="inline-flex items-center gap-1 rounded-md border border-border/50 px-2 py-1 text-[11px] text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                              >
                                <Download className="h-3 w-3" />
                                Descargar
                              </button>
                              {(["CSV","JSON","ZIP","csv","json","zip"].includes(f.type)) && (
                                <button
                                  type="button"
                                  disabled={analyzeKey === f.key}
                                  onClick={() => handleAnalyze(f)}
                                  className="inline-flex items-center gap-1 rounded-md border border-primary/30 bg-primary/5 px-2 py-1 text-[11px] text-primary transition-colors hover:bg-primary/10 disabled:opacity-50"
                                >
                                  {analyzeKey === f.key ? (
                                    <Loader2 className="h-3 w-3 animate-spin" />
                                  ) : (
                                    <KeyRound className="h-3 w-3" />
                                  )}
                                  Analizar
                                </button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}

            {/* ── Resultado del análisis ── */}
            {analyzeError && (
              <Card className="border-destructive/40 bg-destructive/5">
                <CardContent className="flex items-start gap-3 p-4">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
                  <div className="text-sm">
                    <p className="font-semibold text-destructive">Error al analizar archivo</p>
                    <p className="text-xs text-muted-foreground">{analyzeError}</p>
                  </div>
                </CardContent>
              </Card>
            )}
            {analyzeResult && (
              <Card className="border-primary/30 bg-primary/5">
                <CardContent className="flex items-start gap-3 p-4">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                  <div className="space-y-0.5">
                    <p className="text-sm font-semibold">
                      Análisis completado — {analyzeResult.filename}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {analyzeResult.totalRows.toLocaleString()} registros ·{" "}
                      {analyzeResult.emails} emails corporativos detectados ·{" "}
                      Risk score{" "}
                      <span className="font-bold text-foreground">
                        {analyzeResult.score}/100
                      </span>{" "}
                      ({analyzeResult.label}) — ver resultados en el tab Credenciales
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
