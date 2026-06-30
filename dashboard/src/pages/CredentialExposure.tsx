import { motion } from "framer-motion";
import {
  AlertTriangle,
  CalendarRange,
  Crosshair,
  FileKey2,
  Link2,
  Loader2,
  Shield,
  Skull,
  Store,
  Upload,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTrinoNamed } from "@/hooks/useTrinoQuery";
import { useGeoIpBatch } from "@/hooks/useGeoIpBatch";
import { getLegacyHuntApiBase } from "@/lib/api-origin";
import { API_ROUTES } from "@/lib/api-routes";
import { formatNumber } from "@/lib/format";
import {
  LEAK_INTEL_MAX_ROWS_PER_CSV,
  buildLeakIntelReport,
  parseLeakCsvText,
  parseLeakJsonHubDump,
  parseLeakZip,
  type LeakIntelReport,
} from "@/lib/leak-intel";
import {
  buildDomainConsolidatedMarkdown,
  consolidateDomainCredentials,
  extractDomainCredentialLines,
} from "@/lib/leak-intel-domain-consolidated";
import { CREDENTIAL_TAB_EXTERNAL_HUNT } from "@/lib/threat-document-indicators";
import { cn } from "@/lib/utils";
import { useLeakIntelHubStore } from "@/store/leak-intel-hub-store";

function StatBlock({
  label,
  total,
  unique,
  subtitle,
}: {
  label: string;
  total: number;
  unique?: number;
  subtitle?: string;
}) {
  return (
    <Card className="border-border/80 bg-card/80">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        <div className="flex items-baseline gap-3">
          <div>
            <p className="text-xs text-muted-foreground">Total</p>
            <p className="text-2xl font-bold tabular-nums">{formatNumber(total)}</p>
          </div>
          {unique != null && (
            <div>
              <p className="text-xs text-muted-foreground">Unique</p>
              <p className="text-xl font-semibold tabular-nums text-primary">
                {formatNumber(unique)}
              </p>
            </div>
          )}
        </div>
        {subtitle && (
          <p className="text-xs text-muted-foreground">{subtitle}</p>
        )}
      </CardContent>
    </Card>
  );
}

export function CredentialExposurePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = searchParams.get("tab") ?? "insights";

  const setTab = useCallback(
    (value: string) => {
      setSearchParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          if (value === "insights") p.delete("tab");
          else p.set("tab", value);
          return p;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const [orgInput, setOrgInput] = useState("legacy-roots.net");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<LeakIntelReport | null>(null);
  const [sourceLabel, setSourceLabel] = useState<string>("");
  /** Archivo original para ingesta S3 vía API */
  const [stagedFile, setStagedFile] = useState<File | null>(null);
  const [ingestBusy, setIngestBusy] = useState(false);
  const [ingestMsg, setIngestMsg] = useState<string | null>(null);
  const [mdCopied, setMdCopied] = useState(false);

  const blocked = useTrinoNamed(
    ["leak-intel", "blocked"],
    "lh.syslog.top_blocked_ips",
    { limit: 6000, hours: 24 * 45 },
    { staleTime: 15 * 60_000, gcTime: 30 * 60_000 },
  );

  const blockedMap = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of blocked.data ?? []) {
      const ip = String(r.src_ip ?? "").trim();
      if (ip) m[ip] = Number(r.hits ?? 0);
    }
    return m;
  }, [blocked.data]);

  const orgDomains = useMemo(
    () =>
      orgInput
        .split(/[,;\n]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    [orgInput],
  );

  const ingestHub = useLeakIntelHubStore((s) => s.ingestFromReport);

  const recompute = useCallback(
    (files: Parameters<typeof buildLeakIntelReport>[0], label: string) => {
      const r = buildLeakIntelReport(files, {
        orgDomains,
        blockedIpToHits: blockedMap,
      });
      setReport(r);
      setSourceLabel(label);
      ingestHub(r, orgDomains, label);
    },
    [blockedMap, ingestHub, orgDomains],
  );

  const onFiles = useCallback(
    async (list: FileList | null) => {
      const f = list?.[0];
      if (!f) return;
      setBusy(true);
      setError(null);
      try {
        const lower = f.name.toLowerCase();
        let files: Awaited<ReturnType<typeof parseLeakZip>>;
        if (lower.endsWith(".zip")) {
          files = await parseLeakZip(f);
        } else if (lower.endsWith(".csv")) {
          const text = await f.text();
          files = [parseLeakCsvText(f.name, text)];
        } else if (lower.endsWith(".json")) {
          const text = await f.text();
          files = [parseLeakJsonHubDump(f.name, text)];
        } else {
          throw new Error(
            "Usa .zip (CSV y/o JSON), .csv o .json (hub array).",
          );
        }
        if (!files.length) {
          throw new Error("No se encontraron CSV ni JSON dentro del ZIP.");
        }
        recompute(files, f.name);
        setStagedFile(f);
        setIngestMsg(null);
      } catch (e) {
        setReport(null);
        setStagedFile(null);
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [recompute],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      void onFiles(e.dataTransfer.files);
    },
    [onFiles],
  );

  const refreshCorrelation = useCallback(() => {
    if (!report) return;
    recompute(report.files, sourceLabel);
  }, [recompute, report, sourceLabel]);

  const matchIps = useMemo(
    () => (report?.firewallMatches ?? []).map((m) => m.ip),
    [report],
  );
  const { byIp: asnByIp, pending: geoPending } = useGeoIpBatch(matchIps);

  const persistRawToLake = useCallback(async () => {
    if (!stagedFile) return;
    setIngestBusy(true);
    setIngestMsg(null);
    try {
      const fd = new FormData();
      fd.append("file", stagedFile);
      fd.append("org_slug", orgDomains[0] ?? "default");
      const headers: Record<string, string> = {};
      const k = import.meta.env.VITE_INGEST_API_KEY?.trim();
      if (k) headers["X-Ingest-Key"] = k;

      const res = await fetch(`${getLegacyHuntApiBase()}${API_ROUTES.leakIntelUpload}`, {
        method: "POST",
        body: fd,
        headers,
      });
      const data = (await res.json().catch(() => ({}))) as {
        ok?: boolean;
        error?: string;
        bucket?: string;
        key?: string;
      };
      if (!res.ok) {
        throw new Error(data.error ?? `HTTP ${res.status}`);
      }
      if (data.bucket && data.key) {
        setIngestMsg(`Ingesta OK → s3://${data.bucket}/${data.key}`);
      } else {
        setIngestMsg("Ingesta completada.");
      }
    } catch (e) {
      setIngestMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setIngestBusy(false);
    }
  }, [orgDomains, stagedFile]);

  const anyTruncated = report?.files.some((f) => f.truncated);

  const primaryDomain = orgDomains[0]?.trim() ?? "";

  const domainConsolidatedMarkdown = useMemo(() => {
    if (!report || !primaryDomain) return "";
    const raw = extractDomainCredentialLines(report.files, primaryDomain);
    const cons = consolidateDomainCredentials(raw);
    return buildDomainConsolidatedMarkdown(primaryDomain, cons, {
      sourceLabel: sourceLabel || undefined,
    });
  }, [primaryDomain, report, sourceLabel]);

  const copyDomainMarkdown = useCallback(() => {
    if (!domainConsolidatedMarkdown) return;
    void navigator.clipboard.writeText(domainConsolidatedMarkdown).then(() => {
      setMdCopied(true);
      window.setTimeout(() => setMdCopied(false), 2000);
    });
  }, [domainConsolidatedMarkdown]);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
            Credential &amp; data leak intel
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Analiza exportes tipo <strong>extended</strong> (ZIP con CSV y, si aplica,
            JSON hub), <strong>CSV</strong> y{" "}
            <strong>JSON array</strong> (content + leakName/leakId/fechas). Se
            correlacionan IPs de infra con bloqueos OPNsense (Trino) y dominios
            organizativos. Máx. {LEAK_INTEL_MAX_ROWS_PER_CSV} filas por CSV en
            navegador. Tras cargar, usa <strong>Ingestar raw en S3</strong> si
            <code className="mx-1 rounded bg-muted px-1">legacyhunt-api</code> está
            en marcha (puerto 8787). Si la ingesta falla con «bucket does not exist», el nombre de bucket del
            API debe coincidir con MinIO: <code className="rounded bg-muted px-1">GET /api/health</code>{" "}
            (campo <code className="rounded bg-muted px-1">bucket</code>) y{" "}
            <code className="rounded bg-muted px-1">MINIO_BUCKET</code> en el{" "}
            <code className="rounded bg-muted px-1">.env</code> raíz.
          </p>
        </div>
        <Badge variant="outline" className="w-fit gap-1">
          <Shield className="h-3.5 w-3.5" aria-hidden />
          Parseo en navegador; Trino/S3 solo si usas esos botones
        </Badge>
      </div>

      <Card
        className="border-2 border-dashed border-border/80 bg-card/60"
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Upload className="h-4 w-4" aria-hidden />
            Cargar informe
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 lg:flex-row lg:items-end">
          <div className="flex-1 space-y-2">
            <label className="text-xs font-medium text-muted-foreground">
              Dominios organización (coma)
            </label>
            <Input
              value={orgInput}
              onChange={(e) => setOrgInput(e.target.value)}
              placeholder="legacy-roots.net"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <Input
              type="file"
              accept=".zip,.csv,.json,application/json"
              className="max-w-xs cursor-pointer"
              disabled={busy}
              onChange={(e) => void onFiles(e.target.files)}
            />
            <Button
              type="button"
              variant="outline"
              disabled={!report || blocked.isLoading}
              onClick={refreshCorrelation}
            >
              Recalcular correlación Trino
            </Button>
            <Button
              type="button"
              variant="default"
              disabled={!stagedFile || ingestBusy}
              onClick={() => void persistRawToLake()}
            >
              {ingestBusy ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                  Subiendo…
                </>
              ) : (
                <>
                  <Link2 className="mr-2 h-4 w-4" aria-hidden />
                  Ingestar raw en S3
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {busy && (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          Procesando…
        </p>
      )}
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
      {ingestMsg && (
        <p
          className={
            ingestMsg.includes("s3://")
              ? "text-sm text-emerald-600 dark:text-emerald-400"
              : "text-sm text-destructive"
          }
          role="status"
        >
          {ingestMsg}
        </p>
      )}
      {anyTruncated && (
        <p className="text-sm text-amber-600 dark:text-amber-400" role="status">
          Al menos un CSV superó el límite de filas: el análisis es una muestra
          representativa para la UI; use backend para proceso completo.
        </p>
      )}

      {report && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <p className="text-xs text-muted-foreground">
            Fuente: <span className="font-mono text-foreground">{sourceLabel}</span>
          </p>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatBlock
              label="Total leaked (muestra)"
              total={report.stats.totalRecordsSampled}
              unique={report.stats.uniqueEmails}
              subtitle="Registros analizados · emails únicos detectados"
            />
            <StatBlock
              label="Stealer logs (filas clasificadas)"
              total={report.stats.stealerRows}
              subtitle="ULP / malware / tags stealer"
            />
            <StatBlock
              label="Combo / URL+pass"
              total={report.stats.comboRows}
              subtitle="Dumps agregados sin breach único"
            />
            <Card className="border-border/80 bg-card/80">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Password analysis (muestra)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1">
                <div className="flex items-baseline gap-3">
                  <div>
                    <p className="text-xs text-muted-foreground">Muestreadas</p>
                    <p className="text-2xl font-bold tabular-nums">
                      {formatNumber(report.stats.passwordSampleSize)}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Débiles</p>
                    <p className="text-xl font-semibold tabular-nums text-amber-500">
                      {formatNumber(report.stats.weakPasswordSample)}
                    </p>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">
                  Heurística local (longitud, patrones triviales)
                </p>
              </CardContent>
            </Card>
          </div>

          <Card className="border-primary/25 bg-card/80">
            <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <FileKey2 className="h-5 w-5 text-primary" aria-hidden />
                  Overall risk score
                </CardTitle>
                <p className="text-sm text-muted-foreground">
                  Heurística local: dominio, fechas, infra, superposición firewall,
                  contraseñas débiles.
                </p>
              </div>
              <div className="text-right">
                <p className="text-4xl font-bold tabular-nums">
                  {report.overallRiskScore}
                  <span className="text-lg font-normal text-muted-foreground">
                    /100
                  </span>
                </p>
                <Badge
                  variant={
                    report.riskLabel === "High"
                      ? "destructive"
                      : report.riskLabel === "Medium"
                        ? "secondary"
                        : "outline"
                  }
                >
                  {report.riskLabel}
                </Badge>
              </div>
            </CardHeader>
          </Card>

          <Tabs value={tab} onValueChange={setTab}>
            <TabsList className="flex flex-wrap">
              <TabsTrigger value="insights">Leaked credential insights</TabsTrigger>
              <TabsTrigger value="informe-dominio">
                Informe dominio (Markdown)
              </TabsTrigger>
              <TabsTrigger value={CREDENTIAL_TAB_EXTERNAL_HUNT}>
                <Crosshair className="mr-1.5 inline h-3.5 w-3.5" aria-hidden />
                Caza amenazas externas (documentos)
              </TabsTrigger>
              <TabsTrigger value="timeline">Risk timeline</TabsTrigger>
              <TabsTrigger value="correlation">Correlación perímetro</TabsTrigger>
              <TabsTrigger value="files">Archivos</TabsTrigger>
            </TabsList>

            <TabsContent value="insights" className="mt-4 space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">
                    Top riskiest users (exposición por archivos)
                  </CardTitle>
                  <p className="text-sm text-muted-foreground">
                    Desde employee_data_exposure cuando existe en el ZIP.
                  </p>
                </CardHeader>
                <CardContent>
                  {report.riskyUsers.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      No hay filas de employee_data_exposure o no se detectaron
                      emails.
                    </p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead scope="col">Usuario</TableHead>
                          <TableHead scope="col" className="text-right">
                            Score
                          </TableHead>
                          <TableHead scope="col" className="text-right">
                            Archivos ref.
                          </TableHead>
                          <TableHead scope="col">Detalle</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {report.riskyUsers.map((u) => (
                          <TableRow key={u.email}>
                            <TableCell className="font-mono text-xs">
                              {u.email}
                            </TableCell>
                            <TableCell className="text-right tabular-nums">
                              {u.riskScore}
                            </TableCell>
                            <TableCell className="text-right tabular-nums">
                              {u.fileCount}
                            </TableCell>
                            <TableCell className="max-w-md truncate text-xs text-muted-foreground">
                              {u.detail}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <AlertTriangle className="h-4 w-4 text-amber-500" aria-hidden />
                    Risk factors
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {report.riskFactors.map((f) => (
                    <div
                      key={f.id}
                      className="rounded-lg border border-border/80 bg-muted/20 p-3"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <p className="font-medium">{f.title}</p>
                        <Badge variant="outline" className="tabular-nums">
                          Score {f.score}
                        </Badge>
                      </div>
                      <p className="mt-1 text-sm text-muted-foreground">
                        {f.detail}
                      </p>
                    </div>
                  ))}
                </CardContent>
              </Card>

              {report.emailsForOrg.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">
                      Emails corporativos detectados ({report.emailsForOrg.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="flex flex-wrap gap-2">
                    {report.emailsForOrg.slice(0, 40).map((e) => (
                      <Badge key={e} variant="secondary" className="font-mono text-xs">
                        {e}
                      </Badge>
                    ))}
                    {report.emailsForOrg.length > 40 && (
                      <Badge variant="outline">+{report.emailsForOrg.length - 40}</Badge>
                    )}
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="informe-dominio" className="mt-4 space-y-4">
              <Card>
                <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <CardTitle className="text-base">
                      Informe consolidado por dominio
                    </CardTitle>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Usa el primer dominio del campo superior (
                      <span className="font-mono text-foreground">
                        {primaryDomain || "—"}
                      </span>
                      ). Filtra líneas ULP/combolist con correo que termina en ese
                      dominio, deduplica por email + secreto + host y genera Markdown
                      con secciones tipo resumen, cuentas, patrones, servicios,
                      timeline e indicaciones.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    disabled={!domainConsolidatedMarkdown}
                    onClick={copyDomainMarkdown}
                  >
                    {mdCopied ? "Copiado" : "Copiar Markdown"}
                  </Button>
                </CardHeader>
                <CardContent>
                  {!primaryDomain ? (
                    <p className="text-sm text-muted-foreground">
                      Indica al menos un dominio organizativo.
                    </p>
                  ) : (
                    <textarea
                      readOnly
                      className="border-input bg-muted/30 text-foreground placeholder:text-muted-foreground focus-visible:ring-ring h-[min(32rem,55vh)] w-full resize-y rounded-md border px-3 py-2 font-mono text-xs focus-visible:ring-2 focus-visible:outline-none"
                      value={
                        domainConsolidatedMarkdown ||
                        "Sin coincidencias para este dominio en la muestra cargada."
                      }
                      aria-label="Informe Markdown consolidado por dominio"
                    />
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value={CREDENTIAL_TAB_EXTERNAL_HUNT} className="mt-4 space-y-4">
              <Card className="border-destructive/20 bg-card/80">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Crosshair className="h-4 w-4 text-primary" aria-hidden />
                    Caza de amenazas externas (texto en documentos)
                  </CardTitle>
                  <p className="text-sm text-muted-foreground">
                    Familias de stealer/malware, foros, marketplaces y canales tipo
                    Telegram citados en nombres de archivo, metadatos y campos{" "}
                    <code className="rounded bg-muted px-1">content</code>. Listas
                    editables en{" "}
                    <code className="rounded bg-muted px-1">
                      threat-document-indicators.ts
                    </code>
                    .
                  </p>
                </CardHeader>
                <CardContent className="flex flex-wrap gap-3">
                  <Badge variant="secondary" className="tabular-nums">
                    {formatNumber(report.documentThreatHunt.totalIndicatorHits)}{" "}
                    coincidencias
                  </Badge>
                  <Button variant="outline" size="sm" asChild type="button">
                    <Link to="/external-threats">
                      Ver perímetro Trino (IPs bloqueadas)
                    </Link>
                  </Button>
                </CardContent>
              </Card>

              <div className="grid gap-4 lg:grid-cols-3">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-sm font-medium">
                      <Skull className="h-4 w-4 text-destructive" aria-hidden />
                      Malware / stealers
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="max-h-[280px] space-y-1 overflow-y-auto text-sm">
                    {report.documentThreatHunt.malwareFamilies.length === 0 ? (
                      <p className="text-muted-foreground">Sin coincidencias.</p>
                    ) : (
                      report.documentThreatHunt.malwareFamilies.map((m) => (
                        <div
                          key={m.label}
                          className="flex justify-between gap-2 border-b border-border/50 py-1"
                        >
                          <span>{m.label}</span>
                          <span className="tabular-nums text-muted-foreground">
                            {m.count}
                          </span>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-sm font-medium">
                      <Store className="h-4 w-4 text-amber-500" aria-hidden />
                      Foros / venta de datos
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="max-h-[280px] space-y-1 overflow-y-auto text-sm">
                    {report.documentThreatHunt.distributionSites.length === 0 ? (
                      <p className="text-muted-foreground">Sin coincidencias.</p>
                    ) : (
                      report.documentThreatHunt.distributionSites.map((m) => (
                        <div
                          key={m.label}
                          className="flex justify-between gap-2 border-b border-border/50 py-1"
                        >
                          <span className="leading-tight">{m.label}</span>
                          <span className="shrink-0 tabular-nums text-muted-foreground">
                            {m.count}
                          </span>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">
                      Telegram / t.me
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="max-h-[280px] space-y-1 overflow-y-auto text-sm">
                    {report.documentThreatHunt.telegramHandles.length === 0 ? (
                      <p className="text-muted-foreground">Sin handles.</p>
                    ) : (
                      report.documentThreatHunt.telegramHandles.map((t) => (
                        <div
                          key={t.handle}
                          className="flex justify-between gap-2 border-b border-border/50 py-1 font-mono text-xs"
                        >
                          <span>@{t.handle}</span>
                          <span className="tabular-nums text-muted-foreground">
                            {t.count}
                          </span>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Muestras contextuales</CardTitle>
                  <p className="text-sm text-muted-foreground">
                    Fragmentos alrededor de la coincidencia (sin exponer credenciales
                    completas en la tabla).
                  </p>
                </CardHeader>
                <CardContent className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Tipo</TableHead>
                        <TableHead scope="col">Indicador</TableHead>
                        <TableHead scope="col">Archivo</TableHead>
                        <TableHead scope="col">Extracto</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {report.documentThreatHunt.samples.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={4} className="text-muted-foreground">
                            Carga un ZIP/CSV para ver muestras.
                          </TableCell>
                        </TableRow>
                      ) : (
                        report.documentThreatHunt.samples.map((s, i) => (
                          <TableRow key={i}>
                            <TableCell className="text-xs">{s.category}</TableCell>
                            <TableCell className="font-mono text-xs">{s.label}</TableCell>
                            <TableCell className="max-w-[140px] truncate font-mono text-xs">
                              {s.sourceFile}
                            </TableCell>
                            <TableCell className="max-w-md font-mono text-xs text-muted-foreground">
                              {s.excerpt}
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="timeline" className="mt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <CalendarRange className="h-4 w-4" aria-hidden />
                    Leak records por mes (fecha en CSV)
                  </CardTitle>
                </CardHeader>
                <CardContent className="h-[280px]">
                  {report.timeline.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      Sin fechas parseables en la muestra.
                    </p>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={report.timeline}>
                        <CartesianGrid
                          stroke="var(--color-border)"
                          strokeDasharray="4 4"
                        />
                        <XAxis
                          dataKey="period"
                          tick={{ fontSize: 10 }}
                          stroke="var(--color-muted-foreground)"
                        />
                        <YAxis stroke="var(--color-muted-foreground)" width={36} />
                        <Tooltip
                          contentStyle={{
                            background: "var(--color-card)",
                            border: "1px solid var(--color-border)",
                            borderRadius: 8,
                          }}
                        />
                        <Line
                          type="monotone"
                          dataKey="count"
                          stroke="var(--color-chart-2)"
                          strokeWidth={2}
                          dot={false}
                          name="Registros"
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="correlation" className="mt-4 space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">
                    IPs de infraestructura vs bloqueos OPNsense (Trino)
                  </CardTitle>
                  <p className="text-sm text-muted-foreground">
                    Coincidencia exacta de IP entre{" "}
                    <code className="rounded bg-muted px-1">infrastructure_vulnerabilities.csv</code>{" "}
                    y top bloqueos (últimos ~45 días).
                  </p>
                </CardHeader>
                <CardContent>
                  {blocked.error && (
                    <p className="text-sm text-destructive">{blocked.error.message}</p>
                  )}
                  {report.firewallMatches.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      Ninguna IP del informe coincide con el top de bloqueos actual.
                      Puede ampliar ventana en Trino o cargar más histórico en el lake.
                    </p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead scope="col">IP</TableHead>
                          <TableHead scope="col">GeoIP (país)</TableHead>
                          <TableHead scope="col">Dominio</TableHead>
                          <TableHead scope="col">Puertos (informe)</TableHead>
                          <TableHead scope="col" className="text-right">
                            Bloqueos Trino
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {report.firewallMatches.map((m) => {
                          const g = asnByIp[m.ip];
                          return (
                            <TableRow key={m.ip}>
                              <TableCell className="font-mono text-sm">{m.ip}</TableCell>
                              <TableCell className="text-xs">
                                {geoPending && !g ? (
                                  "…"
                                ) : (
                                  <span
                                    className={cn(
                                      g?.countryCode &&
                                        "rounded bg-destructive/15 px-1.5 py-0.5",
                                    )}
                                  >
                                    {g?.countryCode ?? "—"}
                                    {g?.countryName ? ` · ${g.countryName}` : ""}
                                  </span>
                                )}
                              </TableCell>
                              <TableCell className="text-xs">{m.domain ?? "—"}</TableCell>
                              <TableCell className="font-mono text-xs">{m.ports}</TableCell>
                              <TableCell className="text-right tabular-nums font-medium">
                                {formatNumber(m.blockedHits)}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="files" className="mt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">CSV procesados</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Ruta</TableHead>
                        <TableHead scope="col">Tipo</TableHead>
                        <TableHead scope="col" className="text-right">
                          Filas
                        </TableHead>
                        <TableHead scope="col">Muestra truncada</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {report.files.map((f) => (
                        <TableRow key={f.path}>
                          <TableCell className="font-mono text-xs">{f.path}</TableCell>
                          <TableCell className="text-xs">{f.kind}</TableCell>
                          <TableCell className="text-right tabular-nums">
                            {f.rows.length}
                          </TableCell>
                          <TableCell>{f.truncated ? "Sí" : "No"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </motion.div>
      )}
    </div>
  );
}
