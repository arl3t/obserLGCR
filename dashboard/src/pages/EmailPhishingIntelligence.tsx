/**
 * EmailPhishingIntelligence — Detalle Proxmox Mail Gateway.
 *
 * Fuente: minio.hunting.pmg_phishing (vista normalizada por Vector).
 * Antes: 14 queries sueltas + 3 Recharts (AreaChart stacked, BarChart scores, BarChart process).
 * Ahora: 1 batch + MiniSparkline + BarRow + pills.
 */
import { useCallback, useMemo, useState } from "react";
import { keepPreviousData } from "@tanstack/react-query";
import {
  AlertTriangle, Ban, ChevronLeft, ChevronRight, FolderOpen, Globe, Info,
  Mail, MailX, RefreshCw, Shield, ShieldAlert, Target, TrendingUp, Users, Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTimePy } from "@/lib/format";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { OpenCaseModal, type OpenCasePayload } from "@/components/case-management/OpenCaseModal";
import type { Severity } from "@/components/case-management/types";
import {
  BarRow, DetailHeader, EmptyState, KpiTile, LoadingRows, MiniSparkline, SectionCard,
  SeverityBadge, type Tone,
} from "./detection/_components";
import { cn } from "@/lib/utils";

const STALE_5M = {
  staleTime:            5 * 60_000,
  gcTime:               15 * 60_000,
  placeholderData:      keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

type K =
  | "kpis" | "hourly" | "senders" | "senderEmails" | "authFail" | "blists"
  | "urls" | "scoreD" | "recent" | "byProc" | "recipients" | "campaigns"
  | "authBreak" | "spike";

const SPECS = [
  { key: "kpis",         id: "lh.pmg.kpis_24h"                   },
  { key: "hourly",       id: "lh.pmg.actions_by_hour_24h"        },
  { key: "senders",      id: "lh.pmg.top_senders_24h_mat",        params: { limit: 12 } },
  { key: "senderEmails", id: "lh.pmg.top_sender_emails_24h",      params: { limit: 12 } },
  { key: "authFail",     id: "lh.pmg.auth_failures_24h",          params: { limit: 10 } },
  { key: "blists",       id: "lh.pmg.top_blocklists_24h",         params: { limit: 8  } },
  { key: "urls",         id: "lh.pmg.top_suspicious_urls_24h",    params: { limit: 10 } },
  { key: "scoreD",       id: "lh.pmg.spam_score_distribution_24h" },
  { key: "recent",       id: "lh.pmg.recent_events",              params: { limit: 50  } },
  { key: "byProc",       id: "lh.pmg.by_process_24h",             params: { limit: 8  } },
  { key: "recipients",   id: "lh.pmg.top_recipients_24h",         params: { limit: 12 } },
  { key: "campaigns",    id: "lh.pmg.campaign_clusters_24h_mat",  params: { limit: 10 } },
  { key: "authBreak",    id: "lh.pmg.auth_breakdown_24h"          },
  { key: "spike",        id: "lh.pmg.volume_spike_2h"             },
] as const satisfies readonly BatchSpec[];

function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") { const x = Number(v); return Number.isNaN(x) ? 0 : x; }
  return 0;
}

function fmtSize(bytes: unknown): string {
  const b = n(bytes);
  if (b >= 1_048_576) return `${(b / 1_048_576).toFixed(1)} MB`;
  if (b >= 1_024)     return `${(b / 1_024).toFixed(0)} KB`;
  return `${b} B`;
}

function actionTone(action: string): Tone {
  const a = action.toLowerCase();
  if (a === "reject")     return "critical";
  if (a === "quarantine") return "warning";
  if (a === "accepted")   return "ok";
  return "muted";
}

function actionLabel(action: string): string {
  const a = action.toLowerCase();
  if (a === "reject")     return "bloqueado";
  if (a === "quarantine") return "cuarentena";
  if (a === "accepted")   return "aceptado";
  if (a === "deferred")   return "diferido";
  return action || "—";
}

function authTone(type: string): Tone {
  const t = type.toLowerCase();
  if (t === "fail") return "critical";
  if (t === "pass") return "ok";
  return "muted";
}

function scoreBucketTone(bucket: string): Tone {
  const b = bucket.toLowerCase();
  if (b.includes("definit"))  return "critical";
  if (b.includes("probable")) return "warning";
  if (b.includes("sospech"))  return "warning";
  if (b.includes("limpio") || b.includes("clean")) return "ok";
  return "muted";
}

function pmgRiskScore(r: Record<string, unknown>): { score: number; severity: Severity } {
  const spamScore  = n(r.max_spam_score ?? r.avg_spam_score ?? r.spam_score);
  const blocked    = n(r.blocked);
  const recipients = n(r.unique_recipients);
  const hasAuth    = Boolean(r.has_auth_failure ?? r.auth_failed);
  const hasMalUrl  = Boolean(r.has_malicious_url ?? r.url_malicious);
  let score = Math.min(40, spamScore * 2)
            + Math.min(20, Math.log2(blocked + 1) * 3)
            + Math.min(15, Math.log2(recipients + 1) * 3)
            + (hasAuth ? 15 : 0)
            + (hasMalUrl ? 20 : 0);
  score = Math.min(100, Math.round(score));
  const severity: Severity = score >= 75 ? "HIGH" : score >= 50 ? "MEDIUM" : "LOW";
  return { score, severity };
}

export function EmailPhishingIntelligencePage() {
  const { results, isLoading, isFetching, refetch } =
    useTrinoNamedBatch<K>(["pmg", "detail"], SPECS, STALE_5M);

  const kpi          = (results.kpis.data         as Record<string, unknown>[] | undefined)?.[0] ?? {};
  const hourly       = (results.hourly.data       as Record<string, unknown>[] | undefined) ?? [];
  const senders      = (results.senders.data      as Record<string, unknown>[] | undefined) ?? [];
  const senderEmails = (results.senderEmails.data as Record<string, unknown>[] | undefined) ?? [];
  const authFail     = (results.authFail.data     as Record<string, unknown>[] | undefined) ?? [];
  const blists       = (results.blists.data       as Record<string, unknown>[] | undefined) ?? [];
  const urls         = (results.urls.data         as Record<string, unknown>[] | undefined) ?? [];
  const scoreD       = (results.scoreD.data       as Record<string, unknown>[] | undefined) ?? [];
  const recent       = (results.recent.data       as Record<string, unknown>[] | undefined) ?? [];
  const byProc       = (results.byProc.data       as Record<string, unknown>[] | undefined) ?? [];
  const recipients   = (results.recipients.data   as Record<string, unknown>[] | undefined) ?? [];
  const campaigns    = (results.campaigns.data    as Record<string, unknown>[] | undefined) ?? [];
  const authBreak    = (results.authBreak.data    as Record<string, unknown>[] | undefined)?.[0] ?? {};
  const spikeRow     = (results.spike.data        as Record<string, unknown>[] | undefined)?.[0];

  const totalEvents         = n(kpi.total_events);
  const blocked             = n(kpi.blocked);
  const quarantined         = n(kpi.quarantined);
  const rejected            = n(kpi.rejected);
  const authFailures        = n(kpi.auth_failures);
  const avgSpamScore        = n(kpi.avg_spam_score).toFixed(1);
  const uniqueSenderIps     = n(kpi.unique_sender_ips);
  const uniqueSenderDomains = n(kpi.unique_sender_domains);

  const spikeRatio = n(spikeRow?.ratio_vs_prev);
  const hasSpike   = spikeRatio >= 2.0;

  const spark = useMemo(
    () => hourly.map((r) => ({
      value: n(r.blocked) + n(r.quarantined) + n(r.auth_failures),
      label: String(r.hour ?? "").slice(11, 16),
    })),
    [hourly],
  );

  const scoreMax = Math.max(1, ...scoreD.map((r) => n(r.eventos)));
  const procMax  = Math.max(1, ...byProc.map((r) => n(r.total)));
  const hasErr   = Object.values(results).some((r) => r.error);

  // Open Case modal (preservado)
  const [caseModal, setCaseModal] = useState<{ open: boolean; payload: OpenCasePayload }>({
    open: false,
    payload: { iocValue: "", iocType: "ip", sourceLog: "pmg_phishing", severity: "MEDIUM", score: 0 },
  });
  const openCaseFor = useCallback((r: Record<string, unknown>) => {
    const senderIp     = String(r.sender_ip     ?? "");
    const senderDomain = String(r.sender_domain ?? "");
    const senderEmail  = String(r.sender_email  ?? "");
    const iocValue = (senderDomain && senderDomain !== "?" && senderDomain !== "(sin dominio)")
      ? senderDomain
      : (senderEmail && senderEmail !== "?" && senderEmail.includes("@"))
        ? senderEmail.split("@")[1]
        : senderIp;
    const iocType: "ip" | "domain" = iocValue === senderIp ? "ip" : "domain";
    const { score, severity } = pmgRiskScore(r);
    setCaseModal({ open: true, payload: { iocValue, iocType, sourceLog: "pmg_phishing", severity, score } });
  }, []);

  // Paginación feed reciente
  const PAGE_SIZE = 15;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(recent.length / PAGE_SIZE));
  const pagedRows = useMemo(
    () => recent.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [recent, page],
  );

  const noData = !isLoading && totalEvents === 0 && !results.kpis.error;

  return (
    <div className="flex flex-col gap-5 p-6">
      <DetailHeader
        icon={MailX}
        title="Email / Phishing"
        subtitle="Proxmox Mail Gateway · últimas 24 h"
        right={
          <Button
            variant="outline" size="sm" className="h-7 gap-1 text-[11px]"
            onClick={() => void refetch()} disabled={isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
            {isFetching ? "Actualizando…" : "Refrescar"}
          </Button>
        }
      />

      {hasSpike && (
        <div className="flex items-center gap-2 rounded-md border border-orange-500/40 bg-orange-500/10 px-3 py-1.5 text-xs text-orange-500">
          <Zap className="h-3.5 w-3.5" />
          Spike detectado: <strong>×{spikeRatio.toFixed(1)}</strong> vs hora anterior ({n(spikeRow?.total)} eventos esta hora)
        </div>
      )}

      {results.kpis.error && (
        <div className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-600">
          <AlertTriangle className="h-3.5 w-3.5" />
          Tabla pmg_phishing no encontrada. Ejecuta: <code className="font-mono">./scripts/bootstrap-trino-pmg-view.sh</code>
        </div>
      )}

      {hasErr && !results.kpis.error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive">
          Algunas secciones fallaron — reintenta o revisa el proxy Trino.
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
        <KpiTile label="Eventos"         value={totalEvents}         icon={Mail}           tone="info"     loading={isLoading} />
        <KpiTile label="Bloqueados"      value={blocked}             icon={Ban}            tone="critical" loading={isLoading}
          sub={totalEvents ? `${Math.round((blocked / totalEvents) * 100)}%` : undefined} />
        <KpiTile label="Rechazados"      value={rejected}            icon={Ban}            tone="critical" loading={isLoading} sub="reject directo" />
        <KpiTile label="Cuarentena"      value={quarantined}         icon={ShieldAlert}    tone="warning"  loading={isLoading} />
        <KpiTile label="Fallos auth"     value={authFailures}        icon={AlertTriangle}  tone="warning"  loading={isLoading} sub="DMARC/SPF/DKIM" />
        <KpiTile label="Spam medio"      value={avgSpamScore}        icon={Shield}         tone="muted"    loading={isLoading} />
        <KpiTile label="IPs remit."      value={uniqueSenderIps}     icon={Globe}          tone="info"     loading={isLoading} />
        <KpiTile label="Dominios"        value={uniqueSenderDomains} icon={TrendingUp}     tone="info"     loading={isLoading} />
      </div>

      {/* Timeline + score dist */}
      <div className="grid gap-4 lg:grid-cols-3">
        <SectionCard className="lg:col-span-2" title="Actividad por hora" subtitle="Bloqueos + cuarentena + fallos auth">
          {isLoading ? <LoadingRows rows={2} /> : (
            <MiniSparkline data={spark} height={56} tone="critical" />
          )}
        </SectionCard>

        <SectionCard title="Spam score" subtitle="Distribución por bucket">
          {isLoading ? <LoadingRows /> : scoreD.length === 0 ? (
            <EmptyState message="Sin datos" />
          ) : (
            <div className="flex flex-col">
              {scoreD.map((r, i) => (
                <BarRow
                  key={i}
                  label={<span className="truncate text-[11px]">{String(r.bucket ?? "—")}</span>}
                  value={n(r.eventos)}
                  max={scoreMax}
                  tone={scoreBucketTone(String(r.bucket ?? ""))}
                />
              ))}
            </div>
          )}
        </SectionCard>
      </div>

      {/* Top senders + blocklists/procesos */}
      <div className="grid gap-4 xl:grid-cols-2">
        <SectionCard title="Top remitentes — IP / dominio" subtitle="Bloqueados en 24 h — click Caso para abrir incidente">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Dominio</TableHead>
                  <TableHead className="text-right">Bloq</TableHead>
                  <TableHead className="text-right">Dest.</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead className="w-20 text-center">Caso</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={7} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && senders.length === 0 && (
                  <TableRow><TableCell colSpan={7} className="py-6 text-center text-xs text-muted-foreground">Sin datos</TableCell></TableRow>
                )}
                {senders.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs">{String(r.sender_ip ?? "?")}</TableCell>
                    <TableCell className="max-w-[130px] truncate text-[11px] text-muted-foreground">{String(r.sender_domain ?? "?")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-destructive">{n(r.blocked).toLocaleString("es-ES")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.unique_recipients)}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{r.max_spam_score != null ? Number(r.max_spam_score).toFixed(1) : "—"}</TableCell>
                    <TableCell>{Boolean(r.has_auth_failure) && <Badge variant="outline" className="border-yellow-500 text-yellow-600 text-[9px] px-1 py-0">auth</Badge>}</TableCell>
                    <TableCell className="text-center">
                      <Button size="sm" variant="outline" className="h-6 gap-1 px-2 text-[11px]" onClick={() => openCaseFor(r)}>
                        <FolderOpen className="h-3 w-3" /> Caso
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>

        <div className="flex flex-col gap-4">
          <SectionCard title="Blocklists activadas" subtitle="Top 8 listas que bloquearon">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Blocklist</TableHead>
                    <TableHead className="text-right">Hits</TableHead>
                    <TableHead className="text-right">IPs</TableHead>
                    <TableHead className="text-right">Dominios</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading && <TableRow><TableCell colSpan={4} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                  {!isLoading && blists.length === 0 && (
                    <TableRow><TableCell colSpan={4} className="py-4 text-center text-xs text-muted-foreground">Sin blocklists</TableCell></TableRow>
                  )}
                  {blists.map((r, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">{String(r.blocklist ?? "?")}</TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.hits).toLocaleString("es-ES")}</TableCell>
                      <TableCell className="text-right font-mono text-[11px] text-muted-foreground">{n(r.unique_ips)}</TableCell>
                      <TableCell className="text-right font-mono text-[11px] text-muted-foreground">{n(r.unique_domains)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </SectionCard>

          <SectionCard title="Por componente PMG" subtitle="pmg_process breakdown">
            {isLoading ? <LoadingRows rows={3} /> : byProc.length === 0 ? (
              <EmptyState message="Sin datos" />
            ) : (
              <div className="flex flex-col">
                {byProc.map((r, i) => (
                  <BarRow
                    key={i}
                    label={<span className="truncate font-mono">{String(r.pmg_process ?? "otro")}</span>}
                    value={n(r.total)}
                    max={procMax}
                    tone={n(r.blocked) > 0 ? "critical" : "info"}
                    right={n(r.blocked) > 0 ? <span className="text-[10px] text-red-400">{n(r.blocked)} bloq</span> : null}
                  />
                ))}
              </div>
            )}
          </SectionCard>
        </div>
      </div>

      {/* Top sender emails */}
      <SectionCard title="Top emails remitentes" subtitle="Direcciones completas — click Caso para abrir incidente">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>IP</TableHead>
                <TableHead className="text-right">Total</TableHead>
                <TableHead className="text-right">Bloq</TableHead>
                <TableHead className="text-right">Dest.</TableHead>
                <TableHead className="text-right">Score</TableHead>
                <TableHead>Flags</TableHead>
                <TableHead className="w-20 text-center">Caso</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && <TableRow><TableCell colSpan={8} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
              {!isLoading && senderEmails.length === 0 && (
                <TableRow><TableCell colSpan={8} className="py-6 text-center text-xs text-muted-foreground">Sin datos de sender_email</TableCell></TableRow>
              )}
              {senderEmails.map((r, i) => (
                <TableRow key={i}>
                  <TableCell className="max-w-[200px] truncate font-mono text-xs">{String(r.sender_email ?? "?")}</TableCell>
                  <TableCell className="font-mono text-[11px] text-muted-foreground">{String(r.sender_ip ?? "?")}</TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.total_events).toLocaleString("es-ES")}</TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums text-destructive">{n(r.blocked).toLocaleString("es-ES")}</TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.unique_recipients)}</TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums">{r.max_spam_score != null ? Number(r.max_spam_score).toFixed(1) : "—"}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {Boolean(r.has_auth_failure)  && <Badge variant="outline" className="border-yellow-500 text-yellow-600 text-[9px] px-1 py-0">auth</Badge>}
                      {Boolean(r.has_malicious_url) && <Badge variant="destructive" className="text-[9px] px-1 py-0">phishing</Badge>}
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    <Button size="sm" variant="outline" className="h-6 gap-1 px-2 text-[11px]" onClick={() => openCaseFor(r)}>
                      <FolderOpen className="h-3 w-3" /> Caso
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </SectionCard>

      {/* Auth failures + suspicious URLs */}
      <div className="grid gap-4 xl:grid-cols-2">
        <SectionCard title="Fallos DMARC / SPF / DKIM" subtitle="Top 10 dominios con fallos auth">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Dominio</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Tipo</TableHead>
                  <TableHead>DMARC</TableHead>
                  <TableHead>SPF</TableHead>
                  <TableHead>DKIM</TableHead>
                  <TableHead className="text-right">Ev.</TableHead>
                  <TableHead className="text-right">Dest.</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={8} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && authFail.length === 0 && (
                  <TableRow><TableCell colSpan={8} className="py-4 text-center text-xs text-muted-foreground">Sin fallos de autenticación</TableCell></TableRow>
                )}
                {authFail.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="max-w-[120px] truncate font-mono text-xs">{String(r.sender_domain ?? "?")}</TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">{String(r.sender_ip ?? "?")}</TableCell>
                    <TableCell><SeverityBadge label={String(r.auth_fail_type ?? "?")} tone="warning" /></TableCell>
                    <TableCell><SeverityBadge label={String(r.dmarc_result ?? "—")} tone={authTone(String(r.dmarc_result ?? ""))} /></TableCell>
                    <TableCell><SeverityBadge label={String(r.spf_result   ?? "—")} tone={authTone(String(r.spf_result   ?? ""))} /></TableCell>
                    <TableCell><SeverityBadge label={String(r.dkim_result  ?? "—")} tone={authTone(String(r.dkim_result  ?? ""))} /></TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.events).toLocaleString("es-ES")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.unique_recipients)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>

        <SectionCard title="URLs sospechosas" subtitle="Detectadas en cuerpos de email">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URL</TableHead>
                  <TableHead className="text-right">Hits</TableHead>
                  <TableHead className="text-right">Remit.</TableHead>
                  <TableHead className="text-right">Bloq</TableHead>
                  <TableHead>Estado</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={5} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && urls.length === 0 && (
                  <TableRow><TableCell colSpan={5} className="py-4 text-center text-xs text-muted-foreground">Sin URLs detectadas</TableCell></TableRow>
                )}
                {urls.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="max-w-[240px] truncate font-mono text-[11px]">{String(r.suspicious_url ?? "?")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.hits)}</TableCell>
                    <TableCell className="text-right font-mono text-[11px] text-muted-foreground">{n(r.unique_senders)}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-destructive">{n(r.blocked)}</TableCell>
                    <TableCell>
                      <SeverityBadge label={r.url_malicious ? "phishing" : "sin confirmar"} tone={r.url_malicious ? "critical" : "muted"} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>
      </div>

      {/* Auth breakdown */}
      <SectionCard title="Autenticación email — resumen" subtitle="DMARC / SPF / DKIM · tasa de fallos vs pass">
        {isLoading ? <LoadingRows rows={3} /> : (
          <div className="grid grid-cols-3 gap-4">
            {([
              { label: "DMARC", fail: n(authBreak.dmarc_fail), pass: n(authBreak.dmarc_pass), none: n(authBreak.dmarc_none), color: "#ef4444" },
              { label: "SPF",   fail: n(authBreak.spf_fail),   pass: n(authBreak.spf_pass),   none: n(authBreak.spf_none),   color: "#f97316" },
              { label: "DKIM",  fail: n(authBreak.dkim_fail),  pass: n(authBreak.dkim_pass),  none: n(authBreak.dkim_none),  color: "#eab308" },
            ]).map((col) => {
              const total = col.fail + col.pass + col.none || 1;
              const failPct = Math.round((col.fail / total) * 100);
              const passPct = Math.round((col.pass / total) * 100);
              return (
                <div key={col.label} className="flex flex-col items-center gap-1.5">
                  <span className="text-xs font-semibold">{col.label}</span>
                  <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
                    <div style={{ width: `${failPct}%`, background: col.color }} />
                    <div style={{ width: `${passPct}%`, background: "#22c55e" }} />
                  </div>
                  <div className="flex w-full justify-between text-[10px] text-muted-foreground">
                    <span className="font-medium text-destructive">{col.fail.toLocaleString("es-ES")} fail</span>
                    <span className="font-medium text-emerald-500">{col.pass.toLocaleString("es-ES")} pass</span>
                    <span>{col.none.toLocaleString("es-ES")} n/a</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>

      {/* Recipients + campaigns */}
      <div className="grid gap-4 xl:grid-cols-2">
        <SectionCard title="Destinatarios más atacados" subtitle="Top 12">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead><Users className="mr-1 inline h-3 w-3" />Destinatario</TableHead>
                  <TableHead className="text-right">Recib.</TableHead>
                  <TableHead className="text-right">Bloq</TableHead>
                  <TableHead className="text-right">Cuar.</TableHead>
                  <TableHead className="text-right">Remit.</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={6} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && recipients.length === 0 && (
                  <TableRow><TableCell colSpan={6} className="py-6 text-center text-xs text-muted-foreground">Sin datos</TableCell></TableRow>
                )}
                {recipients.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="max-w-[180px] truncate font-mono text-xs">{String(r.recipient_email ?? "?")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.total_received).toLocaleString("es-ES")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-destructive">{n(r.blocked).toLocaleString("es-ES")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-orange-400">{n(r.quarantined).toLocaleString("es-ES")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.unique_senders)}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{r.avg_spam_score != null ? Number(r.avg_spam_score).toFixed(1) : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>

        <SectionCard title="Campañas coordinadas" subtitle="IPs atacando 2+ dominios">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead><Target className="mr-1 inline h-3 w-3 text-rose-500" />IP</TableHead>
                  <TableHead className="text-right">Dominios</TableHead>
                  <TableHead className="text-right">Emails</TableHead>
                  <TableHead className="text-right">Bloq</TableHead>
                  <TableHead className="text-right">Dest.</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead className="w-20 text-center">Caso</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={7} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && campaigns.length === 0 && (
                  <TableRow><TableCell colSpan={7} className="py-6 text-center text-xs text-muted-foreground">Sin campañas</TableCell></TableRow>
                )}
                {campaigns.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs">{String(r.sender_ip ?? "?")}</TableCell>
                    <TableCell className="text-right font-mono text-xs font-semibold tabular-nums">{n(r.targeted_domains)}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.total_emails).toLocaleString("es-ES")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-destructive">{n(r.blocked).toLocaleString("es-ES")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{n(r.unique_recipients)}</TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {Boolean(r.has_auth_fail)     && <Badge variant="outline" className="border-yellow-500 text-yellow-600 text-[9px] px-1 py-0">auth</Badge>}
                        {Boolean(r.has_malicious_url) && <Badge variant="destructive" className="text-[9px] px-1 py-0">phishing</Badge>}
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <Button size="sm" variant="outline" className="h-6 gap-1 px-2 text-[11px]" onClick={() => openCaseFor(r)}>
                        <FolderOpen className="h-3 w-3" /> Caso
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>
      </div>

      {/* Feed reciente */}
      <SectionCard
        title="Feed reciente — Email Gateway"
        subtitle={recent.length > 0 ? `${recent.length} eventos en caché` : "Sin eventos"}
        right={totalPages > 1 && (
          <div className="flex items-center gap-1 text-xs">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}
              className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-30">
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="tabular-nums">{page}/{totalPages}</span>
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
              className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-30">
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        )}
      >
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hora</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Email remit.</TableHead>
                <TableHead>Destinatario</TableHead>
                <TableHead>Acción</TableHead>
                <TableHead className="text-right">Score</TableHead>
                <TableHead className="text-right">Tamaño</TableHead>
                <TableHead>Auth</TableHead>
                <TableHead>Blocklist</TableHead>
                <TableHead className="w-16 text-center" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && <TableRow><TableCell colSpan={10} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
              {!isLoading && pagedRows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={10} className="py-8 text-center text-xs text-muted-foreground">
                    {results.recent.error
                      ? <>Error al consultar <code>pmg_phishing</code>. Ejecuta <code>./scripts/bootstrap-trino-pmg-view.sh</code>.</>
                      : "Sin eventos PMG en las últimas 24 h."}
                  </TableCell>
                </TableRow>
              )}
              {pagedRows.map((r, i) => {
                const timeStr = r.ts
                  ? formatDateTimePy(String(r.ts), { year: undefined, month: undefined, day: undefined })
                  : "?";
                const msgSize = n(r.message_size);
                const isLarge = msgSize > 5_000_000;
                const act = String(r.action ?? "—");
                return (
                  <TableRow key={i}>
                    <TableCell className="whitespace-nowrap font-mono text-[11px] text-muted-foreground">{timeStr}</TableCell>
                    <TableCell className="font-mono text-xs">{String(r.sender_ip ?? "?")}</TableCell>
                    <TableCell className="max-w-[160px] truncate font-mono text-[11px] text-muted-foreground">{String(r.sender_email ?? "?")}</TableCell>
                    <TableCell className="max-w-[130px] truncate text-[11px] text-muted-foreground">{String(r.recipient_email ?? "?")}</TableCell>
                    <TableCell><SeverityBadge label={actionLabel(act)} tone={actionTone(act)} /></TableCell>
                    <TableCell className="text-right font-mono text-xs">{r.spam_score != null ? Number(r.spam_score).toFixed(1) : "—"}</TableCell>
                    <TableCell className={cn("text-right font-mono text-xs", isLarge ? "text-orange-400" : "text-muted-foreground")}>{fmtSize(r.message_size)}</TableCell>
                    <TableCell className="text-[11px]">
                      {r.auth_failed
                        ? <span className="font-medium text-yellow-500">{String(r.auth_fail_type ?? "fail")}</span>
                        : <span className="text-muted-foreground">ok</span>}
                    </TableCell>
                    <TableCell className="max-w-[120px] truncate font-mono text-[11px] text-muted-foreground">{String(r.blocklist_ref ?? "—")}</TableCell>
                    <TableCell className="text-center">
                      {(Boolean(r.is_blocked) || Boolean(r.auth_failed)) && (
                        <Button size="sm" variant="ghost" className="h-6 gap-1 px-1.5 text-[10px]" onClick={() => openCaseFor(r)}>
                          <FolderOpen className="h-3 w-3" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </SectionCard>

      {/* Nota configuración */}
      {noData && (
        <SectionCard title="Panel vacío" subtitle="Pasos para activar la integración PMG">
          <div className="flex items-start gap-2 text-xs text-muted-foreground">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <ol className="list-decimal space-y-1 pl-4">
              <li>PMG → Administración → Syslog → host: IP pública VM, puerto 9025 UDP.</li>
              <li>Verificar Vector: <code className="rounded bg-muted px-1">curl -s http://IP:8687/metrics | grep pmg</code></li>
              <li>Ejecutar sync: <code className="rounded bg-muted px-1">./scripts/sync-s3-lake-to-minio.sh</code></li>
              <li>Bootstrap Trino: <code className="rounded bg-muted px-1">./scripts/bootstrap-trino-pmg-view.sh</code></li>
              <li>Recargar este panel.</li>
            </ol>
          </div>
        </SectionCard>
      )}

      <OpenCaseModal
        open={caseModal.open}
        onOpenChange={(v) => setCaseModal((s) => ({ ...s, open: v }))}
        payload={caseModal.payload}
        sourceLabel="Email Phishing (PMG)"
      />
    </div>
  );
}
