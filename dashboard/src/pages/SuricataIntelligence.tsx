/**
 * SuricataIntelligence — Detalle NIDS (event_type=alert).
 *
 * Fuente: minio.hunting.syslog (JSON Suricata en `message`, filtrado en backend).
 * Antes: 8 useTrinoNamed independientes (8 HTTP reqs) + 4 Recharts barplots.
 * Ahora: 1 useTrinoNamedBatch (1 req) + CSS bar rows + 1 sparkline propia.
 */
import { useMemo, useState } from "react";
import { keepPreviousData } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, FolderOpen, RefreshCw, Swords } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { formatNumber, formatDateTimePy } from "@/lib/format";
import { OpenCaseModal, type OpenCasePayload } from "@/components/case-management/OpenCaseModal";
import type { Severity } from "@/components/case-management/types";
import {
  BarRow,
  DetailHeader,
  EmptyState,
  KpiTile,
  LoadingRows,
  MiniSparkline,
  SectionCard,
  SeverityBadge,
  type Tone,
} from "./detection/_components";
import { cn } from "@/lib/utils";

const STALE_5M = {
  staleTime:            5 * 60_000,
  gcTime:               15 * 60_000,
  placeholderData:      keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

type K =
  | "kpis"
  | "sigs"
  | "attackers"
  | "ports"
  | "hourly"
  | "sev"
  | "cats"
  | "recent";

const SPECS = [
  { key: "kpis",      id: "lh.suricata.kpis_24h_mat"                  },
  { key: "sigs",      id: "lh.suricata.top_signatures_24h_mat",        params: { limit: 10 } },
  { key: "attackers", id: "lh.suricata.top_attackers_24h_mat",         params: { limit: 15 } },
  { key: "ports",     id: "lh.suricata.top_ports_24h_mat",             params: { limit: 10 } },
  { key: "hourly",    id: "lh.suricata.alerts_by_hour_24h_mat"        },
  { key: "sev",       id: "lh.suricata.severity_distribution_24h_mat" },
  { key: "cats",      id: "lh.suricata.top_categories_24h_mat",        params: { limit: 8  } },
  { key: "recent",    id: "lh.suricata.recent_alerts_mat",         params: { limit: 50  } },
] as const satisfies readonly BatchSpec[];

const SEV_LABEL: Record<number, string> = { 1: "Crítica", 2: "Alta", 3: "Media", 4: "Baja", 0: "—" };
function sevTone(s: number): Tone {
  return s === 1 ? "critical" : s === 2 ? "warning" : s === 3 ? "info" : s === 4 ? "ok" : "muted";
}

function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") { const x = Number(v); return Number.isNaN(x) ? 0 : x; }
  return 0;
}

export function SuricataIntelligencePage() {
  const { results, isLoading, isFetching, refetch } =
    useTrinoNamedBatch<K>(["sur", "detail"], SPECS, STALE_5M);

  const kpi    = (results.kpis.data      as Record<string, unknown>[] | undefined)?.[0] ?? {};
  const sigs   = (results.sigs.data      as Record<string, unknown>[] | undefined) ?? [];
  const atks   = (results.attackers.data as Record<string, unknown>[] | undefined) ?? [];
  const ports  = (results.ports.data     as Record<string, unknown>[] | undefined) ?? [];
  const hourly = (results.hourly.data    as Record<string, unknown>[] | undefined) ?? [];
  const sev    = (results.sev.data       as Record<string, unknown>[] | undefined) ?? [];
  const cats   = (results.cats.data      as Record<string, unknown>[] | undefined) ?? [];
  const recent = (results.recent.data    as Record<string, unknown>[] | undefined) ?? [];

  const totalAlerts  = n(kpi.total_alerts);
  const uniqueSrcIps = n(kpi.unique_src_ips);
  const uniqueSigs   = n(kpi.unique_signatures);
  const uniquePorts  = n(kpi.unique_ports_targeted);

  const spark = useMemo(
    () => hourly.map((r) => ({
      value: n(r.alerts),
      label: String(r.hour ?? "").slice(11, 16),
    })),
    [hourly],
  );

  // Severidad como "chips" con contador — reemplaza el BarChart horizontal.
  const sevPills = useMemo(
    () => sev.map((r) => ({
      severity: n(r.severity),
      count:    n(r.hits),
    })).sort((a, b) => a.severity - b.severity),
    [sev],
  );

  // Máximos para normalizar barras CSS (cada bloque usa su propio max).
  const sigsMax   = Math.max(1, ...sigs.map((r) => n(r.hits)));
  const portsMax  = Math.max(1, ...ports.map((r) => n(r.hits)));
  const catsMax   = Math.max(1, ...cats.map((r) => n(r.hits)));

  // Apertura de caso (comportamiento existente preservado).
  const [caseModal, setCaseModal] = useState<{ open: boolean; payload: OpenCasePayload }>({
    open: false,
    payload: { iocValue: "", iocType: "ip", sourceLog: "suricata", severity: "HIGH", score: 0 },
  });
  function openCaseFor(row: Record<string, unknown>) {
    const hits     = n(row.hits);
    const uniqSigs = n(row.unique_sigs);
    const score    = Math.round(18 + Math.min(7, Math.log2(hits + 1) * 1.3) + Math.min(5, uniqSigs * 0.5));
    const severity: Severity = hits >= 500 ? "CRITICAL" : hits >= 50 ? "HIGH" : "MEDIUM";
    setCaseModal({
      open: true,
      payload: { iocValue: String(row.src_ip ?? ""), iocType: "ip", sourceLog: "suricata", severity, score },
    });
  }

  // Paginación del feed reciente — se resuelve client-side (ya hay 100 en cache).
  const PAGE_SIZE = 10;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(recent.length / PAGE_SIZE));
  const paged = useMemo(
    () => recent.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [recent, page],
  );

  const hasErr = Object.values(results).some((r) => r.error);

  return (
    <div className="flex flex-col gap-5 p-6">
      <DetailHeader
        icon={Swords}
        title="Suricata IDS"
        subtitle="NIDS · event_type=alert · últimas 24 h"
        right={
          <Button
            variant="outline"
            size="sm"
            className="h-7 gap-1 text-[11px]"
            onClick={() => void refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
            {isFetching ? "Actualizando…" : "Refrescar"}
          </Button>
        }
      />

      {hasErr && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive">
          Algunas secciones fallaron — reintenta o revisa el proxy Trino.
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiTile label="Alertas"        value={totalAlerts}  tone="critical" loading={isLoading} />
        <KpiTile label="IPs atacantes"  value={uniqueSrcIps} tone="warning"  loading={isLoading} />
        <KpiTile label="Firmas únicas"  value={uniqueSigs}   tone="info"     loading={isLoading} />
        <KpiTile label="Puertos dest."  value={uniquePorts}  tone="info"     loading={isLoading} />
      </div>

      {/* Timeline + severity pills */}
      <div className="grid gap-4 lg:grid-cols-3">
        <SectionCard
          className="lg:col-span-2"
          title="Actividad por hora"
          subtitle="Alertas observadas — ventana 24 h"
        >
          {isLoading ? <LoadingRows rows={2} /> : (
            <MiniSparkline data={spark} height={48} tone="critical" />
          )}
        </SectionCard>

        <SectionCard title="Severidad" subtitle="Distribución de alertas">
          {isLoading ? <LoadingRows rows={4} /> : sevPills.length === 0 ? (
            <EmptyState message="Sin datos de severidad" />
          ) : (
            <div className="flex flex-col gap-1.5">
              {sevPills.map((p) => (
                <div key={p.severity} className="flex items-center justify-between gap-2">
                  <SeverityBadge label={SEV_LABEL[p.severity] ?? String(p.severity)} tone={sevTone(p.severity)} />
                  <span className="text-sm font-semibold tabular-nums">{formatNumber(p.count)}</span>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      </div>

      {/* Top signatures + ports */}
      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Top firmas" subtitle="Las 10 con más hits">
          {isLoading ? <LoadingRows /> : sigs.length === 0 ? (
            <EmptyState message="Sin firmas disparadas" />
          ) : (
            <div className="flex flex-col">
              {sigs.map((r, i) => (
                <BarRow
                  key={i}
                  label={<span className="truncate font-mono">{String(r.signature ?? "—")}</span>}
                  value={n(r.hits)}
                  max={sigsMax}
                  tone={sevTone(n(r.severity))}
                  title={String(r.signature ?? "")}
                />
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="Puertos atacados" subtitle="Top 10 destino">
          {isLoading ? <LoadingRows /> : ports.length === 0 ? (
            <EmptyState message="Sin puertos atacados" />
          ) : (
            <div className="flex flex-col">
              {ports.map((r, i) => (
                <BarRow
                  key={i}
                  label={<span className="font-mono">{String(r.dest_port ?? "?")}</span>}
                  value={n(r.hits)}
                  max={portsMax}
                  tone="warning"
                />
              ))}
            </div>
          )}
        </SectionCard>
      </div>

      {/* Top attackers */}
      <SectionCard title="Top IPs atacantes" subtitle="15 con más hits — click 'Caso' para abrir incidente">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">#</TableHead>
                <TableHead>IP origen</TableHead>
                <TableHead className="text-right">Alertas</TableHead>
                <TableHead className="text-right">Firmas</TableHead>
                <TableHead className="text-right">Puertos</TableHead>
                <TableHead className="w-20 text-center">Caso</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {atks.length === 0 && !isLoading && (
                <TableRow><TableCell colSpan={6} className="py-6 text-center text-xs text-muted-foreground">Sin alertas en 24 h</TableCell></TableRow>
              )}
              {atks.map((row, i) => (
                <TableRow key={i}>
                  <TableCell className="text-muted-foreground">{i + 1}</TableCell>
                  <TableCell className="font-mono">{String(row.src_ip ?? "—")}</TableCell>
                  <TableCell className="text-right font-semibold tabular-nums text-destructive">
                    {formatNumber(n(row.hits))}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(n(row.unique_sigs))}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(n(row.unique_ports))}</TableCell>
                  <TableCell className="text-center">
                    <Button
                      size="sm" variant="outline"
                      className="h-6 gap-1 px-2 text-[11px]"
                      onClick={() => openCaseFor(row)}
                    >
                      <FolderOpen className="h-3 w-3" /> Caso
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </SectionCard>

      {/* Categorías */}
      <SectionCard title="Categorías de alerta" subtitle="Top 8 — atacantes por categoría">
        {isLoading ? <LoadingRows /> : cats.length === 0 ? (
          <EmptyState message="Sin datos de categorías" />
        ) : (
          <div className="flex flex-col">
            {cats.map((r, i) => (
              <BarRow
                key={i}
                label={<span className="truncate">{String(r.category ?? "—")}</span>}
                value={n(r.hits)}
                max={catsMax}
                tone="info"
                right={
                  <span className="text-[10px] text-muted-foreground">
                    {formatNumber(n(r.unique_attackers))} atacantes
                  </span>
                }
              />
            ))}
          </div>
        )}
      </SectionCard>

      {/* Recent feed */}
      <SectionCard
        title="Alertas recientes"
        subtitle={recent.length > 0 ? `${recent.length} en caché` : "Sin alertas"}
        right={totalPages > 1 && (
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-30"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="text-xs tabular-nums text-muted-foreground">{page} / {totalPages}</span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-30"
            >
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
                <TableHead>Sev</TableHead>
                <TableHead>Origen</TableHead>
                <TableHead>Destino</TableHead>
                <TableHead className="text-right">Puerto</TableHead>
                <TableHead>Proto</TableHead>
                <TableHead>Firma</TableHead>
                <TableHead>Acción</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paged.length === 0 && !isLoading && (
                <TableRow><TableCell colSpan={8} className="py-6 text-center text-xs text-muted-foreground">Sin alertas</TableCell></TableRow>
              )}
              {paged.map((row, i) => {
                const ts = formatDateTimePy(row.ts as string | undefined);
                const sv = n(row.severity);
                return (
                  <TableRow key={i}>
                    <TableCell className="whitespace-nowrap font-mono text-[11px] text-muted-foreground">{ts}</TableCell>
                    <TableCell><SeverityBadge label={SEV_LABEL[sv] ?? String(sv)} tone={sevTone(sv)} /></TableCell>
                    <TableCell className="font-mono text-xs">{String(row.src_ip ?? "—")}</TableCell>
                    <TableCell className="font-mono text-xs">{String(row.dest_ip ?? "—")}</TableCell>
                    <TableCell className="text-right font-mono">{String(row.dest_port ?? "—")}</TableCell>
                    <TableCell className="uppercase text-[11px]">{String(row.proto ?? "—")}</TableCell>
                    <TableCell className="max-w-xs truncate text-xs" title={String(row.signature ?? "")}>
                      {String(row.signature ?? "—")}
                    </TableCell>
                    <TableCell>
                      <Badge variant={String(row.action) === "blocked" ? "destructive" : "outline"} className="text-[10px]">
                        {String(row.action ?? "—")}
                      </Badge>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </SectionCard>

      <OpenCaseModal
        open={caseModal.open}
        onOpenChange={(v) => setCaseModal((s) => ({ ...s, open: v }))}
        payload={caseModal.payload}
        sourceLabel="Suricata IDS"
      />
    </div>
  );
}
