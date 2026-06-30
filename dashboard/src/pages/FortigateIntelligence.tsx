/**
 * FortigateIntelligence — Detalle NGFW/UTM Fortigate.
 *
 * Fuente: minio.hunting.fortigate (syslog key=value, VRL-normalizado por Vector).
 * Antes: 10 queries + 4 Recharts (AreaChart stacked + PieChart + BarChart vertical).
 * Ahora: 1 batch + MiniSparkline + BarRow + pills.
 */
import { useMemo, useState } from "react";
import { keepPreviousData } from "@tanstack/react-query";
import {
  Activity, CheckCircle2, FolderOpen, Globe, Layers, RefreshCw,
  Server, Shield, ShieldOff, Wifi,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { formatNumber, formatDateTimePy } from "@/lib/format";
import { OpenCaseModal, type OpenCasePayload } from "@/components/case-management/OpenCaseModal";
import type { Severity } from "@/components/case-management/types";
import {
  BarRow, DetailHeader, EmptyState, KpiTile, LoadingRows, MiniSparkline, SectionCard,
  SeverityBadge, type Tone,
} from "./detection/_components";
import { cn } from "@/lib/utils";

const STALE_10M = {
  staleTime:            10 * 60_000,
  gcTime:               30 * 60_000,
  placeholderData:      keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

type K = "kpis" | "ips" | "ports" | "srcPorts" | "action" | "type" | "hourly" | "device" | "recent";

const SPECS = [
  { key: "kpis",     id: "lh.fg.kpis_24h_mat" },
  { key: "ips",      id: "lh.fg.top_blocked_ips_24h_mat", params: { limit: 20 } },
  { key: "ports",    id: "lh.fg.top_dest_ports_24h_mat", params: { limit: 12 } },
  { key: "srcPorts", id: "lh.fg.top_src_ports_24h_mat",  params: { limit: 10 } },
  { key: "action",   id: "lh.fg.by_action_24h_mat" },
  { key: "type",     id: "lh.fg.by_type_24h_mat" },
  { key: "hourly",   id: "lh.fg.events_by_hour_24h_mat" },
  { key: "device",   id: "lh.fg.by_device_24h_mat" },
  { key: "recent",   id: "lh.fg.recent_events_mat",     params: { limit: 50 } },
] as const satisfies readonly BatchSpec[];

const BLOCK_ACTIONS = new Set([
  "deny", "block", "drop", "reset-drop", "reset-server", "reset-client",
]);
const ALLOW_ACTIONS = new Set(["accept", "passthrough", "close"]);

function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") { const x = Number(v); return Number.isNaN(x) ? 0 : x; }
  return 0;
}

function fmtTs(ts: string): string {
  if (!ts) return "—";
  return formatDateTimePy(ts);
}

function fmtType(lf: string): string {
  return lf.replace(/^fortigate_/, "").replace(/_/g, " / ");
}

function actionTone(a: string): Tone {
  const k = a.toLowerCase();
  if (BLOCK_ACTIONS.has(k)) return "critical";
  if (ALLOW_ACTIONS.has(k)) return "ok";
  return "muted";
}

export function FortigateIntelligencePage() {
  const { results, isLoading, isFetching, refetch } =
    useTrinoNamedBatch<K>(["fg", "detail"], SPECS, STALE_10M);

  const kpi      = (results.kpis.data     as Record<string, unknown>[] | undefined)?.[0] ?? {};
  const ips      = (results.ips.data      as Record<string, unknown>[] | undefined) ?? [];
  const ports    = (results.ports.data    as Record<string, unknown>[] | undefined) ?? [];
  const srcPorts = (results.srcPorts.data as Record<string, unknown>[] | undefined) ?? [];
  const action   = (results.action.data   as Record<string, unknown>[] | undefined) ?? [];
  const type     = (results.type.data     as Record<string, unknown>[] | undefined) ?? [];
  const hourly   = (results.hourly.data   as Record<string, unknown>[] | undefined) ?? [];
  const device   = (results.device.data   as Record<string, unknown>[] | undefined) ?? [];
  const recent   = (results.recent.data   as Record<string, unknown>[] | undefined) ?? [];

  const totalEvents = n(kpi.total_events);
  const blocked     = n(kpi.blocked);
  const allowed     = n(kpi.allowed);
  const attackerIps = n(kpi.unique_attacker_ips);
  const destPorts   = n(kpi.unique_dest_ports);
  const devices     = n(kpi.unique_devices);

  const spark = useMemo(
    () => hourly.map((r) => ({
      value: n(r.blocked),
      label: String(r.hour ?? "").slice(11, 16),
    })),
    [hourly],
  );

  const typeMax   = Math.max(1, ...type.map((r) => n(r.total)));
  const actionMax = Math.max(1, ...action.map((r) => n(r.total)));
  const noData = !isLoading && totalEvents === 0;
  const hasErr = Object.values(results).some((r) => r.error);

  // Open case modal (preservado)
  const [caseModal, setCaseModal] = useState<{ open: boolean; payload: OpenCasePayload }>({
    open: false,
    payload: { iocValue: "", iocType: "ip", sourceLog: "fortigate", severity: "HIGH", score: 0 },
  });
  function openCaseFor(row: Record<string, unknown>) {
    const hits       = n(row.hits);
    const portsHit   = n(row.ports_targeted);
    const act        = String(row.top_action ?? row.action ?? "deny").toLowerCase();
    const base       = BLOCK_ACTIONS.has(act) ? 15 : 13;
    const score      = Math.round(base + Math.min(8, Math.log2(hits + 1) * 1.3) + Math.min(3, portsHit * 0.5));
    const severity: Severity = hits >= 1000 ? "CRITICAL" : hits >= 100 ? "HIGH" : "MEDIUM";
    setCaseModal({
      open: true,
      payload: { iocValue: String(row.src_ip ?? ""), iocType: "ip", sourceLog: "fortigate", severity, score },
    });
  }

  return (
    <div className="flex flex-col gap-5 p-6">
      <DetailHeader
        icon={Server}
        title="Fortigate UTM"
        subtitle="NGFW · deny/block/accept · últimas 24 h"
        right={
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="hidden font-mono text-[10px] sm:inline-flex">
              minio.hunting.fortigate
            </Badge>
            <Button
              variant="outline" size="sm" className="h-7 gap-1 text-[11px]"
              onClick={() => void refetch()} disabled={isFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
              {isFetching ? "Actualizando…" : "Refrescar"}
            </Button>
          </div>
        }
      />

      {hasErr && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive">
          Algunas secciones fallaron — reintenta o revisa el proxy Trino.
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <KpiTile label="Eventos"        value={totalEvents} icon={Activity}     tone="info"     loading={isLoading} />
        <KpiTile label="Bloqueados"     value={blocked}     icon={ShieldOff}    tone="critical" loading={isLoading}
          sub={totalEvents ? `${Math.round((blocked / totalEvents) * 100)}%` : undefined} />
        <KpiTile label="Permitidos"     value={allowed}     icon={CheckCircle2} tone="ok"       loading={isLoading} />
        <KpiTile label="IPs atacantes"  value={attackerIps} icon={Globe}        tone="warning"  loading={isLoading} />
        <KpiTile label="Puertos dest."  value={destPorts}   icon={Wifi}         tone="info"     loading={isLoading} />
        <KpiTile label="Dispositivos"   value={devices}     icon={Server}       tone="muted"    loading={isLoading} />
      </div>

      {noData && (
        <SectionCard title="Sin datos" subtitle="">
          <div className="py-6 text-center">
            <Shield className="mx-auto mb-2 h-8 w-8 text-muted-foreground/40" />
            <p className="text-sm font-medium text-muted-foreground">No hay datos Fortigate en las últimas 24 h</p>
            <p className="mt-1 text-xs text-muted-foreground/60">
              Configura Fortigate → Syslog → puerto 514 UDP, formato default
            </p>
          </div>
        </SectionCard>
      )}

      {!noData && (
        <>
          {/* Timeline + acciones */}
          <div className="grid gap-4 lg:grid-cols-3">
            <SectionCard className="lg:col-span-2" title="Bloqueos por hora" subtitle="Ventana 24 h">
              {isLoading ? <LoadingRows rows={2} /> : (
                <MiniSparkline data={spark} height={56} tone="critical" />
              )}
            </SectionCard>

            <SectionCard title="Acciones" subtitle="Distribución por policy">
              {isLoading ? <LoadingRows /> : action.length === 0 ? (
                <EmptyState message="Sin datos" />
              ) : (
                <div className="flex flex-col">
                  {action.map((r, i) => {
                    const a = String(r.action ?? "—");
                    const tone = actionTone(a);
                    return (
                      <BarRow
                        key={i}
                        label={<SeverityBadge label={a} tone={tone} />}
                        value={n(r.total)}
                        max={actionMax}
                        tone={tone}
                      />
                    );
                  })}
                </div>
              )}
            </SectionCard>
          </div>

          {/* Tipos UTM + Devices */}
          <div className="grid gap-4 lg:grid-cols-2">
            <SectionCard title="Distribución por tipo UTM" subtitle="Top 8 log_family">
              {isLoading ? <LoadingRows /> : type.length === 0 ? (
                <EmptyState message="Sin datos" />
              ) : (
                <div className="flex flex-col">
                  {type.slice(0, 8).map((r, i) => (
                    <BarRow
                      key={i}
                      label={
                        <span className="inline-flex items-center gap-1.5">
                          <Layers className="h-3 w-3 text-muted-foreground" aria-hidden />
                          <span className="truncate">{fmtType(String(r.log_family ?? "—"))}</span>
                        </span>
                      }
                      value={n(r.total)}
                      max={typeMax}
                      tone={n(r.blocked) > n(r.total) / 2 ? "critical" : "info"}
                      right={n(r.blocked) > 0
                        ? <span className="text-[10px] text-red-400">{formatNumber(n(r.blocked))} bloq</span>
                        : null}
                    />
                  ))}
                </div>
              )}
            </SectionCard>

            <SectionCard title="Eventos por dispositivo" subtitle="Fortigate devname">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Dispositivo</TableHead>
                      <TableHead className="text-right">Total</TableHead>
                      <TableHead className="text-right">Bloq</TableHead>
                      <TableHead className="text-right">Perm</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {isLoading && <TableRow><TableCell colSpan={4} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                    {!isLoading && device.length === 0 && (
                      <TableRow><TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">Sin dispositivos</TableCell></TableRow>
                    )}
                    {device.map((r, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{String(r.device ?? "—")}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.total))}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-red-400">{formatNumber(n(r.blocked))}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-emerald-400">{formatNumber(n(r.allowed))}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </SectionCard>
          </div>

          {/* Top attackers */}
          <SectionCard title="Top IPs bloqueadas" subtitle="20 externas — click Caso para abrir incidente">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead className="text-right">Hits</TableHead>
                    <TableHead className="text-right">Puertos</TableHead>
                    <TableHead>Proto</TableHead>
                    <TableHead>Tipo</TableHead>
                    <TableHead>Último visto</TableHead>
                    <TableHead className="w-20 text-center">Caso</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading && <TableRow><TableCell colSpan={7} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                  {!isLoading && ips.length === 0 && (
                    <TableRow><TableCell colSpan={7} className="py-6 text-center text-xs text-muted-foreground">Sin bloqueos en 24 h</TableCell></TableRow>
                  )}
                  {ips.map((r, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">{String(r.src_ip ?? "—")}</TableCell>
                      <TableCell className="text-right font-mono text-xs font-semibold tabular-nums text-destructive">{formatNumber(n(r.hits))}</TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.ports_targeted))}</TableCell>
                      <TableCell className="font-mono text-[11px] uppercase text-muted-foreground">{String(r.top_proto ?? "—")}</TableCell>
                      <TableCell className="max-w-[140px] truncate text-[11px] text-muted-foreground">{fmtType(String(r.top_type ?? "—"))}</TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">{fmtTs(String(r.last_seen ?? ""))}</TableCell>
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

          {/* Top dest + src ports */}
          <div className="grid gap-4 lg:grid-cols-2">
            <SectionCard title="Puertos destino" subtitle="Top 12 atacados">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Puerto</TableHead>
                      <TableHead>Proto</TableHead>
                      <TableHead className="text-right">Hits</TableHead>
                      <TableHead className="text-right">IPs</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {isLoading && <TableRow><TableCell colSpan={4} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                    {!isLoading && ports.length === 0 && (
                      <TableRow><TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">Sin puertos</TableCell></TableRow>
                    )}
                    {ports.map((r, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs font-semibold">{r.dest_port != null ? String(r.dest_port) : "—"}</TableCell>
                        <TableCell className="font-mono text-[11px] uppercase text-muted-foreground">{String(r.proto ?? "—")}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-destructive">{formatNumber(n(r.hits))}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.unique_src_ips))}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </SectionCard>

            <SectionCard title="Puertos origen" subtitle="Top 10 src_port">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Puerto</TableHead>
                      <TableHead>Proto</TableHead>
                      <TableHead className="text-right">Hits</TableHead>
                      <TableHead className="text-right">IPs</TableHead>
                      <TableHead className="text-right">Bloq</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {isLoading && <TableRow><TableCell colSpan={5} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                    {!isLoading && srcPorts.length === 0 && (
                      <TableRow><TableCell colSpan={5} className="py-6 text-center text-xs text-muted-foreground">Sin datos</TableCell></TableRow>
                    )}
                    {srcPorts.map((r, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs font-semibold">{r.src_port != null ? String(r.src_port) : "—"}</TableCell>
                        <TableCell className="font-mono text-[11px] uppercase text-muted-foreground">{String(r.proto ?? "—")}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.hits))}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.unique_src_ips))}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-destructive">{formatNumber(n(r.blocked))}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </SectionCard>
          </div>

          {/* Recent feed */}
          <SectionCard title="Feed reciente" subtitle={recent.length > 0 ? `${recent.length} eventos en caché` : "Sin eventos"}>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Hora</TableHead>
                    <TableHead>Origen</TableHead>
                    <TableHead>Destino</TableHead>
                    <TableHead>Puerto</TableHead>
                    <TableHead>Proto</TableHead>
                    <TableHead>Acción</TableHead>
                    <TableHead>Tipo</TableHead>
                    <TableHead>Dispositivo</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading && <TableRow><TableCell colSpan={8} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                  {!isLoading && recent.length === 0 && (
                    <TableRow><TableCell colSpan={8} className="py-6 text-center text-xs text-muted-foreground">Sin eventos</TableCell></TableRow>
                  )}
                  {recent.map((r, i) => {
                    const act = String(r.action ?? "—");
                    return (
                      <TableRow key={i}>
                        <TableCell className="whitespace-nowrap font-mono text-[11px] text-muted-foreground">{fmtTs(String(r.ts ?? ""))}</TableCell>
                        <TableCell className="font-mono text-xs">{String(r.src_ip ?? "—")}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{String(r.dest_ip ?? "—")}</TableCell>
                        <TableCell className="font-mono text-xs">{r.dest_port != null ? String(r.dest_port) : "—"}</TableCell>
                        <TableCell className="font-mono text-[11px] uppercase text-muted-foreground">{String(r.proto ?? "—")}</TableCell>
                        <TableCell><SeverityBadge label={act} tone={actionTone(act)} /></TableCell>
                        <TableCell className="max-w-[140px] truncate text-[11px] text-muted-foreground">{fmtType(String(r.log_family ?? "—"))}</TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">{String(r.device ?? "—")}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </SectionCard>

        </>
      )}

      <OpenCaseModal
        open={caseModal.open}
        onOpenChange={(v) => setCaseModal((s) => ({ ...s, open: v }))}
        payload={caseModal.payload}
        sourceLabel="Fortigate UTM"
      />
    </div>
  );
}
