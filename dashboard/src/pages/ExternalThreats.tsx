/**
 * ExternalThreats — Detalle Firewall/Filterlog (OPNsense/pfSense).
 *
 * Fuente: minio.hunting.syslog con appname='filterlog'.
 * Antes: 6 queries + 2 Recharts (AreaChart + BarChart vertical).
 * Ahora: 1 batch de 7 queries (agrega perimeter_kpis_24h) + MiniSparkline + BarRow.
 */
import { useEffect, useMemo, useState } from "react";
import { keepPreviousData } from "@tanstack/react-query";
import { sortBy, take } from "lodash";
import {
  AlertTriangle, Crosshair, Globe2, LogIn, LogOut, RefreshCw, Shield, Wifi,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { useGeoIpBatch } from "@/hooks/useGeoIpBatch";
import { formatNumber } from "@/lib/format";
import { perimeterReputationFromHits } from "@/lib/reputation";
import { useInvestigationStore } from "@/store/investigation-store";
import {
  BarRow, DetailHeader, EmptyState, KpiTile, LoadingRows, MiniSparkline, SectionCard,
} from "./detection/_components";
import { cn } from "@/lib/utils";

const STALE_5M = {
  staleTime:            5 * 60_000,
  gcTime:               15 * 60_000,
  placeholderData:      keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

type K = "kpis" | "top" | "hourly" | "ports" | "vpnEvt" | "vpnFail" | "vpnCount";

const SPECS = [
  { key: "kpis",     id: "lh.syslog.perimeter_kpis_24h_mat" },
  { key: "top",      id: "lh.syslog.top_blocked_ips_with_sensor_mat", params: { limit: 15, hours: 24 } },
  { key: "hourly",   id: "lh.syslog.blocks_by_hour_24h_mat" },
  { key: "ports",    id: "lh.syslog.top_attacked_ports_mat",       params: { limit: 12, hours: 24 } },
  { key: "vpnEvt",   id: "lh.syslog.vpn_connections_mat",         params: { limit: 30, hours: 24 } },
  { key: "vpnFail",  id: "lh.syslog.vpn_failed_auth_24h_mat",     params: { limit: 10 } },
  { key: "vpnCount", id: "lh.syslog.vpn_events_24h_mat" },
] as const satisfies readonly BatchSpec[];

type VpnEvent      = { ts: string; service: string; source_ip: string; message: string; event_type: "connect" | "disconnect" | "failed" | "info" };
type VpnFailedRow  = { ts: string; service: string; source_ip: string; message: string };

function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") { const x = Number(v); return Number.isNaN(x) ? 0 : x; }
  return 0;
}

/** Carga el mapeo sensor_ip → nombre amigable desde el servidor. */
function useSensorLabels(): Record<string, string> {
  const [labels, setLabels] = useState<Record<string, string>>({});
  useEffect(() => {
    fetch("/api/sensors/labels")
      .then((r) => r.json())
      .then((d) => { if (d?.ok && d.labels) setLabels(d.labels); })
      .catch(() => {});
  }, []);
  return labels;
}

function sensorName(sensorIps: string, labels: Record<string, string>): string {
  if (!sensorIps) return "—";
  return sensorIps.split(",").map((ip) => labels[ip.trim()] ?? ip.trim()).filter(Boolean).join(", ");
}

function vpnEventIcon(type: VpnEvent["event_type"]) {
  if (type === "connect")    return <LogIn  className="h-3.5 w-3.5 text-emerald-500" aria-hidden />;
  if (type === "disconnect") return <LogOut className="h-3.5 w-3.5 text-yellow-500"  aria-hidden />;
  if (type === "failed")     return <AlertTriangle className="h-3.5 w-3.5 text-destructive" aria-hidden />;
  return null;
}

function vpnEventBadge(type: VpnEvent["event_type"]) {
  const variants = {
    connect:    { variant: "default"     as const, label: "Conectado"    },
    disconnect: { variant: "secondary"   as const, label: "Desconectado" },
    failed:     { variant: "destructive" as const, label: "Fallido"      },
    info:       { variant: "outline"     as const, label: "Info"         },
  };
  const { variant, label } = variants[type] ?? variants.info;
  return <Badge variant={variant} className="text-[10px]">{label}</Badge>;
}

export function ExternalThreatsPage() {
  const openIp       = useInvestigationStore((s) => s.openIp);
  const sensorLabels = useSensorLabels();

  const { results, isLoading, isFetching, refetch } =
    useTrinoNamedBatch<K>(["ext", "detail"], SPECS, STALE_5M);

  const kpi      = (results.kpis.data     as Record<string, unknown>[] | undefined)?.[0] ?? {};
  const topRows  = (results.top.data      as Record<string, unknown>[] | undefined) ?? [];
  const hourly   = (results.hourly.data   as Record<string, unknown>[] | undefined) ?? [];
  const ports    = (results.ports.data    as Record<string, unknown>[] | undefined) ?? [];
  const vpnEvtRaw = (results.vpnEvt.data  as VpnEvent[] | undefined) ?? [];
  const vpnFail  = (results.vpnFail.data  as VpnFailedRow[] | undefined) ?? [];
  const vpnCount = n((results.vpnCount.data as Record<string, unknown>[] | undefined)?.[0]?.c);

  const blocks         = n(kpi.blocks);
  const attackerIps    = n(kpi.unique_attacker_ips);
  const destPorts      = n(kpi.unique_dest_ports);
  const allowed        = n(kpi.allowed);

  // VPN: connects + último disconnect por IP (filtro existente preservado).
  const vpnEvents = useMemo<VpnEvent[]>(() => {
    const connects = vpnEvtRaw.filter((r) => r.event_type === "connect");
    const lastDisc = new Map<string, VpnEvent>();
    for (const r of vpnEvtRaw) {
      if (r.event_type === "disconnect") {
        const prev = lastDisc.get(r.source_ip);
        if (!prev || r.ts > prev.ts) lastDisc.set(r.source_ip, r);
      }
    }
    return [...connects, ...Array.from(lastDisc.values())].sort((a, b) => b.ts.localeCompare(a.ts));
  }, [vpnEvtRaw]);

  // Geo-rollup sobre top IPs (enriquecimiento async externo).
  const ips = useMemo(
    () => topRows.map((r) => String(r.src_ip ?? "")).filter(Boolean),
    [topRows],
  );
  const { byIp, pending: geoPending } = useGeoIpBatch(ips);

  const geoRollup = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const ip of ips) {
      const g = byIp[ip];
      const cc = g?.countryCode ?? (g?.source === "private" ? "LAN" : "?");
      counts[cc] = (counts[cc] ?? 0) + 1;
    }
    return take(
      sortBy(
        Object.entries(counts).map(([country, c]) => ({ country, c })),
        (x) => -x.c,
      ),
      12,
    );
  }, [byIp, ips]);

  const spark = useMemo(
    () => hourly.map((r) => ({
      value: n(r.blocks),
      label: String(r.hour ?? "").slice(11, 16),
    })),
    [hourly],
  );

  const portsMax = Math.max(1, ...ports.map((r) => n(r.hits)));
  const hasErr   = Object.values(results).some((r) => r.error);

  return (
    <div className="flex flex-col gap-5 p-6">
      <DetailHeader
        icon={Shield}
        title="Firewall / Filterlog"
        subtitle="OPNsense · pf filterlog · bloqueos perimetrales (24 h)"
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

      {hasErr && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive">
          Algunas secciones fallaron — reintenta o revisa el proxy Trino.
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiTile label="Bloqueos"       value={blocks}      tone="critical" loading={isLoading} />
        <KpiTile label="IPs atacantes"  value={attackerIps} tone="warning"  loading={isLoading} />
        <KpiTile label="Puertos dest."  value={destPorts}   tone="info"     loading={isLoading} />
        <KpiTile label="Permitidos"     value={allowed}     tone="ok"       loading={isLoading} />
      </div>

      {/* Timeline + ports */}
      <div className="grid gap-4 lg:grid-cols-3">
        <SectionCard className="lg:col-span-2" title="Bloqueos por hora" subtitle="Agregado horario — ventana 24 h">
          {isLoading ? <LoadingRows rows={2} /> : (
            <MiniSparkline data={spark} height={56} tone="critical" />
          )}
        </SectionCard>
        <SectionCard title="Puertos atacados" subtitle="Top 12 destino">
          {isLoading ? <LoadingRows /> : ports.length === 0 ? (
            <EmptyState message="Sin puertos atacados" />
          ) : (
            <div className="flex flex-col">
              {ports.map((r, i) => (
                <BarRow
                  key={i}
                  label={<span className="font-mono">{String(r.dst_port ?? "?")}</span>}
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
      <SectionCard
        title="Top IPs atacantes"
        subtitle="País (GeoIP) · reputación heurística · sensor OPNsense · click Investigar"
      >
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">#</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>País</TableHead>
                <TableHead>Reputación</TableHead>
                <TableHead>Sensor / Iface</TableHead>
                <TableHead className="text-right">Hits</TableHead>
                <TableHead className="w-[100px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && <TableRow><TableCell colSpan={7} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
              {!isLoading && topRows.length === 0 && (
                <TableRow><TableCell colSpan={7} className="py-6 text-center text-xs text-muted-foreground">Sin bloqueos en 24 h</TableCell></TableRow>
              )}
              {topRows.map((row, i) => {
                const ip        = String(row.src_ip ?? "");
                const hits      = n(row.hits);
                const sensorIps = String(row.sensor_ips ?? "");
                const ifaces    = String(row.ifaces     ?? "");
                const geo       = byIp[ip];
                const rep       = perimeterReputationFromHits(hits);
                const sensor    = sensorName(sensorIps, sensorLabels);
                return (
                  <TableRow key={ip}>
                    <TableCell className="text-muted-foreground">{i + 1}</TableCell>
                    <TableCell className="font-mono text-xs">{ip}</TableCell>
                    <TableCell className="text-xs">
                      {geoPending && !geo
                        ? <span className="text-muted-foreground">…</span>
                        : (geo?.countryName ?? geo?.countryCode ?? "—")}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={rep.tone === "bad" ? "destructive" : rep.tone === "warn" ? "secondary" : "outline"}
                        className="text-[10px]"
                      >
                        {rep.label}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-xs">{sensor}</span>
                        {ifaces && ifaces !== "—" && (
                          <span className="font-mono text-[10px] text-muted-foreground">{ifaces}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-semibold tabular-nums text-destructive">
                      {formatNumber(hits)}
                    </TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" className="h-6 gap-1 px-2 text-[11px]" onClick={() => openIp(ip)}>
                        <Crosshair className="h-3 w-3" /> Investigar
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </SectionCard>

      {/* Geo rollup */}
      <SectionCard
        title="Distribución geográfica"
        subtitle="Países del top actual (no es tráfico total)"
      >
        <div className="flex items-center gap-2 flex-wrap">
          <Globe2 className="h-4 w-4 text-muted-foreground" aria-hidden />
          {geoRollup.length === 0
            ? <span className="text-xs text-muted-foreground">Sin datos aún.</span>
            : geoRollup.map(({ country, c }) => (
                <Badge key={country} variant="outline" className="tabular-nums text-[10px]">
                  {country}: {c}
                </Badge>
              ))}
        </div>
      </SectionCard>

      {/* VPN */}
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Actividad VPN</h2>
        <Badge variant="outline" className="gap-1 text-[10px]">
          <Wifi className="h-3 w-3" />
          {isLoading ? "…" : formatNumber(vpnCount)} eventos (24h)
        </Badge>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard
          title="Conexiones VPN activas"
          subtitle="OpenVPN · IPsec · WireGuard — connects + último disconnect por IP"
        >
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tipo</TableHead>
                  <TableHead>Servicio</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Mensaje</TableHead>
                  <TableHead className="text-right">Hora</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={5} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && vpnEvents.length === 0 && (
                  <TableRow><TableCell colSpan={5} className="py-6 text-center text-xs text-muted-foreground">Sin eventos VPN</TableCell></TableRow>
                )}
                {vpnEvents.map((row, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        {vpnEventIcon(row.event_type)}
                        {vpnEventBadge(row.event_type)}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{row.service || "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{row.source_ip || "—"}</TableCell>
                    <TableCell className="max-w-[240px] truncate text-xs text-muted-foreground">
                      {row.message}
                    </TableCell>
                    <TableCell className="text-right font-mono text-[11px] text-muted-foreground">
                      {String(row.ts ?? "").slice(11, 19)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>

        <SectionCard
          title="Autenticaciones fallidas VPN"
          subtitle="TLS error · auth-fail · invalid user (últimas 10)"
        >
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Servicio</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Mensaje</TableHead>
                  <TableHead className="text-right">Hora</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={4} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && vpnFail.length === 0 && (
                  <TableRow><TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">Sin fallos de autenticación</TableCell></TableRow>
                )}
                {vpnFail.map((row, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs">{row.service || "—"}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <span className="font-mono text-xs">{row.source_ip || "—"}</span>
                        {row.source_ip && (
                          <Button size="sm" variant="ghost" className="h-5 w-5 p-0" onClick={() => openIp(row.source_ip)} title="Investigar IP">
                            <Crosshair className="h-3 w-3" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[240px] truncate text-xs text-muted-foreground">
                      {row.message}
                    </TableCell>
                    <TableCell className="text-right font-mono text-[11px] text-muted-foreground">
                      {String(row.ts ?? "").slice(11, 19)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
