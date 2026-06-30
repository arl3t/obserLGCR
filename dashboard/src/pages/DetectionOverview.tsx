/**
 * DetectionOverview — Hub compacto del Detection Center.
 *
 * Muestra 6 tarjetas (una por canal de detección: Wazuh vivo + Wazuh Fluent +
 * Suricata + Firewall + Fortigate + PMG) con KPI principal + 2-3 métricas
 * numéricas secundarias y un CTA al detalle. Una sola llamada batch a Trino
 * (6 queries kpis_24h) reemplaza lo que antes eran ~40 queries
 * distribuidas entre las páginas de detalle abiertas en secuencia.
 */

import { useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  ShieldAlert,    // Wazuh
  Radio,          // Suricata
  Shield,         // Filterlog
  Server,         // Fortigate
  Mail,           // PMG
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { api } from "@/api/client";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

/** tab del dashboard → sensor_family del catálogo (toggle de detección). */
const TAB_TO_FAMILY: Record<SourceKey, string> = {
  wazuh: "wazuh", "wazuh-fluent": "wazuh", suricata: "suricata", firewall: "opnsense", fortigate: "fortigate", pmg: "pmg",
};

/** Estado on/off de fuentes (no-admin, read-only) para anotar las tarjetas. */
function useDisabledSources(): Set<string> {
  const { data } = useQuery({
    queryKey: ["detection-sources-status"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; sources: { family: string; enabled: boolean }[] }>(
        "/api/detection-sources",
      );
      return data.sources ?? [];
    },
    staleTime: 60 * 1000,
    retry: 1,
  });
  return new Set((data ?? []).filter((s) => !s.enabled).map((s) => s.family));
}

/** Cache 2 min + keepPrevious para transiciones sin flicker al refrescar. */
const STALE_2M = {
  staleTime:            2 * 60 * 1000,
  gcTime:               10 * 60 * 1000,
  placeholderData:      keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

type SourceKey = "wazuh" | "wazuh-fluent" | "suricata" | "firewall" | "fortigate" | "pmg";

const OVERVIEW_SPECS = [
  { key: "wazuh",        id: "lh.wazuh_alerts.kpis_24h"    },
  { key: "wazuh-fluent", id: "lh.wazuh_fluent.kpis_24h"    },
  { key: "suricata",  id: "lh.suricata.kpis_24h"        },
  { key: "firewall",  id: "lh.syslog.perimeter_kpis_24h" },
  { key: "fortigate", id: "lh.fg.kpis_24h"              },
  { key: "pmg",       id: "lh.pmg.kpis_24h"             },
] as const satisfies readonly BatchSpec[];

/** Convierte cualquier valor a número seguro. Trino devuelve strings para BIGINT. */
function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") {
    const x = Number(v);
    return Number.isNaN(x) ? 0 : x;
  }
  return 0;
}

/** Tono de la tarjeta — deriva un indicador rojo/ámbar/verde del KPI crítico. */
type Tone = "critical" | "warning" | "ok";

function toneColor(tone: Tone): string {
  return tone === "critical"
    ? "text-red-400"
    : tone === "warning"
      ? "text-amber-400"
      : "text-emerald-400";
}

function toneDotBg(tone: Tone): string {
  return tone === "critical"
    ? "bg-red-500"
    : tone === "warning"
      ? "bg-amber-500"
      : "bg-emerald-500";
}

interface Metric { label: string; value: string }
interface CardSpec {
  tab:        SourceKey;
  title:      string;
  subtitle:   string;
  icon:       React.ElementType;
  primary:    { label: string; value: string };
  metrics:    Metric[];
  tone:       Tone;
}

/** Transforma el row `kpis_24h` de cada fuente al shape común `CardSpec`. */
function buildCardSpecs(data: {
  wazuh:        Record<string, unknown> | undefined;
  wazuhFluent:  Record<string, unknown> | undefined;
  suricata:     Record<string, unknown> | undefined;
  firewall:     Record<string, unknown> | undefined;
  fortigate:    Record<string, unknown> | undefined;
  pmg:          Record<string, unknown> | undefined;
}): CardSpec[] {
  // ── Wazuh (canal vivo wazuh_alerts) ───────────────────────────────────────
  const waz = data.wazuh ?? {};
  const wazAlerts   = n(waz.alerts);
  const wazCritical = n(waz.critical);
  const wazAgents   = n(waz.active_agents);
  const wazManagers = n(waz.manager_nodes);

  // ── Wazuh Fluent (pipeline Fluent Bit → wazuh_fluent) ─────────────────────
  const wfl = data.wazuhFluent ?? {};
  const wflAlerts   = n(wfl.alerts);
  const wflCritical = n(wfl.critical);
  const wflAgents   = n(wfl.active_agents);
  const wflManagers = n(wfl.manager_nodes);

  // ── Suricata ─────────────────────────────────────────────────────────────
  const sur = data.suricata ?? {};
  const surAlerts = n(sur.total_alerts);
  const surIps    = n(sur.unique_src_ips);
  const surSigs   = n(sur.unique_signatures);

  // ── Filterlog perímetro ──────────────────────────────────────────────────
  const fl = data.firewall ?? {};
  const flBlocks  = n(fl.blocks);
  const flIps     = n(fl.unique_attacker_ips);
  const flPorts   = n(fl.unique_dest_ports);

  // ── Fortigate ────────────────────────────────────────────────────────────
  const fg = data.fortigate ?? {};
  const fgEvents  = n(fg.total_events);
  const fgBlocked = n(fg.blocked);
  const fgIps     = n(fg.unique_attacker_ips);
  const fgDevices = n(fg.unique_devices);

  // ── PMG ──────────────────────────────────────────────────────────────────
  const pmg = data.pmg ?? {};
  const pmgEvents     = n(pmg.total_events);
  const pmgBlocked    = n(pmg.blocked);
  const pmgAuthFails  = n(pmg.auth_failures);
  const pmgSenderIps  = n(pmg.unique_sender_ips);

  return [
    {
      tab:      "wazuh",
      title:    "Wazuh",
      subtitle: "HIDS/SIEM · wazuh_alerts",
      icon:     ShieldAlert,
      primary:  { label: "Alertas 24h", value: formatNumber(wazAlerts) },
      metrics: [
        { label: "Críticas (≥12)",  value: formatNumber(wazCritical) },
        { label: "Agentes activos", value: formatNumber(wazAgents) },
        { label: "Managers",        value: formatNumber(wazManagers) },
      ],
      tone: wazCritical > 0 ? "critical" : wazAlerts > 500 ? "warning" : "ok",
    },
    {
      tab:      "wazuh-fluent",
      title:    "Wazuh Fluent",
      subtitle: "HIDS · alerts.json · Fluent Bit",
      icon:     ShieldAlert,
      primary:  { label: "Alertas 24h", value: formatNumber(wflAlerts) },
      metrics: [
        { label: "Críticas (≥12)",  value: formatNumber(wflCritical) },
        { label: "Agentes activos", value: formatNumber(wflAgents) },
        { label: "Managers",        value: formatNumber(wflManagers) },
      ],
      tone: wflCritical > 0 ? "critical" : wflAlerts > 500 ? "warning" : "ok",
    },
    {
      tab:      "suricata",
      title:    "Suricata IDS",
      subtitle: "NIDS · event_type=alert",
      icon:     Radio,
      primary:  { label: "Alertas 24h", value: formatNumber(surAlerts) },
      metrics: [
        { label: "IPs atacantes", value: formatNumber(surIps) },
        { label: "Firmas únicas", value: formatNumber(surSigs) },
      ],
      tone: surAlerts > 1000 ? "critical" : surAlerts > 100 ? "warning" : "ok",
    },
    {
      tab:      "firewall",
      title:    "Firewall / Filterlog",
      subtitle: "OPNsense · pf filterlog",
      icon:     Shield,
      primary:  { label: "Bloqueos 24h", value: formatNumber(flBlocks) },
      metrics: [
        { label: "IPs atacantes", value: formatNumber(flIps) },
        { label: "Puertos dest.", value: formatNumber(flPorts) },
      ],
      tone: flIps > 500 ? "critical" : flBlocks > 1000 ? "warning" : "ok",
    },
    {
      tab:      "fortigate",
      title:    "Fortigate UTM",
      subtitle: "NGFW · deny/block/accept",
      icon:     Server,
      primary:  { label: "Eventos 24h", value: formatNumber(fgEvents) },
      metrics: [
        { label: "Bloqueados",    value: formatNumber(fgBlocked) },
        { label: "IPs atacantes", value: formatNumber(fgIps) },
        { label: "Dispositivos",  value: formatNumber(fgDevices) },
      ],
      tone: fgBlocked > 500 ? "critical" : fgBlocked > 50 ? "warning" : "ok",
    },
    {
      tab:      "pmg",
      title:    "Email / Phishing",
      subtitle: "Proxmox Mail Gateway",
      icon:     Mail,
      primary:  { label: "Eventos 24h", value: formatNumber(pmgEvents) },
      metrics: [
        { label: "Bloqueados",     value: formatNumber(pmgBlocked) },
        { label: "Fallos auth",    value: formatNumber(pmgAuthFails) },
        { label: "IPs remitentes", value: formatNumber(pmgSenderIps) },
      ],
      tone: pmgAuthFails > 10 ? "critical" : pmgBlocked > 50 ? "warning" : "ok",
    },
  ];
}

/** Una tarjeta por fuente — skeleton mientras no hay data. */
function SourceCard({
  spec,
  loading,
  onOpen,
  disabled = false,
}: {
  spec:    CardSpec;
  loading: boolean;
  onOpen:  (tab: SourceKey) => void;
  disabled?: boolean;
}) {
  const Icon = spec.icon;
  return (
    <Card
      role="link"
      tabIndex={0}
      onClick={() => onOpen(spec.tab)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpen(spec.tab); }
      }}
      className={cn(
        "group relative flex cursor-pointer flex-col border-border/80 bg-card/60",
        "transition-colors hover:border-primary/40 hover:bg-card/80",
        spec.tone === "critical" && "border-destructive/40",
      )}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="rounded-lg bg-muted p-2 text-foreground/80">
              <Icon className="h-4 w-4" aria-hidden />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-semibold leading-tight">{spec.title}</p>
              <p className="truncate text-[11px] text-muted-foreground">{spec.subtitle}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {disabled && (
              <Badge
                variant="outline"
                className="shrink-0 border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-600"
                title="Fuente deshabilitada en Ajustes — no genera casos (los logs siguen ingresando al lake)"
              >
                no genera casos
              </Badge>
            )}
            <span
              aria-label={`Estado ${spec.tone}`}
              className={cn("mt-1 h-2 w-2 shrink-0 rounded-full", toneDotBg(spec.tone))}
            />
          </div>
        </div>
      </CardHeader>

      <CardContent className="flex flex-col gap-3 pt-0">
        {/* KPI principal */}
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            {spec.primary.label}
          </p>
          {loading ? (
            <Skeleton className="mt-1 h-8 w-24" />
          ) : (
            <p className={cn(
              "mt-1 text-3xl font-bold tabular-nums tracking-tight",
              toneColor(spec.tone),
            )}>
              {spec.primary.value}
            </p>
          )}
        </div>

        {/* Métricas secundarias */}
        <div className="grid grid-cols-3 gap-2 border-t border-border/60 pt-3">
          {spec.metrics.map((m) => (
            <div key={m.label} className="min-w-0">
              <p className="truncate text-[10px] uppercase tracking-wide text-muted-foreground">
                {m.label}
              </p>
              {loading ? (
                <Skeleton className="mt-1 h-5 w-12" />
              ) : (
                <p className="mt-0.5 text-base font-semibold tabular-nums">{m.value}</p>
              )}
            </div>
          ))}
        </div>

        {/* CTA */}
        <div className="flex items-center justify-end pt-1 text-xs text-muted-foreground group-hover:text-primary">
          Ver detalle
          <ArrowRight className="ml-1 h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden />
        </div>
      </CardContent>
    </Card>
  );
}

/** Página "Resumen" del Detection Center — tab inicial. */
export function DetectionOverviewPage() {
  const [, setParams] = useSearchParams();

  const { results, isLoading, isFetching, refetch } = useTrinoNamedBatch<SourceKey>(
    ["detection", "overview"],
    OVERVIEW_SPECS,
    STALE_2M,
  );

  const rowOf = (k: SourceKey): Record<string, unknown> | undefined => {
    const rows = results[k].data as Record<string, unknown>[] | undefined;
    return rows?.[0];
  };

  const specs = buildCardSpecs({
    wazuh:       rowOf("wazuh"),
    wazuhFluent: rowOf("wazuh-fluent"),
    suricata:    rowOf("suricata"),
    firewall:    rowOf("firewall"),
    fortigate:   rowOf("fortigate"),
    pmg:         rowOf("pmg"),
  });

  const disabledFamilies = useDisabledSources();
  const isDisabled = (tab: SourceKey) => disabledFamilies.has(TAB_TO_FAMILY[tab]);

  const openTab = (tab: SourceKey) => setParams({ tab }, { replace: false });

  // Errores agregados — mostramos 1 banner sumarizado si falla cualquiera.
  // Las fuentes deshabilitadas no cuentan: su query "falla" por estar off, no
  // por un problema real del backend.
  const errors = (Object.keys(results) as SourceKey[])
    .map((k) => ({ key: k, err: results[k].error }))
    .filter((e) => e.err && !isDisabled(e.key));

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Resumen de detecciones</h1>
          <p className="mt-0.5 max-w-2xl text-sm text-muted-foreground">
            Ventana 24h · clic en una tarjeta para abrir el detalle de la fuente.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="cyber" className="shrink-0">6 fuentes · 1 batch</Badge>
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
        </div>
      </header>

      {errors.length > 0 && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive">
          {errors.length} fuente{errors.length > 1 ? "s" : ""} con error — reintenta o revisa los
          logs del backend. ({errors.map((e) => e.key).join(", ")})
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {specs.map((spec) => (
          <SourceCard key={spec.tab} spec={spec} loading={isLoading} onOpen={openTab} disabled={isDisabled(spec.tab)} />
        ))}
      </div>
    </div>
  );
}
