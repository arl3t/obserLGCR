/**
 * WazuhFluentIntelligence — Detalle HIDS vía Fluent Bit.
 *
 * Fuente: minio.hunting.wazuh_fluent (ingest_source='alerts.json').
 * Pipeline: Wazuh Manager → Fluent Bit → Vector :24224 → S3 wazuh_fluent/
 *
 * Antes: 8 queries + 3 Recharts (AreaChart, PieChart, BarChart).
 * Ahora: 1 batch + MiniSparkline + pills de severidad + BarRow.
 */
import { useMemo } from "react";
import { keepPreviousData } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, Archive, Database, Globe, RefreshCw, Server,
  Swords, Terminal, Wifi,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { formatNumber } from "@/lib/format";
import {
  BarRow, DetailHeader, EmptyState, KpiTile, LoadingRows, MiniSparkline, SectionCard,
  SeverityBadge, type Tone,
} from "./detection/_components";
import { cn } from "@/lib/utils";

const STALE_3M = {
  staleTime:            3 * 60_000,
  gcTime:               10 * 60_000,
  placeholderData:      keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

type K = "kpis" | "sev" | "rules" | "agents" | "byHour" | "mgr" | "mitre" | "srcIps";

const SPECS = [
  { key: "kpis",   id: "lh.wazuh_fluent.kpis_24h"               },
  { key: "sev",    id: "lh.wazuh_fluent.severity_buckets_24h"   },
  { key: "rules",  id: "lh.wazuh_fluent.top_rules_24h",             params: { limit: 12 } },
  { key: "agents", id: "lh.wazuh_fluent.top_agents_24h",            params: { limit: 10 } },
  { key: "byHour", id: "lh.wazuh_fluent.alerts_by_hour_today"       },
  { key: "mgr",    id: "lh.wazuh_fluent.manager_nodes_24h"          },
  { key: "mitre",  id: "lh.wazuh_fluent.top_mitre_tactics_24h",     params: { limit: 10 } },
  { key: "srcIps", id: "lh.wazuh_fluent.top_src_ips_24h",           params: { limit: 12 } },
] as const satisfies readonly BatchSpec[];

function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") { const x = Number(v); return Number.isNaN(x) ? 0 : x; }
  return 0;
}

function levelTone(level: number): Tone {
  return level >= 15 ? "critical" : level >= 12 ? "warning" : level >= 9 ? "info" : "muted";
}

function severityTone(key: string): Tone {
  const k = key.toLowerCase();
  if (k === "critical") return "critical";
  if (k === "high")     return "warning";
  if (k === "medium")   return "info";
  return "muted";
}

export function WazuhFluentIntelligencePage() {
  const { results, isLoading, isFetching, refetch } =
    useTrinoNamedBatch<K>(["wazuh-fluent", "detail"], SPECS, STALE_3M);

  const kpi    = (results.kpis.data   as Record<string, unknown>[] | undefined)?.[0] ?? {};
  const sev    = (results.sev.data    as Record<string, unknown>[] | undefined) ?? [];
  const rules  = (results.rules.data  as Record<string, unknown>[] | undefined) ?? [];
  const agents = (results.agents.data as Record<string, unknown>[] | undefined) ?? [];
  const hourly = (results.byHour.data as Record<string, unknown>[] | undefined) ?? [];
  const mgr    = (results.mgr.data    as Record<string, unknown>[] | undefined) ?? [];
  const mitre  = (results.mitre.data  as Record<string, unknown>[] | undefined) ?? [];
  const srcIps = (results.srcIps.data as Record<string, unknown>[] | undefined) ?? [];

  const alerts   = n(kpi.alerts);
  const archives = n(kpi.archives);
  const critical = n(kpi.critical);
  const activeAgents   = n(kpi.active_agents);
  const managerNodes   = n(kpi.manager_nodes);

  const spark = useMemo(
    () => hourly.map((r) => ({
      value: n(r.alerts),
      label: String(r.hr ?? "").slice(11, 16) || String(r.hr ?? ""),
    })),
    [hourly],
  );

  const mitreMax = Math.max(1, ...mitre.map((r) => n(r.c)));
  const hasErr   = Object.values(results).some((r) => r.error);

  return (
    <div className="flex flex-col gap-5 p-6">
      <DetailHeader
        icon={Wifi}
        title="Wazuh Fluent Bit"
        subtitle="HIDS · alerts.json · Fluent Forward :24224 → Vector → S3"
        right={
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="hidden text-[10px] sm:inline-flex">Fluent Bit</Badge>
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
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <KpiTile label="Alertas"       value={alerts}       icon={Activity}       tone="info"     loading={isLoading} />
        <KpiTile label="Archives"      value={archives}     icon={Archive}        tone="muted"    loading={isLoading} />
        <KpiTile label="Críticas (≥12)" value={critical}    icon={AlertTriangle}  tone="critical" loading={isLoading} />
        <KpiTile label="Agentes"       value={activeAgents} icon={Terminal}       tone="ok"       loading={isLoading} />
        <KpiTile label="Managers"      value={managerNodes} icon={Server}         tone="info"     loading={isLoading} />
      </div>

      {/* Timeline + severity pills */}
      <div className="grid gap-4 lg:grid-cols-3">
        <SectionCard className="lg:col-span-2" title="Flujo por hora (hoy)" subtitle="Alertas observadas">
          {isLoading ? <LoadingRows rows={2} /> : spark.length === 0 ? (
            <EmptyState message="Sin datos para hoy todavía" />
          ) : (
            <MiniSparkline data={spark} height={56} tone="info" />
          )}
        </SectionCard>

        <SectionCard title="Severidad" subtitle="Distribución de nivel de regla">
          {isLoading ? <LoadingRows rows={4} /> : sev.length === 0 ? (
            <EmptyState message="Sin datos" />
          ) : (
            <div className="flex flex-col gap-1.5">
              {sev.map((r, i) => {
                const key = String(r.severity ?? "");
                return (
                  <div key={i} className="flex items-center justify-between gap-2">
                    <SeverityBadge label={key || "—"} tone={severityTone(key)} />
                    <span className="text-sm font-semibold tabular-nums">{formatNumber(n(r.c))}</span>
                  </div>
                );
              })}
            </div>
          )}
        </SectionCard>
      </div>

      {/* Rules + Agents */}
      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Top reglas" subtitle="Más disparadas — alerts.json">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule ID</TableHead>
                  <TableHead>Nivel</TableHead>
                  <TableHead className="text-right">Alertas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={3} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && rules.length === 0 && (
                  <TableRow><TableCell colSpan={3} className="py-6 text-center text-xs text-muted-foreground">Sin datos</TableCell></TableRow>
                )}
                {rules.map((r, i) => {
                  const lvl = n(r.max_level);
                  return (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">{String(r.rule_id ?? "—")}</TableCell>
                      <TableCell><SeverityBadge label={String(lvl)} tone={levelTone(lvl)} /></TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.c))}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </SectionCard>

        <SectionCard title="Agentes más activos" subtitle="Hosts con más alertas">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agente</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Manager</TableHead>
                  <TableHead className="text-right">Alertas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={4} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && agents.length === 0 && (
                  <TableRow><TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">Sin datos</TableCell></TableRow>
                )}
                {agents.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs">{String(r.agent_name ?? "—")}</TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">{String(r.agent_ip ?? "—")}</TableCell>
                    <TableCell className="max-w-[140px] truncate text-[11px] text-muted-foreground">{String(r.manager_host ?? "—")}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.c))}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>
      </div>

      {/* MITRE + Top IPs externas */}
      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Tácticas MITRE ATT&CK" subtitle="Top 10 — ventana 24 h">
          {isLoading ? <LoadingRows /> : mitre.length === 0 ? (
            <EmptyState message="Sin tácticas MITRE en el periodo" />
          ) : (
            <div className="flex flex-col">
              {mitre.map((r, i) => (
                <BarRow
                  key={i}
                  label={
                    <span className="inline-flex items-center gap-1.5">
                      <Swords className="h-3 w-3 text-rose-400" aria-hidden />
                      <span className="truncate">{String(r.tactic ?? "—")}</span>
                    </span>
                  }
                  value={n(r.c)}
                  max={mitreMax}
                  tone="critical"
                />
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="IPs atacantes externas" subtitle="Top 12 — 24 h">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Agentes</TableHead>
                  <TableHead>Nivel máx</TableHead>
                  <TableHead className="text-right">Hits</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && <TableRow><TableCell colSpan={4} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
                {!isLoading && srcIps.length === 0 && (
                  <TableRow><TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">Sin IPs externas</TableCell></TableRow>
                )}
                {srcIps.map((r, i) => {
                  const lvl = n(r.max_level);
                  return (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">
                        <span className="inline-flex items-center gap-1.5">
                          <Globe className="h-3 w-3 text-orange-400" aria-hidden />
                          {String(r.src_ip ?? "—")}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatNumber(n(r.agents_affected))}</TableCell>
                      <TableCell><SeverityBadge label={String(lvl)} tone={levelTone(lvl)} /></TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{formatNumber(n(r.hits))}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </SectionCard>
      </div>

      {/* Manager nodes */}
      {mgr.length > 0 && (
        <SectionCard title="Managers activos" subtitle="Nodos Wazuh reportando en 24 h">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {mgr.map((r, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded-lg border border-border/80 bg-muted/30 px-3 py-2"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Database className="h-3 w-3 shrink-0 text-emerald-500" aria-hidden />
                  <span className="truncate font-mono text-xs">{String(r.manager_host ?? "—")}</span>
                </div>
                <div className="flex shrink-0 items-center gap-3 text-[11px] text-muted-foreground">
                  <span>{formatNumber(n(r.alerts))} alts</span>
                  <span>{formatNumber(n(r.agents))} agentes</span>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      )}

      {/* Nota pipeline */}
      <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-xs text-blue-700 dark:text-blue-400">
        <strong>Pipeline separado activo:</strong>{" "}
        Los eventos de <code className="rounded bg-blue-500/10 px-1">archives.json</code>{" "}
        se enrutan a <code className="rounded bg-blue-500/10 px-1">wazuh_fluent_archives/</code>{" "}
        (tabla de forensia). Esta pestaña muestra sólo{" "}
        <code className="rounded bg-blue-500/10 px-1">alerts.json</code>.
      </div>
    </div>
  );
}
