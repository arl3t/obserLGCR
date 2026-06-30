/**
 * OutliersDetection — Panel del Detection Center para el feature Outliers v1.
 *
 * Consume las named queries `lh.outliers.*` vía el endpoint `/api/trino/batch`
 * y expone:
 *   · KPIs que siguen la ventana y filtros activos (summary_window, no el
 *     summary_24h fijo — así los tiles cuadran siempre con la tabla).
 *   · Tabla filtrable (ventana, entity_type, severity, log_family) + filtros
 *     client-side (búsqueda por entity_value + toggle "sólo sin ack").
 *   · Breakdown por anomaly_type (barras relativas, sin Recharts extra).
 *   · Acknowledge por fila (POST /api/outliers/:id/acknowledge) y bulk por
 *     entidad (POST /api/outliers/acknowledge-entity), con badge ×N cuando
 *     hay múltiples detecciones visibles de la misma (entity_type,
 *     entity_value).
 *   · Fila expandible con baseline vs observed, isolation_score y details
 *     JSON del DAG parseados.
 *   · Badge de truncamiento cuando la lista llega al LIST_LIMIT.
 *   · Export CSV client-side de la ventana activa (respeta filtros UI).
 *   · Socket listener: `outlier:new_critical` / `outlier:acknowledged` invalida cache.
 *
 * Diseño: docs/OUTLIER-DETECTION.md §6.2.
 */

import { keepPreviousData, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Download,
  Filter,
  RefreshCw,
  Search,
  Shield,
  Sparkles,
  Users,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
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
import { socket } from "@/lib/socket";
import { cn } from "@/lib/utils";

const STALE_2M = {
  staleTime: 2 * 60 * 1000,
  gcTime: 10 * 60 * 1000,
  placeholderData: keepPreviousData,
  refetchOnWindowFocus: false,
} as const;

const WINDOWS = [
  { id: "1h",  label: "1h",  hours: 1  },
  { id: "6h",  label: "6h",  hours: 6  },
  { id: "24h", label: "24h", hours: 24 },
  { id: "7d",  label: "7d",  hours: 168 },
] as const;
type WindowId = typeof WINDOWS[number]["id"];

// El DAG v1 (outlier_detection_6h.py) sólo emite entity_type='ip'. Los demás
// tipos (host, port, hour, country, …) están reservados en el schema Iceberg
// para detectores futuros — los exponemos acá sólo cuando el DAG los produzca
// para no ofrecer filtros que siempre devuelven 0 filas.
const ENTITY_TYPES = ["all", "ip"] as const;
type EntityFilter = typeof ENTITY_TYPES[number];

const SEVERITIES = ["all", "critical", "high", "medium", "low"] as const;
type SeverityFilter = typeof SEVERITIES[number];

const LOG_FAMILIES = ["all", "syslog", "wazuh", "filterlog", "fortigate", "suricata", "pmg", "multi"] as const;
type LogFamilyFilter = typeof LOG_FAMILIES[number];

function n(v: unknown): number {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  if (typeof v === "string") {
    const x = Number(v);
    return Number.isNaN(x) ? 0 : x;
  }
  return 0;
}

function s(v: unknown): string {
  return v == null ? "" : String(v);
}

function sevClass(sev: string): string {
  const l = sev.toLowerCase();
  if (l === "critical") return "border-red-500/50 bg-red-500/10 text-red-400";
  if (l === "high")     return "border-orange-500/50 bg-orange-500/10 text-orange-400";
  if (l === "medium")   return "border-yellow-500/50 bg-yellow-500/10 text-yellow-400";
  if (l === "low")      return "border-emerald-500/50 bg-emerald-500/10 text-emerald-400";
  return "border-border bg-muted/30 text-muted-foreground";
}

function formatDetectionTime(raw: unknown): string {
  const str = s(raw);
  if (!str) return "—";
  // Trino devuelve "2026-04-22 15:00:00.000 UTC" — lo mostramos en hora PY.
  return formatDateTimePy(str);
}

type OutlierRow = {
  outlier_id: string;
  detection_time: string;
  entity_type: string;
  entity_value: string;
  score: number;
  z_score: number | null;
  isolation_score: number | null;
  anomaly_type: string;
  severity: string;
  log_family: string;
  observed_value: number | null;
  baseline_value: number | null;
  window_hours: number | null;
  baseline_window_days: number | null;
  details: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
};

function toRow(r: Record<string, unknown>): OutlierRow {
  return {
    outlier_id: s(r.outlier_id),
    detection_time: s(r.detection_time),
    entity_type: s(r.entity_type),
    entity_value: s(r.entity_value),
    score: n(r.score),
    z_score: r.z_score == null ? null : n(r.z_score),
    isolation_score: r.isolation_score == null ? null : n(r.isolation_score),
    anomaly_type: s(r.anomaly_type),
    severity: s(r.severity).toLowerCase(),
    log_family: s(r.log_family),
    observed_value: r.observed_value == null ? null : n(r.observed_value),
    baseline_value: r.baseline_value == null ? null : n(r.baseline_value),
    window_hours: r.window_hours == null ? null : n(r.window_hours),
    baseline_window_days: r.baseline_window_days == null ? null : n(r.baseline_window_days),
    details: s(r.details),
    acknowledged_at: r.acknowledged_at ? s(r.acknowledged_at) : null,
    acknowledged_by: r.acknowledged_by ? s(r.acknowledged_by) : null,
  };
}

function downloadCsv(rows: OutlierRow[], windowLabel: string): string | null {
  if (!rows.length) return "No hay outliers para exportar en la ventana seleccionada.";
  const header = [
    "outlier_id", "detection_time", "entity_type", "entity_value",
    "severity", "anomaly_type", "score", "z_score", "isolation_score",
    "log_family", "observed_value", "baseline_value",
    "acknowledged_at", "acknowledged_by",
  ];
  const lines = [header.join(",")];
  for (const r of rows) {
    lines.push([
      r.outlier_id,
      r.detection_time,
      r.entity_type,
      // Las IPs pueden contener ":" (IPv6) pero no comas; aun así envolvemos
      // entity_value por precaución contra rare chars futuros.
      `"${r.entity_value.replace(/"/g, '""')}"`,
      r.severity,
      r.anomaly_type,
      r.score,
      r.z_score ?? "",
      r.isolation_score ?? "",
      r.log_family,
      r.observed_value ?? "",
      r.baseline_value ?? "",
      r.acknowledged_at ?? "",
      r.acknowledged_by ?? "",
    ].join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `outliers_${windowLabel}_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  return null;
}

const LIST_LIMIT = 200;

export function OutliersDetectionPage() {
  const [windowId, setWindowId]       = useState<WindowId>("24h");
  const [entityType, setEntityType]   = useState<EntityFilter>("all");
  const [severity, setSeverity]       = useState<SeverityFilter>("all");
  const [logFamily, setLogFamily]     = useState<LogFamilyFilter>("all");
  const [search, setSearch]           = useState<string>("");
  const [onlyUnack, setOnlyUnack]     = useState<boolean>(false);
  const [expandedId, setExpandedId]   = useState<string | null>(null);
  const [ackingId, setAckingId]       = useState<string | null>(null);
  // Tracking separado para ack bulk por entidad — el botón "Ack ×N" muestra
  // loading distinto al ack individual porque afecta N filas a la vez.
  const [ackingEntityKey, setAckingEntityKey] = useState<string | null>(null);
  // Banner efímero para ack/export/socket (el proyecto no tiene lib de toast).
  const [flash, setFlash] = useState<{ kind: "ok" | "warn" | "err"; msg: string } | null>(null);
  useEffect(() => {
    if (!flash) return;
    const t = setTimeout(() => setFlash(null), 5000);
    return () => clearTimeout(t);
  }, [flash]);

  const hours = useMemo(
    () => WINDOWS.find((w) => w.id === windowId)?.hours ?? 24,
    [windowId],
  );

  // Una sola petición batch: summary + by_family + list.
  // Tanto `list` como `summary` reciben los mismos filtros para que los KPIs
  // reflejen exactamente la ventana/subconjunto que el operador está viendo
  // en la tabla (antes `summary` era fijo 24h → números descuadrados al
  // cambiar ventana o filtros).
  const specs = useMemo<BatchSpec[]>(() => {
    const scopedParams: Record<string, unknown> = { hours };
    if (entityType !== "all") scopedParams.entity_type = entityType;
    if (severity !== "all")   scopedParams.severity    = severity;
    if (logFamily !== "all")  scopedParams.log_family  = logFamily;
    return [
      { key: "list",    id: "lh.outliers.last_window",    params: { ...scopedParams, limit: LIST_LIMIT } },
      { key: "summary", id: "lh.outliers.summary_window", params: scopedParams },
      { key: "family",  id: "lh.outliers.by_log_family",  params: { days: 7 } },
    ];
  }, [hours, entityType, severity, logFamily]);

  const { results, isLoading, isFetching, refetch } = useTrinoNamedBatch<"list" | "summary" | "family">(
    ["outliers", windowId, entityType, severity, logFamily],
    specs,
    STALE_2M,
  );

  const list     = useMemo(() => (results.list.data ?? []).map(toRow),    [results.list.data]);
  const summary  = results.summary.data?.[0] ?? {};
  const byFamily = results.family.data ?? [];
  const truncated = list.length >= LIST_LIMIT;

  // Filtros client-side: búsqueda libre por entity_value + toggle "sólo sin ack".
  // Se aplican sobre el resultado server-side ya filtrado por ventana/tipo/sev/family.
  const displayList = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q && !onlyUnack) return list;
    return list.filter((r) => {
      if (onlyUnack && r.acknowledged_at) return false;
      if (q && !r.entity_value.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [list, search, onlyUnack]);

  // Conteo de detecciones sin-ack por (entity_type|entity_value) sobre displayList.
  // Usado por el botón "Ack ×N" de ack bulk por entidad: si N>1, ofrecemos ackear
  // todas las filas visibles de la misma entidad de una sola vez.
  const unackByEntity = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of displayList) {
      if (r.acknowledged_at) continue;
      const k = `${r.entity_type}|${r.entity_value}`;
      map.set(k, (map.get(k) ?? 0) + 1);
    }
    return map;
  }, [displayList]);

  // Breakdown por anomaly_type para la tarjeta "Detecciones por tipo"
  const byAnomalyType = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of byFamily) {
      const t = s(r.anomaly_type) || "—";
      map.set(t, (map.get(t) ?? 0) + n(r.detections));
    }
    const arr = [...map.entries()].sort((a, b) => b[1] - a[1]);
    const max = arr[0]?.[1] ?? 1;
    return arr.map(([type, count]) => ({ type, count, pct: Math.round((count / max) * 100) }));
  }, [byFamily]);

  // Invalida cache cuando el DAG inserta críticos o alguien ack-ea: el hook
  // useTrinoNamedBatch cachea por queryKey, así que un refetch() fuerza la
  // nueva foto sin recargar la página.
  const qc = useQueryClient();
  useEffect(() => {
    if (!socket.connected) socket.connect();
    const onNewCritical = (payload: { entity_type?: string; entity_value?: string; score?: number }) => {
      setFlash({
        kind: "warn",
        msg: `Nuevo outlier CRITICAL: ${payload?.entity_type ?? "?"} ${payload?.entity_value ?? ""} (score ${payload?.score ?? "?"})`,
      });
      void qc.invalidateQueries({ queryKey: ["outliers"] });
    };
    const onAck = () => {
      void qc.invalidateQueries({ queryKey: ["outliers"] });
    };
    socket.on("outlier:new_critical", onNewCritical);
    socket.on("outlier:acknowledged", onAck);
    return () => {
      socket.off("outlier:new_critical", onNewCritical);
      socket.off("outlier:acknowledged", onAck);
    };
  }, [qc]);

  const handleAck = useCallback(async (outlierId: string) => {
    setAckingId(outlierId);
    try {
      await api.post(`/api/outliers/${encodeURIComponent(outlierId)}/acknowledge`, { notes: null });
      setFlash({ kind: "ok", msg: "Outlier reconocido" });
      await refetch();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "No se pudo reconocer";
      setFlash({ kind: "err", msg });
    } finally {
      setAckingId(null);
    }
  }, [refetch]);

  // Ack bulk por entidad: resuelve todas las detecciones sin-ack de una misma
  // (entity_type, entity_value) dentro de la ventana actual. Quita el ruido de
  // tener que ackear fila por fila cuando el DAG (6h) genera ~4 detecciones/día
  // para una IP persistentemente anómala.
  const handleAckEntity = useCallback(async (entType: string, entValue: string) => {
    const key = `${entType}|${entValue}`;
    setAckingEntityKey(key);
    try {
      const resp = await api.post("/api/outliers/acknowledge-entity", {
        entity_type: entType,
        entity_value: entValue,
        hours,
        notes: null,
      });
      const acked = typeof resp?.data?.acknowledged === "number" ? resp.data.acknowledged : null;
      setFlash({
        kind: "ok",
        msg: acked == null
          ? `Detecciones de ${entValue} reconocidas`
          : `${acked} detección(es) de ${entValue} reconocida(s)`,
      });
      await refetch();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "No se pudo reconocer la entidad";
      setFlash({ kind: "err", msg });
    } finally {
      setAckingEntityKey(null);
    }
  }, [hours, refetch]);

  const windowLabel = WINDOWS.find((w) => w.id === windowId)?.label ?? windowId;

  const handleExportCsv = useCallback(() => {
    // Exportamos lo que el operador está viendo (filtros client-side incluidos),
    // no la lista cruda: sorprende menos y sirve para armar reportes recortados.
    const warn = downloadCsv(displayList, windowLabel);
    if (warn) setFlash({ kind: "warn", msg: warn });
  }, [displayList, windowLabel]);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-4 p-4">
      {/* ── Header ──────────────────────────────────────────────────── */}
      <header className="flex flex-wrap items-center gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-bold tracking-tight">
            <Sparkles className="h-5 w-5 text-primary" aria-hidden />
            Outliers detectados
          </h2>
          <p className="text-xs text-muted-foreground">
            Anomalías unsupervised (Z-Score + Isolation Forest)
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1 text-[11px]"
            onClick={handleExportCsv}
            disabled={isLoading || list.length === 0}
          >
            <Download className="h-3.5 w-3.5" aria-hidden />
            Export CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1 text-[11px]"
            onClick={() => void refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} aria-hidden />
            {isFetching ? "Actualizando…" : "Refrescar"}
          </Button>
        </div>
      </header>

      {/* ── Flash banner (ack / socket / export) ────────────────────── */}
      {flash && (
        <div
          role="status"
          className={cn(
            "rounded-md border px-3 py-2 text-xs",
            flash.kind === "ok"   && "border-emerald-500/40 bg-emerald-500/5 text-emerald-300",
            flash.kind === "warn" && "border-amber-500/40 bg-amber-500/5 text-amber-300",
            flash.kind === "err"  && "border-destructive/50 bg-destructive/5 text-destructive",
          )}
        >
          {flash.msg}
        </div>
      )}

      {/* ── KPIs ─────────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <KpiTile label={`Total ${windowLabel}`} value={formatNumber(n(summary.total))}
                 loading={isLoading} icon={<Shield className="h-3.5 w-3.5" />} />
        <KpiTile label="Critical"  value={formatNumber(n(summary.critical))}
                 loading={isLoading} critical={n(summary.critical) > 0} />
        <KpiTile label="High"      value={formatNumber(n(summary.high))}
                 loading={isLoading} warn={n(summary.high) > 0} />
        <KpiTile label="Sin ack"   value={formatNumber(n(summary.unack_count))}
                 loading={isLoading} warn={n(summary.unack_count) > 0}
                 sub={`${formatNumber(n(summary.unique_entities))} entidades únicas`} />
        <KpiTile label="Max score" value={n(summary.max_score).toFixed(1)}
                 loading={isLoading}
                 sub={`avg ${n(summary.avg_score).toFixed(1)}`} />
      </section>

      {/* ── Filtros ──────────────────────────────────────────────────── */}
      <section className="flex flex-col gap-2 rounded-lg border border-border/60 bg-muted/20 px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          <FilterGroup
            label="Ventana"
            value={windowId}
            options={WINDOWS.map((w) => ({ id: w.id, label: w.label }))}
            onChange={(v) => setWindowId(v as WindowId)}
          />
          <FilterGroup
            label="Tipo"
            value={entityType}
            options={ENTITY_TYPES.map((e) => ({ id: e, label: e === "all" ? "Todos" : e }))}
            onChange={(v) => setEntityType(v as EntityFilter)}
          />
          <FilterGroup
            label="Severidad"
            value={severity}
            options={SEVERITIES.map((e) => ({ id: e, label: e === "all" ? "Todas" : e }))}
            onChange={(v) => setSeverity(v as SeverityFilter)}
          />
          <FilterGroup
            label="Log family"
            value={logFamily}
            options={LOG_FAMILIES.map((e) => ({ id: e, label: e === "all" ? "Todas" : e }))}
            onChange={(v) => setLogFamily(v as LogFamilyFilter)}
          />
        </div>
        {/* Segunda fila: filtros client-side (búsqueda + toggle unack) */}
        <div className="flex flex-wrap items-center gap-2 border-t border-border/40 pt-2">
          <div className="relative flex-1 min-w-[220px] max-w-sm">
            <Search
              className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              type="search"
              placeholder="Buscar entidad (IP, host…)"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 pl-7 text-xs"
              aria-label="Buscar por entidad"
            />
          </div>
          <button
            type="button"
            onClick={() => setOnlyUnack((v) => !v)}
            aria-pressed={onlyUnack}
            className={cn(
              "rounded-md border px-2 py-1 text-[11px] transition-colors",
              onlyUnack
                ? "border-amber-500/50 bg-amber-500/10 text-amber-300"
                : "border-border/60 text-muted-foreground hover:bg-muted/60 hover:text-foreground",
            )}
          >
            {onlyUnack ? "✓ Sólo sin ack" : "Sólo sin ack"}
          </button>
          {(search || onlyUnack) && (
            <span className="text-[10px] text-muted-foreground">
              {formatNumber(displayList.length)} de {formatNumber(list.length)} visibles
            </span>
          )}
        </div>
      </section>

      {/* ── Grid: tabla + breakdown ──────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Tabla ocupa 2 cols */}
        <Card className="border-border/80 lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-chart-2" aria-hidden />
              Detecciones · ventana {windowLabel}
              {displayList.length > 0 && (
                <Badge variant="outline" className="ml-2 text-[10px]">
                  {formatNumber(displayList.length)} filas
                </Badge>
              )}
              {truncated && (
                <Badge
                  variant="outline"
                  className="ml-1 border-amber-500/50 bg-amber-500/10 text-[10px] text-amber-300"
                  title={`Mostrando las primeras ${LIST_LIMIT} filas. Afiná los filtros para ver el resto.`}
                >
                  top {LIST_LIMIT} · afina filtros
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col" className="w-6 pl-4" aria-label="Expandir" />
                  <TableHead scope="col">Detectado</TableHead>
                  <TableHead scope="col">Entidad</TableHead>
                  <TableHead scope="col">Severidad</TableHead>
                  <TableHead scope="col">Tipo anomalía</TableHead>
                  <TableHead scope="col" className="text-right">Score</TableHead>
                  <TableHead scope="col" className="text-right">Z</TableHead>
                  <TableHead scope="col">Log</TableHead>
                  <TableHead scope="col" className="pr-4 w-28 text-right">Acción</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={9} className="pl-4 text-sm text-muted-foreground">
                      Consultando Trino…
                    </TableCell>
                  </TableRow>
                ) : results.list.error ? (
                  <TableRow>
                    <TableCell colSpan={9} className="pl-4 text-sm text-destructive">
                      {results.list.error}
                    </TableCell>
                  </TableRow>
                ) : displayList.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="pl-4 text-sm text-muted-foreground">
                      {list.length === 0
                        ? "Sin outliers en la ventana seleccionada."
                        : "Ninguna fila cumple los filtros client-side (búsqueda / sólo-sin-ack)."}
                    </TableCell>
                  </TableRow>
                ) : (
                  displayList.map((r) => {
                    const expanded = expandedId === r.outlier_id;
                    const entityKey = `${r.entity_type}|${r.entity_value}`;
                    const unackCount = unackByEntity.get(entityKey) ?? 0;
                    const rowId = `outlier-row-${r.outlier_id}`;
                    return (
                      <OutlierRowPair
                        key={r.outlier_id}
                        row={r}
                        rowId={rowId}
                        expanded={expanded}
                        onToggleExpand={() =>
                          setExpandedId((cur) => (cur === r.outlier_id ? null : r.outlier_id))
                        }
                        unackCount={unackCount}
                        ackingId={ackingId}
                        ackingEntityKey={ackingEntityKey}
                        onAck={() => void handleAck(r.outlier_id)}
                        onAckEntity={() => void handleAckEntity(r.entity_type, r.entity_value)}
                      />
                    );
                  })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Breakdown por anomaly_type */}
        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Por tipo de anomalía (7d)</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              Detecciones agregadas de los últimos 7 días.
            </p>
          </CardHeader>
          <CardContent className="space-y-2">
            {isLoading ? (
              [...Array(4)].map((_, i) => <Skeleton key={i} className="h-5 w-full" />)
            ) : byAnomalyType.length === 0 ? (
              <p className="text-sm text-muted-foreground">Sin datos.</p>
            ) : (
              byAnomalyType.map((r) => (
                <div key={r.type} className="flex items-center gap-2">
                  <span className="w-32 shrink-0 truncate font-mono text-xs">{r.type}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted/40">
                    <div
                      className="h-full rounded-full bg-chart-2 transition-all"
                      style={{ width: `${r.pct}%` }}
                    />
                  </div>
                  <span className="w-10 text-right text-[11px] tabular-nums text-muted-foreground">
                    {formatNumber(r.count)}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Componentes internos ────────────────────────────────────────────

function KpiTile({
  label, value, sub, loading, critical, warn, icon,
}: {
  label: string;
  value: string;
  sub?: string;
  loading: boolean;
  critical?: boolean;
  warn?: boolean;
  icon?: React.ReactNode;
}) {
  return (
    <div className={cn(
      "rounded-xl border px-4 py-3",
      critical ? "border-destructive/50 bg-destructive/5"
        : warn  ? "border-amber-500/40 bg-amber-500/5"
                : "border-border/80 bg-card/60",
    )}>
      <p className="flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {icon}
        {label}
      </p>
      {loading ? (
        <Skeleton className="mt-1 h-8 w-20" />
      ) : (
        <p className={cn(
          "mt-1 text-2xl font-bold tabular-nums tracking-tight",
          critical && "text-destructive",
          warn && !critical && "text-amber-400",
        )}>
          {value}
        </p>
      )}
      {sub && <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>}
    </div>
  );
}

/**
 * Fila de outlier + fila expandida con detalles técnicos.
 *
 * La sub-fila sólo se monta cuando `expanded=true` para no serializar el JSON
 * de `details` en todas las 200 filas (algunas detecciones IsolationForest
 * tienen objects anidados).
 */
function OutlierRowPair({
  row, rowId, expanded, onToggleExpand,
  unackCount, ackingId, ackingEntityKey,
  onAck, onAckEntity,
}: {
  row: OutlierRow;
  rowId: string;
  expanded: boolean;
  onToggleExpand: () => void;
  unackCount: number;
  ackingId: string | null;
  ackingEntityKey: string | null;
  onAck: () => void;
  onAckEntity: () => void;
}) {
  const entityKey = `${row.entity_type}|${row.entity_value}`;
  const isAcking = ackingId === row.outlier_id;
  const isAckingEntity = ackingEntityKey === entityKey;
  // Mostramos "Ack ×N" sólo si en la tabla visible hay >1 sin ack de esta misma
  // entidad. Con 1, el botón normal de ack individual basta.
  const showBulk = !row.acknowledged_at && unackCount > 1;

  return (
    <>
      <TableRow className="border-b border-border/60 last:border-0">
        <TableCell className="pl-4 w-6">
          <button
            type="button"
            onClick={onToggleExpand}
            aria-expanded={expanded}
            aria-controls={`${rowId}-details`}
            className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground"
            title={expanded ? "Ocultar detalles" : "Ver detalles"}
          >
            {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>
        </TableCell>
        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
          {formatDetectionTime(row.detection_time)}
        </TableCell>
        <TableCell>
          <div className="flex flex-col">
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
              {row.entity_type}
              {unackCount > 1 && (
                <span
                  className="ml-1 rounded bg-amber-500/15 px-1 py-px font-mono text-amber-300"
                  title={`${unackCount} detecciones sin ack para esta entidad en la vista actual`}
                >
                  ×{unackCount}
                </span>
              )}
            </span>
            <span className="font-mono text-xs">{row.entity_value}</span>
          </div>
        </TableCell>
        <TableCell>
          <span className={cn(
            "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
            sevClass(row.severity),
          )}>
            {row.severity}
          </span>
        </TableCell>
        <TableCell>
          <span className="text-xs font-mono">{row.anomaly_type}</span>
        </TableCell>
        <TableCell className="text-right tabular-nums text-sm font-semibold">
          {row.score.toFixed(1)}
        </TableCell>
        <TableCell className="text-right tabular-nums text-xs text-muted-foreground">
          {row.z_score == null ? "—" : row.z_score.toFixed(2)}
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          {row.log_family}
        </TableCell>
        <TableCell className="pr-4 text-right">
          {row.acknowledged_at ? (
            <span
              className="inline-flex items-center gap-1 text-[10px] text-emerald-400"
              title={`ack por ${row.acknowledged_by ?? "?"} el ${row.acknowledged_at}`}
            >
              <Check className="h-3 w-3" />
              ack
            </span>
          ) : showBulk ? (
            <div className="flex items-center justify-end gap-1">
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-[10px]"
                disabled={isAcking || isAckingEntity}
                onClick={onAck}
                title="Ack sólo esta detección"
              >
                {isAcking ? "…" : "Ack"}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-7 gap-1 px-2 text-[10px]"
                disabled={isAcking || isAckingEntity}
                onClick={onAckEntity}
                title={`Ack todas las ${unackCount} detecciones sin ack de ${row.entity_value} en la ventana`}
              >
                <Users className="h-3 w-3" aria-hidden />
                {isAckingEntity ? "…" : `×${unackCount}`}
              </Button>
            </div>
          ) : (
            <Button
              size="sm"
              variant="ghost"
              className="h-7 gap-1 px-2 text-[10px]"
              disabled={isAcking}
              onClick={onAck}
            >
              {isAcking ? "…" : "Ack"}
            </Button>
          )}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow
          id={`${rowId}-details`}
          className="border-b border-border/60 bg-muted/20 last:border-0"
        >
          <TableCell className="pl-4" />
          <TableCell colSpan={8} className="py-2 pr-4">
            <OutlierDetails row={row} />
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

/** Bloque de detalles: baseline vs observed, isolation_score, details JSON. */
function OutlierDetails({ row }: { row: OutlierRow }) {
  // `details` viene stringificado desde Trino — parseamos defensivamente.
  const parsed = useMemo(() => {
    if (!row.details) return null;
    try {
      const j = JSON.parse(row.details);
      return (j && typeof j === "object") ? (j as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  }, [row.details]);

  const ratio =
    row.baseline_value != null && row.baseline_value > 0 && row.observed_value != null
      ? row.observed_value / row.baseline_value
      : null;

  return (
    <div className="grid gap-3 text-xs md:grid-cols-2">
      <dl className="space-y-1">
        <DetailRow label="outlier_id" value={<span className="font-mono">{row.outlier_id}</span>} />
        <DetailRow
          label="Observado vs baseline"
          value={
            row.observed_value == null && row.baseline_value == null
              ? "—"
              : (
                <span className="font-mono">
                  {row.observed_value == null ? "—" : formatNumber(row.observed_value)}
                  {" / "}
                  {row.baseline_value == null ? "—" : formatNumber(row.baseline_value)}
                  {ratio != null && (
                    <span className="ml-1 text-muted-foreground">
                      (×{ratio.toFixed(2)})
                    </span>
                  )}
                </span>
              )
          }
        />
        <DetailRow
          label="Score / Z / Iso"
          value={
            <span className="font-mono">
              {row.score.toFixed(2)}
              {" · "}
              {row.z_score == null ? "—" : row.z_score.toFixed(2)}
              {" · "}
              {row.isolation_score == null ? "—" : row.isolation_score.toFixed(3)}
            </span>
          }
        />
        <DetailRow
          label="Ventana / baseline"
          value={
            <span className="font-mono">
              {row.window_hours == null ? "—" : `${row.window_hours}h`}
              {" / "}
              {row.baseline_window_days == null ? "—" : `${row.baseline_window_days}d`}
            </span>
          }
        />
      </dl>
      <div>
        <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
          details
        </p>
        {parsed ? (
          <dl className="space-y-0.5">
            {Object.entries(parsed).map(([k, v]) => (
              <DetailRow
                key={k}
                label={k}
                value={
                  <span className="font-mono">
                    {typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}
                  </span>
                }
              />
            ))}
          </dl>
        ) : row.details ? (
          <pre className="overflow-x-auto rounded bg-muted/30 p-2 font-mono text-[11px] text-muted-foreground">
            {row.details}
          </pre>
        ) : (
          <p className="text-muted-foreground">sin details</p>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-2">
      <dt className="w-40 shrink-0 text-[10px] uppercase tracking-wide text-muted-foreground">
        {label}
      </dt>
      <dd className="flex-1 text-xs">{value}</dd>
    </div>
  );
}

function FilterGroup<T extends string>({
  label, value, options, onChange,
}: {
  label: string;
  value: T;
  options: readonly { id: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}:
      </span>
      {options.map((opt) => (
        <button
          key={opt.id}
          onClick={() => onChange(opt.id)}
          className={cn(
            "rounded-md px-2 py-0.5 text-[11px] transition-colors",
            value === opt.id
              ? "bg-primary/15 text-primary font-medium"
              : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}
