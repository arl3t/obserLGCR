/**
 * DetectionLogExplorer — Búsqueda, filtros y detalle de eventos ingeridos.
 */

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Filter, RefreshCw, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DetectionEventSheet } from "@/components/detection/DetectionEventSheet";
import { DetectionSeverityChip } from "@/components/detection/DetectionSeverityChip";
import { fetchDetectionEvents, fetchDetectionLogTypes, type DetectionEvent } from "@/api/detection";
import { cn } from "@/lib/utils";

const HOUR_OPTIONS = [
  { value: 1, label: "1 h" },
  { value: 6, label: "6 h" },
  { value: 24, label: "24 h" },
  { value: 72, label: "3 d" },
  { value: 168, label: "7 d" },
];

function fmtTs(ts: string) {
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "short", timeStyle: "medium" });
}

export function DetectionLogExplorerPage() {
  const [params, setParams] = useSearchParams();
  const family = params.get("family") ?? "";
  const sourceLog = params.get("source_log") ?? "";
  const severity = params.get("severity") ?? "";
  const hours = Math.min(Math.max(parseInt(params.get("hours") ?? "24", 10) || 24, 1), 168);
  const qParam = params.get("q") ?? "";

  const [page, setPage] = useState(0);
  const [searchDraft, setSearchDraft] = useState(qParam);
  const [selected, setSelected] = useState<DetectionEvent | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);
  const limit = 50;

  useEffect(() => {
    setPage(0);
  }, [family, sourceLog, severity, hours, qParam]);

  useEffect(() => {
    setSearchDraft(qParam);
  }, [qParam]);

  const { data: logTypes = [] } = useQuery({
    queryKey: ["detection", "log-types"],
    queryFn: fetchDetectionLogTypes,
    staleTime: 5 * 60_000,
  });

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["detection", "events", family, sourceLog, severity, hours, qParam, page],
    queryFn: () =>
      fetchDetectionEvents({
        hours,
        limit,
        offset: page * limit,
        family: family || undefined,
        source_log: sourceLog || undefined,
        severity: severity || undefined,
        q: qParam || undefined,
      }),
    staleTime: 30_000,
  });

  const events = data?.data ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const families = [...new Set(logTypes.map((t) => t.sensor_family))].sort();
  const sourcesForFamily = logTypes.filter((t) => !family || t.sensor_family === family);

  const applySearch = () => {
    const next = new URLSearchParams(params);
    const q = searchDraft.trim();
    if (q) next.set("q", q);
    else next.delete("q");
    setParams(next);
  };

  const setHours = (h: number) => {
    const next = new URLSearchParams(params);
    next.set("hours", String(h));
    setParams(next);
  };

  const openEvent = (ev: DetectionEvent) => {
    setSelected(ev);
    setSheetOpen(true);
  };

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Explorador de eventos</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            {total.toLocaleString("es-PY")} coincidencias · ventana {hours}h
            {family && ` · familia ${family}`}
            {sourceLog && ` · ${sourceLog}`}
            {qParam && ` · búsqueda «${qParam}»`}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1"
          onClick={() => void refetch()}
          disabled={isFetching}
        >
          <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
          Actualizar
        </Button>
      </header>

      <div className="obser-panel space-y-4 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <Filter className="mb-2 h-4 w-4 text-cyan-400" />
          <div>
            <label className="mb-1 block text-[11px] text-muted-foreground">Ventana</label>
            <div className="flex flex-wrap gap-1">
              {HOUR_OPTIONS.map((o) => (
                <button
                  key={o.value}
                  type="button"
                  onClick={() => setHours(o.value)}
                  className={cn(
                    "rounded-md border px-2 py-1 text-[12px] transition-colors",
                    hours === o.value
                      ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-300"
                      : "border-border text-muted-foreground hover:border-cyan-500/30",
                  )}
                >
                  {o.label}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="mb-1 block text-[11px] text-muted-foreground">Familia</label>
            <select
              value={family}
              onChange={(e) => {
                const v = e.target.value;
                const next = new URLSearchParams(params);
                if (v) next.set("family", v);
                else next.delete("family");
                next.delete("source_log");
                setParams(next);
              }}
              className="rounded-lg border border-border bg-background/80 px-2 py-1.5 text-[13px]"
            >
              <option value="">Todas</option>
              {families.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[11px] text-muted-foreground">source_log</label>
            <select
              value={sourceLog}
              onChange={(e) => {
                const v = e.target.value;
                const next = new URLSearchParams(params);
                if (v) next.set("source_log", v);
                else next.delete("source_log");
                setParams(next);
              }}
              className="min-w-[180px] rounded-lg border border-border bg-background/80 px-2 py-1.5 text-[13px]"
            >
              <option value="">Todos</option>
              {sourcesForFamily.map((t) => (
                <option key={t.source_log} value={t.source_log}>
                  {t.source_log}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[11px] text-muted-foreground">Severidad</label>
            <select
              value={severity}
              onChange={(e) => {
                const v = e.target.value;
                const next = new URLSearchParams(params);
                if (v) next.set("severity", v);
                else next.delete("severity");
                setParams(next);
              }}
              className="rounded-lg border border-border bg-background/80 px-2 py-1.5 text-[13px]"
            >
              <option value="">Todas</option>
              {["critical", "error", "warn", "info", "debug"].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={searchDraft}
              onChange={(e) => setSearchDraft(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && applySearch()}
              placeholder="Buscar en mensaje, IP, hostname, rule_id…"
              className="h-9 pl-8 text-[13px]"
            />
          </div>
          <Button type="button" size="sm" variant="secondary" onClick={applySearch}>
            Buscar
          </Button>
        </div>
      </div>

      <div className="obser-panel overflow-hidden">
        {isLoading ? (
          <div className="py-16 text-center text-sm text-muted-foreground">Cargando eventos…</div>
        ) : events.length === 0 ? (
          <div className="py-16 text-center text-sm text-muted-foreground">
            Sin eventos con los filtros actuales.
            {!qParam && total === 0 && (
              <p className="mt-2 text-[12px]">
                ¿Shipper configurado? Revise la pestaña Fuentes.
              </p>
            )}
          </div>
        ) : (
          <div className="max-h-[640px] divide-y divide-border overflow-y-auto">
            {events.map((ev) => (
              <button
                key={ev.id}
                type="button"
                onClick={() => openEvent(ev)}
                className={cn(
                  "detection-event-row flex w-full flex-col gap-2 px-4 py-3 text-left text-[12px] sm:flex-row sm:items-start sm:gap-4",
                  (ev.severity === "critical" || ev.severity === "error") && "detection-event-row--critical",
                )}
              >
                <span className="obser-mono shrink-0 text-muted-foreground">{fmtTs(ev.event_time)}</span>
                <span className="obser-mono w-28 shrink-0 text-cyan-400/80">{ev.source_log}</span>
                <DetectionSeverityChip severity={ev.severity} className="shrink-0" />
                {(ev.src_ip || ev.dst_ip) && (
                  <span className="obser-mono shrink-0 text-[11px] text-muted-foreground">
                    {ev.src_ip ?? "—"} → {ev.dst_ip ?? "—"}
                  </span>
                )}
                {ev.hostname && (
                  <span className="obser-mono shrink-0 text-muted-foreground">{ev.hostname}</span>
                )}
                {ev.rule_id && (
                  <span className="obser-mono shrink-0 text-[10px] text-amber-400/80">#{ev.rule_id}</span>
                )}
                <span className="min-w-0 flex-1 break-all text-foreground">{ev.message}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {total > limit && (
        <div className="flex items-center justify-between text-[12px] text-muted-foreground">
          <span>
            Página {page + 1} de {totalPages} · {total.toLocaleString("es-PY")} total
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeft className="h-4 w-4" /> Anterior
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Siguiente <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      <DetectionEventSheet event={selected} open={sheetOpen} onOpenChange={setSheetOpen} />
    </div>
  );
}
