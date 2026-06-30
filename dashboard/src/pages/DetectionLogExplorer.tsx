/**
 * DetectionLogExplorer — Explorador de eventos ingeridos por tipo de log.
 */

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Filter, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { fetchDetectionEvents, fetchDetectionLogTypes } from "@/api/detection";
import { cn } from "@/lib/utils";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-red-400",
  error: "text-red-400/90",
  warn: "text-amber-400",
  info: "text-muted-foreground",
  debug: "text-muted-foreground/70",
};

function fmtTs(ts: string) {
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "short", timeStyle: "medium" });
}

export function DetectionLogExplorerPage() {
  const [params, setParams] = useSearchParams();
  const family = params.get("family") ?? "";
  const sourceLog = params.get("source_log") ?? "";
  const severity = params.get("severity") ?? "";

  const [page, setPage] = useState(0);
  const limit = 50;

  useEffect(() => {
    setPage(0);
  }, [family, sourceLog, severity]);

  const { data: logTypes = [] } = useQuery({
    queryKey: ["detection", "log-types"],
    queryFn: fetchDetectionLogTypes,
    staleTime: 5 * 60_000,
  });

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["detection", "events", family, sourceLog, severity, page],
    queryFn: () =>
      fetchDetectionEvents({
        hours: 24,
        limit,
        offset: page * limit,
        family: family || undefined,
        source_log: sourceLog || undefined,
        severity: severity || undefined,
      }),
    staleTime: 30_000,
  });

  const events = data?.data ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const families = [...new Set(logTypes.map((t) => t.sensor_family))].sort();
  const sourcesForFamily = logTypes.filter((t) => !family || t.sensor_family === family);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Explorador de logs</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            {total} eventos en 24h
            {family && ` · familia ${family}`}
            {sourceLog && ` · ${sourceLog}`}
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

      <div className="obser-panel p-4">
        <div className="flex flex-wrap items-end gap-3">
          <Filter className="h-4 w-4 text-cyan-400" />
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
      </div>

      <div className="obser-panel overflow-hidden">
        {isLoading ? (
          <div className="py-16 text-center text-sm text-muted-foreground">Cargando eventos…</div>
        ) : events.length === 0 ? (
          <div className="py-16 text-center text-sm text-muted-foreground">
            Sin eventos con los filtros actuales.
          </div>
        ) : (
          <div className="max-h-[600px] divide-y divide-border overflow-y-auto">
            {events.map((ev) => (
              <div
                key={ev.id}
                className="flex flex-col gap-1 px-4 py-3 text-[12px] transition-colors hover:bg-cyan-500/5 sm:flex-row sm:items-start sm:gap-4"
              >
                <span className="obser-mono shrink-0 text-muted-foreground">{fmtTs(ev.event_time)}</span>
                <span className="obser-mono w-28 shrink-0 text-cyan-400/80">{ev.source_log}</span>
                <span
                  className={cn(
                    "w-16 shrink-0 font-semibold uppercase",
                    SEVERITY_CLASS[ev.severity] ?? "text-muted-foreground",
                  )}
                >
                  {ev.severity}
                </span>
                {ev.hostname && (
                  <span className="obser-mono shrink-0 text-muted-foreground">{ev.hostname}</span>
                )}
                <span className="min-w-0 flex-1 break-all text-foreground">{ev.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {total > limit && (
        <div className="flex items-center justify-between text-[12px] text-muted-foreground">
          <span>
            Página {page + 1} de {totalPages}
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
    </div>
  );
}
