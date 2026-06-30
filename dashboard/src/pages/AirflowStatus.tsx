import { useQuery } from "@tanstack/react-query";
import { RefreshCw, CheckCircle2, XCircle, PauseCircle, Clock, Minus } from "lucide-react";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

interface DagRow {
  dag_id:       string;
  is_paused:    boolean;
  is_active:    boolean;
  schedule_interval: string | null;
  last_parsed_time:  string | null;
  last_state:   string | null;
  last_exec:    string | null;
  last_start:   string | null;
  last_end:     string | null;
  duration_sec: number | null;
  run_type:     string | null;
}

interface DagsResponse {
  ok:   boolean;
  dags: DagRow[];
  ts:   string;
}

const STATE_CFG: Record<string, { label: string; cls: string; icon: typeof CheckCircle2 }> = {
  success: { label: "OK",       cls: "text-emerald-400",  icon: CheckCircle2 },
  failed:  { label: "FALLÓ",    cls: "text-red-400",      icon: XCircle      },
  running: { label: "Corriendo",cls: "text-blue-400",     icon: RefreshCw    },
  queued:  { label: "En cola",  cls: "text-amber-400",    icon: Clock        },
};

function fmtDuration(sec: number | null): string {
  if (sec === null) return "—";
  if (sec < 60)    return `${sec}s`;
  if (sec < 3600)  return `${Math.round(sec / 60)}m`;
  return `${(sec / 3600).toFixed(1)}h`;
}

function fmtAgo(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)    return "ahora";
  if (m < 60)   return `hace ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24)   return `hace ${h}h`;
  return `hace ${Math.floor(h / 24)}d`;
}

function dagGroup(id: string): string {
  if (id.startsWith("filterlog"))     return "Firewall / Syslog";
  if (id.startsWith("fortigate"))     return "FortiGate";
  if (id.startsWith("wazuh"))         return "Wazuh SIEM";
  if (id.startsWith("suricata"))      return "Suricata IDS";
  if (id.startsWith("pmg"))           return "PMG Email";
  if (id.startsWith("iceberg"))       return "Iceberg / Lake";
  if (id.startsWith("mv_"))           return "Vistas materializadas";
  if (id.startsWith("incident"))      return "Incidents / Cases";
  if (id.startsWith("infragovpy"))    return "InfraGOVPY";
  if (id.startsWith("s3"))            return "S3 → MinIO sync";
  if (id.startsWith("telegram"))      return "Inteligencia";
  if (id.startsWith("threat"))        return "Inteligencia";
  if (id.startsWith("outlier"))       return "Análisis";
  if (id.startsWith("syslog"))        return "Iceberg / Lake";
  if (id.startsWith("vicarius"))      return "Inteligencia";
  return "Otros";
}

function StateIcon({ state, paused }: { state: string | null; paused: boolean }) {
  if (paused) return <PauseCircle className="h-4 w-4 text-zinc-500" />;
  if (!state) return <Minus className="h-4 w-4 text-muted-foreground/40" />;
  const cfg = STATE_CFG[state];
  if (!cfg) return <Minus className="h-4 w-4 text-muted-foreground/40" />;
  const Icon = cfg.icon;
  return <Icon className={cn("h-4 w-4", cfg.cls, state === "running" && "animate-spin")} />;
}

export function AirflowStatusPage() {
  const { data, isLoading, dataUpdatedAt, refetch, isFetching } = useQuery<DagsResponse>({
    queryKey: ["airflow-dags"],
    queryFn: async () => {
      const { data } = await api.get<DagsResponse>("/api/airflow/dags");
      return data;
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const dags = data?.dags ?? [];

  // Agrupar
  const groups: Record<string, DagRow[]> = {};
  for (const d of dags) {
    const g = dagGroup(d.dag_id);
    (groups[g] ??= []).push(d);
  }

  // Contadores globales
  const total     = dags.length;
  const active    = dags.filter((d) => !d.is_paused).length;
  const paused    = dags.filter((d) => d.is_paused).length;
  const failed    = dags.filter((d) => d.last_state === "failed").length;
  const ok        = dags.filter((d) => d.last_state === "success").length;
  const neverRan  = dags.filter((d) => !d.last_exec).length;

  const lastSync = dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString("es-PY") : "—";

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">Estado de DAGs — Airflow</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {total} pipelines · última actualización {lastSync}
          </p>
        </div>
        <Button size="sm" variant="outline" className="h-8 gap-1.5 text-xs"
          onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
          Actualizar
        </Button>
      </div>

      {/* KPI counters */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {[
          { label: "Total",        value: total,    cls: "text-foreground" },
          { label: "Activos",      value: active,   cls: "text-emerald-400" },
          { label: "Pausados",     value: paused,   cls: "text-zinc-400" },
          { label: "Con fallo",    value: failed,   cls: failed > 0 ? "text-red-400" : "text-muted-foreground" },
          { label: "Sin historial",value: neverRan, cls: "text-muted-foreground" },
        ].map(({ label, value, cls }) => (
          <div key={label} className="rounded-xl border border-border/50 bg-card/80 p-4">
            <div className={cn("text-2xl font-bold tabular-nums", cls)}>{isLoading ? "—" : value}</div>
            <div className="mt-0.5 text-[11px] text-muted-foreground">{label}</div>
          </div>
        ))}
      </div>

      {/* Tabla agrupada */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
        </div>
      ) : (
        <div className="space-y-6">
          {Object.entries(groups).sort(([a], [b]) => a.localeCompare(b)).map(([group, rows]) => {
            const groupFailed = rows.filter((r) => r.last_state === "failed").length;
            return (
              <div key={group} className="rounded-xl border border-border/50 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2.5 bg-muted/20 border-b border-border/30">
                  <span className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground/80">
                    {group}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-muted-foreground/60">{rows.length} dags</span>
                    {groupFailed > 0 && (
                      <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-[9px] px-1.5 py-0">
                        {groupFailed} fallido{groupFailed > 1 ? "s" : ""}
                      </Badge>
                    )}
                  </div>
                </div>
                <table className="w-full text-[12px]">
                  <thead>
                    <tr className="border-b border-border/20 text-left text-[9px] uppercase tracking-wider text-muted-foreground/50">
                      <th className="px-4 py-2 font-medium w-8"></th>
                      <th className="px-3 py-2 font-medium">Pipeline</th>
                      <th className="px-3 py-2 font-medium w-[90px]">Estado</th>
                      <th className="px-3 py-2 font-medium w-[100px] hidden sm:table-cell">Schedule</th>
                      <th className="px-3 py-2 font-medium w-[110px] hidden md:table-cell text-right">Últ. ejecución</th>
                      <th className="px-3 py-2 font-medium w-[80px] hidden lg:table-cell text-right">Duración</th>
                      <th className="px-3 py-2 font-medium w-[90px] hidden xl:table-cell text-right">Tipo</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((d, i) => {
                      const stateCfg = d.last_state ? STATE_CFG[d.last_state] : null;
                      return (
                        <tr key={d.dag_id}
                          className={cn(
                            "border-b border-border/10 last:border-0 transition-colors hover:bg-muted/10",
                            i % 2 === 0 ? "bg-card/40" : "bg-card/20",
                            d.last_state === "failed" && "bg-red-500/5 hover:bg-red-500/10",
                          )}>
                          <td className="px-4 py-2.5 text-center">
                            <StateIcon state={d.last_state} paused={d.is_paused} />
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="font-mono text-[11px] text-foreground/90">{d.dag_id}</span>
                            {d.is_paused && (
                              <span className="ml-2 text-[9px] text-zinc-500 uppercase tracking-wide">pausado</span>
                            )}
                          </td>
                          <td className="px-3 py-2.5">
                            {d.is_paused ? (
                              <span className="text-[10px] text-zinc-500">Pausado</span>
                            ) : !d.last_state ? (
                              <span className="text-[10px] text-muted-foreground/50">Sin runs</span>
                            ) : (
                              <span className={cn("text-[10px] font-semibold", stateCfg?.cls ?? "text-muted-foreground")}>
                                {stateCfg?.label ?? d.last_state}
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2.5 hidden sm:table-cell">
                            <span className="font-mono text-[10px] text-muted-foreground/70 truncate block max-w-[88px]">
                              {d.schedule_interval ?? "—"}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 hidden md:table-cell text-right text-[11px] text-muted-foreground">
                            {fmtAgo(d.last_end ?? d.last_start)}
                          </td>
                          <td className="px-3 py-2.5 hidden lg:table-cell text-right font-mono text-[11px] text-muted-foreground">
                            {fmtDuration(d.duration_sec)}
                          </td>
                          <td className="px-3 py-2.5 hidden xl:table-cell text-right">
                            {d.run_type && (
                              <span className="text-[9px] text-muted-foreground/50 uppercase">{d.run_type}</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            );
          })}
        </div>
      )}

      {/* Nota */}
      {ok === 0 && !isLoading && dags.length > 0 && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-[12px] text-amber-400/90">
          Todos los DAGs están pausados o sin historial de ejecución. Activar desde la UI de Airflow o vía API.
        </div>
      )}
    </div>
  );
}
