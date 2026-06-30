/**
 * SystemHealthButton — estado operativo de obserLGCR (API + infraestructura NOC).
 * Fuente: GET /api/health + GET /api/noc/devices (refresco 60s).
 */

import { Server, Wifi, WifiOff, AlertTriangle } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

interface ApiHealth {
  ok: boolean;
  service?: string;
  mode?: string;
}

interface NocDevice {
  status: string;
  open_alerts?: number;
}

interface NocAlertsResponse {
  data?: { status: string }[];
  alerts?: { status: string }[];
}

interface SystemHealth {
  apiOk: boolean;
  service: string;
  mode: string;
  totalDevices: number;
  online: number;
  offline: number;
  openAlerts: number;
}

function useSystemHealth(intervalMs = 60_000): SystemHealth | null {
  const { data } = useQuery<SystemHealth>({
    queryKey: ["system-health"],
    queryFn: async () => {
      const [healthRes, devicesRes, alertsRes] = await Promise.all([
        api.get<ApiHealth>("/api/health"),
        api.get<{ data?: NocDevice[]; devices?: NocDevice[] }>("/api/noc/devices").catch(() => null),
        api.get<NocAlertsResponse>("/api/noc/alerts?status=open").catch(() => null),
      ]);

      const health = healthRes.data;
      const devices = devicesRes?.data?.data ?? devicesRes?.data?.devices ?? [];
      const alertsPayload = alertsRes?.data?.data ?? alertsRes?.data?.alerts ?? [];

      return {
        apiOk: health.ok === true,
        service: health.service ?? "obserlgcr-api",
        mode: health.mode ?? "—",
        totalDevices: devices.length,
        online: devices.filter((d) => d.status === "online").length,
        offline: devices.filter((d) => d.status === "offline").length,
        openAlerts: alertsPayload.filter((a) => a.status === "open").length,
      };
    },
    staleTime: intervalMs,
    refetchInterval: intervalMs,
    refetchOnWindowFocus: false,
  });
  return data ?? null;
}

function statusTone(health: SystemHealth | null): "ok" | "warn" | "error" | "unknown" {
  if (!health) return "unknown";
  if (!health.apiOk) return "error";
  if (health.offline > 0 || health.openAlerts > 0) return "warn";
  return "ok";
}

const DOT: Record<ReturnType<typeof statusTone>, string> = {
  ok: "bg-emerald-500",
  warn: "bg-amber-500",
  error: "bg-red-500",
  unknown: "bg-muted-foreground/40",
};

export function SystemHealthButton() {
  const health = useSystemHealth();
  const tone = statusTone(health);

  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="relative gap-2 border-cyan-500/20 bg-cyan-500/5 pr-3 text-xs hover:bg-cyan-500/10"
          aria-label={`Estado del sistema: ${tone === "ok" ? "operativo" : tone === "warn" ? "con alertas" : tone === "error" ? "degradado" : "cargando"}`}
        >
          <Server className="h-3.5 w-3.5 shrink-0 text-cyan-400" aria-hidden />
          <span className="hidden sm:inline">Sistema</span>
          <span className={cn("h-2 w-2 shrink-0 rounded-full", DOT[tone])} aria-hidden />
        </Button>
      </SheetTrigger>

      <SheetContent side="right" className="flex w-[min(100vw,24rem)] flex-col gap-0 p-0">
        <SheetHeader className="border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-cyan-400" aria-hidden />
            <SheetTitle className="text-sm font-semibold">Estado del sistema</SheetTitle>
          </div>
          <p className="text-xs text-muted-foreground">
            obserLGCR · API e infraestructura NOC · actualiza cada 60 s
          </p>
        </SheetHeader>

        <div className="flex-1 space-y-3 overflow-y-auto px-4 py-4 text-xs">
          {health == null ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full rounded-lg" />
              ))}
            </div>
          ) : (
            <>
              <div
                className={cn(
                  "rounded-lg border p-3",
                  health.apiOk
                    ? "border-emerald-500/30 bg-emerald-500/8"
                    : "border-red-500/30 bg-red-500/8",
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold">API obserLGCR</span>
                  <span
                    className={cn(
                      "text-[11px] font-bold uppercase",
                      health.apiOk ? "text-emerald-400" : "text-red-400",
                    )}
                  >
                    {health.apiOk ? "Operativa" : "Caída"}
                  </span>
                </div>
                <p className="mt-1 text-muted-foreground">
                  {health.service} · modo {health.mode}
                </p>
              </div>

              <div className="rounded-lg border border-border bg-muted/20 p-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold">Infraestructura NOC</span>
                  <span className="text-[11px] font-bold tabular-nums text-cyan-400">
                    {health.totalDevices} dispositivo{health.totalDevices !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <div className="flex items-center gap-2 rounded-md border border-emerald-500/20 bg-emerald-500/5 px-2.5 py-2">
                    <Wifi className="h-3.5 w-3.5 text-emerald-400" />
                    <div>
                      <div className="text-base font-bold tabular-nums">{health.online}</div>
                      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">En línea</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 rounded-md border border-red-500/20 bg-red-500/5 px-2.5 py-2">
                    <WifiOff className="h-3.5 w-3.5 text-red-400" />
                    <div>
                      <div className="text-base font-bold tabular-nums">{health.offline}</div>
                      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Fuera</div>
                    </div>
                  </div>
                </div>
              </div>

              <div
                className={cn(
                  "rounded-lg border p-3",
                  health.openAlerts > 0
                    ? "border-amber-500/30 bg-amber-500/8"
                    : "border-border bg-muted/20",
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 font-semibold">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                    Alertas abiertas
                  </span>
                  <span
                    className={cn(
                      "text-[11px] font-bold tabular-nums",
                      health.openAlerts > 0 ? "text-amber-400" : "text-emerald-400",
                    )}
                  >
                    {health.openAlerts}
                  </span>
                </div>
                <p className="mt-1 text-muted-foreground">
                  {health.openAlerts > 0
                    ? "Hay dispositivos que requieren atención del operador NOC."
                    : "Sin alertas activas en este momento."}
                </p>
              </div>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
