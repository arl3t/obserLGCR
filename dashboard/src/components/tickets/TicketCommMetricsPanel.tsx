/**
 * TicketCommMetricsPanel.tsx — F4: métricas de COMUNICACIÓN del Sistema de Tickets.
 *
 * Mide la calidad de la conversación cliente↔SOC (distinto del SLA operacional):
 * FRT/NRT, ball-in-court, ping-pong (round-trips), y disposición de las solicitudes
 * accionables (TTD-acción, % riesgo aceptado) + registro de riesgos vigentes.
 *
 * Reutilizable: se monta en la página de Tickets y en el Centro de Mando
 * (pages/OverviewCharts.tsx). Ver docs/PROPUESTA-TICKETING-PUBLICO.md §5/§6.4.
 */
import { useQuery } from "@tanstack/react-query";
import { MessageSquare, Clock, Repeat, ShieldQuestion, AlertTriangle, Hourglass, Star } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { getCommMetrics, getActionMetrics, getRiskAcceptances } from "@/api/tickets";
import { fmtDuration, num } from "@/components/tickets/ticket-format";
import type { ReactNode } from "react";

function Kpi({ icon, label, value, hint }: { icon: ReactNode; label: string; value: ReactNode; hint?: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className="rounded-md bg-muted/40 p-2">{icon}</div>
        <div>
          <div className="text-2xl font-semibold tabular-nums">{value}</div>
          <div className="text-xs text-muted-foreground">{label}</div>
          {hint && <div className="text-[10px] text-muted-foreground/70">{hint}</div>}
        </div>
      </CardContent>
    </Card>
  );
}

export function TicketCommMetricsPanel({ days = 30, compact = false }: { days?: number; compact?: boolean }) {
  const commQ = useQuery({
    queryKey: ["ticket-comm-metrics", days],
    queryFn: () => getCommMetrics(days),
    staleTime: 60_000,
  });
  const actQ = useQuery({
    queryKey: ["ticket-action-metrics", days],
    queryFn: () => getActionMetrics(days),
    staleTime: 60_000,
  });
  const riskQ = useQuery({
    queryKey: ["ticket-risk-acceptances"],
    queryFn: () => getRiskAcceptances(),
    staleTime: 60_000,
  });

  if (commQ.isLoading || actQ.isLoading) {
    return (
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)}
      </div>
    );
  }

  const cm = commQ.data;
  const am = actQ.data;
  const overdueRisk = (riskQ.data ?? []).filter((r) => r.risk_review_at && new Date(r.risk_review_at) < new Date()).length;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi icon={<MessageSquare className="h-4 w-4 text-cyan-400" />} label="Tickets abiertos"
          value={num(cm?.open_tickets)} hint={`${num(cm?.tickets)} en ${days}d`} />
        <Kpi icon={<Clock className="h-4 w-4 text-emerald-400" />} label="FRT medio"
          value={fmtDuration(cm?.frt_avg_sec)} hint="1ª respuesta" />
        <Kpi icon={<Clock className="h-4 w-4 text-emerald-400" />} label="NRT medio"
          value={fmtDuration(cm?.nrt_avg_sec)} hint="respuestas sig." />
        <Kpi icon={<Repeat className="h-4 w-4 text-purple-400" />} label="Ping-pong"
          value={cm?.round_trips_avg != null ? Number(cm.round_trips_avg).toFixed(1) : "—"} hint="round-trips/ticket" />
        <Kpi icon={<ShieldQuestion className="h-4 w-4 text-amber-400" />} label="Espera SOC"
          value={num(cm?.waiting_on_soc)} hint={`${num(cm?.waiting_on_client)} espera cliente`} />
        <Kpi icon={<Hourglass className="h-4 w-4 text-cyan-400" />} label="TTD-acción"
          value={fmtDuration(am?.ttd_avg_sec)} hint="cliente decide" />
      </div>

      {!compact && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Kpi icon={<AlertTriangle className="h-4 w-4 text-purple-400" />} label="Riesgos aceptados"
            value={num(am?.risk_accepted)} hint={overdueRisk ? `${overdueRisk} a revisar` : "vigentes"} />
          <Kpi icon={<Hourglass className="h-4 w-4 text-emerald-400" />} label="Solicitudes ejecutadas"
            value={num(am?.executed)} />
          <Kpi icon={<AlertTriangle className="h-4 w-4 text-red-400" />} label="Solicitudes vencidas"
            value={num(am?.overdue)} hint="sin decidir" />
          <Kpi icon={<Repeat className="h-4 w-4 text-amber-400" />} label="Reaperturas"
            value={num(cm?.reopens)} />
          <Kpi icon={<Star className="h-4 w-4 text-amber-400" />} label="CSAT"
            value={cm?.csat_avg != null ? `${Number(cm.csat_avg).toFixed(1)}★` : "—"}
            hint={`${num(cm?.csat_count)} respuestas`} />
        </div>
      )}
    </div>
  );
}
