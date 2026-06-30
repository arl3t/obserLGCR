/**
 * TicketNotificationButton.tsx — botón "Tickets" de la barra superior.
 *
 * Con la flag FEATURE_TICKET_ASSISTANT activa, este botón ES el disparador del
 * Asistente de Tickets: lo abre en vista triage (las novedades viven dentro del
 * panel). Muestra un badge con cuántos tickets requieren acción del SOC y una
 * animación de pulso cuando hay un ticket nuevo sin responder o un mensaje del
 * cliente sin leer.
 *
 * Con la flag apagada, conserva el comportamiento histórico: campana con el
 * Sheet de actividad reciente (GET /api/tickets/activity).
 */
import { useEffect, useState } from "react";
import { Ticket as TicketIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { socket } from "@/lib/socket";
import { Button } from "@/components/ui/button";
import {
  Sheet, SheetClose, SheetContent, SheetHeader, SheetTitle, SheetTrigger,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { getTicketActivity, type TicketActivity } from "@/api/tickets";
import { PRIORITY_COLOR } from "@/components/tickets/ticket-format";
import { PRIORITY_LABEL, STATUS_LABEL, type TicketStatus } from "@/components/tickets/types";
import { useTicketAttention } from "@/components/tickets/useTicketAttention";
import { useTicketAssistantStore } from "@/store/ticket-assistant-store";
import { FEATURE_TICKET_ASSISTANT } from "@/lib/feature-flags";
import { formatTimePy } from "@/lib/format";

const SEEN_KEY = "ticket_notif_seen_at";
const CHANNEL_LABEL: Record<string, string> = {
  PORTAL: "Portal", API: "API", EMAIL: "Email", SOC_INITIATED: "SOC",
};

function fmtTime(iso: string) {
  try { return formatTimePy(iso); } catch { return iso.slice(0, 16).replace("T", " "); }
}

export function TicketNotificationButton() {
  return FEATURE_TICKET_ASSISTANT ? <AssistantTicketButton /> : <LegacyTicketBell />;
}

// ── Disparador del Asistente (flag on) ────────────────────────────────────────
function AssistantTicketButton() {
  const { badge, hasPending } = useTicketAttention();
  const showTriage = useTicketAssistantStore((s) => s.showTriage);
  const qc = useQueryClient();

  // Mantener el badge/pulso al día en vivo por socket.
  useEffect(() => {
    socket.connect();
    const onEvent = () => {
      void qc.invalidateQueries({ queryKey: ["tickets", "assistant"] });
      void qc.invalidateQueries({ queryKey: ["tickets", "assistant-mine"] });
    };
    socket.on("ticket:new", onEvent);
    socket.on("ticket:assigned", onEvent);
    return () => { socket.off("ticket:new", onEvent); socket.off("ticket:assigned", onEvent); };
  }, [qc]);

  return (
    <Button
      data-ticket-assistant-trigger
      variant="outline"
      size="sm"
      onClick={() => showTriage()}
      className="relative gap-2 border-border/60 pr-3 text-xs"
      aria-label={`Asistente de Tickets — ${badge} requieren acción${hasPending ? ", hay novedades" : ""}`}
    >
      <TicketIcon className="h-3.5 w-3.5 shrink-0" aria-hidden />
      <span className="hidden sm:inline">Tickets</span>
      {badge > 0 ? (
        <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-cyan-500 px-1 text-[10px] font-bold text-white tabular-nums">
          {badge > 99 ? "99+" : badge}
        </span>
      ) : (
        <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-muted px-1 text-[10px] font-medium text-muted-foreground tabular-nums">0</span>
      )}
      {/* Pulso: ticket nuevo sin responder o mensaje del cliente sin leer. */}
      {hasPending && (
        <span className="absolute -right-1 -top-1 flex h-2.5 w-2.5" aria-hidden>
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-cyan-500" />
        </span>
      )}
    </Button>
  );
}

// ── Campana histórica (flag off) ──────────────────────────────────────────────
function LegacyTicketBell() {
  const [seenAt, setSeenAt] = useState<number>(() => Number(localStorage.getItem(SEEN_KEY) || 0));

  const { data, isLoading, refetch } = useQuery<TicketActivity[]>({
    queryKey: ["ticket-activity", "nav"],
    queryFn: () => getTicketActivity(20),
    staleTime: 15_000,
    refetchInterval: 20_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: false,
  });

  // Actualización en vivo por socket.
  useEffect(() => {
    socket.connect();
    const onEvent = () => void refetch();
    socket.on("ticket:new", onEvent);
    socket.on("ticket:assigned", onEvent);
    return () => { socket.off("ticket:new", onEvent); socket.off("ticket:assigned", onEvent); };
  }, [refetch]);

  const activity = data ?? [];
  const unread = activity.filter((a) => new Date(a.created_at).getTime() > seenAt).length;

  function markSeen() {
    const now = Date.now();
    localStorage.setItem(SEEN_KEY, String(now));
    setSeenAt(now);
  }

  return (
    <Sheet onOpenChange={(open) => { if (open) markSeen(); }}>
      <SheetTrigger asChild>
        <Button variant="outline" size="sm" className="relative gap-2 border-border/60 pr-3 text-xs" aria-label={`Tickets: ${unread} novedad(es)`}>
          <TicketIcon className="h-3.5 w-3.5 shrink-0" aria-hidden />
          <span className="hidden sm:inline">Tickets</span>
          {isLoading ? (
            <Skeleton className="h-4 w-5 rounded-full" />
          ) : unread > 0 ? (
            <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-cyan-500 px-1 text-[10px] font-bold text-white tabular-nums">
              {unread > 99 ? "99+" : unread}
            </span>
          ) : (
            <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-muted px-1 text-[10px] font-medium text-muted-foreground tabular-nums">0</span>
          )}
        </Button>
      </SheetTrigger>

      <SheetContent side="right" className="flex w-[min(100vw,27rem)] flex-col gap-0 p-0">
        <SheetHeader className="border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <TicketIcon className="h-4 w-4 text-cyan-400" aria-hidden />
            <SheetTitle className="text-sm font-semibold">Tickets — actividad reciente</SheetTitle>
          </div>
          <p className="text-xs text-muted-foreground">Tickets nuevos y a quién se asignaron</p>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-4 py-3">
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20 w-full rounded-lg" />)}</div>
          ) : activity.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <TicketIcon className="h-10 w-10 text-muted-foreground/40" />
              <p className="text-sm text-muted-foreground">Sin tickets recientes</p>
            </div>
          ) : (
            <div className="space-y-2">
              {activity.map((a) => {
                const isNew = new Date(a.created_at).getTime() > seenAt;
                return (
                  <div key={a.id} className={`rounded-lg border p-3 text-xs space-y-1.5 ${isNew ? "border-cyan-500/40 bg-cyan-500/8" : "border-border bg-muted/20"}`}>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase" style={{ color: PRIORITY_COLOR[a.priority], borderColor: PRIORITY_COLOR[a.priority] }}>
                        {PRIORITY_LABEL[a.priority]}
                      </span>
                      <span className="font-mono text-muted-foreground">{a.public_ref}</span>
                      <span className="ml-auto text-[10px] text-muted-foreground/70">{CHANNEL_LABEL[a.channel] ?? a.channel}</span>
                    </div>
                    <p className="font-medium leading-snug text-foreground">{a.subject}</p>
                    <div className="flex items-center justify-between gap-2 text-muted-foreground">
                      <span className="truncate">
                        {a.org_name ? a.org_name + " · " : ""}
                        {a.assigned_operator
                          ? <>asignado a <span className="font-medium text-foreground">{a.assigned_operator_name ?? a.assigned_operator}</span></>
                          : <span className="text-amber-400">sin asignar</span>}
                      </span>
                      <span className="shrink-0 text-[10px] text-muted-foreground/60 tabular-nums">{fmtTime(a.created_at)}</span>
                    </div>
                    <div className="text-[10px] text-muted-foreground/70">{STATUS_LABEL[a.status as TicketStatus] ?? a.status}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="border-t border-border p-3">
          <SheetClose asChild>
            <Link to="/tickets" className="flex w-full items-center justify-center rounded-md border border-border bg-muted/30 py-2 text-xs font-medium text-foreground transition-colors hover:bg-accent hover:text-accent-foreground">
              Ver todos los tickets →
            </Link>
          </SheetClose>
        </div>
      </SheetContent>
    </Sheet>
  );
}
