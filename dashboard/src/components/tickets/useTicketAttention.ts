/**
 * useTicketAttention — fuente única de la "atención" de tickets que comparten
 * el botón "Tickets" del header (badge + animación de pendientes) y el panel del
 * Asistente (listas de triage). React-query deduplica las queries por key.
 *
 * Distingue dos grupos para que NUNCA se diga "no hay ticket" cuando el operador
 * tiene trabajo abierto:
 *   - attention → pelota del SOC (waiting_on === "SOC"), no terminal. Acción ya.
 *   - following → mis tickets (asignados a mí) que siguen abiertos aunque la
 *     pelota la tenga el cliente. Es lo que el operador "tiene en seguimiento".
 */
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getCommSlaConfig, listTickets } from "@/api/tickets";
import { computeSla, queueScore } from "@/components/tickets/ticket-sla";
import type { SlaState } from "@/components/tickets/ticket-sla";
import type { TicketRow } from "@/components/tickets/types";

const TERMINAL = new Set(["RESUELTO", "CERRADO"]);

export interface TicketAttention {
  attention: TicketRow[];   // pelota del SOC — acción inmediata
  following: TicketRow[];   // míos abiertos, en seguimiento (pelota del cliente)
  badge: number;            // cuántos requieren acción del SOC
  hasPending: boolean;      // hay ticket nuevo sin responder o mensaje sin leer
  loading: boolean;
  slaOf: (t: TicketRow) => SlaState;
}

export function useTicketAttention(): TicketAttention {
  const slaQ = useQuery({ queryKey: ["ticket-sla-config"], queryFn: () => getCommSlaConfig(), staleTime: 300_000 });
  const listQ = useQuery({
    queryKey: ["tickets", "assistant"],
    queryFn: () => listTickets({ limit: 200 }),
    staleTime: 20_000,
    refetchInterval: 45_000,
    refetchOnWindowFocus: true,
  });
  const mineQ = useQuery({
    queryKey: ["tickets", "assistant-mine"],
    queryFn: () => listTickets({ mine: true, limit: 100 }),
    staleTime: 20_000,
    refetchInterval: 60_000,
  });

  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNowMs(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  const cfg = slaQ.data ?? null;
  const slaOf = (t: TicketRow) => computeSla(t, cfg, nowMs);

  return useMemo(() => {
    const all = listQ.data ?? [];
    const attention = all
      .filter((t) => !TERMINAL.has(t.status) && t.waiting_on === "SOC")
      .sort((a, b) => queueScore(b, slaOf(b)) - queueScore(a, slaOf(a)));
    const inAtt = new Set(attention.map((t) => t.id));
    const following = (mineQ.data ?? [])
      .filter((t) => !TERMINAL.has(t.status) && !inAtt.has(t.id))
      .sort((a, b) => queueScore(b, slaOf(b)) - queueScore(a, slaOf(a)));
    // Pendiente = ticket nuevo sin primera respuesta o mensaje del cliente sin leer.
    const hasPending = attention.some(
      (t) => Number(t.unread_client ?? 0) > 0 || !t.first_response_at,
    );
    return { attention, following, badge: attention.length, hasPending, loading: listQ.isLoading, slaOf };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [listQ.data, mineQ.data, cfg, nowMs, listQ.isLoading]);
}
