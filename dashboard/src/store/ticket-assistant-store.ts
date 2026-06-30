import { create } from "zustand";

/**
 * ticket-assistant-store — estado global del launcher "Asistente de Tickets".
 * Espejo del patrón de investigation-store: el overlay se monta una vez en el
 * DashboardLayout y se controla desde cualquier punto de la consola.
 *
 * Vistas:
 *   triage → lista de tickets que requieren atención (cola como conversación)
 *   ticket → hilo + acciones de un ticket puntual
 */
type AssistantView = "triage" | "ticket";

type AssistantState = {
  open: boolean;
  view: AssistantView;
  ticketId: string | null;
  toggle: (open?: boolean) => void;
  close: () => void;
  showTriage: () => void;
  openTicket: (id: string) => void;
};

export const useTicketAssistantStore = create<AssistantState>((set, get) => ({
  open: false,
  view: "triage",
  ticketId: null,
  toggle: (open) => set({ open: open ?? !get().open }),
  close: () => set({ open: false }),
  showTriage: () => set({ open: true, view: "triage", ticketId: null }),
  openTicket: (id) => set({ open: true, view: "ticket", ticketId: id }),
}));
