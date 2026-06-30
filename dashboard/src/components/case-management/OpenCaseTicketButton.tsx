import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Loader2, Ticket } from "lucide-react";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import {
  createActionRequest,
  getTicketsByCase,
  listActiveOrgs,
  type ActiveOrg,
} from "@/api/tickets";
import { C, alpha } from "@/lib/cm-theme";

/** Organización cliente por defecto para tickets NOC (debe existir en /tickets/orgs). */
const PREFERRED_ORG_SLUG = "lgcr";

function resolveOrgSlug(orgs: ActiveOrg[]): string {
  const picked = orgs.find((o) => o.slug === PREFERRED_ORG_SLUG) ?? orgs[0];
  return picked?.slug ?? PREFERRED_ORG_SLUG;
}

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

interface OpenCaseTicketButtonProps {
  caseId: string;
  hostname?: string | null;
  recommendedAction?: string | null;
  compact?: boolean;
}

/** Crea ticket vinculado al caso NOC (action-request → ticket automático). */
export function OpenCaseTicketButton({
  caseId,
  hostname,
  recommendedAction,
  compact,
}: OpenCaseTicketButtonProps) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);

  const ticketsQ = useQuery({
    queryKey: ["case-linked-tickets", caseId],
    queryFn: () => getTicketsByCase(caseId),
    staleTime: 30_000,
  });

  const openTicket = ticketsQ.data?.find((t) => t.status !== "CERRADO");

  const orgsQ = useQuery({
    queryKey: ["active-orgs"],
    queryFn: () => listActiveOrgs(),
    staleTime: 60_000,
  });

  const needsOrg = (ticketsQ.data ?? []).length === 0;
  const orgReady = !needsOrg || !orgsQ.isLoading;

  const mut = useMutation({
    mutationFn: async () => {
      const title = hostname
        ? `Incidente NOC — ${hostname}`
        : `Incidente NOC — caso ${caseId.slice(0, 8)}`;
      const rationale =
        recommendedAction?.trim() ||
        "Incidente generado desde alerta NOC (dispositivo sin heartbeat / caída detectada).";
      const linked = ticketsQ.data ?? [];
      const orgSlug = linked.length === 0
        ? resolveOrgSlug(orgsQ.data ?? await listActiveOrgs())
        : undefined;
      return createActionRequest({
        caseId,
        actionType: "OTRO",
        title,
        rationale,
        urgency: "HIGH",
        orgSlug,
      });
    },
    onSuccess: () => {
      toast.success("Ticket creado y vinculado al caso");
      void qc.invalidateQueries({ queryKey: ["case-linked-tickets", caseId] });
      void qc.invalidateQueries({ queryKey: ["case-tickets", caseId] });
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  async function handleClick() {
    setBusy(true);
    try {
      await mut.mutateAsync();
    } finally {
      setBusy(false);
    }
  }

  if (openTicket) {
    return (
      <Link
        to={`/tickets?ticket=${openTicket.id}`}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 4,
          fontSize: compact ? 11 : 12,
          padding: compact ? "4px 10px" : "6px 14px",
          borderRadius: 6,
          background: alpha(C.green, 12),
          border: `1px solid ${alpha(C.green, 28)}`,
          color: C.green,
          fontWeight: 600,
          textDecoration: "none",
        }}
      >
        <Ticket size={compact ? 12 : 13} />
        Ticket {openTicket.public_ref}
      </Link>
    );
  }

  return (
    <button
      type="button"
      onClick={() => void handleClick()}
      disabled={busy || mut.isPending || !orgReady}
      title={!orgReady ? "Cargando organizaciones…" : undefined}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: compact ? 11 : 12,
        padding: compact ? "4px 10px" : "6px 14px",
        borderRadius: 6,
        background: alpha(C.blue, 12),
        border: `1px solid ${alpha(C.blue, 28)}`,
        color: C.blue,
        cursor: busy ? "wait" : "pointer",
        fontWeight: 600,
      }}
    >
      {busy || mut.isPending ? (
        <Loader2 size={12} className="animate-spin" />
      ) : (
        <Ticket size={compact ? 12 : 13} />
      )}
      Abrir ticket
    </button>
  );
}
