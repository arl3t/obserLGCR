/**
 * CaseTicketsCard.tsx — "Acciones al cliente" dentro de la Investigación.
 *
 * Se monta en la columna derecha del caso (junto a HuntVerdictCard). Muestra los
 * tickets vinculados al caso y sus solicitudes accionables, y permite al analista
 * SOLICITAR una acción al cliente (contención en firewall, aislar host…) que
 * desemboca en su decisión / aceptación de riesgo desde el portal.
 *
 * GET /api/tickets/by-case/:caseId + POST /api/tickets/action-requests.
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §6.
 */
import { memo, useState, useEffect, useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { buildIncidentVerdict } from "@/lib/incident-verdict";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { ShieldAlert, Send, Loader2, Ticket, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDateTimePy } from "@/lib/format";
import { getTicketsByCase, createActionRequest, listActiveOrgs } from "@/api/tickets";
import {
  ACTION_TYPE_LABEL, ACTION_STATUS_LABEL, PRIORITY_LABEL, STATUS_LABEL,
  type ActionType, type TicketPriority,
} from "@/components/tickets/types";
import { ACTION_STATUS_COLOR } from "@/components/tickets/ticket-format";
import type { FullCase } from "./useCaseInvestigation";

const ACTION_TYPES: ActionType[] = [
  "CONTENCION_FIREWALL", "AISLAR_HOST", "BLOQUEO_IOC", "RESET_CREDENCIALES",
  "APLICAR_PARCHE", "DESHABILITAR_CUENTA", "DESHABILITAR_SERVICIO", "OTRO",
];
const SELECT_CLS = "h-8 rounded-md border bg-card px-2 text-sm text-foreground";

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

// Título sugerido según el tipo de acción + el IOC del caso.
function defaultTitle(actionType: ActionType, ioc: string): string {
  const map: Record<ActionType, string> = {
    CONTENCION_FIREWALL:   ioc ? `Bloquear ${ioc} en el firewall` : "Aplicar contención en el firewall",
    BLOQUEO_IOC:           ioc ? `Bloquear el indicador ${ioc}` : "Bloquear el indicador",
    AISLAR_HOST:           ioc ? `Aislar el host afectado (${ioc})` : "Aislar el host afectado",
    RESET_CREDENCIALES:    "Resetear las credenciales comprometidas",
    APLICAR_PARCHE:        "Aplicar el parche de seguridad",
    DESHABILITAR_CUENTA:   "Deshabilitar la cuenta comprometida",
    DESHABILITAR_SERVICIO: "Deshabilitar el servicio expuesto",
    OTRO:                  ioc ? `Acción sobre ${ioc}` : "Acción solicitada al cliente",
  };
  return map[actionType] ?? "";
}
// Justificación sugerida a partir del veredicto + la acción recomendada del caso.
function defaultRationale(c: FullCase): string {
  const parts: string[] = [];
  try {
    const v = buildIncidentVerdict(c);
    if (v?.verdictLabel) parts.push(`Veredicto: ${v.verdictLabel}.`);
    if (v?.summary) parts.push(v.summary);
  } catch { /* veredicto best-effort */ }
  const rec = c.recommended_action ?? c.lessons_learned;
  if (rec) parts.push(`Acción recomendada: ${rec}`);
  return parts.join("\n\n");
}

export const CaseTicketsCard = memo(function CaseTicketsCard({ c }: { c: FullCase }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [actionType, setActionType] = useState<ActionType>("CONTENCION_FIREWALL");
  const [title, setTitle] = useState("");
  const [rationale, setRationale] = useState("");
  const [urgency, setUrgency] = useState<TicketPriority>("HIGH");
  const [orgSlug, setOrgSlug] = useState("");

  const q = useQuery({
    queryKey: ["case-tickets", c.id],
    queryFn: () => getTicketsByCase(c.id),
    staleTime: 30_000,
  });

  const ticketList = q.data ?? [];
  // El cliente (org) solo hay que elegirlo si el caso aún NO tiene ticket vinculado;
  // si ya hay uno, la solicitud reusa ese ticket (y su organización).
  const needsOrg = ticketList.length === 0;
  const orgsQ = useQuery({
    queryKey: ["active-orgs"],
    queryFn: () => listActiveOrgs(),
    enabled: open && needsOrg,
    staleTime: 60_000,
  });

  const mut = useMutation({
    mutationFn: () => createActionRequest({ caseId: c.id, actionType, title, rationale, urgency, orgSlug: needsOrg ? orgSlug : undefined }),
    onSuccess: () => {
      toast.success("Solicitud enviada al cliente");
      setTitle(""); setRationale(""); setOrgSlug(""); setOpen(false);
      void qc.invalidateQueries({ queryKey: ["case-tickets", c.id] });
      void qc.invalidateQueries({ queryKey: ["case-timeline", c.id] });
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  // ── Autocompletado: al abrir el formulario, prerellena título (IOC + acción) y
  //    justificación (veredicto + acción recomendada). El analista puede editar. ──
  const ioc = c.ioc_value ?? "";
  const allDefaultTitles = useMemo(() => new Set(ACTION_TYPES.map((a) => defaultTitle(a, ioc))), [ioc]);
  useEffect(() => {
    if (!open) return;
    setTitle((t) => (t ? t : defaultTitle(actionType, ioc)));
    setRationale((r) => (r ? r : defaultRationale(c)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  useEffect(() => {
    // Al cambiar el tipo de acción, actualizar el título SOLO si sigue siendo un
    // valor autogenerado (no editado a mano).
    if (open) setTitle((t) => (t === "" || allDefaultTitles.has(t)) ? defaultTitle(actionType, ioc) : t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [actionType]);

  const actionReqs = ticketList.flatMap((t) => t.actionRequests.map((ar) => ({ ar, ref: t.public_ref })));

  return (
    <div className="space-y-3 rounded-lg border border-border/60 bg-muted/10 p-3">
      {/* Encabezado */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <ShieldAlert className="h-3.5 w-3.5" /> Acciones al cliente
        </div>
        <button className="text-xs font-medium text-cyan-400 hover:underline" onClick={() => setOpen((v) => !v)}>
          {open ? "Cancelar" : "+ Solicitar"}
        </button>
      </div>

      {/* Tickets vinculados */}
      {ticketList.length > 0 && (
        <div className="space-y-1">
          {ticketList.map((t) => (
            <Link key={t.id} to="/tickets" className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
              <Ticket className="h-3 w-3" />
              <span className="font-mono">{t.public_ref}</span>
              <span className="rounded bg-muted px-1.5 py-0.5">{STATUS_LABEL[t.status]}</span>
              <ExternalLink className="h-3 w-3 opacity-60" />
            </Link>
          ))}
        </div>
      )}

      {/* Formulario de solicitud */}
      {open && (
        <div className="space-y-2 rounded-md border bg-card/60 p-2">
          {needsOrg && (
            <div>
              <label className="text-[11px] text-muted-foreground">Cliente (organización)</label>
              <select className={cn(SELECT_CLS, "w-full")} value={orgSlug} onChange={(e) => setOrgSlug(e.target.value)}>
                <option value="">— Elegí el cliente —</option>
                {(orgsQ.data ?? []).filter((o) => o.slug !== "default").map((o) => (
                  <option key={o.id} value={o.slug}>{o.name}</option>
                ))}
              </select>
            </div>
          )}
          <div className="flex gap-2">
            <select className={cn(SELECT_CLS, "flex-1")} value={actionType} onChange={(e) => setActionType(e.target.value as ActionType)}>
              {ACTION_TYPES.map((a) => <option key={a} value={a}>{ACTION_TYPE_LABEL[a]}</option>)}
            </select>
            <select className={SELECT_CLS} value={urgency} onChange={(e) => setUrgency(e.target.value as TicketPriority)}>
              {(["URGENT", "HIGH", "MEDIUM", "LOW"] as TicketPriority[]).map((u) => <option key={u} value={u}>{PRIORITY_LABEL[u]}</option>)}
            </select>
          </div>
          <input className="h-8 w-full rounded-md border bg-card px-2 text-sm" placeholder="Título (ej: Bloquear 203.0.113.40 en el FW)"
            value={title} onChange={(e) => setTitle(e.target.value)} />
          <textarea className="min-h-[48px] w-full rounded-md border bg-card p-2 text-sm" placeholder="Justificación (lenguaje claro, sin telemetría cruda)"
            value={rationale} onChange={(e) => setRationale(e.target.value)} />
          <button
            className="flex w-full items-center justify-center gap-1.5 rounded-md bg-purple-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
            disabled={!title.trim() || !rationale.trim() || (needsOrg && !orgSlug) || mut.isPending}
            onClick={() => mut.mutate()}>
            {mut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Solicitar al cliente
          </button>
          {needsOrg && (
            <p className="text-[11px] text-muted-foreground">Se creará y vinculará un ticket del cliente elegido a este caso.</p>
          )}
        </div>
      )}

      {/* Solicitudes existentes + su disposición */}
      {actionReqs.length > 0 ? (
        <div className="space-y-2">
          {actionReqs.map(({ ar, ref }) => (
            <div key={ar.id} className="rounded-md border p-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium">{ACTION_TYPE_LABEL[ar.action_type]}</span>
                <span className="shrink-0 rounded border px-1.5 py-0.5 text-[11px]"
                  style={{ color: ACTION_STATUS_COLOR[ar.status], borderColor: ACTION_STATUS_COLOR[ar.status] }}>
                  {ACTION_STATUS_LABEL[ar.status]}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">{ar.title}</p>
              {ar.status === "RIESGO_ACEPTADO" && (
                <p className="mt-1 text-[11px] text-purple-400">
                  Riesgo asumido por {ar.risk_accepted_by}
                  {ar.risk_review_at && ` · revisar ${formatDateTimePy(ar.risk_review_at)}`}
                </p>
              )}
              {ar.decided_at && ar.status !== "RIESGO_ACEPTADO" && (
                <p className="mt-1 text-[11px] text-muted-foreground">
                  {ACTION_STATUS_LABEL[ar.status]} por {ar.decided_by} · {formatDateTimePy(ar.decided_at)}
                </p>
              )}
              <p className="mt-0.5 text-[10px] text-muted-foreground/70 font-mono">{ref}</p>
            </div>
          ))}
        </div>
      ) : (
        !open && <p className="text-xs text-muted-foreground">Sin solicitudes. Usá «+ Solicitar» para pedir una acción al cliente.</p>
      )}
    </div>
  );
});
