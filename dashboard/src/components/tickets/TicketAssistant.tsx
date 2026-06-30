/**
 * TicketAssistant.tsx — Launcher flotante "Asistente de Tickets" (copiloto de
 * triage del SOC). Capa fina sobre /api/tickets: NO sustituye la página
 * /tickets (cola, filtros, bulk, Kanban) — delega el trabajo pesado a ella.
 *
 * Hace tres cosas, todas con confirmación humana (nada se ejecuta solo):
 *   1. Triage: lista los tickets que requieren atención, ordenados por el mismo
 *      queueScore de la cola, clicables.
 *   2. Hilo del ticket con identidad cliente/analista (espejo de TicketDetail).
 *   3. Acciones puntuales como confirmación: clasificar con IA (checkbox por
 *      campo, sobre el ai_suggested real), asignármelo, responder (abre la
 *      ficha), cerrar (genera el sign-off del cliente — el SOC no cierra directo).
 *
 * Detrás de la flag FEATURE_TICKET_ASSISTANT. Montado una vez en DashboardLayout.
 * Fiel al mockup public/mockups/gestion-tickets-chatbot.html.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  Check, ChevronDown, Copy, Loader2, Send, Sparkles,
} from "lucide-react";
import {
  applyAiSuggestion, assignTicket, classifyTicket,
  getTicket, markTicketRead, requestClosure,
} from "@/api/tickets";
import { useTicketAttention } from "@/components/tickets/useTicketAttention";
import {
  PRIORITY_LABEL, SENTIMENT_EMOJI, SENTIMENT_LABEL, STATUS_LABEL,
  TYPE_LABEL, type AiSuggestion, type Sentiment, type TicketDetail, type TicketRow,
} from "@/components/tickets/types";
import { useTicketAssistantStore } from "@/store/ticket-assistant-store";
import { useAuth } from "@/auth/useAuth";
import { formatTimePy } from "@/lib/format";
import { C } from "@/lib/cm-theme";

const NEGATIVE_SENTIMENT = new Set<Sentiment>(["FRUSTRADO", "ENOJADO"]);

// Campos de la sugerencia IA expuestos como checkbox por-campo (mismos que
// admite applyAiSuggestion → aplica sólo los presentes).
const AI_FIELDS = ["type", "priority", "sentiment", "service_slug", "tags"] as const;
type AiField = (typeof AI_FIELDS)[number];
const AI_FIELD_META: Record<AiField, { icon: string; label: string }> = {
  type:        { icon: "🏷️", label: "Tipo" },
  priority:    { icon: "🚦", label: "Prioridad" },
  sentiment:   { icon: "❤️", label: "Sentimiento" },
  service_slug:{ icon: "🧩", label: "Servicio" },
  tags:        { icon: "#",  label: "Etiquetas" },
};

type ChatEntry = { id: number; side: "user" | "bot"; content: ReactNode };

function fmtTime(iso: string): string {
  try { return formatTimePy(iso); } catch { return iso.slice(11, 16); }
}

// Valor legible de un campo de la sugerencia para la tarjeta de clasificación.
function aiFieldValue(s: AiSuggestion, f: AiField): string | null {
  switch (f) {
    case "type":         return s.type ? TYPE_LABEL[s.type] : null;
    case "priority":     return s.priority ? PRIORITY_LABEL[s.priority] : null;
    case "sentiment":    return s.sentiment ? `${SENTIMENT_EMOJI[s.sentiment]} ${SENTIMENT_LABEL[s.sentiment]}` : null;
    case "service_slug": return s.service_slug ?? null;
    case "tags":         return s.tags?.length ? s.tags.join(", ") : null;
  }
}

export function TicketAssistant() {
  const { open, view, ticketId, close, showTriage, openTicket } = useTicketAssistantStore();
  const { displayName } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const prefersReducedMotion = useReducedMotion();

  const threadRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLElement>(null);
  const idRef = useRef(0);
  const nextId = () => ++idRef.current;

  // Log conversacional efímero (Q&A de texto + confirmaciones de acción). Se
  // reinicia al cambiar de vista/ticket; el contenido estructural (lista de
  // triage / hilo del ticket) se deriva de las queries.
  const [log, setLog] = useState<ChatEntry[]>([]);
  const pushBot = (content: ReactNode) => setLog((l) => [...l, { id: nextId(), side: "bot", content }]);
  const pushUser = (content: ReactNode) => setLog((l) => [...l, { id: nextId(), side: "user", content }]);
  useEffect(() => { setLog([]); }, [view, ticketId]);

  // ── Datos reales (compartidos con el botón "Tickets" del header) ─────────────
  const { attention, following, loading: listLoading, slaOf } = useTicketAttention();
  const ticketQ = useQuery({
    queryKey: ["ticket", ticketId],
    queryFn: () => getTicket(ticketId as string),
    enabled: open && view === "ticket" && !!ticketId,
  });

  // Cerrar al clickear fuera del panel (ignora el botón disparador del header,
  // marcado con data-ticket-assistant-trigger, para no reabrir/cerrar en bucle).
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      const target = e.target as HTMLElement | null;
      if (!target) return;
      if (panelRef.current?.contains(target)) return;
      if (target.closest("[data-ticket-assistant-trigger]")) return;
      close();
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open, close]);

  // Marcar leído al abrir un ticket (espejo del comportamiento real de la ficha).
  useEffect(() => {
    if (open && view === "ticket" && ticketId) {
      void markTicketRead(ticketId).then(() => {
        void qc.invalidateQueries({ queryKey: ["tickets"] });
      }).catch(() => {});
    }
  }, [open, view, ticketId, qc]);

  // Auto-scroll al fondo cuando cambia el contenido.
  useEffect(() => {
    const el = threadRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [log, view, ticketId, ticketQ.data, attention.length]);

  // ── Clasificación IA por-campo ───────────────────────────────────────────────
  const [aiChecked, setAiChecked] = useState<Record<AiField, boolean>>(
    { type: true, priority: true, sentiment: true, service_slug: true, tags: true },
  );
  const classifyMut = useMutation({
    mutationFn: () => classifyTicket(ticketId as string),
    onSuccess: (s) => {
      const init = {} as Record<AiField, boolean>;
      for (const f of AI_FIELDS) init[f] = aiFieldValue(s, f) != null;
      setAiChecked(init);
      pushBot(<AiCard suggestion={s} />);
    },
    onError: () => pushBot(<span style={{ color: C.red }}>No pude clasificar el ticket. Probá de nuevo.</span>),
  });
  const applyMut = useMutation({
    mutationFn: (fields: AiSuggestion) => applyAiSuggestion(ticketId as string, fields),
    onSuccess: (_row, fields) => {
      const n = Object.keys(fields).length;
      void qc.invalidateQueries({ queryKey: ["tickets"] });
      void qc.invalidateQueries({ queryKey: ["ticket", ticketId] });
      pushBot(<>Listo ✅ Apliqué la clasificación a <b>{ticketRef}</b> ({n} campo{n > 1 ? "s" : ""}). Quedó en la auditoría del ticket.</>);
    },
    onError: () => pushBot(<span style={{ color: C.red }}>No se pudo aplicar la sugerencia.</span>),
  });
  const assignMut = useMutation({
    mutationFn: () => assignTicket(ticketId as string),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["tickets"] });
      void qc.invalidateQueries({ queryKey: ["ticket", ticketId] });
      pushBot(<>Hecho — <b>{ticketRef}</b> queda asignado a {displayName ?? "vos"}.</>);
    },
    onError: () => pushBot(<span style={{ color: C.red }}>No se pudo asignar el ticket.</span>),
  });
  const closeMut = useMutation({
    mutationFn: () => requestClosure(ticketId as string),
    onSuccess: ({ link }) => {
      void qc.invalidateQueries({ queryKey: ["tickets"] });
      void qc.invalidateQueries({ queryKey: ["ticket", ticketId] });
      pushBot(<ClosureLink link={link} />);
    },
    onError: () => pushBot(<span style={{ color: C.red }}>No se pudo generar el enlace de cierre.</span>),
  });

  const ticket = ticketQ.data;
  const ticketRef = ticket?.public_ref ?? "el ticket";

  function applyClassification(s: AiSuggestion) {
    const fields: AiSuggestion = {};
    if (aiChecked.type && s.type) fields.type = s.type;
    if (aiChecked.priority && s.priority) fields.priority = s.priority;
    if (aiChecked.sentiment && s.sentiment) fields.sentiment = s.sentiment;
    if (aiChecked.service_slug && s.service_slug) fields.service_slug = s.service_slug;
    if (aiChecked.tags && s.tags?.length) fields.tags = s.tags;
    if (Object.keys(fields).length === 0) {
      pushBot(<span style={{ color: C.orange }}>Tildá al menos un campo para aplicar.</span>);
      return;
    }
    applyMut.mutate(fields);
  }

  // ── Entrada de texto: intents de triage sobre la cola real ───────────────────
  const [input, setInput] = useState("");

  // Responde un texto del usuario interpretando intents simples sobre la cola
  // real (no LLM: el asistente es un copiloto de triage, no el chat SOC).
  function respondIntent(v: string) {
    const breaches = attention.filter((t) => slaOf(t).kind === "breach");
    const unread = attention.filter((t) => Number(t.unread_client ?? 0) > 0);
    const angry = attention.filter((t) => t.sentiment && NEGATIVE_SENTIMENT.has(t.sentiment));
    if (/vencid|sla/i.test(v)) {
      pushBot(breaches.length
        ? <>Hay <b>{breaches.length}</b> con SLA vencido. El más crítico: {ticketLink(breaches[0], openTicket)}.</>
        : <>Ninguno con SLA vencido ahora mismo 👍</>);
    } else if (/sin leer|no le[íi]/i.test(v)) {
      pushBot(unread.length
        ? <>{unread.length} con mensajes sin leer: {unread.slice(0, 3).map((t, i) => <span key={t.id}>{i > 0 ? ", " : ""}{ticketLink(t, openTicket)}</span>)}.</>
        : <>No hay mensajes del cliente sin leer 👍</>);
    } else if (/molest|enojad|frustrad/i.test(v)) {
      pushBot(angry.length
        ? <>😠 {angry.length} cliente(s) con tono negativo. Te recomiendo empezar por {ticketLink(angry[0], openTicket)}.</>
        : <>Ningún cliente con sentimiento negativo en la cola 🙂</>);
    } else {
      pushBot(<>Puedo ayudarte a <b>clasificar</b>, <b>asignar</b>, <b>responder</b> o <b>cerrar</b> un ticket. Tocá uno de la cola o usá los botones de acción.</>);
    }
  }
  function sendUser() {
    const v = input.trim();
    if (!v) return;
    setInput("");
    pushUser(v);
    respondIntent(v);
  }
  // Chip de triage: muestra una pregunta legible y responde el intent.
  function askIntent(question: string, intent: string) {
    pushUser(question);
    respondIntent(intent);
  }

  // El disparador vive en el botón "Tickets" del header (TicketNotificationButton).
  // Cerrado = no se monta el panel.
  if (!open) return null;

  const headerSub = view === "ticket" && ticket
    ? `${ticket.public_ref} · ${ticket.org_name ?? "—"}`
    : "Triage de la cola · en línea";

  return (
    <AnimatePresence>
      <motion.section
        key="assistant-panel"
        ref={panelRef}
        initial={prefersReducedMotion ? false : { opacity: 0, y: 12, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={prefersReducedMotion ? undefined : { opacity: 0, y: 12, scale: 0.98 }}
        transition={{ duration: 0.18, ease: "easeOut" }}
        className="fixed bottom-6 right-6 z-50 flex h-[640px] max-h-[calc(100dvh-3rem)] w-[400px] max-w-[calc(100vw-2rem)] flex-col overflow-hidden rounded-2xl border shadow-2xl"
        style={{ background: C.card, borderColor: C.border }}
        role="dialog"
        aria-label="Asistente de Tickets"
      >
        {/* Header */}
        <header className="flex items-center gap-2.5 border-b px-4 py-3" style={{ borderColor: C.border, background: C.bg }}>
          <div className="relative grid h-8 w-8 place-items-center rounded-lg" style={{ background: `color-mix(in srgb, ${C.purple} 22%, transparent)` }}>
            <Sparkles className="h-4 w-4" style={{ color: C.purple }} aria-hidden />
            <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full" style={{ background: C.green, border: `2px solid ${C.card}` }} />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold leading-tight" style={{ color: C.text }}>Asistente de Tickets</div>
            <div className="truncate text-[11px] leading-tight" style={{ color: C.textDim }}>{headerSub}</div>
          </div>
          <div className="ml-auto flex items-center gap-1">
            {view === "ticket" && (
              <button onClick={showTriage} title="Volver a la cola" className="grid h-7 w-7 place-items-center rounded-md hover:bg-black/20" style={{ color: C.textDim }}>
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 12h18M3 6h18M3 18h18" /></svg>
              </button>
            )}
            <button onClick={close} title="Minimizar" className="grid h-7 w-7 place-items-center rounded-md hover:bg-black/20" style={{ color: C.textDim }}>
              <ChevronDown className="h-4 w-4" />
            </button>
          </div>
        </header>

        {/* Hilo */}
        <div ref={threadRef} className="flex-1 space-y-3 overflow-y-auto px-3 py-3">
          {view === "triage" ? (
            <TriageView
              loading={listLoading}
              attention={attention}
              following={following}
              name={displayName}
              onOpen={openTicket}
              slaKind={(t) => slaOf(t).kind}
            />
          ) : (
            <TicketView ticket={ticket} loading={ticketQ.isLoading} slaLabel={ticket ? slaOf(ticket).kind : "ok"} />
          )}

          {/* Log conversacional */}
          {log.map((e) => <Bubble key={e.id} side={e.side}>{e.content}</Bubble>)}

          {(classifyMut.isPending || assignMut.isPending || closeMut.isPending || applyMut.isPending) && (
            <Bubble side="bot"><Loader2 className="h-3.5 w-3.5 animate-spin" /></Bubble>
          )}
        </div>

        {/* Composer */}
        <footer className="border-t px-3 py-2.5" style={{ borderColor: C.border, background: C.bg }}>
          <div className="mb-2 flex flex-wrap gap-1.5">
            {view === "triage" ? (
              <>
                <Chip onClick={() => askIntent("¿Cuáles tienen SLA vencido?", "vencido")}>⚠ Vencidos</Chip>
                <Chip onClick={() => askIntent("¿Cuáles tienen mensajes sin leer?", "sin leer")}>✉ Sin leer</Chip>
                <Chip onClick={() => askIntent("¿Algún cliente molesto?", "molesto")}>😠 Clientes molestos</Chip>
              </>
            ) : (
              <>
                <Chip onClick={() => classifyMut.mutate()} disabled={classifyMut.isPending}>✨ Clasificar con IA</Chip>
                <Chip onClick={() => assignMut.mutate()} disabled={assignMut.isPending}>🙋 Asignármelo</Chip>
                <Chip onClick={() => { navigate(`/tickets?open=${ticketId}`); close(); }}>💬 Responder</Chip>
                <Chip onClick={() => closeMut.mutate()} disabled={closeMut.isPending}>✓ Cerrar</Chip>
              </>
            )}
          </div>
          <div className="flex items-end gap-2">
            <textarea
              rows={1}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendUser(); } }}
              placeholder="Escribí un mensaje o pedí una acción…"
              className="flex-1 resize-none rounded-lg border px-3 py-2 text-sm focus:outline-none"
              style={{ background: C.card, borderColor: C.border, color: C.text }}
            />
            <button onClick={sendUser} className="grid h-9 w-9 shrink-0 place-items-center rounded-lg text-white hover:brightness-110" style={{ background: C.blue }}>
              <Send className="h-4 w-4" />
            </button>
          </div>
          <div className="mt-1.5 text-center text-[10px]" style={{ color: C.textDim }}>
            Las acciones piden confirmación antes de aplicarse — nada se ejecuta solo.
          </div>
        </footer>
      </motion.section>
    </AnimatePresence>
  );

  // Tarjeta de clasificación IA (closure sobre aiChecked/applyClassification).
  function AiCard({ suggestion }: { suggestion: AiSuggestion }) {
    const conf = Math.round(suggestion.confidence ?? 0); // ya viene 0–100 (espejo de la ficha)
    const confColor = conf >= 85 ? C.green : conf >= 70 ? C.orange : C.red;
    const rows = AI_FIELDS.map((f) => {
      const val = aiFieldValue(suggestion, f);
      if (val == null) return null;
      return (
        <label key={f} className="flex cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-1.5" style={{ background: C.bg, borderColor: C.border }}>
          <input
            type="checkbox"
            checked={aiChecked[f]}
            onChange={(e) => setAiChecked((c) => ({ ...c, [f]: e.target.checked }))}
            className="h-4 w-4"
          />
          <span className="w-20 text-[12px]" style={{ color: C.textDim }}>{AI_FIELD_META[f].icon} {AI_FIELD_META[f].label}</span>
          <span className="flex-1 text-[13px] font-medium" style={{ color: C.text }}>{val}</span>
        </label>
      );
    }).filter(Boolean);
    return (
      <div className="rounded-xl border p-2.5" style={{ borderColor: `color-mix(in srgb, ${C.purple} 40%, transparent)`, background: `color-mix(in srgb, ${C.purple} 12%, ${C.card})` }}>
        <div className="flex items-center gap-1.5 text-[13px] font-semibold" style={{ color: C.purple }}>
          <Sparkles className="h-3.5 w-3.5" /> Clasificación por IA
          {conf > 0 && <span className="ml-auto text-[11px]" style={{ color: confColor }}>confianza {conf}%</span>}
        </div>
        {suggestion.summary && <p className="mt-1 text-[12px] italic" style={{ color: C.textDim }}>“{suggestion.summary}”</p>}
        <div className="mt-0.5 text-[10px]" style={{ color: C.textDim }}>
          Fuente: {suggestion.source === "llm" ? "modelo" : "heurística"} · revisá y destildá lo que no aplique
        </div>
        <div className="mt-2 space-y-1">{rows}</div>
        <div className="mt-2.5 flex gap-2">
          <button
            onClick={() => applyClassification(suggestion)}
            disabled={applyMut.isPending}
            className="flex flex-1 items-center justify-center gap-1 rounded-lg py-1.5 text-[13px] font-medium text-white hover:brightness-110"
            style={{ background: C.blue }}
          >
            <Check className="h-3.5 w-3.5" /> Aplicar lo tildado
          </button>
          <button onClick={() => classifyMut.mutate()} className="rounded-lg border px-3 text-[13px] hover:bg-black/20" style={{ borderColor: C.border, color: C.textDim }}>
            Re-analizar
          </button>
        </div>
      </div>
    );
  }
}

// ── Subcomponentes presentacionales ───────────────────────────────────────────

function Bubble({ side, children }: { side: "user" | "bot"; children: ReactNode }) {
  const mine = side === "user";
  return (
    <div className={`flex ${mine ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[88%] rounded-2xl px-3 py-2 text-[13px] leading-snug ${mine ? "rounded-br-sm text-white" : "rounded-bl-sm border"}`}
        style={mine ? { background: C.blue } : { background: C.bg, borderColor: C.border, color: C.text }}
      >
        {children}
      </div>
    </div>
  );
}

function Chip({ children, onClick, disabled }: { children: ReactNode; onClick: () => void; disabled?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="rounded-full border px-2.5 py-1 text-[12px] hover:brightness-110 disabled:opacity-50"
      style={{ background: C.card, borderColor: C.border, color: C.text }}
    >
      {children}
    </button>
  );
}

function TriageView({
  loading, attention, following, name, onOpen, slaKind,
}: {
  loading: boolean;
  attention: TicketRow[];
  following: TicketRow[];
  name: string | null;
  onOpen: (id: string) => void;
  slaKind: (t: TicketRow) => string;
}) {
  if (loading) return <Bubble side="bot"><Loader2 className="h-3.5 w-3.5 animate-spin" /></Bubble>;
  const greeting = `Buenas${name ? ` ${name.split(" ")[0]}` : ""} 👋 `;
  return (
    <>
      <Bubble side="bot">
        {greeting}
        {attention.length
          ? <>Tenés <b>{attention.length} ticket{attention.length > 1 ? "s" : ""} que necesita{attention.length > 1 ? "n" : ""} atención</b>. Los ordeno por urgencia:</>
          : following.length
            ? <>No hay tickets esperando al SOC ahora mismo. Estos los tenés <b>en seguimiento</b>:</>
            : <>No tenés tickets abiertos pendientes 🎉</>}
      </Bubble>
      {attention.slice(0, 8).map((t) => (
        <TriageCard key={t.id} t={t} kind={slaKind(t)} mode="attention" onOpen={onOpen} />
      ))}
      {following.length > 0 && (
        <>
          {attention.length > 0 && (
            <div className="px-1 pt-1 text-[11px] font-semibold" style={{ color: C.textDim }}>
              En seguimiento (pelota del cliente)
            </div>
          )}
          {following.slice(0, 6).map((t) => (
            <TriageCard key={t.id} t={t} kind={slaKind(t)} mode="following" onOpen={onOpen} />
          ))}
        </>
      )}
    </>
  );
}

// Tarjeta de un ticket en la lista de triage. mode distingue la "pelota":
// attention = acción del SOC; following = en seguimiento (pelota del cliente).
function TriageCard({
  t, kind, mode, onOpen,
}: {
  t: TicketRow;
  kind: string;
  mode: "attention" | "following";
  onOpen: (id: string) => void;
}) {
  const sla = kind === "breach" ? { txt: "SLA vencido", color: C.red }
    : kind === "warn" ? { txt: "SLA por vencer", color: C.orange }
      : kind === "client" ? { txt: "Espera cliente", color: C.textDim }
        : { txt: "En tiempo", color: C.green };
  const unread = Number(t.unread_client ?? 0);
  return (
    <button
      onClick={() => onOpen(t.id)}
      className="block w-full rounded-xl border px-3 py-2 text-left transition hover:brightness-110"
      style={{ background: C.bg, borderColor: C.border }}
    >
      <div className="flex items-center gap-2">
        <span className="font-mono text-[11px]" style={{ color: C.textDim }}>{t.public_ref}</span>
        <span className="text-[10px] font-semibold" style={{ color: sla.color }}>● {sla.txt}</span>
        {unread > 0 && (
          <span className="ml-auto rounded-full px-1.5 py-0.5 text-[10px]" style={{ background: `color-mix(in srgb, ${C.info} 20%, transparent)`, color: C.info }}>
            {unread} sin leer
          </span>
        )}
      </div>
      <div className="mt-0.5 truncate text-[13px] font-medium" style={{ color: C.text }}>{t.subject}</div>
      <div className="mt-1 flex items-center gap-2 text-[11px]" style={{ color: C.textDim }}>
        <span>{t.sentiment ? `${SENTIMENT_EMOJI[t.sentiment]} ` : ""}{t.org_name ?? "—"}</span>
        {mode === "attention" ? (
          <span className="rounded-full px-1.5 py-0.5 text-[10px]" style={{ background: `color-mix(in srgb, ${C.orange} 18%, transparent)`, color: C.orange }}>→ acción SOC</span>
        ) : (
          <span className="rounded-full px-1.5 py-0.5 text-[10px]" style={{ background: `color-mix(in srgb, ${C.green} 16%, transparent)`, color: C.green }}>en seguimiento</span>
        )}
      </div>
    </button>
  );
}

function TicketView({ ticket, loading, slaLabel }: { ticket: TicketDetail | undefined; loading: boolean; slaLabel: string }) {
  if (loading || !ticket) return <Bubble side="bot"><Loader2 className="h-3.5 w-3.5 animate-spin" /></Bubble>;
  const slaTxt = slaLabel === "breach" ? "SLA vencido" : slaLabel === "warn" ? "SLA por vencer" : slaLabel === "client" ? "Espera cliente" : "En tiempo";
  const messages = ticket.messages ?? [];
  return (
    <>
      <Bubble side="bot">
        Abrí <b>{ticket.public_ref}</b> — “{ticket.subject}”.<br />
        <span className="text-[12px]" style={{ color: C.textDim }}>
          {ticket.org_name ?? "—"} · prioridad {PRIORITY_LABEL[ticket.priority]} · {STATUS_LABEL[ticket.status]} · {slaTxt}
        </span>
      </Bubble>
      {messages.map((m) => {
        const mine = m.author_type === "SOC";
        const sys = m.author_type === "SYSTEM";
        if (sys) {
          return (
            <div key={m.id} className="text-center text-[10px]" style={{ color: C.textDim }}>
              {m.body} · {fmtTime(m.created_at)}
            </div>
          );
        }
        return (
          <Bubble key={m.id} side={mine ? "user" : "bot"}>
            <div className={`mb-0.5 text-[10px] font-semibold ${mine ? "text-white/80" : ""}`} style={mine ? undefined : { color: C.textDim }}>
              {mine ? `🛡️ ${m.author_name ?? "Analista"} · Analista` : `👤 ${m.author_name ?? "Cliente"} · Cliente`}
            </div>
            {m.body}
            <div className={`mt-0.5 text-right text-[10px] ${mine ? "text-white/60" : ""}`} style={mine ? undefined : { color: C.textDim }}>
              {fmtTime(m.created_at)}
            </div>
          </Bubble>
        );
      })}
      <Bubble side="bot">¿Qué hacemos con este ticket? Puedo proponer acciones — todas requieren tu visto bueno.</Bubble>
    </>
  );
}

function ClosureLink({ link }: { link: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      Para cerrar generé el <b>enlace de confirmación del cliente</b> (sign-off). El SOC no cierra directo — el cliente debe abrirlo:
      <div className="mt-2 flex items-center gap-2 rounded-lg border px-2 py-1.5" style={{ borderColor: C.border, background: C.bg }}>
        <span className="flex-1 truncate font-mono text-[11px]" style={{ color: C.textDim }}>{link}</span>
        <button
          onClick={() => { void navigator.clipboard?.writeText(link).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }); }}
          className="grid h-6 w-6 place-items-center rounded hover:bg-black/20"
          style={{ color: copied ? C.green : C.textDim }}
          title="Copiar"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      </div>
    </div>
  );
}

// Enlace inline a un ticket dentro de una respuesta del bot.
function ticketLink(t: TicketRow, onOpen: (id: string) => void): ReactNode {
  return (
    <button onClick={() => onOpen(t.id)} className="font-mono font-semibold underline" style={{ color: C.blue }}>
      {t.public_ref}
    </button>
  );
}
