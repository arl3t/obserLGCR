/**
 * TicketsPage.tsx — F3 + bloque "ordenar y clasificar tickets" (20 mejoras).
 *
 * Cola de tickets con clasificación (tipo/servicio/etiquetas/severidad técnica),
 * orden inteligente (score de cola, buckets de SLA, fijar, vistas guardadas,
 * agrupación, layout tabla/Kanban) y workflow (acciones masivas, snooze, reglas,
 * watchers, IA). El detalle reúne la conversación, clasificación, duplicados y más.
 *
 * Superficie INTERNA (auth en router.tsx). Ver docs/PROPUESTA-TICKETING-PUBLICO.md.
 */
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import {
  Ticket as TicketIcon, RefreshCw, Send, Link2, UserPlus, ShieldAlert,
  MessageSquare, Loader2, ArrowRight, FolderOpen, FileText, X, Pin,
  LayoutGrid, Table as TableIcon, Star, Save, ChevronDown, ChevronRight,
  BookOpen, RotateCw, Building2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { formatDateTimePy } from "@/lib/format";
import {
  listTickets, getTicket, replyTicket, transitionTicket, linkCase, assignTicket,
  createActionRequest, listTemplates, getMessageReportHtml,
  getCaseReportHtml, sendReportToTicket, getCommSlaConfig,
  getCasePlaybookHtml, sendPlaybookToTicket, getMessagePlaybookHtml, markTicketRead,
  listServices, getTagCloud, listSavedViews, createSavedView, deleteSavedView,
  getUserPrefs, setUserPrefs, pinTicket, bulkUpdate, setCcContacts, requestClosure,
} from "@/api/tickets";
import {
  computeSla, fmtCountdown, compareTickets, slaBucket,
  makeMultiSort, SLA_BUCKET_LABEL, type SlaBucket, type SlaState,
} from "@/components/tickets/ticket-sla";
import { cn } from "@/lib/utils";
import { useSocOperators } from "@/hooks/useSocWorkflow";
import { TicketCommMetricsPanel } from "@/components/tickets/TicketCommMetricsPanel";
import { ReportIframeModal } from "@/components/tickets/ReportIframeModal";
import { TicketKanban } from "@/components/tickets/TicketKanban";
import {
  ClassificationEditor, AiSuggestPanel, DuplicatesPanel, WatchersBar, SnoozeControl,
} from "@/components/tickets/TicketDetailExtras";
import {
  fmtDuration, PRIORITY_COLOR, STATUS_COLOR, WAITING_COLOR, ACTION_STATUS_COLOR,
  SLA_COLOR, SLA_ROW_BG, slaAccent,
} from "@/components/tickets/ticket-format";
import { C, alpha } from "@/lib/cm-theme";
import {
  STATUS_LABEL, WAITING_LABEL, PRIORITY_LABEL, ACTION_TYPE_LABEL, ACTION_STATUS_LABEL,
  TYPE_LABEL, TYPE_COLOR, CHANNEL_LABEL, SENTIMENT_EMOJI,
} from "@/components/tickets/types";
import type {
  TicketRow, TicketStatus, TicketDetail, ActionType, TicketPriority, Visibility,
  TicketType, SortRule, WaitingOn, TicketMessage,
} from "@/components/tickets/types";

// Transiciones válidas (espejo de services/ticketService.mjs VALID_TRANSITIONS).
const NEXT_STATUS: Record<TicketStatus, TicketStatus[]> = {
  ABIERTO: ["EN_ATENCION", "ESPERANDO_CLIENTE", "RESUELTO", "CERRADO"],
  EN_ATENCION: ["ESPERANDO_CLIENTE", "RESUELTO", "CERRADO"],
  ESPERANDO_CLIENTE: ["EN_ATENCION", "RESUELTO", "CERRADO"],
  RESUELTO: ["CERRADO", "REABIERTO"],
  REABIERTO: ["EN_ATENCION", "RESUELTO", "CERRADO"],
  CERRADO: ["REABIERTO"],
};

const ACTION_TYPES: ActionType[] = [
  "CONTENCION_FIREWALL", "AISLAR_HOST", "BLOQUEO_IOC", "RESET_CREDENCIALES",
  "APLICAR_PARCHE", "DESHABILITAR_CUENTA", "DESHABILITAR_SERVICIO", "OTRO",
];

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error desconocido";
}

const SELECT_CLS = "h-8 rounded-md border bg-card px-2 text-sm text-foreground";

// (#9) Sentimientos que ameritan elevar la fila a alerta (cliente molesto).
const NEGATIVE_SENTIMENT = new Set(["ENOJADO", "FRUSTRADO"]);

// ── Helpers de identidad (#1/#2) ──────────────────────────────────────────────
/** Iniciales para el avatar (2 letras: primera y última palabra). */
function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

/** Color de avatar estable por nombre (hash → paleta de tema). */
function avatarColor(name: string): string {
  const palette = [C.purple, C.cyan, C.blue, C.green, C.orange];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}

/** Avatar de iniciales + nombre del analista. */
function AnalystChip({ name, subtle }: { name: string; subtle?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 align-middle">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[9px] font-bold text-white"
        style={{ background: avatarColor(name) }}>{initialsOf(name)}</span>
      <span className={cn("truncate", subtle ? "text-muted-foreground" : "font-medium text-foreground")}>{name}</span>
    </span>
  );
}

/** (#4) Pelota direccional: deja claro de qué lado está la acción. */
function WaitingPill({ w }: { w: WaitingOn }) {
  if (w === "NONE") return <span className="text-xs text-muted-foreground">—</span>;
  const soc = w === "SOC";
  const color = WAITING_COLOR[w];
  return (
    <span className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold"
      style={{ color, borderColor: color, background: alpha(color, 8) }}
      title={soc ? "La pelota está del lado del SOC" : "Esperando al cliente"}>
      {soc ? "→ Acción SOC" : "Esperando cliente"}
    </span>
  );
}

/** (#1) Autor del mensaje con nombre real del analista/cliente + avatar. */
function MessageAuthor({ m }: { m: TicketMessage }) {
  if (m.author_type === "SYSTEM") return <span className="text-muted-foreground">Sistema</span>;
  const isClient = m.author_type === "CLIENT";
  const name = (m.author_name && m.author_name.trim()) || (isClient ? "Cliente" : "SOC");
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[9px] font-bold text-white"
        style={{ background: isClient ? C.blue : avatarColor(name) }}>{initialsOf(name)}</span>
      <span className="font-semibold text-foreground">{name}</span>
      <span className="rounded bg-muted px-1 text-[9px] font-medium uppercase text-muted-foreground">
        {isClient ? "Cliente" : "Analista"}
      </span>
    </span>
  );
}

// (#11) Modos de agrupación.
type GroupMode = "none" | "status" | "priority" | "assigned" | "service" | "type" | "sla";
const GROUP_LABEL: Record<GroupMode, string> = {
  none: "Sin agrupar", status: "Estado", priority: "Prioridad", assigned: "Asignado",
  service: "Servicio", type: "Tipo", sla: "SLA",
};
// (#12) Modos de orden (persistidos por usuario).
type SortMode = "smart" | "score" | "newest" | "priority" | "updated";
const SORT_LABEL: Record<SortMode, string> = {
  smart: "Inteligente (SLA)", score: "Score de cola", newest: "Más nuevos",
  priority: "Prioridad", updated: "Actividad",
};
const SORT_RULES: Record<SortMode, SortRule[]> = {
  smart: [], // usa compareTickets
  score: [{ col: "score", dir: "desc" }],
  newest: [{ col: "created_at", dir: "desc" }],
  priority: [{ col: "priority", dir: "desc" }, { col: "sla", dir: "asc" }],
  updated: [{ col: "updated_at", dir: "desc" }],
};

export function TicketsPage() {
  const qc = useQueryClient();
  const { data: operators = [] } = useSocOperators();

  // Filtros
  const [status, setStatus] = useState<TicketStatus | "">("");
  const [waitingOn, setWaitingOn] = useState<"" | "SOC" | "CLIENT" | "NONE">("");
  const [type, setType] = useState<TicketType | "">("");
  const [service, setService] = useState("");
  const [tag, setTag] = useState("");
  const [channel, setChannel] = useState("");
  const [mine, setMine] = useState(false);
  const [onlyUnread, setOnlyUnread] = useState(false);
  const [search, setSearch] = useState("");
  // Orden / agrupación / layout
  const [groupMode, setGroupMode] = useState<GroupMode>("none");
  const [sortMode, setSortMode] = useState<SortMode>("smart");
  const [layout, setLayout] = useState<"table" | "kanban">("table");
  // Selección masiva (#17) + detalle
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Deep-link ?open=<id> — el Asistente de Tickets (launcher flotante) delega
  // aquí "Responder / abrir ficha completa". Consume el parámetro una sola vez.
  const [searchParams, setSearchParams] = useSearchParams();
  useEffect(() => {
    const openId = searchParams.get("open");
    if (openId) {
      setSelectedId(openId);
      searchParams.delete("open");
      setSearchParams(searchParams, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Datos de apoyo
  const slaQ = useQuery({ queryKey: ["ticket-sla-config"], queryFn: () => getCommSlaConfig(), staleTime: 300_000 });
  const servicesQ = useQuery({ queryKey: ["ticket-services"], queryFn: () => listServices(), staleTime: 300_000 });
  const tagCloudQ = useQuery({ queryKey: ["ticket-tag-cloud"], queryFn: () => getTagCloud(40), staleTime: 120_000 });
  const viewsQ = useQuery({ queryKey: ["ticket-views"], queryFn: () => listSavedViews(), staleTime: 120_000 });
  const prefsQ = useQuery({ queryKey: ["ticket-prefs"], queryFn: () => getUserPrefs(), staleTime: 300_000 });

  // Sembrar layout + orden desde prefs una sola vez.
  useEffect(() => {
    if (!prefsQ.data) return;
    if (prefsQ.data.layout) setLayout(prefsQ.data.layout);
    const s = prefsQ.data.sort?.[0]?.col;
    const found = (Object.keys(SORT_RULES) as SortMode[]).find((k) => SORT_RULES[k][0]?.col === s);
    if (found) setSortMode(found);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefsQ.data?.operator_ci]);

  const listQ = useQuery({
    queryKey: ["tickets", status, waitingOn, type, service, tag, mine],
    queryFn: () => listTickets({ status, waitingOn, type, service, tag, mine, limit: 300 }),
    staleTime: 20_000,
  });

  // Reloj para la cuenta regresiva.
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 15_000);
    return () => clearInterval(id);
  }, []);

  const cfg = slaQ.data ?? null;
  const slaOf = (t: TicketRow) => computeSla(t, cfg, nowMs);

  const rows = useMemo(() => {
    const all = listQ.data ?? [];
    const q = search.trim().toLowerCase();
    let filtered = all.filter((t) => {
      if (channel && t.channel !== channel) return false;
      if (onlyUnread && !(Number(t.unread_client ?? 0) > 0)) return false;
      if (q && !(
        t.public_ref.toLowerCase().includes(q) ||
        t.subject.toLowerCase().includes(q) ||
        (t.tags ?? []).some((tg) => tg.includes(q)) ||
        (t.primary_case_id ?? "").toLowerCase().includes(q)
      )) return false;
      return true;
    });
    // Pinned siempre arriba; dentro de cada grupo, el orden elegido.
    const cmp = sortMode === "smart"
      ? (a: TicketRow, b: TicketRow) => compareTickets(a, b, slaOf)
      : makeMultiSort(SORT_RULES[sortMode], slaOf);
    filtered = [...filtered].sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      return cmp(a, b);
    });
    return filtered;
  }, [listQ.data, search, channel, onlyUnread, sortMode, cfg, nowMs]); // eslint-disable-line react-hooks/exhaustive-deps

  // (#8) Resumen de alertas accionables sobre la cola ya filtrada.
  const alerts = useMemo(() => {
    let breach = 0, unread = 0, waitingSoc = 0, angry = 0;
    for (const t of rows) {
      if (slaOf(t).kind === "breach") breach++;
      if (Number(t.unread_client ?? 0) > 0) unread++;
      if (t.waiting_on === "SOC") waitingSoc++;
      if (t.sentiment && NEGATIVE_SENTIMENT.has(t.sentiment)) angry++;
    }
    return { breach, unread, waitingSoc, angry };
  }, [rows, cfg, nowMs]); // eslint-disable-line react-hooks/exhaustive-deps

  // (#11) Agrupación.
  const groups = useMemo(() => groupRows(rows, groupMode, slaOf, servicesNameMap(servicesQ.data)), [rows, groupMode, servicesQ.data, nowMs]); // eslint-disable-line react-hooks/exhaustive-deps

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ["tickets"] });
    void qc.invalidateQueries({ queryKey: ["ticket-comm-metrics"] });
    void qc.invalidateQueries({ queryKey: ["ticket-action-metrics"] });
    void qc.invalidateQueries({ queryKey: ["ticket-tag-cloud"] });
    if (selectedId) void qc.invalidateQueries({ queryKey: ["ticket", selectedId] });
  }

  const pinMut = useMutation({
    mutationFn: ({ id, pinned }: { id: string; pinned: boolean }) => pinTicket(id, pinned),
    onSuccess: invalidate,
    onError: (e) => toast.error(errMsg(e)),
  });
  const moveMut = useMutation({
    mutationFn: ({ id, to }: { id: string; to: TicketStatus }) => transitionTicket(id, { toStatus: to }),
    onSuccess: () => { toast.success("Estado actualizado"); invalidate(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  function persistLayout(l: "table" | "kanban") {
    setLayout(l);
    void setUserPrefs({ layout: l }).then(() => qc.invalidateQueries({ queryKey: ["ticket-prefs"] }));
  }
  function persistSort(s: SortMode) {
    setSortMode(s);
    void setUserPrefs({ sort: SORT_RULES[s] }).then(() => qc.invalidateQueries({ queryKey: ["ticket-prefs"] }));
  }

  function toggleSel(id: string) {
    setSelected((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  function applySavedView(filters: Record<string, string>) {
    setStatus((filters.status as TicketStatus) ?? "");
    setWaitingOn((filters.waitingOn as "SOC" | "CLIENT" | "NONE") ?? "");
    setType((filters.type as TicketType) ?? "");
    setService(filters.service ?? "");
    setTag(filters.tag ?? "");
    setChannel(filters.channel ?? "");
    setMine(filters.mine === "true");
  }

  const saveViewMut = useMutation({
    mutationFn: (name: string) => createSavedView({
      name,
      filters: { status, waitingOn, type, service, tag, channel, mine: String(mine) },
      sort: SORT_RULES[sortMode],
    }),
    onSuccess: () => { toast.success("Vista guardada"); void qc.invalidateQueries({ queryKey: ["ticket-views"] }); },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="flex flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <TicketIcon className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-xl font-semibold">Tickets</h1>
            <p className="text-sm text-muted-foreground">
              Clasificación, priorización y comunicación con el cliente vinculada a casos
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <Button variant={layout === "table" ? "secondary" : "ghost"} size="sm" onClick={() => persistLayout("table")}>
            <TableIcon className="h-4 w-4" /> Tabla
          </Button>
          <Button variant={layout === "kanban" ? "secondary" : "ghost"} size="sm" onClick={() => persistLayout("kanban")}>
            <LayoutGrid className="h-4 w-4" /> Kanban
          </Button>
          <Button variant="ghost" size="sm" onClick={() => void listQ.refetch()}>
            <RefreshCw className="h-4 w-4" /> Actualizar
          </Button>
        </div>
      </div>

      {/* F4 — métricas de comunicación */}
      <TicketCommMetricsPanel days={30} />

      {/* Vistas guardadas (#10) */}
      <div className="flex flex-wrap items-center gap-2">
        <Star className="h-4 w-4 text-amber-400" />
        <span className="text-xs text-muted-foreground">Vistas:</span>
        {(viewsQ.data ?? []).map((v) => (
          <span key={v.id} className="group inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs">
            <button onClick={() => applySavedView(v.filters)}>{v.name}{v.is_shared && " ·🌐"}</button>
            {!v.is_shared && (
              <button className="opacity-0 group-hover:opacity-100"
                onClick={() => deleteSavedView(v.id).then(() => qc.invalidateQueries({ queryKey: ["ticket-views"] }))}>
                <X className="h-3 w-3" />
              </button>
            )}
          </span>
        ))}
        <Button size="sm" variant="ghost" className="h-7"
          onClick={() => { const n = prompt("Nombre de la vista:"); if (n?.trim()) saveViewMut.mutate(n.trim()); }}>
          <Save className="h-3.5 w-3.5" /> Guardar vista
        </Button>
      </div>

      {/* Filtros */}
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant={mine ? "secondary" : "outline"} className="h-8" onClick={() => setMine((m) => !m)}>
          {mine ? "Mi cola" : "Todos"}
        </Button>
        <select className={SELECT_CLS} value={status} onChange={(e) => setStatus(e.target.value as TicketStatus | "")}>
          <option value="">Estado: todos</option>
          {Object.keys(STATUS_LABEL).map((s) => <option key={s} value={s}>{STATUS_LABEL[s as TicketStatus]}</option>)}
        </select>
        <select className={SELECT_CLS} value={type} onChange={(e) => setType(e.target.value as TicketType | "")}>
          <option value="">Tipo: todos</option>
          {(Object.keys(TYPE_LABEL) as TicketType[]).map((k) => <option key={k} value={k}>{TYPE_LABEL[k]}</option>)}
        </select>
        <select className={SELECT_CLS} value={service} onChange={(e) => setService(e.target.value)}>
          <option value="">Servicio: todos</option>
          {(servicesQ.data ?? []).map((s) => <option key={s.id} value={s.slug}>{s.name}</option>)}
        </select>
        <select className={SELECT_CLS} value={channel} onChange={(e) => setChannel(e.target.value)}>
          <option value="">Canal: todos</option>
          {Object.keys(CHANNEL_LABEL).map((c) => <option key={c} value={c}>{CHANNEL_LABEL[c]}</option>)}
        </select>
        <select className={SELECT_CLS} value={waitingOn} onChange={(e) => setWaitingOn(e.target.value as typeof waitingOn)}>
          <option value="">Pelota: cualquiera</option>
          <option value="SOC">Espera SOC</option>
          <option value="CLIENT">Espera cliente</option>
          <option value="NONE">Sin pendiente</option>
        </select>
        <Input className="h-8 w-56" placeholder="Buscar ref / asunto / etiqueta / caso…" value={search} onChange={(e) => setSearch(e.target.value)} />
        {tag && (
          <Badge variant="outline" className="gap-1">#{tag}<button onClick={() => setTag("")}><X className="h-3 w-3" /></button></Badge>
        )}
        <div className="ml-auto flex items-center gap-2">
          <select className={SELECT_CLS} value={groupMode} onChange={(e) => setGroupMode(e.target.value as GroupMode)}>
            {(Object.keys(GROUP_LABEL) as GroupMode[]).map((g) => <option key={g} value={g}>Agrupar: {GROUP_LABEL[g]}</option>)}
          </select>
          <select className={SELECT_CLS} value={sortMode} onChange={(e) => persistSort(e.target.value as SortMode)}>
            {(Object.keys(SORT_LABEL) as SortMode[]).map((s) => <option key={s} value={s}>Orden: {SORT_LABEL[s]}</option>)}
          </select>
          <span className="text-xs text-muted-foreground">{rows.length}</span>
        </div>
      </div>

      {/* Nube de etiquetas (#2) */}
      {(tagCloudQ.data?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          {tagCloudQ.data!.map((tc) => (
            <button key={tc.tag}
              className={cn("rounded-full border px-2 py-0.5 text-[11px] hover:bg-muted/40",
                tag === tc.tag && "border-cyan-500 text-cyan-400")}
              onClick={() => setTag(tag === tc.tag ? "" : tc.tag)}>
              #{tc.tag} <span className="text-muted-foreground">{tc.n}</span>
            </button>
          ))}
        </div>
      )}

      {/* (#8) Tira de alertas accionables */}
      {(alerts.breach > 0 || alerts.unread > 0 || alerts.waitingSoc > 0 || alerts.angry > 0) && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-xs">
          <span className="font-medium text-muted-foreground">Atención:</span>
          {alerts.breach > 0 && (
            <button
              className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-semibold"
              style={{ color: SLA_COLOR.breach, borderColor: SLA_COLOR.breach, background: alpha(C.red, 8) }}
              onClick={() => setGroupMode("sla")}
              title="Agrupar por SLA para ver los vencidos arriba">
              ⚠ {alerts.breach} vencido{alerts.breach > 1 ? "s" : ""} (SLA)
            </button>
          )}
          {alerts.unread > 0 && (
            <button
              className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-semibold",
                onlyUnread && "ring-1 ring-cyan-400")}
              style={{ color: C.cyan, borderColor: C.cyan, background: alpha(C.cyan, 8) }}
              onClick={() => setOnlyUnread((v) => !v)}
              title="Filtrar tickets con mensajes nuevos del cliente sin leer">
              ✉ {alerts.unread} sin leer del cliente
            </button>
          )}
          {alerts.waitingSoc > 0 && (
            <button
              className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-semibold",
                waitingOn === "SOC" && "ring-1 ring-amber-400")}
              style={{ color: C.orange, borderColor: C.orange, background: alpha(C.orange, 8) }}
              onClick={() => setWaitingOn((w) => (w === "SOC" ? "" : "SOC"))}
              title="Filtrar tickets cuya pelota está del lado del SOC">
              → {alerts.waitingSoc} esperan al SOC
            </button>
          )}
          {alerts.angry > 0 && (
            <span
              className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-semibold"
              style={{ color: C.red, borderColor: C.red, background: alpha(C.red, 8) }}
              title="Tickets con cliente frustrado o enojado">
              😠 {alerts.angry} cliente{alerts.angry > 1 ? "s" : ""} molesto{alerts.angry > 1 ? "s" : ""}
            </span>
          )}
        </div>
      )}

      {/* Barra de acciones masivas (#17) */}
      {selected.size > 0 && (
        <BulkActionBar
          ids={[...selected]} operators={operators}
          onDone={() => { setSelected(new Set()); invalidate(); }}
          onClear={() => setSelected(new Set())}
        />
      )}

      {/* Contenido */}
      {listQ.isLoading ? (
        <div className="space-y-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : rows.length === 0 ? (
        <Card><CardContent className="p-8 text-center text-sm text-muted-foreground">No hay tickets para el filtro actual.</CardContent></Card>
      ) : layout === "kanban" ? (
        <TicketKanban rows={rows} slaOf={slaOf} onSelect={setSelectedId} onMove={(id, to) => moveMut.mutate({ id, to })} />
      ) : (
        <div className="space-y-4">
          {groups.map((g) => (
            <TicketGroup key={g.key} group={g} slaOf={slaOf}
              selected={selected} onToggleSel={toggleSel}
              onSelect={setSelectedId} onPin={(id, p) => pinMut.mutate({ id, pinned: p })} />
          ))}
        </div>
      )}

      {/* Detalle */}
      <Sheet open={selectedId !== null} onOpenChange={(o) => !o && setSelectedId(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          {selectedId && <TicketDetailPanel ticketId={selectedId} services={servicesQ.data ?? []} onChanged={invalidate} />}
        </SheetContent>
      </Sheet>
    </div>
  );
}

// ── Agrupación ──────────────────────────────────────────────────────────────
interface Group { key: string; label: string; color?: string; rows: TicketRow[] }

function servicesNameMap(services?: { slug: string; name: string }[]): Record<string, string> {
  const m: Record<string, string> = {};
  for (const s of services ?? []) m[s.slug] = s.name;
  return m;
}

function groupRows(rows: TicketRow[], mode: GroupMode, slaOf: (t: TicketRow) => SlaState, svcNames: Record<string, string>): Group[] {
  if (mode === "none") return [{ key: "all", label: "", rows }];
  const map = new Map<string, Group>();
  const put = (key: string, label: string, t: TicketRow, color?: string) => {
    if (!map.has(key)) map.set(key, { key, label, color, rows: [] });
    map.get(key)!.rows.push(t);
  };
  for (const t of rows) {
    if (mode === "status") put(t.status, STATUS_LABEL[t.status], t, STATUS_COLOR[t.status]);
    else if (mode === "priority") put(t.priority, PRIORITY_LABEL[t.priority], t, PRIORITY_COLOR[t.priority]);
    else if (mode === "type") put(t.ticket_type, TYPE_LABEL[t.ticket_type], t, TYPE_COLOR[t.ticket_type]);
    else if (mode === "assigned") put(t.assigned_operator ?? "—", t.assigned_operator ? (t.assigned_operator_name ?? t.assigned_operator) : "Sin asignar", t);
    else if (mode === "service") put(t.service_slug ?? "—", t.service_name ?? svcNames[t.service_slug ?? ""] ?? "Sin servicio", t);
    else if (mode === "sla") { const b = slaBucket(slaOf(t)); put(b, SLA_BUCKET_LABEL[b as SlaBucket], t, SLA_COLOR[slaOf(t).kind]); }
  }
  // Orden de buckets de SLA: vencidos → por vencer → en tiempo → sin reloj.
  const order: Record<string, number> = { breach: 0, soon: 1, ontime: 2, other: 3 };
  return [...map.values()].sort((a, b) => (order[a.key] ?? 99) - (order[b.key] ?? 99) || b.rows.length - a.rows.length);
}

function TicketGroup({ group, slaOf, selected, onToggleSel, onSelect, onPin }: {
  group: Group; slaOf: (t: TicketRow) => SlaState;
  selected: Set<string>; onToggleSel: (id: string) => void; onSelect: (id: string) => void;
  onPin: (id: string, pinned: boolean) => void;
}) {
  const [open, setOpen] = useState(true);
  const hasHeader = group.label !== "";
  return (
    <Card>
      {hasHeader && (
        <button className="flex w-full items-center gap-2 border-b px-3 py-2 text-left text-sm font-medium hover:bg-muted/20"
          onClick={() => setOpen((o) => !o)}>
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <span style={{ color: group.color }}>{group.label}</span>
          <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">{group.rows.length}</span>
        </button>
      )}
      {open && (
        <CardContent className="p-0">
          <table className="w-full text-sm">
            <thead className="border-b text-left text-xs text-muted-foreground">
              <tr>
                <th className="p-2 w-8"></th>
                <th className="p-2">SLA</th>
                <th className="p-2">Ref</th><th className="p-2">Asunto</th>
                <th className="p-2">Tipo</th><th className="p-2">Prioridad</th>
                <th className="p-2">Estado</th><th className="p-2">Pelota</th>
                <th className="p-2">Asignado</th><th className="p-2">Caso</th>
                <th className="p-2 w-8"></th>
              </tr>
            </thead>
            <tbody>
              {group.rows.map((t) => {
                const sla = slaOf(t);
                const angry = !!t.sentiment && NEGATIVE_SENTIMENT.has(t.sentiment);
                return (
                  <tr key={t.id}
                    className={cn("cursor-pointer border-b border-l-4 hover:bg-muted/30",
                      angry ? "bg-red-500/[0.06]" : SLA_ROW_BG[sla.kind],
                      t.pinned && "bg-amber-500/[0.04]")}
                    style={{ borderLeftColor: angry ? C.red : slaAccent(sla.kind) }}
                    onClick={() => onSelect(t.id)}>
                    <td className="p-2" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(t.id)} onChange={() => onToggleSel(t.id)} />
                    </td>
                    <td className="p-2">
                      {sla.metric ? (
                        <span className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-semibold tabular-nums"
                          style={{ color: SLA_COLOR[sla.kind], borderColor: SLA_COLOR[sla.kind] }}>
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: SLA_COLOR[sla.kind] }} />
                          {fmtCountdown(sla.remainingSec)}
                          <span className="text-[10px] font-normal opacity-70">{sla.metric}</span>
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">{sla.label}</span>
                      )}
                    </td>
                    <td className="p-2 font-mono text-xs">
                      <span className="inline-flex items-center gap-1">
                        {t.pinned && <Pin className="h-3 w-3 text-amber-500" fill="currentColor" />}
                        {t.public_ref}
                      </span>
                    </td>
                    <td className="p-2 max-w-[16rem]">
                      <div className="flex items-center gap-1.5">
                        {Number(t.unread_client ?? 0) > 0 && (
                          <span title={`${t.unread_client} mensaje(s) nuevo(s) del cliente sin leer`}
                            className="inline-flex h-4 min-w-[1rem] shrink-0 animate-pulse items-center justify-center rounded-full bg-cyan-500 px-1 text-[10px] font-bold text-white">
                            {t.unread_client}
                          </span>
                        )}
                        <div className={cn("truncate", Number(t.unread_client ?? 0) > 0 && "font-semibold")}>{t.subject}</div>
                      </div>
                      {(t.tags ?? []).length > 0 && (
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {t.tags!.slice(0, 3).map((tg) => <span key={tg} className="rounded bg-muted px-1 text-[10px] text-muted-foreground">#{tg}</span>)}
                        </div>
                      )}
                    </td>
                    <td className="p-2">
                      <span className="rounded px-1.5 py-0.5 text-[11px] font-medium"
                        style={{ color: TYPE_COLOR[t.ticket_type], background: `${TYPE_COLOR[t.ticket_type]}18` }}>
                        {TYPE_LABEL[t.ticket_type]}
                      </span>
                    </td>
                    <td className="p-2">
                      <span className="inline-flex items-center gap-1">
                        <Badge variant="outline" style={{ color: PRIORITY_COLOR[t.priority], borderColor: PRIORITY_COLOR[t.priority] }}>{PRIORITY_LABEL[t.priority]}</Badge>
                        {angry ? (
                          <span className="inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
                            title={t.sentiment ?? undefined}
                            style={{ color: C.red, background: alpha(C.red, 12) }}>
                            {t.sentiment && SENTIMENT_EMOJI[t.sentiment]} molesto
                          </span>
                        ) : (
                          t.sentiment && t.sentiment !== "NEUTRAL" && <span title={t.sentiment}>{SENTIMENT_EMOJI[t.sentiment]}</span>
                        )}
                      </span>
                    </td>
                    <td className="p-2"><Badge variant="outline" style={{ color: STATUS_COLOR[t.status], borderColor: STATUS_COLOR[t.status] }}>{STATUS_LABEL[t.status]}</Badge></td>
                    <td className="p-2"><WaitingPill w={t.waiting_on} /></td>
                    <td className="p-2 text-xs">
                      {t.assigned_operator
                        ? <AnalystChip name={t.assigned_operator_name ?? t.assigned_operator} />
                        : <span className="font-medium text-amber-500">Sin asignar</span>}
                    </td>
                    <td className="p-2 font-mono text-xs">{t.primary_case_id ?? "—"}</td>
                    <td className="p-2" onClick={(e) => e.stopPropagation()}>
                      <button title={t.pinned ? "Desfijar" : "Fijar"} onClick={() => onPin(t.id, !t.pinned)}>
                        <Pin className={cn("h-3.5 w-3.5", t.pinned ? "text-amber-500" : "text-muted-foreground")} fill={t.pinned ? "currentColor" : "none"} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </CardContent>
      )}
    </Card>
  );
}

// ── Barra de acciones masivas (#17) ───────────────────────────────────────────
function BulkActionBar({ ids, operators, onDone, onClear }: {
  ids: string[]; operators: { id: string; name: string; is_active: boolean }[];
  onDone: () => void; onClear: () => void;
}) {
  const [op, setOp] = useState("");
  const [prio, setPrio] = useState("");
  const [tag, setTag] = useState("");
  const mut = useMutation({
    mutationFn: (body: Parameters<typeof bulkUpdate>[1]) => bulkUpdate(ids, body),
    onSuccess: (r) => { toast.success(`${r.affected}/${r.total} tickets actualizados`); onDone(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-cyan-500/40 bg-cyan-500/[0.05] p-2 text-sm">
      <span className="font-medium">{ids.length} seleccionados</span>
      <select className={SELECT_CLS} value={op} onChange={(e) => setOp(e.target.value)}>
        <option value="">Reasignar a…</option>
        {operators.filter((o) => o.is_active).map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
      </select>
      <Button size="sm" variant="outline" disabled={!op || mut.isPending} onClick={() => mut.mutate({ assignedOperator: op })}>Asignar</Button>
      <select className={SELECT_CLS} value={prio} onChange={(e) => setPrio(e.target.value)}>
        <option value="">Prioridad…</option>
        {(["URGENT", "HIGH", "MEDIUM", "LOW"] as TicketPriority[]).map((p) => <option key={p} value={p}>{PRIORITY_LABEL[p]}</option>)}
      </select>
      <Button size="sm" variant="outline" disabled={!prio || mut.isPending} onClick={() => mut.mutate({ priority: prio as TicketPriority })}>Aplicar</Button>
      <Input className="h-8 w-28" placeholder="+ etiqueta" value={tag} onChange={(e) => setTag(e.target.value)} />
      <Button size="sm" variant="outline" disabled={!tag.trim() || mut.isPending} onClick={() => mut.mutate({ addTag: tag.trim().toLowerCase() })}>Etiquetar</Button>
      {/* Cierre masivo retirado: cerrar requiere confirmación del cliente por ticket (sign-off #23). */}
      <Button size="sm" variant="ghost" className="ml-auto" onClick={onClear}><X className="h-4 w-4" /></Button>
    </div>
  );
}

// ── Panel de detalle ──────────────────────────────────────────────────────────
function TicketDetailPanel({ ticketId, services, onChanged }: {
  ticketId: string; services: import("@/components/tickets/types").TicketService[]; onChanged: () => void;
}) {
  const qc = useQueryClient();
  const detailQ = useQuery({
    queryKey: ["ticket", ticketId],
    queryFn: () => getTicket(ticketId),
    staleTime: 10_000,
  });
  const templatesQ = useQuery({ queryKey: ["ticket-templates"], queryFn: () => listTemplates(), staleTime: 300_000 });

  const [reply, setReply] = useState("");
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [visibility, setVisibility] = useState<Visibility>("PUBLIC");
  const [expectsReply, setExpectsReply] = useState(true);
  const [caseToLink, setCaseToLink] = useState("");
  const [showAr, setShowAr] = useState(false);
  const [showSendReport, setShowSendReport] = useState(false);
  const [showSendPlaybook, setShowSendPlaybook] = useState(false);
  const [ccDraft, setCcDraft] = useState("");

  // Al abrir el ticket: marcar como leído por el SOC (apaga el resaltado de
  // no-leídos en la lista). Best-effort; refresca la lista para limpiar el blink.
  useEffect(() => {
    markTicketRead(ticketId)
      .then(() => qc.invalidateQueries({ queryKey: ["tickets"] }))
      .catch(() => { /* no bloquea la vista de detalle */ });
  }, [ticketId, qc]);

  function refresh() {
    void qc.invalidateQueries({ queryKey: ["ticket", ticketId] });
    void qc.invalidateQueries({ queryKey: ["ticket-dupes", ticketId] });
    onChanged();
  }

  const replyMut = useMutation({
    mutationFn: () => replyTicket(ticketId, { body: reply, visibility, expectsReply }),
    onSuccess: () => { setReply(""); toast.success("Mensaje enviado"); refresh(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const statusMut = useMutation({
    mutationFn: (toStatus: TicketStatus) => transitionTicket(ticketId, { toStatus }),
    onSuccess: (_d, s) => { toast.success(`Estado → ${STATUS_LABEL[s]}`); refresh(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const closureMut = useMutation({
    mutationFn: () => requestClosure(ticketId),
    onSuccess: async ({ link }) => {
      try { await navigator.clipboard.writeText(link); } catch { /* clipboard opcional */ }
      toast.success("Vínculo de confirmación generado y enviado al cliente (copiado al portapapeles).");
      refresh();
    },
    onError: (e) => toast.error(errMsg(e)),
  });
  const linkMut = useMutation({
    mutationFn: () => linkCase(ticketId, { caseId: caseToLink.trim(), linkType: "PRIMARY" }),
    onSuccess: () => { setCaseToLink(""); toast.success("Caso vinculado"); refresh(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const assignMut = useMutation({
    mutationFn: () => assignTicket(ticketId),
    onSuccess: () => { toast.success("Ticket asignado a vos"); refresh(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const ccMut = useMutation({
    mutationFn: (list: string[]) => setCcContacts(ticketId, list),
    onSuccess: () => { setCcDraft(""); refresh(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  if (detailQ.isLoading || !detailQ.data) {
    return <div className="space-y-3 pt-6">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-16 w-full" />)}</div>;
  }
  const t: TicketDetail = detailQ.data;
  const ccList = (t.cc_contacts ?? []).map((c) => (typeof c === "string" ? c : c.email)).filter(Boolean) as string[];

  return (
    <div className="space-y-4">
      {reportHtml && <ReportIframeModal html={reportHtml} onClose={() => setReportHtml(null)} />}
      <SheetHeader className="space-y-1">
        <SheetTitle className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm">{t.public_ref}</span>
          <Badge variant="outline" style={{ color: STATUS_COLOR[t.status], borderColor: STATUS_COLOR[t.status] }}>{STATUS_LABEL[t.status]}</Badge>
          <Badge variant="outline" style={{ color: WAITING_COLOR[t.waiting_on], borderColor: WAITING_COLOR[t.waiting_on] }}>{WAITING_LABEL[t.waiting_on]}</Badge>
          <Badge variant="outline" style={{ color: TYPE_COLOR[t.ticket_type], borderColor: TYPE_COLOR[t.ticket_type] }}>{TYPE_LABEL[t.ticket_type]}</Badge>
        </SheetTitle>
        <p className="text-sm">{t.subject}</p>
        <p className="text-xs text-muted-foreground">
          {CHANNEL_LABEL[t.channel] ?? t.channel} · prioridad {PRIORITY_LABEL[t.priority]} ·
          FRT {fmtDuration(t.first_response_at ? (new Date(t.first_response_at).getTime() - new Date(t.created_at).getTime()) / 1000 : null)}
        </p>
      </SheetHeader>

      {/* (#2) Banda de identidad: cliente y analista a cargo, prominentes. */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-2.5">
        <div className="flex items-start gap-2">
          <Building2 className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
          <div className="min-w-0">
            <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Cliente</div>
            <div className="truncate font-medium">{t.org_name ?? t.org_slug ?? "—"}</div>
            {(t.requester_contact?.name || t.requester_contact?.email) && (
              <div className="truncate text-xs text-muted-foreground">
                {t.requester_contact?.name || t.requester_contact?.email}
              </div>
            )}
          </div>
        </div>
        <div className="min-w-0">
          <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Analista a cargo</div>
          {t.assigned_operator
            ? <div className="mt-0.5"><AnalystChip name={t.assigned_operator_name ?? t.assigned_operator} /></div>
            : <div className="mt-0.5 font-medium text-amber-500">Sin asignar</div>}
        </div>
      </div>

      {/* Clasificación editable (#1/#4/#5/#2) */}
      <ClassificationEditor t={t} services={services} onChanged={refresh} />

      {/* Sugerencia de IA (#3/#7) */}
      <AiSuggestPanel t={t} onChanged={refresh} />

      {/* Duplicados (#6) */}
      <DuplicatesPanel t={t} onChanged={refresh} />

      {/* Orden / workflow: snooze (#18) + watchers (#20) */}
      <div className="space-y-2 rounded-md border p-2">
        <SnoozeControl t={t} onChanged={refresh} />
        <WatchersBar t={t} onChanged={refresh} />
      </div>

      {/* Vínculo a caso */}
      <div className="flex flex-wrap items-center gap-2">
        {t.primary_case_id ? (
          <>
            <Link to={`/gestion?investigate=${t.primary_case_id}`} className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:underline">
              <FolderOpen className="h-3.5 w-3.5" /> Caso {t.primary_case_id}
            </Link>
            <Button size="sm" variant="outline" onClick={() => setShowSendReport(true)}>
              <FileText className="h-3.5 w-3.5" /> Enviar informe
            </Button>
            <Button size="sm" variant="outline" onClick={() => setShowSendPlaybook(true)}>
              <BookOpen className="h-3.5 w-3.5" /> Enviar playbook
            </Button>
          </>
        ) : (
          <>
            <Input className="h-7 w-48 text-xs" placeholder="ID de caso a vincular" value={caseToLink} onChange={(e) => setCaseToLink(e.target.value)} />
            <Button size="sm" variant="outline" disabled={!caseToLink.trim() || linkMut.isPending} onClick={() => linkMut.mutate()}>
              <Link2 className="h-3.5 w-3.5" /> Vincular
            </Button>
          </>
        )}
        {!t.assigned_operator && (
          <Button size="sm" variant="ghost" disabled={assignMut.isPending} onClick={() => assignMut.mutate()}>
            <UserPlus className="h-3.5 w-3.5" /> Tomar
          </Button>
        )}
      </div>

      {showSendReport && t.primary_case_id && (
        <SendReportFromTicketModal caseId={t.primary_case_id} ticketId={ticketId}
          onClose={() => setShowSendReport(false)} onSent={() => { setShowSendReport(false); refresh(); }} />
      )}

      {showSendPlaybook && t.primary_case_id && (
        <SendPlaybookFromTicketModal caseId={t.primary_case_id} ticketId={ticketId}
          onClose={() => setShowSendPlaybook(false)} onSent={() => { setShowSendPlaybook(false); refresh(); }} />
      )}

      {/* CC del cliente (#20) */}
      <div className="flex flex-wrap items-center gap-1 text-xs">
        <span className="text-muted-foreground">CC cliente:</span>
        {ccList.map((c) => (
          <Badge key={c} variant="outline" className="gap-1">{c}
            <button onClick={() => ccMut.mutate(ccList.filter((x) => x !== c))}><X className="h-2.5 w-2.5" /></button>
          </Badge>
        ))}
        <Input className="h-6 w-40 text-xs" placeholder="+ email" value={ccDraft} onChange={(e) => setCcDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && ccDraft.includes("@")) ccMut.mutate([...ccList, ccDraft.trim()]); }} />
      </div>

      {/* Hilo */}
      <div>
        <div className="mb-2 flex items-center gap-1 text-xs font-medium text-muted-foreground">
          <MessageSquare className="h-3.5 w-3.5" /> Conversación
        </div>
        <div className="space-y-2">
          {t.messages.length === 0 && <p className="text-xs text-muted-foreground">Sin mensajes aún.</p>}
          {t.messages.map((m) => (
            <div key={m.id} className="rounded-md border p-2"
              style={{ background: m.author_type === "CLIENT" ? "color-mix(in srgb, var(--cm-blue) 6%, transparent)" : undefined }}>
              <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1">
                  <MessageAuthor m={m} />
                  {m.visibility === "INTERNAL" && <span className="ml-1 text-amber-400">· nota interna</span>}
                </span>
                <span>{formatDateTimePy(m.created_at)}{m.turnaround_seconds != null && ` · ${fmtDuration(m.turnaround_seconds)}`}</span>
              </div>
              <p className="mt-1 whitespace-pre-wrap text-sm">{m.body}</p>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {m.has_report && (
                  <button className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs text-cyan-500 hover:bg-muted/40"
                    onClick={async () => { try { setReportHtml(await getMessageReportHtml(m.id)); } catch (e) { toast.error(errMsg(e)); } }}>
                    <FileText className="h-3 w-3" /> Ver informe
                  </button>
                )}
                {m.has_playbook && (
                  <button className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs text-emerald-500 hover:bg-muted/40"
                    onClick={async () => { try { setReportHtml(await getMessagePlaybookHtml(m.id)); } catch (e) { toast.error(errMsg(e)); } }}>
                    <BookOpen className="h-3 w-3" /> Ver playbook
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Responder — (#3) acción primaria fija al pie del panel mientras se
          desplaza el hilo. */}
      {t.status !== "CERRADO" && (
        <div className="sticky bottom-0 z-10 space-y-2 rounded-md border bg-background p-2 shadow-[0_-6px_16px_-10px_rgba(0,0,0,0.5)]">
          {(templatesQ.data?.length ?? 0) > 0 && (
            <select className={SELECT_CLS + " w-full"} value=""
              onChange={(e) => {
                const tpl = templatesQ.data?.find((x) => x.id === e.target.value);
                if (tpl) setReply((r) => (r.trim() ? r + "\n\n" + tpl.body : tpl.body));
              }}>
              <option value="">Insertar plantilla…</option>
              {templatesQ.data?.map((tpl) => <option key={tpl.id} value={tpl.id}>{tpl.title}</option>)}
            </select>
          )}
          <textarea className="min-h-[64px] w-full rounded-md border bg-card p-2 text-sm" placeholder="Escribir respuesta…"
            value={reply} onChange={(e) => setReply(e.target.value)} />
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <label className="flex items-center gap-1"><input type="checkbox" checked={visibility === "INTERNAL"} onChange={(e) => setVisibility(e.target.checked ? "INTERNAL" : "PUBLIC")} /> Nota interna</label>
            <label className="flex items-center gap-1"><input type="checkbox" checked={expectsReply} onChange={(e) => setExpectsReply(e.target.checked)} disabled={visibility === "INTERNAL"} /> Espera respuesta del cliente</label>
            <Button size="sm" className="ml-auto" disabled={!reply.trim() || replyMut.isPending} onClick={() => replyMut.mutate()}>
              {replyMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />} Enviar
            </Button>
          </div>
        </div>
      )}

      {/* Transición de estado — el cierre directo está bloqueado: requiere
          confirmación del cliente (sign-off #23), por eso se filtra CERRADO. */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Mover a:</span>
        {NEXT_STATUS[t.status].filter((s) => s !== "CERRADO").map((s) => (
          <Button key={s} size="sm" variant="outline" disabled={statusMut.isPending} onClick={() => statusMut.mutate(s)}>
            <ArrowRight className="h-3 w-3" /> {STATUS_LABEL[s]}
          </Button>
        ))}
      </div>

      {/* Cierre con confirmación del cliente (sign-off #23) */}
      {t.status !== "CERRADO" && (
        <div className="space-y-2 rounded-md border p-2">
          {t.closure_requested_at ? (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge variant="outline" className="border-amber-500 text-amber-500">Cierre pendiente de confirmación</Badge>
              <span className="text-muted-foreground">
                Vínculo enviado al cliente {formatDateTimePy(t.closure_requested_at)}.
              </span>
              <Button size="sm" variant="ghost" disabled={closureMut.isPending}
                onClick={() => closureMut.mutate()}>
                Reenviar vínculo
              </Button>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="outline" disabled={closureMut.isPending}
                onClick={() => closureMut.mutate()}>
                {closureMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                Solicitar confirmación de cierre
              </Button>
              <span className="text-xs text-muted-foreground">
                Para cerrar este ticket se requiere la confirmación del cliente.
              </span>
            </div>
          )}
        </div>
      )}

      {/* Solicitudes accionables */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <span className="flex items-center gap-1 text-xs font-medium text-muted-foreground">
            <ShieldAlert className="h-3.5 w-3.5" /> Solicitudes al cliente
          </span>
          <Button size="sm" variant="ghost" onClick={() => setShowAr((v) => !v)}>{showAr ? "Cerrar" : "+ Nueva"}</Button>
        </div>
        {showAr && (
          <CreateActionRequestForm ticketId={ticketId} caseId={t.primary_case_id ?? undefined}
            onDone={() => { setShowAr(false); refresh(); }} />
        )}
        <div className="mt-2 space-y-2">
          {t.actionRequests.length === 0 && !showAr && <p className="text-xs text-muted-foreground">Ninguna.</p>}
          {t.actionRequests.map((ar) => (
            <div key={ar.id} className="rounded-md border p-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="font-medium">{ACTION_TYPE_LABEL[ar.action_type]}</span>
                <Badge variant="outline" style={{ color: ACTION_STATUS_COLOR[ar.status], borderColor: ACTION_STATUS_COLOR[ar.status] }}>{ACTION_STATUS_LABEL[ar.status]}</Badge>
              </div>
              <p className="text-xs text-muted-foreground">{ar.title}</p>
              {ar.status === "RIESGO_ACEPTADO" && (
                <p className="mt-1 text-[11px] text-purple-400">
                  Riesgo asumido por {ar.risk_accepted_by}{ar.risk_review_at && ` · revisar ${formatDateTimePy(ar.risk_review_at)}`}
                </p>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Formulario: crear solicitud accionable ────────────────────────────────────
function CreateActionRequestForm({ ticketId, caseId, onDone }: {
  ticketId: string; caseId?: string; onDone: () => void;
}) {
  const [actionType, setActionType] = useState<ActionType>("CONTENCION_FIREWALL");
  const [title, setTitle] = useState("");
  const [rationale, setRationale] = useState("");
  const [urgency, setUrgency] = useState<TicketPriority>("HIGH");

  const mut = useMutation({
    mutationFn: () => createActionRequest({ ticketId, caseId, actionType, title, rationale, urgency }),
    onSuccess: () => { toast.success("Solicitud enviada al cliente"); onDone(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="space-y-2 rounded-md border p-2">
      <div className="flex gap-2">
        <select className={SELECT_CLS + " flex-1"} value={actionType} onChange={(e) => setActionType(e.target.value as ActionType)}>
          {ACTION_TYPES.map((a) => <option key={a} value={a}>{ACTION_TYPE_LABEL[a]}</option>)}
        </select>
        <select className={SELECT_CLS} value={urgency} onChange={(e) => setUrgency(e.target.value as TicketPriority)}>
          {(["URGENT", "HIGH", "MEDIUM", "LOW"] as TicketPriority[]).map((u) => <option key={u} value={u}>{PRIORITY_LABEL[u]}</option>)}
        </select>
      </div>
      <Input className="h-8" placeholder="Título (ej: Bloquear 203.0.113.40 en el FW)" value={title} onChange={(e) => setTitle(e.target.value)} />
      <textarea className="min-h-[48px] w-full rounded-md border bg-card p-2 text-sm" placeholder="Justificación (lenguaje claro, sin telemetría cruda)"
        value={rationale} onChange={(e) => setRationale(e.target.value)} />
      <Button size="sm" className="w-full" disabled={!title.trim() || !rationale.trim() || mut.isPending} onClick={() => mut.mutate()}>
        {mut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5" />} Solicitar al cliente
      </Button>
    </div>
  );
}

// ── Modal: vista previa del informe del caso + envío al cliente en ESTE ticket ──
function SendReportFromTicketModal({ caseId, ticketId, onClose, onSent }: {
  caseId: string; ticketId: string; onClose: () => void; onSent: () => void;
}) {
  const reportQ = useQuery({
    queryKey: ["case-report-html", caseId],
    queryFn: () => getCaseReportHtml(caseId),
    staleTime: 30_000,
  });
  const sendMut = useMutation({
    mutationFn: () => sendReportToTicket(caseId, { ticketId }),
    onSuccess: () => { toast.success("Informe enviado al cliente"); onSent(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="flex h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl bg-white shadow-xl">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <span className="text-sm font-medium text-slate-800">Informe del incidente — vista previa</span>
          <button className="rounded p-1 text-slate-500 hover:bg-slate-100" onClick={onClose}><X className="h-4 w-4" /></button>
        </div>
        {reportQ.isLoading ? (
          <div className="flex flex-1 items-center justify-center text-sm text-slate-400">Generando informe…</div>
        ) : (
          <iframe sandbox="" title="Informe" srcDoc={reportQ.data ?? ""} className="w-full flex-1 border-0" />
        )}
        <div className="flex items-center gap-2 border-t px-4 py-2">
          <button className="ml-auto flex items-center gap-1.5 rounded-md bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
            disabled={reportQ.isLoading || sendMut.isPending} onClick={() => sendMut.mutate()}>
            {sendMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Enviar al cliente
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Vista previa + envío del PLAYBOOK al cliente ──────────────────────────────
// Espejo de SendReportFromTicketModal. El backend consulta la base de
// conocimiento: si ya existe un playbook reutilizable para este tipo de caso lo
// reenvía (sin re-llamar al LLM); "Regenerar" (forceNew) fuerza uno nuevo.
function SendPlaybookFromTicketModal({ caseId, ticketId, onClose, onSent }: {
  caseId: string; ticketId: string; onClose: () => void; onSent: () => void;
}) {
  const qc = useQueryClient();
  const [forceNew, setForceNew] = useState(false);
  const playbookQ = useQuery({
    queryKey: ["case-playbook-html", caseId, forceNew],
    queryFn: () => getCasePlaybookHtml(caseId, forceNew),
    staleTime: 30_000,
  });
  const sendMut = useMutation({
    mutationFn: () => sendPlaybookToTicket(caseId, { ticketId, forceNew }),
    onSuccess: (r) => { toast.success(r.reused ? "Playbook reutilizado y enviado" : "Playbook generado y enviado"); onSent(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="flex h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl bg-white shadow-xl">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <span className="text-sm font-medium text-slate-800">Playbook de respuesta — vista previa</span>
          <button className="rounded p-1 text-slate-500 hover:bg-slate-100" onClick={onClose}><X className="h-4 w-4" /></button>
        </div>
        {playbookQ.isLoading ? (
          <div className="flex flex-1 items-center justify-center text-sm text-slate-400">Consultando base de conocimiento / generando…</div>
        ) : (
          <iframe sandbox="" title="Playbook" srcDoc={playbookQ.data ?? ""} className="w-full flex-1 border-0" />
        )}
        <div className="flex items-center gap-2 border-t px-4 py-2">
          <button className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-50"
            disabled={playbookQ.isLoading || sendMut.isPending}
            onClick={() => { setForceNew(true); void qc.invalidateQueries({ queryKey: ["case-playbook-html", caseId] }); }}>
            <RotateCw className="h-3.5 w-3.5" /> Regenerar
          </button>
          <button className="ml-auto flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
            disabled={playbookQ.isLoading || sendMut.isPending} onClick={() => sendMut.mutate()}>
            {sendMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Enviar al cliente
          </button>
        </div>
      </div>
    </div>
  );
}
