/**
 * TicketDetailExtras.tsx — subpaneles del detalle del ticket para el bloque de
 * clasificación / orden / workflow (20 mejoras): clasificación editable (#1/#4/#5),
 * sugerencia de IA (#3/#7), duplicados + merge (#6), watchers (#20), snooze (#18).
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import {
  Sparkles, Copy, GitMerge, Eye, EyeOff, Clock, Loader2, Check, X, Tag as TagIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { formatDateTimePy } from "@/lib/format";
import {
  setClassification, classifyTicket, applyAiSuggestion, setTags,
  getDuplicates, mergeTicket, addWatcher, removeWatcher, snoozeTicket,
  type DuplicateCandidate,
} from "@/api/tickets";
import {
  TYPE_LABEL, TECH_SEVERITY_LABEL, SENTIMENT_LABEL, SENTIMENT_EMOJI, PRIORITY_LABEL,
} from "@/components/tickets/types";
import type {
  TicketDetail, TicketType, TechnicalSeverity, TicketService, TicketPriority, AiSuggestion,
} from "@/components/tickets/types";
import { useSocOperators } from "@/hooks/useSocWorkflow";

const SELECT = "h-8 rounded-md border bg-card px-2 text-sm text-foreground";
function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

// ── (#1/#4/#5) Editor de clasificación ────────────────────────────────────────
export function ClassificationEditor({ t, services, onChanged }: {
  t: TicketDetail; services: TicketService[]; onChanged: () => void;
}) {
  const mut = useMutation({
    mutationFn: (body: Parameters<typeof setClassification>[1]) => setClassification(t.id, body),
    onSuccess: () => { toast.success("Clasificación actualizada"); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="grid grid-cols-2 gap-2 rounded-md border p-2 text-xs">
      <label className="flex flex-col gap-1">
        <span className="text-muted-foreground">Tipo</span>
        <select className={SELECT} value={t.ticket_type}
          onChange={(e) => mut.mutate({ ticketType: e.target.value as TicketType })}>
          {(Object.keys(TYPE_LABEL) as TicketType[]).map((k) => <option key={k} value={k}>{TYPE_LABEL[k]}</option>)}
        </select>
      </label>
      <label className="flex flex-col gap-1">
        <span className="text-muted-foreground">Severidad técnica</span>
        <select className={SELECT} value={t.technical_severity ?? ""}
          onChange={(e) => mut.mutate({ technicalSeverity: (e.target.value || null) as TechnicalSeverity | null })}>
          <option value="">— sin evaluar</option>
          {(Object.keys(TECH_SEVERITY_LABEL) as TechnicalSeverity[]).map((k) => <option key={k} value={k}>{TECH_SEVERITY_LABEL[k]}</option>)}
        </select>
      </label>
      <label className="flex flex-col gap-1">
        <span className="text-muted-foreground">Prioridad cliente</span>
        <select className={SELECT} value={t.priority}
          onChange={(e) => mut.mutate({ priority: e.target.value as TicketPriority })}>
          {(["URGENT", "HIGH", "MEDIUM", "LOW"] as TicketPriority[]).map((k) => <option key={k} value={k}>{PRIORITY_LABEL[k]}</option>)}
        </select>
      </label>
      <label className="flex flex-col gap-1">
        <span className="text-muted-foreground">Servicio afectado</span>
        <select className={SELECT} value={t.service_slug ?? ""}
          onChange={(e) => mut.mutate({ serviceSlug: e.target.value || null })}>
          <option value="">— ninguno</option>
          {services.map((s) => <option key={s.id} value={s.slug}>{s.name}</option>)}
        </select>
      </label>
      <div className="col-span-2 flex items-center gap-2">
        <span className="text-muted-foreground">Sentimiento:</span>
        {t.sentiment
          ? <span>{SENTIMENT_EMOJI[t.sentiment]} {SENTIMENT_LABEL[t.sentiment]}</span>
          : <span className="text-muted-foreground">—</span>}
        {mut.isPending && <Loader2 className="ml-auto h-3.5 w-3.5 animate-spin" />}
      </div>
      <TagEditor t={t} onChanged={onChanged} />
    </div>
  );
}

// (#2) Etiquetas editables
function TagEditor({ t, onChanged }: { t: TicketDetail; onChanged: () => void }) {
  const [draft, setDraft] = useState("");
  const mut = useMutation({
    mutationFn: (tags: string[]) => setTags(t.id, tags),
    onSuccess: onChanged,
    onError: (e) => toast.error(errMsg(e)),
  });
  const tags = t.tags ?? [];
  return (
    <div className="col-span-2 flex flex-col gap-1">
      <span className="text-muted-foreground">Etiquetas</span>
      <div className="flex flex-wrap items-center gap-1">
        {tags.map((tg) => (
          <Badge key={tg} variant="outline" className="gap-1">
            <TagIcon className="h-2.5 w-2.5" />{tg}
            <button onClick={() => mut.mutate(tags.filter((x) => x !== tg))}><X className="h-2.5 w-2.5" /></button>
          </Badge>
        ))}
        <Input className="h-6 w-28 text-xs" placeholder="+ etiqueta" value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && draft.trim()) { mut.mutate([...tags, draft.trim().toLowerCase()]); setDraft(""); }
          }} />
      </div>
    </div>
  );
}

// ── (#3/#7) Sugerencia de IA ──────────────────────────────────────────────────
export function AiSuggestPanel({ t, onChanged }: { t: TicketDetail; onChanged: () => void }) {
  const sug = t.ai_suggested ?? null;
  const classifyMut = useMutation({
    mutationFn: () => classifyTicket(t.id),
    onSuccess: () => { toast.success("Ticket analizado por IA"); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const applyMut = useMutation({
    mutationFn: (fields: AiSuggestion) => applyAiSuggestion(t.id, fields),
    onSuccess: () => { toast.success("Sugerencia aplicada"); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="rounded-md border border-purple-500/30 bg-purple-500/[0.04] p-2 text-xs">
      <div className="flex items-center gap-1.5 font-medium text-purple-400">
        <Sparkles className="h-3.5 w-3.5" /> Clasificación por IA
        <Button size="sm" variant="ghost" className="ml-auto h-6"
          disabled={classifyMut.isPending} onClick={() => classifyMut.mutate()}>
          {classifyMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />}
          {sug ? "Re-analizar" : "Analizar"}
        </Button>
      </div>
      {sug && (
        <div className="mt-2 space-y-1">
          <p>Tipo sugerido: <b>{sug.type ? TYPE_LABEL[sug.type] : "—"}</b> · Prioridad: <b>{sug.priority ? PRIORITY_LABEL[sug.priority] : "—"}</b></p>
          <p>Sentimiento: <b>{sug.sentiment ? `${SENTIMENT_EMOJI[sug.sentiment]} ${SENTIMENT_LABEL[sug.sentiment]}` : "—"}</b>
            {typeof sug.confidence === "number" && <> · confianza {sug.confidence}%</>}
            {sug.source && <span className="text-muted-foreground"> · {sug.source === "llm" ? "modelo" : "heurística"}</span>}
          </p>
          {sug.summary && <p className="text-muted-foreground">“{sug.summary}”</p>}
          {Array.isArray(sug.tags) && sug.tags.length > 0 && <p>Etiquetas: {sug.tags.join(", ")}</p>}
          <Button size="sm" variant="outline" className="mt-1 h-6" disabled={applyMut.isPending}
            onClick={() => applyMut.mutate(sug)}>
            <Check className="h-3 w-3" /> Aplicar sugerencia
          </Button>
        </div>
      )}
    </div>
  );
}

// ── (#6) Duplicados + merge ───────────────────────────────────────────────────
export function DuplicatesPanel({ t, onChanged }: { t: TicketDetail; onChanged: () => void }) {
  const qc = useQueryClient();
  const dupQ = useQuery({
    queryKey: ["ticket-dupes", t.id],
    queryFn: () => getDuplicates(t.id),
    staleTime: 30_000,
  });
  const mergeMut = useMutation({
    mutationFn: (into: DuplicateCandidate) => mergeTicket(t.id, into.id),
    onSuccess: () => { toast.success("Tickets fusionados"); void qc.invalidateQueries({ queryKey: ["tickets"] }); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  const candidates = dupQ.data ?? [];
  if (!candidates.length) return null;

  return (
    <div className="rounded-md border border-amber-500/30 bg-amber-500/[0.04] p-2 text-xs">
      <div className="flex items-center gap-1.5 font-medium text-amber-500">
        <Copy className="h-3.5 w-3.5" /> Posibles duplicados ({candidates.length})
      </div>
      <div className="mt-1 space-y-1">
        {candidates.map((c) => (
          <div key={c.id} className="flex items-center gap-2">
            <span className="font-mono text-[11px]">{c.public_ref}</span>
            <span className="flex-1 truncate text-muted-foreground">{c.subject}</span>
            {typeof c.sim === "number" && <span className="text-[10px] text-muted-foreground">{Math.round(c.sim * 100)}%</span>}
            <Button size="sm" variant="ghost" className="h-6" disabled={mergeMut.isPending}
              onClick={() => { if (confirm(`¿Fusionar ESTE ticket dentro de ${c.public_ref}? Se cerrará el actual.`)) mergeMut.mutate(c); }}>
              <GitMerge className="h-3 w-3" /> Fusionar aquí
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── (#20) Watchers internos ───────────────────────────────────────────────────
export function WatchersBar({ t, onChanged }: { t: TicketDetail; onChanged: () => void }) {
  const { data: operators = [] } = useSocOperators();
  const [pick, setPick] = useState("");
  const addMut = useMutation({
    mutationFn: (ci: string) => addWatcher(t.id, ci),
    onSuccess: () => { setPick(""); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const rmMut = useMutation({
    mutationFn: (ci: string) => removeWatcher(t.id, ci),
    onSuccess: onChanged,
    onError: (e) => toast.error(errMsg(e)),
  });
  const watchers = t.watchers ?? [];

  return (
    <div className="flex flex-wrap items-center gap-1 text-xs">
      <Eye className="h-3.5 w-3.5 text-muted-foreground" />
      <span className="text-muted-foreground">Siguen:</span>
      {watchers.length === 0 && <span className="text-muted-foreground">nadie</span>}
      {watchers.map((w) => (
        <Badge key={w.operator_ci} variant="outline" className="gap-1">
          {w.operator_name ?? w.operator_ci}
          <button onClick={() => rmMut.mutate(w.operator_ci)}><EyeOff className="h-2.5 w-2.5" /></button>
        </Badge>
      ))}
      <select className={SELECT + " ml-auto h-7"} value={pick}
        onChange={(e) => { setPick(e.target.value); if (e.target.value) addMut.mutate(e.target.value); }}>
        <option value="">+ seguir…</option>
        {operators.filter((o) => o.is_active && !watchers.some((w) => w.operator_ci === o.id))
          .map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
      </select>
    </div>
  );
}

// ── (#18) Posponer (snooze) ───────────────────────────────────────────────────
export function SnoozeControl({ t, onChanged }: { t: TicketDetail; onChanged: () => void }) {
  const mut = useMutation({
    mutationFn: (until: string | null) => snoozeTicket(t.id, until),
    onSuccess: (_d, until) => { toast.success(until ? "Ticket pospuesto" : "Snooze cancelado"); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const snooze = (hours: number) => mut.mutate(new Date(Date.now() + hours * 3.6e6).toISOString());

  return (
    <div className="flex flex-wrap items-center gap-1 text-xs">
      <Clock className="h-3.5 w-3.5 text-muted-foreground" />
      {t.snoozed_until && new Date(t.snoozed_until) > new Date() ? (
        <>
          <span className="text-muted-foreground">Pospuesto hasta {formatDateTimePy(t.snoozed_until)}</span>
          <Button size="sm" variant="ghost" className="h-6" onClick={() => mut.mutate(null)}>Cancelar</Button>
        </>
      ) : (
        <>
          <span className="text-muted-foreground">Posponer:</span>
          <Button size="sm" variant="outline" className="h-6" onClick={() => snooze(4)}>4h</Button>
          <Button size="sm" variant="outline" className="h-6" onClick={() => snooze(24)}>1d</Button>
          <Button size="sm" variant="outline" className="h-6" onClick={() => snooze(72)}>3d</Button>
        </>
      )}
    </div>
  );
}
