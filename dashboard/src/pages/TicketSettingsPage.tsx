/**
 * TicketSettingsPage.tsx — administración del catálogo de servicios (#5) y de las
 * reglas de negocio configurables (#19) del Sistema de Tickets.
 *
 * Solo gestores (gateado en router.tsx). Las reglas se evalúan al crear el ticket
 * (ver services/ticketRules.mjs); el catálogo alimenta el filtro/clasificación.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { Settings, Plus, Trash2, Power, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  listServices, createService, updateService, deleteService,
  listRules, createRule, updateRule, deleteRule,
} from "@/api/tickets";
import { TYPE_LABEL, PRIORITY_LABEL, CHANNEL_LABEL } from "@/components/tickets/types";
import type {
  TicketType, TicketPriority, TicketRuleCondition, TicketRuleAction,
} from "@/components/tickets/types";

const SELECT = "h-8 rounded-md border bg-card px-2 text-sm text-foreground";
function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

export function TicketSettingsPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Settings className="h-7 w-7 text-cyan-400" />
        <div>
          <h1 className="text-xl font-semibold">Configuración de Tickets</h1>
          <p className="text-sm text-muted-foreground">Catálogo de servicios y reglas de negocio de la cola</p>
        </div>
      </div>
      <ServicesAdmin />
      <RulesAdmin />
    </div>
  );
}

// ── (#5) Catálogo de servicios ────────────────────────────────────────────────
function ServicesAdmin() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ticket-services-admin"], queryFn: () => listServices(), staleTime: 60_000 });
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const inval = () => qc.invalidateQueries({ queryKey: ["ticket-services-admin"] });

  const createMut = useMutation({
    mutationFn: () => createService({ name: name.trim(), slug: slug.trim().toLowerCase() }),
    onSuccess: () => { setName(""); setSlug(""); toast.success("Servicio creado"); inval(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const toggleMut = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => updateService(id, { active }),
    onSuccess: inval, onError: (e) => toast.error(errMsg(e)),
  });
  const delMut = useMutation({
    mutationFn: (id: string) => deleteService(id),
    onSuccess: () => { toast.success("Servicio eliminado"); inval(); }, onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <h2 className="text-sm font-semibold">Servicios / productos</h2>
        <div className="space-y-1">
          {(q.data ?? []).map((s) => (
            <div key={s.id} className="flex items-center gap-2 rounded-md border p-2 text-sm">
              <span className="font-medium">{s.name}</span>
              <code className="text-xs text-muted-foreground">{s.slug}</code>
              {!s.active && <Badge variant="outline" className="text-muted-foreground">inactivo</Badge>}
              <span className="ml-auto text-xs text-muted-foreground">{s.open_tickets ?? 0} abiertos</span>
              <Button size="sm" variant="ghost" onClick={() => toggleMut.mutate({ id: s.id, active: !s.active })}>
                <Power className="h-3.5 w-3.5" />
              </Button>
              <Button size="sm" variant="ghost" onClick={() => { if (confirm(`¿Eliminar ${s.name}?`)) delMut.mutate(s.id); }}>
                <Trash2 className="h-3.5 w-3.5 text-red-400" />
              </Button>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <Input className="h-8 w-48" placeholder="Nombre" value={name} onChange={(e) => setName(e.target.value)} />
          <Input className="h-8 w-40" placeholder="slug" value={slug} onChange={(e) => setSlug(e.target.value)} />
          <Button size="sm" disabled={!name.trim() || !slug.trim() || createMut.isPending} onClick={() => createMut.mutate()}>
            <Plus className="h-3.5 w-3.5" /> Agregar
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── (#19) Reglas de negocio ───────────────────────────────────────────────────
function RulesAdmin() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ticket-rules-admin"], queryFn: () => listRules(), staleTime: 60_000 });
  const inval = () => qc.invalidateQueries({ queryKey: ["ticket-rules-admin"] });
  const [show, setShow] = useState(false);

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => updateRule(id, { enabled }),
    onSuccess: inval, onError: (e) => toast.error(errMsg(e)),
  });
  const delMut = useMutation({
    mutationFn: (id: string) => deleteRule(id),
    onSuccess: () => { toast.success("Regla eliminada"); inval(); }, onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">Reglas de negocio</h2>
          <Button size="sm" variant="ghost" onClick={() => setShow((v) => !v)}>{show ? "Cerrar" : "+ Nueva regla"}</Button>
        </div>
        {show && <RuleForm onDone={() => { setShow(false); inval(); }} />}
        <div className="space-y-1">
          {(q.data ?? []).length === 0 && <p className="text-xs text-muted-foreground">Sin reglas. Las reglas se evalúan al crear el ticket.</p>}
          {(q.data ?? []).map((r) => (
            <div key={r.id} className="flex items-start gap-2 rounded-md border p-2 text-sm">
              <div className="flex-1">
                <span className="font-medium">{r.name}</span>
                {!r.enabled && <Badge variant="outline" className="ml-2 text-muted-foreground">deshabilitada</Badge>}
                <p className="text-xs text-muted-foreground">
                  SI {describeCond(r.conditions)} → {describeAction(r.actions)}
                </p>
              </div>
              <Button size="sm" variant="ghost" onClick={() => toggleMut.mutate({ id: r.id, enabled: !r.enabled })}>
                <Power className={r.enabled ? "h-3.5 w-3.5 text-green-400" : "h-3.5 w-3.5 text-muted-foreground"} />
              </Button>
              <Button size="sm" variant="ghost" onClick={() => { if (confirm(`¿Eliminar la regla ${r.name}?`)) delMut.mutate(r.id); }}>
                <Trash2 className="h-3.5 w-3.5 text-red-400" />
              </Button>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function describeCond(c: TicketRuleCondition): string {
  const parts: string[] = [];
  if (c.type) parts.push(`tipo=${TYPE_LABEL[c.type]}`);
  if (c.priority) parts.push(`prioridad=${PRIORITY_LABEL[c.priority]}`);
  if (c.channel) parts.push(`canal=${CHANNEL_LABEL[c.channel] ?? c.channel}`);
  if (c.service_slug) parts.push(`servicio=${c.service_slug}`);
  if (c.tag) parts.push(`etiqueta=${c.tag}`);
  if (c.subject_contains) parts.push(`asunto~"${c.subject_contains}"`);
  return parts.join(" y ") || "(sin condición)";
}
function describeAction(a: TicketRuleAction): string {
  const parts: string[] = [];
  if (a.assign_tier) parts.push(`asignar a ${a.assign_tier}`);
  if (a.assign_ci) parts.push(`asignar a ${a.assign_ci}`);
  if (a.set_priority) parts.push(`prioridad=${PRIORITY_LABEL[a.set_priority]}`);
  if (a.set_type) parts.push(`tipo=${TYPE_LABEL[a.set_type]}`);
  if (a.add_tag) parts.push(`etiquetar ${a.add_tag}`);
  if (a.notify_sm) parts.push("avisar al SM");
  return parts.join(", ") || "(sin acción)";
}

function RuleForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [cond, setCond] = useState<TicketRuleCondition>({});
  const [act, setAct] = useState<TicketRuleAction>({});
  const mut = useMutation({
    mutationFn: () => createRule({ name: name.trim(), conditions: cond, actions: act }),
    onSuccess: () => { toast.success("Regla creada"); onDone(); },
    onError: (e) => toast.error(errMsg(e)),
  });

  const set = <K extends keyof TicketRuleCondition>(k: K, v: TicketRuleCondition[K]) =>
    setCond((c) => ({ ...c, [k]: v || undefined }));
  const setA = <K extends keyof TicketRuleAction>(k: K, v: TicketRuleAction[K]) =>
    setAct((a) => ({ ...a, [k]: v || undefined }));

  return (
    <div className="space-y-2 rounded-md border p-3">
      <Input className="h-8" placeholder="Nombre de la regla" value={name} onChange={(e) => setName(e.target.value)} />
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">SI (condiciones)</p>
          <select className={SELECT + " w-full"} value={cond.type ?? ""} onChange={(e) => set("type", e.target.value as TicketType)}>
            <option value="">Tipo: cualquiera</option>
            {(Object.keys(TYPE_LABEL) as TicketType[]).map((k) => <option key={k} value={k}>{TYPE_LABEL[k]}</option>)}
          </select>
          <select className={SELECT + " w-full"} value={cond.priority ?? ""} onChange={(e) => set("priority", e.target.value as TicketPriority)}>
            <option value="">Prioridad: cualquiera</option>
            {(["URGENT", "HIGH", "MEDIUM", "LOW"] as TicketPriority[]).map((p) => <option key={p} value={p}>{PRIORITY_LABEL[p]}</option>)}
          </select>
          <select className={SELECT + " w-full"} value={cond.channel ?? ""} onChange={(e) => set("channel", e.target.value)}>
            <option value="">Canal: cualquiera</option>
            {Object.keys(CHANNEL_LABEL).map((c) => <option key={c} value={c}>{CHANNEL_LABEL[c]}</option>)}
          </select>
          <Input className="h-8" placeholder="Etiqueta (opcional)" value={cond.tag ?? ""} onChange={(e) => set("tag", e.target.value)} />
          <Input className="h-8" placeholder="Asunto contiene… (opcional)" value={cond.subject_contains ?? ""} onChange={(e) => set("subject_contains", e.target.value)} />
        </div>
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">ENTONCES (acciones)</p>
          <select className={SELECT + " w-full"} value={act.assign_tier ?? ""} onChange={(e) => setA("assign_tier", e.target.value)}>
            <option value="">Asignar a tier…</option>
            {["L1", "L1L2", "L2", "L3", "LEADER"].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <select className={SELECT + " w-full"} value={act.set_priority ?? ""} onChange={(e) => setA("set_priority", e.target.value as TicketPriority)}>
            <option value="">Fijar prioridad…</option>
            {(["URGENT", "HIGH", "MEDIUM", "LOW"] as TicketPriority[]).map((p) => <option key={p} value={p}>{PRIORITY_LABEL[p]}</option>)}
          </select>
          <select className={SELECT + " w-full"} value={act.set_type ?? ""} onChange={(e) => setA("set_type", e.target.value as TicketType)}>
            <option value="">Fijar tipo…</option>
            {(Object.keys(TYPE_LABEL) as TicketType[]).map((k) => <option key={k} value={k}>{TYPE_LABEL[k]}</option>)}
          </select>
          <Input className="h-8" placeholder="Agregar etiqueta…" value={act.add_tag ?? ""} onChange={(e) => setA("add_tag", e.target.value)} />
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={!!act.notify_sm} onChange={(e) => setA("notify_sm", e.target.checked)} /> Avisar al Shift Manager</label>
        </div>
      </div>
      <Button size="sm" className="w-full" disabled={!name.trim() || mut.isPending} onClick={() => mut.mutate()}>
        {mut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />} Crear regla
      </Button>
    </div>
  );
}
