/**
 * CaseInvestigationTabsLazy.tsx
 * Tabs cargados bajo demanda desde CaseInvestigationView (Timeline / Tasks /
 * Assets / Evidences). Mantiene a CaseInvestigationView por debajo de 1.7K
 * líneas y separa el bundle del Resumen (default) del resto, acelerando el
 * primer render del caso.
 */

import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle, BookOpen, Bug, CheckSquare, Clock, ExternalLink, FileText,
  FolderOpen, Mail, Plus, RefreshCw, Shield, Sparkles, Tag,
} from "lucide-react";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { suggestAssets, type AssetSuggestion } from "@/lib/asset-suggestions";
import { formatDateTimePy } from "@/lib/format";
import {
  useFullCase, useApplyTemplate, useAddTask, useUpdateTask,
  useAddAsset, useAddIoc, useAddEvidence, useAddTimelineEvent, useTemplates,
  useCaseEvents,
  type TaskPhase, type TaskStatus, type CaseTask, type CaseEventRow,
} from "./useCaseInvestigation";

const PHASE_LABEL: Record<string, string> = {
  DETECTION: "Detection & Analysis",
  CONTAINMENT: "Containment",
  ERADICATION: "Eradication",
  RECOVERY: "Recovery",
  POST_INCIDENT: "Post-Incident",
};
const PHASE_COLOR: Record<string, string> = {
  DETECTION:     "bg-blue-500/10 text-blue-400 border-blue-500/30",
  CONTAINMENT:   "bg-orange-500/10 text-orange-400 border-orange-500/30",
  ERADICATION:   "bg-red-500/10 text-red-400 border-red-500/30",
  RECOVERY:      "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  POST_INCIDENT: "bg-purple-500/10 text-purple-400 border-purple-500/30",
};
const EVENT_ICON: Record<string, React.ElementType> = {
  ADOPT:         FolderOpen,
  STATUS_CHANGE: RefreshCw,
  ESCALATE:      AlertTriangle,
  SLACK_NOTIFY:  Tag,
  CLIENT_NOTIFY: Mail,
  NOTE:          BookOpen,
  EVIDENCE:      FileText,
  IOC:           Shield,
  ASSET:         AlertTriangle,
  DETECTION:     Shield,
  CONTAINMENT:   AlertTriangle,
};

type FullCase = NonNullable<ReturnType<typeof useFullCase>["data"]>;

// ── Timeline Tab ─────────────────────────────────────────────────────────────

export function TimelineTab({
  caseId, c, operatorCi,
}: { caseId: string; c: FullCase; operatorCi: string }) {
  const [noteText, setNoteText] = useState("");
  const [filter, setFilter] = useState<"all" | "manual" | "system">("all");
  const addEvent = useAddTimelineEvent(caseId);

  async function submitNote() {
    if (!noteText.trim()) return;
    await addEvent.mutateAsync({ eventType: "NOTE", title: noteText.trim(), operatorCi });
    setNoteText("");
  }

  const allEvents = c.timeline ?? [];
  // MANUAL = acciones del operador (notas, tareas, quick actions); el resto
  // (SYSTEM/ALERT/ENRICHMENT/SOAR) es actividad automática. Permite aislar
  // "qué hizo el operador" vs "qué hizo la plataforma".
  const manualCount = allEvents.filter((e) => e.source === "MANUAL").length;
  const events = filter === "all"
    ? allEvents
    : allEvents.filter((e) => filter === "manual" ? e.source === "MANUAL" : e.source !== "MANUAL");

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Input
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Añadir nota al timeline…"
          className="text-xs"
          onKeyDown={e => { if (e.key === "Enter") void submitNote(); }}
        />
        <Button size="sm" onClick={() => void submitNote()} disabled={addEvent.isPending || !noteText.trim()}>
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>

      {/* Filtro origen: operador (MANUAL) vs sistema (automático) */}
      <div className="flex items-center gap-1 text-[11px]">
        {([
          ["all", `Todos (${allEvents.length})`],
          ["manual", `Operador (${manualCount})`],
          ["system", `Sistema (${allEvents.length - manualCount})`],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setFilter(key)}
            className={cn(
              "rounded border px-2 py-0.5 transition",
              filter === key
                ? "border-primary/50 bg-primary/10 text-primary font-semibold"
                : "border-border/50 text-muted-foreground hover:bg-muted/30",
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {events.length === 0 ? (
        <p className="text-sm text-muted-foreground">Sin eventos en el timeline.</p>
      ) : (
        <div className="relative space-y-0">
          <div className="absolute left-[18px] top-2 bottom-2 w-px bg-border/60" />
          {events.map((ev) => {
            const Icon = EVENT_ICON[ev.event_type] ?? BookOpen;
            const phaseCls = ev.phase ? (PHASE_COLOR[ev.phase] ?? "") : "";
            return (
              <div key={ev.id} className="relative flex gap-3 pb-4">
                <div className={cn(
                  "relative z-10 flex h-9 w-9 shrink-0 items-center justify-center rounded-full border bg-card",
                  phaseCls || "border-border/60",
                )}>
                  <Icon className="h-3.5 w-3.5" />
                </div>
                <div className="min-w-0 flex-1 pt-0.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-medium">{ev.title ?? ev.event_type}</span>
                    {ev.phase && (
                      <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", phaseCls)}>
                        {ev.phase}
                      </span>
                    )}
                    <span className="ml-auto text-[10px] text-muted-foreground">
                      {formatDateTimePy(ev.event_ts)}
                    </span>
                  </div>
                  {ev.description && (
                    <p className="mt-0.5 text-xs text-muted-foreground">{ev.description}</p>
                  )}
                  <div className="flex gap-2 text-[10px] text-muted-foreground/60">
                    <span>@{ev.operator_ci ?? "system"}</span>
                    {ev.related_asset && <span>· asset: {ev.related_asset}</span>}
                    {ev.related_ioc   && <span>· ioc: {ev.related_ioc}</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Tasks Tab ────────────────────────────────────────────────────────────────

export function TasksTab({
  caseId, c, operatorCi,
}: { caseId: string; c: FullCase; operatorCi: string }) {
  const [newTitle, setNewTitle] = useState("");
  const [newPhase, setNewPhase] = useState<TaskPhase>("DETECTION");
  const addTask    = useAddTask(caseId);
  const updateTask = useUpdateTask(caseId);
  const templates  = useTemplates();
  const applyTpl   = useApplyTemplate(caseId);

  async function handleAddTask() {
    if (!newTitle.trim()) return;
    await addTask.mutateAsync({ title: newTitle.trim(), phase: newPhase, operatorCi });
    setNewTitle("");
  }

  const phases = ["DETECTION", "CONTAINMENT", "ERADICATION", "RECOVERY", "POST_INCIDENT"] as TaskPhase[];

  return (
    <div className="space-y-4">
      {!c.template_id && (
        <Card className="border-primary/20 bg-primary/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs text-primary">Aplicar plantilla de investigación</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {[...(templates.data ?? [])]
                // La plantilla recomendada por táctica (backend) va primero.
                .sort((a, b) =>
                  (b.id === c.recommended_template_id ? 1 : 0) -
                  (a.id === c.recommended_template_id ? 1 : 0))
                .map(tpl => {
                  const isRecommended = tpl.id === c.recommended_template_id;
                  return (
                    <Button
                      key={tpl.id}
                      size="sm"
                      variant={isRecommended ? "default" : "outline"}
                      className={cn("h-7 text-xs", isRecommended && "ring-1 ring-primary")}
                      disabled={applyTpl.isPending}
                      title={isRecommended ? "Plantilla recomendada para la táctica MITRE de este caso" : undefined}
                      onClick={() => void applyTpl.mutateAsync({ templateId: tpl.id, operatorCi })}
                    >
                      <BookOpen className="mr-1.5 h-3 w-3" />
                      {tpl.name}
                      <span className="ml-1 opacity-60">({tpl.tasks_template.length})</span>
                      {isRecommended && (
                        <span className="ml-1.5 rounded bg-primary-foreground/20 px-1 text-[9px] font-semibold uppercase">
                          ✓ Recomendada
                        </span>
                      )}
                    </Button>
                  );
                })}
            </div>
            {applyTpl.isSuccess && (
              <p className="mt-2 text-xs text-emerald-400">
                ✓ {applyTpl.data?.tasksCreated} tareas cargadas desde "{applyTpl.data?.templateName}"
              </p>
            )}
          </CardContent>
        </Card>
      )}

      <div className="flex gap-2">
        <select
          value={newPhase}
          onChange={e => setNewPhase(e.target.value as TaskPhase)}
          className="h-9 rounded-md border border-input bg-background px-2 text-xs"
        >
          {phases.map(p => <option key={p} value={p}>{PHASE_LABEL[p]}</option>)}
        </select>
        <Input
          value={newTitle}
          onChange={e => setNewTitle(e.target.value)}
          placeholder="Nueva tarea…"
          className="text-xs"
          onKeyDown={e => { if (e.key === "Enter") void handleAddTask(); }}
        />
        <Button size="sm" onClick={() => void handleAddTask()} disabled={addTask.isPending || !newTitle.trim()}>
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>

      {phases.map(phase => {
        const tasks = c.tasks.filter(t => t.phase === phase);
        if (!tasks.length) return null;
        const done = tasks.filter(t => t.status === "DONE").length;
        const pct = Math.round((done / tasks.length) * 100);
        const pending = tasks.filter(t => t.status !== "DONE" && t.status !== "SKIPPED");
        return (
          <div key={phase}>
            <div className="mb-2 flex items-center gap-2">
              <div className={cn("inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-semibold", PHASE_COLOR[phase] ?? "")}>
                {PHASE_LABEL[phase]}
              </div>
              <span className="font-mono text-[10px] text-muted-foreground">{done}/{tasks.length}</span>
              <div className="h-1 w-20 overflow-hidden rounded-full bg-muted/40">
                <div
                  className={cn("h-full transition-all", pct === 100 ? "bg-emerald-500" : pct >= 50 ? "bg-orange-500" : "bg-red-500")}
                  style={{ width: `${pct}%` }}
                />
              </div>
              {pending.length > 0 && (
                <button
                  onClick={() => { pending.forEach(t => void updateTask.mutateAsync({ taskId: t.id, status: "DONE", operatorCi })); }}
                  disabled={updateTask.isPending}
                  className="ml-auto rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:cursor-wait disabled:opacity-60"
                  title="Marcar todas las tareas pendientes de esta fase como completadas"
                >
                  ✓ Completar fase ({pending.length})
                </button>
              )}
            </div>
            <div className="space-y-1.5">
              {tasks.map(task => (
                <TaskRow key={task.id} task={task} updateTask={updateTask} operatorCi={operatorCi} />
              ))}
            </div>
          </div>
        );
      })}
      {c.tasks.length === 0 && (
        <div className="rounded-md border border-dashed border-border/50 bg-muted/10 px-4 py-6 text-center">
          <CheckSquare className="mx-auto mb-2 h-6 w-6 text-muted-foreground/50" aria-hidden />
          <p className="text-sm text-muted-foreground">Sin tareas todavía.</p>
          <p className="mt-1 text-xs text-muted-foreground/70">
            Cargá una plantilla NIST/SANS desde arriba o agregá una tarea libre
            con el formulario. Las tareas estructuran las fases Detection → Recovery.
          </p>
        </div>
      )}
    </div>
  );
}

function TaskRow({
  task, updateTask, operatorCi,
}: {
  task: CaseTask;
  updateTask: ReturnType<typeof useUpdateTask>;
  operatorCi: string;
}) {
  const STATUS_OPTIONS: TaskStatus[] = ["OPEN", "IN_PROGRESS", "DONE", "SKIPPED"];
  const STATUS_LABEL: Record<TaskStatus, string> = {
    OPEN: "Pendiente", IN_PROGRESS: "En curso", DONE: "Completada", SKIPPED: "Omitida",
  };
  const STATUS_COLOR: Record<TaskStatus, string> = {
    OPEN:        "text-muted-foreground",
    IN_PROGRESS: "text-yellow-400",
    DONE:        "text-emerald-400",
    SKIPPED:     "text-muted-foreground/50",
  };

  return (
    <div className={cn(
      "flex items-start gap-2 rounded-md border px-3 py-2",
      task.status === "DONE" ? "border-emerald-500/20 bg-emerald-500/5 opacity-70" :
      task.status === "SKIPPED" ? "border-border/40 opacity-40" :
      "border-border/60 bg-card/50",
    )}>
      <button
        onClick={() => void updateTask.mutateAsync({
          taskId: task.id,
          status: task.status === "DONE" ? "OPEN" : "DONE",
          operatorCi,
        })}
        className={cn("mt-0.5 h-4 w-4 shrink-0 rounded border", task.status === "DONE"
          ? "border-emerald-500 bg-emerald-500/20 text-emerald-400"
          : "border-border/60",
        )}
      >
        {task.status === "DONE" && <CheckSquare className="h-4 w-4" />}
      </button>
      <div className="min-w-0 flex-1">
        <p className={cn("text-xs font-medium", task.status === "DONE" ? "line-through text-muted-foreground" : "")}>
          {task.title}
        </p>
        {task.description && <p className="text-[11px] text-muted-foreground">{task.description}</p>}
      </div>
      <select
        value={task.status}
        onChange={e => void updateTask.mutateAsync({
          taskId: task.id,
          status: e.target.value as TaskStatus,
          operatorCi,
        })}
        className={cn(
          "h-6 rounded border border-input bg-background px-1.5 text-[10px]",
          STATUS_COLOR[task.status as TaskStatus] ?? "",
        )}
      >
        {STATUS_OPTIONS.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
      </select>
    </div>
  );
}

// ── Assets Tab ───────────────────────────────────────────────────────────────

export function AssetsTab({
  caseId, c, operatorCi,
}: { caseId: string; c: FullCase; operatorCi: string }) {
  const [value, setValue] = useState("");
  const [type,  setType]  = useState("HOST");
  const [addingAll, setAddingAll] = useState(false);
  const addAsset = useAddAsset(caseId);

  // Sugerencias derivadas del caso (IOC + timeline), dedup contra los assets ya
  // registrados. Se recalculan cuando cambian assets/iocs/timeline.
  const suggestions = useMemo(() => suggestAssets(c), [c]);

  async function handleAdd() {
    if (!value.trim()) return;
    await addAsset.mutateAsync({ assetValue: value.trim(), assetType: type as never, addedBy: operatorCi });
    setValue("");
  }

  async function addSuggestion(s: AssetSuggestion) {
    await addAsset.mutateAsync({
      assetValue: s.assetValue, assetType: s.assetType as never,
      ipAddress: s.ipAddress, hostname: s.hostname, domain: s.domain,
      compromised: s.compromised, addedBy: operatorCi,
    });
  }

  async function addAll() {
    setAddingAll(true);
    try {
      for (const s of suggestions) await addSuggestion(s);
    } finally {
      setAddingAll(false);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <select value={type} onChange={e => setType(e.target.value)}
          className="h-9 rounded-md border border-input bg-background px-2 text-xs">
          {["HOST", "USER", "ACCOUNT", "ENDPOINT", "NETWORK", "OTHER"].map(t => <option key={t}>{t}</option>)}
        </select>
        <Input value={value} onChange={e => setValue(e.target.value)}
          placeholder="IP, hostname, usuario…" className="text-xs"
          onKeyDown={e => { if (e.key === "Enter") void handleAdd(); }} />
        <Button size="sm" onClick={() => void handleAdd()} disabled={addAsset.isPending || !value.trim()}>
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>

      {/* Sugerencias automáticas — assets involucrados deducidos del caso */}
      {suggestions.length > 0 && (
        <div className="rounded-md border border-sky-500/30 bg-sky-500/5 p-2.5">
          <div className="mb-2 flex items-center gap-2">
            <Sparkles className="h-3.5 w-3.5 text-sky-400" />
            <span className="text-[11px] font-bold uppercase tracking-wider text-sky-300">
              Assets sugeridos del caso
            </span>
            <span className="text-[10px] text-muted-foreground">{suggestions.length}</span>
            <Button size="sm" variant="outline" className="ml-auto h-6 text-[10px]"
              onClick={() => void addAll()} disabled={addAsset.isPending || addingAll}>
              {addingAll ? "Agregando…" : "Agregar todos"}
            </Button>
          </div>
          <div className="space-y-1.5">
            {suggestions.map(s => (
              <div key={s.assetValue} className="flex items-center gap-2 rounded border border-border/40 bg-background/40 px-2 py-1.5 text-xs">
                <span className="rounded bg-muted/40 px-1.5 py-0 text-[9px] uppercase text-muted-foreground">{s.assetType}</span>
                <span className="truncate font-mono text-foreground/90" title={s.assetValue}>{s.assetValue}</span>
                {s.compromised && (
                  <span className="rounded border border-red-500/40 bg-red-500/10 px-1 py-0 text-[9px] text-red-400">comprometido</span>
                )}
                <span className="ml-auto text-[9px] text-muted-foreground/70">{s.origin}</span>
                <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]"
                  onClick={() => void addSuggestion(s)} disabled={addAsset.isPending}>
                  <Plus className="mr-0.5 h-3 w-3" /> Agregar
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {c.assets.length === 0 ? (
        suggestions.length === 0 && (
          <p className="text-sm text-muted-foreground">Sin assets registrados.</p>
        )
      ) : (
        <div className="space-y-2">
          {c.assets.map(a => (
            <div key={a.id} className={cn(
              "flex items-start gap-3 rounded-md border px-3 py-2 text-xs",
              a.compromised ? "border-red-500/30 bg-red-500/5" : "border-border/60",
            )}>
              <div className="flex-1 space-y-0.5">
                <div className="flex items-center gap-2 font-mono font-medium">
                  {a.asset_value}
                  {a.compromised && (
                    <span className="rounded border border-red-500/40 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400">
                      COMPROMETIDO
                    </span>
                  )}
                </div>
                <p className="text-muted-foreground">
                  {a.asset_type}{a.ip_address ? ` · ${a.ip_address}` : ""}{a.hostname ? ` · ${a.hostname}` : ""}
                </p>
                {a.containment_status && (
                  <span className="text-[10px] text-muted-foreground/70">Contención: {a.containment_status}</span>
                )}
              </div>
              <span className="text-[10px] text-muted-foreground">{formatDateTimePy(a.created_at)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Evidences Tab ────────────────────────────────────────────────────────────

export function EvidencesTab({
  caseId, c, operatorCi,
}: { caseId: string; c: FullCase; operatorCi: string }) {
  const [name, setName]     = useState("");
  const [evType, setEvType] = useState("LOG");
  const [desc, setDesc]     = useState("");
  const [hash, setHash]     = useState("");
  const addEvidence = useAddEvidence(caseId);

  async function handleAdd() {
    if (!name.trim()) return;
    await addEvidence.mutateAsync({
      evidenceType: evType as never,
      name:         name.trim(),
      description:  desc || undefined,
      collectedBy:  operatorCi || "system",
      hashSha256:   hash || undefined,
    });
    setName(""); setDesc(""); setHash("");
  }

  return (
    <div className="space-y-3">
      <Card className="border-border/70">
        <CardHeader className="pb-2">
          <CardTitle className="text-xs">Registrar evidencia</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex gap-2">
            <select value={evType} onChange={e => setEvType(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-2 text-xs">
              {["LOG", "PCAP", "SCREENSHOT", "DUMP", "ARTIFACT", "OTHER"].map(t => <option key={t}>{t}</option>)}
            </select>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="Nombre de la evidencia…" className="flex-1 text-xs" />
          </div>
          <Input value={desc} onChange={e => setDesc(e.target.value)} placeholder="Descripción (opcional)…" className="text-xs" />
          <div className="flex gap-2">
            <Input value={hash} onChange={e => setHash(e.target.value)} placeholder="SHA-256 (opcional)…" className="font-mono text-xs" />
            <Button size="sm" onClick={() => void handleAdd()} disabled={addEvidence.isPending || !name.trim()}>
              <Plus className="mr-1 h-3.5 w-3.5" />Añadir
            </Button>
          </div>
        </CardContent>
      </Card>

      {c.evidences.length === 0 ? (
        <p className="text-sm text-muted-foreground">Sin evidencias registradas.</p>
      ) : (
        <div className="space-y-2">
          {c.evidences.map(ev => (
            <div key={ev.id} className="rounded-md border border-border/60 px-3 py-2 text-xs space-y-1">
              <div className="flex items-center gap-2">
                <FileText className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="font-medium">{ev.name}</span>
                <Badge variant="outline" className="text-[10px]">{ev.evidence_type}</Badge>
              </div>
              {ev.description && <p className="text-muted-foreground">{ev.description}</p>}
              <div className="flex flex-wrap gap-3 text-[10px] text-muted-foreground">
                <span>Recolectado por: <span className="text-foreground">{ev.collected_by}</span></span>
                <span>{formatDateTimePy(ev.collected_at)}</span>
                {ev.hash_sha256 && <span className="font-mono">SHA-256: {ev.hash_sha256.slice(0, 16)}…</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── IOCs Tab ─────────────────────────────────────────────────────────────────

const TLP_STYLES: Record<string, string> = {
  WHITE: "border-gray-400/40 bg-gray-400/10 text-gray-400",
  GREEN: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  AMBER: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  RED:   "border-red-500/40 bg-red-500/10 text-red-400",
};

export function IocsTab({
  caseId, c, operatorCi,
}: { caseId: string; c: FullCase; operatorCi: string }) {
  const [value, setValue] = useState("");
  const [type,  setType]  = useState("ip");
  const [tlp,   setTlp]   = useState("AMBER");
  const addIoc = useAddIoc(caseId);

  async function handleAdd() {
    if (!value.trim()) return;
    await addIoc.mutateAsync({ iocType: type, iocValue: value.trim(), tlp: tlp as never, addedBy: operatorCi });
    setValue("");
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <select value={type} onChange={e => setType(e.target.value)}
          className="h-9 rounded-md border border-input bg-background px-2 text-xs">
          {["ip", "domain", "hash_md5", "hash_sha256", "url", "email", "filename"].map(t => <option key={t}>{t}</option>)}
        </select>
        <select value={tlp} onChange={e => setTlp(e.target.value)}
          className="h-9 rounded-md border border-input bg-background px-2 text-xs">
          {["WHITE", "GREEN", "AMBER", "RED"].map(t => <option key={t}>{t}</option>)}
        </select>
        <Input value={value} onChange={e => setValue(e.target.value)}
          placeholder="Valor del IOC…" className="flex-1 text-xs"
          onKeyDown={e => { if (e.key === "Enter") void handleAdd(); }} />
        <Button size="sm" onClick={() => void handleAdd()} disabled={addIoc.isPending || !value.trim()}>
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>
      {c.iocs.length === 0 ? (
        <p className="text-sm text-muted-foreground">Sin IOCs registrados.</p>
      ) : (
        <div className="space-y-2">
          {c.iocs.map(ioc => (
            <div key={ioc.id} className="flex items-start gap-3 rounded-md border border-border/60 px-3 py-2 text-xs">
              <div className="flex-1 space-y-0.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-medium">{ioc.ioc_value}</span>
                  {ioc.is_primary && <Badge variant="outline" className="text-[10px]">Primary</Badge>}
                  <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", TLP_STYLES[ioc.tlp] ?? TLP_STYLES.AMBER)}>
                    TLP:{ioc.tlp}
                  </span>
                  {/* Veredicto por-IOC inline, derivado de la reputación enriquecida */}
                  {(() => {
                    const vt = ioc.vt_malicious ?? null;
                    const ab = ioc.abuse_score ?? null;
                    const misp = Boolean(ioc.in_misp);
                    if (vt == null && ab == null && !misp) {
                      return <span className="rounded border border-border/50 px-1.5 py-0.5 text-[10px] text-muted-foreground">Sin datos</span>;
                    }
                    const [label, cls] =
                      (vt ?? 0) > 0 || (ab ?? 0) >= 50 || misp
                        ? ["Malicioso", "border-red-500/40 bg-red-500/10 text-red-400"]
                        : (ab ?? 0) >= 25
                          ? ["Sospechoso", "border-amber-500/40 bg-amber-500/10 text-amber-300"]
                          : ["Limpio", "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"];
                    return <span className={cn("rounded border px-1.5 py-0.5 text-[10px] font-semibold", cls)}>{label}</span>;
                  })()}
                </div>
                <p className="text-muted-foreground">{ioc.ioc_type}</p>
                <div className="flex flex-wrap gap-1">
                  {ioc.vt_malicious != null && ioc.vt_malicious > 0 && (
                    <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400">
                      VT {ioc.vt_malicious}
                    </span>
                  )}
                  {ioc.in_misp && (
                    <span className="rounded border border-fuchsia-500/30 bg-fuchsia-500/10 px-1.5 py-0.5 text-[10px] text-fuchsia-400">
                      MISP
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Outliers Tab ─────────────────────────────────────────────────────────────
// Tab "Outliers relacionados" del case detail: consulta
// GET /api/outliers/for-case/:caseId que a su vez hace JOIN entre los IOCs
// del caso (case_iocs en Postgres) y la tabla Iceberg hunting.outliers.
// Alimentado por el DAG outlier_detection_6h — ver docs/OUTLIER-DETECTION.md.

type OutlierForCase = {
  outlier_id: string;
  detection_time: string;
  entity_type: string;
  entity_value: string;
  score: number;
  z_score: number | null;
  anomaly_type: string;
  severity: string;
  log_family: string;
  window_hours: number;
  details?: string | null;
  related_ioc_id?: string | null;
  related_case_id?: string | null;
  acknowledged_at?: string | null;
};

type OutlierForCaseResponse = {
  ok: boolean;
  rows: OutlierForCase[];
  ioc_count?: number;
  note?: string;
};

function useOutliersForCase(caseId: string) {
  return useQuery<OutlierForCaseResponse>({
    queryKey: ["outliers-for-case", caseId],
    queryFn: async () => {
      const { data } = await api.get<OutlierForCaseResponse>(
        `/api/outliers/for-case/${encodeURIComponent(caseId)}`,
      );
      return data;
    },
    enabled: Boolean(caseId),
    staleTime: 60_000,
  });
}

function outlierSevClass(sev: string): string {
  const l = sev.toLowerCase();
  if (l === "critical") return "border-red-500/50 bg-red-500/10 text-red-400";
  if (l === "high")     return "border-orange-500/50 bg-orange-500/10 text-orange-400";
  if (l === "medium")   return "border-yellow-500/50 bg-yellow-500/10 text-yellow-400";
  if (l === "low")      return "border-emerald-500/50 bg-emerald-500/10 text-emerald-400";
  return "border-border bg-muted/30 text-muted-foreground";
}

export function OutliersTab({ caseId }: { caseId: string }) {
  const { data, isLoading, error } = useOutliersForCase(caseId);
  const rows = data?.rows ?? [];

  if (isLoading) {
    return (
      <div className="space-y-2">
        <div className="h-6 w-40 animate-pulse rounded bg-muted/40" />
        <div className="h-24 w-full animate-pulse rounded bg-muted/30" />
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">
        Error al cargar outliers: {error instanceof Error ? error.message : "desconocido"}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Contexto: explica de dónde salen estos datos. Si no hay IOCs en el
          caso, el backend devuelve `note` — lo mostramos como hint. */}
      <div className="flex items-start gap-2 rounded-md border border-border/60 bg-muted/20 p-3 text-xs">
        <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
        <div>
          <p className="font-semibold text-foreground/90">
            Anomalías detectadas relacionadas al caso
          </p>
          <p className="mt-0.5 text-muted-foreground">
            Match por <code className="font-mono">entity_value</code> o
            <code className="ml-1 font-mono">related_ioc_id</code> contra los IOCs del caso
            {data?.ioc_count != null && ` · ${data.ioc_count} IOCs evaluados`}
            . Ventana de detección: 7 días.
          </p>
          {data?.note && (
            <p className="mt-1 text-muted-foreground">{data.note}</p>
          )}
        </div>
      </div>

      {rows.length === 0 ? (
        <Card className="border-border/60">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
            <Sparkles className="h-8 w-8 opacity-40" aria-hidden />
            <p>Este caso no tiene outliers asociados.</p>
            <p className="text-xs">
              El DAG <span className="font-mono">outlier_detection_6h</span> corre cada 6h —
              si la anomalía es reciente, puede aparecer en el próximo ciclo.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-border/60">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Sparkles className="h-4 w-4 text-primary" aria-hidden />
              {rows.length} outlier{rows.length !== 1 ? "s" : ""}
              <Badge variant="outline" className="ml-2 text-[10px]">7d</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border/40">
              {rows.map((o) => (
                <div key={o.outlier_id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-xs">
                  <span className={cn(
                    "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                    outlierSevClass(o.severity),
                  )}>
                    {o.severity}
                  </span>
                  <div className="flex min-w-0 flex-col">
                    <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                      {o.entity_type} · {o.anomaly_type}
                    </span>
                    <span className="truncate font-mono text-[11px]">{o.entity_value}</span>
                  </div>
                  <div className="ml-auto flex items-center gap-3">
                    <span className="text-muted-foreground">{o.log_family}</span>
                    {o.z_score != null && (
                      <span className="tabular-nums text-muted-foreground">
                        z={o.z_score.toFixed(2)}
                      </span>
                    )}
                    <span className="rounded bg-primary/10 px-2 py-0.5 font-semibold tabular-nums text-primary">
                      score {o.score.toFixed(1)}
                    </span>
                    <span className="whitespace-nowrap text-muted-foreground">
                      {formatDateTimePy(o.detection_time)}
                    </span>
                    {o.acknowledged_at && (
                      <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-400">
                        ack
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── CVEs Tab (B1 audit Casos 2026-05-21) ─────────────────────────────────────
// Consume GET /api/cases/:id/cves — consolida dos canales:
//   · Wazuh vulnerability-detector: vulnerabilidades *instaladas* en los
//     hosts/IPs del caso (paquete vulnerable presente).
//   · Patrones de explotación: heurísticas regex aplicadas sobre los IOCs
//     del caso (Log4Shell, ProxyLogon, etc.) — indica intento *de uso*.
// Los dos canales se complementan; un caso puede tener uno, otro o ambos.

type NvdEnrichment = {
  cvssV3Score: number | null;
  cvssV3Severity: string | null;
  cvssV3Vector: string | null;
  cvssV2Score: number | null;
  cweIds: string[];
  description: string | null;
  references: string[];
  vulnStatus: string | null;
  publishedAt: string | null;
  // EPSS (I1): probabilidad de explotación a 30 días [0..1] + percentil [0..1].
  epssScore: number | null;
  epssPercentile: number | null;
};

type KevInfo = {
  vendorProject: string | null;
  product: string | null;
  vulnerabilityName: string | null;
  dateAdded: string | null;
  shortDescription: string | null;
  requiredAction: string | null;
  dueDate: string | null;
  knownRansomwareUse: boolean;
};

type CvesResponse = {
  caseId: string;
  windowDays: number;
  wazuhCves: Array<{
    cve_id: string;
    cvss_score: number;
    cvss_source: string;
    severity: string | null;
    package_name: string | null;
    package_version: string | null;
    vuln_title: string | null;
    host_name: string | null;
    host_ip: string | null;
    rule_description: string | null;
    alert_count: number;
    last_seen: string | null;
    nvd: NvdEnrichment | null;
    kev: KevInfo | null;
    officialScore: number;
  }>;
  patterns: Array<{
    name: string;
    cve?: string;
    mitre?: string;
    tone: "crit" | "high" | "warn";
    detail: string;
    source: "pattern" | "cve_literal";
    sourceIocValue?: string;
    sourceIocType?: string;
    nvd: NvdEnrichment | null;
    kev: KevInfo | null;
  }>;
  maxTone: "crit" | "high" | "warn" | null;
  counts: {
    wazuh: number; patterns: number; assets: number; iocs: number;
    nvdHits?: number; kevHits?: number;
  };
  errors?: string[];
};

function useCaseCves(caseId: string, days: number, pollPending = true) {
  return useQuery<CvesResponse>({
    queryKey: ["case-cves", caseId, days],
    queryFn: async () => {
      const { data } = await api.get<CvesResponse>(
        `/api/cases/${encodeURIComponent(caseId)}/cves`,
        { params: { days } },
      );
      return data;
    },
    enabled: Boolean(caseId),
    staleTime: 60_000,
    // NVD se hidrata async — si todavía hay CVEs sin enrichment, repolleamos
    // cada 15s hasta que entren al cache. Cuando todos tengan nvd!=null o
    // sean patterns sin CVE, dejamos de repollear. El parent puede forzar
    // stop pasando `pollPending=false` (ej. tras timeout 60s).
    refetchInterval: (q) => {
      if (!pollPending) return false;
      const d = q.state.data as CvesResponse | undefined;
      if (!d) return false;
      const allCves = [
        ...d.wazuhCves.map(w => ({ cve: w.cve_id, nvd: w.nvd })),
        ...d.patterns.filter(p => p.cve).map(p => ({ cve: p.cve!, nvd: p.nvd })),
      ];
      const pending = allCves.some(c => c.cve && c.nvd === null);
      return pending ? 15_000 : false;
    },
  });
}

function toneClass(tone: "crit" | "high" | "warn"): string {
  if (tone === "crit") return "border-red-500/50 bg-red-500/10 text-red-400";
  if (tone === "high") return "border-orange-500/50 bg-orange-500/10 text-orange-400";
  return "border-yellow-500/50 bg-yellow-500/10 text-yellow-400";
}

function cvssTone(score: number): "crit" | "high" | "warn" {
  if (score >= 9) return "crit";
  if (score >= 7) return "high";
  return "warn";
}

/**
 * Tono consolidado para un CVE — combina KEV (explotación activa) + CVSS v3
 * oficial NVD + CVSS Wazuh + tono del pattern en una sola decisión visual.
 *
 * Reglas (mayor → menor prioridad):
 *   · kev.knownRansomwareUse → crit (incidente activo conocido por ransomware)
 *   · kev !== null            → crit (CISA lo cataloga como explotación activa)
 *   · CVSS v3 NVD ≥ 9         → crit
 *   · CVSS v3 NVD ≥ 7         → high
 *   · CVSS v3 NVD definido    → warn
 *   · fallback wazuhScore     → cvssTone(score)
 *   · fallback patternTone    → patternTone
 *   · sin datos               → warn
 */
function effectiveTone(args: {
  nvd?: NvdEnrichment | null;
  kev?: KevInfo | null;
  wazuhScore?: number;
  patternTone?: "crit" | "high" | "warn";
}): "crit" | "high" | "warn" {
  if (args.kev) return "crit"; // KEV siempre eleva al máximo
  const v3 = args.nvd?.cvssV3Score;
  if (v3 != null) return cvssTone(v3);
  if (args.wazuhScore != null && args.wazuhScore > 0) return cvssTone(args.wazuhScore);
  if (args.patternTone) return args.patternTone;
  return "warn";
}

/**
 * Sub-componente: badges/metadata NVD + KEV que se reusa entre wazuhCves y
 * patterns. Compacto — diseñado para una línea horizontal extra debajo del
 * título del CVE.
 */
function NvdKevDecorations({
  nvd, kev, timedOut = false,
}: { nvd: NvdEnrichment | null; kev: KevInfo | null; timedOut?: boolean }) {
  if (!nvd && !kev) {
    return (
      <span className={cn(
        "text-[10px] italic",
        timedOut ? "text-amber-400/80" : "text-muted-foreground/60",
      )}>
        {timedOut
          ? "NVD: no disponible (tras 60s) — refrescá para reintentar"
          : "NVD: hidratando…"}
      </span>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
      {kev && (
        <span
          className={cn(
            "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-semibold uppercase",
            kev.knownRansomwareUse
              ? "border-red-500/60 bg-red-500/20 text-red-300"
              : "border-orange-500/60 bg-orange-500/15 text-orange-300",
          )}
          title={kev.shortDescription ?? kev.vulnerabilityName ?? ""}
        >
          🚨 KEV
          {kev.knownRansomwareUse && " · ransomware"}
          {kev.dueDate && (
            <span className="font-mono opacity-70">due {kev.dueDate}</span>
          )}
        </span>
      )}
      {nvd?.cvssV3Score != null && (
        <span
          className={cn(
            "tabular-nums rounded border px-1.5 py-0.5",
            toneClass(cvssTone(nvd.cvssV3Score)),
          )}
          title={nvd.cvssV3Vector ?? ""}
        >
          NVD v3 {nvd.cvssV3Score.toFixed(1)}
          {nvd.cvssV3Severity ? ` ${nvd.cvssV3Severity}` : ""}
        </span>
      )}
      {nvd?.epssScore != null && (
        <span
          className={cn(
            "tabular-nums rounded border px-1.5 py-0.5",
            nvd.epssScore >= 0.5
              ? "border-red-500/50 bg-red-500/10 text-red-400"
              : nvd.epssScore >= 0.1
                ? "border-orange-500/50 bg-orange-500/10 text-orange-400"
                : "border-border/40 bg-muted/20 text-muted-foreground",
          )}
          title={
            "EPSS — probabilidad de explotación a 30 días (FIRST.org)"
            + (nvd.epssPercentile != null
              ? ` · percentil ${(nvd.epssPercentile * 100).toFixed(0)}%`
              : "")
          }
        >
          EPSS {(nvd.epssScore * 100).toFixed(nvd.epssScore >= 0.1 ? 0 : 1)}%
        </span>
      )}
      {(nvd?.cweIds ?? []).slice(0, 3).map((cwe) => (
        <a
          key={cwe}
          href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, "")}.html`}
          target="_blank"
          rel="noopener noreferrer"
          className="rounded border border-purple-500/40 bg-purple-500/10 px-1.5 py-0.5 font-mono text-purple-400 hover:bg-purple-500/20"
        >
          {cwe}
        </a>
      ))}
      {nvd?.vulnStatus && /awaiting/i.test(nvd.vulnStatus) && (
        <span className="rounded border border-border/40 px-1.5 py-0.5 text-muted-foreground italic">
          NVD: {nvd.vulnStatus}
        </span>
      )}
    </div>
  );
}

export function CvesTab({ caseId }: { caseId: string }) {
  const [days, setDays] = useState(7);
  // Timeout para NVD hidratación async: si tras 4 polls (~60s) seguimos con
  // CVEs sin nvd, asumimos que NVD está caído o saturado y paramos el polling.
  // El usuario puede forzar reintento manual con el botón refresh.
  const [nvdTimedOut, setNvdTimedOut] = useState(false);
  const { data, isLoading, error, refetch } = useCaseCves(caseId, days, !nvdTimedOut);

  // Cuenta polls con pending; cuando llega a 4 (≈60s) seteamos timeout.
  // Se resetea cuando todos los CVEs tienen nvd o cuando cambia caseId/days.
  const pollCountRef = useRef(0);
  useEffect(() => { pollCountRef.current = 0; setNvdTimedOut(false); }, [caseId, days]);
  useEffect(() => {
    if (!data) return;
    const allCves = [
      ...data.wazuhCves.map(w => ({ cve: w.cve_id, nvd: w.nvd })),
      ...data.patterns.filter(p => p.cve).map(p => ({ cve: p.cve!, nvd: p.nvd })),
    ];
    const pending = allCves.some(c => c.cve && c.nvd === null);
    if (!pending) {
      pollCountRef.current = 0;
      if (nvdTimedOut) setNvdTimedOut(false);
      return;
    }
    pollCountRef.current += 1;
    if (pollCountRef.current >= 4 && !nvdTimedOut) setNvdTimedOut(true);
  }, [data, nvdTimedOut]);

  function forceRefreshNvd() {
    pollCountRef.current = 0;
    setNvdTimedOut(false);
    void refetch();
  }

  if (isLoading) {
    return (
      <div className="space-y-2">
        <div className="h-6 w-40 animate-pulse rounded bg-muted/40" />
        <div className="h-24 w-full animate-pulse rounded bg-muted/30" />
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">
        Error al cargar CVEs: {error instanceof Error ? error.message : "desconocido"}
      </div>
    );
  }

  const wazuh = data?.wazuhCves ?? [];
  const patterns = data?.patterns ?? [];
  const empty = wazuh.length === 0 && patterns.length === 0;

  return (
    <div className="space-y-4">
      {/* Header: contexto + selector de ventana */}
      <div className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-border/60 bg-muted/20 p-3 text-xs">
        <div className="flex items-start gap-2">
          <Bug className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
          <div>
            <p className="font-semibold text-foreground/90">
              Vulnerabilidades y patrones de explotación detectados
            </p>
            <p className="mt-0.5 text-muted-foreground">
              · <span className="font-semibold text-foreground/80">Wazuh vuln-detector</span>:
              CVEs *instaladas* en los hosts del caso (filtrado por
              <code className="mx-1 font-mono">case_assets</code>).
              · <span className="font-semibold text-foreground/80">Patrones</span>:
              firmas de exploit aplicadas sobre los IOCs del caso (Log4Shell,
              ProxyLogon, etc.).
            </p>
            {data?.counts && (
              <p className="mt-1 text-muted-foreground/80">
                {data.counts.assets} assets · {data.counts.iocs} IOCs ·
                {" "}{wazuh.length} CVEs · {patterns.length} patrones
                {data.counts.nvdHits != null && data.counts.nvdHits > 0 && (
                  <> · {data.counts.nvdHits} hidratadas NVD</>
                )}
                {data.counts.kevHits != null && data.counts.kevHits > 0 && (
                  <> · <span className="font-semibold text-orange-300">{data.counts.kevHits} KEV</span></>
                )}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-[10px] uppercase tracking-wide text-muted-foreground">
            Ventana
          </label>
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="h-7 rounded border border-input bg-background px-2 text-xs"
          >
            {[1, 7, 14, 30, 60, 90].map(d => (
              <option key={d} value={d}>{d} día{d !== 1 ? "s" : ""}</option>
            ))}
          </select>
          <Button
            size="sm"
            variant="ghost"
            onClick={forceRefreshNvd}
            className={cn(
              "h-7 px-2 text-[11px]",
              nvdTimedOut && "border border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20",
            )}
            title={nvdTimedOut
              ? "Reintentar enrichment NVD — el último intento expiró tras 60s"
              : "Refrescar CVEs y NVD"}
          >
            <RefreshCw className="h-3 w-3" />
          </Button>
        </div>
      </div>

      {nvdTimedOut && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-[11px] text-amber-400">
          ⏱ NVD no respondió en 60s para algunos CVEs. Polling pausado para no
          saturar la API. Click en <RefreshCw className="inline h-3 w-3" /> para
          reintentar.
        </div>
      )}

      {data?.errors?.length && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-[11px] text-amber-400">
          ⚠ {data.errors.join(" · ")}
        </div>
      )}

      {empty && (
        <Card className="border-border/60">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
            <Bug className="h-8 w-8 opacity-40" aria-hidden />
            <p>Sin CVEs ni patrones de exploit asociados.</p>
            <p className="text-xs">
              Wazuh vuln-detector necesita assets con hostname o IP cargados.
              Los patrones requieren IOCs (URLs, payloads) con texto reconocible.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Patrones de explotación (más operativos para el SOC) */}
      {patterns.length > 0 && (
        <Card className="border-border/60">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-orange-400" aria-hidden />
              Patrones de explotación
              <Badge variant="outline" className="ml-2 text-[10px]">{patterns.length}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3">
            {/* Densidad: card por pattern con border-l-4 según tono.
                Reemplaza divide-y para dar respiro visual cuando hay 10+. */}
            <div className="space-y-2">
              {patterns.map((p, i) => {
                const tone = effectiveTone({ nvd: p.nvd, kev: p.kev, patternTone: p.tone });
                return (
                <div
                  key={`${p.name}-${p.cve ?? ""}-${i}`}
                  className={cn(
                    "rounded-md border bg-card/40 px-3 py-2.5 text-xs",
                    "border-l-4",
                    tone === "crit" ? "border-l-red-500"     :
                    tone === "high" ? "border-l-orange-500"  :
                                      "border-l-yellow-500",
                    "border-y-border/40 border-r-border/40",
                  )}
                >
                  {/* Línea 1: tono + título + CVE + MITRE */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={cn(
                      "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                      toneClass(tone),
                    )}>
                      {tone}
                    </span>
                    <span className="font-semibold">{p.name}</span>
                    {p.cve && (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${p.cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded border border-border/60 px-1.5 py-0.5 font-mono text-[11px] hover:bg-muted/40"
                      >
                        {p.cve}
                        <ExternalLink className="h-2.5 w-2.5" />
                      </a>
                    )}
                    {p.mitre && (
                      <span className="rounded border border-blue-500/40 bg-blue-500/10 px-1.5 py-0.5 text-[10px] text-blue-400">
                        {p.mitre}
                      </span>
                    )}
                  </div>

                  {/* Línea 2: badges NVD/KEV (espacio dedicado) */}
                  {p.cve && (
                    <div className="mt-1.5">
                      <NvdKevDecorations nvd={p.nvd} kev={p.kev} timedOut={nvdTimedOut} />
                    </div>
                  )}

                  {/* Línea 3: descripción NVD (limitada a 2 líneas) */}
                  {p.nvd?.description && (
                    <p className="mt-1.5 text-[11px] leading-snug text-muted-foreground line-clamp-2"
                       title={p.nvd.description}>
                      {p.nvd.description}
                    </p>
                  )}

                  {/* Línea 4: contexto del match (IOC + payload detectado) */}
                  <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted-foreground/80">
                    {p.sourceIocValue && (
                      <span className="font-mono" title={p.sourceIocValue}>
                        ← {p.sourceIocType}: <span className="text-muted-foreground">{p.sourceIocValue}</span>
                      </span>
                    )}
                    <code className="truncate font-mono" title={p.detail}>
                      {p.detail}
                    </code>
                  </div>
                </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Wazuh vulnerability-detector */}
      {wazuh.length > 0 && (
        <Card className="border-border/60">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-primary" aria-hidden />
              CVEs reportadas por Wazuh
              <Badge variant="outline" className="ml-2 text-[10px]">{wazuh.length}</Badge>
              <Badge variant="outline" className="text-[10px]">{days}d</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3">
            <div className="space-y-2">
              {wazuh.map((w) => {
                const wazuhScore = Number(w.cvss_score) || 0;
                // Tono consolidado: KEV/NVD v3 toman precedencia sobre el
                // CVSS local de Wazuh para evitar dos lógicas convivientes.
                const tone = effectiveTone({ nvd: w.nvd, kev: w.kev, wazuhScore });
                return (
                  <div
                    key={w.cve_id}
                    className={cn(
                      "rounded-md border bg-card/40 px-3 py-2.5 text-xs",
                      "border-l-4",
                      tone === "crit" ? "border-l-red-500"     :
                      tone === "high" ? "border-l-orange-500"  :
                                        "border-l-yellow-500",
                      "border-y-border/40 border-r-border/40",
                    )}
                  >
                    {/* Línea 1: CVSS + CVE id + severity Wazuh */}
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={cn(
                        "tabular-nums rounded border px-1.5 py-0.5 text-[10px] font-semibold",
                        toneClass(tone),
                      )}>
                        CVSS {Number(w.cvss_score).toFixed(1)}
                      </span>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${w.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-mono font-semibold hover:underline"
                      >
                        {w.cve_id}
                        <ExternalLink className="h-2.5 w-2.5" />
                      </a>
                      {w.severity && (
                        <span className="rounded border border-border/60 px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
                          {w.severity}
                        </span>
                      )}
                      <span className="text-[10px] text-muted-foreground/70">
                        {w.cvss_source}
                      </span>
                    </div>

                    {/* Línea 2: título de la vuln */}
                    {(w.vuln_title || w.rule_description) && (
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        {w.vuln_title ?? w.rule_description}
                      </p>
                    )}

                    {/* Línea 3: badges NVD/KEV */}
                    <div className="mt-1.5">
                      <NvdKevDecorations nvd={w.nvd} kev={w.kev} timedOut={nvdTimedOut} />
                    </div>

                    {/* Línea 4: descripción NVD */}
                    {w.nvd?.description && (
                      <p className="mt-1.5 text-[11px] leading-snug text-muted-foreground line-clamp-2"
                         title={w.nvd.description}>
                        {w.nvd.description}
                      </p>
                    )}

                    {/* Línea 5: paquete + host + alert count */}
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted-foreground/80">
                      {w.package_name && (
                        <span className="font-mono">
                          {w.package_name}{w.package_version ? `@${w.package_version}` : ""}
                        </span>
                      )}
                      {w.host_name && w.host_name !== "—" && <span>host: {w.host_name}</span>}
                      {w.host_ip && w.host_ip !== "—" && <span>ip: {w.host_ip}</span>}
                      <span>· {w.alert_count} alerta{w.alert_count !== 1 ? "s" : ""}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── Events Tab (F2 vista de eventos por caso) ───────────────────────────────
// Pagina eventos crudos de la fuente del caso vía GET /api/incidents/:id/events.
// Cubre el gap entre RawEventPanel (1 evento) y TraceabilityPanel (cap 50, 3
// fuentes UNION) cuando el snapshot Hunt Pivots reportó cientos/miles de
// alertas y el operador quiere recorrerlas dentro de la fuente del caso.

const EVT_SEV_TONE: Record<string, string> = {
  CRITICAL:   "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH:       "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM:     "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW:        "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  NEGLIGIBLE: "bg-zinc-700/15 text-zinc-500 border-zinc-700/30",
};
const EVT_HOURS_OPTIONS = [6, 24, 72, 168];
const EVT_PAGE_SIZE = 50;
const EVT_SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] as const;
type EvtSev = typeof EVT_SEVS[number] | "ALL";

export function EventsTab({ caseId }: { caseId: string }) {
  const [hours, setHours]     = useState<number>(24);
  const [severity, setSev]    = useState<EvtSev>("ALL");
  const [offset, setOffset]   = useState<number>(0);
  const [expanded, setExpanded] = useState<number | null>(null);

  // Reset offset cuando cambian filtros — la página actual deja de tener
  // sentido si el dataset subyacente cambió.
  useEffect(() => { setOffset(0); setExpanded(null); }, [caseId, hours, severity]);

  const { data, isLoading, isFetching, error, refetch } = useCaseEvents(caseId, {
    hours,
    limit: EVT_PAGE_SIZE,
    offset,
    severity: severity === "ALL" ? null : severity,
  });

  const events: CaseEventRow[] = data?.events ?? [];

  return (
    <div className="space-y-4">
      {/* Contexto + controles */}
      <div className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-border/60 bg-muted/20 p-3 text-xs">
        <div className="flex items-start gap-2">
          <FileText className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
          <div>
            <p className="font-semibold text-foreground/90">
              Eventos crudos de la fuente del caso
            </p>
            <p className="mt-0.5 text-muted-foreground">
              Match por IOC <code className="font-mono">{data?.ioc ?? "—"}</code> en{" "}
              <span className="font-semibold text-foreground/80">{data?.source ?? "—"}</span>{" "}
              · ventana ±{hours} h alrededor de la apertura del caso · cap {EVT_PAGE_SIZE}/página.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-[10px] uppercase tracking-wide text-muted-foreground">
            Ventana
          </label>
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="h-7 rounded border border-input bg-background px-2 text-xs"
          >
            {EVT_HOURS_OPTIONS.map(h => (
              <option key={h} value={h}>±{h} h</option>
            ))}
          </select>
          <label className="text-[10px] uppercase tracking-wide text-muted-foreground">
            Severity
          </label>
          <select
            value={severity}
            onChange={(e) => setSev(e.target.value as EvtSev)}
            className="h-7 rounded border border-input bg-background px-2 text-xs"
          >
            <option value="ALL">Todas</option>
            {EVT_SEVS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-xs"
            onClick={() => void refetch()}
            title="Reconsultar"
          >
            <RefreshCw className={cn("h-3 w-3", isFetching && "animate-spin")} />
          </Button>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          <div className="h-6 w-40 animate-pulse rounded bg-muted/40" />
          <div className="h-24 w-full animate-pulse rounded bg-muted/30" />
          <div className="h-24 w-full animate-pulse rounded bg-muted/30" />
        </div>
      ) : error ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">
          Error al cargar eventos: {error instanceof Error ? error.message : "desconocido"}
        </div>
      ) : events.length === 0 ? (
        <Card className="border-border/60">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
            <FileText className="h-8 w-8 opacity-40" aria-hidden />
            <p>Sin eventos para los filtros actuales.</p>
            <p className="text-xs">
              Probá ampliar la ventana o quitar el filtro de severity.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-border/60">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FileText className="h-4 w-4 text-primary" aria-hidden />
              {events.length} evento{events.length !== 1 ? "s" : ""}{" "}
              <span className="text-muted-foreground font-normal">
                · offset {offset}
                {data?.hasMore ? <> · <span className="text-amber-400">hay más</span></> : <> · fin del rango</>}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border/40">
              {events.map((ev, i) => {
                const tsLabel = ev.ts
                  ? formatDateTimePy(ev.ts)
                  : "—";
                const isOpen = expanded === i;
                return (
                  <div key={`${ev.ts ?? ""}-${i}`} className="px-4 py-2 text-xs">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className={cn(
                        "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                        EVT_SEV_TONE[ev.severity ?? "NEGLIGIBLE"] ?? EVT_SEV_TONE.NEGLIGIBLE,
                      )}>
                        {ev.severity ?? "—"}
                      </span>
                      <span className="whitespace-nowrap font-mono text-muted-foreground tabular-nums">
                        {tsLabel}
                      </span>
                      {ev.rule_id && (
                        <span className="rounded bg-muted/40 px-1.5 py-0.5 font-mono text-[10px]" title={ev.rule_desc ?? undefined}>
                          {ev.rule_id}
                        </span>
                      )}
                      {ev.host && (
                        <span className="text-muted-foreground">
                          host=<span className="font-mono text-foreground/90">{ev.host}</span>
                        </span>
                      )}
                      {ev.src_ip && (
                        <span className="text-muted-foreground">
                          src=<span className="font-mono text-foreground/90">{ev.src_ip}</span>
                        </span>
                      )}
                      {ev.dst_ip && (
                        <span className="text-muted-foreground">
                          dst=<span className="font-mono text-foreground/90">{ev.dst_ip}</span>
                        </span>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className="ml-auto h-6 px-2 text-[10px]"
                        onClick={() => setExpanded(isOpen ? null : i)}
                      >
                        {isOpen ? "Ocultar" : "Detalle"}
                      </Button>
                    </div>

                    {(ev.rule_desc || ev.msg_preview) && (
                      <div className="mt-1 truncate font-mono text-[11px] text-foreground/70" title={ev.rule_desc ?? ev.msg_preview ?? undefined}>
                        {ev.rule_desc ?? ev.msg_preview}
                      </div>
                    )}

                    {isOpen && ev.msg_preview && (
                      <pre className="mt-2 max-h-48 overflow-auto rounded border border-border/40 bg-background/60 p-2 font-mono text-[10.5px] leading-snug text-foreground/85 whitespace-pre-wrap break-all">
                        {ev.msg_preview}
                      </pre>
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Paginación */}
      {(offset > 0 || data?.hasMore) && (
        <div className="flex items-center justify-between rounded-md border border-border/60 bg-muted/10 px-3 py-2 text-xs">
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs"
            disabled={offset === 0 || isFetching}
            onClick={() => setOffset(Math.max(0, offset - EVT_PAGE_SIZE))}
          >
            ← Anterior
          </Button>
          <span className="text-muted-foreground">
            Página {Math.floor(offset / EVT_PAGE_SIZE) + 1}
            {isFetching && <span className="ml-2 text-[10px]">cargando…</span>}
          </span>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs"
            disabled={!data?.hasMore || isFetching}
            onClick={() => setOffset(offset + EVT_PAGE_SIZE)}
          >
            Siguiente →
          </Button>
        </div>
      )}
    </div>
  );
}

// Default export para que React.lazy() pueda cargar todos los tabs como un
// único chunk separado del Resumen (lazy "tab bundle"). El parent importa
// nombrado y usa Promise resolved con default = { TimelineTab, ... }.
const TabsBundle = { TimelineTab, TasksTab, AssetsTab, EvidencesTab, IocsTab, OutliersTab, CvesTab, EventsTab };
export default TabsBundle;

// Re-exports adicionales para consumidores que ya usaban estos íconos
// localmente desde CaseInvestigationView.
export { Clock };
