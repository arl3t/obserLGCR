/**
 * FindingCard — tarjeta SOC playbook con 5 campos (qué/dónde/por qué/refs/acción).
 *
 * Estructura visual fija para que el analista escanee rápidamente:
 *
 *   ┌─────────────────────────────────────────────┐
 *   │ [icon] CRITICAL · Credencial expuesta · O365│
 *   ├─────────────────────────────────────────────┤
 *   │ DÓNDE   RedLine dump · 2026-04-12           │
 *   │         admin@acme.py / 'Acme2024!'         │
 *   │ POR QUÉ Servicio CIS top 25 + cruce MISP    │
 *   │ REFS    [🔗 MISP] [🔗 Shodan]               │
 *   │ ACCIÓN  [Forzar reset] [Abrir caso]         │
 *   └─────────────────────────────────────────────┘
 *
 * Las acciones se delegan a `onAction(action, finding)`. La card no abre
 * modales ni cambia tabs — el contenedor (FindingsFeed/TabResumen) maneja
 * los handlers contra el Provider.
 */

import { useState } from "react";
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  CheckCheck,
  Clock,
  Hourglass,
  MessageSquarePlus,
  ShieldOff,
  Sparkles,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { formatRelativeTimeEs } from "@/lib/format";
import {
  KIND_ICON,
  KIND_LABEL,
  KIND_TINT,
  SEVERITY_BADGE,
  SEVERITY_BORDER,
  SEVERITY_LABEL,
} from "@/components/digital-surveillance/findings/finding-styles";
import { primaryTtp } from "@/components/digital-surveillance/risk-engine/mitre-attack-map";
import {
  useUpsertAnnotation,
  useDeleteAnnotation,
  AnnotationVersionConflict,
  type AnnotationRow,
  type AnnotationState,
} from "@/hooks/useSurveillanceWorkspace";
import { loadOperatorCi, saveOperatorCi, validateCi } from "@/lib/operator-ci";
import { cn } from "@/lib/utils";
import type {
  AnalystFinding,
  AnalystFindingAction,
  AnalystFindingRef,
} from "@/types/digital-surveillance";

const ANNOTATION_LABEL: Record<AnnotationState, string> = {
  triaged:          "Triaged",
  "false-positive": "Falso positivo",
  resolved:         "Resuelto",
};

const ANNOTATION_BADGE: Record<AnnotationState, string> = {
  triaged:          "border-sky-500/40    bg-sky-500/10    text-sky-700    dark:text-sky-400",
  "false-positive": "border-zinc-500/40   bg-zinc-500/10   text-zinc-700   dark:text-zinc-400",
  resolved:         "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
};

// ─────────────────────────────────────────────────────────────────────────────
// SLA / aging — color escalado por edad del finding
//
// Se aplica solo a `critical`/`high` porque los `medium`/`low` no tienen SLA
// agresivo. El timestamp de referencia es `evidenceTimestamp` (cuándo el dato
// se observó originalmente) — no `detectedAt` (cuándo el agregador lo emitió,
// que cambia con cada render).
// ─────────────────────────────────────────────────────────────────────────────

type AgeBucket = "fresh" | "warm" | "stale" | "old";

function ageBucket(iso: string | null): AgeBucket | null {
  if (!iso) return null;
  const ms = Date.now() - Date.parse(iso);
  if (Number.isNaN(ms) || ms < 0) return null;
  const hours = ms / (1000 * 60 * 60);
  if (hours < 1)  return "fresh";   // < 1h
  if (hours < 6)  return "warm";    // < 6h
  if (hours < 24) return "stale";   // < 24h
  return "old";                     // ≥ 24h
}

const AGE_BADGE: Record<AgeBucket, string> = {
  fresh: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  warm:  "border-amber-500/40  bg-amber-500/10  text-amber-700 dark:text-amber-400",
  stale: "border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-400",
  old:   "border-red-500/50    bg-red-500/15    text-red-700 dark:text-red-400 animate-pulse",
};

const AGE_LABEL: Record<AgeBucket, string> = {
  fresh: "< 1h",
  warm:  "< 6h",
  stale: "< 24h",
  old:   "≥ 24h",
};

/** Estado del finding relativo al análisis previo — feature #3 "¿qué cambió?". */
export type FindingDiffBadge =
  | { status: "new" }
  | { status: "severity-up"; prevSeverity: AnalystFinding["severity"] }
  | { status: "severity-down"; prevSeverity: AnalystFinding["severity"] };

export type FindingCardProps = {
  finding: AnalystFinding;
  /** Dominio bajo análisis — necesario para upsertear anotaciones (PK: domain+findingId). */
  domain: string;
  /** Despachar acción del botón. El parent decide qué hacer (open case, watchlist, etc). */
  onAction: (action: AnalystFindingAction, finding: AnalystFinding) => void;
  /** Click sobre un chip de ref — el parent navega al tab. */
  onRefClick: (ref: AnalystFindingRef, finding: AnalystFinding) => void;
  /** Anotación existente del finding (overlay del backend). Puede ser undefined si no hay. */
  annotation?: AnnotationRow;
  /** Estado del finding respecto al análisis previo (NEW / subió / bajó). */
  diffBadge?: FindingDiffBadge;
};

export function FindingCard({ finding, domain, onAction, onRefClick, annotation, diffBadge }: FindingCardProps) {
  const KindIcon = KIND_ICON[finding.kind];
  const tint = KIND_TINT[finding.kind];

  const primary = finding.actions.find((a) => a.primary);
  const secondaryActions = finding.actions.filter((a) => !a.primary);

  // Chip SLA solo para critical/high — el resto no tiene compromiso temporal
  // y agregar chip a todas las cards quita relevancia al diseño.
  const showAge = finding.severity === "critical" || finding.severity === "high";
  const bucket = showAge ? ageBucket(finding.evidenceTimestamp) : null;

  // Estado del editor de anotaciones (inline en el footer de la card).
  const [annotateOpen, setAnnotateOpen] = useState(false);

  // MITRE ATT&CK TTP primaria del kind — null para kinds informativos.
  const ttp = primaryTtp(finding.kind);

  return (
    <Card className={cn("border-l-4 shadow-sm", SEVERITY_BORDER[finding.severity])}>
      <CardContent className="space-y-3 p-4 sm:p-5">
        {/* Header — qué + severidad + kind + aging */}
        <div className="flex flex-wrap items-start gap-3">
          <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted/50", tint)}>
            <KindIcon className="h-4 w-4" aria-hidden />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className={cn("h-5 text-[10px] font-bold uppercase tracking-wider", SEVERITY_BADGE[finding.severity])}>
                {SEVERITY_LABEL[finding.severity]}
              </Badge>
              {diffBadge && <DiffBadge badge={diffBadge} />}
              <Badge variant="outline" className={cn("h-5 text-[10px]", tint)}>
                {KIND_LABEL[finding.kind]}
              </Badge>
              {bucket && (
                <Badge
                  variant="outline"
                  className={cn("h-5 gap-1 text-[10px] font-mono", AGE_BADGE[bucket])}
                  title={`Edad del dato: ${AGE_LABEL[bucket]}${bucket === "old" ? " — escalación recomendada" : ""}`}
                >
                  <Hourglass className="h-2.5 w-2.5" aria-hidden />
                  {AGE_LABEL[bucket]}
                </Badge>
              )}
              {annotation && (
                <Badge
                  variant="outline"
                  className={cn("h-5 gap-1 text-[10px] font-medium", ANNOTATION_BADGE[annotation.state])}
                  title={`${ANNOTATION_LABEL[annotation.state]} por CI ${annotation.operator_ci}${annotation.note ? ` · "${annotation.note}"` : ""}`}
                >
                  <CheckCheck className="h-2.5 w-2.5" aria-hidden />
                  {ANNOTATION_LABEL[annotation.state]}
                </Badge>
              )}
              {ttp && ttp.technique !== "Multiple" && (
                <a
                  href={ttp.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`MITRE ATT&CK · ${ttp.technique} ${ttp.techniqueName} — ${ttp.tacticName}`}
                  className="inline-flex h-5 items-center gap-1 rounded-md border border-border/60 bg-muted/30 px-1.5 font-mono text-[10px] text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                >
                  <span className="font-semibold">ATT&CK</span>
                  {ttp.technique}
                </a>
              )}
            </div>
            <h4 className="mt-1.5 text-base font-semibold leading-tight text-foreground">
              {finding.title}
            </h4>
          </div>
        </div>

        {/* Body — dónde + por qué (SOC playbook) */}
        <dl className="grid gap-x-3 gap-y-2 text-sm sm:grid-cols-[88px,1fr]">
          <dt className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground sm:pt-0.5">
            Dónde
          </dt>
          <dd className="space-y-0.5">
            <p className="font-medium text-foreground">{finding.sourceLabel}</p>
            <p className="text-xs text-muted-foreground">
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">{finding.evidence}</code>
            </p>
            {finding.evidenceTimestamp && (
              <p className="flex items-center gap-1 text-[10px] text-muted-foreground/70">
                <Clock className="h-3 w-3" aria-hidden />
                {formatRelativeTimeEs(finding.evidenceTimestamp)}
              </p>
            )}
          </dd>

          <dt className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground sm:pt-0.5">
            Por qué
          </dt>
          <dd className="text-xs leading-relaxed text-foreground/80">
            {finding.why}
          </dd>

          {finding.refs.length > 0 && (
            <>
              <dt className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground sm:pt-1">
                Refs
              </dt>
              <dd className="flex flex-wrap gap-1.5">
                {finding.refs.map((ref, i) => (
                  <button
                    key={`${ref.tab}-${i}`}
                    type="button"
                    onClick={() => onRefClick(ref, finding)}
                    title={ref.hint ? `${ref.label} · ${ref.hint}` : ref.label}
                    className="inline-flex items-center gap-1 rounded-md border border-border/70 bg-muted/30 px-2 py-0.5 text-[11px] font-medium text-foreground/80 transition-colors hover:border-primary/50 hover:bg-primary/5 hover:text-foreground"
                  >
                    <ArrowRight className="h-3 w-3 text-muted-foreground" aria-hidden />
                    {ref.label}
                  </button>
                ))}
              </dd>
            </>
          )}
        </dl>

        {/* Footer — acciones + triage */}
        <div className="flex flex-wrap items-center gap-2 border-t border-border/50 pt-3">
          {primary && (
            <Button
              size="sm"
              className="h-8 gap-1.5 text-xs"
              onClick={() => onAction(primary, finding)}
            >
              {primary.label}
            </Button>
          )}
          {secondaryActions.map((a) => (
            <Button
              key={a.id}
              size="sm"
              variant="outline"
              className="h-8 gap-1.5 text-xs"
              onClick={() => onAction(a, finding)}
            >
              {a.label}
            </Button>
          ))}
          <Button
            size="sm"
            variant="ghost"
            className="ml-auto h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            onClick={() => setAnnotateOpen((v) => !v)}
            title={annotation ? "Editar triage" : "Marcar triage del finding"}
          >
            <MessageSquarePlus className="h-3.5 w-3.5" aria-hidden />
            {annotation ? ANNOTATION_LABEL[annotation.state] : "Triage"}
          </Button>
        </div>

        {/* Editor inline de anotación (Ola B #3) */}
        {annotateOpen && (
          <AnnotationEditor
            finding={finding}
            domain={domain}
            existing={annotation}
            onClose={() => setAnnotateOpen(false)}
          />
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Editor inline de anotación
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// DiffBadge — "¿qué cambió?" desde el análisis previo
// ─────────────────────────────────────────────────────────────────────────────

function DiffBadge({ badge }: { badge: FindingDiffBadge }) {
  if (badge.status === "new") {
    return (
      <Badge
        variant="outline"
        className="h-5 gap-1 border-emerald-500/50 bg-emerald-500/15 text-[10px] font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-400"
        title="Hallazgo nuevo desde el análisis previo"
      >
        <Sparkles className="h-2.5 w-2.5" aria-hidden />
        Nuevo
      </Badge>
    );
  }
  if (badge.status === "severity-up") {
    return (
      <Badge
        variant="outline"
        className="h-5 gap-1 border-red-500/50 bg-red-500/15 text-[10px] font-semibold uppercase tracking-wider text-red-700 dark:text-red-400"
        title={`Severidad subió: ${SEVERITY_LABEL[badge.prevSeverity]} → actual`}
      >
        <ArrowUp className="h-2.5 w-2.5" aria-hidden />
        Subió
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="h-5 gap-1 border-sky-500/40 bg-sky-500/10 text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-400"
      title={`Severidad bajó: ${SEVERITY_LABEL[badge.prevSeverity]} → actual`}
    >
      <ArrowDown className="h-2.5 w-2.5" aria-hidden />
      Bajó
    </Badge>
  );
}

function AnnotationEditor({
  finding,
  domain,
  existing,
  onClose,
}: {
  finding: AnalystFinding;
  domain: string;
  existing?: AnnotationRow;
  onClose: () => void;
}) {
  const [state, setState] = useState<AnnotationState>(existing?.state ?? "triaged");
  const [note, setNote] = useState<string>(existing?.note ?? "");
  const [ci, setCi] = useState<string>(existing?.operator_ci ?? loadOperatorCi());
  const [error, setError] = useState<string | null>(null);

  const upsert = useUpsertAnnotation();
  const remove = useDeleteAnnotation();

  function handleSave() {
    setError(null);
    const ciErr = validateCi(ci);
    if (ciErr) { setError(ciErr); return; }
    saveOperatorCi(ci);
    // OCC: enviar version actual de la anotación (0 si es nueva). Si otro
    // operador editó después de que cargamos esta vista, el server devuelve
    // 412 y mostramos un aviso con la versión live + reset a esa versión.
    const expectedVersion = existing?.version ?? 0;
    upsert.mutate(
      {
        findingId: finding.id,
        domain,
        state,
        note: note.trim() || null,
        operatorCi: ci.trim(),
        expectedVersion,
      },
      {
        onSuccess: () => onClose(),
        onError: (err) => {
          if (err instanceof AnnotationVersionConflict) {
            setError(`Conflicto: otro operador editó esta anotación (versión ${err.currentVersion}). Recargá para ver los cambios.`);
          } else {
            setError(err.message);
          }
        },
      },
    );
  }

  function handleDelete() {
    if (!existing) return;
    remove.mutate(
      { findingId: finding.id, domain },
      { onSuccess: () => onClose() },
    );
  }

  return (
    <div className="space-y-2 rounded-lg border border-border/60 bg-muted/30 p-3 text-xs">
      <div className="flex items-center justify-between">
        <p className="font-semibold text-foreground">Triage del hallazgo</p>
        <Button
          size="sm"
          variant="ghost"
          className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
          onClick={onClose}
          title="Cerrar"
        >
          <X className="h-3.5 w-3.5" aria-hidden />
        </Button>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {(["triaged", "false-positive", "resolved"] as AnnotationState[]).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setState(s)}
            className={cn(
              "rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors",
              state === s
                ? cn("border-foreground/30", ANNOTATION_BADGE[s])
                : "border-border/50 bg-card text-muted-foreground hover:text-foreground",
            )}
          >
            {ANNOTATION_LABEL[s]}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-[1fr,120px] gap-2">
        <Input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Nota (opcional)"
          className="h-8 text-xs"
        />
        <Input
          value={ci}
          onChange={(e) => setCi(e.target.value)}
          placeholder="CI"
          className="h-8 font-mono text-xs"
        />
      </div>

      {error && (
        <p className="flex items-center gap-1 text-[11px] text-destructive">
          <ShieldOff className="h-3 w-3" aria-hidden />
          {error}
        </p>
      )}

      <div className="flex items-center justify-end gap-1.5">
        {existing && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-[11px] text-destructive hover:bg-destructive/10"
            onClick={handleDelete}
            disabled={remove.isPending}
          >
            Borrar
          </Button>
        )}
        <Button
          size="sm"
          className="h-7 px-3 text-[11px]"
          onClick={handleSave}
          disabled={upsert.isPending || !ci.trim()}
        >
          {upsert.isPending ? "Guardando…" : existing ? "Actualizar" : "Guardar"}
        </Button>
      </div>
    </div>
  );
}
