/**
 * OpenCaseModal — Modal reutilizable para apertura manual de casos SOC.
 *
 * Se usa desde las páginas de inteligencia (Wazuh, Suricata, Fortigate, PMG)
 * para abrir un caso a partir de un IOC observado en las top-alertas tables.
 *
 * Flujo:
 *  1. Operador hace clic en "Abrir Caso" en una fila de top-alertas.
 *  2. Modal se abre pre-cargado con IOC, fuente y severidad/score estimados.
 *  3. Operador ingresa su CI, ajusta severidad si lo desea, y confirma.
 *  4. POST /api/incidents/open-from-flow
 *     - 201/200 → muestra case_id + link a Case Management
 *     - 409 (dedup activo) → panel de 3 acciones:
 *         a) Ver caso existente
 *         b) Añadir como re-ocurrencia
 *         c) Forzar caso nuevo (con justificación)
 *     - 403 (supresión o perfil) → muestra motivo y expiry
 *     - 400 → error de validación
 */
import * as Dialog from "@radix-ui/react-dialog";
import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "@/api/client";
import { formatDateTimePy } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { useSocOperators } from "@/hooks/useSocWorkflow";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  FolderOpen,
  GitMerge,
  Loader2,
  Lock,
  RefreshCw,
  ShieldAlert,
  X,
} from "lucide-react";
import type { Severity } from "@/components/case-management/types";

// ── Tipos públicos ─────────────────────────────────────────────────────────────

export interface OpenCasePayload {
  /** Valor del IOC: IP, dominio, hash, URL */
  iocValue: string;
  /** Tipo del IOC */
  iocType: "ip" | "domain" | "hash" | "url";
  /** Identificador de la fuente de log */
  sourceLog: string;
  /** Severidad pre-calculada (editable por el operador antes de confirmar) */
  severity: Severity;
  /**
   * Score estimado basado en campos de la alerta.
   * Se muestra como referencia; el backend aplica los gates finales.
   */
  score: number;
  /** Tactic MITRE si está disponible en la alerta */
  mitreTacticId?: string;
  mitreTacticName?: string;
  /** Dedup key pre-calculada (SHA256-like) */
  dedupKey?: string;
}

interface OpenCaseModalProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  payload: OpenCasePayload;
  /** Etiqueta legible de la fuente, p.ej. "Suricata IDS", "Fortigate UTM" */
  sourceLabel: string;
  /** Callback opcional cuando el caso se crea o se incrementa como recurrencia.
   *  Usado por el flujo Hunt Pivots (docs/HUNT-PIVOTS.md) para hacer audit +
   *  link de outlier post-creación. */
  onCaseCreated?: (caseId: string, isRecurrence: boolean) => void;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const SEVERITY_OPTIONS: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"];

const SEV_BADGE: Record<Severity, string> = {
  CRITICAL:   "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH:       "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM:     "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW:        "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  NEGLIGIBLE: "bg-zinc-700/15 text-zinc-500 border-zinc-700/30",
};

/** Rango de color para la barra de score (0-100 normalizado al max ≈130) */
function scoreColor(s: number): string {
  const n = Math.min(100, (s / 130) * 100);
  if (n >= 70) return "bg-red-500";
  if (n >= 45) return "bg-orange-500";
  if (n >= 30) return "bg-yellow-500";
  return "bg-zinc-500";
}

// ── Tipo de respuesta de la API ────────────────────────────────────────────────

interface OpenFlowOk {
  ok: true;
  caseId: string;
  status: string;
}

interface OpenFlowError {
  error: string;
  hint?: string;
  suppressedUntil?: string;
  existingCaseId?: string;
  existing_case_id?: string;
  existingSeverity?: string;
  existingScore?: number;
  existingOperator?: string;
  existingOccurrences?: number;
  iocValue?: string;
  threshold?: number;
  profiles?: { id: string; severities: string[]; minScore: number }[];
}

interface OccurrenceOk {
  ok: true;
  caseId: string;
  occurrenceCount: number;
  score: number;
}

// ── Componente ─────────────────────────────────────────────────────────────────

export function OpenCaseModal({
  open,
  onOpenChange,
  payload,
  sourceLabel,
  onCaseCreated,
}: OpenCaseModalProps) {
  const [operatorCi, setOperatorCi]           = useState("");
  // Lista de operadores activos para el dropdown. Stale 2m + refetch cada 5m
  // (suficiente; los registros cambian 1-2 veces por shift).
  const { data: operators, isLoading: operatorsLoading, isError: operatorsError } = useSocOperators();
  const activeOperators = useMemo(
    () => (operators ?? []).filter((o) => o.is_active),
    [operators],
  );
  const [severity, setSeverity]               = useState<Severity>(payload.severity);
  const [force, setForce]                     = useState(false);
  const [successData, setSuccessData]         = useState<OpenFlowOk | null>(null);
  const [apiError, setApiError]               = useState<OpenFlowError | null>(null);
  // Estado del panel 409: null = no elegido, "view" | "occurrence" | "force-new"
  const [dupAction, setDupAction]             = useState<null | "view" | "occurrence" | "force-new">(null);
  const [forceJustification, setForceJustification] = useState("");
  const [occurrenceOk, setOccurrenceOk]       = useState<OccurrenceOk | null>(null);

  // Reset estado cuando se cierra
  function handleOpenChange(v: boolean) {
    if (!v) {
      setOperatorCi("");
      setSeverity(payload.severity);
      setForce(false);
      setSuccessData(null);
      setApiError(null);
      setDupAction(null);
      setForceJustification("");
      setOccurrenceOk(null);
    }
    onOpenChange(v);
  }

  const mutation = useMutation({
    mutationFn: async () => {
      const body = {
        iocValue:        payload.iocValue,
        iocType:         payload.iocType,
        sourceLog:       payload.sourceLog,
        score:           payload.score,
        severity,
        dedupKey:        payload.dedupKey,
        mitreTacticId:   payload.mitreTacticId,
        mitreTacticName: payload.mitreTacticName,
        operatorCi:      operatorCi.trim(),
        force,
      };
      const res = await api.post<OpenFlowOk>("/api/incidents/open-from-flow", body);
      return res.data;
    },
    onSuccess: (data) => {
      setApiError(null);
      setDupAction(null);
      setSuccessData(data);
      onCaseCreated?.(data.caseId, false);
    },
    onError: (err: unknown) => {
      setSuccessData(null);
      setDupAction(null);
      const axiosErr = err as { response?: { data?: OpenFlowError; status?: number } };
      const data = axiosErr?.response?.data ?? { error: String(err) };
      setApiError(data as OpenFlowError);
    },
  });

  const occurrenceMutation = useMutation({
    mutationFn: async (caseId: string) => {
      const body = {
        operatorCi:      operatorCi.trim(),
        newScore:        payload.score,
        sourceLog:       payload.sourceLog,
        mitreTacticName: payload.mitreTacticName,
      };
      const res = await api.post<OccurrenceOk>(`/api/incidents/${caseId}/add-occurrence`, body);
      return res.data;
    },
    onSuccess: (data) => {
      setOccurrenceOk(data);
      onCaseCreated?.(data.caseId, true);
    },
  });

  const canSubmit =
    operatorCi.trim().length >= 5 &&
    !mutation.isPending;

  const existingCaseId =
    apiError?.existingCaseId ??
    apiError?.existing_case_id ??
    null;

  const is409 = !!(apiError && existingCaseId);

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border bg-card shadow-2xl outline-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95"
          aria-describedby="open-case-desc"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                <FolderOpen className="h-4 w-4 text-primary" />
              </div>
              <div>
                <Dialog.Title className="text-sm font-semibold text-foreground">
                  Abrir Caso de Incidente
                </Dialog.Title>
                <p className="text-xs text-muted-foreground">{sourceLabel}</p>
              </div>
            </div>
            <Dialog.Close asChild>
              <button className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
                <X className="h-4 w-4" />
              </button>
            </Dialog.Close>
          </div>

          {/* Body */}
          <div className="space-y-4 px-5 py-4" id="open-case-desc">

            {/* IOC info */}
            <div className="rounded-lg border border-border bg-muted/30 px-4 py-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">IOC</span>
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground uppercase">
                  {payload.iocType}
                </span>
              </div>
              <p className="break-all font-mono text-sm font-semibold text-foreground">
                {payload.iocValue}
              </p>
              <div className="flex items-center justify-between pt-1">
                <span className="text-xs text-muted-foreground">Fuente</span>
                <span className="font-mono text-xs text-foreground/80">{payload.sourceLog}</span>
              </div>
            </div>

            {/* Score estimado */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">Score estimado</span>
                <span className="font-mono text-sm font-bold text-foreground">{payload.score} pts</span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full rounded-full transition-all ${scoreColor(payload.score)}`}
                  style={{ width: `${Math.min(100, (payload.score / 130) * 100)}%` }}
                />
              </div>
              <p className="text-[11px] text-muted-foreground">
                Score calculado desde campos de la alerta. El backend aplicará los gates finales.
              </p>
            </div>

            {/* Severidad */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-foreground">Severidad del caso</label>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITY_OPTIONS.map((s) => (
                  <button
                    key={s}
                    onClick={() => setSeverity(s)}
                    className={`inline-flex items-center rounded-full border px-3 py-0.5 text-[11px] font-semibold uppercase tracking-wide transition-all ${
                      severity === s
                        ? SEV_BADGE[s] + " ring-1 ring-offset-1 ring-offset-card"
                        : "border-border bg-transparent text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {/* Operador */}
            <div className="space-y-1.5">
              <label htmlFor="ci-select" className="text-xs font-medium text-foreground">
                Operador <span className="text-destructive">*</span>
              </label>
              <select
                id="ci-select"
                value={operatorCi}
                onChange={(e) => setOperatorCi(e.target.value)}
                disabled={operatorsLoading}
                className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm disabled:opacity-50"
              >
                <option value="">
                  {operatorsLoading
                    ? "Cargando operadores…"
                    : operatorsError
                      ? "Error al cargar — recargá"
                      : "Seleccionar operador…"}
                </option>
                {activeOperators.map((op) => (
                  <option key={op.id} value={op.id}>
                    {op.name} · {op.role_id} · CI {op.id}
                  </option>
                ))}
              </select>
            </div>

            {/* Force override — solo visible cuando no hay 409 */}
            {!is409 && (
              <label className="flex cursor-pointer items-center gap-2.5">
                <input
                  type="checkbox"
                  checked={force}
                  onChange={(e) => setForce(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-border accent-primary"
                />
                <span className="text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">Forzar apertura</span> — omite perfiles, dedup y supresión activa (override de operador)
                </span>
              </label>
            )}

            {/* ── Feedback estados ─────────────────────────────────────────── */}

            {/* Éxito */}
            {successData && (
              <div className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3">
                <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-500" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-emerald-600 dark:text-emerald-400">
                    Caso abierto correctamente
                  </p>
                  <p className="mt-0.5 break-all font-mono text-xs text-emerald-700/80 dark:text-emerald-300/70">
                    ID: {successData.caseId}
                  </p>
                  <a
                    href={`/gestion?investigate=${successData.caseId}`}
                    className="mt-1.5 inline-flex items-center gap-1 text-xs font-medium text-emerald-600 underline underline-offset-2 hover:text-emerald-500 dark:text-emerald-400"
                  >
                    <ExternalLink className="h-3 w-3" />
                    Ir al caso
                  </a>
                </div>
              </div>
            )}

            {/* Re-ocurrencia registrada */}
            {occurrenceOk && (
              <div className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3">
                <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-500" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-emerald-600 dark:text-emerald-400">
                    Re-ocurrencia registrada
                  </p>
                  <p className="mt-0.5 text-xs text-emerald-700/80 dark:text-emerald-300/70">
                    Ocurrencia #{occurrenceOk.occurrenceCount} añadida al caso {occurrenceOk.caseId.slice(0, 8)}…
                  </p>
                  <a
                    href={`/gestion?investigate=${occurrenceOk.caseId}`}
                    className="mt-1.5 inline-flex items-center gap-1 text-xs font-medium text-emerald-600 underline underline-offset-2 hover:text-emerald-500 dark:text-emerald-400"
                  >
                    <ExternalLink className="h-3 w-3" />
                    Ver caso
                  </a>
                </div>
              </div>
            )}

            {/* Error: caso duplicado (409) — panel de 3 acciones */}
            {is409 && !occurrenceOk && (
              <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 space-y-3">
                <div className="flex items-start gap-3">
                  <ShieldAlert className="mt-0.5 h-4 w-4 flex-shrink-0 text-yellow-500" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-yellow-600 dark:text-yellow-400">
                      IOC ya tiene caso activo
                    </p>
                    <p className="mt-0.5 text-xs text-yellow-700/80 dark:text-yellow-300/70">
                      {apiError!.error}
                    </p>
                    {/* Contexto del caso existente */}
                    {(apiError!.existingSeverity || apiError!.existingScore != null || apiError!.existingOperator) && (
                      <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
                        {apiError!.existingSeverity && (
                          <span className="rounded bg-yellow-500/20 px-1.5 py-0.5 font-semibold text-yellow-600 dark:text-yellow-300 uppercase">
                            {apiError!.existingSeverity}
                          </span>
                        )}
                        {apiError!.existingScore != null && (
                          <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground">
                            score {apiError!.existingScore}
                          </span>
                        )}
                        {apiError!.existingOperator && (
                          <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground">
                            op. {apiError!.existingOperator}
                          </span>
                        )}
                        {apiError!.existingOccurrences != null && apiError!.existingOccurrences > 1 && (
                          <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                            {apiError!.existingOccurrences} ocurrencias
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* 3 acciones */}
                {dupAction === null && (
                  <div className="grid grid-cols-1 gap-2 pt-1">
                    <a
                      href={`/gestion?investigate=${existingCaseId!}`}
                      className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs font-medium text-yellow-600 transition-colors hover:bg-yellow-500/20 dark:text-yellow-400"
                    >
                      <ExternalLink className="h-3.5 w-3.5 flex-shrink-0" />
                      Ver caso existente
                      <span className="ml-auto font-mono text-[10px] text-yellow-700/60 dark:text-yellow-300/50">
                        {existingCaseId!.slice(0, 8)}…
                      </span>
                    </a>
                    <button
                      onClick={() => setDupAction("occurrence")}
                      disabled={operatorCi.trim().length < 5}
                      className="flex items-center gap-2 rounded-md border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-xs font-medium text-blue-600 transition-colors hover:bg-blue-500/20 dark:text-blue-400 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <RefreshCw className="h-3.5 w-3.5 flex-shrink-0" />
                      Añadir como re-ocurrencia
                      <span className="ml-auto text-[10px] text-blue-700/60 dark:text-blue-300/50">
                        incrementa contador
                      </span>
                    </button>
                    <button
                      onClick={() => setDupAction("force-new")}
                      className="flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-medium text-red-600 transition-colors hover:bg-red-500/20 dark:text-red-400"
                    >
                      <GitMerge className="h-3.5 w-3.5 flex-shrink-0" />
                      Forzar caso nuevo
                      <span className="ml-auto text-[10px] text-red-700/60 dark:text-red-300/50">
                        requiere justificación
                      </span>
                    </button>
                  </div>
                )}

                {/* Confirmación: añadir como re-ocurrencia */}
                {dupAction === "occurrence" && (
                  <div className="space-y-2 pt-1">
                    <p className="text-xs text-blue-700/80 dark:text-blue-300/70">
                      Se registrará una nueva ocurrencia del IOC en el caso existente.
                      El score se actualizará si la nueva detección es mayor.
                    </p>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        className="h-7 flex-1 gap-1 text-xs bg-blue-600 hover:bg-blue-700 text-white"
                        disabled={occurrenceMutation.isPending || operatorCi.trim().length < 5}
                        onClick={() => occurrenceMutation.mutate(existingCaseId!)}
                      >
                        {occurrenceMutation.isPending ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3 w-3" />
                        )}
                        Confirmar re-ocurrencia
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => setDupAction(null)}
                      >
                        Volver
                      </Button>
                    </div>
                  </div>
                )}

                {/* Confirmación: forzar caso nuevo */}
                {dupAction === "force-new" && (
                  <div className="space-y-2 pt-1">
                    <p className="text-xs text-red-700/80 dark:text-red-300/70">
                      Se abrirá un nuevo caso independiente. Ingresá una justificación.
                    </p>
                    <textarea
                      rows={2}
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring resize-none"
                      placeholder="Justificación para forzar apertura…"
                      value={forceJustification}
                      onChange={(e) => setForceJustification(e.target.value)}
                    />
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        className="h-7 flex-1 gap-1 text-xs bg-red-600 hover:bg-red-700 text-white"
                        disabled={forceJustification.trim().length < 10 || mutation.isPending}
                        onClick={() => {
                          setForce(true);
                          mutation.mutate();
                        }}
                      >
                        {mutation.isPending ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <GitMerge className="h-3 w-3" />
                        )}
                        Forzar apertura
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => { setDupAction(null); setForceJustification(""); }}
                      >
                        Volver
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Error: supresión activa (403 + suppressedUntil) */}
            {apiError && apiError.suppressedUntil && !existingCaseId && (
              <div className="flex items-start gap-3 rounded-lg border border-orange-500/30 bg-orange-500/10 px-4 py-3">
                <Lock className="mt-0.5 h-4 w-4 flex-shrink-0 text-orange-500" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-orange-600 dark:text-orange-400">
                    IOC suprimido
                  </p>
                  <p className="mt-0.5 text-xs text-orange-700/80 dark:text-orange-300/70">
                    {apiError.error}
                  </p>
                  <p className="mt-0.5 font-mono text-[11px] text-orange-700/60 dark:text-orange-300/50">
                    Supresión hasta: {formatDateTimePy(apiError.suppressedUntil)}
                  </p>
                  {force ? null : (
                    <p className="mt-1 text-[11px] text-orange-700/60 dark:text-orange-300/50">
                      Activá "Forzar apertura" para ignorar la supresión.
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Error: perfil / score insuficiente (403 genérico) */}
            {apiError && !existingCaseId && !apiError.suppressedUntil && (
              <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3">
                <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-destructive" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-destructive">
                    No se puede abrir el caso
                  </p>
                  <p className="mt-0.5 text-xs text-destructive/80">{apiError.error}</p>
                  {apiError.hint && (
                    <p className="mt-0.5 text-[11px] text-muted-foreground">{apiError.hint}</p>
                  )}
                  {apiError.threshold != null && (
                    <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                      Umbral requerido: {apiError.threshold} pts — Score actual: {payload.score} pts
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
            <Dialog.Close asChild>
              <Button variant="outline" size="sm" className="h-8 text-xs">
                Cancelar
              </Button>
            </Dialog.Close>
            {(successData || occurrenceOk) ? (
              <Dialog.Close asChild>
                <Button size="sm" className="h-8 text-xs">
                  Cerrar
                </Button>
              </Dialog.Close>
            ) : is409 ? null : (
              <Button
                size="sm"
                className="h-8 gap-1.5 text-xs"
                disabled={!canSubmit}
                onClick={() => mutation.mutate()}
              >
                {mutation.isPending ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Abriendo…
                  </>
                ) : (
                  <>
                    <FolderOpen className="h-3.5 w-3.5" />
                    Abrir Caso
                  </>
                )}
              </Button>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
