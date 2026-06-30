/**
 * CaseDetailSheet.tsx
 * Panel lateral de detalle de un caso SOC.
 * Recibe callbacks del hook padre (onAdopt, onChangeStatus, onNotifySlack).
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { X, Shield, ShieldCheck, Bell, ChevronDown, ArrowUpCircle, Clock, ExternalLink, UserCog } from "lucide-react";
import type { SocCase, CaseStatus, EscalationLevel, CaseClassification } from "./types";
import { OpenCaseTicketButton } from "./OpenCaseTicketButton";
import { loadOperatorCi, saveOperatorCi, validateCi } from "@/lib/operator-ci";
import { useSocOperators, useSocRoles, useShiftManager } from "@/hooks/useSocWorkflow";
import { useTransitionPolicy } from "@/hooks/useTransitionPolicy";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { getTicketsByCase } from "@/api/tickets";
import { extractApiErrorMessage } from "@/components/case-management/useCaseManagement";
import { C, alpha } from "@/lib/cm-theme";
import { formatDateTimePy, formatTimePy } from "@/lib/format";

const SEV_COLOR: Record<string, string> = {
  CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.cyan,
  LOW: C.green, NEGLIGIBLE: C.textDim,
};

const STATUS_LABEL: Record<string, string> = {
  NUEVO:          "Nuevo",
  EN_ANALISIS:    "En análisis",
  CONFIRMADO:     "Confirmado",
  MONITOREADO:    "Monitoreado",
  ESCALADO:       "Escalado",
  FALSO_POSITIVO: "Falso positivo",
  CERRADO:        "Cerrado",
};

// VALID_TRANSITIONS viene de useTransitionPolicy() — fuente única en el backend
// vía GET /api/incidents/transitions. El fallback local vive en useTransitionPolicy.

// Outcome del cierre (audit 2026-05-26): el tipo CaseClassification vive en
// ./types.ts. Las etiquetas legibles para el select se definen acá porque
// son específicas a esta UI.
const CLASSIFICATION_LABEL: Record<CaseClassification, string> = {
  TRUE_POSITIVE:  "Verdadero positivo — incidente real",
  FALSE_POSITIVE: "Falso positivo — actividad legítima",
  DUPLICATE:      "Duplicado — ya tratado en otro caso",
  NO_ACTIONABLE:  "Sin acción — no procede",
};

// Templates de motivo para cierre/FP (audit UX 2026-05-20). Reducen typos y
// estandarizan razones para reporting. Si el manager pide más, migrar a una
// tabla PG `closure_templates` con endpoint GET /api/incidents/closure-templates.
// `classification` (audit 2026-05-26): se aplica al seleccionar el chip para
// auto-llenar el select de Resultado.
const CLOSURE_TEMPLATES: Array<{ label: string; reason: string; color: string; classification: CaseClassification }> = [
  { label: "FP — Whitelisted",    reason: "Falso positivo: IOC en allowlist / activo conocido",         color: C.green,  classification: "FALSE_POSITIVE" },
  { label: "FP — Test/Lab",       reason: "Falso positivo: tráfico de pruebas o lab interno",           color: C.green,  classification: "FALSE_POSITIVE" },
  { label: "FP — Tuning",         reason: "Falso positivo: regla requiere ajuste (ver detalle)",        color: C.green,  classification: "FALSE_POSITIVE" },
  { label: "FP — Scanner",        reason: "Falso positivo: scanner autorizado (Nessus/OpenVAS/etc)",    color: C.green,  classification: "FALSE_POSITIVE" },
  { label: "Cerrado — Resuelto",  reason: "Caso resuelto: acción tomada, monitorear recurrencia",       color: C.blue,   classification: "TRUE_POSITIVE" },
  { label: "Cerrado — Mitigado",  reason: "Mitigado externamente (bloqueo upstream / proveedor)",       color: C.blue,   classification: "TRUE_POSITIVE" },
  { label: "Cerrado — Sin impacto", reason: "Sin impacto en activos críticos, baja prioridad",          color: C.cyan,   classification: "NO_ACTIONABLE" },
  { label: "Cerrado — Duplicado", reason: "Duplicado de caso existente (ver dedup_key)",                color: C.purple, classification: "DUPLICATE" },
];

const ESCALATION_LEVELS: Array<{ value: EscalationLevel; label: string }> = [
  { value: "TIER1",    label: "Tier 1 — Analista SOC" },
  { value: "TIER2",    label: "Tier 2 — Analista Senior" },
  { value: "IR",       label: "IR Team — Incident Response" },
  { value: "EXECUTIVE",label: "Ejecutivo / CISO" },
  { value: "EXTERNAL", label: "Externo (CERT / Proveedor)" },
];

const TIMELINE_ACTION_LABEL: Record<string, string> = {
  ADOPT:         "Caso adoptado",
  STATUS_CHANGE: "Cambio de estado",
  ESCALATE:      "Escalación",
  SLACK:         "Notificación Slack",
  MERGE:         "Casos fusionados",
};

// ── NIST SP 800-61 phase classification ────────────────────────────────────────
const NIST_PHASES: Array<{ id: string; label: string; color: string }> = [
  { id: "DETECTION",        label: "Detección",       color: C.blue },
  { id: "TRIAGE_L1",        label: "Triaje L1",        color: C.purple },
  { id: "INVESTIGATION_L2", label: "Investigación L2", color: C.orange },
  { id: "RESPONSE_L3",      label: "Respuesta L3",     color: C.red },
  { id: "CLOSURE",          label: "Cierre",           color: C.green },
];

const NIST_PHASE_ORDER = NIST_PHASES.map((p) => p.id);

function getNistPhase(entry: { action: string; detail?: string }): string {
  const action = entry.action ?? "";
  const detail = (entry.detail ?? "").toUpperCase();

  if (action === "ESCALATE") return "RESPONSE_L3";
  if (action === "ADOPT")    return "TRIAGE_L1";
  if (action === "SLACK")    return "TRIAGE_L1";
  if (action === "MERGE")    return "INVESTIGATION_L2";

  if (action === "STATUS_CHANGE") {
    if (detail.includes("CERRADO") || detail.includes("FALSO_POSITIVO")) return "CLOSURE";
    if (detail.includes("ESCALADO")) return "RESPONSE_L3";
    if (detail.includes("CONFIRMADO") || detail.includes("MONITOREADO")) return "INVESTIGATION_L2";
    if (detail.includes("EN_ANALISIS") || detail.includes("ANALISIS")) return "TRIAGE_L1";
  }

  return "DETECTION";
}

const FUNCTIONAL_IMPACT_LABEL: Record<string, { label: string; color: string }> = {
  NONE:        { label: "Ninguno",        color: C.green },
  MINIMAL:     { label: "Mínimo",         color: C.orange },
  SIGNIFICANT: { label: "Significativo",  color: C.orange },
  SEVERE:      { label: "Severo",         color: C.red },
};
const INFORMATION_IMPACT_LABEL: Record<string, { label: string; color: string }> = {
  NONE:              { label: "Ninguno",          color: C.green },
  SUSPECTED_BREACH:  { label: "Brecha sospechada",color: C.orange },
  CONFIRMED_LOSS:    { label: "Pérdida confirmada",color: C.red },
  CONFIRMED_CHANGE:  { label: "Modificación conf.",color: C.red },
  NOT_APPLICABLE:    { label: "No aplica",         color: C.textDim },
};
const RECOVERABILITY_LABEL: Record<string, { label: string; color: string }> = {
  REGULAR:         { label: "Regular",          color: C.green },
  SUPPLEMENTED:    { label: "Requiere apoyo",   color: C.orange },
  EXTENDED:        { label: "Tiempo extendido", color: C.orange },
  NOT_RECOVERABLE: { label: "No recuperable",   color: C.red },
};
const INCIDENT_CATEGORY_LABEL: Record<string, string> = {
  UNAUTHORIZED_ACCESS: "Acceso no autorizado",
  DENIAL_OF_SERVICE:   "Denegación de servicio",
  MALICIOUS_CODE:      "Código malicioso",
  IMPROPER_USAGE:      "Uso indebido",
  SCANS_PROBES:        "Escaneos / sondeo",
  INVESTIGATION:       "Investigación",
  OTHER:               "Otro",
};

interface Props {
  case:              SocCase;
  onClose:           () => void;
  onAdopt?:          (operatorCi: string, force?: boolean) => Promise<void>;
  onChangeStatus?:   (status: CaseStatus, reason?: string, operatorCi?: string, classification?: CaseClassification) => Promise<void>;
  onNotifySlack?:    (reason: "escalated" | "manual") => Promise<void>;
  onEscalate?:       (level: EscalationLevel, escalatedTo: string, reason: string, operatorCi: string) => Promise<void>;
}

export function CaseDetailSheet({
  case: c,
  onClose,
  onAdopt,
  onChangeStatus,
  onNotifySlack,
  onEscalate,
}: Props) {
  // CI desde localStorage (persistido entre pestañas y sesiones)
  const [ciInput, setCiInput]           = useState(loadOperatorCi);
  const [adoptError, setAdoptError]     = useState<string | null>(null);
  const [adopting, setAdopting]         = useState(false);

  // Reasignación de caso ya adoptado (fuerza la transferencia vía /adopt force=true).
  const [reassignCi, setReassignCi]       = useState("");
  const [reassignBusy, setReassignBusy]   = useState(false);
  const [reassignError, setReassignError] = useState<string | null>(null);

  // Mapa de transiciones válidas y caps requeridos — consumido del backend.
  const policy = useTransitionPolicy();

  // Lista de operadores candidatos (activos con rol can_adopt=true).
  const { data: operators = [] } = useSocOperators();
  const { data: roles = [] }     = useSocRoles();
  // P3.4 (audit 2026-05-27): Shift Manager activo para pre-fillear el campo
  // "escalado a" — destino natural para TIER2/3 desde L1. El operador
  // puede sobrescribir si quiere otra cosa (ej: equipo externo).
  const { data: currentShiftMgr } = useShiftManager();
  const adoptRoleIds = useMemo(
    () => new Set(roles.filter(r => r.can_adopt).map(r => r.id)),
    [roles],
  );
  const candidates = useMemo(
    () => operators
      .filter(o => o.is_active && (adoptRoleIds.size === 0 || adoptRoleIds.has(o.role_id)))
      .sort((a,b) => a.name.localeCompare(b.name)),
    [operators, adoptRoleIds],
  );
  // Para reasignar: mismos candidatos pero excluyendo al owner actual.
  const reassignCandidates = useMemo(
    () => candidates.filter(o => o.id !== c.operatorCi),
    [candidates, c.operatorCi],
  );

  const [statusError, setStatusError]   = useState<string | null>(null);
  const [closureReason, setClosureReason] = useState("");
  // Audit 2026-05-26: classification es obligatoria para cierre/FP en el backend.
  // Default TRUE_POSITIVE; los chips de template auto-llenan el valor real.
  const [classification, setClassification] = useState<CaseClassification>("TRUE_POSITIVE");
  const [statusBusy, setStatusBusy]     = useState(false);

  // ── P1 #16: autocompletado de cierre ───────────────────────────────────────
  // Sugerencia de template según señales del caso (severidad/score/escalación).
  // No auto-aplica: destaca el chip "★ Sugerido" para reducir el "¿cuál elijo?".
  const suggestedTemplateLabel = useMemo(() => {
    const isThreat = c.escalationSuggested
      || c.severity === "CRITICAL" || c.severity === "HIGH";
    if (isThreat) return "Cerrado — Resuelto";
    if (c.source === "noc_down") return "Cerrado — Mitigado";
    return "Cerrado — Sin impacto";
  }, [c.escalationSuggested, c.severity, c.source]);
  // Validación en vivo: cerrar FP un caso marcado para escalación exige ≥80 chars
  // (paridad con el gate 4-eyes del backend). Avisar antes del round-trip.
  const fpNeeds80 = classification === "FALSE_POSITIVE" && c.escalationSuggested;
  const reasonTooShortForFp = fpNeeds80 && closureReason.trim().length < 80;

  const [slackBusy, setSlackBusy]       = useState(false);
  const [containBusy, setContainBusy]   = useState(false);
  const [containMsg, setContainMsg]     = useState<string | null>(null);
  // slackOk inicializado desde el servidor si ya se notificó antes
  const [slackOk, setSlackOk]           = useState(c.slackNotifiedAt != null);
  const [slackError, setSlackError]     = useState<string | null>(null);

  // ── Escalación ──────────────────────────────────────────────────────────────
  const [showEscModal, setShowEscModal] = useState(false);
  const [escLevel, setEscLevel]         = useState<EscalationLevel>("TIER2");
  const [escTo, setEscTo]               = useState("");
  const [escReason, setEscReason]       = useState("");
  const [escBusy, setEscBusy]           = useState(false);
  const [escError, setEscError]         = useState<string | null>(null);
  // Auto-focus el primer input al abrir + ESC cierra. El panel hoy es inline
  // dentro del sheet (no overlay), así que ESC con preventDefault evita que
  // suba al cerrar el sheet completo.
  const escToInputRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    if (!showEscModal) return;
    escToInputRef.current?.focus();
    // P3.4 — Pre-fill con el SM activo SÓLO si el operador no tipeó nada.
    // Si ya hay valor (sea por reapertura del modal o input manual previo)
    // no lo pisamos. Formato "Nombre (CI)" — match con cómo se muestra en
    // otras vistas y permite que el backend resuelva al CI con regex.
    if (!escTo.trim() && currentShiftMgr?.id) {
      const label = currentShiftMgr.name
        ? `${currentShiftMgr.name} (${currentShiftMgr.id})`
        : currentShiftMgr.id;
      setEscTo(label);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape" && !escBusy) {
        e.stopPropagation();
        setShowEscModal(false);
      }
    }
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  // escTo deliberadamente excluido — sólo queremos pre-fill al ABRIR el modal,
  // no re-trigger cada vez que el operador edita el input.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showEscModal, escBusy, currentShiftMgr?.id]);

  // ── Timeline (fuente canónica: case_timeline_events vía API) ────────────────
  const [showTimeline, setShowTimeline] = useState(false);
  const [timelineEvents, setTimelineEvents] = useState<typeof c.timeline | null>(null);
  const [timelineSource, setTimelineSource] = useState<"case_timeline_events" | "legacy_jsonb" | null>(null);

  useEffect(() => {
    if (!c.id) return;
    // api client inyecta Bearer vía interceptor — requerido tras requireAuth()
    // en /api/incidents/*. Con fetch crudo devolvía 401 y caía al fallback JSONB.
    api.get<{ timeline?: Array<Record<string, unknown>>; source?: "case_timeline_events" | "legacy_jsonb" }>(
      `/api/incidents/${encodeURIComponent(c.id)}/timeline`,
    )
      .then(({ data }) => {
        if (data && Array.isArray(data.timeline)) {
          setTimelineEvents(data.timeline.map((e) => ({
            ts:       String(e.ts ?? ""),
            action:   String(e.action ?? ""),
            operator: String(e.operator ?? "system"),
            detail:   e.detail != null ? String(e.detail) : undefined,
          })));
          setTimelineSource(data.source ?? null);
        }
      })
      .catch(() => {/* fallback al JSONB de c.timeline */});
  }, [c.id]);

  const sevColor = SEV_COLOR[c.severity] ?? C.cyan;
  const assetLabel = c.hostname || c.srcIp || "—";

  // ── Adopt ─────────────────────────────────────────────────────────────────
  async function handleAdopt() {
    const ci = ciInput.trim();
    const ciErr = validateCi(ci);
    if (ciErr) { setAdoptError(ciErr); return; }
    setAdopting(true);
    setAdoptError(null);
    try {
      await onAdopt?.(ci);
      saveOperatorCi(ci);
      onClose();
    } catch (err) {
      setAdoptError(err instanceof Error ? err.message : "Error al adoptar");
    } finally {
      setAdopting(false);
    }
  }

  // ── Reassign (force transfer a otro operador) ────────────────────────────
  async function handleReassign() {
    const ci = reassignCi.trim();
    const ciErr = validateCi(ci);
    if (ciErr) { setReassignError(ciErr); return; }
    if (ci === c.operatorCi) {
      setReassignError("El caso ya está asignado a ese operador.");
      return;
    }
    setReassignBusy(true);
    setReassignError(null);
    try {
      await onAdopt?.(ci, true);
      onClose();
    } catch (err) {
      setReassignError(err instanceof Error ? err.message : "Error al reasignar");
    } finally {
      setReassignBusy(false);
    }
  }

  // ── Change status ─────────────────────────────────────────────────────────
  async function handleChangeStatus(newStatus: CaseStatus) {
    setStatusBusy(true);
    setStatusError(null);
    try {
      // Para cierre/FP el backend exige classification. Si el operador eligió
      // FALSO_POSITIVO sin tocar el select, forzar FALSE_POSITIVE (UX coherente
      // con la elección del botón).
      const isClosure = newStatus === "CERRADO" || newStatus === "FALSO_POSITIVO";
      const effectiveClass: CaseClassification | undefined = isClosure
        ? (newStatus === "FALSO_POSITIVO" ? "FALSE_POSITIVE" : classification)
        : undefined;
      await onChangeStatus?.(
        newStatus,
        closureReason || undefined,
        ciInput.trim() || undefined,
        effectiveClass,
      );
      onClose();
    } catch (err) {
      // El backend devuelve mensajes accionables (p.ej. CASE_HAS_OPEN_TICKETS al
      // intentar cerrar un caso con ticket abierto); mostralos tal cual.
      setStatusError(extractApiErrorMessage(err));
    } finally {
      setStatusBusy(false);
    }
  }

  // ── Escalación ─────────────────────────────────────────────────────────────
  async function handleEscalate() {
    if (!escReason.trim()) { setEscError("El motivo es obligatorio."); return; }
    setEscBusy(true); setEscError(null);
    try {
      await onEscalate?.(escLevel, escTo.trim(), escReason.trim(), ciInput.trim());
      setShowEscModal(false);
      onClose();
    } catch (err) {
      setEscError(err instanceof Error ? err.message : "Error al escalar");
    } finally { setEscBusy(false); }
  }

  // ── Contención (P1 #5 SOAR-lite) ────────────────────────────────────────────
  async function handleContain() {
    if (containBusy) return;
    setContainBusy(true);
    setContainMsg(null);
    try {
      const { data } = await api.post<{ ok: boolean; soar?: { configured: boolean; ok: boolean } }>(
        `/api/incidents/${c.id}/contain`,
        { action: c.recommendedAction ?? undefined },
      );
      setContainMsg(
        data.soar?.configured
          ? (data.soar.ok ? "Contención registrada y enviada al SOAR ✓" : "Contención registrada (SOAR no respondió OK)")
          : "Contención registrada (sin SOAR configurado)",
      );
    } catch (err) {
      setContainMsg(err instanceof Error ? err.message : "Error al registrar contención");
    } finally { setContainBusy(false); }
  }

  // ── Slack notify ──────────────────────────────────────────────────────────
  async function handleSlack() {
    setSlackBusy(true);
    setSlackError(null);
    try {
      await onNotifySlack?.("manual");
      setSlackOk(true);
    } catch (err) {
      setSlackError(err instanceof Error ? err.message : "Error al enviar a Slack");
    } finally { setSlackBusy(false); }
  }

  const transitions = policy.transitions[c.status] ?? [];

  // (#5) Tickets vinculados sin cerrar bloquean el cierre del caso — espejo del
  // guard backend CASE_HAS_OPEN_TICKETS. Mejor prevenir que recibir el 409.
  const linkedTicketsQ = useQuery({
    queryKey: ["case-linked-tickets", c.id],
    queryFn:  () => getTicketsByCase(c.id),
    enabled:  !!c.id,
    staleTime: 30_000,
  });
  const openTickets = (linkedTicketsQ.data ?? []).filter((t) => t.status !== "CERRADO");
  const closeBlocked = openTickets.length > 0;

  return (
    <div
      style={{
        position: "fixed", top: 0, right: 0, bottom: 0, zIndex: 1000,
        width: 420, maxWidth: "96vw",
        background: C.bg,
        borderLeft: `1px solid ${alpha(sevColor, 25)}`,
        display: "flex", flexDirection: "column",
        overflowY: "auto",
        boxShadow: "-8px 0 32px rgba(0,0,0,0.4)",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "16px 20px",
          borderBottom: `1px solid ${C.border}`,
          position: "sticky", top: 0, background: C.bg, zIndex: 1,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Shield size={16} color={sevColor} />
          <span style={{ color: sevColor, fontWeight: 700, fontSize: 14 }}>
            {c.severity}
          </span>
          <span style={{ color: C.textDim, fontSize: 12 }}>
            · {STATUS_LABEL[c.status] ?? c.status}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <OpenCaseTicketButton
            caseId={c.id}
            hostname={c.hostname ?? c.srcIp}
            recommendedAction={c.recommendedAction}
          />
          <button
            onClick={onClose}
            style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim }}
          >
            <X size={16} />
          </button>
        </div>
      </div>

      <div style={{ padding: "16px 20px", flex: 1, display: "flex", flexDirection: "column", gap: 16 }}>
        {/* Activo / incidente NOC */}
        <Section label="Activo">
          <div style={{ fontFamily: "monospace", color: C.text, fontSize: 14, fontWeight: 600, paddingBottom: 6 }}>
            {assetLabel}
          </div>
          {c.hostname && c.srcIp && c.hostname !== c.srcIp && (
            <Field label="Identificador" value={c.srcIp} mono />
          )}
          <Field label="Origen" value={c.sourceLabel || c.source || "—"} />
          {c.sensorKey && <Field label="Agente / dispositivo" value={c.sensorKey} mono />}
          {c.detectedAt && (
            <Field label="Detectado" value={formatDateTimePy(c.detectedAt)} />
          )}
        </Section>
        {c.recommendedAction && (
          <Section label="Acción recomendada">
            <div style={{ color: C.text, fontSize: 13, lineHeight: 1.5 }}>
              {c.recommendedAction}
            </div>
            {/* P1 #5: aplicar/registrar la contención (evento CONTAINMENT → MTTC;
                + webhook SOAR si está configurado). No cambia el estado del caso. */}
            {c.status !== "CERRADO" && c.status !== "FALSO_POSITIVO" && (
              <div style={{ marginTop: 8 }}>
                <button
                  type="button"
                  onClick={() => void handleContain()}
                  disabled={containBusy}
                  style={{
                    display: "flex", alignItems: "center", gap: 6,
                    fontSize: 12, padding: "6px 14px", borderRadius: 6,
                    background: alpha(C.orange, 12), border: `1px solid ${alpha(C.orange, 30)}`,
                    color: C.orange, cursor: containBusy ? "not-allowed" : "pointer",
                    fontWeight: 600,
                  }}
                >
                  <ShieldCheck size={13} /> {containBusy ? "Conteniendo…" : "Aplicar contención"}
                </button>
                {containMsg && (
                  <div style={{ color: C.textDim, fontSize: 11, marginTop: 4 }}>{containMsg}</div>
                )}
              </div>
            )}
          </Section>
        )}

        {(c.incidentCategory || c.functionalImpact || c.informationImpact || c.recoverability) && (
          <Section label="Impacto NIST SP 800-61">
            <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 6 }}>
              <Shield size={10} color={C.textDim} />
              <span style={{ color: C.textDim, fontSize: 10, letterSpacing: "0.1em" }}>CLASIFICACIÓN</span>
            </div>
            {c.incidentCategory && (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", padding: "3px 0" }}>
                <span style={{ color: C.textDim, fontSize: 11 }}>Categoría</span>
                <span style={{ color: C.text, fontSize: 12 }}>
                  {INCIDENT_CATEGORY_LABEL[c.incidentCategory] ?? c.incidentCategory}
                </span>
              </div>
            )}
            {c.functionalImpact && (() => {
              const d = FUNCTIONAL_IMPACT_LABEL[c.functionalImpact] ?? { label: c.functionalImpact, color: C.textDim };
              return (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "3px 0" }}>
                  <span style={{ color: C.textDim, fontSize: 11 }}>Impacto funcional</span>
                  <span style={{
                    fontSize: 11, padding: "1px 8px", borderRadius: 4,
                    background: alpha(d.color, 12), color: d.color, border: `1px solid ${alpha(d.color, 25)}`,
                  }}>{d.label}</span>
                </div>
              );
            })()}
            {c.informationImpact && (() => {
              const d = INFORMATION_IMPACT_LABEL[c.informationImpact] ?? { label: c.informationImpact, color: C.textDim };
              return (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "3px 0" }}>
                  <span style={{ color: C.textDim, fontSize: 11 }}>Impacto información</span>
                  <span style={{
                    fontSize: 11, padding: "1px 8px", borderRadius: 4,
                    background: alpha(d.color, 12), color: d.color, border: `1px solid ${alpha(d.color, 25)}`,
                  }}>{d.label}</span>
                </div>
              );
            })()}
            {c.recoverability && (() => {
              const d = RECOVERABILITY_LABEL[c.recoverability] ?? { label: c.recoverability, color: C.textDim };
              return (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "3px 0" }}>
                  <span style={{ color: C.textDim, fontSize: 11 }}>Recuperabilidad</span>
                  <span style={{
                    fontSize: 11, padding: "1px 8px", borderRadius: 4,
                    background: alpha(d.color, 12), color: d.color, border: `1px solid ${alpha(d.color, 25)}`,
                  }}>{d.label}</span>
                </div>
              );
            })()}
          </Section>
        )}

        {/* Respuesta y contención */}
        {(c.containmentStatus || c.rootCause || c.lessonsLearned) && (
          <Section label="Respuesta y contención">
            {c.containmentStatus && (
              <Field label="Contención" value={c.containmentStatus} />
            )}
            {c.rootCause && (
              <>
                <div style={{ color: C.textDim, fontSize: 10, margin: "6px 0 3px" }}>Causa raíz</div>
                <div style={{ color: C.text, fontSize: 12, lineHeight: 1.5 }}>{c.rootCause}</div>
              </>
            )}
            {c.lessonsLearned && (
              <>
                <div style={{ height: 1, background: C.border, margin: "6px 0" }} />
                <div style={{ color: C.textDim, fontSize: 10, marginBottom: 3 }}>Lecciones aprendidas</div>
                <div style={{ color: C.textDim, fontSize: 12, lineHeight: 1.5 }}>{c.lessonsLearned}</div>
              </>
            )}
          </Section>
        )}

        {/* Evidencias */}
        {c.evidenceLinks.length > 0 && (
          <Section label="Evidencias">
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {c.evidenceLinks.map((link, i) => (
                <a
                  key={i}
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "flex", alignItems: "center", gap: 6,
                    color: C.cyan, fontSize: 12, textDecoration: "none",
                    padding: "4px 6px", borderRadius: 4,
                    background: alpha(C.cyan, 5),
                  }}
                >
                  <ExternalLink size={10} />
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {link}
                  </span>
                </a>
              ))}
            </div>
          </Section>
        )}

        {/* Adopción */}
        {!c.adoptedAt && (
          <Section label="Adoptar caso">
            {candidates.length > 0 ? (
              <select
                value={ciInput}
                onChange={(e) => setCiInput(e.target.value)}
                style={{
                  width: "100%", background: C.bg, border: `1px solid ${C.border}`,
                  borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13,
                  boxSizing: "border-box",
                }}
              >
                <option value="">— Seleccionar operador —</option>
                {candidates.map(o => (
                  <option key={o.id} value={o.id}>
                    {o.name} · {o.role_id} · {o.id}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={ciInput}
                onChange={(e) => setCiInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void handleAdopt()}
                placeholder="CI del operador"
                style={{
                  width: "100%", background: C.bg, border: `1px solid ${C.border}`,
                  borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13,
                  boxSizing: "border-box",
                }}
              />
            )}
            {adoptError && (
              <div style={{ color: C.red, fontSize: 12, marginTop: 4 }}>{adoptError}</div>
            )}
            <button
              onClick={() => void handleAdopt()}
              disabled={adopting || ciInput.trim().length < 5}
              style={{
                marginTop: 8, width: "100%",
                background: alpha(sevColor, 12), border: `1px solid ${alpha(sevColor, 31)}`,
                borderRadius: 6, padding: "7px", color: sevColor,
                cursor: adopting ? "not-allowed" : "pointer",
                fontSize: 13, fontWeight: 600,
              }}
            >
              {adopting ? "Adoptando…" : "Adoptar"}
            </button>
          </Section>
        )}

        {c.adoptedAt && (
          <Section label="Adoptado">
            <Field
              label="Operador"
              value={
                c.operatorCi
                  ? (operators.find((o) => o.id === c.operatorCi)?.name ?? c.operatorCi)
                  : "—"
              }
            />
            <Field label="Fecha" value={formatDateTimePy(c.adoptedAt)} />

            <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${C.border}` }}>
              <div style={{ color: C.textDim, fontSize: 11, marginBottom: 6, display: "flex", alignItems: "center", gap: 6 }}>
                <UserCog size={12} />
                REASIGNAR A OTRO OPERADOR
              </div>
              {reassignCandidates.length > 0 ? (
                <select
                  value={reassignCi}
                  onChange={(e) => { setReassignCi(e.target.value); setReassignError(null); }}
                  style={{
                    width: "100%", background: C.bg, border: `1px solid ${C.border}`,
                    borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13,
                    boxSizing: "border-box",
                  }}
                >
                  <option value="">— Seleccionar nuevo operador —</option>
                  {reassignCandidates.map(o => (
                    <option key={o.id} value={o.id}>
                      {o.name} · {o.role_id} · {o.id}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  value={reassignCi}
                  onChange={(e) => { setReassignCi(e.target.value); setReassignError(null); }}
                  placeholder="CI del nuevo operador"
                  style={{
                    width: "100%", background: C.bg, border: `1px solid ${C.border}`,
                    borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13,
                    boxSizing: "border-box",
                  }}
                />
              )}
              {reassignError && (
                <div style={{ color: C.red, fontSize: 12, marginTop: 4 }}>{reassignError}</div>
              )}
              {reassignCi.trim().length >= 5 && reassignCi.trim() !== c.operatorCi && (
                <>
                  <div style={{ marginTop: 6, fontSize: 11, color: alpha(C.orange, 60), lineHeight: 1.4 }}>
                    La reasignación fuerza la transferencia y queda registrada en el timeline.
                  </div>
                  <button
                    onClick={() => void handleReassign()}
                    disabled={reassignBusy}
                    style={{
                      marginTop: 8, width: "100%",
                      background: alpha(C.orange, 15), border: `1px solid ${alpha(C.orange, 50)}`,
                      borderRadius: 6, padding: "6px", color: C.orange,
                      cursor: reassignBusy ? "not-allowed" : "pointer",
                      fontSize: 12, fontWeight: 700,
                    }}
                  >
                    {reassignBusy ? "Reasignando…" : "Confirmar reasignación"}
                  </button>
                </>
              )}
            </div>
          </Section>
        )}

        {/* Transiciones de estado */}
        {transitions.length > 0 && (
          <Section label="Cambiar estado">
            {(["CERRADO", "FALSO_POSITIVO"].some((s) => transitions.includes(s as CaseStatus))) && (
              <div style={{ marginBottom: 8 }}>
                {/* Templates de motivo — chips clickeables que rellenan el campo.
                    Reduce typos y acelera bulk de cierres similares (audit UX 2026-05-20).
                    Para personalizar, mover a una tabla `closure_templates` cuando
                    el manager lo pida. */}
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 6 }}>
                  {CLOSURE_TEMPLATES.map((tpl) => {
                    const isSuggested = tpl.label === suggestedTemplateLabel;
                    return (
                    <button
                      key={tpl.label}
                      type="button"
                      onClick={() => {
                        setClosureReason(tpl.reason);
                        // Audit 2026-05-26: el template también define el outcome.
                        setClassification(tpl.classification);
                      }}
                      title={`${tpl.reason} · Resultado: ${CLASSIFICATION_LABEL[tpl.classification]}${isSuggested ? " · Sugerido por señales del caso" : ""}`}
                      style={{
                        fontSize: 10, padding: "2px 7px", borderRadius: 4,
                        background: alpha(tpl.color, isSuggested ? 14 : 6),
                        border: `1px solid ${alpha(tpl.color, isSuggested ? 60 : 30)}`,
                        color: tpl.color, cursor: "pointer",
                        whiteSpace: "nowrap",
                        fontWeight: isSuggested ? 700 : 400,
                      }}
                    >
                      {isSuggested ? "★ " : ""}{tpl.label}
                    </button>
                    );
                  })}
                </div>
                <input
                  type="text"
                  value={closureReason}
                  onChange={(e) => setClosureReason(e.target.value)}
                  placeholder="Motivo / notas de cierre (opcional)"
                  style={{
                    width: "100%", background: C.bg,
                    border: `1px solid ${reasonTooShortForFp ? C.orange : C.border}`,
                    borderRadius: 6, padding: "6px 10px", color: C.text, fontSize: 12,
                    boxSizing: "border-box",
                  }}
                />
                {/* P1 #16: validación en vivo del gate 4-eyes (FP escalado ≥80). */}
                {fpNeeds80 && (
                  <div style={{ color: reasonTooShortForFp ? C.orange : C.green, fontSize: 10, marginTop: 3 }}>
                    {reasonTooShortForFp
                      ? `Caso marcado para escalación: justificación ≥80 caracteres para cerrarlo como FP (${closureReason.trim().length}/80), o usá un 2º aprobador.`
                      : `✓ Justificación suficiente (${closureReason.trim().length}/80).`}
                  </div>
                )}
                {/* Audit 2026-05-26: select de Resultado obligatorio en backend
                    al cerrar (CERRADO/FALSO_POSITIVO). Si el operador clickea
                    FALSO_POSITIVO directo, igual se fuerza FALSE_POSITIVE en
                    handleChangeStatus. */}
                <label style={{ display: "block", marginTop: 6, color: C.textDim, fontSize: 11 }}>
                  Resultado *
                </label>
                <select
                  value={classification}
                  onChange={(e) => setClassification(e.target.value as CaseClassification)}
                  style={{
                    width: "100%", background: C.bg, border: `1px solid ${C.border}`,
                    borderRadius: 6, padding: "6px 10px", color: C.text, fontSize: 12,
                    boxSizing: "border-box", marginTop: 2,
                  }}
                >
                  {(Object.keys(CLASSIFICATION_LABEL) as CaseClassification[]).map((k) => (
                    <option key={k} value={k}>{CLASSIFICATION_LABEL[k]}</option>
                  ))}
                </select>
              </div>
            )}
            {/* (#5) Aviso de bloqueo de cierre por tickets abiertos. */}
            {closeBlocked && (["CERRADO", "FALSO_POSITIVO"].some((s) => transitions.includes(s as CaseStatus))) && (
              <div style={{
                marginBottom: 8, padding: "6px 10px", borderRadius: 6,
                background: alpha(C.orange, 12), border: `1px solid ${alpha(C.orange, 40)}`,
                color: C.orange, fontSize: 11, lineHeight: 1.5,
              }}>
                No se puede cerrar: {openTickets.length} ticket(s) sin cerrar →{" "}
                {openTickets.map((t) => t.public_ref).join(", ")}. Cerrá el/los ticket(s) primero.
              </div>
            )}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {transitions.map((st) => {
                const isTerminal = st === "CERRADO" || st === "FALSO_POSITIVO";
                const blocked = isTerminal && closeBlocked;
                return (
                  <button
                    key={st}
                    onClick={() => { if (!blocked) void handleChangeStatus(st); }}
                    disabled={statusBusy || blocked}
                    title={blocked ? `Cerrá primero ${openTickets.length} ticket(s) abierto(s) asociado(s)` : undefined}
                    style={{
                      fontSize: 12, padding: "5px 12px", borderRadius: 6,
                      background: C.card, border: `1px solid ${C.border}`,
                      color: C.textDim, opacity: blocked ? 0.5 : 1,
                      cursor: (statusBusy || blocked) ? "not-allowed" : "pointer",
                      display: "flex", alignItems: "center", gap: 4,
                    }}
                  >
                    <ChevronDown size={11} />
                    {STATUS_LABEL[st] ?? st}
                  </button>
                );
              })}
            </div>
            {statusError && (
              <div style={{ color: C.red, fontSize: 12, marginTop: 6 }}>{statusError}</div>
            )}
          </Section>
        )}

        {/* Escalación */}
        {c.status !== "CERRADO" && c.status !== "FALSO_POSITIVO" && onEscalate && (
          <Section label="Escalación NIST §3.3">
            {c.escalation ? (
              <div>
                <Field label="Nivel"      value={c.escalation.level} accent={C.purple} />
                <Field label="Escalado a" value={c.escalation.escalatedTo ?? "—"} />
                {c.escalation.escalatedAt && (
                  <Field label="Fecha" value={formatDateTimePy(c.escalation.escalatedAt)} />
                )}
                {c.escalation.reason && (
                  <div style={{ color: C.textDim, fontSize: 11, marginTop: 6, lineHeight: 1.5 }}>
                    {c.escalation.reason}
                  </div>
                )}
              </div>
            ) : (
              <>
                <button
                  onClick={() => setShowEscModal(true)}
                  style={{
                    display: "flex", alignItems: "center", gap: 6,
                    fontSize: 12, padding: "6px 14px", borderRadius: 6,
                    background: alpha(C.purple, 12), border: `1px solid ${alpha(C.purple, 25)}`,
                    color: C.purple, cursor: "pointer", width: "100%",
                    justifyContent: "center", fontWeight: 600,
                  }}
                >
                  <ArrowUpCircle size={13} /> Escalar incidente
                </button>

                {showEscModal && (
                  <div
                    style={{
                      marginTop: 12, padding: 12, background: C.bg,
                      border: `1px solid ${alpha(C.purple, 30)}`,
                      borderLeft: `3px solid ${C.purple}`,
                      borderRadius: 8,
                      display: "flex", flexDirection: "column", gap: 8,
                      animation: "lhSlideDown 160ms ease-out",
                    }}
                    role="region"
                    aria-label="Formulario de escalación"
                  >
                    <style>{`
                      @keyframes lhSlideDown {
                        from { opacity: 0; transform: translateY(-6px); max-height: 0; }
                        to   { opacity: 1; transform: translateY(0);   max-height: 400px; }
                      }
                    `}</style>
                    <div style={{ fontSize: 10, color: C.textDim, textTransform: "uppercase", letterSpacing: 0.5 }}>
                      Escalación  ·  ESC para cancelar
                    </div>
                    <select
                      value={escLevel}
                      onChange={(e) => setEscLevel(e.target.value as EscalationLevel)}
                      style={{
                        background: C.bg, border: `1px solid ${C.border}`,
                        borderRadius: 6, padding: "6px 10px",
                        color: C.text, fontSize: 12, width: "100%",
                      }}
                    >
                      {ESCALATION_LEVELS.map((l) => (
                        <option key={l.value} value={l.value}>{l.label}</option>
                      ))}
                    </select>
                    <input
                      ref={escToInputRef}
                      type="text"
                      value={escTo}
                      onChange={(e) => setEscTo(e.target.value)}
                      placeholder="Escalado a (nombre / equipo)"
                      style={{
                        background: C.bg, border: `1px solid ${C.border}`,
                        borderRadius: 6, padding: "6px 10px",
                        color: C.text, fontSize: 12, width: "100%", boxSizing: "border-box",
                      }}
                    />
                    <textarea
                      value={escReason}
                      onChange={(e) => setEscReason(e.target.value)}
                      placeholder="Motivo de escalación (obligatorio)"
                      rows={3}
                      style={{
                        background: C.bg, border: `1px solid ${C.border}`,
                        borderRadius: 6, padding: "6px 10px",
                        color: C.text, fontSize: 12, resize: "none",
                        width: "100%", boxSizing: "border-box",
                      }}
                    />
                    {escError && (
                      <div style={{ color: C.red, fontSize: 11 }}>{escError}</div>
                    )}
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        onClick={() => void handleEscalate()}
                        disabled={escBusy}
                        style={{
                          flex: 1, padding: "6px", borderRadius: 6,
                          background: alpha(C.purple, 12), border: `1px solid ${alpha(C.purple, 25)}`,
                          color: C.purple, fontSize: 12, cursor: escBusy ? "not-allowed" : "pointer",
                          fontWeight: 600,
                        }}
                      >
                        {escBusy ? "Escalando…" : "Confirmar escalación"}
                      </button>
                      <button
                        onClick={() => setShowEscModal(false)}
                        style={{
                          padding: "6px 12px", borderRadius: 6,
                          background: C.card, border: `1px solid ${C.border}`,
                          color: C.textDim, fontSize: 12, cursor: "pointer",
                        }}
                      >
                        Cancelar
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </Section>
        )}

        {/* Slack */}
        <Section label="Notificaciones">
          <button
            onClick={() => void handleSlack()}
            disabled={slackBusy || (slackOk && !slackError)}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              fontSize: 12, padding: "6px 14px", borderRadius: 6,
              background: slackError ? alpha(C.red, 8) : slackOk ? alpha(C.green, 12) : C.border,
              border: `1px solid ${slackError ? alpha(C.red, 25) : slackOk ? alpha(C.green, 25) : C.border}`,
              color: slackError ? C.red : slackOk ? C.green : C.textDim,
              cursor: slackBusy || (slackOk && !slackError) ? "not-allowed" : "pointer",
            }}
            title={slackError ?? undefined}
          >
            <Bell size={12} />
            {slackError
              ? "Error al enviar — click para reintentar"
              : slackOk
                ? `Enviado${c.slackNotifiedAt ? " · " + formatTimePy(c.slackNotifiedAt) : ""}`
                : slackBusy ? "Enviando…" : "Notificar a Slack"}
          </button>
        </Section>

        {/* Timeline — fuente canónica: case_timeline_events; fallback: JSONB legacy */}
        {(() => {
          const tl = timelineEvents ?? c.timeline;
          if (tl.length === 0) return null;
          return (
          <Section label="Historial">
            <button
              onClick={() => setShowTimeline((v) => !v)}
              style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                width: "100%", background: "none", border: "none", cursor: "pointer",
                color: C.textDim, fontSize: 11, padding: 0,
              }}
            >
              <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <Clock size={11} />
                {tl.length} {tl.length === 1 ? "evento" : "eventos"}
                {timelineSource === "legacy_jsonb" && (
                  <span style={{ color: C.textDim, fontSize: 9, marginLeft: 4 }}>(legacy)</span>
                )}
              </span>
              <ChevronDown
                size={11}
                style={{ transform: showTimeline ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}
              />
            </button>
            {showTimeline && (() => {
              const tl2 = timelineEvents ?? c.timeline;
              // Group entries by NIST phase, preserving chronological order
              const grouped: Record<string, typeof c.timeline> = {};
              for (const entry of tl2) {
                const phase = getNistPhase(entry);
                if (!grouped[phase]) grouped[phase] = [];
                grouped[phase].push(entry);
              }
              // Sort phases by canonical NIST order
              const phases = NIST_PHASE_ORDER.filter((p) => grouped[p]?.length);

              return (
                <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 10 }}>
                  {phases.map((phaseId) => {
                    const meta = NIST_PHASES.find((p) => p.id === phaseId)!;
                    const entries = [...grouped[phaseId]].reverse();
                    return (
                      <div key={phaseId}>
                        {/* Phase header */}
                        <div style={{
                          display: "flex", alignItems: "center", gap: 6, marginBottom: 4,
                        }}>
                          <div style={{
                            width: 6, height: 6, borderRadius: "50%",
                            background: meta.color, flexShrink: 0,
                          }} />
                          <span style={{
                            color: meta.color, fontSize: 10, fontWeight: 700,
                            letterSpacing: "0.1em", textTransform: "uppercase",
                          }}>
                            {meta.label}
                          </span>
                          <div style={{ flex: 1, height: 1, background: meta.color, opacity: 0.2 }} />
                          <span style={{ color: C.textDim, fontSize: 9 }}>
                            {entries.length} {entries.length === 1 ? "evento" : "eventos"}
                          </span>
                        </div>

                        {/* Entries in this phase */}
                        <div style={{ display: "flex", flexDirection: "column", gap: 4, paddingLeft: 12,
                          borderLeft: `2px solid ${alpha(meta.color, 13)}` }}>
                          {entries.map((entry, i) => (
                            <div
                              key={i}
                              style={{
                                display: "flex", flexDirection: "column", gap: 2,
                                padding: "5px 8px",
                                background: C.bg, borderRadius: 6,
                                borderLeft: `2px solid ${alpha(meta.color, 33)}`,
                              }}
                            >
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                                <span style={{ color: C.text, fontSize: 11, fontWeight: 600 }}>
                                  {TIMELINE_ACTION_LABEL[entry.action] ?? entry.action}
                                </span>
                                <span style={{ color: C.textDim, fontSize: 10 }}>
                                  {formatDateTimePy(entry.ts)}
                                </span>
                              </div>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                                <span style={{ color: C.textDim, fontSize: 10, fontFamily: "monospace" }}>
                                  {entry.operator}
                                </span>
                                {entry.detail && (
                                  <span style={{ color: C.textDim, fontSize: 10, maxWidth: "60%", textAlign: "right" }}>
                                    {entry.detail}
                                  </span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            })()}
          </Section>
          );
        })()}
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ color: C.textDim, fontSize: 10, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: "10px 12px" }}>
        {children}
      </div>
    </div>
  );
}

function Field({ label, value, mono, accent }: { label: string; value: string; mono?: boolean; accent?: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", padding: "3px 0" }}>
      <span style={{ color: C.textDim, fontSize: 11 }}>{label}</span>
      <span style={{ color: accent ?? C.text, fontSize: 12, fontFamily: mono ? "monospace" : undefined }}>
        {value}
      </span>
    </div>
  );
}
