/**
 * CaseDetailSheet.tsx
 * Panel lateral de detalle de un caso SOC.
 * Recibe callbacks del hook padre (onAdopt, onChangeStatus, onNotifySlack).
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { X, Shield, ShieldCheck, Bell, ChevronDown, ArrowUpCircle, Clock, Microscope, Upload, ExternalLink, Server, User, Network, PlusCircle, CheckCircle2, Crosshair, UserCog } from "lucide-react";
import type { SocCase, CaseStatus, EscalationLevel, CaseClassification } from "./types";
import { ScoringDetailPanel } from "./ScoringDetailPanel";
import { loadOperatorCi, saveOperatorCi, validateCi } from "@/lib/operator-ci";
import { inferAttackType } from "@/lib/attack-type";
import { useSocOperators, useSocRoles, useShiftManager } from "@/hooks/useSocWorkflow";
import { useTransitionPolicy } from "@/hooks/useTransitionPolicy";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { getTicketsByCase } from "@/api/tickets";
import { extractApiErrorMessage } from "@/components/case-management/useCaseManagement";
import { C, alpha } from "@/lib/cm-theme";
import { formatDateTimePy, formatTimePy, PY_TZ } from "@/lib/format";

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
  /** Abre la vista de investigación DFIR completa para este caso. */
  onInvestigate?:    (caseId: string) => void;
}

export function CaseDetailSheet({
  case: c,
  onClose,
  onAdopt,
  onChangeStatus,
  onNotifySlack,
  onEscalate,
  onInvestigate,
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
    const isThreat = c.escalationSuggested || c.score >= 70
      || c.severity === "CRITICAL" || c.severity === "HIGH";
    if (isThreat)      return "Cerrado — Resuelto";
    if (c.score < 30)  return "FP — Whitelisted";
    return "Cerrado — Sin impacto";
  }, [c.escalationSuggested, c.score, c.severity]);
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

  // ── MISP Export ─────────────────────────────────────────────────────────────
  const [mispBusy, setMispBusy]         = useState(false);
  const [mispResult, setMispResult]     = useState<{ ok: boolean; event_id?: string; error?: string } | null>(null);

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

  // ── Sensor labels + registro inline ─────────────────────────────────────────
  const [sensorLabels, setSensorLabels] = useState<Record<string, string>>({});
  const [showSensorReg, setShowSensorReg] = useState(false);
  const [sensorRegName, setSensorRegName] = useState("");
  const [sensorRegType, setSensorRegType] = useState("wazuh");
  const [sensorRegLoc, setSensorRegLoc]   = useState("");
  const [sensorRegBusy, setSensorRegBusy] = useState(false);
  const [sensorRegOk, setSensorRegOk]     = useState(false);
  const [sensorRegErr, setSensorRegErr]   = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/sensors/labels")
      .then((r) => r.json())
      .then((d) => { if (d?.ok && d.labels) setSensorLabels(d.labels); })
      .catch(() => {});
  }, []);

  // Clave de búsqueda en sensor_registry:
  //   1. c.sensorKey (devname para OPNsense/Suricata/Fortigate, agent.ip para Wazuh)
  //   2. c.source (source_log categórico como fallback de registro manual)
  const regKey         = c.sensorKey || c.source;
  const sensorResolved = sensorLabels[regKey];
  // Nombre del agente/dispositivo a mostrar en la sección de sensor
  const sensorDevice   = c.sensorKey || c.hostname || null;

  async function handleSensorRegister() {
    if (!sensorRegName.trim()) { setSensorRegErr("El nombre del sensor es obligatorio."); return; }
    setSensorRegBusy(true); setSensorRegErr(null);
    try {
      const res = await fetch("/api/sensors/upsert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sensor_ip:   regKey,
          sensor_name: sensorRegName.trim(),
          sensor_type: sensorRegType,
          location:    sensorRegLoc.trim() || undefined,
        }),
      });
      const data = await res.json() as { ok: boolean; error?: string };
      if (!data.ok) throw new Error(data.error ?? "Error al registrar");
      // Refresh labels
      const labelsRes = await fetch("/api/sensors/labels");
      const labelsData = await labelsRes.json() as { ok: boolean; labels?: Record<string, string> };
      if (labelsData?.ok && labelsData.labels) setSensorLabels(labelsData.labels);
      setSensorRegOk(true);
      setShowSensorReg(false);
    } catch (e) {
      setSensorRegErr(e instanceof Error ? e.message : "Error de red");
    } finally {
      setSensorRegBusy(false);
    }
  }

  const sevColor = SEV_COLOR[c.severity] ?? C.cyan;

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

  // ── MISP Export ───────────────────────────────────────────────────────────
  async function handleMispExport() {
    if (mispBusy || mispResult?.ok) return;
    setMispBusy(true);
    setMispResult(null);
    try {
      const iocType = (() => {
        const t = (c.iocType ?? "").toLowerCase();
        if (t.includes("ip"))     return "ip-dst";
        if (t.includes("domain")) return "domain";
        if (t.includes("hash") || t.includes("md5"))   return "md5";
        if (t.includes("sha256")) return "sha256";
        if (t.includes("url"))    return "url";
        return "ip-dst";
      })();
      const tags: string[] = ["LegacyHunt"];
      if (c.mitre.tacticName)  tags.push(`misp-galaxy:mitre-attack-pattern="${c.mitre.tacticName}"`);
      if (c.severity === "CRITICAL" || c.severity === "HIGH") tags.push("tlp:red");
      else tags.push("tlp:amber");

      const body = {
        title:       `[LegacyHunt] ${c.severity} — ${c.srcIp} (${c.source})`,
        threatLevel: c.severity === "CRITICAL" ? 1 : c.severity === "HIGH" ? 2 : 3,
        caseId:      c.id,
        tags,
        iocs: [{ type: iocType, value: c.srcIp, comment: `Score ${c.score} — ${c.source}` }],
      };
      const res  = await fetch("/api/intel/misp/export", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const data = await res.json() as { ok: boolean; event_id?: string; error?: string };
      setMispResult(data);
    } catch (e) {
      setMispResult({ ok: false, error: e instanceof Error ? e.message : "Error de red" });
    } finally {
      setMispBusy(false);
    }
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
          {onInvestigate && (
            <button
              onClick={() => { onInvestigate(c.id); onClose(); }}
              title="Abrir investigación DFIR completa"
              style={{
                display: "flex", alignItems: "center", gap: 4,
                background: alpha(C.purple, 12), border: `1px solid ${alpha(C.purple, 25)}`,
                borderRadius: 6, padding: "4px 10px",
                color: C.purple, cursor: "pointer", fontSize: 11, fontWeight: 600,
              }}
            >
              <Microscope size={12} />
              Investigar
            </button>
          )}
          <button
            onClick={onClose}
            style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim }}
          >
            <X size={16} />
          </button>
        </div>
      </div>

      <div style={{ padding: "16px 20px", flex: 1, display: "flex", flexDirection: "column", gap: 16 }}>
        {/* IOC */}
        <Section label="IOC">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingBottom: 6 }}>
            <span style={{ fontFamily: "monospace", color: C.text, fontSize: 14, fontWeight: 600 }}>{c.srcIp}</span>
            {c.isInternal ? (
              <span style={{
                fontSize: 10, padding: "2px 7px", borderRadius: 4, fontWeight: 700,
                background: alpha(C.orange, 12), color: C.orange, border: `1px solid ${alpha(C.orange, 25)}`,
              }}>
                RFC1918 · INTERNA
              </span>
            ) : (
              <span style={{
                fontSize: 10, padding: "2px 7px", borderRadius: 4,
                background: alpha(C.blue, 12), color: C.blue, border: `1px solid ${alpha(C.blue, 25)}`,
              }}>
                IP PÚBLICA
              </span>
            )}
          </div>
          {c.isInternal && (
            <div style={{ fontSize: 10, color: alpha(C.orange, 50), marginBottom: 4, lineHeight: 1.4 }}>
              Enriquecimiento externo no aplica (VT/AbuseIPDB/MISP → score 0). El score refleja sólo correlación interna (Wazuh + MITRE).
            </div>
          )}
          <Field label="Tipo"   value={c.iocType} />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "3px 0" }}>
            <span style={{ color: C.textDim, fontSize: 11 }}>Fuente</span>
            <span style={{
              fontFamily: "monospace", fontSize: 11,
              color: sensorResolved ? C.cyan : C.textDim,
            }}>
              {sensorResolved ?? c.sourceLabel}
            </span>
          </div>
          <Field label="Score"  value={String(c.score)} accent={sevColor} />
          {c.detectedAt && (
            <Field label="Detectado" value={formatDateTimePy(c.detectedAt)} />
          )}
        </Section>

        {/* Fuente / Sensor */}
        <Section label="Sensor de origen">
          {/* Caso huérfano: ni source_log ni sensor_key — mostrar aviso explícito.
              Sucede en casos creados antes del fix de pgUpsertCase (incidents.mjs:170)
              que no persistía estos campos en INSERT, dejando ~490 casos sin origen. */}
          {!c.source && !c.sensorKey && !sensorDevice ? (
            <div style={{
              padding: "10px 12px", borderRadius: 6,
              background: alpha(C.orange, 8), border: `1px solid ${alpha(C.orange, 25)}`,
              color: C.orange, fontSize: 11, lineHeight: 1.5,
            }}>
              <div style={{ fontWeight: 700, marginBottom: 3 }}>⚠ Origen del evento no identificado</div>
              <div style={{ color: alpha(C.orange, 75) }}>
                Este caso no registra sistema fuente ni sensor. Probablemente fue creado
                antes del fix de persistencia de origen, o el flujo de apertura no propagó
                el contexto. Adopta el caso para enriquecerlo manualmente desde el panel
                de investigación.
              </div>
            </div>
          ) : (
            <>
              {/* Fila sistema origen */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "2px 0" }}>
                <span style={{ color: C.textDim, fontSize: 10, letterSpacing: "0.08em" }}>SISTEMA</span>
                <span style={{ fontSize: 11, color: c.sourceLabel ? C.textDim : C.orange, fontWeight: 600 }}>
                  {c.sourceLabel || "— sin identificar —"}
                </span>
              </div>
              {/* Fila agente/dispositivo */}
              {sensorDevice && (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "2px 0" }}>
                  <span style={{ color: C.textDim, fontSize: 10, letterSpacing: "0.08em" }}>
                    {c.source?.includes("wazuh") ? "AGENTE" : "DISPOSITIVO"}
                  </span>
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: C.text }}>{sensorDevice}</span>
                </div>
              )}
            </>
          )}

          <div style={{ height: 1, background: C.border, margin: "6px 0" }} />

          {/* Bloque de registro de sensor: solo aplica si tenemos clave a registrar.
              Sin regKey no podemos crear un row en sensor_registry (clave vacía). */}
          {regKey && (<>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
              <Server size={12} color={sensorResolved ? C.cyan : C.orange} style={{ flexShrink: 0 }} />
              <div style={{ minWidth: 0 }}>
                <div style={{
                  fontSize: 12, fontWeight: 600,
                  color: sensorResolved ? C.text : C.orange,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>
                  {sensorRegOk
                    ? (sensorLabels[regKey] ?? regKey)
                    : (sensorResolved ?? regKey)}
                </div>
                <div style={{ fontSize: 10, color: C.textDim, marginTop: 1 }}>
                  {sensorRegOk || sensorResolved ? (
                    <span style={{ color: C.green, display: "inline-flex", alignItems: "center", gap: 3 }}>
                      <CheckCircle2 size={9} /> Registrado
                    </span>
                  ) : (
                    <span style={{ color: C.orange }}>Sin registro — clave: {regKey}</span>
                  )}
                </div>
              </div>
            </div>
            {!sensorResolved && !sensorRegOk && (
              <button
                onClick={() => setShowSensorReg((v) => !v)}
                title="Registrar este sensor"
                style={{
                  display: "flex", alignItems: "center", gap: 4,
                  fontSize: 11, padding: "3px 10px", borderRadius: 5, flexShrink: 0,
                  background: alpha(C.orange, 8), border: `1px solid ${alpha(C.orange, 25)}`,
                  color: C.orange, cursor: "pointer", fontWeight: 600,
                }}
              >
                <PlusCircle size={11} />
                {showSensorReg ? "Cancelar" : "Registrar"}
              </button>
            )}
          </div>

          {showSensorReg && (
            <div style={{
              marginTop: 10, padding: 10,
              background: C.bg, border: `1px solid ${alpha(C.orange, 19)}`,
              borderRadius: 8, display: "flex", flexDirection: "column", gap: 7,
            }}>
              <div style={{ fontSize: 10, color: alpha(C.orange, 50), marginBottom: 2 }}>
                Clave: <span style={{ fontFamily: "monospace", color: C.orange }}>{regKey}</span>
              </div>
              <input
                type="text"
                value={sensorRegName}
                onChange={(e) => setSensorRegName(e.target.value)}
                placeholder="Nombre del sensor (ej. SIEM Principal)"
                style={{
                  background: C.bg, border: `1px solid ${C.border}`, borderRadius: 5,
                  padding: "6px 9px", color: C.text, fontSize: 12,
                  width: "100%", boxSizing: "border-box",
                }}
              />
              <select
                value={sensorRegType}
                onChange={(e) => setSensorRegType(e.target.value)}
                style={{
                  background: C.bg, border: `1px solid ${C.border}`, borderRadius: 5,
                  padding: "6px 9px", color: C.text, fontSize: 12, width: "100%",
                }}
              >
                <option value="wazuh">Wazuh SIEM</option>
                <option value="suricata">Suricata IDS</option>
                <option value="firewall">Firewall</option>
                <option value="syslog">Syslog</option>
                <option value="zeek">Zeek NSM</option>
                <option value="elastic">Elastic / Filebeat</option>
                <option value="custom">Otro</option>
              </select>
              <input
                type="text"
                value={sensorRegLoc}
                onChange={(e) => setSensorRegLoc(e.target.value)}
                placeholder="Ubicación (opcional, ej. DC-Norte)"
                style={{
                  background: C.bg, border: `1px solid ${C.border}`, borderRadius: 5,
                  padding: "6px 9px", color: C.text, fontSize: 12,
                  width: "100%", boxSizing: "border-box",
                }}
              />
              {sensorRegErr && (
                <div style={{ fontSize: 11, color: C.red }}>{sensorRegErr}</div>
              )}
              <button
                onClick={() => void handleSensorRegister()}
                disabled={sensorRegBusy || !sensorRegName.trim()}
                style={{
                  padding: "6px", borderRadius: 5, fontSize: 12, fontWeight: 600,
                  background: alpha(C.orange, 12), border: `1px solid ${alpha(C.orange, 31)}`,
                  color: C.orange, cursor: sensorRegBusy ? "not-allowed" : "pointer",
                }}
              >
                {sensorRegBusy ? "Registrando…" : "Guardar sensor"}
              </button>
            </div>
          )}
          </>)}
        </Section>

        {/* Clasificación del ataque (badge + MITRE + categoría NIST + editor) */}
        <AttackClassificationSection c={c} />

        {/* Score breakdown */}
        <Section label="Score breakdown">
          <ScoreBar label="MITRE"    pts={c.scoreBreakdown.mitre}    max={40} color={C.purple} />
          <ScoreBar label="Evidencia" pts={c.scoreBreakdown.evidence} max={35} color={C.blue} />
          <ScoreBar label="Wazuh"    pts={c.scoreBreakdown.wazuh}    max={25} color={sevColor} />
          <ScoreBar label="MISP"     pts={c.scoreBreakdown.misp}     max={20} color={C.orange} />
          <ScoreBar label="Contexto" pts={c.scoreBreakdown.context}  max={10} color={C.green} />
        </Section>

        {/* ── Análisis de scoring + taxonomía (solo casos en investigación) ─── */}
        {["EN_ANALISIS", "CONFIRMADO", "ESCALADO", "MONITOREADO"].includes(c.status) && (
          <ScoringDetailPanel caseId={c.id} baseScore={c.score} />
        )}

        {/* Enriquecimiento IOC */}
        {(c.enrichment.vtMalicious != null
          || c.enrichment.abuseConfidence != null
          || c.enrichment.inUrlhaus
          || c.enrichment.inOpenphish
          || c.enrichment.vtPermalink
          || c.enrichment.shodanOrg
          || c.enrichment.inMisp) && (
          <Section label="Inteligencia">
            {/* VirusTotal */}
            {(c.enrichment.vtMalicious != null || c.enrichment.vtPermalink) && (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "3px 0" }}>
                <span style={{ color: C.textDim, fontSize: 11 }}>VirusTotal</span>
                <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  {c.enrichment.vtMalicious != null && (
                    <span style={{
                      fontSize: 11, padding: "1px 8px", borderRadius: 4,
                      background: c.enrichment.vtMalicious > 0 ? alpha(C.red, 12) : alpha(C.green, 12),
                      color: c.enrichment.vtMalicious > 0 ? C.red : C.green,
                      border: `1px solid ${c.enrichment.vtMalicious > 0 ? alpha(C.red, 25) : alpha(C.green, 25)}`,
                    }}>
                      {c.enrichment.vtMalicious} maliciosos
                      {c.enrichment.vtSuspicious != null && c.enrichment.vtSuspicious > 0
                        ? ` / ${c.enrichment.vtSuspicious} sospechosos` : ""}
                    </span>
                  )}
                  {c.enrichment.vtPermalink && (
                    <a href={c.enrichment.vtPermalink} target="_blank" rel="noopener noreferrer"
                       style={{ color: C.blue, fontSize: 10, display: "flex", alignItems: "center", gap: 2 }}>
                      <ExternalLink size={10} /> VT Report
                    </a>
                  )}
                </span>
              </div>
            )}
            {c.enrichment.abuseConfidence != null && (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "3px 0" }}>
                <span style={{ color: C.textDim, fontSize: 11 }}>AbuseIPDB</span>
                <span style={{
                  fontSize: 11, padding: "1px 8px", borderRadius: 4,
                  background: c.enrichment.abuseConfidence > 50 ? alpha(C.red, 12) : alpha(C.green, 12),
                  color: c.enrichment.abuseConfidence > 50 ? C.red : C.textDim,
                  border: `1px solid ${c.enrichment.abuseConfidence > 50 ? alpha(C.red, 25) : alpha(C.green, 25)}`,
                }}>
                  {c.enrichment.abuseConfidence}% confianza
                </span>
              </div>
            )}
            {/* Shodan */}
            {c.enrichment.shodanOrg && (
              <>
                <div style={{ height: 1, background: C.border, margin: "5px 0" }} />
                <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 4 }}>
                  <span style={{ color: C.textDim, fontSize: 10, letterSpacing: "0.1em" }}>SHODAN</span>
                </div>
                <Field label="Organización" value={c.enrichment.shodanOrg} />
                {c.enrichment.shodanCountry && <Field label="País" value={c.enrichment.shodanCountry} />}
                {c.enrichment.shodanPorts?.length > 0 && (
                  <div style={{ display: "flex", justifyContent: "space-between", padding: "3px 0" }}>
                    <span style={{ color: C.textDim, fontSize: 11 }}>Puertos abiertos</span>
                    <span style={{ color: C.text, fontSize: 11, fontFamily: "monospace" }}>
                      {c.enrichment.shodanPorts.slice(0, 8).join(", ")}
                      {c.enrichment.shodanPorts.length > 8 ? ` +${c.enrichment.shodanPorts.length - 8}` : ""}
                    </span>
                  </div>
                )}
              </>
            )}
            {(c.enrichment.inUrlhaus || c.enrichment.inOpenphish || c.enrichment.inMisp) && (
              <>
                <div style={{ height: 1, background: C.border, margin: "5px 0" }} />
                {c.enrichment.inUrlhaus   && <Field label="URLhaus"   value="Detectado" accent={C.red} />}
                {c.enrichment.inOpenphish && <Field label="OpenPhish" value="Detectado" accent={C.orange} />}
                {c.enrichment.inMisp      && <Field label="MISP"      value="En base de datos" accent={C.purple} />}
              </>
            )}
            {c.enrichment.enrichedAt && (
              <div style={{ marginTop: 6, color: C.textDim, fontSize: 10 }}>
                Enriquecido: {new Date(c.enrichment.enrichedAt).toLocaleString("es-ES", { timeZone: PY_TZ, dateStyle: "short", timeStyle: "short" })}
              </div>
            )}
          </Section>
        )}

        {/* Acción recomendada */}
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

        {/* Contexto del activo — siempre visible, campos editables inline */}
        <NetworkContextSection c={c} />

        {/* NIST SP 800-61 — Clasificación de impacto */}
        {(c.incidentCategory || c.functionalImpact || c.informationImpact || c.recoverability) && (
          <Section label="Impacto NIST SP 800-61">
            <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 6 }}>
              <Network size={10} color={C.textDim} />
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

        {/* Slack + MISP export */}
        <Section label="Notificaciones">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
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

            {/* MISP Export */}
            <button
              onClick={() => void handleMispExport()}
              disabled={mispBusy || mispResult?.ok === true}
              title="Exportar este IOC a MISP como nuevo evento"
              style={{
                display: "flex", alignItems: "center", gap: 6,
                fontSize: 12, padding: "6px 14px", borderRadius: 6,
                background: mispResult?.ok ? alpha(C.purple, 12) : mispResult?.ok === false ? alpha(C.red, 6) : C.border,
                border: `1px solid ${mispResult?.ok ? alpha(C.purple, 25) : mispResult?.ok === false ? alpha(C.red, 19) : C.border}`,
                color: mispResult?.ok ? C.purple : mispResult?.ok === false ? C.red : C.textDim,
                cursor: mispBusy || mispResult?.ok ? "not-allowed" : "pointer",
              }}
            >
              <Upload size={12} />
              {mispResult?.ok
                ? `Exportado a MISP · Event #${mispResult.event_id}`
                : mispResult?.ok === false
                  ? `Error: ${mispResult.error?.slice(0, 30)}`
                  : mispBusy ? "Exportando…" : "Exportar a MISP"}
            </button>
          </div>
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

function ScoreBar({ label, pts, max, color }: { label: string; pts: number; max: number; color: string }) {
  const pct = max > 0 ? Math.min(100, (pts / max) * 100) : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0" }}>
      <span style={{ color: C.textDim, fontSize: 10, width: 60, flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, height: 5, background: C.border, borderRadius: 3, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3, transition: "width 0.3s" }} />
      </div>
      <span style={{ color, fontSize: 10, width: 36, textAlign: "right", flexShrink: 0 }}>
        {pts}/{max}
      </span>
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

// ── AttackClassificationSection ───────────────────────────────────────────────
// Badge "Tipo de ataque detectado" + editor MITRE/categoría NIST. Cuando el
// caso llega sin metadata (caso típico tipo E8D8863), permite al operador
// clasificarlo manualmente. PATCH /api/incidents/:id persiste los cambios.

const MITRE_TACTICS: Array<{ id: string; name: string }> = [
  { id: "TA0043", name: "Reconocimiento" },
  { id: "TA0042", name: "Desarrollo de recursos" },
  { id: "TA0001", name: "Acceso inicial" },
  { id: "TA0002", name: "Ejecución" },
  { id: "TA0003", name: "Persistencia" },
  { id: "TA0004", name: "Escalada de privilegios" },
  { id: "TA0005", name: "Evasión de defensas" },
  { id: "TA0006", name: "Acceso a credenciales" },
  { id: "TA0007", name: "Descubrimiento" },
  { id: "TA0008", name: "Movimiento lateral" },
  { id: "TA0009", name: "Recolección" },
  { id: "TA0011", name: "Comando y control (C2)" },
  { id: "TA0010", name: "Exfiltración" },
  { id: "TA0040", name: "Impacto" },
];

const NIST_CATEGORIES: Array<{ id: string; label: string }> = [
  { id: "UNAUTHORIZED_ACCESS", label: "Acceso no autorizado" },
  { id: "DENIAL_OF_SERVICE",   label: "Denegación de servicio" },
  { id: "MALICIOUS_CODE",      label: "Código malicioso" },
  { id: "IMPROPER_USAGE",      label: "Uso indebido" },
  { id: "SCANS_PROBES",        label: "Escaneo / sondas" },
  { id: "INVESTIGATION",       label: "Investigación abierta" },
  { id: "OTHER",               label: "Otro" },
];

function AttackClassificationSection({ c }: { c: SocCase }) {
  const inferred = inferAttackType(c);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving]   = useState(false);
  const [err, setErr]         = useState<string | null>(null);
  const [ok, setOk]           = useState(false);

  const [tacticId, setTacticId]     = useState(c.mitre.tacticId    ?? "");
  const [techniqueId, setTechId]    = useState(c.mitre.techniqueId ?? "");
  const [category, setCategory]     = useState(c.incidentCategory  ?? "");

  async function handleSave() {
    setSaving(true); setErr(null); setOk(false);
    try {
      const tacticName = MITRE_TACTICS.find((t) => t.id === tacticId)?.name ?? null;
      const body: Record<string, unknown> = {};
      if (tacticId    !== (c.mitre.tacticId    ?? "")) { body.mitreTacticId    = tacticId    || null; body.mitreTacticName = tacticName; }
      if (techniqueId !== (c.mitre.techniqueId ?? "")) body.mitreTechniqueId = techniqueId || null;
      if (category    !== (c.incidentCategory  ?? "")) body.incidentCategory = category    || null;
      if (!Object.keys(body).length) { setEditing(false); return; }
      try {
        await api.patch(`/api/incidents/${encodeURIComponent(c.id)}`, body);
      } catch (err: unknown) {
        const msg = (err as { response?: { data?: { error?: string }; status?: number } })?.response?.data?.error
                 ?? (err as Error)?.message
                 ?? "Error al guardar";
        throw new Error(msg);
      }
      setOk(true); setEditing(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Error al guardar");
    } finally { setSaving(false); }
  }

  const inputStyle: React.CSSProperties = {
    background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4,
    color: C.text, fontSize: 11, padding: "3px 6px", width: "100%",
  };

  return (
    <Section label="Tipo de ataque detectado">
      {/* Badge principal */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "8px 10px", borderRadius: 6, marginBottom: 8,
        background: inferred ? alpha(inferred.color, 8) : alpha(C.orange, 6),
        border: `1px solid ${inferred ? alpha(inferred.color, 31) : alpha(C.orange, 25)}`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, flex: 1 }}>
          <Crosshair size={14} color={inferred ? inferred.color : C.orange} style={{ flexShrink: 0 }} />
          <div style={{ minWidth: 0 }}>
            <div style={{
              fontSize: 13, fontWeight: 700,
              color: inferred ? inferred.color : C.orange,
            }}>
              {inferred ? inferred.label : "No clasificado"}
            </div>
            <div style={{ fontSize: 10, color: C.textDim, marginTop: 1 }}>
              {inferred ? inferred.detail : "Falta MITRE táctica y categoría NIST. Clasificar manualmente."}
              {inferred?.confidence === "low" && (
                <span style={{ marginLeft: 6, padding: "1px 5px", borderRadius: 3, background: alpha(C.orange, 15), color: C.orange, fontSize: 9 }}>
                  inferido
                </span>
              )}
            </div>
          </div>
        </div>
        <button
          onClick={() => { setEditing((v) => !v); setErr(null); setOk(false); }}
          style={{
            background: "none", border: `1px solid ${C.border}`, borderRadius: 4,
            color: C.textDim, fontSize: 10, padding: "3px 10px", cursor: "pointer", flexShrink: 0,
          }}
        >
          {editing ? "Cancelar" : (inferred ? "Editar" : "Clasificar")}
        </button>
      </div>

      {!editing ? (
        <>
          {(c.mitre.tacticId || c.mitre.techniqueId) && (
            <div style={{ display: "flex", flexDirection: "column", gap: 2, marginBottom: 4 }}>
              {c.mitre.tacticName  && <Field label="Táctica"   value={c.mitre.tacticName} />}
              {c.mitre.tacticId    && <Field label="Táctica ID" value={c.mitre.tacticId} mono />}
              {c.mitre.techniqueId && <Field label="Técnica"   value={c.mitre.techniqueId} mono />}
            </div>
          )}
          {c.incidentCategory && (
            <Field label="Categoría NIST" value={c.incidentCategory} />
          )}
          {ok && <div style={{ marginTop: 6, color: C.green, fontSize: 11 }}>✓ Clasificación guardada</div>}
        </>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <div>
            <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>TÁCTICA MITRE ATT&amp;CK</div>
            <select style={inputStyle} value={tacticId} onChange={(e) => setTacticId(e.target.value)}>
              <option value="">— No clasificada —</option>
              {MITRE_TACTICS.map((t) => (
                <option key={t.id} value={t.id}>{t.id} · {t.name}</option>
              ))}
            </select>
          </div>
          <div>
            <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>TÉCNICA (opcional, ej. T1110, T1078)</div>
            <input
              style={{ ...inputStyle, fontFamily: "monospace" }}
              value={techniqueId}
              onChange={(e) => setTechId(e.target.value.toUpperCase().replace(/[^T0-9.]/g, ""))}
              placeholder="T1110"
            />
          </div>
          <div>
            <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>CATEGORÍA NIST SP 800-61</div>
            <select style={inputStyle} value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">— Sin categoría —</option>
              {NIST_CATEGORIES.map((n) => (
                <option key={n.id} value={n.id}>{n.label}</option>
              ))}
            </select>
          </div>
          {err && <div style={{ color: C.red, fontSize: 11 }}>{err}</div>}
          <button
            onClick={() => void handleSave()}
            disabled={saving}
            style={{
              background: C.blue, border: "none", borderRadius: 4, color: "#ffffff",
              fontSize: 11, padding: "5px 12px", cursor: saving ? "not-allowed" : "pointer",
              opacity: saving ? 0.7 : 1, alignSelf: "flex-start",
            }}
          >
            {saving ? "Guardando…" : "Guardar clasificación"}
          </button>
        </div>
      )}
    </Section>
  );
}

// ── NetworkContextSection ─────────────────────────────────────────────────────
// Sección de contexto de red/activo. Siempre visible; permite edición inline.
// PATCH /api/incidents/:id guarda los cambios.

const NETWORK_ZONE_COLOR: Record<string, string> = {
  perimeter: C.orange,
  endpoint:  C.blue,
  internal:  C.purple,
  email:     C.cyan,
};

const FW_ACTION_COLOR: Record<string, string> = {
  ACCEPT: C.green,
  ALLOW:  C.green,
  DENY:   C.red,
  DROP:   C.red,
  BLOCK:  C.red,
};

function NetworkContextSection({ c }: { c: SocCase }) {
  const [editing, setEditing]   = useState(false);
  const [saving,  setSaving]    = useState(false);
  const [saveErr, setSaveErr]   = useState<string | null>(null);
  const [saveOk,  setSaveOk]    = useState(false);

  const [hostname,   setHostname]   = useState(c.hostname        ?? "");
  const [srcIp,      setSrcIp]      = useState(c.sourceIp        ?? "");
  const [srcPort,    setSrcPort]    = useState(c.sourcePort != null ? String(c.sourcePort) : "");
  const [dstIp,      setDstIp]      = useState(c.destinationIp   ?? "");
  const [dstPort,    setDstPort]    = useState(c.destinationPort != null ? String(c.destinationPort) : "");
  const [proto,      setProto]      = useState(c.protocol        ?? "");
  const [user,       setUser]       = useState(c.affectedUser    ?? "");
  const [assetId,    setAssetId]    = useState(c.assetId         ?? "");
  const [assetType,  setAssetType]  = useState(c.assetType       ?? "");
  const [bizImpact,  setBizImpact]  = useState(c.businessImpact  ?? "");

  const hasAnyData = c.hostname || c.sourceIp || c.destinationIp || c.affectedUser
    || c.networkZone || c.protocol || c.firewallAction || c.srcCountry;

  async function handleSave() {
    setSaving(true);
    setSaveErr(null);
    setSaveOk(false);
    try {
      const body: Record<string, unknown> = {};
      if (hostname  !== (c.hostname        ?? "")) body.hostname        = hostname  || null;
      if (srcIp     !== (c.sourceIp        ?? "")) body.sourceIp        = srcIp     || null;
      if (srcPort   !== (c.sourcePort != null ? String(c.sourcePort) : ""))
        body.sourcePort = srcPort ? Number(srcPort) : null;
      if (dstIp     !== (c.destinationIp   ?? "")) body.destinationIp   = dstIp     || null;
      if (dstPort   !== (c.destinationPort != null ? String(c.destinationPort) : ""))
        body.destinationPort = dstPort ? Number(dstPort) : null;
      if (proto     !== (c.protocol        ?? "")) body.protocol        = proto     || null;
      if (user      !== (c.affectedUser    ?? "")) body.affectedUser    = user      || null;
      if (assetId   !== (c.assetId         ?? "")) body.assetId         = assetId   || null;
      if (assetType !== (c.assetType       ?? "")) body.assetType       = assetType || null;
      if (bizImpact !== (c.businessImpact  ?? "")) body.businessImpact  = bizImpact || null;

      if (!Object.keys(body).length) { setEditing(false); return; }

      try {
        await api.patch(`/api/incidents/${encodeURIComponent(c.id)}`, body);
      } catch (err: unknown) {
        const msg = (err as { response?: { data?: { error?: string }; status?: number } })?.response?.data?.error
                 ?? (err as Error)?.message
                 ?? "Error al guardar";
        throw new Error(msg);
      }
      setSaveOk(true);
      setEditing(false);
    } catch (err) {
      setSaveErr(err instanceof Error ? err.message : "Error al guardar");
    } finally {
      setSaving(false);
    }
  }

  const inputStyle: React.CSSProperties = {
    background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4,
    color: C.text, fontSize: 11, padding: "2px 6px", width: "100%",
    fontFamily: "monospace",
  };
  const rowStyle: React.CSSProperties = {
    display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, marginBottom: 4,
  };

  return (
    <Section label="Contexto de red / activo">
      {/* Cabecera con badges automáticos y botón editar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <Server size={10} color={C.textDim} />
          <span style={{ color: C.textDim, fontSize: 10, letterSpacing: "0.1em" }}>RED</span>
          {c.networkZone && (() => {
            const zc = NETWORK_ZONE_COLOR[c.networkZone] ?? C.textDim;
            return (
              <span style={{
                fontSize: 9, padding: "1px 6px", borderRadius: 3, fontWeight: 600,
                background: alpha(zc, 12),
                color: zc,
                border: `1px solid ${alpha(zc, 25)}`,
                textTransform: "uppercase",
              }}>
                {c.networkZone}
              </span>
            );
          })()}
          {c.firewallAction && (() => {
            const fc = FW_ACTION_COLOR[c.firewallAction] ?? C.textDim;
            return (
              <span style={{
                fontSize: 9, padding: "1px 6px", borderRadius: 3, fontWeight: 600,
                background: alpha(fc, 12),
                color: fc,
                border: `1px solid ${alpha(fc, 25)}`,
              }}>
                {c.firewallAction}
              </span>
            );
          })()}
          {c.srcCountry && (
            <span style={{ fontSize: 10, color: C.textDim }} title="País origen">
              🌐 {c.srcCountry}
            </span>
          )}
        </div>
        <button
          onClick={() => { setEditing((v) => !v); setSaveErr(null); setSaveOk(false); }}
          style={{
            background: "none", border: `1px solid ${C.border}`, borderRadius: 4,
            color: C.textDim, fontSize: 10, padding: "2px 8px", cursor: "pointer",
          }}
        >
          {editing ? "Cancelar" : "Editar"}
        </button>
      </div>

      {!editing ? (
        // ── Modo lectura ────────────────────────────────────────────────────
        <>
          {/* Flujo de red: SRC → DST */}
          {(c.sourceIp || c.destinationIp) ? (
            <div style={{
              display: "flex", alignItems: "center", gap: 6, padding: "6px 8px",
              background: C.bg, borderRadius: 6, marginBottom: 6, flexWrap: "wrap",
            }}>
              {/* Origen */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start" }}>
                <span style={{ color: C.textDim, fontSize: 9 }}>ORIGEN</span>
                <span style={{ color: C.text, fontSize: 12, fontFamily: "monospace", fontWeight: 600 }}>
                  {c.sourceIp ?? "—"}
                  {c.sourcePort != null && <span style={{ color: C.textDim }}>:{c.sourcePort}</span>}
                </span>
              </div>
              {/* Protocolo/acción */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: 1, minWidth: 60 }}>
                {c.protocol && (
                  <span style={{ color: C.textDim, fontSize: 9, textTransform: "uppercase" }}>
                    {c.protocol}
                  </span>
                )}
                <div style={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <div style={{ width: 20, height: 1, background: C.border }} />
                  <span style={{ fontSize: 8, color: C.textDim }}>▶</span>
                  <div style={{ width: 20, height: 1, background: C.border }} />
                </div>
              </div>
              {/* Destino */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end" }}>
                <span style={{ color: C.textDim, fontSize: 9 }}>DESTINO</span>
                <span style={{ color: C.text, fontSize: 12, fontFamily: "monospace", fontWeight: 600 }}>
                  {c.destinationIp ?? "—"}
                  {c.destinationPort != null && <span style={{ color: C.textDim }}>:{c.destinationPort}</span>}
                </span>
              </div>
            </div>
          ) : (
            <div style={{ color: C.textDim, fontSize: 11, padding: "4px 0", fontStyle: "italic" }}>
              Sin datos de red — <button
                onClick={() => setEditing(true)}
                style={{ background: "none", border: "none", color: C.blue, fontSize: 11, cursor: "pointer", padding: 0 }}
              >
                añadir manualmente
              </button>
            </div>
          )}

          {/* Hostname / Activo */}
          {(c.hostname || c.assetId || c.assetType) && (
            <>
              <div style={{ height: 1, background: C.border, margin: "6px 0" }} />
              <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 4 }}>
                <Server size={9} color={C.textDim} />
                <span style={{ color: C.textDim, fontSize: 9, letterSpacing: "0.1em" }}>ACTIVO</span>
              </div>
              {c.hostname  && <Field label="Hostname"    value={c.hostname}  mono />}
              {c.assetId   && <Field label="Asset ID"    value={c.assetId}   mono />}
              {c.assetType && <Field label="Tipo activo" value={c.assetType} />}
            </>
          )}

          {/* Usuario */}
          {c.affectedUser && (
            <>
              <div style={{ height: 1, background: C.border, margin: "6px 0" }} />
              <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 4 }}>
                <User size={9} color={C.textDim} />
                <span style={{ color: C.textDim, fontSize: 9, letterSpacing: "0.1em" }}>USUARIO AFECTADO</span>
              </div>
              <Field label="Usuario" value={c.affectedUser} mono />
            </>
          )}

          {/* Impacto negocio */}
          {c.businessImpact && (
            <>
              <div style={{ height: 1, background: C.border, margin: "6px 0" }} />
              <div style={{ color: C.text, fontSize: 12, lineHeight: 1.5 }}>
                <span style={{ color: C.textDim, fontSize: 10 }}>Impacto negocio: </span>
                {c.businessImpact}
              </div>
            </>
          )}

          {/* Mensaje si no hay nada */}
          {!hasAnyData && (
            <div style={{ color: C.textDim, fontSize: 11, textAlign: "center", padding: "8px 0" }}>
              Sin datos de contexto — haz clic en Editar para añadirlos
            </div>
          )}

          {saveOk && (
            <div style={{ marginTop: 6, color: C.green, fontSize: 11 }}>✓ Guardado correctamente</div>
          )}
        </>
      ) : (
        // ── Modo edición ────────────────────────────────────────────────────
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={rowStyle}>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>IP ORIGEN</div>
              <input style={inputStyle} value={srcIp} onChange={(e) => setSrcIp(e.target.value)} placeholder="192.168.1.10" />
            </div>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>PUERTO ORIGEN</div>
              <input style={inputStyle} value={srcPort} onChange={(e) => setSrcPort(e.target.value.replace(/\D/g,""))} placeholder="54321" inputMode="numeric" />
            </div>
          </div>
          <div style={rowStyle}>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>IP DESTINO</div>
              <input style={inputStyle} value={dstIp} onChange={(e) => setDstIp(e.target.value)} placeholder="203.0.113.45" />
            </div>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>PUERTO DESTINO</div>
              <input style={inputStyle} value={dstPort} onChange={(e) => setDstPort(e.target.value.replace(/\D/g,""))} placeholder="443" inputMode="numeric" />
            </div>
          </div>
          <div style={rowStyle}>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>PROTOCOLO</div>
              <select style={{ ...inputStyle, fontFamily: "inherit" }} value={proto} onChange={(e) => setProto(e.target.value)}>
                <option value="">—</option>
                {["tcp","udp","icmp","dns","http","https","smtp","ftp","ssh"].map((p) => (
                  <option key={p} value={p}>{p.toUpperCase()}</option>
                ))}
              </select>
            </div>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>HOSTNAME</div>
              <input style={inputStyle} value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="WORKSTATION-01" />
            </div>
          </div>
          <div style={rowStyle}>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>USUARIO AFECTADO</div>
              <input style={inputStyle} value={user} onChange={(e) => setUser(e.target.value)} placeholder="jdoe@empresa.com" />
            </div>
            <div>
              <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>TIPO ACTIVO</div>
              <select style={{ ...inputStyle, fontFamily: "inherit" }} value={assetType} onChange={(e) => setAssetType(e.target.value)}>
                <option value="">—</option>
                {["SERVER","WORKSTATION","NETWORK_DEVICE","CLOUD","IOT","UNKNOWN"].map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>ASSET ID</div>
            <input style={inputStyle} value={assetId} onChange={(e) => setAssetId(e.target.value)} placeholder="AST-001" />
          </div>
          <div>
            <div style={{ color: C.textDim, fontSize: 9, marginBottom: 2 }}>IMPACTO NEGOCIO</div>
            <textarea
              style={{ ...inputStyle, fontFamily: "inherit", resize: "vertical" }}
              value={bizImpact}
              onChange={(e) => setBizImpact(e.target.value)}
              placeholder="Describe el impacto en los servicios o datos de negocio…"
              rows={2}
            />
          </div>
          {saveErr && <div style={{ color: C.red, fontSize: 11 }}>{saveErr}</div>}
          <button
            onClick={() => void handleSave()}
            disabled={saving}
            style={{
              background: C.blue, border: "none", borderRadius: 4, color: "#ffffff",
              fontSize: 11, padding: "5px 12px", cursor: saving ? "not-allowed" : "pointer",
              opacity: saving ? 0.7 : 1,
            }}
          >
            {saving ? "Guardando…" : "Guardar contexto"}
          </button>
        </div>
      )}
    </Section>
  );
}
