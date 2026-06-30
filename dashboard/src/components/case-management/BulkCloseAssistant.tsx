/**
 * BulkCloseAssistant — Asistente de cierre masivo (wizard 3 pasos).
 *
 * Visible/usable SÓLO para el Shift Manager activo (RBAC en UI + backend). Cierra
 * en lote casos abiertos que matcheen criterios; el dry-run (preview) es
 * obligatorio antes de confirmar. Caso de uso: reconocimiento hacia origen
 * legítimo (Microsoft / scanner autorizado / RFC1918).
 *
 * Strings en español; estilos del tema oscuro SOC (C/alpha).
 */
import { useState } from "react";
import { toast } from "sonner";
import { X, ChevronRight, ChevronLeft, Loader2, AlertTriangle, ShieldCheck, Lightbulb, Ban } from "lucide-react";
import { C, alpha } from "@/lib/cm-theme";
import {
  useBulkClosePreview, useBulkCloseExecute, useBulkWatchlistExecute,
  useBulkCloseDrain, useBulkCloseUndo, useBulkCloseTriage,
  type BulkCloseCriteria, type BulkClosePreview, type BulkAction, type ClusterAction,
  type TriageBucket,
} from "@/hooks/useBulkClose";

const SEVERITIES = ["LOW", "NEGLIGIBLE", "MEDIUM", "HIGH", "CRITICAL"] as const;
const STATUSES = ["NUEVO", "EN_ANALISIS", "CONFIRMADO", "MONITOREADO", "ESCALADO"] as const;
const IOC_TYPES = ["any", "ip", "domain", "fqdn", "url"] as const;

const CLASSIFICATIONS = [
  { value: "FALSE_POSITIVE", label: "Falso positivo — actividad legítima" },
  { value: "NO_ACTIONABLE", label: "Sin acción — no procede" },
  { value: "DUPLICATE", label: "Duplicado — ya tratado en otro caso" },
  { value: "TRUE_POSITIVE", label: "Verdadero positivo — resuelto" },
];

const REASON_TEMPLATES = [
  "Reconocimiento hacia infraestructura Microsoft/O365 legítima",
  "Scanner autorizado (Nessus/OpenVAS/etc) en allowlist",
  "Tráfico de origen confiable / activo conocido (RFC1918)",
  "Falso positivo: regla requiere ajuste (ver detalle)",
];

const ACTIONS: Array<{ id: BulkAction; label: string; color: string; desc: string }> = [
  { id: "close", label: "Cerrar casos", color: C.green, desc: "Cierra como FP/CERRADO (+ supresión opcional)" },
  { id: "watchlist", label: "Agregar a watchlist", color: C.orange, desc: "Bloquea las IPs en el feed saliente lgcrBL" },
  { id: "close_and_watchlist", label: "Cerrar + watchlist", color: C.red, desc: "Bloquea las IPs y cierra los casos" },
];

interface Preset { label: string; hint?: string; crit: Partial<BulkCloseCriteria>; action?: BulkAction; }
// Presets anclados a los clusters REALES del lake (auditoría 2026-06-17):
// el discriminador es técnica T1046 + netclass + firewall_action=blocked.
const PRESETS: Preset[] = [
  { label: "Discovery interno bloqueado", hint: "RFC1918 · T1046 · ya bloqueado → FP + supresión",
    crit: { mitreTechniqueId: "T1046", netClass: "internal", firewallAction: "blocked", iocType: "ip", severityIn: ["MEDIUM", "HIGH"], includeHighSeverity: true }, action: "close" },
  { label: "Discovery público bloqueado → lgcrBL", hint: "IP pública · T1046 · ya bloqueado → bloquear + cerrar",
    crit: { mitreTechniqueId: "T1046", netClass: "public", firewallAction: "blocked", iocType: "ip", severityIn: ["MEDIUM", "HIGH"], includeHighSeverity: true }, action: "close_and_watchlist" },
  { label: "Recon + scanner benigno", hint: "origen confiable (scanner autorizado)",
    crit: { mitreTacticId: "TA0043", matchTrustedOrigins: true }, action: "close" },
  { label: "Recon + Microsoft", hint: "dominio Microsoft/O365",
    crit: { mitreTacticId: "TA0043", iocType: "domain", iocPattern: "%microsoft%" }, action: "close" },
];

// Etiqueta + color de la acción recomendada por cluster (R5).
const CLUSTER_ACTION: Record<ClusterAction, { label: string; color: string }> = {
  close_and_suppress: { label: "Cerrar FP + supresión", color: C.green },
  close_and_watchlist: { label: "Bloquear lgcrBL + cerrar", color: C.orange },
  manual_review: { label: "Revisión manual (no apto para lote)", color: C.red },
  review: { label: "Revisar (confianza baja)", color: C.textDim },
};

function errMsg(e: unknown): string {
  const r = (e as { response?: { status?: number; data?: { error?: string; details?: string[] } } }).response;
  if (r?.status === 403) return "Sólo el Shift Manager activo puede ejecutar cierre masivo.";
  return r?.data?.error ?? (r?.data?.details?.join("; ")) ?? (e instanceof Error ? e.message : "Error");
}

const chip = (active: boolean, color: string): React.CSSProperties => ({
  padding: "4px 10px", fontSize: 11, fontWeight: 600, borderRadius: 5, cursor: "pointer",
  background: active ? alpha(color, 19) : "transparent",
  border: `1px solid ${alpha(active ? color : C.border, active ? 50 : 30)}`,
  color: active ? color : C.textDim, whiteSpace: "nowrap",
});
const field: React.CSSProperties = {
  width: "100%", padding: "6px 8px", background: C.bg, border: `1px solid ${C.border}`,
  borderRadius: 5, color: C.text, fontSize: 12,
};
const label: React.CSSProperties = { fontSize: 11, fontWeight: 600, color: C.textDim, marginBottom: 4, display: "block" };

export function BulkCloseAssistant({
  operatorCi, onClose, onDone,
}: {
  operatorCi: string;
  onClose: () => void;
  onDone?: () => void;
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1);

  // ── Criterios (paso 1) ──
  const [mitreTacticId, setMitre] = useState("TA0043");
  const [mitreTechniqueId, setTechnique] = useState("");
  const [netClass, setNetClass] = useState<"" | "internal" | "public">("");
  const [firewallAction, setFirewallAction] = useState<"" | "blocked" | "allowed" | "none">("");
  const [techClass, setTechClass] = useState<"" | "recon" | "threat" | "other">("");
  const [severitySet, setSeveritySet] = useState<Set<string>>(new Set(["LOW", "MEDIUM", "NEGLIGIBLE"]));
  const [statusSet, setStatusSet] = useState<Set<string>>(new Set(["NUEVO", "EN_ANALISIS"]));
  const [iocType, setIocType] = useState<string>("any");
  const [iocPattern, setIocPattern] = useState("");
  const [sourceLog, setSourceLog] = useState("");
  const [matchTrusted, setMatchTrusted] = useState(false);
  const [maxAgeDays, setMaxAgeDays] = useState(30);
  const [limit, setLimit] = useState(200);

  // ── Cierre (paso 3) ──
  const [closeStatus, setCloseStatus] = useState<"FALSO_POSITIVO" | "CERRADO">("FALSO_POSITIVO");
  const [classification, setClassification] = useState("FALSE_POSITIVE");
  const [reason, setReason] = useState("");
  const [createSuppressions, setCreateSuppressions] = useState(true);
  const [suppressionDays, setSuppressionDays] = useState(30);
  const [includeHigh, setIncludeHigh] = useState(false);
  const [smartSuppressions, setSmartSuppressions] = useState(true); // M4
  const [forceVetoed, setForceVetoed] = useState(false);            // M2

  // ── Acción del asistente ──
  const [action, setAction] = useState<BulkAction>("close");
  const [watchlistDays, setWatchlistDays] = useState(30);

  const [preview, setPreview] = useState<BulkClosePreview | null>(null);
  const previewMut = useBulkClosePreview();
  const executeMut = useBulkCloseExecute();
  const watchlistMut = useBulkWatchlistExecute();
  const drainMut = useBulkCloseDrain();   // M5
  const undoMut = useBulkCloseUndo();      // M3
  const triageQ = useBulkCloseTriage(true); // T1

  const toggle = (set: Set<string>, v: string, fn: (s: Set<string>) => void) => {
    const next = new Set(set);
    next.has(v) ? next.delete(v) : next.add(v);
    fn(next);
  };

  function buildCriteria(): BulkCloseCriteria {
    return {
      mitreTacticId: mitreTacticId.trim() || null,
      mitreTechniqueId: mitreTechniqueId.trim() || null,
      netClass: netClass || null,
      firewallAction: firewallAction || null,
      techClass: techClass || null,
      severityIn: [...severitySet],
      statusIn: [...statusSet],
      iocType: iocType === "any" ? null : iocType,
      iocPattern: iocPattern.trim(),
      sourceLog: sourceLog.trim(),
      matchTrustedOrigins: matchTrusted,
      maxAgeDays,
      includeHighSeverity: includeHigh,
      limit,
    };
  }

  function applyCriteria(crit: Partial<BulkCloseCriteria>) {
    setMitre(crit.mitreTacticId ?? "");
    setTechnique(crit.mitreTechniqueId ?? "");
    setNetClass(crit.netClass ?? "");
    setFirewallAction(crit.firewallAction ?? "");
    setTechClass(crit.techClass ?? "");
    setIocType(crit.iocType ?? "any");
    setIocPattern(crit.iocPattern ?? "");
    setMatchTrusted(crit.matchTrustedOrigins ?? false);
    setIncludeHigh(crit.includeHighSeverity ?? false);
    if (crit.severityIn) setSeveritySet(new Set(crit.severityIn));
  }
  function applyPreset(p: Preset) {
    applyCriteria(p.crit);
    if (p.action) setAction(p.action);
  }
  // T2: aplica un bucket de triage → criterios + acción + motivo, y previsualiza.
  async function applyTriageBucket(b: TriageBucket) {
    applyCriteria(b.criteria);
    const act: BulkAction = b.action === "close_and_watchlist" ? "close_and_watchlist" : "close";
    setAction(act);
    if (!reason.trim()) setReason(b.action === "close_and_watchlist"
      ? "Recon público ya bloqueado — bloqueo proactivo en lgcrBL + cierre (triage)"
      : "Recon interno ya bloqueado por el firewall — cierre masivo (triage)");
    try {
      const res = await previewMut.mutateAsync({ ...b.criteria });
      setPreview(res);
      setStep(2);
    } catch (e) { toast.error("Error al previsualizar el bucket", { description: errMsg(e) }); }
  }

  // Aplica la recomendación del backend (acción + estado/clasificación de cierre).
  function applyRecommendation() {
    const r = preview?.recommendation;
    if (!r) return;
    setAction(r.action);
    setCloseStatus(r.closeStatus);
    setClassification(r.classification);
    if (r.action === "close_and_watchlist") setIncludeHigh(true);
    setStep(3);
  }

  async function runPreview() {
    try {
      const res = await previewMut.mutateAsync(buildCriteria());
      setPreview(res);
      setStep(2);
    } catch (e) { toast.error("Error al previsualizar", { description: errMsg(e) }); }
  }

  async function doWatchlist() {
    const res = await watchlistMut.mutateAsync({
      confirmToken: preview!.confirmToken,
      caseIds: preview!.caseIds,
      watchlist: { days: watchlistDays, reason: reason.trim() || "Alta masiva al feed lgcrBL" },
    });
    toast.success(`${res.added} IP${res.added === 1 ? "" : "s"} agregada${res.added === 1 ? "" : "s"} al feed lgcrBL`, {
      description: `${res.skipped} sin IP · ${res.errors.length} rechazadas (reservadas/allowlist)`,
    });
  }
  function closureBody() {
    return {
      status: closeStatus, classification, reason: reason.trim(),
      createSuppressions, suppressionDays, includeHighSeverity: includeHigh,
      smartSuppressions, forceVetoed,
    };
  }
  // Toast de éxito con acción "Deshacer" (M3) cuando hay opId.
  function closeSuccessToast(closed: number, skipped: number, errors: number, suppr: number, opId?: string | null) {
    toast.success(`${closed} caso${closed === 1 ? "" : "s"} cerrado${closed === 1 ? "" : "s"}`, {
      description: `${skipped} omitidos · ${errors} errores · ${suppr} supresiones`,
      duration: 12000,
      action: opId ? {
        label: "Deshacer",
        onClick: async () => {
          try {
            const u = await undoMut.mutateAsync({ opId });
            toast.success(`Deshecho: ${u.reopened} reabiertos · ${u.suppressionsExpired} supresiones expiradas`);
            onDone?.();
          } catch (e) { toast.error("No se pudo deshacer", { description: errMsg(e) }); }
        },
      } : undefined,
    });
  }
  async function doClose() {
    const res = await executeMut.mutateAsync({
      confirmToken: preview!.confirmToken,
      caseIds: preview!.caseIds,
      closure: closureBody(),
    });
    closeSuccessToast(res.closed, res.skipped, res.errors.length, res.suppressionsCreated, res.opId);
  }
  // M5: vaciar el cluster completo (más allá del cap), por criterios.
  async function doDrain() {
    const n = preview?.matchCountTotal ?? preview?.matchCount ?? 0;
    if (!window.confirm(`Vas a VACIAR el cluster completo (~${n} casos, en lotes) como ${closeStatus}.\nMotivo: ${reason.trim()}\n\n¿Confirmás?`)) return;
    try {
      const res = await drainMut.mutateAsync({ criteria: buildCriteria(), closure: closureBody(), maxTotal: 5000 });
      closeSuccessToast(res.closed, res.skipped, res.errors, res.suppressionsCreated, res.opId);
      onDone?.(); onClose();
    } catch (e) { toast.error("Error al vaciar el cluster", { description: errMsg(e) }); }
  }

  async function runExecute() {
    if (!preview) return;
    const closing = action === "close" || action === "close_and_watchlist";
    if (reason.trim().length < 5) { toast.warning("El motivo es obligatorio (mín. 5 caracteres)."); return; }
    if (closing && (includeHigh || forceVetoed) && reason.trim().length < 20) {
      toast.warning("Incluir CRITICAL/HIGH o forzar vetados exige un motivo de al menos 20 caracteres."); return;
    }
    const n = preview.caseIds.length;
    const verb = action === "watchlist" ? `agregar las IPs de ${n} caso${n === 1 ? "" : "s"} al feed lgcrBL`
      : action === "close_and_watchlist" ? `bloquear las IPs en lgcrBL y cerrar ${n} caso${n === 1 ? "" : "s"} como ${closeStatus}`
      : `cerrar ${n} caso${n === 1 ? "" : "s"} como ${closeStatus} (${classification})`;
    if (!window.confirm(`Vas a ${verb}.\nMotivo: ${reason.trim()}\n\n¿Confirmás?`)) return;
    try {
      if (action === "watchlist") await doWatchlist();
      else if (action === "close") await doClose();
      else { await doWatchlist(); await doClose(); }  // combo: bloquear y luego cerrar
      onDone?.();
      onClose();
    } catch (e) { toast.error("Error al ejecutar la acción", { description: errMsg(e) }); }
  }

  const busy = previewMut.isPending || executeMut.isPending || watchlistMut.isPending || drainMut.isPending;
  const vetoedInSample = (preview?.sample ?? []).filter((r) => r.veto).length;

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 1000, background: "rgba(0,0,0,0.55)",
      display: "flex", justifyContent: "flex-end",
    }} onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{
        width: 520, maxWidth: "100vw", height: "100%", background: C.bg,
        borderLeft: `1px solid ${C.border}`, display: "flex", flexDirection: "column",
        boxShadow: "-8px 0 32px rgba(0,0,0,0.5)",
      }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "14px 16px", borderBottom: `1px solid ${C.border}` }}>
          <ShieldCheck size={16} style={{ color: C.orange }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: C.text }}>Cierre masivo de casos</div>
            <div style={{ fontSize: 10.5, color: C.textDim }}>Shift Manager {operatorCi} · paso {step} de 3</div>
          </div>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: C.textDim, cursor: "pointer" }}>
            <X size={18} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
          {/* ── Paso 1 ── */}
          {step === 1 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {/* T2: panel de triage del backlog */}
              <div style={{ border: `1px solid ${alpha(C.cyan, 30)}`, borderRadius: 8, padding: 10, background: alpha(C.cyan, 6) }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                  <Lightbulb size={14} style={{ color: C.cyan }} />
                  <span style={{ fontSize: 12.5, fontWeight: 700, color: C.cyan }}>Triage del backlog</span>
                  {triageQ.data && <span style={{ fontSize: 10.5, color: C.textDim }}>{triageQ.data.total} casos abiertos</span>}
                  {triageQ.isFetching && <Loader2 size={12} style={{ color: C.textDim, animation: "spin 0.8s linear infinite" }} />}
                </div>
                {triageQ.isError && <div style={{ fontSize: 11, color: C.red }}>No se pudo cargar el triage.</div>}
                <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                  {(triageQ.data?.buckets ?? []).map((b) => {
                    const meta = CLUSTER_ACTION[b.action];
                    return (
                      <div key={b.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", background: C.card, border: `1px solid ${C.border}`, borderRadius: 5 }}>
                        <span style={{ fontSize: 14, fontWeight: 700, color: b.count > 0 ? C.text : C.textDim, minWidth: 38, textAlign: "right" }}>{b.count}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 11.5, color: C.text }}>{b.label}</div>
                          <div style={{ fontSize: 10, color: meta.color }}>{b.hint}</div>
                        </div>
                        {b.closable ? (
                          <button onClick={() => void applyTriageBucket(b)} disabled={busy || b.count === 0}
                            style={{ background: b.count > 0 ? C.cyan : C.border, border: "none", color: b.count > 0 ? "#04121a" : C.textDim, borderRadius: 5, padding: "5px 9px", fontSize: 11, fontWeight: 600, cursor: b.count > 0 ? "pointer" : "default", whiteSpace: "nowrap" }}>
                            Triar →
                          </button>
                        ) : (
                          <span title="No apto para lote — enrutar a analista" style={{ fontSize: 10, color: C.red, fontWeight: 600, whiteSpace: "nowrap" }}>→ analista</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              <div>
                <span style={label}>Presets rápidos</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {PRESETS.map((p) => (
                    <button key={p.label} title={p.hint} onClick={() => applyPreset(p)} style={chip(false, C.cyan)}>{p.label}</button>
                  ))}
                </div>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{ flex: 1 }}>
                  <span style={label}>Táctica MITRE</span>
                  <input value={mitreTacticId} onChange={(e) => setMitre(e.target.value)} placeholder="TA0043" style={field} />
                </div>
                <div style={{ flex: 1 }}>
                  <span style={label}>Técnica MITRE</span>
                  <input value={mitreTechniqueId} onChange={(e) => setTechnique(e.target.value)} placeholder="T1046" style={field} />
                </div>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{ flex: 1 }}>
                  <span style={label}>Red (netclass)</span>
                  <select value={netClass} onChange={(e) => setNetClass(e.target.value as "" | "internal" | "public")} style={field}>
                    <option value="">cualquiera</option>
                    <option value="internal">interna (RFC1918)</option>
                    <option value="public">pública</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <span style={label}>Acción firewall</span>
                  <select value={firewallAction} onChange={(e) => setFirewallAction(e.target.value as "" | "blocked" | "allowed" | "none")} style={field}>
                    <option value="">cualquiera</option>
                    <option value="blocked">bloqueado (ya mitigado)</option>
                    <option value="allowed">permitido</option>
                    <option value="none">sin acción</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <span style={label}>Clase de técnica</span>
                  <select value={techClass} onChange={(e) => setTechClass(e.target.value as "" | "recon" | "threat" | "other")} style={field}>
                    <option value="">cualquiera</option>
                    <option value="recon">recon (ruido)</option>
                    <option value="threat">amenaza</option>
                    <option value="other">otra</option>
                  </select>
                </div>
              </div>
              <div>
                <span style={label}>Severidad</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {SEVERITIES.map((s) => {
                    const high = s === "CRITICAL" || s === "HIGH";
                    return (
                      <button key={s} onClick={() => toggle(severitySet, s, setSeveritySet)}
                        style={chip(severitySet.has(s), high ? C.red : C.green)}>{s}</button>
                    );
                  })}
                </div>
              </div>
              <div>
                <span style={label}>Estado</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {STATUSES.map((s) => (
                    <button key={s} onClick={() => toggle(statusSet, s, setStatusSet)} style={chip(statusSet.has(s), C.blue)}>{s}</button>
                  ))}
                </div>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{ flex: 1 }}>
                  <span style={label}>Tipo IOC</span>
                  <select value={iocType} onChange={(e) => setIocType(e.target.value)} style={field}>
                    {IOC_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <div style={{ flex: 2 }}>
                  <span style={label}>Patrón IOC (ILIKE)</span>
                  <input value={iocPattern} onChange={(e) => setIocPattern(e.target.value)} placeholder="%microsoft%" style={field} />
                </div>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{ flex: 2 }}>
                  <span style={label}>Source log (prefijo)</span>
                  <input value={sourceLog} onChange={(e) => setSourceLog(e.target.value)} placeholder="wazuh" style={field} />
                </div>
                <div style={{ flex: 1 }}>
                  <span style={label}>Antigüedad ≤ (días)</span>
                  <input type="number" min={1} max={365} value={maxAgeDays} onChange={(e) => setMaxAgeDays(Number(e.target.value))} style={field} />
                </div>
                <div style={{ flex: 1 }}>
                  <span style={label}>Límite</span>
                  <input type="number" min={1} max={200} value={limit} onChange={(e) => setLimit(Math.min(200, Number(e.target.value)))} style={field} />
                </div>
              </div>
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: C.text, cursor: "pointer" }}>
                <input type="checkbox" checked={matchTrusted} onChange={(e) => setMatchTrusted(e.target.checked)} />
                Sólo orígenes confiables (Microsoft / scanner benigno / RFC1918)
              </label>
            </div>
          )}

          {/* ── Paso 2: preview ── */}
          {step === 2 && preview && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{ flex: 1, padding: 12, background: C.card, borderRadius: 6, border: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: (preview.matchCountTotal ?? preview.matchCount) > 0 ? C.orange : C.textDim }}>{preview.matchCountTotal ?? preview.matchCount}</div>
                  <div style={{ fontSize: 11, color: C.textDim }}>casos coinciden{(preview.matchCountTotal ?? 0) > preview.matchCount ? ` (lote: ${preview.matchCount})` : ""}</div>
                </div>
                <div style={{ flex: 2, fontSize: 11.5, color: C.text, display: "flex", flexDirection: "column", justifyContent: "center", gap: 3 }}>
                  <div>Severidad: {Object.entries(preview.bySeverity).map(([k, v]) => `${k}:${v}`).join(" · ") || "—"}</div>
                  <div>Estado: {Object.entries(preview.byStatus).map(([k, v]) => `${k}:${v}`).join(" · ") || "—"}</div>
                  {preview.blocked.highSeverity > 0 && (
                    <div style={{ color: C.red }}>⛔ {preview.blocked.highSeverity} CRITICAL/HIGH bloqueados (no habilitados)</div>
                  )}
                </div>
              </div>
              {preview.capped && (
                <div style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 11.5, color: C.orange, padding: "6px 8px", background: alpha(C.orange, 12), borderRadius: 5 }}>
                  <AlertTriangle size={13} /> El lote cierra hasta {preview.cappedAt}; el cluster completo tiene {preview.matchCountTotal ?? preview.matchCount}. Usá "Vaciar cluster" en el paso 3 para todo.
                </div>
              )}
              {preview.recommendation && preview.matchCount > 0 && (
                <div style={{ padding: "8px 10px", background: alpha(C.cyan, 10), border: `1px solid ${alpha(C.cyan, 30)}`, borderRadius: 6 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 700, color: C.cyan, marginBottom: 3 }}>
                    <Lightbulb size={13} /> Recomendación
                  </div>
                  <div style={{ fontSize: 11.5, color: C.text, marginBottom: 6 }}>{preview.recommendation.rationale}</div>
                  <button onClick={applyRecommendation}
                    style={{ background: C.cyan, border: "none", color: "#04121a", borderRadius: 5, padding: "5px 10px", fontSize: 11.5, fontWeight: 600, cursor: "pointer" }}>
                    Aplicar recomendación →
                  </button>
                </div>
              )}
              {preview.clusters && preview.clusters.length > 0 && (
                <div>
                  <span style={label}>Clusters (netclass · firewall · técnica)</span>
                  <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                    {preview.clusters.map((cl) => {
                      const meta = CLUSTER_ACTION[cl.action];
                      const conf = cl.avgConfidence;
                      const confColor = conf == null ? C.textDim : conf >= 0.7 ? C.green : conf >= 0.4 ? C.orange : C.red;
                      return (
                        <div key={cl.key} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", background: C.card, border: `1px solid ${C.border}`, borderRadius: 5 }}>
                          <span style={{ fontSize: 13, fontWeight: 700, color: C.text, minWidth: 34, textAlign: "right" }}>{cl.count}</span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: 11.5, color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{cl.label}</div>
                            <div style={{ fontSize: 10, color: meta.color, fontWeight: 600 }}>{meta.label}{cl.vetoed > 0 ? ` · ${cl.vetoed} vetados` : ""}</div>
                          </div>
                          <span title="confianza media de cierre" style={{ fontSize: 11, fontWeight: 700, color: confColor }}>{conf == null ? "—" : `${Math.round(conf * 100)}%`}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
              <div>
                <span style={label}>Muestra (máx. 10)</span>
                <div style={{ border: `1px solid ${C.border}`, borderRadius: 6, overflow: "hidden" }}>
                  <table style={{ width: "100%", fontSize: 10.5, borderCollapse: "collapse" }}>
                    <thead style={{ background: C.card, color: C.textDim }}>
                      <tr>
                        <th style={{ textAlign: "left", padding: "4px 6px" }}>IOC</th>
                        <th style={{ textAlign: "left", padding: "4px 6px" }}>Tipo</th>
                        <th style={{ textAlign: "left", padding: "4px 6px" }}>Sev</th>
                        <th style={{ textAlign: "left", padding: "4px 6px" }}>Estado</th>
                        <th style={{ textAlign: "left", padding: "4px 6px" }}>Táctica</th>
                        <th style={{ textAlign: "right", padding: "4px 6px" }}>Score</th>
                        <th style={{ textAlign: "right", padding: "4px 6px" }}>Conf.</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.sample.length === 0 ? (
                        <tr><td colSpan={7} style={{ padding: 8, textAlign: "center", color: C.textDim }}>Sin coincidencias</td></tr>
                      ) : preview.sample.map((r) => {
                        const conf = r.confidence ?? null;
                        const confColor = r.veto ? C.red : conf == null ? C.textDim : conf >= 0.7 ? C.green : conf >= 0.4 ? C.orange : C.red;
                        return (
                        <tr key={r.id} style={{ borderTop: `1px solid ${C.border}` }}>
                          <td style={{ padding: "4px 6px", fontFamily: "monospace", color: C.text }}>{(r.ioc_value ?? "—").slice(0, 26)}</td>
                          <td style={{ padding: "4px 6px", color: C.textDim }}>{r.ioc_type ?? "—"}</td>
                          <td style={{ padding: "4px 6px", color: C.text }}>{r.severity}</td>
                          <td style={{ padding: "4px 6px", color: C.textDim }}>{r.status}</td>
                          <td style={{ padding: "4px 6px", color: C.textDim }}>{r.mitre_technique_id ?? r.mitre_tactic_id ?? "—"}</td>
                          <td style={{ padding: "4px 6px", textAlign: "right", color: C.text }}>{r.score ?? "—"}</td>
                          <td title={r.veto ?? undefined} style={{ padding: "4px 6px", textAlign: "right", fontWeight: 600, color: confColor }}>{r.veto ? "⛔" : conf == null ? "—" : `${Math.round(conf * 100)}%`}</td>
                        </tr>
                      ); })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ── Paso 3: acción + confirmar ── */}
          {step === 3 && preview && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div>
                <span style={label}>Acción a aplicar</span>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {ACTIONS.map((a) => (
                    <button key={a.id} onClick={() => setAction(a.id)}
                      style={{
                        textAlign: "left", padding: "8px 10px", borderRadius: 6, cursor: "pointer",
                        background: action === a.id ? alpha(a.color, 14) : "transparent",
                        border: `1px solid ${alpha(action === a.id ? a.color : C.border, action === a.id ? 50 : 30)}`,
                      }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5, fontWeight: 700, color: action === a.id ? a.color : C.text }}>
                        {a.id === "close" ? <ShieldCheck size={13} /> : <Ban size={13} />}
                        {a.label}
                      </div>
                      <div style={{ fontSize: 10.5, color: C.textDim, marginTop: 2 }}>{a.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ fontSize: 12, color: C.text }}>
                Afecta a <strong style={{ color: C.orange }}>{preview.caseIds.length}</strong> casos.
              </div>

              {action !== "watchlist" && (
                <div style={{ display: "flex", gap: 10 }}>
                  <div style={{ flex: 1 }}>
                    <span style={label}>Estado de cierre</span>
                    <select value={closeStatus} onChange={(e) => setCloseStatus(e.target.value as "FALSO_POSITIVO" | "CERRADO")} style={field}>
                      <option value="FALSO_POSITIVO">FALSO_POSITIVO</option>
                      <option value="CERRADO">CERRADO</option>
                    </select>
                  </div>
                  <div style={{ flex: 1 }}>
                    <span style={label}>Clasificación</span>
                    <select value={classification} onChange={(e) => setClassification(e.target.value)} style={field}>
                      {CLASSIFICATIONS.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                    </select>
                  </div>
                </div>
              )}

              {action !== "close" && (
                <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
                  <div style={{ width: 150 }}>
                    <span style={label}>Watchlist: vigencia (días)</span>
                    <input type="number" min={1} max={90} value={watchlistDays} onChange={(e) => setWatchlistDays(Number(e.target.value))} style={field} />
                  </div>
                  <div style={{ flex: 1, fontSize: 10.5, color: C.textDim, paddingBottom: 7 }}>
                    Sólo IPs públicas entran al feed lgcrBL; reservadas/allowlist se rechazan.
                  </div>
                </div>
              )}

              <div>
                <span style={label}>Motivo (obligatorio)</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 6 }}>
                  {REASON_TEMPLATES.map((t) => (
                    <button key={t} onClick={() => setReason(t)} style={chip(false, C.green)}>{t.slice(0, 28)}…</button>
                  ))}
                </div>
                <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3}
                  placeholder="Ej. Reconocimiento hacia infraestructura Microsoft legítima"
                  style={{ ...field, resize: "vertical" }} />
              </div>

              {action !== "watchlist" && (
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: C.text, cursor: "pointer" }}>
                  <input type="checkbox" checked={createSuppressions} onChange={(e) => setCreateSuppressions(e.target.checked)} />
                  Crear supresiones al cerrar como FP
                  {createSuppressions && (
                    <input type="number" min={1} max={365} value={suppressionDays} onChange={(e) => setSuppressionDays(Number(e.target.value))}
                      style={{ ...field, width: 64, marginLeft: 4 }} />
                  )}
                  {createSuppressions && <span style={{ color: C.textDim, fontSize: 11 }}>días</span>}
                </label>
              )}

              {action !== "watchlist" && createSuppressions && (
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11.5, color: C.text, cursor: "pointer" }}>
                  <input type="checkbox" checked={smartSuppressions} onChange={(e) => setSmartSuppressions(e.target.checked)} />
                  Supresión inteligente (recon interno ≤14d · IP pública no se suprime, va al feed)
                </label>
              )}

              {action !== "watchlist" && (
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: C.red, cursor: "pointer", padding: "6px 8px", background: alpha(C.red, 10), borderRadius: 5 }}>
                  <input type="checkbox" checked={includeHigh} onChange={(e) => setIncludeHigh(e.target.checked)} />
                  Incluir CRITICAL/HIGH (exige motivo ≥ 20 caracteres)
                </label>
              )}

              {action !== "watchlist" && vetoedInSample > 0 && (
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: C.red, cursor: "pointer", padding: "6px 8px", background: alpha(C.red, 14), borderRadius: 5, border: `1px solid ${alpha(C.red, 40)}` }}>
                  <input type="checkbox" checked={forceVetoed} onChange={(e) => setForceVetoed(e.target.checked)} />
                  ⚠ Forzar casos VETADOS (amenaza/CRITICAL/intel maliciosa) — sólo si sabés lo que hacés (motivo ≥ 20)
                </label>
              )}

              {/* M5: vaciar cluster completo cuando hay más de lo que entra en el lote */}
              {(action === "close") && (preview.matchCountTotal ?? 0) > preview.matchCount && (
                <button onClick={() => void doDrain()} disabled={busy || reason.trim().length < 10}
                  style={{ background: alpha(C.orange, 16), border: `1px solid ${alpha(C.orange, 50)}`, color: C.orange, borderRadius: 6, padding: "8px 10px", fontSize: 12, fontWeight: 600, cursor: busy ? "wait" : "pointer", display: "flex", alignItems: "center", gap: 6 }}>
                  {drainMut.isPending ? <Loader2 size={14} style={{ animation: "spin 0.8s linear infinite" }} /> : <Ban size={14} />}
                  Vaciar cluster completo (~{preview.matchCountTotal} casos, en lotes) — motivo ≥ 10
                </button>
              )}
            </div>
          )}
        </div>

        {/* Footer nav */}
        <div style={{ display: "flex", gap: 8, padding: "12px 16px", borderTop: `1px solid ${C.border}` }}>
          {step > 1 && (
            <button onClick={() => setStep((s) => (s - 1) as 1 | 2 | 3)} disabled={busy}
              style={{ background: "transparent", border: `1px solid ${C.border}`, color: C.text, borderRadius: 6, padding: "7px 12px", fontSize: 12, cursor: "pointer", display: "flex", alignItems: "center", gap: 4 }}>
              <ChevronLeft size={14} /> Atrás
            </button>
          )}
          <div style={{ flex: 1 }} />
          {step === 1 && (
            <button onClick={() => void runPreview()} disabled={busy}
              style={{ background: C.blue, border: "none", color: "#fff", borderRadius: 6, padding: "7px 14px", fontSize: 12, fontWeight: 600, cursor: busy ? "wait" : "pointer", display: "flex", alignItems: "center", gap: 6 }}>
              {previewMut.isPending ? <Loader2 size={14} style={{ animation: "spin 0.8s linear infinite" }} /> : null}
              Previsualizar <ChevronRight size={14} />
            </button>
          )}
          {step === 2 && (
            <button onClick={() => setStep(3)} disabled={busy || !preview || preview.matchCount === 0}
              style={{ background: preview && preview.matchCount > 0 ? C.blue : C.border, border: "none", color: "#fff", borderRadius: 6, padding: "7px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", gap: 6, opacity: preview && preview.matchCount > 0 ? 1 : 0.6 }}>
              Configurar acción <ChevronRight size={14} />
            </button>
          )}
          {step === 3 && (
            <button onClick={() => void runExecute()} disabled={busy}
              style={{ background: action === "watchlist" ? C.orange : C.red, border: "none", color: "#fff", borderRadius: 6, padding: "7px 14px", fontSize: 12, fontWeight: 700, cursor: busy ? "wait" : "pointer", display: "flex", alignItems: "center", gap: 6 }}>
              {busy ? <Loader2 size={14} style={{ animation: "spin 0.8s linear infinite" }} /> : null}
              {action === "watchlist" ? "Agregar al feed" : action === "close_and_watchlist" ? "Bloquear y cerrar" : "Cerrar"} {preview?.caseIds.length ?? 0}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
