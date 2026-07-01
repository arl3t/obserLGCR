/**
 * CaseDetailSheet.tsx
 * Panel lateral de detalle de un caso SOC (solo lectura + gobernanza/contención).
 */

import { useEffect, useState } from "react";
import { X, Shield, ShieldCheck, ChevronDown, Clock, ExternalLink } from "lucide-react";
import type { SocCase } from "./types";
import { CaseGovernancePanel } from "./CaseGovernancePanel";
import { CaseAckButton } from "./CaseAckButton";
import { api } from "@/api/client";
import { C, alpha } from "@/lib/cm-theme";
import { formatDateTimePy } from "@/lib/format";

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
  case:            SocCase;
  onClose:           () => void;
  onAcknowledged?:   () => void;
}

export function CaseDetailSheet({ case: c, onClose, onAcknowledged }: Props) {
  const [containBusy, setContainBusy] = useState(false);
  const [containMsg, setContainMsg]     = useState<string | null>(null);

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
          <CaseAckButton caseItem={c} onAcknowledged={onAcknowledged} />
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
        {c.governanceContext && (
          <CaseGovernancePanel caseItem={c} />
        )}
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
