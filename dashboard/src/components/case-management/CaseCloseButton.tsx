/**
 * CaseCloseButton — cierre manual de un caso desde el panel de detalle.
 * PATCH /api/incidents/:id/status con classification y postmortem si aplica.
 */

import { useMemo, useState } from "react";
import { CheckCircle2, Loader2, X } from "lucide-react";
import { toast } from "sonner";
import type { CaseClassification, CaseStatus, SocCase } from "./types";
import { extractApiErrorMessage } from "./useCaseManagement";
import { useEscapeKey } from "@/hooks/useEscapeKey";
import { C, alpha } from "@/lib/cm-theme";

const CLASSIFICATION_OPTIONS: Array<{ value: CaseClassification; label: string }> = [
  { value: "TRUE_POSITIVE",  label: "Positivo verdadero" },
  { value: "FALSE_POSITIVE", label: "Falso positivo" },
  { value: "DUPLICATE",      label: "Duplicado" },
  { value: "NO_ACTIONABLE",  label: "Sin acción requerida" },
];

const POSTMORTEM_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
const POSTMORTEM_MIN = 60;
const FP_ESCALATION_REASON_MIN = 80;

interface Props {
  caseItem: SocCase;
  compact?: boolean;
  onCloseCase: (
    caseId: string,
    status: CaseStatus,
    reason: string,
    classification: CaseClassification | undefined,
    lessonsLearned: string | undefined,
  ) => Promise<void>;
}

function isTerminal(status: string): boolean {
  return status === "CERRADO" || status === "FALSO_POSITIVO";
}

export function CaseCloseButton({ caseItem: c, compact, onCloseCase }: Props) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [closeStatus, setCloseStatus] = useState<"CERRADO" | "FALSO_POSITIVO">("CERRADO");
  const [classification, setClassification] = useState<CaseClassification>("NO_ACTIONABLE");
  const [reason, setReason] = useState("");
  const [lessonsLearned, setLessonsLearned] = useState("");

  const needsPostmortem = closeStatus === "CERRADO" && POSTMORTEM_SEVERITIES.has(c.severity);
  const needsLongFpReason = closeStatus === "FALSO_POSITIVO" && c.escalationSuggested;

  const canSubmit = useMemo(() => {
    if (closeStatus === "CERRADO" && !classification) return false;
    if (needsPostmortem && lessonsLearned.trim().length < POSTMORTEM_MIN) return false;
    if (needsLongFpReason && reason.trim().length < FP_ESCALATION_REASON_MIN) return false;
    return true;
  }, [closeStatus, classification, needsPostmortem, lessonsLearned, needsLongFpReason, reason]);

  useEscapeKey(() => setOpen(false), open && !busy);

  if (isTerminal(c.status)) return null;

  function resetForm() {
    setCloseStatus("CERRADO");
    setClassification("NO_ACTIONABLE");
    setReason("");
    setLessonsLearned("");
  }

  async function handleSubmit() {
    if (!canSubmit) return;
    setBusy(true);
    try {
      const finalClass =
        closeStatus === "FALSO_POSITIVO" ? ("FALSE_POSITIVE" as CaseClassification) : classification;
      await onCloseCase(
        c.id,
        closeStatus,
        reason.trim() || "Cierre manual desde gestión de incidentes",
        finalClass,
        needsPostmortem ? lessonsLearned.trim() : undefined,
      );
      toast.success(closeStatus === "FALSO_POSITIVO" ? "Caso marcado como falso positivo" : "Caso cerrado");
      setOpen(false);
      resetForm();
    } catch (err) {
      toast.error("No se pudo cerrar el caso", { description: extractApiErrorMessage(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 4,
          fontSize: compact ? 11 : 12,
          padding: compact ? "4px 10px" : "6px 14px",
          borderRadius: 6,
          background: alpha(C.green, 12),
          border: `1px solid ${alpha(C.green, 28)}`,
          color: C.green,
          cursor: "pointer",
          fontWeight: 600,
        }}
      >
        <CheckCircle2 size={compact ? 12 : 13} />
        Cerrar caso
      </button>

      {open && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 200,
            background: alpha("#000000", 55),
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 16,
          }}
          onClick={() => !busy && setOpen(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "min(100%, 28rem)",
              background: C.card,
              border: `1px solid ${alpha(C.green, 25)}`,
              borderRadius: 10,
              padding: 20,
              boxShadow: "0 16px 48px rgba(0,0,0,.45)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: C.text }}>Cerrar incidente</div>
                <div style={{ fontSize: 11, color: C.textDim, marginTop: 4 }}>
                  {c.caseCode ?? c.id.slice(0, 8)} · {c.severity}
                </div>
              </div>
              <button
                type="button"
                onClick={() => !busy && setOpen(false)}
                style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim }}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  Tipo de cierre
                </span>
                <select
                  value={closeStatus}
                  onChange={(e) => setCloseStatus(e.target.value as "CERRADO" | "FALSO_POSITIVO")}
                  disabled={busy}
                  style={{
                    background: C.bg,
                    border: `1px solid ${C.border}`,
                    borderRadius: 6,
                    padding: "8px 10px",
                    color: C.text,
                    fontSize: 12,
                  }}
                >
                  <option value="CERRADO">Cerrado — incidente resuelto</option>
                  <option value="FALSO_POSITIVO">Falso positivo</option>
                </select>
              </label>

              {closeStatus === "CERRADO" && (
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                    Clasificación
                  </span>
                  <select
                    value={classification}
                    onChange={(e) => setClassification(e.target.value as CaseClassification)}
                    disabled={busy}
                    style={{
                      background: C.bg,
                      border: `1px solid ${C.border}`,
                      borderRadius: 6,
                      padding: "8px 10px",
                      color: C.text,
                      fontSize: 12,
                    }}
                  >
                    {CLASSIFICATION_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </label>
              )}

              <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  Motivo {needsLongFpReason ? `(mín. ${FP_ESCALATION_REASON_MIN} caracteres)` : "(opcional)"}
                </span>
                <textarea
                  rows={2}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  disabled={busy}
                  placeholder="Resumen del cierre o justificación…"
                  style={{
                    background: C.bg,
                    border: `1px solid ${C.border}`,
                    borderRadius: 6,
                    padding: "8px 10px",
                    color: C.text,
                    fontSize: 12,
                    resize: "vertical",
                  }}
                />
              </label>

              {needsPostmortem && (
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                    Postmortem (mín. {POSTMORTEM_MIN} caracteres)
                  </span>
                  <textarea
                    rows={3}
                    value={lessonsLearned}
                    onChange={(e) => setLessonsLearned(e.target.value)}
                    disabled={busy}
                    placeholder="1) Causa raíz · 2) Prevención · 3) Mejora de proceso"
                    style={{
                      background: C.bg,
                      border: `1px solid ${C.border}`,
                      borderRadius: 6,
                      padding: "8px 10px",
                      color: C.text,
                      fontSize: 12,
                      resize: "vertical",
                    }}
                  />
                  <span style={{ fontSize: 10, color: lessonsLearned.trim().length >= POSTMORTEM_MIN ? C.green : C.textDim }}>
                    {lessonsLearned.trim().length}/{POSTMORTEM_MIN}
                  </span>
                </label>
              )}

              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 4 }}>
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  disabled={busy}
                  style={{
                    fontSize: 12,
                    padding: "6px 14px",
                    borderRadius: 6,
                    border: `1px solid ${C.border}`,
                    background: "transparent",
                    color: C.textDim,
                    cursor: busy ? "not-allowed" : "pointer",
                  }}
                >
                  Cancelar
                </button>
                <button
                  type="button"
                  onClick={() => void handleSubmit()}
                  disabled={busy || !canSubmit}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    fontSize: 12,
                    padding: "6px 14px",
                    borderRadius: 6,
                    border: `1px solid ${alpha(C.green, 30)}`,
                    background: alpha(C.green, 14),
                    color: C.green,
                    cursor: busy || !canSubmit ? "not-allowed" : "pointer",
                    fontWeight: 600,
                    opacity: busy || !canSubmit ? 0.6 : 1,
                  }}
                >
                  {busy ? <Loader2 size={13} /> : <CheckCircle2 size={13} />}
                  Confirmar cierre
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
