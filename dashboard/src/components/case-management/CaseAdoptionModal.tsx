/**
 * CaseAdoptionModal.tsx
 * Modal obligatorio para adoptar un caso SOC.
 * Requiere CI del operador (≥ 5 chars). No puede cerrarse sin adoptar o cancelar explícitamente.
 */

import { useMemo, useState } from "react";
import { AlertTriangle, ShieldCheck } from "lucide-react";
import type { SocCase } from "./types";
import type { ScoringProfile } from "./scoringProfiles";
import { loadOperatorCi, saveOperatorCi, validateCi } from "@/lib/operator-ci";
import { useSocOperators, useSocRoles } from "@/hooks/useSocWorkflow";
import { useEscapeKey } from "@/hooks/useEscapeKey";
import { C, alpha } from "@/lib/cm-theme";

const SEV_COLOR: Record<string, string> = {
  CRITICAL: C.red,
  HIGH:     C.orange,
  MEDIUM:   C.cyan,
  LOW:      C.green,
};

interface Props {
  case:               SocCase;
  triggeringProfiles: ScoringProfile[];
  onAdopt:            (operatorCi: string, force?: boolean) => Promise<void>;
  onClose:            () => void;
}

interface AdoptConflict {
  adoptedBy:     string | null;
  adoptedByRole: string | null;
  adoptedAt:     string | null;
  hint:          string | null;
  message:       string;
}

function fmtRelative(iso: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return iso;
  const min = Math.round(ms / 60_000);
  if (min < 1)        return "hace instantes";
  if (min < 60)       return `hace ${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48)        return `hace ${hr}h`;
  return `hace ${Math.round(hr / 24)}d`;
}

export function CaseAdoptionModal({ case: c, triggeringProfiles, onAdopt, onClose }: Props) {
  const [ci, setCi]         = useState(loadOperatorCi);
  const [busy, setBusy]     = useState(false);
  const [error, setError]   = useState<string | null>(null);
  const [conflict, setConflict] = useState<AdoptConflict | null>(null);

  useEscapeKey(onClose, !busy);

  const sevColor = SEV_COLOR[c.severity] ?? C.cyan;

  // Candidatos: operadores activos cuyo rol tenga can_adopt=true.
  const { data: operators = [] } = useSocOperators();
  const { data: roles = [] }     = useSocRoles();
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

  // Guard de transferencia: advierte si el candidato seleccionado tiene un rol
  // inferior al del owner saliente (reasignación hacia abajo en la jerarquía).
  const ROLE_RANK: Record<string, number> = { L1: 1, L1L2: 2, L2: 3, L3: 4, LEADER: 5, ADMIN: 6 };
  const selected = operators.find(o => o.id === ci);
  const downgradeWarning = conflict?.adoptedByRole && selected
    ? (ROLE_RANK[selected.role_id] ?? 0) < (ROLE_RANK[conflict.adoptedByRole] ?? 0)
    : false;

  async function handleAdopt(force = false) {
    const trimmed = ci.trim();
    const ciErr = validateCi(trimmed);
    if (ciErr) { setError(ciErr); return; }
    setBusy(true);
    setError(null);
    if (!force) setConflict(null);
    try {
      await onAdopt(trimmed, force);
      saveOperatorCi(trimmed);
      onClose();
    } catch (err) {
      // Detectar 409 (axios) y abrir UI de transferencia
      const axiosErr = err as { response?: { status?: number; data?: { error?: string; adoptedBy?: string; adoptedByRole?: string; adoptedAt?: string; hint?: string; canForce?: boolean } } };
      const resp = axiosErr.response;
      if (resp?.status === 409 && resp.data?.canForce) {
        setConflict({
          adoptedBy:     resp.data.adoptedBy ?? null,
          adoptedByRole: resp.data.adoptedByRole ?? null,
          adoptedAt:     resp.data.adoptedAt ?? null,
          hint:          resp.data.hint ?? null,
          message:       resp.data.error ?? "El caso ya fue adoptado por otro operador",
        });
      } else {
        setError(err instanceof Error ? err.message : "Error al adoptar el caso");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 9000,
        background: "rgba(0,0,0,0.75)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
    >
      <div
        style={{
          background: C.bg,
          border: `1px solid ${alpha(sevColor, 38)}`,
          borderRadius: 12,
          padding: 28,
          width: 440,
          maxWidth: "94vw",
          boxShadow: `0 0 40px ${alpha(sevColor, 12)}`,
        }}
      >
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
          <AlertTriangle size={20} color={sevColor} />
          <span style={{ color: sevColor, fontWeight: 700, fontSize: 15 }}>
            Adoptar caso — {c.severity}
          </span>
        </div>

        {/* IOC */}
        <div
          style={{
            background: C.card,
            borderRadius: 8,
            padding: "10px 14px",
            marginBottom: 14,
            fontFamily: "monospace",
            fontSize: 13,
            color: C.text,
          }}
        >
          <div style={{ color: C.textDim, fontSize: 11, marginBottom: 4 }}>IOC</div>
          <div>{c.srcIp}</div>
          <div style={{ color: C.textDim, marginTop: 4 }}>
            Score: <span style={{ color: sevColor }}>{c.score}</span>
            {c.mitre.tacticName && (
              <span> · MITRE: {c.mitre.tacticName}</span>
            )}
          </div>
        </div>

        {/* Perfiles disparadores */}
        {triggeringProfiles.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ color: C.textDim, fontSize: 11, marginBottom: 6 }}>
              PERFILES ACTIVOS
            </div>
            {triggeringProfiles.map((p) => (
              <div
                key={p.id}
                style={{
                  fontSize: 12,
                  color: C.textDim,
                  padding: "3px 0",
                }}
              >
                · {p.name}
              </div>
            ))}
          </div>
        )}

        {/* Operador selector */}
        <div style={{ marginBottom: 16 }}>
          <label style={{ color: C.textDim, fontSize: 12, display: "block", marginBottom: 6 }}>
            Operador que adopta
          </label>
          {candidates.length > 0 ? (
            <select
              value={ci}
              onChange={(e) => setCi(e.target.value)}
              style={{
                width: "100%",
                background: C.bg,
                border: `1px solid ${C.border}`,
                borderRadius: 6,
                padding: "8px 12px",
                color: C.text,
                fontSize: 14,
                outline: "none",
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
              value={ci}
              onChange={(e) => setCi(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void handleAdopt()}
              placeholder="Ingrese su CI (mín. 5 caracteres)"
              style={{
                width: "100%",
                background: C.bg,
                border: `1px solid ${C.border}`,
                borderRadius: 6,
                padding: "8px 12px",
                color: C.text,
                fontSize: 14,
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          )}
          {error && (
            <div style={{ color: C.red, fontSize: 12, marginTop: 6 }}>{error}</div>
          )}
        </div>

        {/* Conflicto de adopción — opción de transferencia */}
        {conflict && (() => {
          const ownerName = conflict.adoptedBy
            ? (operators.find(o => o.id === conflict.adoptedBy)?.name ?? conflict.adoptedBy)
            : "—";
          return (
          <div style={{
            marginBottom: 14, padding: "10px 12px", borderRadius: 8,
            background: alpha(C.orange, 8), border: `1px solid ${alpha(C.orange, 38)}`,
            color: C.orange, fontSize: 12, lineHeight: 1.5,
          }}>
            <div style={{ fontWeight: 700, marginBottom: 4 }}>
              Caso tomado por <span style={{ color: C.text }}>{ownerName}</span>
              {conflict.adoptedAt && <span style={{ color: alpha(C.orange, 80), fontWeight: 500 }}> · {fmtRelative(conflict.adoptedAt)}</span>}
            </div>
            <div style={{ color: alpha(C.orange, 80), fontSize: 11 }}>
              <span style={{ fontFamily: "monospace" }}>CI {conflict.adoptedBy ?? "—"}</span>
              {conflict.adoptedByRole && <> · rol <span style={{ fontFamily: "monospace" }}>{conflict.adoptedByRole}</span></>}
            </div>
            {conflict.hint && (
              <div style={{ marginTop: 4, color: alpha(C.orange, 80) }}>{conflict.hint}</div>
            )}
            <div style={{ marginTop: 4, color: alpha(C.orange, 60), fontSize: 11 }}>
              Confirmar reasignación queda registrado en el timeline del caso.
            </div>
            {downgradeWarning && (
              <div style={{ marginTop: 6, padding: "6px 8px", background: alpha(C.red, 8),
                            border: `1px solid ${alpha(C.red, 38)}`, borderRadius: 6,
                            color: C.red, fontSize: 11, fontWeight: 600 }}>
                ⚠ El operador seleccionado ({selected?.role_id}) tiene un rol inferior al owner actual ({conflict?.adoptedByRole}).
                La reasignación hacia abajo puede degradar la capacidad de respuesta.
              </div>
            )}
          </div>
          );
        })()}

        {/* Actions */}
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button
            onClick={onClose}
            disabled={busy}
            style={{
              background: "transparent",
              border: `1px solid ${C.border}`,
              borderRadius: 6,
              padding: "7px 16px",
              color: C.textDim,
              cursor: busy ? "not-allowed" : "pointer",
              fontSize: 13,
            }}
          >
            Cancelar
          </button>
          {conflict ? (
            <button
              onClick={() => void handleAdopt(true)}
              disabled={busy || ci.trim().length < 5}
              style={{
                background: alpha(C.orange, 15),
                border: `1px solid ${alpha(C.orange, 50)}`,
                borderRadius: 6,
                padding: "7px 16px",
                color: C.orange,
                cursor: busy || ci.trim().length < 5 ? "not-allowed" : "pointer",
                fontSize: 13,
                fontWeight: 700,
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <ShieldCheck size={14} />
              {busy ? "Reasignando…" : "Reasignar a mí"}
            </button>
          ) : (
            <button
              onClick={() => void handleAdopt(false)}
              disabled={busy || ci.trim().length < 5}
              style={{
                background: alpha(sevColor, 12),
                border: `1px solid ${alpha(sevColor, 38)}`,
                borderRadius: 6,
                padding: "7px 16px",
                color: sevColor,
                cursor: busy || ci.trim().length < 5 ? "not-allowed" : "pointer",
                fontSize: 13,
                fontWeight: 600,
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <ShieldCheck size={14} />
              {busy ? "Adoptando…" : "Adoptar caso"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
