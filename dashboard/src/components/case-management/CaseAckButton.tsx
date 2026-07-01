import { useState } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { acknowledgeNocInventory } from "@/api/noc";
import type { SocCase } from "./types";
import { C, alpha } from "@/lib/cm-theme";

interface Props {
  caseItem:    SocCase;
  compact?:    boolean;
  onAcknowledged?: () => void;
}

function resolveAckTarget(caseItem: SocCase): { nocDeviceId: string | null; canAck: boolean } {
  const ctx = caseItem.governanceContext;
  if (!ctx) return { nocDeviceId: null, canAck: false };

  const payload = (ctx.payload ?? {}) as Record<string, unknown>;
  const incidentType = ctx.incidentType ?? "";
  const nocDeviceId =
    ctx.nocDeviceId ?? (payload.noc_device_id as string | undefined) ?? null;
  const canAck = Boolean(nocDeviceId) && (
    incidentType.startsWith("unknown") || incidentType === "undocumented_host"
  );
  return { nocDeviceId, canAck };
}

/** Reconocimiento de inventario (ACK) desde el detalle del caso. */
export function CaseAckButton({ caseItem, compact, onAcknowledged }: Props) {
  const { nocDeviceId, canAck } = resolveAckTarget(caseItem);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  if (!canAck || !nocDeviceId) return null;

  async function handleAck() {
    setBusy(true);
    try {
      await acknowledgeNocInventory(nocDeviceId!, undefined);
      toast.success("Activo reconocido en inventario");
      setDone(true);
      onAcknowledged?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "No se pudo reconocer el activo");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <span
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
          fontWeight: 600,
        }}
      >
        <CheckCircle2 size={compact ? 12 : 13} />
        ACK
      </span>
    );
  }

  return (
    <button
      type="button"
      onClick={() => void handleAck()}
      disabled={busy}
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
        cursor: busy ? "wait" : "pointer",
        fontWeight: 600,
      }}
    >
      {busy ? (
        <Loader2 size={12} className="animate-spin" />
      ) : (
        <CheckCircle2 size={compact ? 12 : 13} />
      )}
      {busy ? "ACK…" : "ACK inventario"}
    </button>
  );
}
