import { useState } from "react";
import { CheckCircle2, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { acknowledgeNocInventory, type NocDeviceDetail } from "@/api/noc";

type Props = {
  device: NocDeviceDetail;
  onAcknowledged: () => void;
};

export function DeviceInventoryAckPanel({ device, onAcknowledged }: Props) {
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);

  if (device.inventory_ack) {
    return (
      <section className="ut-card" style={{ borderColor: "rgba(52, 211, 153, 0.25)" }}>
        <div className="flex items-center gap-2 text-emerald-400">
          <CheckCircle2 className="h-4 w-4" />
          <span className="text-sm font-medium">Activo reconocido en inventario</span>
        </div>
        {device.inventory_ack_at && (
          <p className="ut-sidebar__text mt-1">
            ACK {new Date(device.inventory_ack_at).toLocaleString("es-PY")}
            {device.discovered_via ? ` · origen: ${device.discovered_via}` : ""}
          </p>
        )}
      </section>
    );
  }

  return (
    <section className="ut-card" style={{ borderColor: "rgba(251, 191, 36, 0.35)" }}>
      <div className="flex items-center gap-2 text-amber-300">
        <AlertTriangle className="h-4 w-4" />
        <span className="text-sm font-medium">Activo sin reconocimiento (ACK)</span>
      </div>
      <p className="ut-sidebar__text mt-2">
        Detectado vía {device.discovered_via ?? "descubrimiento"}. Sin ACK puede generar incidente en Gestión.
      </p>
      <textarea
        className="ut-input mt-3 min-h-[60px] w-full text-[12px]"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Notas de reconocimiento (opcional)"
      />
      <button
        type="button"
        disabled={busy}
        className="ut-btn ut-btn--sm mt-2"
        onClick={async () => {
          setBusy(true);
          try {
            await acknowledgeNocInventory(device.id, notes.trim() || undefined);
            toast.success("Activo reconocido");
            onAcknowledged();
          } catch {
            toast.error("No se pudo reconocer el activo");
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Reconociendo…" : "Reconocer activo (ACK)"}
      </button>
    </section>
  );
}
