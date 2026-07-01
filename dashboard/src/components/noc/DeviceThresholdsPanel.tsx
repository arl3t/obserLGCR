import { FormEvent, useState } from "react";
import { toast } from "sonner";
import { patchNocDevice, type NocDeviceDetail } from "@/api/noc";

interface DeviceThresholdsPanelProps {
  device: NocDeviceDetail;
  onSaved: (device: NocDeviceDetail) => void;
}

export function DeviceThresholdsPanel({ device, onSaved }: DeviceThresholdsPanelProps) {
  const [form, setForm] = useState({
    heartbeat_timeout_secs: String(device.heartbeat_timeout_secs),
    cpu_threshold_pct: String(device.cpu_threshold_pct),
    mem_threshold_pct: String(device.mem_threshold_pct),
    rtt_threshold_ms: String(device.rtt_threshold_ms),
    description: device.description ?? "",
  });
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const updated = await patchNocDevice(device.id, {
        heartbeat_timeout_secs: Number(form.heartbeat_timeout_secs),
        cpu_threshold_pct: Number(form.cpu_threshold_pct),
        mem_threshold_pct: Number(form.mem_threshold_pct),
        rtt_threshold_ms: Number(form.rtt_threshold_ms),
        description: form.description.trim() || undefined,
      });
      toast.success("Umbrales actualizados");
      onSaved(updated);
    } catch {
      toast.error("No se pudieron guardar los umbrales");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="ut-card">
      <h3 className="ut-chart-head__title" style={{ marginBottom: "0.75rem" }}>
        Umbrales de alerta
      </h3>
      <form onSubmit={submit} className="noc-thresholds-form">
        <div>
          <label className="ut-card__label">Timeout heartbeat (s)</label>
          <input
            className="ut-input"
            type="number"
            min={30}
            value={form.heartbeat_timeout_secs}
            onChange={(e) => setForm((p) => ({ ...p, heartbeat_timeout_secs: e.target.value }))}
          />
        </div>
        <div>
          <label className="ut-card__label">CPU máx (%)</label>
          <input
            className="ut-input"
            type="number"
            min={1}
            max={100}
            value={form.cpu_threshold_pct}
            onChange={(e) => setForm((p) => ({ ...p, cpu_threshold_pct: e.target.value }))}
          />
        </div>
        <div>
          <label className="ut-card__label">Memoria máx (%)</label>
          <input
            className="ut-input"
            type="number"
            min={1}
            max={100}
            value={form.mem_threshold_pct}
            onChange={(e) => setForm((p) => ({ ...p, mem_threshold_pct: e.target.value }))}
          />
        </div>
        <div>
          <label className="ut-card__label">RTT máx (ms)</label>
          <input
            className="ut-input"
            type="number"
            min={1}
            value={form.rtt_threshold_ms}
            onChange={(e) => setForm((p) => ({ ...p, rtt_threshold_ms: e.target.value }))}
          />
        </div>
        <div className="noc-thresholds-form__full">
          <label className="ut-card__label">Descripción</label>
          <input
            className="ut-input"
            value={form.description}
            onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
          />
        </div>
        <div className="noc-thresholds-form__actions">
          <button type="submit" className="ut-btn ut-btn--sm" disabled={saving}>
            {saving ? "Guardando…" : "Guardar umbrales"}
          </button>
        </div>
      </form>
    </section>
  );
}
