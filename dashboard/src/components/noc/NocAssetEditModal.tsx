import { FormEvent, useState } from "react";
import { toast } from "sonner";
import { patchNocDevice } from "@/api/noc";
import type { NocDevice } from "./types";
import { DEVICE_FAMILIES } from "./deviceFamilies";

interface Props {
  device: NocDevice;
  onClose: () => void;
  onSaved: () => void;
}

export function NocAssetEditModal({ device, onClose, onSaved }: Props) {
  const [form, setForm] = useState({
    hostname: device.hostname ?? "",
    device_type: device.device_type ?? "other",
    site: device.site ?? "",
    ip_address: (device.ip_address ?? "").replace(/\/32$/, ""),
    description: "",
    tags: "",
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const uf = (field: keyof typeof form, value: string) => setForm((p) => ({ ...p, [field]: value }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!form.hostname.trim()) {
      setError("El hostname es obligatorio.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      const tags = form.tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      await patchNocDevice(device.id, {
        hostname: form.hostname.trim(),
        device_type: form.device_type,
        site: form.site.trim(),
        ip_address: form.ip_address.trim() || undefined,
        description: form.description.trim() || undefined,
        ...(tags.length ? { tags } : {}),
      } as Parameters<typeof patchNocDevice>[1]);
      toast.success(`Activo "${form.hostname.trim()}" actualizado`);
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo actualizar el activo.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-md border border-[var(--ut-border)] bg-[var(--ut-bg-card)] shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-[var(--ut-border)] px-5 py-4">
          <div>
            <h2 className="text-sm font-semibold">Gestionar activo</h2>
            <p className="text-[11px] text-muted-foreground">{device.ip_address?.replace(/\/32$/, "") ?? "sin IP"}</p>
          </div>
          <button type="button" onClick={onClose} className="ut-btn ut-btn--outline ut-btn--sm" aria-label="Cerrar">✕</button>
        </div>
        <form onSubmit={submit} className="space-y-4 p-5">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="ut-card__label">Nombre (hostname) *</label>
              <input required value={form.hostname} onChange={(e) => uf("hostname", e.target.value)} className="ut-input" />
            </div>
            <div>
              <label className="ut-card__label">Familia / tipo</label>
              <select value={form.device_type} onChange={(e) => uf("device_type", e.target.value)} className="ut-input">
                {DEVICE_FAMILIES.map((f) => (
                  <option key={f.id} value={f.id}>{f.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="ut-card__label">Sitio</label>
              <input value={form.site} onChange={(e) => uf("site", e.target.value)} className="ut-input" placeholder="Ej. DC-Principal" />
            </div>
            <div>
              <label className="ut-card__label">IP</label>
              <input value={form.ip_address} onChange={(e) => uf("ip_address", e.target.value)} className="ut-input" placeholder="10.0.0.5" />
            </div>
            <div>
              <label className="ut-card__label">Etiquetas (coma)</label>
              <input value={form.tags} onChange={(e) => uf("tags", e.target.value)} className="ut-input" placeholder="prod, critico" />
            </div>
            <div className="col-span-2">
              <label className="ut-card__label">Descripción</label>
              <textarea
                value={form.description}
                onChange={(e) => uf("description", e.target.value)}
                className="ut-input"
                rows={3}
                placeholder="Función, owner, criticidad…"
              />
            </div>
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="ut-btn ut-btn--outline ut-btn--sm">Cancelar</button>
            <button type="submit" disabled={saving} className="ut-btn ut-btn--sm">{saving ? "Guardando…" : "Guardar cambios"}</button>
          </div>
        </form>
      </div>
    </div>
  );
}
