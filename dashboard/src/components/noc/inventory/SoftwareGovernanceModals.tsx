import { useState, type ReactNode } from "react";
import { useMutation } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import {
  createBlacklist,
  createWhitelist,
  type MatchType,
  type ServerSoftware,
  type Severity,
} from "@/api/inventory";

const MATCH_TYPES: MatchType[] = ["exact", "prefix", "suffix", "regex", "cpe"];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-md rounded-md border border-[var(--ut-border)] bg-[var(--ut-bg-card)] p-5 shadow-xl" role="dialog">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onClose} aria-label="Cerrar">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

function BlacklistModal({
  software,
  hostname,
  onClose,
  onSuccess,
}: {
  software: ServerSoftware;
  hostname: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [form, setForm] = useState({
    software_name: software.name,
    pattern: software.name,
    match_type: "exact" as MatchType,
    severity: "HIGH" as Severity,
    notes: `Detectado en ${hostname}`,
  });
  const inp = "ut-input";
  const mut = useMutation({
    mutationFn: () =>
      createBlacklist({
        software_name: form.software_name.trim(),
        pattern: form.pattern.trim(),
        match_type: form.match_type,
        severity: form.severity,
        notes: form.notes.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success(`"${software.name}" añadido a lista negra`);
      onSuccess();
      onClose();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <Modal title="Añadir a lista negra" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <input required className={inp} value={form.software_name} onChange={(e) => setForm((p) => ({ ...p, software_name: e.target.value }))} />
        <input required className={inp} value={form.pattern} onChange={(e) => setForm((p) => ({ ...p, pattern: e.target.value }))} />
        <select className={inp} value={form.match_type} onChange={(e) => setForm((p) => ({ ...p, match_type: e.target.value as MatchType }))}>
          {MATCH_TYPES.map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <select className={inp} value={form.severity} onChange={(e) => setForm((p) => ({ ...p, severity: e.target.value as Severity }))}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <div className="flex justify-end gap-2">
          <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onClose}>Cancelar</button>
          <button type="submit" disabled={mut.isPending} className="ut-btn ut-btn--sm">
            {mut.isPending ? <Loader2 size={14} className="animate-spin" /> : "Guardar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function WhitelistModal({
  software,
  hostname,
  onClose,
  onSuccess,
}: {
  software: ServerSoftware;
  hostname: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [form, setForm] = useState({
    software_name: software.name,
    pattern: software.name,
    match_type: "exact" as MatchType,
    notes: `Detectado en ${hostname}`,
  });
  const inp = "ut-input";
  const mut = useMutation({
    mutationFn: () =>
      createWhitelist({
        software_name: form.software_name.trim(),
        pattern: form.pattern.trim(),
        match_type: form.match_type,
        notes: form.notes.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success(`"${software.name}" añadido a lista blanca`);
      onSuccess();
      onClose();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <Modal title="Añadir a lista blanca" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <input required className={inp} value={form.software_name} onChange={(e) => setForm((p) => ({ ...p, software_name: e.target.value }))} />
        <input required className={inp} value={form.pattern} onChange={(e) => setForm((p) => ({ ...p, pattern: e.target.value }))} />
        <select className={inp} value={form.match_type} onChange={(e) => setForm((p) => ({ ...p, match_type: e.target.value as MatchType }))}>
          {MATCH_TYPES.map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <div className="flex justify-end gap-2">
          <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onClose}>Cancelar</button>
          <button type="submit" disabled={mut.isPending} className="ut-btn ut-btn--sm">
            {mut.isPending ? <Loader2 size={14} className="animate-spin" /> : "Guardar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function SoftwareGovernanceModals({
  blacklistTarget,
  whitelistTarget,
  hostname,
  onCloseBlacklist,
  onCloseWhitelist,
  onSuccess,
}: {
  blacklistTarget: ServerSoftware | null;
  whitelistTarget: ServerSoftware | null;
  hostname: string;
  onCloseBlacklist: () => void;
  onCloseWhitelist: () => void;
  onSuccess: () => void;
}) {
  return (
    <>
      {blacklistTarget && (
        <BlacklistModal software={blacklistTarget} hostname={hostname} onClose={onCloseBlacklist} onSuccess={onSuccess} />
      )}
      {whitelistTarget && (
        <WhitelistModal software={whitelistTarget} hostname={hostname} onClose={onCloseWhitelist} onSuccess={onSuccess} />
      )}
    </>
  );
}
