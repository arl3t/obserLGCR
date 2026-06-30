import { FormEvent, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { ChevronDown, ChevronRight, Loader2, Package, ShieldAlert, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import {
  createBlacklist,
  createWhitelist,
  listHostServerSoftware,
  listInventoryHosts,
  type InventoryHost,
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

function fmtTs(ts: string | null) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "short", timeStyle: "short" });
}

function invNotes(hostname: string | null, kind: "blacklist" | "whitelist") {
  const label = kind === "blacklist" ? "lista negra" : "lista blanca";
  return hostname ? `Detectado en inventario (${label}): ${hostname}` : `Detectado en inventario (${label})`;
}

function defaultBlForm(software: ServerSoftware, hostname: string | null) {
  return {
    software_name: software.name,
    pattern: software.name,
    match_type: "exact" as MatchType,
    severity: "HIGH" as Severity,
    publisher: software.publisher ?? "",
    notes: invNotes(hostname, "blacklist"),
  };
}

function defaultWlForm(software: ServerSoftware, hostname: string | null) {
  return {
    software_name: software.name,
    pattern: software.name,
    match_type: "exact" as MatchType,
    publisher: software.publisher ?? "",
    notes: invNotes(hostname, "whitelist"),
  };
}

function BlacklistModal({
  software,
  hostname,
  onClose,
  onSuccess,
}: {
  software: ServerSoftware;
  hostname: string | null;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [form, setForm] = useState(() => defaultBlForm(software, hostname));
  const inp = "ut-input";

  const mut = useMutation({
    mutationFn: () =>
      createBlacklist({
        software_name: form.software_name.trim(),
        pattern: form.pattern.trim(),
        match_type: form.match_type,
        severity: form.severity,
        publisher: form.publisher.trim() || undefined,
        notes: form.notes.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success(`"${software.name}" añadido a lista negra`);
      onSuccess();
      onClose();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!form.software_name.trim() || !form.pattern.trim()) return;
    mut.mutate();
  }

  return (
    <Modal title="Añadir a lista negra" onClose={onClose}>
      <SoftwareModalHint software={software} hostname={hostname} />
      <form onSubmit={submit} className="space-y-3">
        <RuleFields
          inp={inp}
          form={form}
          setForm={
            setForm as React.Dispatch<
              React.SetStateAction<{
                software_name: string;
                pattern: string;
                match_type: MatchType;
                publisher: string;
                notes: string;
                severity?: Severity;
              }>
            >
          }
          showSeverity
        />
        <ModalActions onClose={onClose} pending={mut.isPending} submitLabel="Añadir a blacklist" />
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
  hostname: string | null;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [form, setForm] = useState(() => defaultWlForm(software, hostname));
  const inp = "ut-input";

  const mut = useMutation({
    mutationFn: () =>
      createWhitelist({
        software_name: form.software_name.trim(),
        pattern: form.pattern.trim(),
        match_type: form.match_type,
        publisher: form.publisher.trim() || undefined,
        notes: form.notes.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success(`"${software.name}" añadido a lista blanca`);
      onSuccess();
      onClose();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!form.software_name.trim() || !form.pattern.trim()) return;
    mut.mutate();
  }

  return (
    <Modal title="Añadir a lista blanca" onClose={onClose}>
      <SoftwareModalHint software={software} hostname={hostname} />
      <form onSubmit={submit} className="space-y-3">
        <RuleFields inp={inp} form={form} setForm={setForm} />
        <ModalActions onClose={onClose} pending={mut.isPending} submitLabel="Añadir a whitelist" />
      </form>
    </Modal>
  );
}

function SoftwareModalHint({
  software,
  hostname,
}: {
  software: ServerSoftware;
  hostname: string | null;
}) {
  return (
    <p className="ut-sidebar__text" style={{ marginBottom: "0.75rem" }}>
      Crear regla desde <strong>{software.name}</strong>
      {software.version ? ` v${software.version}` : ""}
      {hostname ? ` · ${hostname}` : ""}
    </p>
  );
}

function RuleFields({
  inp,
  form,
  setForm,
  showSeverity,
}: {
  inp: string;
  form: {
    software_name: string;
    pattern: string;
    match_type: MatchType;
    publisher: string;
    notes: string;
    severity?: Severity;
  };
  setForm: React.Dispatch<
    React.SetStateAction<{
      software_name: string;
      pattern: string;
      match_type: MatchType;
      publisher: string;
      notes: string;
      severity?: Severity;
    }>
  >;
  showSeverity?: boolean;
}) {
  return (
    <>
      <div>
        <label className="ut-card__label">Nombre *</label>
        <input
          required
          className={inp}
          value={form.software_name}
          onChange={(e) => setForm((p) => ({ ...p, software_name: e.target.value }))}
        />
      </div>
      <div>
        <label className="ut-card__label">Patrón *</label>
        <input
          required
          className={inp}
          value={form.pattern}
          onChange={(e) => setForm((p) => ({ ...p, pattern: e.target.value }))}
        />
      </div>
      <div className={showSeverity ? "grid grid-cols-2 gap-3" : undefined}>
        <div>
          <label className="ut-card__label">Match</label>
          <select
            className={inp}
            value={form.match_type}
            onChange={(e) => setForm((p) => ({ ...p, match_type: e.target.value as MatchType }))}
          >
            {MATCH_TYPES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </div>
        {showSeverity && (
          <div>
            <label className="ut-card__label">Severidad</label>
            <select
              className={inp}
              value={form.severity}
              onChange={(e) => setForm((p) => ({ ...p, severity: e.target.value as Severity }))}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>
      <div>
        <label className="ut-card__label">Editor / publisher</label>
        <input
          className={inp}
          value={form.publisher}
          onChange={(e) => setForm((p) => ({ ...p, publisher: e.target.value }))}
        />
      </div>
      <div>
        <label className="ut-card__label">Notas</label>
        <input
          className={inp}
          value={form.notes}
          onChange={(e) => setForm((p) => ({ ...p, notes: e.target.value }))}
        />
      </div>
    </>
  );
}

function ModalActions({
  onClose,
  pending,
  submitLabel,
}: {
  onClose: () => void;
  pending: boolean;
  submitLabel: string;
}) {
  return (
    <div className="flex justify-end gap-2">
      <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onClose}>
        Cancelar
      </button>
      <button type="submit" disabled={pending} className="ut-btn ut-btn--sm">
        {pending ? <Loader2 size={14} className="animate-spin" /> : submitLabel}
      </button>
    </div>
  );
}

function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        className="w-full max-w-md rounded-md border border-[var(--ut-border)] bg-[var(--ut-bg-card)] p-5 shadow-xl"
        role="dialog"
        aria-labelledby="inv-gov-modal-title"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 id="inv-gov-modal-title" className="text-sm font-semibold">
            {title}
          </h2>
          <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onClose} aria-label="Cerrar">
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function SoftwareTable({
  loading,
  items,
  hostId,
  hostname,
}: {
  loading: boolean;
  items: ServerSoftware[];
  hostId: string;
  hostname: string | null;
}) {
  const qc = useQueryClient();
  const [blacklistTarget, setBlacklistTarget] = useState<ServerSoftware | null>(null);
  const [whitelistTarget, setWhitelistTarget] = useState<ServerSoftware | null>(null);

  const inval = () => {
    void qc.invalidateQueries({ queryKey: ["inventory-server-software", hostId] });
    void qc.invalidateQueries({ queryKey: ["inventory-hosts"] });
    void qc.invalidateQueries({ queryKey: ["governance-blacklist"] });
    void qc.invalidateQueries({ queryKey: ["governance-whitelist"] });
    void qc.invalidateQueries({ queryKey: ["governance-queue"] });
  };

  const quickBlMut = useMutation({
    mutationFn: (s: ServerSoftware) =>
      createBlacklist({
        software_name: s.name,
        pattern: s.name,
        match_type: "prefix",
        notes: invNotes(hostname, "blacklist"),
      }),
    onSuccess: (_d, s) => {
      toast.success(`"${s.name}" en lista negra (prefix)`);
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const quickWlMut = useMutation({
    mutationFn: (s: ServerSoftware) =>
      createWhitelist({
        software_name: s.name,
        pattern: s.name,
        match_type: "prefix",
        notes: invNotes(hostname, "whitelist"),
      }),
    onSuccess: (_d, s) => {
      toast.success(`"${s.name}" en lista blanca (prefix)`);
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const quickPending = quickBlMut.isPending || quickWlMut.isPending;

  if (loading) {
    return (
      <p className="ut-sidebar__text" style={{ padding: "1rem" }}>
        <Loader2 size={14} className="animate-spin" aria-hidden /> Cargando software…
      </p>
    );
  }
  if (items.length === 0) {
    return <p className="ut-sidebar__text" style={{ padding: "1rem" }}>Sin datos de gobernanza para este host.</p>;
  }
  return (
    <>
      <div className="ut-table-wrap" style={{ margin: "0.5rem 1rem 1rem" }}>
        <table className="ut-table">
          <thead>
            <tr>
              <th>Software</th>
              <th>Versión</th>
              <th>Origen</th>
              <th>Estado</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {items.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td>{s.version ?? "—"}</td>
                <td>{s.package_manager ?? "—"}</td>
                <td>
                  {s.is_blacklisted ? (
                    <span className="ut-metric__value--danger">Prohibido</span>
                  ) : s.is_whitelisted ? (
                    <span className="ut-metric__value--success">Aprobado</span>
                  ) : (
                    <span className="ut-sidebar__text">Sin clasificar</span>
                  )}
                </td>
                <td>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", alignItems: "center" }}>
                    {s.is_blacklisted ? (
                      <span className="ut-sidebar__text">En lista negra</span>
                    ) : (
                      <>
                        {!s.is_whitelisted && (
                          <button
                            type="button"
                            className="ut-btn ut-btn--outline ut-btn--sm"
                            title="Añadir a lista blanca"
                            disabled={quickPending}
                            onClick={() => setWhitelistTarget(s)}
                          >
                            <ShieldCheck size={14} aria-hidden /> Whitelist
                          </button>
                        )}
                        <button
                          type="button"
                          className="ut-btn ut-btn--outline ut-btn--sm"
                          title="Añadir a lista negra"
                          disabled={quickPending}
                          onClick={() => setBlacklistTarget(s)}
                        >
                          <ShieldAlert size={14} aria-hidden /> Blacklist
                        </button>
                        {!s.is_whitelisted && (
                          <button
                            type="button"
                            className="ut-btn ut-btn--outline ut-btn--sm"
                            title="Whitelist prefix (1 clic)"
                            disabled={quickPending}
                            onClick={() => quickWlMut.mutate(s)}
                          >
                            P+
                          </button>
                        )}
                        <button
                          type="button"
                          className="ut-btn ut-btn--outline ut-btn--sm"
                          title="Blacklist prefix (1 clic)"
                          disabled={quickPending}
                          onClick={() => quickBlMut.mutate(s)}
                        >
                          P−
                        </button>
                      </>
                    )}
                    {s.is_whitelisted && !s.is_blacklisted && (
                      <span className="ut-sidebar__text">Aprobado</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {blacklistTarget && (
        <BlacklistModal
          software={blacklistTarget}
          hostname={hostname}
          onClose={() => setBlacklistTarget(null)}
          onSuccess={inval}
        />
      )}
      {whitelistTarget && (
        <WhitelistModal
          software={whitelistTarget}
          hostname={hostname}
          onClose={() => setWhitelistTarget(null)}
          onSuccess={inval}
        />
      )}
    </>
  );
}

function HostSoftwareRow({ host }: { host: InventoryHost }) {
  const [open, setOpen] = useState(false);
  const swQ = useQuery({
    queryKey: ["inventory-server-software", host.id],
    queryFn: () => listHostServerSoftware(host.id),
    enabled: open,
  });

  const forbidden = swQ.data?.filter((s) => s.is_blacklisted).length ?? 0;

  return (
    <>
      <tr>
        <td>
          <button
            type="button"
            className="ut-btn ut-btn--outline ut-btn--sm"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-label={open ? "Ocultar software" : "Ver software"}
          >
            {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        </td>
        <td className="ut-table__host zbx-host">{host.hostname ?? "—"}</td>
        <td>{host.ip_address ?? "—"}</td>
        <td>
          {host.os_name ?? "—"} {host.os_version ?? ""}
        </td>
        <td>{host.software_count ?? 0}</td>
        <td>{forbidden > 0 ? <span className="ut-metric__value--danger">{forbidden}</span> : "0"}</td>
        <td>{fmtTs(host.last_report_at)}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} style={{ padding: 0, background: "rgba(0,0,0,0.2)" }}>
            <SoftwareTable
              loading={swQ.isLoading}
              items={swQ.data ?? []}
              hostId={host.id}
              hostname={host.hostname}
            />
          </td>
        </tr>
      )}
    </>
  );
}

export function InventoryPanel() {
  const hostsQ = useQuery({
    queryKey: ["inventory-hosts"],
    queryFn: listInventoryHosts,
    refetchInterval: 30_000,
  });

  const hosts = hostsQ.data ?? [];
  const totalSw = hosts.reduce((a, h) => a + (h.software_count ?? 0), 0);

  return (
    <>
      <div className="ut-toolbar" style={{ marginTop: "1rem" }}>
        <header className="ut-header" style={{ marginBottom: 0 }}>
          <h2 className="ut-header__title" style={{ fontSize: "1.1rem" }}>
            <Package size={18} style={{ display: "inline", marginRight: "0.35rem" }} aria-hidden />
            Inventario hardware / software
          </h2>
          <p className="ut-header__subtitle">
            Reportes de collector, agente NOC y SNMP. Envíe paquetes a lista blanca/negra; P+ / P− añaden regla
            prefix en un clic.
          </p>
        </header>
      </div>

      <div style={{ display: "flex", gap: "1rem", marginBottom: "1.25rem", flexWrap: "wrap" }}>
        <article className="ut-card" style={{ minWidth: "8rem" }}>
          <p className="ut-card__label">Hosts</p>
          <p className="ut-metric__value">{hosts.length}</p>
        </article>
        <article className="ut-card" style={{ minWidth: "8rem" }}>
          <p className="ut-card__label">Paquetes (último snapshot)</p>
          <p className="ut-metric__value">{totalSw}</p>
        </article>
      </div>

      <section className="ut-card">
        {hostsQ.isLoading ? (
          <p className="ut-sidebar__text">Cargando inventario…</p>
        ) : hosts.length === 0 ? (
          <p className="ut-sidebar__text">
            Sin hosts inventariados. Envíe un reporte vía <code>POST /api/inventory/report</code> o SNMP Telegraf.
          </p>
        ) : (
          <div className="ut-table-wrap">
            <table className="ut-table">
              <thead>
                <tr>
                  <th aria-label="Expandir" />
                  <th>Hostname</th>
                  <th>IP</th>
                  <th>SO</th>
                  <th>Software</th>
                  <th>Prohibidos</th>
                  <th>Último reporte</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => (
                  <HostSoftwareRow key={h.id} host={h} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
