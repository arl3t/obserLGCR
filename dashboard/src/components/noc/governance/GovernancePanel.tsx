import { FormEvent, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Loader2, Plus, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  createBlacklist,
  createWhitelist,
  deleteBlacklist,
  deleteWhitelist,
  getGovernanceConfig,
  listBlacklist,
  listIncidentsQueue,
  listWhitelist,
  updateGovernanceConfig,
  type MatchType,
  type Severity,
} from "@/api/inventory";

const MATCH_TYPES: MatchType[] = ["exact", "prefix", "suffix", "regex", "cpe"];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

function fmtTs(ts: string) {
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "short", timeStyle: "short" });
}

export function GovernancePanel({ embedded = false }: { embedded?: boolean }) {
  const qc = useQueryClient();
  const [showBl, setShowBl] = useState(false);
  const [showWl, setShowWl] = useState(false);
  const [blForm, setBlForm] = useState({
    software_name: "",
    pattern: "",
    match_type: "prefix" as MatchType,
    severity: "HIGH" as Severity,
    notes: "",
  });
  const [wlForm, setWlForm] = useState({
    software_name: "",
    pattern: "",
    match_type: "exact" as MatchType,
  });

  const inval = () => {
    void qc.invalidateQueries({ queryKey: ["governance-blacklist"] });
    void qc.invalidateQueries({ queryKey: ["governance-whitelist"] });
    void qc.invalidateQueries({ queryKey: ["governance-queue"] });
    void qc.invalidateQueries({ queryKey: ["governance-config"] });
    void qc.invalidateQueries({ queryKey: ["inventory-hosts"] });
  };

  const blQ = useQuery({ queryKey: ["governance-blacklist"], queryFn: listBlacklist });
  const wlQ = useQuery({ queryKey: ["governance-whitelist"], queryFn: listWhitelist });
  const cfgQ = useQuery({ queryKey: ["governance-config"], queryFn: getGovernanceConfig });
  const queueQ = useQuery({
    queryKey: ["governance-queue"],
    queryFn: () => listIncidentsQueue("pending"),
    refetchInterval: 15_000,
  });

  const cfgMut = useMutation({
    mutationFn: (strict: boolean) => updateGovernanceConfig(strict),
    onSuccess: () => {
      toast.success("Configuración actualizada");
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const createBlMut = useMutation({
    mutationFn: () => createBlacklist(blForm),
    onSuccess: () => {
      toast.success("Regla añadida a lista negra");
      setShowBl(false);
      setBlForm({ software_name: "", pattern: "", match_type: "prefix", severity: "HIGH", notes: "" });
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const createWlMut = useMutation({
    mutationFn: () => createWhitelist(wlForm),
    onSuccess: () => {
      toast.success("Regla añadida a lista blanca");
      setShowWl(false);
      setWlForm({ software_name: "", pattern: "", match_type: "exact" });
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const deleteBlMut = useMutation({
    mutationFn: deleteBlacklist,
    onSuccess: () => {
      toast.success("Regla eliminada");
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const deleteWlMut = useMutation({
    mutationFn: deleteWhitelist,
    onSuccess: () => {
      toast.success("Regla eliminada");
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  function submitBl(e: FormEvent) {
    e.preventDefault();
    if (!blForm.software_name.trim() || !blForm.pattern.trim()) return;
    createBlMut.mutate();
  }

  function submitWl(e: FormEvent) {
    e.preventDefault();
    if (!wlForm.software_name.trim() || !wlForm.pattern.trim()) return;
    createWlMut.mutate();
  }

  const inp = "ut-input";

  return (
    <>
      {!embedded && (
      <div className="ut-toolbar" style={{ marginTop: "1rem" }}>
        <header className="ut-header" style={{ marginBottom: 0 }}>
          <h2 className="ut-header__title" style={{ fontSize: "1.1rem" }}>
            <ShieldAlert size={18} style={{ display: "inline", marginRight: "0.35rem" }} aria-hidden />
            Gobernanza de software
          </h2>
          <p className="ut-header__subtitle">
            Listas blanca/negra · detección automática → cola de incidentes → Gestión
          </p>
        </header>
      </div>
      )}

      <section className="ut-card" style={{ marginBottom: "1.25rem" }}>
        <label className="flex cursor-pointer items-center gap-3">
          <input
            type="checkbox"
            checked={cfgQ.data?.strict_whitelist ?? false}
            disabled={cfgMut.isPending || cfgQ.isLoading}
            onChange={(e) => cfgMut.mutate(e.target.checked)}
          />
          <span>
            <strong>Whitelist estricta</strong> — software no listado genera incidente{" "}
            <code>unapproved_software</code>
          </span>
        </label>
      </section>

      {(queueQ.data?.length ?? 0) > 0 && (
        <section className="ut-card" style={{ marginBottom: "1.25rem" }}>
          <h3 className="ut-chart-head__title">Cola pendiente ({queueQ.data?.length})</h3>
          <div className="ut-table-wrap">
            <table className="ut-table">
              <thead>
                <tr>
                  <th>Tipo</th>
                  <th>Host</th>
                  <th>Severidad</th>
                  <th>Software</th>
                  <th>Creado</th>
                </tr>
              </thead>
              <tbody>
                {queueQ.data?.map((q) => (
                  <tr key={q.id}>
                    <td>{q.incident_type}</td>
                    <td className="ut-table__host">{q.hostname}</td>
                    <td>
                      <span className="ut-metric__value--danger">{q.severity}</span>
                    </td>
                    <td>{String(q.payload?.software_name ?? q.payload?.pattern ?? "—")}</td>
                    <td>{fmtTs(q.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
        {/* Lista negra */}
        <section className="ut-card">
          <div className="ut-chart-head">
            <h3 className="ut-chart-head__title">
              <ShieldAlert size={16} aria-hidden /> Lista negra
            </h3>
            <button type="button" className="ut-btn ut-btn--sm" onClick={() => setShowBl(true)}>
              <Plus size={14} aria-hidden /> Añadir
            </button>
          </div>
          {blQ.isLoading ? (
            <p className="ut-sidebar__text">Cargando…</p>
          ) : (blQ.data?.length ?? 0) === 0 ? (
            <p className="ut-sidebar__text">Sin reglas. Ejemplo lab: TeamViewer, AnyDesk.</p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {blQ.data?.map((r) => (
                <li
                  key={r.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    gap: "0.5rem",
                    padding: "0.5rem 0",
                    borderBottom: "1px solid var(--ut-border-subtle, #333)",
                  }}
                >
                  <div>
                    <strong>{r.software_name}</strong>
                    <br />
                    <span className="ut-sidebar__text">
                      {r.match_type} · <code>{r.pattern}</code> · {r.severity}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="ut-btn ut-btn--outline ut-btn--sm"
                    title="Eliminar regla"
                    onClick={() => {
                      if (window.confirm(`¿Eliminar regla "${r.software_name}"?`)) {
                        deleteBlMut.mutate(r.id);
                      }
                    }}
                  >
                    <Trash2 size={14} aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Lista blanca */}
        <section className="ut-card">
          <div className="ut-chart-head">
            <h3 className="ut-chart-head__title">
              <ShieldCheck size={16} aria-hidden /> Lista blanca
            </h3>
            <button type="button" className="ut-btn ut-btn--sm" onClick={() => setShowWl(true)}>
              <Plus size={14} aria-hidden /> Añadir
            </button>
          </div>
          {wlQ.isLoading ? (
            <p className="ut-sidebar__text">Cargando…</p>
          ) : (wlQ.data?.length ?? 0) === 0 ? (
            <p className="ut-sidebar__text">Opcional. Software explícitamente autorizado.</p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {wlQ.data?.map((r) => (
                <li
                  key={r.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "0.5rem 0",
                    borderBottom: "1px solid var(--ut-border-subtle, #333)",
                  }}
                >
                  <span>
                    <strong>{r.software_name}</strong> — {r.match_type}: <code>{r.pattern}</code>
                  </span>
                  <button
                    type="button"
                    className="ut-btn ut-btn--outline ut-btn--sm"
                    onClick={() => {
                      if (window.confirm(`¿Eliminar "${r.software_name}"?`)) {
                        deleteWlMut.mutate(r.id);
                      }
                    }}
                  >
                    <Trash2 size={14} aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {showBl && (
        <Modal title="Nueva regla — lista negra" onClose={() => setShowBl(false)}>
          <form onSubmit={submitBl} className="space-y-3">
            <div>
              <label className="ut-card__label">Nombre *</label>
              <input
                required
                className={inp}
                value={blForm.software_name}
                onChange={(e) => setBlForm((p) => ({ ...p, software_name: e.target.value }))}
              />
            </div>
            <div>
              <label className="ut-card__label">Patrón *</label>
              <input
                required
                className={inp}
                placeholder="teamviewer"
                value={blForm.pattern}
                onChange={(e) => setBlForm((p) => ({ ...p, pattern: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="ut-card__label">Match</label>
                <select
                  className={inp}
                  value={blForm.match_type}
                  onChange={(e) => setBlForm((p) => ({ ...p, match_type: e.target.value as MatchType }))}
                >
                  {MATCH_TYPES.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="ut-card__label">Severidad</label>
                <select
                  className={inp}
                  value={blForm.severity}
                  onChange={(e) => setBlForm((p) => ({ ...p, severity: e.target.value as Severity }))}
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={() => setShowBl(false)}>
                Cancelar
              </button>
              <button type="submit" disabled={createBlMut.isPending} className="ut-btn ut-btn--sm">
                {createBlMut.isPending ? <Loader2 size={14} className="animate-spin" /> : "Guardar"}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {showWl && (
        <Modal title="Nueva regla — lista blanca" onClose={() => setShowWl(false)}>
          <form onSubmit={submitWl} className="space-y-3">
            <div>
              <label className="ut-card__label">Nombre *</label>
              <input
                required
                className={inp}
                value={wlForm.software_name}
                onChange={(e) => setWlForm((p) => ({ ...p, software_name: e.target.value }))}
              />
            </div>
            <div>
              <label className="ut-card__label">Patrón *</label>
              <input
                required
                className={inp}
                value={wlForm.pattern}
                onChange={(e) => setWlForm((p) => ({ ...p, pattern: e.target.value }))}
              />
            </div>
            <div>
              <label className="ut-card__label">Match</label>
              <select
                className={inp}
                value={wlForm.match_type}
                onChange={(e) => setWlForm((p) => ({ ...p, match_type: e.target.value as MatchType }))}
              >
                {MATCH_TYPES.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={() => setShowWl(false)}>
                Cancelar
              </button>
              <button type="submit" disabled={createWlMut.isPending} className="ut-btn ut-btn--sm">
                Guardar
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
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
        aria-labelledby="gov-modal-title"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 id="gov-modal-title" className="text-sm font-semibold">{title}</h2>
          <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={onClose} aria-label="Cerrar">
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
