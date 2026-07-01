import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Check, ChevronDown, Play, Shield } from "lucide-react";
import { toast } from "sonner";
import { authFetch } from "@/lib/auth-fetch";
import { ackNocAlert, openIncidentFromNocAlert } from "@/api/noc";
import type { NocAlert } from "./types";
import { gestionCaseUrl, nocAlertCaseId } from "./nocCaseLink";

interface Device {
  id: string;
  hostname: string;
}

interface Log {
  id: string;
  ts: string;
  severity: string;
  message: string;
}

interface Action {
  id: string;
  action_type: string;
  status: string;
  output: string | null;
  requested_at: string;
}

interface DeviceOperationsPanelProps {
  device: Device;
  logs: Log[];
  alerts: NocAlert[];
  actions: Action[];
  onChanged: () => void;
}

function fmtTs(ts: string) {
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "short", timeStyle: "medium" });
}

function alertTypeLabel(t: string) {
  const m: Record<string, string> = {
    down: "Caída",
    high_cpu: "CPU alta",
    high_mem: "Memoria alta",
    high_rtt: "Latencia alta",
  };
  return m[t] ?? t;
}

export function DeviceOperationsPanel({
  device,
  logs,
  alerts,
  actions,
  onChanged,
}: DeviceOperationsPanelProps) {
  const [actionType, setActionType] = useState("ping");
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  async function handleAck(id: string) {
    try {
      await ackNocAlert(id);
      toast.success("Alerta reconocida");
      onChanged();
    } catch {
      toast.error("Error al reconocer alerta");
    }
  }

  async function handleResolve(id: string) {
    await authFetch(`/api/noc/alerts/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "resolve" }),
    });
    onChanged();
  }

  async function handleOpenIncident(alert: NocAlert) {
    const existing = nocAlertCaseId(alert);
    if (existing) {
      window.location.href = gestionCaseUrl(existing);
      return;
    }
    try {
      const result = await openIncidentFromNocAlert(alert.id);
      if (result.caseId) {
        toast.success(`Caso abierto en gestión`, {
          action: {
            label: "Ver caso",
            onClick: () => {
              window.location.href = gestionCaseUrl(result.caseId!);
            },
          },
        });
      } else if (result.outcome === "already_linked" || result.outcome === "linked_existing") {
        toast.info("Caso ya vinculado");
      } else {
        toast.success("Incidente registrado");
      }
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "No se pudo abrir el caso");
    }
  }

  async function submitAction(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    const payload: Record<string, unknown> = {};
    if (target.trim()) payload.target = target.trim();
    const res = await authFetch("/api/noc/actions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: device.id, action_type: actionType, payload }),
    });
    setSubmitting(false);
    if (res.ok) {
      setTarget("");
      onChanged();
    }
  }

  return (
    <div className="space-y-4">
      <section>
        <div className="ut-chart-head">
          <h3 className="ut-chart-head__title">Alertas</h3>
          <Link to="/gestion" className="ut-table__link text-[12px]">
            Gestión de incidentes →
          </Link>
        </div>
        {alerts.length === 0 ? (
          <p className="ut-sidebar__text">Sin alertas.</p>
        ) : (
          alerts.map((a) => {
            const caseId = nocAlertCaseId(a);
            return (
            <div
              key={a.id}
              className={`ut-log-row ${a.status === "open" ? "noc-row--alerting" : ""}`}
              style={{ justifyContent: "space-between", flexWrap: "wrap", gap: "0.5rem" }}
            >
              <span>
                <strong className={a.status === "open" ? "ut-metric__value--danger" : ""}>
                  {alertTypeLabel(a.alert_type)}
                </strong>
                {" · "}
                <span className="ut-notify__meta">
                  {a.status}
                  {a.ack_by ? ` · ack ${a.ack_by}` : ""} · {fmtTs(a.triggered_at)}
                  {caseId ? ` · caso ${caseId.slice(0, 8)}…` : ""}
                </span>
              </span>
              <div className="noc-alert-actions">
                {caseId && (
                  <Link to={gestionCaseUrl(caseId)} className="ut-btn ut-btn--outline ut-btn--sm">
                    Ver caso
                  </Link>
                )}
                {a.status === "open" && (
                  <button
                    type="button"
                    className="ut-btn ut-btn--outline ut-btn--sm"
                    onClick={() => void handleAck(a.id)}
                  >
                    Ack
                  </button>
                )}
                {(a.status === "open" || a.status === "ack") && a.alert_type === "down" && (
                  <button
                    type="button"
                    className="ut-btn ut-btn--outline ut-btn--sm"
                    onClick={() => void handleOpenIncident(a)}
                  >
                    <Shield size={12} aria-hidden /> {caseId ? "Ver caso" : "Caso"}
                  </button>
                )}
                {(a.status === "open" || a.status === "ack") && (
                  <button
                    type="button"
                    className="ut-btn ut-btn--sm"
                    onClick={() => void handleResolve(a.id)}
                  >
                    <Check size={12} aria-hidden /> Resolver
                  </button>
                )}
              </div>
            </div>
            );
          })
        )}
      </section>

      <section>
        <h3 className="ut-chart-head__title" style={{ marginBottom: "0.5rem" }}>
          Logs
        </h3>
        <div style={{ maxHeight: "240px", overflowY: "auto" }}>
          {logs.length === 0 ? (
            <p className="ut-sidebar__text">Sin logs.</p>
          ) : (
            logs.map((l) => (
              <div key={l.id} className="ut-log-row">
                <span className="ut-notify__meta" style={{ minWidth: "7rem" }}>
                  {fmtTs(l.ts)}
                </span>
                <span className={l.severity === "error" ? "ut-metric__value--danger" : ""}>
                  {l.severity}
                </span>
                <span>{l.message}</span>
              </div>
            ))
          )}
        </div>
      </section>

      <section>
        <h3 className="ut-chart-head__title" style={{ marginBottom: "0.5rem" }}>
          Acciones remotas
        </h3>
        <form onSubmit={submitAction} className="flex flex-wrap gap-2 items-end">
          <div>
            <label className="ut-card__label">Acción</label>
            <select
              value={actionType}
              onChange={(e) => setActionType(e.target.value)}
              className="ut-input"
            >
              <option value="ping">Ping</option>
              <option value="traceroute">Traceroute</option>
              <option value="reboot">Reboot</option>
            </select>
          </div>
          <div style={{ flex: 1, minWidth: "10rem" }}>
            <label className="ut-card__label">Destino</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="8.8.8.8"
              className="ut-input"
            />
          </div>
          <button type="submit" disabled={submitting} className="ut-btn ut-btn--sm">
            <Play size={12} aria-hidden /> {submitting ? "…" : "Ejecutar"}
          </button>
        </form>
        {actions.map((a) => (
          <div key={a.id}>
            <button
              type="button"
              className="ut-log-row w-full text-left"
              onClick={() => setExpanded((p) => (p === a.id ? null : a.id))}
            >
              <span className="ut-notify__name">{a.action_type}</span>
              <span className="ut-notify__meta">{a.status}</span>
              <span className="ut-notify__meta" style={{ marginLeft: "auto" }}>
                {fmtTs(a.requested_at)}
              </span>
              <ChevronDown size={12} className={expanded === a.id ? "rotate-180" : ""} />
            </button>
            {expanded === a.id && a.output && (
              <pre className="mt-1 overflow-x-auto rounded bg-black/40 p-2 text-[11px] text-emerald-400">
                {a.output}
              </pre>
            )}
          </div>
        ))}
      </section>
    </div>
  );
}
