import { Link } from "react-router-dom";
import { Check, ExternalLink, Shield } from "lucide-react";
import { toast } from "sonner";
import type { NocAlert } from "./types";
import { ackNocAlert, openIncidentFromNocAlert, resolveNocAlert } from "@/api/noc";
import { alertSeverityRank, formatAgo } from "./uptime/helpers";
import { gestionCaseUrl, nocAlertCaseId } from "./nocCaseLink";

interface NocFleetAlertsProps {
  alerts: NocAlert[];
  onChanged: () => void;
}

function alertLabel(type: string): string {
  const m: Record<string, string> = {
    down: "Caída",
    high_cpu: "CPU alta",
    high_mem: "Memoria alta",
    high_rtt: "Latencia alta",
  };
  return m[type] ?? type;
}

function severityClass(type: string): string {
  if (type === "down") return "ut-metric__value--danger";
  if (type === "high_cpu" || type === "high_mem") return "ut-metric__value--warning";
  return "";
}

export function NocFleetAlerts({ alerts, onChanged }: NocFleetAlertsProps) {
  const sorted = [...alerts].sort(
    (a, b) =>
      (a.status === "open" ? 0 : a.status === "ack" ? 1 : 2) -
        (b.status === "open" ? 0 : b.status === "ack" ? 1 : 2) ||
      alertSeverityRank(a.alert_type) - alertSeverityRank(b.alert_type) ||
      new Date(b.triggered_at).getTime() - new Date(a.triggered_at).getTime(),
  );

  const openCount = alerts.filter((a) => a.status === "open" || a.status === "ack").length;

  async function handleAck(id: string) {
    try {
      await ackNocAlert(id);
      toast.success("Alerta reconocida");
      onChanged();
    } catch {
      toast.error("No se pudo reconocer la alerta");
    }
  }

  async function handleResolve(id: string) {
    try {
      await resolveNocAlert(id);
      toast.success("Alerta resuelta");
      onChanged();
    } catch {
      toast.error("No se pudo resolver la alerta");
    }
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
        toast.info("Caso ya vinculado a esta alerta");
      } else {
        toast.success("Incidente registrado en gestión");
      }
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "No se pudo abrir el caso");
    }
  }

  return (
    <section className="ut-card" aria-labelledby="noc-alerts-inbox">
      <div className="ut-chart-head">
        <h2 id="noc-alerts-inbox" className="ut-chart-head__title">
          Bandeja de alertas
        </h2>
        <span className="ut-chart-head__range">
          {openCount} activa{openCount !== 1 ? "s" : ""} · {alerts.length} total
        </span>
      </div>

      <div className="ut-table-wrap">
        <table className="ut-table">
          <thead>
            <tr>
              <th>Severidad</th>
              <th>Activo</th>
              <th>IP</th>
              <th>Estado</th>
              <th>Caso</th>
              <th>Desde</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: "2rem" }}>
                  Sin alertas registradas
                </td>
              </tr>
            ) : (
              sorted.map((a) => {
                const caseId = nocAlertCaseId(a);
                return (
                  <tr
                    key={a.id}
                    className={
                      (a.status === "open" || a.status === "ack") && a.alert_type === "down"
                        ? "noc-row--alerting"
                        : undefined
                    }
                  >
                    <td>
                      <strong className={severityClass(a.alert_type)}>{alertLabel(a.alert_type)}</strong>
                    </td>
                    <td className="ut-table__host">
                      <Link to={`/noc/${a.device_id}`} className="ut-table__link">
                        {a.hostname}
                      </Link>
                    </td>
                    <td>{a.ip_address?.replace(/\/32$/, "") ?? "—"}</td>
                    <td>
                      <span className={a.status === "open" ? "ut-metric__value--warning" : ""}>
                        {a.status}
                      </span>
                    </td>
                    <td>
                      {caseId ? (
                        <Link to={gestionCaseUrl(caseId)} className="ut-table__link font-mono text-[11px]">
                          {caseId.slice(0, 8)}…
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>{formatAgo(a.triggered_at)}</td>
                    <td>
                      <div className="noc-alert-actions">
                        {(a.status === "open" || a.status === "ack") && (
                          <>
                            {a.status === "open" && (
                              <button
                                type="button"
                                className="ut-btn ut-btn--outline ut-btn--sm"
                                onClick={() => void handleAck(a.id)}
                              >
                                Ack
                              </button>
                            )}
                            {a.alert_type === "down" && (
                              <button
                                type="button"
                                className="ut-btn ut-btn--outline ut-btn--sm"
                                onClick={() => void handleOpenIncident(a)}
                                title={caseId ? "Ver caso en gestión" : "Abrir caso en gestión de incidentes"}
                              >
                                <Shield size={12} aria-hidden /> {caseId ? "Ver caso" : "Caso"}
                              </button>
                            )}
                            <button
                              type="button"
                              className="ut-btn ut-btn--sm"
                              onClick={() => void handleResolve(a.id)}
                            >
                              <Check size={12} aria-hidden /> Resolver
                            </button>
                          </>
                        )}
                        <Link to={`/noc/${a.device_id}`} className="ut-btn ut-btn--outline ut-btn--sm">
                          <ExternalLink size={12} aria-hidden />
                        </Link>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
