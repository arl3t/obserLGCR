import { Link } from "react-router-dom";
import { ArrowRight, Activity, ExternalLink, Shield } from "lucide-react";
import type { NocAlert, NocDevice } from "./types";
import { NocStatusBadge } from "@/components/ui/NocStatusBadge";
import {
  alertSeverityRank,
  computeFleetSla,
  formatAgo,
  groupDevicesBySite,
} from "./uptime/helpers";
import { countLinkedNocCases, gestionCaseUrl, nocAlertCaseId } from "./nocCaseLink";

interface NocWallboardProps {
  devices: NocDevice[];
  alerts: NocAlert[];
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

function fmtTs(ts: string) {
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "short", timeStyle: "medium" });
}

function siteDotClass(offline: number, alerting: number): string {
  if (offline > 0) return "noc-site-dot noc-site-dot--down";
  if (alerting > 0) return "noc-site-dot noc-site-dot--warn";
  return "noc-site-dot noc-site-dot--ok";
}

function alertStatusLabel(status: string): { status: "online" | "offline" | "degraded"; label: string } {
  if (status === "resolved") return { status: "degraded", label: "Resuelto" };
  if (status === "ack") return { status: "degraded", label: "Ack" };
  if (status === "open") return { status: "offline", label: "Abierto" };
  return { status: "degraded", label: status };
}

export function NocWallboard({ devices, alerts }: NocWallboardProps) {
  const sla = computeFleetSla(devices);
  const online = devices.filter((d) => d.status === "online").length;
  const offline = devices.filter((d) => d.status === "offline").length;
  const openAlerts = alerts.filter((a) => a.status === "open" || a.status === "ack");
  const downOpen = openAlerts.filter((a) => a.alert_type === "down").length;
  const linkedCases = countLinkedNocCases(alerts);
  const sites = groupDevicesBySite(devices).slice(0, 6);

  const activeAlerts = [...openAlerts].sort(
    (a, b) =>
      alertSeverityRank(a.alert_type) - alertSeverityRank(b.alert_type) ||
      new Date(a.triggered_at).getTime() - new Date(b.triggered_at).getTime(),
  );

  const recentEvents = [...alerts]
    .sort((a, b) => new Date(b.triggered_at).getTime() - new Date(a.triggered_at).getTime())
    .slice(0, 12);

  return (
    <div className="noc-wallboard">
      <div className="noc-wallboard__kpis">
        <article className={`ut-card ${sla < 99 ? "noc-metric--critical" : ""}`}>
          <p className="ut-card__label">SLA activos (online)</p>
          <p className={`ut-metric__value ${sla >= 99 ? "ut-metric__value--success" : "ut-metric__value--warning"}`}>
            {sla}%
          </p>
          <p className="ut-metric__sub">{online} de {devices.length} activos</p>
        </article>
        <article className="ut-card">
          <p className="ut-card__label">Online</p>
          <p className="ut-metric__value ut-metric__value--success">{online}</p>
        </article>
        <article className={`ut-card ${offline > 0 ? "noc-metric--critical" : ""}`}>
          <p className="ut-card__label">Offline</p>
          <p className="ut-metric__value ut-metric__value--danger">{offline}</p>
        </article>
        <article className={`ut-card ${openAlerts.length > 0 ? "noc-metric--critical" : ""}`}>
          <p className="ut-card__label">Alertas activas</p>
          <p className="ut-metric__value ut-metric__value--warning">{openAlerts.length}</p>
          {downOpen > 0 && <p className="ut-metric__sub">{downOpen} caída{downOpen !== 1 ? "s" : ""}</p>}
        </article>
        <article className={`ut-card ${linkedCases > 0 ? "" : ""}`}>
          <p className="ut-card__label">Casos en gestión</p>
          <p className="ut-metric__value">{linkedCases}</p>
          <Link
            to={linkedCases > 0 ? "/gestion" : "/noc?view=alerts"}
            className="ut-table__link text-[11px]"
          >
            {linkedCases > 0 ? "Ver gestión →" : "Bandeja alertas →"}
          </Link>
        </article>
      </div>

      <div className="noc-wallboard__grid">
        <section className="ut-card">
          <div className="ut-chart-head">
            <h2 className="ut-chart-head__title">Alertas activas</h2>
            <Link to="/noc?view=alerts" className="ut-table__link text-[12px]">
              Ver todas <ArrowRight size={12} className="inline" />
            </Link>
          </div>
          {activeAlerts.length === 0 ? (
            <p className="ut-sidebar__text">Sin alertas abiertas.</p>
          ) : (
            <ul className="noc-wallboard__alert-list">
              {activeAlerts.slice(0, 8).map((a) => {
                const caseId = nocAlertCaseId(a);
                return (
                  <li key={a.id} className="noc-wallboard__alert-item">
                    <span
                      className={
                        a.alert_type === "down"
                          ? "ut-metric__value--danger"
                          : "ut-metric__value--warning"
                      }
                    >
                      {alertLabel(a.alert_type)}
                    </span>
                    <Link to={`/noc/${a.device_id}`} className="ut-notify__name">
                      {a.hostname}
                    </Link>
                    <span className="ut-notify__meta">{formatAgo(a.triggered_at)}</span>
                    <div className="noc-alert-actions">
                      {caseId ? (
                        <Link to={gestionCaseUrl(caseId)} className="ut-btn ut-btn--outline ut-btn--sm">
                          <ExternalLink size={12} aria-hidden /> Caso
                        </Link>
                      ) : a.alert_type === "down" ? (
                        <Link to={`/noc?view=alerts`} className="ut-btn ut-btn--outline ut-btn--sm">
                          <Shield size={12} aria-hidden /> Caso
                        </Link>
                      ) : null}
                      <Link to={`/noc/${a.device_id}`} className="ut-btn ut-btn--outline ut-btn--sm">
                        →
                      </Link>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        <section className="ut-card">
          <div className="ut-chart-head">
            <h2 className="ut-chart-head__title">Sitios</h2>
            <Link to="/noc?view=sites" className="ut-table__link text-[12px]">
              Ver sitios <ArrowRight size={12} className="inline" />
            </Link>
          </div>
          {sites.length === 0 ? (
            <p className="ut-sidebar__text">Sin sitios definidos.</p>
          ) : (
            <ul className="noc-wallboard__sites">
              {sites.map((s) => (
                <li key={s.site} className="noc-wallboard__site-row">
                  <span className={siteDotClass(s.offline, s.alerting)} aria-hidden />
                  <span className="ut-notify__name">{s.site}</span>
                  <span className="ut-notify__meta">
                    {s.online}/{s.total} online
                    {s.alerting > 0 ? ` · ${s.alerting} alerta${s.alerting !== 1 ? "s" : ""}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="ut-card">
        <div className="ut-chart-head">
          <h2 className="ut-chart-head__title">
            <Activity size={16} className="inline mr-1" aria-hidden />
            Eventos recientes
          </h2>
        </div>
        <div className="noc-wallboard__events">
          {recentEvents.length === 0 ? (
            <p className="ut-sidebar__text">Sin eventos registrados.</p>
          ) : (
            recentEvents.map((e) => {
              const st = alertStatusLabel(e.status);
              const caseId = nocAlertCaseId(e);
              return (
                <div key={e.id} className="ut-log-row">
                  <span className="ut-notify__meta" style={{ minWidth: "8rem" }}>
                    {fmtTs(e.triggered_at)}
                  </span>
                  <NocStatusBadge status={st.status} label={st.label} pulse={false} />
                  <span className="ut-notify__name">{e.hostname}</span>
                  <span>{alertLabel(e.alert_type)}</span>
                  {caseId && (
                    <Link to={gestionCaseUrl(caseId)} className="ut-table__link text-[11px]">
                      Caso →
                    </Link>
                  )}
                </div>
              );
            })
          )}
        </div>
      </section>
    </div>
  );
}
