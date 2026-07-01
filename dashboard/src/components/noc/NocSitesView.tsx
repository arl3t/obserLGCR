import { Link } from "react-router-dom";
import type { NocDevice } from "./types";
import { groupDevicesBySite } from "./uptime/helpers";

function siteDotClass(offline: number, alerting: number): string {
  if (offline > 0) return "noc-site-dot noc-site-dot--down";
  if (alerting > 0) return "noc-site-dot noc-site-dot--warn";
  return "noc-site-dot noc-site-dot--ok";
}

interface NocSitesViewProps {
  devices: NocDevice[];
  siteFilter: string | null;
  onSiteFilter: (site: string | null) => void;
}

export function NocSitesView({ devices, siteFilter, onSiteFilter }: NocSitesViewProps) {
  const sites = groupDevicesBySite(devices);

  if (siteFilter) {
    const filtered = devices.filter((d) => (d.site?.trim() || "Sin sitio") === siteFilter);
    return (
      <section className="ut-card">
        <div className="ut-chart-head">
          <button type="button" className="ut-header__back" onClick={() => onSiteFilter(null)}>
            ← Todos los sitios
          </button>
          <h2 className="ut-chart-head__title">{siteFilter}</h2>
          <span className="ut-chart-head__range">{filtered.length} activos</span>
        </div>
        <div className="noc-sites__device-list">
          {filtered.map((d) => (
            <Link key={d.id} to={`/noc/${d.id}`} className="noc-sites__device-card">
              <span
                className={
                  d.status === "offline"
                    ? "noc-site-dot noc-site-dot--down"
                    : (d.open_alerts ?? 0) > 0
                      ? "noc-site-dot noc-site-dot--warn"
                      : "noc-site-dot noc-site-dot--ok"
                }
              />
              <div>
                <p className="ut-notify__name">{d.hostname}</p>
                <p className="ut-notify__meta">
                  {[d.ip_address?.replace(/\/32$/, ""), d.device_type, d.status].filter(Boolean).join(" · ")}
                </p>
              </div>
            </Link>
          ))}
        </div>
      </section>
    );
  }

  return (
    <div className="noc-sites__grid">
      {sites.length === 0 ? (
        <section className="ut-card">
          <p className="ut-sidebar__text">Sin sitios definidos. Asigne un sitio al registrar dispositivos.</p>
        </section>
      ) : (
        sites.map((s) => (
          <button
            key={s.site}
            type="button"
            className={`ut-card noc-sites__card ${s.alerting > 0 ? "noc-metric--critical" : ""}`}
            onClick={() => onSiteFilter(s.site)}
          >
            <div className="noc-sites__card-head">
              <span className={siteDotClass(s.offline, s.alerting)} />
              <h3 className="ut-chart-head__title">{s.site}</h3>
            </div>
            <div className="noc-sites__stats">
              <div>
                <p className="ut-card__label">Activos</p>
                <p className="ut-metric__value">{s.total}</p>
              </div>
              <div>
                <p className="ut-card__label">Online</p>
                <p className="ut-metric__value ut-metric__value--success">{s.online}</p>
              </div>
              <div>
                <p className="ut-card__label">Offline</p>
                <p className={`ut-metric__value ${s.offline > 0 ? "ut-metric__value--danger" : ""}`}>
                  {s.offline}
                </p>
              </div>
              <div>
                <p className="ut-card__label">Alertas</p>
                <p className={`ut-metric__value ${s.alerting > 0 ? "ut-metric__value--warning" : ""}`}>
                  {s.alerting}
                </p>
              </div>
            </div>
          </button>
        ))
      )}
    </div>
  );
}
