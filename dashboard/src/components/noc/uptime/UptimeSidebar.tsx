import type { NocAlert, NocDevice } from "../types";

interface UptimeSidebarProps {
  devices: NocDevice[];
  alerts: NocAlert[];
  onRefresh?: () => void;
  refreshing?: boolean;
  showAgentCta?: boolean;
}

export function UptimeSidebar({
  devices,
  alerts,
  onRefresh,
  refreshing,
  showAgentCta = true,
}: UptimeSidebarProps) {
  const sites = [...new Set(devices.map((d) => d.site).filter(Boolean))] as string[];
  const primarySite = sites[0] ?? "default";
  const offlineCount = devices.filter((d) => d.status === "offline").length;
  const dotClass =
    offlineCount === 0
      ? "ut-map__dot"
      : offlineCount === devices.length
        ? "ut-map__dot ut-map__dot--down"
        : "ut-map__dot ut-map__dot--warn";

  const openAlerts = alerts.filter((a) => a.status === "open");

  return (
    <aside className="ut-sidebar" aria-label="Panel lateral">
      {showAgentCta && (
        <article className="ut-card ut-premium">
          <h2 className="ut-sidebar__title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
            </svg>
            Agente NOC
          </h2>
          <p className="ut-sidebar__text">
            Instala el agente en cada activo para heartbeats cada 5 min, métricas CPU/MEM/RTT y acciones remotas.
          </p>
          <a href="#noc-agents" className="ut-btn">
            Ver instalación
          </a>
        </article>
      )}

      <article className="ut-card">
        <h2 className="ut-sidebar__title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <circle cx="12" cy="12" r="3" />
            <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
          </svg>
          Sincronización
        </h2>
        <p className="ut-sidebar__text">
          Watcher de heartbeat cada 30 s. Los dispositivos sin señal generan alerta <strong>down</strong> e incidente en Gestión.
        </p>
        {onRefresh && (
          <button
            type="button"
            className="ut-btn ut-btn--outline"
            onClick={onRefresh}
            disabled={refreshing}
          >
            {refreshing ? "Actualizando…" : "Actualizar ahora"}
          </button>
        )}
      </article>

      <article className="ut-card">
        <h2 className="ut-sidebar__title">Regions</h2>
        <div
          className="ut-map"
          role="img"
          aria-label={`Sitio ${primarySite}: ${offlineCount === 0 ? "todos operativos" : `${offlineCount} fuera de línea`}`}
        >
          <span className={dotClass} style={{ color: offlineCount === 0 ? "#4ade80" : offlineCount === devices.length ? "#f87171" : "#ffb300" }} aria-hidden="true" />
          <p className="ut-map__caption">
            {primarySite} · {devices.length} activo{devices.length !== 1 ? "s" : ""}
          </p>
        </div>
        {sites.length > 1 && (
          <p className="ut-sidebar__text" style={{ marginTop: "0.5rem" }}>
            Sitios: {sites.join(", ")}
          </p>
        )}
      </article>

      <article className="ut-card">
        <h2 className="ut-sidebar__title">Notificaciones</h2>
        <p className="ut-sidebar__text">Alertas activas en la flota:</p>
        <ul className="ut-notify">
          {openAlerts.length === 0 ? (
            <li className="ut-notify__item">
              <span>
                <span className="ut-notify__name">Sin alertas abiertas</span>
                <span className="ut-notify__meta">Todos los chequeos OK</span>
              </span>
            </li>
          ) : (
            openAlerts.slice(0, 5).map((a) => (
              <li key={a.id} className="ut-notify__item">
                <span aria-hidden="true">⚠</span>
                <span>
                  <span className="ut-notify__name">{a.hostname}</span>
                  <span className="ut-notify__meta">
                    {a.alert_type} · {new Date(a.triggered_at).toLocaleString("es-PY")}
                  </span>
                </span>
              </li>
            ))
          )}
        </ul>
      </article>
    </aside>
  );
}
