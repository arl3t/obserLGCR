import { Link, useSearchParams } from "react-router-dom";
import { LayoutDashboard, MapPin, Radio, Settings, Table2 } from "lucide-react";
import type { NocHubView } from "./types";

const VIEWS: { id: NocHubView; label: string; icon: typeof Radio }[] = [
  { id: "activos", label: "Activos", icon: Table2 },
  { id: "wallboard", label: "Wallboard", icon: LayoutDashboard },
  { id: "alerts", label: "Alertas", icon: Radio },
  { id: "sites", label: "Sitios", icon: MapPin },
];

interface NocHubNavProps {
  openAlerts: number;
}

export function NocHubNav({ openAlerts }: NocHubNavProps) {
  const [params, setParams] = useSearchParams();
  const raw = params.get("view");
  const view: NocHubView =
    raw === "activos" || raw === "fleet" || raw === "alerts" || raw === "sites" || raw === "wallboard"
      ? raw === "fleet"
        ? "activos"
        : (raw as NocHubView)
      : "activos";

  return (
    <nav className="noc-hub-nav" aria-label="Vistas del centro NOC">
      <div className="noc-hub-nav__tabs">
        {VIEWS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            className={`noc-hub-nav__tab ${view === id ? "noc-hub-nav__tab--active" : ""}`}
            onClick={() => {
              const next = new URLSearchParams(params);
              next.set("view", id);
              setParams(next, { replace: true });
            }}
          >
            <Icon size={14} aria-hidden />
            {label}
            {id === "alerts" && openAlerts > 0 && (
              <span className="noc-hub-nav__badge">{openAlerts}</span>
            )}
          </button>
        ))}
      </div>
      <Link to="/noc/config" className="noc-hub-nav__config">
        <Settings size={14} aria-hidden />
        Configuración
      </Link>
    </nav>
  );
}

export function useNocHubView(): NocHubView {
  const [params] = useSearchParams();
  const raw = params.get("view");
  if (!raw || raw === "activos" || raw === "fleet") return "activos";
  if (raw === "alerts" || raw === "sites" || raw === "wallboard") return raw;
  return "activos";
}
