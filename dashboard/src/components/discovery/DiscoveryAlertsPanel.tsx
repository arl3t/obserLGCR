import { AlertTriangle, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import type { AlertSeverity, DiscoveryAlerts } from "@/api/discovery";

type Props = {
  alerts: DiscoveryAlerts | undefined;
  loading: boolean;
};

const SEVERITY_ORDER: AlertSeverity[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL: Record<AlertSeverity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
};

export function DiscoveryAlertsPanel({ alerts, loading }: Props) {
  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!alerts) {
    return <p className="py-8 text-center text-sm text-muted-foreground">Seleccione un escaneo completado.</p>;
  }

  if (alerts.total === 0) {
    return (
      <div className="discovery-alerts__ok">
        <ShieldCheck className="h-8 w-8 text-emerald-400" />
        <p className="text-sm font-medium">Sin puertos críticos expuestos</p>
        <p className="text-[11px] text-muted-foreground">
          No se detectaron servicios sensibles (RDP, SMB, Telnet, SNMP…) en los hosts activos.
        </p>
      </div>
    );
  }

  return (
    <div className="discovery-alerts">
      <div className="discovery-alerts__header">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-red-400" />
          <div>
            <h3 className="text-sm font-semibold">Alertas de puertos críticos</h3>
            <p className="text-[11px] text-muted-foreground">
              {alerts.total} exposiciones detectadas · servicios de alto riesgo accesibles en red
            </p>
          </div>
        </div>
        <div className="discovery-alerts__severity-chips">
          {SEVERITY_ORDER.map((sev) =>
            alerts.by_severity[sev] ? (
              <span key={sev} className={`discovery-alert-chip discovery-alert-chip--${sev}`}>
                {alerts.by_severity[sev]} {SEVERITY_LABEL[sev]}
              </span>
            ) : null,
          )}
        </div>
      </div>

      <div className="discovery-alerts__monitored">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Puertos monitorizados:</span>
        {Object.entries(alerts.critical_ports).map(([port, label]) => (
          <code key={port} className="discovery-alert-port-tag">{port} {label}</code>
        ))}
      </div>

      <div className="discovery-alerts__table">
        <div className="discovery-alerts__row discovery-alerts__row--head">
          <span>Severidad</span>
          <span>Host</span>
          <span>Puerto</span>
          <span>Servicio</span>
          <span>Estado</span>
        </div>
        {alerts.alerts.map((a, i) => (
          <div key={`${a.ip}-${a.port}-${i}`} className={`discovery-alerts__row discovery-alerts__row--${a.severity}`}>
            <span className={`discovery-alert-chip discovery-alert-chip--${a.severity}`}>
              {a.severity === "critical" && <AlertTriangle className="h-3 w-3" />}
              {SEVERITY_LABEL[a.severity]}
            </span>
            <span>
              <code className="text-[12px] text-cyan-300">{a.ip}</code>
              {a.hostname && <span className="ml-1.5 text-[10px] text-muted-foreground">{a.hostname}</span>}
            </span>
            <code className="text-[12px]">{a.port}</code>
            <span className="text-[11px]">
              {a.service}
              {a.product && <span className="ml-1 text-muted-foreground">{a.product}</span>}
            </span>
            <span className="text-[10px]">
              {a.documented ? (
                <span className="text-emerald-400/80">documentado</span>
              ) : (
                <span className="text-amber-400">sin documentar</span>
              )}
              {a.noc_open_alerts > 0 && <span className="ml-1 text-red-400">· {a.noc_open_alerts} NOC</span>}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
