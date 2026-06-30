import { Link } from "react-router-dom";
import { Activity, ArrowRight, Radio } from "lucide-react";

export function DetectionObservabilityFooter() {
  return (
    <footer className="detection-footer mx-6 mb-6 mt-2 rounded-xl px-4 py-4 sm:px-5">
      <div className="max-w-3xl space-y-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400/90">
          Observabilidad de logs de seguridad
        </p>
        <h2 className="text-sm font-semibold text-foreground sm:text-base">
          Centraliza alertas de sensores antes del análisis SOC
        </h2>
        <p className="text-[13px] leading-relaxed text-muted-foreground">
          Este módulo <strong className="font-medium text-foreground">recibe y explora</strong> eventos
          ingeridos por el shipper (Wazuh, Suricata, Fortigate, OPNsense, PMG, syslog). No abre casos
          automáticamente: el operador investiga aquí y, si procede, crea un incidente en{" "}
          <Link to="/gestion" className="text-amber-400/90 hover:underline">
            Gestión
          </Link>
          .
        </p>
        <div className="detection-pipeline pt-1">
          <span className="detection-pipeline__step">
            <Radio className="h-3 w-3" /> Sensores / logs
          </span>
          <span className="detection-pipeline__arrow">→</span>
          <span className="detection-pipeline__step">
            <Activity className="h-3 w-3" /> Shipper
          </span>
          <span className="detection-pipeline__arrow">→</span>
          <span className="detection-pipeline__step">PostgreSQL · detection_events</span>
          <span className="detection-pipeline__arrow">→</span>
          <span className="detection-pipeline__step">Explorador + KPIs</span>
        </div>
        <Link
          to="/gestion"
          className="inline-flex items-center gap-0.5 pt-1 text-[11px] text-amber-400/90 hover:underline"
        >
          Ir a Gestión SOC <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
    </footer>
  );
}
