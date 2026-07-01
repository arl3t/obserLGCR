/**
 * Panel de investigación para casos originados en gobernanza NOC
 * (software prohibido, activo sin ACK, host desconocido).
 */
import { Link } from "react-router-dom";
import { AlertTriangle, ExternalLink, Package, Server } from "lucide-react";
import type { SocCase } from "./types";
import { C, alpha } from "@/lib/cm-theme";

const INCIDENT_LABEL: Record<string, string> = {
  forbidden_software: "Software prohibido",
  unapproved_software: "Software no aprobado",
  unknown_asset: "Activo no reconocido",
  undocumented_host: "Host sin documentar",
  keepalive_down: "Caída de heartbeat",
};

function severityColor(sev: string | null | undefined) {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") return C.red;
  if (s === "HIGH") return C.orange;
  if (s === "MEDIUM") return C.cyan;
  return C.textDim;
}

type Props = {
  caseItem: SocCase;
};

export function CaseGovernancePanel({ caseItem }: Props) {
  const ctx = caseItem.governanceContext;

  if (!ctx) return null;

  const payload = (ctx.payload ?? {}) as Record<string, unknown>;
  const incidentType = ctx.incidentType ?? "";
  const nocDeviceId = ctx.nocDeviceId ?? (payload.noc_device_id as string | undefined);
  const inventoryCase = incidentType.startsWith("unknown") || incidentType === "undocumented_host";

  const isSoftware =
    incidentType === "forbidden_software" || incidentType === "unapproved_software";

  return (
    <div
      style={{
        border: `1px solid ${alpha(C.orange, 25)}`,
        borderRadius: 8,
        background: alpha(C.orange, 6),
        padding: 14,
        display: "flex",
        flexDirection: "column",
        gap: 12,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {isSoftware ? (
          <Package size={16} color={C.orange} />
        ) : (
          <Server size={16} color={C.orange} />
        )}
        <span style={{ fontSize: 12, fontWeight: 700, color: C.orange, letterSpacing: "0.04em" }}>
          INVESTIGACIÓN NOC · {INCIDENT_LABEL[incidentType] ?? incidentType}
        </span>
        {ctx.autoOpened && (
          <span
            style={{
              fontSize: 10,
              padding: "2px 6px",
              borderRadius: 4,
              background: alpha(C.purple, 12),
              color: C.purple,
            }}
          >
            auto-abierto
          </span>
        )}
      </div>

      <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
        {payload.software_name != null && (
          <Row label="Software" value={`${payload.software_name} ${payload.software_version ?? ""}`.trim()} mono />
        )}
        {payload.publisher != null && <Row label="Editor" value={String(payload.publisher)} />}
        {payload.rule_name != null && <Row label="Regla" value={String(payload.rule_name)} />}
        {payload.ip_address != null && <Row label="IP" value={String(payload.ip_address)} mono />}
        {payload.discovered_via != null && (
          <Row label="Origen descubrimiento" value={String(payload.discovered_via)} />
        )}
        {payload.policy != null && <Row label="Política" value={String(payload.policy)} />}
        {(payload.severity as string | undefined) && (
          <Row label="Severidad regla" value={String(payload.severity)} color={severityColor(String(payload.severity))} />
        )}
      </div>

      {isSoftware && (
        <p style={{ fontSize: 11, color: C.textDim, lineHeight: 1.5, margin: 0 }}>
          Verifique el inventario del host, desinstale el software o solicite excepción en{" "}
          <Link to="/noc/config" style={{ color: C.cyan }}>
            Gobernanza de software
          </Link>
          .
        </p>
      )}

      {inventoryCase && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <p style={{ fontSize: 11, color: C.textDim, lineHeight: 1.5, margin: 0 }}>
            <AlertTriangle size={12} style={{ display: "inline", marginRight: 4, verticalAlign: "middle" }} />
            Este activo apareció en descubrimiento/inventario sin reconocimiento (ACK). Usá el botón
            «ACK inventario» en la cabecera del panel para confirmarlo.
          </p>
          {nocDeviceId && (
            <Link
              to={`/noc/${nocDeviceId}`}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                fontSize: 11,
                color: C.cyan,
                textDecoration: "none",
              }}
            >
              Ver en NOC <ExternalLink size={12} />
            </Link>
          )}
        </div>
      )}
    </div>
  );
}

function Row({
  label,
  value,
  mono,
  color,
}: {
  label: string;
  value: string;
  mono?: boolean;
  color?: string;
}) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
      <span style={{ color: C.textDim }}>{label}</span>
      <span style={{ color: color ?? C.text, fontFamily: mono ? "monospace" : "inherit", textAlign: "right" }}>
        {value}
      </span>
    </div>
  );
}
