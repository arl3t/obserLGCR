/**
 * MobileCaseList — Lista de casos optimizada para viewport <800px (C4).
 *
 * Reemplaza la tabla de 9 columnas del CaseManagementDashboard por cards
 * apiladas con la info esencial para decidir (severity, IOC, status, SLA,
 * adopt 1-click si aplica). Click → /gestion?investigate=… (o open modal
 * de adopción si el caso no tiene owner y no soy CI guardado).
 *
 * Foco: oncall que recibió alerta Slack 3am y quiere ver de qué se trata
 * sin abrir laptop. Información secundaria (Score, Detectado, Sensor) queda
 * fuera para no recargar la card.
 */

import { useMemo } from "react";
import { ArrowRight, Shield } from "lucide-react";
import { Link } from "react-router-dom";
import type { SocCase, Severity, CaseStatus } from "./types";
import { caseCode } from "./case-normalize";
import { formatSlaRemaining } from "@/lib/sla-calc";

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL:   "#ff3b5c",
  HIGH:       "#ff9500",
  MEDIUM:     "#00f5ff",
  LOW:        "#22c55e",
  NEGLIGIBLE: "#64748b",
};

const STATUS_LABEL_SHORT: Record<CaseStatus, string> = {
  NUEVO:           "Nuevo",
  EN_ANALISIS:     "Análisis",
  CONFIRMADO:      "Confirm.",
  ESCALADO:        "Escalado",
  MONITOREADO:     "Monitor",
  FALSO_POSITIVO:  "FP",
  CERRADO:         "Cerrado",
};

interface MobileCaseListProps {
  cases:        SocCase[];
  isLoading:    boolean;
  myOperatorCi: string;
  /** Abre el panel lateral de detalle del incidente. */
  onSelect: (c: SocCase) => void;
  /** Callback opcional para adoptar 1-click desde la card. Si no se pasa,
   *  la card no muestra el botón "Adoptar". */
  onAdopt?: (c: SocCase) => void;
}

export function MobileCaseList({
  cases, isLoading, myOperatorCi, onSelect, onAdopt,
}: MobileCaseListProps) {
  if (isLoading && cases.length === 0) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {Array.from({ length: 5 }).map((_, i) => <SkeletonCard key={i} />)}
      </div>
    );
  }

  if (cases.length === 0) {
    return (
      <div style={{
        padding: "32px 16px", textAlign: "center", color: "#7a8aa0",
        background: "#11161d", border: "1px dashed #1c2530", borderRadius: 8,
        fontSize: 13,
      }}>
        Sin casos para los filtros actuales.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {cases.map((c) => (
        <MobileCaseCard
          key={c.id}
          c={c}
          isMine={!!myOperatorCi && c.operatorCi === myOperatorCi}
          onSelect={onSelect}
          onAdopt={onAdopt}
        />
      ))}
    </div>
  );
}

function MobileCaseCard({
  c, isMine, onSelect, onAdopt,
}: {
  c: SocCase;
  isMine: boolean;
  onSelect: (c: SocCase) => void;
  onAdopt?: (c: SocCase) => void;
}) {
  const sev = (SEV_COLOR[c.severity as Severity] ?? "#94a3b8");
  const sla = useMemo(() => formatSlaRemaining(c.detectedAt, c.slaSec), [c.detectedAt, c.slaSec]);
  // pct = % del SLA consumido. >=100 = breach (texto con signo "−" del helper).
  const slaPct = useMemo(() => {
    if (!c.detectedAt || c.slaSec <= 0) return 0;
    const elapsed = (Date.now() - new Date(c.detectedAt).getTime()) / 1000;
    return (elapsed / c.slaSec) * 100;
  }, [c.detectedAt, c.slaSec]);
  const slaColor = slaPct >= 100 ? "#ff3b5c"
                : slaPct >= 90  ? "#ff3b5c"
                : slaPct >= 70  ? "#ff9500"
                                : "#7a8aa0";
  const noOwner = !c.operatorCi;
  const status = c.status as CaseStatus;

  return (
    <article
      onClick={() => onSelect(c)}
      style={{
        background: "#11161d",
        border: "1px solid #1c2530",
        borderLeft: `3px solid ${sev}`,
        borderRadius: 8,
        padding: "10px 12px",
        cursor: "pointer",
        display: "grid",
        gridTemplateColumns: "auto 1fr auto",
        gridTemplateRows: "auto auto",
        rowGap: 6,
        columnGap: 8,
        alignItems: "center",
      }}
    >
      {/* Row 1: sev | IOC | SLA */}
      <span style={{
        gridColumn: "1", gridRow: "1",
        fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 3,
        background: sev + "25", color: sev, letterSpacing: "0.05em",
        display: "inline-flex", alignItems: "center", gap: 4,
      }}>
        {c.severity === "CRITICAL" && (
          <span style={{ width: 5, height: 5, borderRadius: "50%", background: sev }} />
        )}
        {c.severity}
      </span>
      <span style={{
        gridColumn: "2", gridRow: "1",
        fontSize: 13, fontWeight: 600, color: "#d6e0ee",
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
      }}>
        {c.hostname || c.srcIp || `#${c.id.slice(0, 8)}`}
      </span>
      <span style={{
        gridColumn: "3", gridRow: "1",
        fontSize: 10, color: slaColor, fontWeight: 600,
      }}>
        SLA {sla ?? "—"}
      </span>

      {/* Row 2: status + meta + acción */}
      <span style={{
        gridColumn: "1", gridRow: "2",
        fontSize: 9, fontWeight: 600, padding: "1px 6px", borderRadius: 3,
        background: "#3b82f620", color: "#60a5fa", border: "1px solid #3b82f640",
        whiteSpace: "nowrap",
      }}>
        {STATUS_LABEL_SHORT[status] ?? c.status}
      </span>
      <span style={{
        gridColumn: "2", gridRow: "2",
        fontSize: 10, color: "#7a8aa0",
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
      }}>
        <span style={{ fontFamily: "ui-monospace, monospace", marginRight: 6 }}>
          {caseCode(c)}
        </span>
        · {c.sourceLabel || c.source || "—"}
        {isMine && <> · <strong style={{ color: "#5fb4ce" }}>tú</strong></>}
        {!isMine && noOwner && <> · <strong style={{ color: "#e2a766" }}>sin owner</strong></>}
      </span>
      <span style={{
        gridColumn: "3", gridRow: "2",
        display: "inline-flex", alignItems: "center", gap: 6,
      }}>
        {noOwner && onAdopt && (
          <button
            onClick={(e) => { e.stopPropagation(); onAdopt(c); }}
            style={{
              fontSize: 10, fontWeight: 600, padding: "3px 8px", borderRadius: 4,
              background: "#5fb4ce20", color: "#5fb4ce", border: "1px solid #5fb4ce40",
              cursor: "pointer",
            }}
            title="Adoptar este caso"
          >
            <Shield size={9} style={{ verticalAlign: "middle", marginRight: 3 }} />
            Adoptar
          </button>
        )}
        <ArrowRight size={12} color="#7a8aa0" />
      </span>
    </article>
  );
}

function SkeletonCard() {
  return (
    <div style={{
      background: "#11161d", border: "1px solid #1c2530", borderRadius: 8,
      padding: "10px 12px", height: 56,
      animation: "pulse 1.4s ease-in-out infinite",
    }} />
  );
}

/**
 * MobileBlocker — banner que avisa "esta vista no está optimizada para móvil"
 * y oculta un componente. Usado para tabla/widgets que no se adaptan.
 */
export function MobileBlocker({ children }: { children?: React.ReactNode }) {
  return (
    <div style={{
      padding: "16px 14px", textAlign: "center",
      background: "#11161d", border: "1px dashed #1c2530", borderRadius: 8,
      color: "#7a8aa0", fontSize: 11,
    }}>
      {children ?? <>Vista no optimizada para pantallas pequeñas. Usá una laptop o tablet en horizontal.</>}
    </div>
  );
}

/**
 * Link wrapper helper para tests/storybook (no usado en runtime; el click va
 * por el onInvestigate handler que decide). Reexpuesto por completitud. */
export const _MobileCardLink = Link;
