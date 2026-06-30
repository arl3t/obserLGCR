/**
 * ViewersStack — avatar stack que muestra quién más está mirando el caso
 * en tiempo real (C3).
 *
 * Diseño:
 *   - Hasta `maxAvatars` iniciales coloreados por hash del CI (consistente
 *     entre sesiones); resto se compacta en un chip "+N".
 *   - Hover sobre un avatar muestra nombre + tab activo + tiempo desde
 *     primer-visto ("Juan está en Assets · hace 4 min").
 *   - Si está vacío (sólo vos), no renderiza nada para no añadir ruido al
 *     header.
 */

import { useMemo } from "react";
import type { CaseViewer } from "./useCaseViewers";

interface ViewersStackProps {
  viewers: CaseViewer[];
  /** ID del operador actual — se filtra automáticamente del stack. */
  selfOperatorId?: string | null;
  /** Cuántos avatares iniciales mostrar antes de colapsar a "+N". */
  maxAvatars?: number;
}

const COLORS = [
  "#5fb4ce", "#6ec07e", "#e2a766", "#d65f5f",
  "#6e9bd6", "#a87bd6", "#cea25f", "#9ba6b6",
];

function hashColor(id: string): string {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0;
  return COLORS[Math.abs(h) % COLORS.length];
}

function initials(name: string | null | undefined, id: string): string {
  const src = (name && name.trim()) || id;
  const parts = src.trim().split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return src.slice(0, 2).toUpperCase();
}

function timeAgo(iso: string): string {
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "ahora";
  const s = Math.floor(ms / 1000);
  if (s < 60)    return `hace ${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60)    return `hace ${m}m`;
  const h = Math.floor(m / 60);
  return `hace ${h}h`;
}

export function ViewersStack({ viewers, selfOperatorId, maxAvatars = 3 }: ViewersStackProps) {
  const others = useMemo(
    () => viewers.filter((v) => v.operatorId !== selfOperatorId),
    [viewers, selfOperatorId],
  );

  if (others.length === 0) return null;

  const head    = others.slice(0, maxAvatars);
  const overflow = Math.max(0, others.length - maxAvatars);

  return (
    <div
      style={{ display: "inline-flex", alignItems: "center", gap: -6 }}
      title={`${others.length} operador${others.length === 1 ? "" : "es"} más mirando este caso`}
    >
      {head.map((v) => (
        <Avatar key={v.operatorId} viewer={v} />
      ))}
      {overflow > 0 && (
        <span
          title={others.slice(maxAvatars).map((v) => v.operatorName ?? v.operatorId).join(", ")}
          style={{
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            width: 26, height: 26, borderRadius: "50%",
            background: "#1c2530", color: "#d6e0ee",
            border: "2px solid #0a0d12",
            fontSize: 10, fontWeight: 700,
            marginLeft: -6,
          }}
        >
          +{overflow}
        </span>
      )}
    </div>
  );
}

function Avatar({ viewer }: { viewer: CaseViewer }) {
  const bg = hashColor(viewer.operatorId);
  const label = initials(viewer.operatorName, viewer.operatorId);
  const tip = `${viewer.operatorName ?? viewer.operatorId}${
    viewer.activeTab ? ` · ${viewer.activeTab}` : ""
  } · ${timeAgo(viewer.firstSeenAt)}`;
  return (
    <span
      title={tip}
      style={{
        display: "inline-flex", alignItems: "center", justifyContent: "center",
        width: 26, height: 26, borderRadius: "50%",
        background: bg, color: "#0a0d12",
        border: "2px solid #0a0d12",
        fontSize: 10, fontWeight: 700,
        marginLeft: -6,
        cursor: "help",
      }}
    >
      {label}
    </span>
  );
}
