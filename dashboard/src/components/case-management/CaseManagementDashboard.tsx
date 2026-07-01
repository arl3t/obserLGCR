/**
 * CaseManagementDashboard.tsx
 * Dashboard principal de Gestión de Casos SOC.
 * Datos 100% desde el backend real vía useCaseManagement.
 */

import React, { Fragment, memo, useCallback, useState, useMemo, useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import {
  RefreshCw, AlertCircle, Shield, Clock, CheckCircle,
  Search, ChevronLeft, ChevronRight,
  ChevronUp, ChevronDown, Server, User,
  Globe, Link as LinkIcon, Hash, Mail, FileText, KeyRound,
  Keyboard, ShieldCheck, MoreHorizontal, Wrench, Layers, X, FileDown,
  type LucideIcon,
} from "lucide-react";
import { api } from "@/api/client";
import { caseCode }                from "./case-normalize";
import { formatDateTimePy, formatDatePy } from "@/lib/format";
import { useCaseManagement }       from "./useCaseManagement";
import { CaseDetailSheet }         from "./CaseDetailSheet";
import { CaseAdoptionModal }       from "./CaseAdoptionModal";
import { ProfileSelector }         from "./ProfileSelector";
import { ExecutiveReportMenu }     from "./ExecutiveReportMenu";
import { BulkCloseAssistant }      from "./BulkCloseAssistant";
import { exportSelectedCasesReportPdf } from "@/lib/cases-report-pdf";
import { useStatusDist }           from "./useCaseInvestigation";
import { getTriggeringProfiles, loadProfiles } from "./scoringProfiles";
import type { SocCase, Severity, CaseStatus, DashboardKpis } from "./types";
import { NotificationBell }        from "@/components/soc/NotificationBell";
import { WorkflowStatusBar, LifecycleStageBadge } from "@/components/soc/WorkflowStatusBar";
import { useSocOperators, useShiftManager } from "@/hooks/useSocWorkflow";
import { useCaseUpdates }          from "@/hooks/useCaseUpdates";
import { useMyWorkload }           from "@/hooks/useMyWorkload";
import { useDuplicatesCount }      from "@/hooks/useDuplicatesCount";
import { useViewport }             from "@/hooks/useViewport";
import { MobileCaseList }          from "./MobileCaseList";
import { loadOperatorCi, validateCi } from "@/lib/operator-ci";
import { useOperatorIdentity } from "@/hooks/useOperatorIdentity";
import { loadFilters, saveFilters, loadSavedViews, upsertSavedView, deleteSavedView, type SavedCaseView, type PersistedCaseFilters } from "@/lib/case-filters-storage";
import { calcSlaPct, slaColor, relativeTime, formatSlaRemaining } from "@/lib/sla-calc";
import { useAuth }                 from "@/auth/useAuth";

// ── Colores ────────────────────────────────────────────────────────────────────
// `C` y `alpha()` viven en lib/cm-theme.ts (compartidos con otros componentes
// de case management). Resuelven a CSS variables `--cm-*` que cambian por tema.
import { C, alpha } from "@/lib/cm-theme";

const SEV_COLOR: Record<string, string> = {
  CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.cyan,
  LOW: C.green, NEGLIGIBLE: C.textDim,
};

const SEV_RANK: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NEGLIGIBLE: 4,
};

function isEscalatedCase(c: SocCase): boolean {
  return c.status === "ESCALADO" || c.escalation != null;
}

function isResolvedCase(c: SocCase): boolean {
  return c.status === "CERRADO" || c.status === "FALSO_POSITIVO";
}

/**
 * Orden de prioridad para la vista L1:
 *   0. Escalados abiertos      — requieren handoff/seguimiento
 *   1. CRITICAL/HIGH sin adoptar (abiertos)
 *   2. MEDIUM/LOW sin adoptar (abiertos)
 *   3. Adoptados abiertos      — hay dueño, menor urgencia de mirada
 *   4. CERRADO / FALSO_POSITIVO — resueltos, al final
 */
function casePriorityBucket(c: SocCase): number {
  if (isResolvedCase(c)) return 4;
  if (isEscalatedCase(c)) return 0;
  if (!c.adoptedAt) {
    return c.severity === "CRITICAL" || c.severity === "HIGH" ? 1 : 2;
  }
  return 3;
}

const SEV_OPTIONS: Array<Severity | "ALL"> = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"];
const STATUS_OPTIONS: Array<CaseStatus | "ALL"> = [
  "ALL", "NUEVO", "EN_ANALISIS", "CONFIRMADO", "ESCALADO", "MONITOREADO", "FALSO_POSITIVO", "CERRADO",
];
const STATUS_LABEL: Record<string, string> = {
  ALL: "Todos", NUEVO: "Nuevo", EN_ANALISIS: "En análisis",
  CONFIRMADO: "Confirmado", ESCALADO: "Escalado",
  MONITOREADO: "Monitoreado", FALSO_POSITIVO: "FP", CERRADO: "Cerrado",
};

// Clases eCSIRT/MISP (mig 088) para el filtro de la cola. Las claves espejan
// ECSIRT_CLASSES del backend (services/ecsirtClassify.mjs); el label es la
// etiqueta compacta en español que se muestra en el dropdown.
const CLASS_OPTIONS: Array<{ key: string; label: string }> = [
  { key: "ALL",               label: "Todas" },
  { key: "MALICIOUS_CODE",    label: "Malware" },
  { key: "INTRUSION",         label: "Intrusión" },
  { key: "INTRUSION_ATTEMPT", label: "Intento de intrusión" },
  { key: "FRAUD",             label: "Fraude / Phishing" },
  { key: "INFO_GATHERING",    label: "Recolección de info" },
  { key: "INFO_CONTENT_SEC",  label: "Seguridad de contenido" },
  { key: "AVAILABILITY",      label: "Disponibilidad (DoS)" },
  { key: "ABUSIVE_CONTENT",   label: "Contenido abusivo" },
  { key: "VULNERABLE",        label: "Sistema vulnerable" },
  { key: "OTHER",             label: "Sin clasificar" },
];
const CLASS_LABEL: Record<string, string> = Object.fromEntries(
  CLASS_OPTIONS.map((o) => [o.key, o.label]),
);

const PAGE_SIZE_OPTIONS = [25, 50, 100] as const;

// Ejemplos rotantes en el placeholder del buscador — descubrir la DSL sin
// tener que leer el tooltip. El usuario ve un ejemplo distinto cada 4.5s
// mientras no escriba, lo cual desambigua "es búsqueda libre" vs "acepta
// filtros tipados". Cobertura: las 4 dimensiones más usadas (sev, status,
// MITRE, source) + las 2 nuevas C5 (score, age) que abren capacidades de
// análisis que antes requerían exportar CSV.
const SEARCH_HINTS = [
  "IP, IOC, o filtros — ej: sev:c op:me",
  "ej: status:nuevo op:none (cola de triage)",
  "ej: mitre:T1110 sev:h (brute force alto)",
  "ej: source:wazuh_alerts sev:c (Wazuh críticos)",
  "ej: score:>=70 age:<7d (alto recientes)",
  "ej: score:50-80 op:me (mis pendientes medios)",
];

// La salud del sistema (SM activo, caché Trino, automatización) vive ahora en
// el botón "Sistema" de la barra superior — ver components/layout/SystemHealthButton.

// ── A1 — Chip del banner "Mi trabajo hoy" ────────────────────────────────────
function MyWorkChip({
  label, count, color, active, onClick, title, ratioOf,
}: {
  label: string;
  count: number;
  color: string;
  active: boolean;
  onClick: () => void;
  title?: string;
  /** Si está definido, el chip muestra `count/ratioOf (XX%)` en vez de solo
   *  count. Útil para contextualizar "En riesgo SLA" como fracción de
   *  "Mis activos" — evita la duda "¿por qué son iguales?". */
  ratioOf?: number;
}) {
  const showRatio = ratioOf != null && ratioOf > 0;
  const pct = showRatio ? Math.round((count / ratioOf) * 100) : null;
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        display: "inline-flex", alignItems: "center", gap: 7,
        padding: "4px 10px", borderRadius: 6, cursor: "pointer",
        background: active ? `${color}30` : `${color}12`,
        border: `1px solid ${color}${active ? "70" : "30"}`,
        color, fontSize: 11, fontWeight: 600,
        transition: "background 120ms",
      }}
    >
      <span>{label}</span>
      <span style={{
        fontSize: 10, fontWeight: 700,
        background: `${color}25`, border: `1px solid ${color}50`,
        padding: "0 5px", borderRadius: 3, minWidth: 16, textAlign: "center",
      }}>
        {showRatio ? `${count}/${ratioOf}` : count}
      </span>
      {showRatio && pct != null && (
        <span style={{ fontSize: 10, opacity: 0.85 }}>
          ({pct}%)
        </span>
      )}
    </button>
  );
}

// ── C10 + C5 — Parser de búsqueda con sintaxis ───────────────────────────────
// Tokens soportados (case-insensitive):
//   sev:<LEVEL>      C/H/M/L/N o nombres completos
//   status:<ST>      NUEVO/EN_ANALISIS/... o sinónimos en inglés (new/open/...)
//   op:<CI>          me | none | <CI>
//   role:<ROLE>      L1/L2/L3/LEADER (CSV admitido)
//   mitre:<TXXXX>    técnica MITRE (texto libre upcase)
//   source:<SRC>     wazuh_alerts, fortigate_*, etc.
//   score:<EXPR>     >N, <N, >=N, <=N, N-M, =N o N exacto
//   age:<EXPR>       <Nd, >Nd, Nd (N + unidad m/h/d/w). <Nd = recientes; >Nd = viejos
//   createdAt:<EXPR> absoluto (>=ISO/<=ISO) o alias relativo de age:
// Lo no-reconocido queda en el texto libre. El parser es tolerante: un ":" sin
// valor o un valor inválido devuelve el token al texto libre para que ILIKE
// matchee literalmente (útil para IPv6 o UUIDs pegados).
type ParsedSearch = {
  free: string;                 // texto libre, sin tokens
  severity?: Severity | "ALL";
  status?: CaseStatus | "ALL";
  assignedTo?: string;           // CI | __me__ | __unassigned__
  role?: string;                 // CSV de roles o un solo rol
  mitre?: string;
  source?: string;
  /** Rango de score (inclusivo). Min/Max se resuelven a enteros antes de
   *  pasar al backend. score:>N convierte a min=N+1; score:<N a max=N-1. */
  scoreMin?: number;
  scoreMax?: number;
  /** Rango de created_at como ISO 8601. age: y createdAt: relativo se
   *  resuelven a timestamps absolutos en el momento del parseo. */
  createdAtMin?: string;
  createdAtMax?: string;
};

/** Parsea expresiones tipo `>N`, `<N`, `>=N`, `<=N`, `N-M`, `=N`, `N` a un
 *  rango inclusivo (min, max). Devuelve null si la entrada no parsea. */
function parseNumRange(raw: string): { min?: number; max?: number } | null {
  const v = raw.trim();
  if (!v) return null;
  // Range "N-M" — solo si AMBOS son enteros no negativos (evita engullir
  // valores tipo "2026-05" que también matchean dígito-dígito).
  const rng = v.match(/^(\d+)\s*-\s*(\d+)$/);
  if (rng) {
    const min = Number(rng[1]); const max = Number(rng[2]);
    if (min > max) return null;
    return { min, max };
  }
  // Comparadores
  const cmp = v.match(/^(>=|<=|>|<|=)\s*(-?\d+)$/);
  if (cmp) {
    const n = Number(cmp[2]);
    switch (cmp[1]) {
      case ">":  return { min: n + 1 };
      case ">=": return { min: n };
      case "<":  return { max: n - 1 };
      case "<=": return { max: n };
      case "=":  return { min: n, max: n };
    }
  }
  // Exact integer
  if (/^-?\d+$/.test(v)) {
    const n = Number(v);
    return { min: n, max: n };
  }
  return null;
}

/** Convierte un sufijo de duración (`7d`, `2h`, `30m`, `1w`) a milisegundos.
 *  Devuelve null si no parsea. */
function durationToMs(raw: string): number | null {
  const m = raw.match(/^(\d+)\s*(m|h|d|w)$/i);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n < 0) return null;
  const unit = m[2].toLowerCase();
  const MS = { m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 } as const;
  return n * MS[unit as "m" | "h" | "d" | "w"];
}

/** Resuelve expresiones de `age:` / `createdAt:` (relativas) a un rango de
 *  timestamps ISO. Semántica: `<Nd` = recientes (created_at >= now - Nd);
 *  `>Nd` = viejos (created_at <= now - Nd); `Nd` solo (sin operador) = `<Nd`. */
function parseRelativeAge(
  raw: string, now: number,
): { minIso?: string; maxIso?: string } | null {
  const v = raw.trim();
  if (!v) return null;
  // ¿Operador delante?
  const opMatch = v.match(/^(>=|<=|>|<|=)?\s*(.+)$/);
  if (!opMatch) return null;
  const op    = opMatch[1] ?? "<";          // default: "<" (recientes)
  const value = opMatch[2].trim();
  const ms = durationToMs(value);
  if (ms == null) return null;
  const threshold = new Date(now - ms).toISOString();
  switch (op) {
    case ">":  case ">=": return { maxIso: threshold };   // viejos
    case "<":  case "<=": return { minIso: threshold };   // recientes
    case "=":  // ventana ±1m alrededor del punto; raro pero soportable
      return { minIso: new Date(now - ms - 60_000).toISOString(),
               maxIso: new Date(now - ms + 60_000).toISOString() };
  }
  return null;
}

/** Resuelve `createdAt:>2026-05-15` (ISO absoluto). `>` = newer (después de);
 *  `<` = older (antes de). Devuelve null si la fecha no parsea como ISO. */
function parseAbsoluteCreatedAt(
  raw: string,
): { minIso?: string; maxIso?: string } | null {
  const v = raw.trim();
  const opMatch = v.match(/^(>=|<=|>|<|=)?\s*(.+)$/);
  if (!opMatch) return null;
  const op = opMatch[1] ?? "=";
  const date = opMatch[2].trim();
  // Aceptamos YYYY-MM-DD o ISO completo. Date.parse devuelve NaN si malo.
  if (!/^\d{4}-\d{2}-\d{2}([T ].+)?$/.test(date)) return null;
  const t = Date.parse(date);
  if (!Number.isFinite(t)) return null;
  const iso = new Date(t).toISOString();
  switch (op) {
    case ">": case ">=": return { minIso: iso };
    case "<": case "<=": return { maxIso: iso };
    case "=": return { minIso: iso, maxIso: iso };
  }
  return null;
}

/** Normaliza severity aceptando abreviaciones: c/h/m/l → CRITICAL/... */
function parseSevToken(raw: string): Severity | null {
  const up = raw.toUpperCase();
  const full: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"];
  if ((full as string[]).includes(up)) return up as Severity;
  const short: Record<string, Severity> = { C: "CRITICAL", H: "HIGH", M: "MEDIUM", L: "LOW", N: "NEGLIGIBLE" };
  return short[up] ?? null;
}

/** Normaliza status aceptando sinónimos: `new → NUEVO`, `open → NUEVO`. */
function parseStatusToken(raw: string): CaseStatus | null {
  const up = raw.toUpperCase();
  const valid: CaseStatus[] = ["NUEVO", "EN_ANALISIS", "CONFIRMADO", "ESCALADO", "MONITOREADO", "FALSO_POSITIVO", "CERRADO"];
  if ((valid as string[]).includes(up)) return up as CaseStatus;
  const syn: Record<string, CaseStatus> = {
    NEW: "NUEVO", OPEN: "NUEVO", ANALYSIS: "EN_ANALISIS", CONFIRMED: "CONFIRMADO",
    ESCALATED: "ESCALADO", FP: "FALSO_POSITIVO", CLOSED: "CERRADO",
  };
  return syn[up] ?? null;
}

function parseSearchSyntax(input: string, now: number = Date.now()): ParsedSearch {
  const out: ParsedSearch = { free: "" };
  if (!input) return out;
  const parts: string[] = [];
  for (const token of input.split(/\s+/)) {
    if (!token) continue;
    // El valor puede contener comparadores y rangos (>=, <=, >, <, -), así
    // que separamos por el PRIMER `:` solamente (no por regex sobre todo).
    const colonIdx = token.indexOf(":");
    if (colonIdx <= 0 || colonIdx === token.length - 1) {
      parts.push(token);
      continue;
    }
    const key = token.slice(0, colonIdx).toLowerCase();
    const val = token.slice(colonIdx + 1);
    if (!/^[a-z]+$/.test(key)) { parts.push(token); continue; }
    switch (key) {
      case "sev": case "severity": {
        const s = parseSevToken(val);
        if (s) out.severity = s; else parts.push(token);
        break;
      }
      case "status": case "st": {
        const s = parseStatusToken(val);
        if (s) out.status = s; else parts.push(token);
        break;
      }
      case "op": case "operator": case "owner": {
        const v = val.trim();
        if (v.toLowerCase() === "me") out.assignedTo = "__me__";
        else if (v.toLowerCase() === "none" || v === "-") out.assignedTo = "__unassigned__";
        else out.assignedTo = v;
        break;
      }
      case "role": case "tier": {
        out.role = val.toUpperCase();
        break;
      }
      case "mitre": case "technique": case "t": {
        out.mitre = val.toUpperCase();
        break;
      }
      case "source": case "src": {
        out.source = val.toLowerCase();
        break;
      }
      case "score": {
        const r = parseNumRange(val);
        if (r) {
          if (r.min != null) out.scoreMin = r.min;
          if (r.max != null) out.scoreMax = r.max;
        } else { parts.push(token); }
        break;
      }
      case "age": {
        const r = parseRelativeAge(val, now);
        if (r) {
          if (r.minIso) out.createdAtMin = r.minIso;
          if (r.maxIso) out.createdAtMax = r.maxIso;
        } else { parts.push(token); }
        break;
      }
      case "createdat": case "created": {
        // Heurística: si parsea como duración (`7d`, `>2h`) es relativo;
        // sino intentamos absoluto (ISO/YYYY-MM-DD).
        const rRel = parseRelativeAge(val, now);
        if (rRel) {
          if (rRel.minIso) out.createdAtMin = rRel.minIso;
          if (rRel.maxIso) out.createdAtMax = rRel.maxIso;
          break;
        }
        const rAbs = parseAbsoluteCreatedAt(val);
        if (rAbs) {
          if (rAbs.minIso) out.createdAtMin = rAbs.minIso;
          if (rAbs.maxIso) out.createdAtMax = rAbs.maxIso;
        } else { parts.push(token); }
        break;
      }
      default: parts.push(token);
    }
  }
  out.free = parts.join(" ").trim();
  return out;
}

// ── A3 — Chip de edad con color según % de SLA consumido ─────────────────────
// `detectedAt` + `slaSec` definen el deadline; el chip muestra edad relativa
// ("2h 14m") y pinta rojo cuando ≥90%, ámbar entre 70-90%, gris resto.
function AgeChip({ detectedAt, slaSec }: { detectedAt: string | null; slaSec: number }) {
  if (!detectedAt) return null;
  const ageMs = Date.now() - Date.parse(detectedAt);
  if (!Number.isFinite(ageMs) || ageMs < 0) return null;
  const mins  = Math.max(0, Math.floor(ageMs / 60_000));
  const label = mins < 60 ? `${mins}m`
              : mins < 60 * 24 ? `${Math.floor(mins / 60)}h ${mins % 60}m`
              : `${Math.floor(mins / (60 * 24))}d ${Math.floor((mins % (60 * 24)) / 60)}h`;
  const pct   = slaSec > 0 ? Math.min(100, Math.max(0, (ageMs / (slaSec * 1000)) * 100)) : 0;
  // pct≥90 → rojo "casi vencido"; 70-90 → ámbar; <70 → gris neutro
  const tint  = pct >= 90 ? C.red : pct >= 70 ? C.orange : C.textDim;
  const bg    = alpha(tint, 18);
  const color = tint;
  const border= alpha(tint, 44);
  return (
    <span
      title={slaSec > 0 ? `Edad ${label} · ${pct.toFixed(0)}% del SLA` : `Edad ${label}`}
      style={{
        display: "inline-flex", alignItems: "center", gap: 3,
        padding: "1px 6px", borderRadius: 4, fontSize: 10, fontWeight: 600,
        background: bg, color, border: `1px solid ${border}`,
        fontFamily: "ui-monospace, monospace",
      }}
    >
      <span>{label}</span>
      {pct >= 70 && slaSec > 0 && (
        <span style={{ fontSize: 9, opacity: 0.85 }}>({Math.round(pct)}%)</span>
      )}
    </span>
  );
}

// Mapa de iconos por tipo de IOC para visual scan rápido en la tabla.
// Si el backend agrega tipos nuevos, caen al fallback (Server). El icono va a
// la izquierda del valor del IOC en CaseRow.
const IOC_TYPE_ICON: Record<string, LucideIcon> = {
  ip:         Server,
  ipv4:       Server,
  ipv6:       Server,
  domain:     Globe,
  fqdn:       Globe,
  url:        LinkIcon,
  hash:       Hash,
  md5:        Hash,
  sha1:       Hash,
  sha256:     Hash,
  email:      Mail,
  emailaddr:  Mail,
  file:       FileText,
  filename:   FileText,
  credential: KeyRound,
};

function iocTypeIcon(iocType: string | null | undefined): LucideIcon {
  const k = String(iocType || "").toLowerCase().trim();
  return IOC_TYPE_ICON[k] ?? Server;
}

/** Modos de agrupación de la cola de incidentes NOC. */
type GroupMode = "none" | "activo";

// ── HeaderMenu — botón con dropdown para colapsar acciones del header ──────────
// Despeja el header (de 11 botones a ~6) agrupando toggles de paneles y acciones
// masivas. Cierra al click-fuera / ESC. Espejo del patrón de ExecutiveReportMenu.
interface MenuItem {
  label: string;
  onClick: () => void;
  icon?: LucideIcon;
  color?: string;
  badge?: number;
  disabled?: boolean;
  hidden?: boolean;
  title?: string;
}
function HeaderMenu({
  label, icon: Icon, items, accent = C.text, badge,
}: { label: string; icon?: LucideIcon; items: MenuItem[]; accent?: string; badge?: number }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const visible = items.filter((it) => !it.hidden);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onKey); };
  }, [open]);
  if (visible.length === 0) return null;
  return (
    <div ref={ref} style={{ position: "relative", display: "inline-block" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        style={{ ...btnStyle, color: accent, borderColor: alpha(accent, 25), display: "inline-flex", alignItems: "center", gap: 6 }}
      >
        {Icon && <Icon size={13} />}
        {label}
        {badge != null && badge > 0 && (
          <span style={{
            fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 8,
            background: alpha(C.orange, 25), color: C.orange, border: `1px solid ${alpha(C.orange, 50)}`,
          }}>{badge}</span>
        )}
        <ChevronDown size={12} style={{ transform: open ? "rotate(180deg)" : undefined, transition: "transform 0.15s" }} />
      </button>
      {open && (
        <div style={{
          position: "absolute", top: "calc(100% + 4px)", right: 0, minWidth: 220, zIndex: 100,
          background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8,
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)", padding: 4,
        }}>
          {visible.map((it) => {
            const col = it.color ?? C.text;
            return (
              <button
                key={it.label}
                disabled={it.disabled}
                title={it.title}
                onClick={() => { it.onClick(); setOpen(false); }}
                style={{
                  display: "flex", alignItems: "center", gap: 8, width: "100%", textAlign: "left",
                  background: "transparent", border: "none", color: it.disabled ? C.textDim : col,
                  padding: "8px 10px", borderRadius: 4, cursor: it.disabled ? "not-allowed" : "pointer",
                  fontSize: 12, opacity: it.disabled ? 0.5 : 1,
                }}
                onMouseEnter={(e) => { if (!it.disabled) e.currentTarget.style.background = C.card; }}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                {it.icon && <it.icon size={13} style={{ color: col }} />}
                <span style={{ flex: 1 }}>{it.label}</span>
                {it.badge != null && it.badge > 0 && (
                  <span style={{
                    fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 8,
                    background: alpha(C.orange, 25), color: C.orange,
                  }}>{it.badge}</span>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── SideDrawer — contenedor lateral derecho para paneles secundarios ──────────
// Reemplaza el apilamiento vertical de paneles (Supresiones/Duplicados/Handover…)
// por un slide-over con backdrop. Sólo uno abierto a la vez.
function SideDrawer({
  open, onClose, title, width = 560, children,
}: { open: boolean; onClose: () => void; title: string; width?: number; children: React.ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, zIndex: 60, background: "rgba(0,0,0,0.45)", display: "flex", justifyContent: "flex-end" }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "min(96vw, " + width + "px)", height: "100%", background: C.bg,
          borderLeft: `1px solid ${C.border}`, boxShadow: "-8px 0 32px rgba(0,0,0,0.4)",
          display: "flex", flexDirection: "column", overflow: "hidden",
        }}
      >
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "12px 16px", borderBottom: `1px solid ${C.border}`, flexShrink: 0,
        }}>
          <span style={{ fontSize: 14, fontWeight: 700, color: C.text }}>{title}</span>
          <button
            onClick={onClose}
            title="Cerrar (Esc)"
            style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim, display: "flex" }}
          >
            <X size={18} />
          </button>
        </div>
        <div style={{ flex: 1, overflow: "auto", padding: 16 }}>{children}</div>
      </div>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────────────────────

export function CaseManagementDashboard() {
  // Carga inicial desde localStorage para persistir los filtros entre sesiones.
  const persisted = useMemo(() => loadFilters(), []);
  // C4 — Viewport reactivo. La tabla de 9 columnas no entra en <800px;
  // cuando isMobile, el body se reemplaza por MobileCaseList (cards stack).
  const { isMobile } = useViewport();
  const [sevFilter, setSevFilter]     = useState<Severity | "ALL">(persisted.severity);
  const [statusFilter, setStatusFilter] = useState<CaseStatus | "ALL">(persisted.status);
  const [classFilter, setClassFilter] = useState<string>(persisted.incidentClass ?? "ALL");
  const [search, setSearch]           = useState(persisted.search);
  // Placeholder rotante para descubrir la DSL de filtros — usuarios no lo
  // encontraban con el hint estático. Rota cada 4.5s entre 4 ejemplos
  // representativos cuando el input está vacío.
  const [hintIdx, setHintIdx] = useState(0);
  useEffect(() => {
    if (search) return; // si está escribiendo, no rotamos para no distraer
    const t = setInterval(() => setHintIdx(i => (i + 1) % SEARCH_HINTS.length), 4500);
    return () => clearInterval(t);
  }, [search]);
  const searchPlaceholder = SEARCH_HINTS[hintIdx];
  const [assignedTo, setAssignedTo]   = useState<string>(persisted.assignedTo);     // "" | "__unassigned__" | "__me__" | <CI>
  const [assignedRoles, setAssignedRoles] = useState<string[]>(   // multi-perfil
    persisted.assignedRole ? persisted.assignedRole.split(",").filter(Boolean) : [],
  );
  const [includeClosed, setIncludeClosed] = useState<boolean>(persisted.includeClosed);
  const [page, setPage]               = useState(1);  // page no se persiste — siempre 1 al volver
  const [pageSize, setPageSize]       = useState<number>(persisted.pageSize);
  const [dateFrom, setDateFrom]       = useState(persisted.dateFrom);
  const [dateTo, setDateTo]           = useState(persisted.dateTo);
  const [sort, setSort]               = useState(persisted.sort);
  const [sortDir, setSortDir]         = useState<"asc" | "desc">(persisted.sortDir);
  // C5 — Filtros DSL extra (score:>N, age:<7d, createdAt:>2026-05-15). Se
  // setean desde applySearch al detectar tokens; persisten en localStorage.
  const [scoreMin, setScoreMin]               = useState<number | null>(persisted.scoreMin ?? null);
  const [scoreMax, setScoreMax]               = useState<number | null>(persisted.scoreMax ?? null);
  const [createdAtMin, setCreatedAtMin]       = useState<string>(persisted.createdAtMin ?? "");
  const [createdAtMax, setCreatedAtMax]       = useState<string>(persisted.createdAtMax ?? "");
  // A4 — Toggle "Agrupar por IOC": cuando está ON, filas con el mismo srcIp
  // (ioc_value) colapsan en una sola entrada con badge `Nx`. Click expande.
  // Agrupación de la cola: "none" (plano) · "activo" (mismo hostname/IP).
  const [groupMode, setGroupMode]         = useState<GroupMode>("none");
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  // Sincroniza filtros → localStorage en cada cambio (debounce trivial via React batching).
  useEffect(() => {
    saveFilters({
      severity: sevFilter, status: statusFilter, search,
      pageSize, sort, sortDir, dateFrom, dateTo,
      assignedTo, assignedRole: assignedRoles.join(","),
      includeClosed,
      scoreMin, scoreMax, createdAtMin, createdAtMax,
      incidentClass: classFilter,
    });
  }, [sevFilter, statusFilter, search, pageSize, sort, sortDir, dateFrom, dateTo,
      assignedTo, assignedRoles, includeClosed,
      scoreMin, scoreMax, createdAtMin, createdAtMax, classFilter]);
  const [selectedCase,      setSelectedCase]      = useState<SocCase | null>(null);
  const [adoptingCase,      setAdoptingCase]      = useState<SocCase | null>(null);
  /** Hotkeys: índice de fila enfocada en displayCases. -1 = ninguna. */
  const [focusIdx,          setFocusIdx]          = useState<number>(-1);
  const [showHotkeysHelp,   setShowHotkeysHelp]   = useState<boolean>(false);
  // Vistas guardadas (P2 #15): combos de filtros con nombre, aplicables en 1 clic.
  const [savedViews,        setSavedViews]        = useState<SavedCaseView[]>(() => loadSavedViews());
  // Multi-select (P0 #12): IDs marcados para acción masiva + estado del batch.
  const [selectedIds,       setSelectedIds]       = useState<Set<string>>(new Set());
  const [bulkBusy,          setBulkBusy]          = useState<boolean>(false);
  // Operador destino del selector "Asignar a…" en la barra de acciones masivas.
  const [bulkAssignTarget,  setBulkAssignTarget]  = useState<string>("");
  // Deep-link: ?case=<id> abre el panel lateral de detalle al montar.
  const [searchParams, setSearchParams] = useSearchParams();
  // Deep-link desde /leader: ?openHandover=true → abrir el panel al montar.
  useEffect(() => {
    if (searchParams.get("openHandover") === "true") {
      setShowHandover(true);
      const next = new URLSearchParams(searchParams);
      next.delete("openHandover");
      setSearchParams(next, { replace: true });
    }
    // Deep-link desde /hunt (tab "Puertos atacados"): ?search=dport:NN
    // Setea el search input para que el DSL haga su parsing al blur/Enter.
    // El segundo param (_hint) es solo informativo, lo limpiamos también.
    const incomingSearch = searchParams.get("search");
    if (incomingSearch) {
      setSearch(incomingSearch);
      const next = new URLSearchParams(searchParams);
      next.delete("search");
      next.delete("_hint");
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);
  // Deep-link desde /triage o /leader: ?preset=mine|critical|mine-escalated|…
  // → aplica el preset y limpia el query param. Guard via ref: solo se
  // ejecuta una vez por sesión de montaje, sin importar cuántos re-renders
  // ocurran después. Aplica la lógica inline (no usa applyQuickPreset que
  // está definida más abajo) para evitar forward references.
  const presetAppliedRef = useRef(false);
  useEffect(() => {
    if (presetAppliedRef.current) return;
    const preset = searchParams.get("preset");
    if (!preset) return;
    // Mapeo plano sin colores (los presets visuales se evalúan en
    // QUICK_PRESETS abajo, pero acá solo necesitamos los filtros).
    const PRESET_FILTERS: Record<string, {
      sev?: Severity | "ALL"; status?: CaseStatus | "ALL";
      assignedTo?: "" | "__me__" | "__unassigned__"; includeClosed?: boolean;
    }> = {
      mine:              { assignedTo: "__me__",         includeClosed: false, sev: "ALL", status: "ALL" },
      critical:          { assignedTo: "__unassigned__", includeClosed: false, sev: "CRITICAL", status: "ALL" },
      unowned:           { assignedTo: "__unassigned__", includeClosed: false, sev: "ALL", status: "ALL" },
      escalated:         { assignedTo: "",               includeClosed: false, sev: "ALL", status: "ESCALADO" },
      newL1:             { assignedTo: "__unassigned__", includeClosed: false, sev: "ALL", status: "NUEVO" },
      "mine-escalated":  { assignedTo: "__me__",         includeClosed: false, sev: "ALL", status: "ESCALADO" },
    };
    const p = PRESET_FILTERS[preset];
    if (p) {
      if (p.sev !== undefined) setSevFilter(p.sev);
      if (p.status !== undefined) setStatusFilter(p.status);
      if (p.assignedTo !== undefined) setAssignedTo(p.assignedTo);
      if (p.includeClosed !== undefined) setIncludeClosed(p.includeClosed);
      setPage(1);
    }
    presetAppliedRef.current = true;
    const next = new URLSearchParams(searchParams);
    next.delete("preset");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);
  const { preferredUsername } = useAuth();
  // P1 #13: identidad resuelta desde la sesión (JWT → soc_operators.id). Es la
  // fuente de verdad del CI; siembra localStorage para que los flujos que usan
  // loadOperatorCi() dejen de pedirlo por window.prompt.
  const sessionIdentity = useOperatorIdentity();
  // CI real de soc_operators > username KC > localStorage (fallback sin sesión).
  const operatorCi = sessionIdentity?.ci ?? preferredUsername ?? loadOperatorCi();
  // Paneles secundarios — ahora viven en un sidebar derecho (SideDrawer). Sólo
  // uno abierto a la vez: openPanel(id) activa el elegido y cierra los demás.
  const [showProfiles,      setShowProfiles]      = useState(false);
  const [showSuppressions,  setShowSuppressions]  = useState(false);
  const [showDuplicates,    setShowDuplicates]    = useState(false);
  const [showHandover,      setShowHandover]      = useState(false);
  const [showBulkClose,     setShowBulkClose]     = useState(false);
  type PanelId = "profiles" | "suppressions" | "duplicates" | "handover" | "bulkClose";
  const openPanel = useCallback((id: PanelId) => {
    setShowProfiles(id === "profiles");
    setShowSuppressions(id === "suppressions");
    setShowDuplicates(id === "duplicates");
    setShowHandover(id === "handover");
    setShowBulkClose(id === "bulkClose");
  }, []);
  // Resumen operativo (Mi trabajo + KPIs + Sistema) colapsable y persistido —
  // despeja la franja superior cuando el operador ya conoce su estado.
  const [summaryCollapsed, setSummaryCollapsed] = useState<boolean>(() => {
    try { return localStorage.getItem("lh.cm.summaryCollapsed") === "1"; } catch { return false; }
  });
  const toggleSummary = useCallback(() => {
    setSummaryCollapsed((v) => {
      const next = !v;
      try { localStorage.setItem("lh.cm.summaryCollapsed", next ? "1" : "0"); } catch { /* private mode */ }
      return next;
    });
  }, []);
  // Filtros avanzados (clase eCSIRT, rango de fechas, tamaño de página) plegados
  // por defecto — la fila primaria queda con búsqueda/severidad/estado/owner.
  const [showAdvFilters, setShowAdvFilters] = useState<boolean>(() => {
    try { return localStorage.getItem("lh.cm.advFilters") === "1"; } catch { return false; }
  });
  const toggleAdvFilters = useCallback(() => {
    setShowAdvFilters((v) => {
      const next = !v;
      try { localStorage.setItem("lh.cm.advFilters", next ? "1" : "0"); } catch { /* private mode */ }
      return next;
    });
  }, []);
  const [escBusy,           setEscBusy]           = useState(false);
  const [escMsg,            setEscMsg]            = useState<string | null>(null);
  /** Preview del bulk escalate (dryRun del backend). Si no es null, el
   *  operador aún no confirmó la operación. */
  const [bulkPreview, setBulkPreview] = useState<{
    wouldEscalate: number;
    belowThreshold: number;
    skippedByStatus: number;
    bySev: Record<string, number>;
  } | null>(null);
  // Obtener rol del operador para permisos de UI
  const { data: operators } = useSocOperators();
  const currentOperator = operators?.find((o) => o.id === operatorCi) ?? null;
  const operatorRole = currentOperator?.role_id ?? null;

  // Mapa CI → nombre completo. Alimenta la visualización en las tablas /
  // chips: "Roberto Insfran" en lugar de "3988739". El CI sigue siendo la
  // identidad canónica en filtros, URLs y tooltips de auditoría.
  const operatorNames = useMemo(() => {
    const m: Record<string, string> = {};
    for (const o of operators ?? []) {
      if (o?.id && o?.name) m[String(o.id)] = String(o.name);
    }
    return m;
  }, [operators]);

  const statusDist = useStatusDist();
  // P1.6 (audit 2026-05-27): el banner "X casos sin asignar" cierra el flujo
  // con un click directo si hay Shift Manager activo. Si no, el botón se
  // oculta y queda sólo "Ver sin asignar" (filtro pasivo).
  const { data: currentShiftMgr } = useShiftManager();
  // RBAC UI: el Asistente de cierre masivo SÓLO se muestra al Shift Manager
  // activo (el backend repite la validación). No a LEADER/ADMIN que no sea SM.
  const isActiveShiftManager =
    !!operatorCi && !!currentShiftMgr?.id && currentShiftMgr.id === operatorCi;
  const [bulkAssignSmBusy, setBulkAssignSmBusy] = useState(false);

  // P1.8 (audit 2026-05-27): los atajos J/K/⏎/A/I/? existen desde C1 (2026-04)
  // pero nunca tuvieron discoverability. La primera vez que un operador abre
  // /gestion mostramos un toast persistente apuntando a `?`. Flag local-only
  // — si limpiás localStorage, vuelve a aparecer (deliberado, no es feature).
  useEffect(() => {
    const FLAG = "lh.shortcuts.intro_seen";
    try {
      if (localStorage.getItem(FLAG) === "1") return;
      // Pequeño delay para que el toast aparezca DESPUÉS del render inicial —
      // si dispara durante mount, se pisa con el resto del paint.
      const t = setTimeout(() => {
        toast("⌨ Probá `?` para ver los atajos de teclado", {
          description: "j/k navegan, ⏎ abre detalle, a adopta.",
          duration: 1000,
        });
        try { localStorage.setItem(FLAG, "1"); } catch { /* private mode */ }
      }, 800);
      return () => clearTimeout(t);
    } catch { /* localStorage bloqueado → no romper la vista */ }
  }, []);

  /**
   * Paso 1 del bulk escalate: dryRun al backend para obtener el conteo por
   *  severidad. No muta nada — deja al operador confirmar antes de ejecutar.
   *  El backend /bulk-escalate-unadopted ya soporta dryRun:true desde
   *  incidents.mjs:3399, así que el preview no requiere ningún cambio extra.
   */
  async function handleBulkEscalate() {
    const ci = operatorCi;
    if (ci.trim().length < 5) {
      setEscMsg("Registra tu CI primero (botón 'Registrarme').");
      return;
    }
    setEscBusy(true); setEscMsg(null); setBulkPreview(null);
    try {
      const { data: d } = await api.post<{
        ok?: boolean;
        would_escalate?: number;
        below_threshold?: number;
        skipped_by_status?: number;
        cases?: Array<{ case_id: string; severity: string }>;
        error?: string;
      }>("/api/incidents/bulk-escalate-unadopted", { operatorCi: ci.trim(), dryRun: true });
      const bySev: Record<string, number> = {};
      for (const c of d.cases ?? []) {
        const sev = String(c.severity ?? "LOW").toUpperCase();
        bySev[sev] = (bySev[sev] ?? 0) + 1;
      }
      if ((d.would_escalate ?? 0) === 0) {
        setEscMsg(`Sin casos para escalar. Bajo umbral: ${d.below_threshold ?? 0}${
          d.skipped_by_status ? ` · saltados por estado: ${d.skipped_by_status}` : ""
        }`);
      } else {
        setBulkPreview({
          wouldEscalate:   d.would_escalate ?? 0,
          belowThreshold:  d.below_threshold ?? 0,
          skippedByStatus: d.skipped_by_status ?? 0,
          bySev,
        });
      }
    } catch (e) {
      setEscMsg(`Error: ${e instanceof Error ? e.message : String(e)}`);
    } finally { setEscBusy(false); }
  }

  /**
   * P1.6 — Asigna en lote a los unassigned-open al Shift Manager activo.
   * Flujo:
   *   1) confirm() con el nombre del SM y la cuenta (cap 100, server-side cap 200)
   *   2) GET /api/incidents/open?assignedTo=__unassigned__&pageSize=100 → IDs
   *   3) POST /api/incidents/bulk-assign con caseIds + targetCi
   *   4) toast + void refetch()
   * No corremos un dryRun separado porque la cuenta ya vive en kpis.unassignedOpen
   * y el backend rebota silenciosamente casos cerrados (best-effort), así que
   * el riesgo de "asignar de más" es nulo.
   */
  async function handleBulkAssignToSM() {
    const target = currentShiftMgr;
    if (!target?.id) {
      toast.error("No hay Shift Manager activo");
      return;
    }
    const unassignedTotal = kpis?.unassignedOpen ?? 0;
    const BATCH_CAP = 100;
    const willAssign = Math.min(unassignedTotal, BATCH_CAP);
    if (willAssign <= 0) return;

    const ok = window.confirm(
      `Asignar ${willAssign} caso${willAssign === 1 ? "" : "s"} sin owner ` +
      `a ${target.name ?? target.id} (${target.id})?` +
      (unassignedTotal > BATCH_CAP
        ? `\n\nSólo los primeros ${BATCH_CAP} de ${unassignedTotal} se asignan ahora.`
        : ""),
    );
    if (!ok) return;

    setBulkAssignSmBusy(true);
    try {
      // Traemos sólo IDs — pageSize alto evita N requests. Backend cap 200,
      // acá pedimos hasta 100 para coincidir con BATCH_CAP.
      const { data: lst } = await api.get<{ cases?: Array<{ id: string }> }>(
        `/api/incidents/open?assignedTo=__unassigned__&pageSize=${BATCH_CAP}&page=1&severity=ALL&status=ALL&sort=created_at&sortDir=desc`,
      );
      const caseIds = (lst.cases ?? []).map(c => String(c.id)).filter(Boolean);
      if (caseIds.length === 0) {
        toast.info("No quedan casos sin asignar");
        return;
      }
      const { data: d } = await api.post<{
        ok?: boolean; assigned?: number; skipped?: number; errors?: number;
        target?: { ci: string; name?: string };
      }>("/api/incidents/bulk-assign", {
        caseIds,
        targetCi: target.id,
        reason: `Distribución de backlog huérfano por ${operatorCi || "LEADER"}`,
      });
      const assigned = d.assigned ?? 0;
      const skipped  = d.skipped  ?? 0;
      toast.success(
        `${assigned} caso${assigned === 1 ? "" : "s"} asignado${assigned === 1 ? "" : "s"} a ${d.target?.name ?? target.id}`,
        skipped > 0
          ? { description: `${skipped} omitido${skipped === 1 ? "" : "s"} (cerrado o ya reasignado)` }
          : undefined,
      );
      void refetch();
    } catch (e) {
      toast.error("Error al asignar en lote", {
        description: e instanceof Error ? e.message : String(e),
      });
    } finally { setBulkAssignSmBusy(false); }
  }

  /** Paso 2: ejecución real tras confirmación del operador. */
  async function confirmBulkEscalate() {
    const ci = operatorCi;
    if (ci.trim().length < 5) return;
    setEscBusy(true); setEscMsg(null);
    try {
      const { data: d } = await api.post<{
        ok?: boolean;
        escalated?: number;
        below_threshold?: number;
        escalated_to?: { label?: string; name?: string; ci?: string; source?: string };
      }>(
        "/api/incidents/bulk-escalate-unadopted",
        { operatorCi: ci.trim() },
      );
      const target = d.escalated_to?.label ?? "SOC Leader";
      const sourceTag = d.escalated_to?.source === "FALLBACK_LEADER"
        ? " (LEADER fallback, sin Shift Manager designado)"
        : d.escalated_to?.source === "SHIFT_MANAGER" ? " (Shift Manager activo)" : "";
      setEscMsg(`Escalados: ${d.escalated} casos a ${target}${sourceTag}.${
        d.below_threshold ? ` Sin umbral: ${d.below_threshold}.` : ""
      }`);
      setBulkPreview(null);
      void refetch();
    } catch (e) {
      setEscMsg(`Error: ${e instanceof Error ? e.message : String(e)}`);
    } finally { setEscBusy(false); }
  }

  const profiles = useMemo(() => loadProfiles(), []);
  const {
    cases,
    total,
    kpis,
    isLoading,
    isLoadingKpis,
    isError,
    errorMessage,
    refetch,
    adoptCase,
    facets,
  } = useCaseManagement({
    severity: sevFilter,
    status:   statusFilter,
    search,
    page,
    pageSize,
    sort,
    sortDir,
    dateFrom: dateFrom || undefined,
    dateTo:   dateTo   || undefined,
    // Resolver __me__ al CI actual antes de enviar al backend
    assignedTo:   assignedTo === "__me__" ? (operatorCi || undefined)
                : assignedTo               ? assignedTo
                :                            undefined,
    assignedRole: assignedRoles.length > 0 ? assignedRoles.join(",") : undefined,
    includeClosed,
    scoreMin,
    scoreMax,
    createdAtMin: createdAtMin || undefined,
    createdAtMax: createdAtMax || undefined,
    incidentClass: classFilter !== "ALL" ? classFilter : undefined,
  });

  useEffect(() => {
    const id = searchParams.get("case") ?? searchParams.get("investigate");
    if (!id || cases.length === 0) return;
    const found = cases.find((c) => c.id === id);
    if (found) setSelectedCase(found);
    const next = new URLSearchParams(searchParams);
    next.delete("case");
    next.delete("investigate");
    setSearchParams(next, { replace: true });
  }, [searchParams, cases, setSearchParams]);

  // Real-time: refetch cuando otro operador cambia un caso
  useCaseUpdates(useCallback(() => { void refetch(); }, [refetch]));

  /**
   * Reordenamiento client-side por "prioridad L1" cuando el sort por defecto
   * (severity) está activo. Sirve como tie-break visual dentro de la página:
   *  escalados > CRITICAL/HIGH sin adoptar > resto sin adoptar > adoptados >
   *  cerrados. Si el operador eligió otro sort explícito (score, creado, …)
   *  respetamos su criterio y no reordenamos.
   *
   * Nota: la paginación la resuelve el backend, así que esto solo reordena lo
   * ya visible — suficiente para el preset L1 (status=NUEVO) donde casi todos
   * son del mismo cubo y el orden fino ayuda.
   */
  const displayCases = useMemo(() => {
    if (sort !== "severity") return cases;
    return [...cases].sort((a, b) => {
      const pa = casePriorityBucket(a);
      const pb = casePriorityBucket(b);
      if (pa !== pb) return pa - pb;
      const sa = SEV_RANK[a.severity] ?? 99;
      const sb = SEV_RANK[b.severity] ?? 99;
      if (sa !== sb) return sa - sb;
      const ta = a.createdAt ? Date.parse(a.createdAt) : 0;
      const tb = b.createdAt ? Date.parse(b.createdAt) : 0;
      return tb - ta;
    });
  }, [cases, sort]);

  // A4 — Lista renderizada con agrupamiento opcional por activo (hostname/IP).
  type RenderItem =
    | { kind: "single"; case: SocCase }
    | { kind: "group";  groupKey: string; label: string; leader: SocCase; members: SocCase[]; expanded: boolean };
  const groupKeyOf = useCallback((c: SocCase): { key: string; label: string } => {
    const key = c.hostname || c.srcIp || c.id;
    const label = c.hostname || c.srcIp || "—";
    return { key, label };
  }, []);
  const renderedCases = useMemo<RenderItem[]>(() => {
    if (groupMode === "none") return displayCases.map((c) => ({ kind: "single", case: c }));
    const groups = new Map<string, { label: string; members: SocCase[] }>();
    for (const c of displayCases) {
      const { key, label } = groupKeyOf(c);
      const g = groups.get(key) ?? { label, members: [] };
      g.members.push(c);
      groups.set(key, g);
    }
    const out: RenderItem[] = [];
    for (const [key, g] of groups) {
      // Agrupar por táctica: incluso un único caso se muestra bajo su cabecera
      // (la táctica es una dimensión de clasificación, no de deduplicación).
      // Agrupar por IOC: un caso solo se renderiza plano (no es un "duplicado").
      if (g.members.length === 1 && groupMode === "activo") {
        out.push({ kind: "single", case: g.members[0] });
      } else {
        out.push({
          kind: "group", groupKey: key, label: g.label,
          leader: g.members[0],      // ya vienen ordenados por severidad
          members: g.members,
          expanded: expandedGroups.has(key),
        });
      }
    }
    return out;
  }, [displayCases, groupMode, expandedGroups, groupKeyOf]);

  function toggleGroup(key: string) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  // Title del tab con contador de CRITICAL sin adoptar. Operador en otro
  // tab del navegador detecta casos nuevos sin tener que volver a LegacyHunt.
  useEffect(() => {
    const baseTitle = "LegacyHunt SOC";
    const n = kpis?.criticalUnadopted ?? 0;
    document.title = n > 0 ? `(${n}) ⚠ ${baseTitle}` : baseTitle;
    return () => { document.title = baseTitle; };
  }, [kpis?.criticalUnadopted]);

  // Notificación push + sonido cuando *aumenta* criticalUnadopted. La idea
  // es alertar de CRITICAL nuevos, no recordar los que ya están abiertos:
  // por eso comparamos contra el conteo anterior (ref). Pide permiso de
  // Notification al primer hit; si el usuario lo niega, fallback silencioso
  // al cambio de title. Audio file en /public/sounds/critical-alert.mp3
  // (si no existe, el .play() falla silenciosamente).
  const prevCriticalRef = useRef<number | null>(null);
  useEffect(() => {
    const n = kpis?.criticalUnadopted ?? 0;
    const prev = prevCriticalRef.current;
    prevCriticalRef.current = n;
    if (prev === null) return; // primer render — no notificar
    if (n <= prev) return;     // sólo subidas
    // Desktop notification (manejo de permiso)
    if (typeof Notification !== "undefined") {
      if (Notification.permission === "default") {
        Notification.requestPermission().catch(() => {});
      }
      if (Notification.permission === "granted") {
        try {
          new Notification("⚠ CRITICAL sin adoptar", {
            body: `${n} caso${n !== 1 ? "s" : ""} requiere${n === 1 ? "" : "n"} atención inmediata`,
            tag: "lh-critical-unadopted",
            silent: false,
          });
        } catch { /* navegadores sin soporte completo */ }
      }
    }
    // Audio (best-effort, sin throw si autoplay block)
    try {
      const audio = new Audio("/sounds/critical-alert.mp3");
      audio.volume = 0.5;
      void audio.play().catch(() => {});
    } catch { /* sin audio */ }
  }, [kpis?.criticalUnadopted]);

  // Handlers estables por caso — habilitan React.memo en CaseRow.
  // Definidos aquí porque el effect de hotkeys los necesita en deps.
  // No dependen de `c` a nivel closure: la fila inyecta su propio case al click.
  const handleSelectCase = useCallback((c: SocCase) => setSelectedCase(c), []);
  // Refetch estable para refrescar la cola tras una transición inline de estado.
  const handleCaseChanged = useCallback(() => { void refetch(); }, [refetch]);

  // ── Multi-select (P0 #12) ──────────────────────────────────────────────────
  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);
  const clearSelection = useCallback(() => setSelectedIds(new Set()), []);

  // Seleccionar/deseleccionar TODOS los casos de la página actual. displayCases
  // es la lista plana de la página (incluye los miembros de grupos colapsados),
  // así que cubre todo lo visible aunque "Agrupar por IOC" esté activo.
  const pageCaseIds = useMemo(() => displayCases.map((c) => c.id), [displayCases]);
  const allPageSelected = pageCaseIds.length > 0 && pageCaseIds.every((id) => selectedIds.has(id));
  const somePageSelected = !allPageSelected && pageCaseIds.some((id) => selectedIds.has(id));
  const toggleSelectAllPage = useCallback(() => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      const allSel = pageCaseIds.length > 0 && pageCaseIds.every((id) => next.has(id));
      pageCaseIds.forEach((id) => (allSel ? next.delete(id) : next.add(id)));
      return next;
    });
  }, [pageCaseIds]);

  // ── Vistas guardadas (P2 #15) ──────────────────────────────────────────────
  const handleSaveView = useCallback(() => {
    const name = window.prompt("Nombre de la vista (combo de filtros actual):", "");
    if (!name?.trim()) return;
    const current: PersistedCaseFilters = {
      severity: sevFilter, status: statusFilter, search,
      pageSize, sort, sortDir, dateFrom, dateTo,
      assignedTo, assignedRole: assignedRoles.join(","),
      includeClosed, scoreMin, scoreMax, createdAtMin, createdAtMax,
      incidentClass: classFilter,
    };
    setSavedViews(upsertSavedView(name, current));
  }, [sevFilter, statusFilter, search, pageSize, sort, sortDir, dateFrom, dateTo,
      assignedTo, assignedRoles, includeClosed, scoreMin, scoreMax, createdAtMin, createdAtMax, classFilter]);

  const applySavedView = useCallback((f: PersistedCaseFilters) => {
    setSevFilter(f.severity); setStatusFilter(f.status); setSearch(f.search);
    setPageSize(f.pageSize); setSort(f.sort); setSortDir(f.sortDir);
    setDateFrom(f.dateFrom); setDateTo(f.dateTo);
    setAssignedTo(f.assignedTo); setAssignedRoles((f.assignedRole ?? "").split(",").filter(Boolean));
    setIncludeClosed(f.includeClosed);
    setScoreMin(f.scoreMin ?? null); setScoreMax(f.scoreMax ?? null);
    setCreatedAtMin(f.createdAtMin ?? ""); setCreatedAtMax(f.createdAtMax ?? "");
    setClassFilter(f.incidentClass ?? "ALL");
    setPage(1);
  }, []);

  const handleDeleteView = useCallback((name: string) => {
    setSavedViews(deleteSavedView(name));
  }, []);

  /** Acción masiva de estado (P0 #12) → POST /api/incidents/bulk-status.
   *  El backend reusa workflowEngine.transitionCase por caso (todos los gates:
   *  postmortem, 4-eyes, clasificación, RBAC), así que los fallos por-caso se
   *  reportan sin abortar el batch. */
  const runBulkStatus = useCallback(async (status: string, label: string) => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    const reason = window.prompt(
      `Motivo para "${label}" ${ids.length} caso(s) (mín. 80 chars si alguno es FP escalado; postmortem≥60 ya debe estar grabado en cierres MEDIUM+):`,
      "",
    );
    if (reason === null) return;   // cancelado
    setBulkBusy(true);
    try {
      const { data } = await api.post<{
        ok: boolean; total: number; succeeded: number; failed: number;
        results?: Array<{ id: string; ok: boolean; error?: string }>;
      }>("/api/incidents/bulk-status", { caseIds: ids, status, reason: reason || undefined },
        { timeout: 120_000 });   // lote: más holgado que el default 60s
      if (data.failed > 0) {
        const firstErr = data.results?.find((r) => !r.ok)?.error;
        toast.warning(`${data.succeeded}/${data.total} aplicados · ${data.failed} fallaron`, {
          description: firstErr ? `Ej.: ${firstErr}` : undefined,
        });
      } else {
        toast.success(`${data.succeeded} caso(s) → ${label}`);
      }
      clearSelection();
      void refetch();
    } catch (e) {
      toast.error("Error en acción masiva", { description: e instanceof Error ? e.message : String(e) });
    } finally {
      setBulkBusy(false);
    }
  }, [selectedIds, clearSelection, refetch]);

  // Cierre FORZADO en lote (solo ADMIN/LEADER): cierra los casos seleccionados en
  // cualquier estado y OMITE el postmortem. Distinto de runBulkStatus("CERRADO"),
  // que sí exige postmortem≥60 en MEDIUM+. Manda force:true al backend, que valida
  // el rol server-side. Doble confirmación porque es irreversible y masivo.
  const runBulkForceClose = useCallback(async () => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    const reason = window.prompt(
      `CIERRE FORZADO de ${ids.length} caso(s) SIN postmortem (solo ADMIN/LEADER).\n` +
        `Cierra los casos en cualquier estado y omite el postmortem. Motivo (queda auditado):`,
      "",
    );
    if (reason === null) return;   // cancelado
    if (!window.confirm(`¿Confirmás el cierre forzado de ${ids.length} caso(s) sin postmortem?`)) return;
    setBulkBusy(true);
    try {
      const { data } = await api.post<{
        ok: boolean; total: number; succeeded: number; failed: number;
        results?: Array<{ id: string; ok: boolean; error?: string }>;
      }>("/api/incidents/bulk-status", {
        caseIds: ids, status: "CERRADO", force: true, reason: reason || undefined,
      }, { timeout: 120_000 });   // lote: más holgado que el default 60s
      if (data.failed > 0) {
        const firstErr = data.results?.find((r) => !r.ok)?.error;
        toast.warning(`${data.succeeded}/${data.total} cerrados · ${data.failed} fallaron`, {
          description: firstErr ? `Ej.: ${firstErr}` : undefined,
        });
      } else {
        toast.success(`${data.succeeded} caso(s) cerrados (forzado, sin postmortem)`);
      }
      clearSelection();
      void refetch();
    } catch (e) {
      toast.error("Error en cierre forzado", { description: e instanceof Error ? e.message : String(e) });
    } finally {
      setBulkBusy(false);
    }
  }, [selectedIds, clearSelection, refetch]);

  // ── Asignación masiva (P0) → POST /api/incidents/bulk-assign ────────────────
  // LEADER/ADMIN asigna a cualquier operador; un no-líder sólo puede
  // autoasignarse (targetCi === su CI — "Tomar yo", adopción masiva).
  const runBulkAssign = useCallback(async (targetCi: string, targetLabel: string) => {
    const ids = [...selectedIds];
    if (ids.length === 0 || !targetCi) return;
    if (!window.confirm(`¿Asignar ${ids.length} caso(s) a ${targetLabel}?`)) return;
    setBulkBusy(true);
    try {
      const { data } = await api.post<{
        ok: boolean; assigned?: number; skipped?: number; errors?: number;
        target?: { name?: string };
      }>("/api/incidents/bulk-assign",
        { caseIds: ids, targetCi, reason: `Asignación en lote desde la cola por ${operatorCi || "operador"}` },
        { timeout: 120_000 });
      const n = data.assigned ?? 0;
      toast.success(`${n} caso(s) asignado(s) a ${data.target?.name ?? targetLabel}`, {
        description: (data.skipped ?? 0) > 0 ? `${data.skipped} omitido(s) (cerrado o ya reasignado)` : undefined,
      });
      clearSelection();
      void refetch();
    } catch (e) {
      const status = (e as { response?: { status?: number } }).response?.status;
      const msg = (e as { response?: { data?: { error?: string } } }).response?.data?.error
        ?? (e instanceof Error ? e.message : String(e));
      toast.error(status === 403 ? "Sin permisos para asignar a ese operador" : "Error al asignar", { description: msg });
    } finally {
      setBulkBusy(false);
    }
  }, [selectedIds, operatorCi, clearSelection, refetch]);

  // ── Agrupar la selección en 1 caso (merge manual cross-IOC) ─────────────────
  // Canónico = mayor severidad, desempate por más antiguo. Los demás quedan
  // CERRADO → canónico (merged_into_case_id). Gated LEADER/ADMIN + motivo en
  // backend (manual:true salta la validación de mismo-IOC).
  const runBulkMergeSelected = useCallback(async () => {
    const sel = displayCases.filter((c) => selectedIds.has(c.id));
    if (sel.length < 2) { toast.warning("Seleccioná al menos 2 casos para agrupar"); return; }
    const canon = [...sel].sort((a, b) => {
      const sr = (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99);
      if (sr !== 0) return sr;
      return (a.createdAt ? Date.parse(a.createdAt) : 0) - (b.createdAt ? Date.parse(b.createdAt) : 0);
    })[0];
    const dups = sel.filter((c) => c.id !== canon.id);
    const distinctIocs = new Set(sel.map((c) => c.srcIp || c.id)).size;
    const reason = window.prompt(
      `Agrupar ${sel.length} caso(s) en 1 ${distinctIocs > 1 ? `(${distinctIocs} IOCs distintos)` : "(mismo IOC)"}.\n` +
      `Canónico: ${caseCode(canon)} [${canon.severity}] ${canon.srcIp}.\n` +
      `Los demás quedarán CERRADO → canónico. Motivo (mín. 10 caracteres):`, "");
    if (reason === null) return;
    if (reason.trim().length < 10) { toast.warning("Motivo demasiado corto (mín. 10 caracteres)"); return; }
    setBulkBusy(true);
    try {
      const { data } = await api.post<{ ok: boolean; merged?: number }>("/api/incidents/merge", {
        canonicalCaseId: canon.id, duplicateCaseIds: dups.map((c) => c.id),
        operatorCi, manual: true, reason: reason.trim(),
      }, { timeout: 120_000 });
      toast.success(`${data.merged ?? dups.length} caso(s) agrupados → ${caseCode(canon)}`);
      clearSelection();
      void refetch();
    } catch (e) {
      const status = (e as { response?: { status?: number } }).response?.status;
      const msg = (e as { response?: { data?: { error?: string } } }).response?.data?.error
        ?? (e instanceof Error ? e.message : String(e));
      toast.error(status === 403 ? "Sólo LEADER/ADMIN puede agrupar casos de distinto IOC" : "Error al agrupar", { description: msg });
    } finally {
      setBulkBusy(false);
    }
  }, [displayCases, selectedIds, operatorCi, clearSelection, refetch]);

  // ── Informe ejecutivo de los casos seleccionados ────────────────────────────
  // Pide la narrativa del analista LLM al backend (POST /api/reports/cases,
  // enfoque contexto + impacto de negocio) y renderiza el PDF cliente-side. Si el
  // LLM no responde, el informe sale igual con resumen + tabla (degradación).
  const exportSelectedReport = useCallback(async () => {
    const sel = displayCases.filter((c) => selectedIds.has(c.id));
    if (sel.length === 0) return;
    setBulkBusy(true);
    const tId = toast.loading("Generando informe ejecutivo (analista IA)…");
    try {
      let narrative = null, agg = null;
      try {
        const { data } = await api.post<{
          ok: boolean;
          narrative: import("@/lib/cases-report-pdf").CasesReportNarrative | null;
          agg: import("@/lib/cases-report-pdf").CasesReportAgg | null;
        }>("/api/reports/cases", { caseIds: sel.map((c) => c.id) }, { timeout: 120_000 });
        narrative = data.narrative; agg = data.agg;
      } catch (e) {
        // El reporte sigue siendo útil sin narrativa (resumen + tabla).
        toast.warning("Sin análisis IA — se genera el informe con resumen y detalle", {
          description: (e as { response?: { data?: { error?: string } } }).response?.data?.error,
        });
      }
      await exportSelectedCasesReportPdf({ cases: sel, operatorNames, generatedBy: operatorCi || null, narrative, agg });
      toast.success(`Informe de ${sel.length} caso(s) generado`, { id: tId });
    } catch (e) {
      toast.error("Error al generar el informe", { id: tId, description: e instanceof Error ? e.message : String(e) });
    } finally {
      setBulkBusy(false);
    }
  }, [displayCases, selectedIds, operatorNames, operatorCi]);
  /**
   * Adopción 1-click:
   *  - Si hay CI guardado y válido en localStorage → POST directo, sin modal.
   *  - Si no hay CI / es inválido → abre modal para pedirlo (se guardará).
   *  - Si hay conflict 409 u otro error → abre modal como fallback (la UI
   *    de transferencia ya está implementada allí).
   *
   * Refetch por invalidación del cache refleja el cambio en <500 ms; si se
   *  quiere feedback más inmediato se puede añadir optimistic update en
   *  useCaseManagement.adoptCase. La latencia actual es tolerable.
   */
  const handleAdoptCase = useCallback(async (c: SocCase) => {
    const ci = loadOperatorCi();
    if (!ci || validateCi(ci)) {
      setAdoptingCase(c);
      return;
    }
    try {
      await adoptCase(c.id, ci);
    } catch {
      setAdoptingCase(c);
    }
  }, [adoptCase]);

  // Hotkeys globales (mismo patrón que /triage):
  //   j / ArrowDown → siguiente fila
  //   k / ArrowUp   → anterior
  //   Enter         → abre detail sheet de la fila enfocada
  //   a             → adopta la fila enfocada (1-click)
  //   ?             → muestra/oculta ayuda
  //   Esc           → cierra ayuda
  useEffect(() => {
    function handler(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement | null)?.tagName?.toLowerCase();
      const isEditable = tag === "input" || tag === "textarea" || tag === "select"
        || (e.target as HTMLElement | null)?.isContentEditable;
      if (isEditable) return;
      if (selectedCase || adoptingCase) return;

      const len = displayCases.length;
      const c = focusIdx >= 0 && focusIdx < len ? displayCases[focusIdx] : null;

      switch (e.key) {
        case "j":
        case "ArrowDown":
          if (len > 0) {
            e.preventDefault();
            setFocusIdx(i => Math.min(i < 0 ? 0 : i + 1, len - 1));
          }
          break;
        case "k":
        case "ArrowUp":
          if (len > 0) {
            e.preventDefault();
            setFocusIdx(i => Math.max(i <= 0 ? 0 : i - 1, 0));
          }
          break;
        case "Enter":
          if (c) { e.preventDefault(); handleSelectCase(c); }
          break;
        case "a":
        case "A":
          if (c) { e.preventDefault(); void handleAdoptCase(c); }
          break;
        case "?":
          e.preventDefault();
          setShowHotkeysHelp(v => !v);
          break;
        case "Escape":
          if (showHotkeysHelp) { e.preventDefault(); setShowHotkeysHelp(false); }
          break;
      }
    }
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [displayCases, focusIdx, selectedCase, adoptingCase, showHotkeysHelp,
      handleSelectCase, handleAdoptCase]);

  // Scroll-into-view de la fila enfocada al cambiar focusIdx.
  useEffect(() => {
    if (focusIdx < 0) return;
    const c = displayCases[focusIdx];
    if (!c) return;
    const el = document.getElementById(`lh-case-row-${c.id}`);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [focusIdx, displayCases]);

  // Clamp focusIdx si la lista mostrada se acorta (cambio de filtros, etc).
  useEffect(() => {
    if (focusIdx >= displayCases.length) setFocusIdx(displayCases.length - 1);
  }, [displayCases.length, focusIdx]);

  // Reset page when filters change
  function applySevFilter(v: Severity | "ALL") { setSevFilter(v); setPage(1); }
  function applyStatusFilter(v: CaseStatus | "ALL") { setStatusFilter(v); setPage(1); }
  function applyClassFilter(v: string) { setClassFilter(v); setPage(1); }
  function applySearch(v: string) {
    // C10 + C5 — al confirmar la búsqueda (blur/Enter) parseamos tokens tipo
    // `sev:HIGH op:3988739 mitre:T1110 score:>150 age:<7d` y los seteamos como
    // filtros nativos, dejando en el input solo el texto libre. Esto ocurre
    // únicamente cuando detectamos al menos un token reconocido para no
    // interferir con los caracteres ":" usados en IPv6 o UUIDs pegados.
    const parsed = parseSearchSyntax(v);
    const consumed =
      parsed.severity !== undefined ||
      parsed.status   !== undefined ||
      parsed.assignedTo!== undefined ||
      parsed.role     !== undefined ||
      parsed.mitre    !== undefined ||
      parsed.source   !== undefined ||
      parsed.scoreMin !== undefined ||
      parsed.scoreMax !== undefined ||
      parsed.createdAtMin !== undefined ||
      parsed.createdAtMax !== undefined;
    if (consumed) {
      if (parsed.severity)   setSevFilter(parsed.severity);
      if (parsed.status)     setStatusFilter(parsed.status);
      if (parsed.assignedTo !== undefined) setAssignedTo(parsed.assignedTo);
      if (parsed.role)       setAssignedRoles(parsed.role.split(",").filter(Boolean));
      if (parsed.scoreMin !== undefined) setScoreMin(parsed.scoreMin);
      if (parsed.scoreMax !== undefined) setScoreMax(parsed.scoreMax);
      if (parsed.createdAtMin !== undefined) setCreatedAtMin(parsed.createdAtMin);
      if (parsed.createdAtMax !== undefined) setCreatedAtMax(parsed.createdAtMax);
      // `mitre` y `source` no son filtros del endpoint aún — los dejamos en el
      // texto libre para que `ILIKE %mitre%` en PG los matchee.
      const extra = [
        parsed.mitre  ? `mitre:${parsed.mitre}`   : "",
        parsed.source ? `source:${parsed.source}` : "",
      ].filter(Boolean).join(" ");
      setSearch([parsed.free, extra].filter(Boolean).join(" "));
    } else {
      setSearch(v);
    }
    setPage(1);
  }
  function applyPageSize(v: number) { setPageSize(v); setPage(1); }
  function applyDateFrom(v: string) { setDateFrom(v); setPage(1); }
  function applyDateTo(v: string)   { setDateTo(v);   setPage(1); }
  function clearDateRange() { setDateFrom(""); setDateTo(""); setPage(1); }
  function applyAssignedTo(v: string)   { setAssignedTo(v);   setPage(1); }
  function toggleAssignedRole(role: string) {
    setAssignedRoles((prev) =>
      prev.includes(role) ? prev.filter((r) => r !== role) : [...prev, role]
    );
    setPage(1);
  }
  function clearAssignedRoles() { setAssignedRoles([]); setPage(1); }
  function applyIncludeClosed(v: boolean) { setIncludeClosed(v); setPage(1); }

  function applySort(col: string) {
    if (sort === col) {
      setSortDir((d) => d === "asc" ? "desc" : "asc");
    } else {
      setSort(col);
      setSortDir("asc");
    }
    setPage(1);
  }

  // ── Chips de filtros activos ─────────────────────────────────────────────
  // Resumen compacto debajo del bar de filtros. Cada pill cierra SÓLO su
  // filtro; el botón "Limpiar todo" resetea los 6. No compite con los
  // controles primarios (sev/status/asignado) — complementa mostrando el
  // estado actual en una línea y facilitando quitar uno sin recorrer controles.
  type ActiveFilter = { key: string; label: string; clear: () => void };
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const out: ActiveFilter[] = [];
    if (sevFilter !== "ALL") {
      out.push({ key: "sev", label: `sev: ${sevFilter}`, clear: () => applySevFilter("ALL") });
    }
    if (statusFilter !== "ALL") {
      out.push({
        key: "status",
        label: `estado: ${STATUS_LABEL[statusFilter] ?? statusFilter}`,
        clear: () => applyStatusFilter("ALL"),
      });
    }
    if (classFilter !== "ALL") {
      out.push({
        key: "class",
        label: `clase: ${CLASS_LABEL[classFilter] ?? classFilter}`,
        clear: () => applyClassFilter("ALL"),
      });
    }
    if (search) {
      const short = search.length > 18 ? `${search.slice(0, 18)}…` : search;
      out.push({ key: "search", label: `búsqueda: "${short}"`, clear: () => applySearch("") });
    }
    if (assignedTo === "__me__") {
      out.push({ key: "assignedMe", label: "asignado: tú", clear: () => applyAssignedTo("") });
    } else if (assignedTo === "__unassigned__") {
      out.push({ key: "assignedNone", label: "sin owner", clear: () => applyAssignedTo("") });
    } else if (assignedTo) {
      out.push({ key: "assignedCi", label: `asignado: ${assignedTo}`, clear: () => applyAssignedTo("") });
    }
    if (assignedRoles.length) {
      out.push({
        key: "roles",
        label: `rol: ${assignedRoles.join(",")}`,
        clear: clearAssignedRoles,
      });
    }
    if (includeClosed) {
      out.push({ key: "closed", label: "incluye cerrados", clear: () => applyIncludeClosed(false) });
    }
    if (dateFrom) {
      out.push({ key: "from", label: `desde ${dateFrom}`, clear: () => applyDateFrom("") });
    }
    if (dateTo) {
      out.push({ key: "to", label: `hasta ${dateTo}`, clear: () => applyDateTo("") });
    }
    // C5 — chips para score y createdAt. score muestra el rango como existe
    // realmente (min, max o min-max). createdAt formatea ISO → fecha local
    // corta para evitar mostrar timestamps largos.
    if (scoreMin != null || scoreMax != null) {
      const label = scoreMin != null && scoreMax != null
        ? (scoreMin === scoreMax ? `score: ${scoreMin}` : `score: ${scoreMin}-${scoreMax}`)
        : scoreMin != null
          ? `score: ≥${scoreMin}`
          : `score: ≤${scoreMax}`;
      out.push({
        key: "score",
        label,
        clear: () => { setScoreMin(null); setScoreMax(null); setPage(1); },
      });
    }
    const fmtDate = (iso: string) => {
      const d = new Date(iso);
      return Number.isFinite(d.getTime()) ? formatDatePy(iso) : iso;
    };
    if (createdAtMin) {
      out.push({
        key: "createdMin",
        label: `creado ≥ ${fmtDate(createdAtMin)}`,
        clear: () => { setCreatedAtMin(""); setPage(1); },
      });
    }
    if (createdAtMax) {
      out.push({
        key: "createdMax",
        label: `creado ≤ ${fmtDate(createdAtMax)}`,
        clear: () => { setCreatedAtMax(""); setPage(1); },
      });
    }
    return out;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sevFilter, statusFilter, classFilter, search, assignedTo, assignedRoles, includeClosed, dateFrom, dateTo,
      scoreMin, scoreMax, createdAtMin, createdAtMax]);

  function clearAllFilters() {
    setSevFilter("ALL"); setStatusFilter("ALL"); setClassFilter("ALL"); setSearch("");
    setAssignedTo(""); setAssignedRoles([]); setIncludeClosed(false);
    setDateFrom(""); setDateTo("");
    setScoreMin(null); setScoreMax(null);
    setCreatedAtMin(""); setCreatedAtMax("");
    setPage(1);
  }

  // ── Vistas rápidas (audit 2026-05-13: consolidación) ───────────────────────
  // Antes había 2 barras (`Vistas:` + `Cola:`) con 9 botones y redundancias
  // (`CRITICAL sin adoptar` ↔ banner rojo; `Escalados` ↔ `Cola L3`; `Vista
  // LEADER` ↔ `CRITICAL`; `Cola L1L2` no filtraba nada). Quedaron 5 presets
  // útiles en una sola barra:
  //
  //   mine        — Mis abiertos (mi CI)
  //   critical    — Críticos sin adoptar (sev=CRITICAL + unassigned, cualquier
  //                  status; alineado con el banner rojo del KPI strip)
  //   unowned     — Sin asignar (todos los abiertos sin owner)
  //   escalated   — Escalados (status=ESCALADO, cualquier owner; ≡ Cola L3 antes)
  //   newL1       — Nuevos L1 (status=NUEVO sin owner — primera cola del SOC)
  //
  // Cola L2 (CONFIRMADO sin owner) y Cola L1/L2 (status=ALL = sin filtro) se
  // omitieron porque eran ~0 casos o no filtraban.
  type QuickPreset = {
    label: string;
    hint:  string;
    color: string;
    /** Filtros que aplica. undefined = no lo toca (igual que "ALL"/""). */
    sev?:           Severity | "ALL";
    status?:        CaseStatus | "ALL";
    assignedTo?:    "" | "__me__" | "__unassigned__";
    includeClosed?: boolean;
  };
  const QUICK_PRESETS: Record<string, QuickPreset> = {
    mine:      { label: "Mis abiertos",          hint: "Casos que adoptaste y siguen abiertos",
                 color: C.cyan,   assignedTo: "__me__",        includeClosed: false,
                 sev: "ALL",      status: "ALL" },
    critical:  { label: "Críticos sin adoptar",  hint: "CRITICAL abiertos sin owner — atención inmediata (cualquier status)",
                 color: C.red,    assignedTo: "__unassigned__", includeClosed: false,
                 sev: "CRITICAL", status: "ALL" },
    unowned:   { label: "Sin asignar",           hint: "Todos los casos abiertos sin owner — backlog huérfano",
                 color: C.orange, assignedTo: "__unassigned__", includeClosed: false,
                 sev: "ALL",      status: "ALL" },
    escalated: { label: "Escalados",             hint: "Casos en status=ESCALADO (handoff activo a L2/L3)",
                 color: C.purple, status: "ESCALADO",            includeClosed: false,
                 sev: "ALL",      assignedTo: "" },
    newL1:     { label: "Nuevos L1",             hint: "status=NUEVO sin owner — primera cola del turno",
                 color: C.blue,   status: "NUEVO",               includeClosed: false,
                 sev: "ALL",      assignedTo: "__unassigned__" },
    // C2.6 — usado por el deep-link "Escalados a mí" desde /triage.
    "mine-escalated": {
      label: "Mis escalados", hint: "Casos status=ESCALADO asignados a mí",
      color: C.orange, status: "ESCALADO", assignedTo: "__me__",
      sev: "ALL", includeClosed: false,
    },
  };

  function isQuickPresetActive(key: string): boolean {
    const p = QUICK_PRESETS[key];
    if (!p) return false;
    // Requiero igualdad en cada campo que el preset define — si el usuario
    // manualmente cambió algo, el preset deja de estar "activo" visualmente.
    if (p.sev        !== undefined && sevFilter     !== p.sev)        return false;
    if (p.status     !== undefined && statusFilter  !== p.status)     return false;
    if (p.assignedTo !== undefined && assignedTo    !== p.assignedTo) return false;
    if (p.includeClosed !== undefined && includeClosed !== p.includeClosed) return false;
    return true;
  }

  function applyQuickPreset(key: string) {
    const p = QUICK_PRESETS[key];
    if (!p) return;
    // Toggle: si ya está activo, limpio todos los campos que tocaba.
    if (isQuickPresetActive(key)) {
      if (p.sev        !== undefined) setSevFilter("ALL");
      if (p.status     !== undefined) setStatusFilter("ALL");
      if (p.assignedTo !== undefined) setAssignedTo("");
      if (p.includeClosed !== undefined) setIncludeClosed(false);
      setPage(1);
      return;
    }
    if (p.sev        !== undefined) setSevFilter(p.sev);
    if (p.status     !== undefined) setStatusFilter(p.status);
    if (p.assignedTo !== undefined) setAssignedTo(p.assignedTo);
    if (p.includeClosed !== undefined) setIncludeClosed(p.includeClosed);
    setPage(1);
  }

  // ── Carga personal (R12 audit 2026-05-13) ───────────────────────────────────
  // Antes este bloque iteraba `cases` (la página actual de 50 filas) y reportaba
  // counts locales — bug donde "Mis activos == En riesgo SLA == Tu carga" porque
  // los tres se cocinaban del mismo contador. Ahora usa GET /api/incidents/me
  // (cache 30s) que cuenta contra todo `incident_cases_pg` scopeado al CI del
  // JWT.
  //
  // Adaptamos al shape que esperaba el componente: { mine, mineAtRisk,
  // unassignedCritical, newToday }. `unassignedCritical` y `newToday` son
  // globales (no por operador) — los necesita el banner para empujar a la
  // próxima presa de adopción.
  const workload = useMyWorkload(Boolean(operatorCi));
  const myLoad = {
    mine:               workload.mineOpen,
    mineAtRisk:         workload.mineAtRisk,
    mineBreached:       workload.mineBreached,
    unassignedCritical: workload.criticalUnadopted,
    newToday:           workload.newUnassigned24h,
  };

  // R8: count global de grupos duplicados pendientes (PG-only, 60s stale).
  // Alimenta el badge en el botón "Duplicados" del header.
  const dupesCount = useDuplicatesCount();

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div style={{ background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "system-ui, sans-serif" }}>
      {/* Workflow Status Bar */}
      <WorkflowStatusBar operatorCi={operatorCi} operatorRole={operatorRole} />

      {/* Barra de acciones masivas (P0 #12) — flotante, sólo con selección. */}
      {selectedIds.size > 0 && (
        <div style={{
          position: "fixed", bottom: 20, left: "50%", transform: "translateX(-50%)",
          zIndex: 50, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
          justifyContent: "center", maxWidth: "min(96vw, 1180px)",
          background: C.card, border: `1px solid ${C.cyan}`,
          borderRadius: 10, padding: "10px 16px", boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
        }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>
            {selectedIds.size} seleccionado(s)
          </span>
          <div style={{ width: 1, height: 20, background: C.border }} />
          {([
            ["MONITOREADO", "Monitorear"],
            ["FALSO_POSITIVO", "Falso positivo"],
            ["CERRADO", "Cerrar"],
            ["ESCALADO", "Escalar"],
          ] as Array<[string, string]>).map(([st, lbl]) => (
            <button
              key={st}
              disabled={bulkBusy}
              onClick={() => void runBulkStatus(st, lbl)}
              style={{ ...btnStyle, color: C.text, opacity: bulkBusy ? 0.5 : 1 }}
            >
              {lbl}
            </button>
          ))}
          <div style={{ width: 1, height: 20, background: C.border }} />
          {/* Reporte de los casos seleccionados (PDF cliente-side) */}
          <button
            disabled={bulkBusy}
            onClick={() => void exportSelectedReport()}
            title="Generar un PDF con los casos seleccionados"
            style={{ ...btnStyle, color: C.cyan, opacity: bulkBusy ? 0.5 : 1, display: "flex", alignItems: "center", gap: 5 }}
          >
            <FileDown size={13} /> Reporte
          </button>
          {/* Tomar yo — autoasignación masiva (cualquier operador con CI) */}
          {operatorCi && (
            <button
              disabled={bulkBusy}
              onClick={() => void runBulkAssign(operatorCi, "ti")}
              title="Autoasignarte los casos seleccionados (los tomás vos)"
              style={{ ...btnStyle, color: C.cyan, opacity: bulkBusy ? 0.5 : 1, display: "flex", alignItems: "center", gap: 5 }}
            >
              <User size={13} /> Tomar yo
            </button>
          )}
          {/* Asignar a otro operador + Agrupar en 1 caso — LEADER/ADMIN */}
          {["ADMIN", "LEADER"].includes(String(operatorRole ?? "").toUpperCase()) && (
            <>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                <select
                  value={bulkAssignTarget}
                  disabled={bulkBusy}
                  onChange={(e) => setBulkAssignTarget(e.target.value)}
                  title="Asignar los casos seleccionados a un operador"
                  style={{
                    background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6,
                    padding: "5px 8px", color: C.text, fontSize: 12, maxWidth: 170,
                  }}
                >
                  <option value="">Asignar a…</option>
                  {operators?.filter((o) => o.is_active).map((o) => (
                    <option key={o.id} value={o.id}>{o.name} ({o.role_id})</option>
                  ))}
                </select>
                <button
                  disabled={bulkBusy || !bulkAssignTarget}
                  onClick={() => {
                    const op = operators?.find((o) => o.id === bulkAssignTarget);
                    void runBulkAssign(bulkAssignTarget, op?.name ?? bulkAssignTarget);
                  }}
                  style={{ ...btnStyle, color: C.text, opacity: (bulkBusy || !bulkAssignTarget) ? 0.5 : 1 }}
                >
                  Asignar
                </button>
              </span>
              <button
                disabled={bulkBusy || selectedIds.size < 2}
                onClick={() => void runBulkMergeSelected()}
                title="Fusionar los seleccionados en un caso canónico (mayor severidad). Permite IOCs distintos."
                style={{
                  ...btnStyle, color: C.purple, border: `1px solid ${alpha(C.purple, 40)}`,
                  opacity: (bulkBusy || selectedIds.size < 2) ? 0.5 : 1,
                  display: "flex", alignItems: "center", gap: 5,
                }}
              >
                <Layers size={13} /> Agrupar en 1
              </button>
            </>
          )}
          <div style={{ width: 1, height: 20, background: C.border }} />
          {/* Cierre FORZADO sin postmortem — solo ADMIN/LEADER. */}
          {["ADMIN", "LEADER"].includes(String(operatorRole ?? "").toUpperCase()) && (
            <button
              disabled={bulkBusy}
              onClick={() => void runBulkForceClose()}
              title="Cerrar los casos seleccionados en cualquier estado, omitiendo el postmortem (queda auditado)."
              style={{
                ...btnStyle, color: C.red, border: `1px solid ${alpha(C.red, 40)}`,
                background: alpha(C.red, 10), opacity: bulkBusy ? 0.5 : 1, fontWeight: 600,
              }}
            >
              Forzar cierre
            </button>
          )}
          <button onClick={clearSelection} disabled={bulkBusy}
            style={{ ...btnStyle, color: C.textDim }}>
            Limpiar
          </button>
        </div>
      )}

      {/* ── Sidebar derecho: paneles secundarios (uno a la vez) ──────────────── */}
      <SideDrawer open={showProfiles} onClose={() => setShowProfiles(false)} title="Perfiles de scoring">
        <ProfileSelector />
      </SideDrawer>
      <SideDrawer open={showSuppressions} onClose={() => setShowSuppressions(false)} title="IOCs suprimidos">
        <SuppressionPanel onClose={() => setShowSuppressions(false)} />
      </SideDrawer>
      <SideDrawer open={showDuplicates} onClose={() => setShowDuplicates(false)} title="Duplicados / fusión de casos" width={760}>
        <DuplicatePanel operatorCi={operatorCi} onClose={() => setShowDuplicates(false)} onMerged={() => void refetch()} />
      </SideDrawer>
      <SideDrawer open={showHandover} onClose={() => setShowHandover(false)} title="Handover de turno" width={720}>
        <HandoverPanel operatorCi={operatorCi} onClose={() => setShowHandover(false)} />
      </SideDrawer>
      {isActiveShiftManager && operatorCi && (
        <SideDrawer open={showBulkClose} onClose={() => setShowBulkClose(false)} title="Cierre masivo" width={820}>
          <BulkCloseAssistant
            operatorCi={operatorCi}
            onClose={() => setShowBulkClose(false)}
            onDone={() => void refetch()}
          />
        </SideDrawer>
      )}

      <div style={{ padding: "24px" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Shield size={20} color={C.cyan} />
          <span style={{ fontSize: 18, fontWeight: 700 }}>Gestión de Incidentes NOC</span>
          <span style={{ fontSize: 12, color: C.textDim }}>
            {total > 0 && `${total} caso${total !== 1 ? "s" : ""}`}
          </span>
          {operatorRole && (() => {
            const ROLE_COLOR: Record<string, string> = {
              LEADER: C.orange, ADMIN: C.red,
              L3: C.purple, L2: C.purple, L1L2: C.cyan, L1: C.blue,
            };
            const rc = ROLE_COLOR[operatorRole] ?? C.blue;
            return (
              <span style={{
                fontSize: 10, padding: "2px 8px", borderRadius: 4,
                background: alpha(rc, 12), color: rc, border: `1px solid ${alpha(rc, 25)}`,
                fontWeight: 600,
              }}>
                {operatorRole}
              </span>
            );
          })()}
          {operatorCi && myLoad.mine > 0 && (
            <button
              onClick={() => applyQuickPreset("mine")}
              title={`Tenés ${myLoad.mine} caso(s) abierto(s)${myLoad.mineBreached > 0 ? `, ${myLoad.mineBreached} con SLA vencido` : ""}${myLoad.mineAtRisk > 0 ? `, ${myLoad.mineAtRisk} por vencer` : ""}. Click para filtrar.`}
              style={{
                display: "inline-flex", alignItems: "center", gap: 6,
                fontSize: 10, padding: "2px 10px", borderRadius: 4,
                background: isQuickPresetActive("mine") ? alpha(C.cyan, 19) : alpha(C.cyan, 9),
                color: C.cyan, border: `1px solid ${alpha(C.cyan, 31)}`,
                fontWeight: 600, cursor: "pointer",
              }}
            >
              <User size={10} />
              <span>Tu carga: {myLoad.mine}</span>
              {myLoad.mineBreached > 0 && (
                <span
                  style={{
                    fontSize: 9, padding: "0 5px", borderRadius: 3, fontWeight: 700,
                    background: alpha(C.red, 19), color: C.red, border: `1px solid ${alpha(C.red, 38)}`,
                  }}
                  title={`${myLoad.mineBreached} con SLA vencido`}
                >
                  {myLoad.mineBreached}⛔
                </span>
              )}
              {myLoad.mineAtRisk > 0 && (
                <span
                  style={{
                    fontSize: 9, padding: "0 5px", borderRadius: 3, fontWeight: 700,
                    background: alpha(C.orange, 19), color: C.orange, border: `1px solid ${alpha(C.orange, 38)}`,
                  }}
                  title={`${myLoad.mineAtRisk} próximo(s) a vencer SLA`}
                >
                  {myLoad.mineAtRisk}⚠
                </span>
              )}
            </button>
          )}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {operatorCi && <NotificationBell operatorCi={operatorCi} />}
          <ExecutiveReportMenu
            visible={operatorRole === "LEADER" || operatorRole === "ADMIN"}
          />
          {/* Menú Herramientas — agrupa los paneles secundarios (ahora en sidebar). */}
          <HeaderMenu
            label="Herramientas"
            icon={Wrench}
            accent={C.cyan}
            badge={dupesCount.groupsCount}
            items={[
              { label: "Perfiles de scoring", icon: Layers, color: C.cyan, onClick: () => openPanel("profiles") },
              { label: "Duplicados", icon: Layers, color: dupesCount.groupsCount > 0 ? C.orange : C.text,
                badge: dupesCount.groupsCount, onClick: () => openPanel("duplicates"),
                title: dupesCount.groupsCount > 0
                  ? `${dupesCount.groupsCount} grupos · ${dupesCount.totalDuplicates} casos pendientes de fusión`
                  : "Sin duplicados pendientes" },
              { label: "Supresiones", icon: ShieldCheck, color: C.orange, onClick: () => openPanel("suppressions"),
                title: "IOCs suprimidos (no generan nuevos casos mientras estén activos)" },
              { label: "Handover de turno", icon: FileText, color: C.green, onClick: () => openPanel("handover"),
                hidden: !(operatorRole === "LEADER" || operatorRole === "ADMIN") },
            ]}
          />
          {/* Menú Acciones masivas — escalar / cierre masivo. */}
          <HeaderMenu
            label="Acciones"
            icon={MoreHorizontal}
            accent={C.orange}
            items={[
              { label: "Escalar no adoptados", icon: RefreshCw, color: C.orange, disabled: escBusy,
                onClick: () => void handleBulkEscalate(),
                title: "Escala a SOC Leader los casos sin adoptar que superaron el umbral por severidad" },
              { label: "Cierre masivo", icon: ShieldCheck, color: C.orange,
                hidden: !isActiveShiftManager, onClick: () => openPanel("bulkClose"),
                title: "Asistente de cierre masivo — sólo Shift Manager activo" },
            ]}
          />
          <button
            onClick={refetch}
            disabled={isLoading}
            style={{ ...btnStyle, display: "flex", alignItems: "center", gap: 5 }}
          >
            <RefreshCw size={13} style={{ animation: isLoading ? "spin 0.8s linear infinite" : undefined }} />
            Actualizar
          </button>
          {/* P1.8 — Chip permanente con atajos: abre el modal de ayuda (mismo
              que dispara `?`). Visible siempre para discoverability — no
              depende del flag intro_seen. */}
          <button
            onClick={() => setShowHotkeysHelp(v => !v)}
            title="Atajos de teclado (?)"
            style={{
              ...btnStyle, display: "flex", alignItems: "center", gap: 5,
              color: C.cyan, borderColor: alpha(C.cyan, 25),
              background: alpha(C.cyan, 6),
            }}
          >
            <Keyboard size={13} />
            <span style={{ fontWeight: 600 }}>Atajos</span>
            <kbd style={{
              fontFamily: "ui-monospace, monospace", fontSize: 10,
              padding: "0 5px", borderRadius: 3,
              background: alpha(C.cyan, 14), color: C.cyan,
              border: `1px solid ${alpha(C.cyan, 31)}`,
            }}>?</kbd>
          </button>
        </div>
      </div>

      {/* Bulk escalate preview — pide confirmación antes de ejecutar con
          el conteo por severidad devuelto por el dryRun del backend. */}
      {bulkPreview && (
        <div style={{
          marginBottom: 12, padding: "12px 14px", borderRadius: 6, fontSize: 12,
          background: alpha(C.orange, 8), border: `1px solid ${alpha(C.orange, 38)}`, color: C.orange,
          display: "flex", flexDirection: "column", gap: 8,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <span style={{ fontWeight: 700, color: C.orange }}>
              ⚠ Confirmar escalación — {bulkPreview.wouldEscalate} caso{bulkPreview.wouldEscalate === 1 ? "" : "s"}
            </span>
            {Object.entries(bulkPreview.bySev)
              .sort(([a], [b]) => {
                const rank = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NEGLIGIBLE: 5 } as Record<string, number>;
                return (rank[a] ?? 9) - (rank[b] ?? 9);
              })
              .map(([sev, n]) => {
                const sc = SEV_COLOR[sev] ?? C.textDim;
                return (
                  <span key={sev} style={{
                    fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
                    background: alpha(sc, 22),
                    color:      sc,
                    border:    `1px solid ${alpha(sc, 44)}`,
                  }}>
                    {sev}: {n}
                  </span>
                );
              })
            }
            {bulkPreview.belowThreshold > 0 && (
              <span style={{ color: C.textDim, fontSize: 11 }}>
                · bajo umbral: {bulkPreview.belowThreshold}
              </span>
            )}
            {bulkPreview.skippedByStatus > 0 && (
              <span style={{ color: C.textDim, fontSize: 11 }}>
                · saltados por estado: {bulkPreview.skippedByStatus}
              </span>
            )}
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button
              onClick={() => setBulkPreview(null)}
              disabled={escBusy}
              style={{
                background: "transparent", border: `1px solid ${C.border}`,
                borderRadius: 5, padding: "5px 12px", fontSize: 12,
                color: C.textDim, cursor: escBusy ? "not-allowed" : "pointer",
              }}
            >
              Cancelar
            </button>
            <button
              onClick={() => void confirmBulkEscalate()}
              disabled={escBusy}
              style={{
                background: C.orange, border: `1px solid ${C.orange}`,
                borderRadius: 5, padding: "5px 14px", fontSize: 12, fontWeight: 700,
                color: "#0a0a0f", cursor: escBusy ? "not-allowed" : "pointer",  // texto oscuro fijo sobre fondo ámbar (legible en ambos temas)
                display: "flex", alignItems: "center", gap: 5,
              }}
            >
              {escBusy ? <RefreshCw size={12} style={{ animation: "spin 0.8s linear infinite" }} /> : null}
              Confirmar escalación
            </button>
          </div>
        </div>
      )}

      {/* Bulk escalate result */}
      {escMsg && (
        <div style={{
          marginBottom: 12, padding: "8px 14px", borderRadius: 6, fontSize: 12,
          background: escMsg.startsWith("Escalados") ? alpha(C.orange, 8) : alpha(C.red, 8),
          border: `1px solid ${escMsg.startsWith("Escalados") ? alpha(C.orange, 25) : alpha(C.red, 25)}`,
          color: escMsg.startsWith("Escalados") ? C.orange : C.red,
          display: "flex", justifyContent: "space-between", alignItems: "center",
        }}>
          <span>{escMsg}</span>
          <button onClick={() => setEscMsg(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "inherit", fontSize: 14 }}>×</button>
        </div>
      )}

      {/* Paneles secundarios → ahora en sidebar derecho (ver <SideDrawer> al
          final del componente). Se abren desde el menú "Herramientas". */}

      {/* ── Resumen operativo (colapsable) ─────────────────────────────────────
          Agrupa Mi trabajo hoy + KPIs + estado de Sistema en una sola sección
          plegable. Despeja la franja superior — el operador la expande cuando
          la necesita. Estado persistido en localStorage. */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8, marginBottom: summaryCollapsed ? 12 : 8,
      }}>
        <button
          onClick={toggleSummary}
          title={summaryCollapsed ? "Mostrar resumen operativo" : "Ocultar resumen operativo"}
          style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase",
            background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6,
            padding: "4px 10px", color: C.textDim, cursor: "pointer", fontWeight: 600,
          }}
        >
          <ChevronDown size={12} style={{ transform: summaryCollapsed ? "rotate(-90deg)" : undefined, transition: "transform 0.15s" }} />
          Resumen operativo
        </button>
        {summaryCollapsed && (
          <span style={{ display: "inline-flex", gap: 8, alignItems: "center", fontSize: 11, color: C.textDim }}>
            {(kpis?.openCases ?? 0) > 0 && <span><b style={{ color: C.text }}>{kpis!.openCases}</b> abiertos</span>}
            {(kpis?.criticalUnadopted ?? 0) > 0 && (
              <span style={{ color: C.red, fontWeight: 600 }}>{kpis!.criticalUnadopted} CRITICAL sin adoptar</span>
            )}
            {operatorCi && myLoad.mine > 0 && <span>· {myLoad.mine} míos</span>}
          </span>
        )}
      </div>

      {!summaryCollapsed && (<>
      {/* A1 — Banner "Mi trabajo hoy": accesos directos a las 4 colas más
          relevantes para el operador de turno. Cada chip aplica el filtro
          correspondiente. Se oculta si no hay operatorCi o si las 4 colas
          están vacías — evita ruido cuando la sala está limpia. */}
      {operatorCi && (myLoad.mine > 0 || myLoad.unassignedCritical > 0 || myLoad.newToday > 0) && (
        <div style={{
          marginBottom: 12, padding: "10px 14px", borderRadius: 8,
          background: C.card, border: `1px solid ${C.border}`,
          display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10,
        }}>
          <span style={{
            fontSize: 10, fontWeight: 700, letterSpacing: "0.08em",
            color: C.textDim, textTransform: "uppercase",
          }}>
            Mi trabajo hoy
          </span>
          <MyWorkChip
            label="Mis activos"
            count={myLoad.mine}
            color={C.cyan}
            active={isQuickPresetActive("mine")}
            onClick={() => applyQuickPreset("mine")}
            title="Tus casos abiertos (total)"
          />
          {myLoad.mineAtRisk > 0 && (
            <MyWorkChip
              label="Por vencer SLA"
              count={myLoad.mineAtRisk}
              ratioOf={myLoad.mine}
              color={C.orange}
              active={isQuickPresetActive("mine") && sort === "sla"}
              onClick={() => {
                applyQuickPreset("mine");
                setSort("sla"); setSortDir("desc");
              }}
              title={`${myLoad.mineAtRisk} de ${myLoad.mine} entre 70% y 100% del SLA — todavía a tiempo · click: ordenar por SLA`}
            />
          )}
          {myLoad.mineBreached > 0 && (
            <MyWorkChip
              label="SLA vencido"
              count={myLoad.mineBreached}
              ratioOf={myLoad.mine}
              color={C.red}
              active={isQuickPresetActive("mine") && sort === "sla"}
              onClick={() => {
                applyQuickPreset("mine");
                setSort("sla"); setSortDir("desc");
              }}
              title={`${myLoad.mineBreached} de ${myLoad.mine} ya superaron el 100% del SLA — incumplidos · click: ordenar por SLA`}
            />
          )}
          <MyWorkChip
            label="CRITICAL sin adoptar"
            count={myLoad.unassignedCritical}
            color={C.red}
            active={sevFilter === "CRITICAL" && assignedTo === "__unassigned__"}
            onClick={() => {
              applySevFilter("CRITICAL");
              applyAssignedTo("__unassigned__");
              applyIncludeClosed(false);
            }}
            title="Casos CRITICAL/HIGH sin owner — próxima presa para adopción"
          />
          <MyWorkChip
            label="Nuevos 24h sin owner"
            count={myLoad.newToday}
            color={C.textDim}
            active={statusFilter === "NUEVO" && assignedTo === "__unassigned__"}
            onClick={() => {
              applyStatusFilter("NUEVO");
              applyAssignedTo("__unassigned__");
            }}
            title="Casos creados en las últimas 24h que nadie tomó"
          />
        </div>
      )}

      {/* KPI Strip */}
      <KpiStrip
        kpis={kpis}
        isLoading={isLoadingKpis}
        statusDist={statusDist.data}
        onStatusFilter={applyStatusFilter}
        activeStatus={statusFilter}
        onSevFilter={applySevFilter}
        onIncludeClosed={applyIncludeClosed}
      />

      {/* La franja "Sistema" (SM activo + caché Trino + automatización) se
          reubicó al botón "Sistema" de la barra superior (SystemHealthButton),
          junto a Scoring e Incidentes — visible en toda la app, no sólo aquí. */}
      </>)}

      {/* Handover y Cierre masivo → también en sidebar derecho (al final). */}

      {/* Vistas rápidas personales */}
      <div style={{ display: "flex", gap: 6, marginBottom: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.08em", textTransform: "uppercase" }}>Vistas:</span>
        {Object.entries(QUICK_PRESETS).map(([key, p]) => {
          const active   = isQuickPresetActive(key);
          const disabled = key === "mine" && !operatorCi;
          return (
            <button
              key={key}
              onClick={() => applyQuickPreset(key)}
              disabled={disabled}
              title={disabled ? "Configurá tu CI de operador primero" : p.hint}
              style={{
                fontSize: 10, padding: "3px 10px", borderRadius: 4,
                cursor: disabled ? "not-allowed" : "pointer",
                fontWeight: 600, transition: "all 0.15s",
                opacity: disabled ? 0.4 : 1,
                background: active ? alpha(p.color, 19) : "transparent",
                border: `1px solid ${active ? alpha(p.color, 50) : C.border}`,
                color: active ? p.color : C.textDim,
              }}
            >
              {p.label}
            </button>
          );
        })}
        {/* P2 #15: vistas guardadas del usuario + botón guardar */}
        {savedViews.length > 0 && (
          <span style={{ width: 1, height: 16, background: C.border, margin: "0 2px" }} />
        )}
        {savedViews.map((v) => (
          <span key={v.name} style={{ display: "inline-flex", alignItems: "center" }}>
            <button
              onClick={() => applySavedView(v.filters)}
              title={`Aplicar vista guardada: ${v.name}`}
              style={{
                fontSize: 10, padding: "3px 8px", borderRadius: "4px 0 0 4px",
                cursor: "pointer", fontWeight: 600,
                background: alpha(C.cyan, 10), border: `1px solid ${alpha(C.cyan, 35)}`,
                borderRight: "none", color: C.cyan,
              }}
            >
              ★ {v.name}
            </button>
            <button
              onClick={() => handleDeleteView(v.name)}
              title="Borrar vista"
              style={{
                fontSize: 10, padding: "3px 5px", borderRadius: "0 4px 4px 0",
                cursor: "pointer", background: "transparent",
                border: `1px solid ${alpha(C.cyan, 35)}`, color: C.textDim,
              }}
            >
              ×
            </button>
          </span>
        ))}
        <button
          onClick={handleSaveView}
          title="Guardar los filtros actuales como una vista reutilizable"
          style={{
            fontSize: 10, padding: "3px 10px", borderRadius: 4, cursor: "pointer",
            background: "transparent", border: `1px dashed ${C.border}`, color: C.textDim,
          }}
        >
          + Guardar vista
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
        {/* Search — soporta sintaxis `sev:HIGH op:<CI> status:NUEVO mitre:T1110
            role:L2 source:wazuh_alerts`. El parser corre en blur/Enter para
            no aplicar filtros a cada tecla. Lo no-reconocido se envía al
            backend como texto libre (ILIKE). */}
        <div style={{ position: "relative", flex: "1 1 200px" }}>
          <Search size={12} style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", color: C.textDim }} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onBlur={(e) => applySearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") applySearch((e.target as HTMLInputElement).value);
            }}
            placeholder={searchPlaceholder}
            title={[
              "Sintaxis de búsqueda avanzada (combinable con texto libre):",
              "  sev:CRITICAL|HIGH|MEDIUM|LOW  (o abreviado: sev:c · sev:h)",
              "  status:NUEVO|EN_REVISION|ESCALADO|CERRADO|FALSO_POSITIVO  (o status:fp)",
              "  op:<CI>  ·  op:me  (= tu usuario)  ·  op:none  (sin asignar)",
              "  role:L1|L1L2|L2|L3  (cualquiera del rol)",
              "  mitre:T1110  ·  source:wazuh_alerts",
              "  score:>=70  ·  score:50-80  ·  score:<30",
              "  age:<7d   (recientes)  ·  age:>30d  (antiguos)  · unidades: m h d w",
              "  createdAt:>2026-05-15  (después de)  ·  createdAt:<2026-05-01",
              "",
              "Ejemplos:",
              "  sev:c op:me           → mis CRITICAL",
              "  status:nuevo op:none  → cola de triage",
              "  mitre:T1078 sev:h     → uso credenciales legítimas, severidad alta",
              "  score:>=70 age:<7d    → score alto en los últimos 7 días",
              "  score:50-80 op:me     → mis pendientes con score medio",
            ].join("\n")}
            style={{
              width: "100%", paddingLeft: 28, padding: "7px 10px 7px 28px",
              background: C.card, border: `1px solid ${C.border}`,
              borderRadius: 6, color: C.text, fontSize: 12, boxSizing: "border-box",
            }}
          />
        </div>

        {/* Severity filter */}
        <div style={{ display: "flex", gap: 4 }}>
          {SEV_OPTIONS.map((s) => {
            const sc = SEV_COLOR[s] ?? C.cyan;
            const active = sevFilter === s;
            return (
              <button
                key={s}
                onClick={() => applySevFilter(s)}
                style={{
                  ...filterBtnStyle,
                  background: active ? alpha(sc, 18) : "transparent",
                  borderColor: active ? alpha(sc, 44) : C.border,
                  color:       active ? sc : C.textDim,
                  fontWeight: active ? 600 : 400,
                }}
              >
                {s === "ALL" ? "Todos" : s}
              </button>
            );
          })}
        </div>

        {/* Status filter */}
        <select
          value={statusFilter}
          onChange={(e) => applyStatusFilter(e.target.value as CaseStatus | "ALL")}
          style={{
            background: C.card, border: `1px solid ${C.border}`,
            borderRadius: 6, padding: "6px 10px", color: C.text, fontSize: 12,
          }}
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{STATUS_LABEL[s] ?? s}</option>
          ))}
        </select>

        {/* Clase eCSIRT + Rango de fechas → fila avanzada (toggle "Más filtros"). */}

        {/* Filtro por operador / rol asignado ─────────────────────────────── */}
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          {/* Toggle "Mis casos" — usa el CI del operador actual */}
          <button
            onClick={() => applyAssignedTo(assignedTo === "__me__" ? "" : "__me__")}
            disabled={!operatorCi}
            title={operatorCi ? `Filtrar por mi CI (${operatorCi})` : "Inicia sesión para filtrar mis casos"}
            style={{
              ...filterBtnStyle,
              background:  assignedTo === "__me__" ? alpha(C.cyan, 12) : "transparent",
              borderColor: assignedTo === "__me__" ? alpha(C.cyan, 38) : C.border,
              color:       assignedTo === "__me__" ? C.cyan : C.textDim,
              opacity:     operatorCi ? 1 : 0.5,
              cursor:      operatorCi ? "pointer" : "not-allowed",
              display: "flex", alignItems: "center", gap: 4,
            }}
          >
            <User size={11} />
            Mis casos
          </button>

          {/* Selector de "asignado a" con valores especiales y por CI */}
          <select
            value={assignedTo === "__me__" ? "" : assignedTo}
            onChange={(e) => applyAssignedTo(e.target.value)}
            title="Filtrar por owner del caso"
            style={{
              background: C.card, border: `1px solid ${C.border}`,
              borderRadius: 6, padding: "5px 8px", color: C.text, fontSize: 12,
              minWidth: 150,
            }}
          >
            <option value="">Owner: cualquiera</option>
            <option value="__unassigned__">
              Sin asignar{facets?.unassigned != null ? ` · ${facets.unassigned}` : ""}
            </option>
            {operators?.filter((o) => o.is_active).map((o) => {
              const cnt = facets?.byOperator?.[o.id];
              return (
                <option key={o.id} value={o.id}>
                  {o.id} — {o.name} ({o.role_id}){cnt != null ? ` · ${cnt}` : ""}
                </option>
              );
            })}
          </select>

          {/* Filtro multi-perfil — chips con conteo */}
          <div style={{ display: "flex", alignItems: "center", gap: 3, padding: "0 4px",
                        borderLeft: `1px solid ${C.border}`, paddingLeft: 8 }}>
            <span style={{ fontSize: 10, color: C.textDim, marginRight: 2 }}>Perfil</span>
            {(["LEADER","L1","L1L2","L2","L3"] as const).map((role) => {
              const active = assignedRoles.includes(role);
              const cnt = facets?.byRole?.[role];
              return (
                <button
                  key={role}
                  onClick={() => toggleAssignedRole(role)}
                  title={`Filtrar por owners con perfil ${role}`}
                  style={{
                    fontSize: 10, padding: "3px 8px", borderRadius: 4, cursor: "pointer",
                    background:  active ? alpha(C.cyan, 15) : "transparent",
                    border:     `1px solid ${active ? alpha(C.cyan, 38) : C.border}`,
                    color:       active ? C.cyan : C.textDim,
                    fontWeight:  active ? 700 : 500,
                  }}
                >
                  {role}{cnt != null ? ` · ${cnt}` : ""}
                </button>
              );
            })}
            {assignedRoles.length > 0 && (
              <button
                onClick={clearAssignedRoles}
                title="Limpiar perfiles seleccionados"
                style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim, fontSize: 14, padding: "0 2px", lineHeight: 1 }}
              >×</button>
            )}
          </div>

          {/* Toggle "Incluir cerrados" */}
          <label
            title="Por defecto se ocultan CERRADO y FALSO_POSITIVO"
            style={{
              display: "inline-flex", alignItems: "center", gap: 4,
              fontSize: 11, color: includeClosed ? C.text : C.textDim,
              cursor: "pointer", padding: "3px 8px", borderRadius: 4,
              background: includeClosed ? alpha(C.textDim, 15) : "transparent",
              border: `1px solid ${includeClosed ? alpha(C.textDim, 31) : C.border}`,
              userSelect: "none",
            }}
          >
            <input
              type="checkbox"
              checked={includeClosed}
              onChange={(e) => applyIncludeClosed(e.target.checked)}
              style={{ accentColor: C.cyan, cursor: "pointer" }}
            />
            Incluir cerrados
          </label>

          {(assignedTo) && (
            <button
              onClick={() => applyAssignedTo("")}
              title="Limpiar filtro de owner"
              style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim, fontSize: 14, padding: "0 2px", lineHeight: 1 }}
            >
              ×
            </button>
          )}
        </div>

        {/* Toggle "Más filtros" — abre la fila avanzada (clase, fechas, filas). */}
        {(() => {
          const advCount = (classFilter !== "ALL" ? 1 : 0) + (dateFrom || dateTo ? 1 : 0);
          return (
            <button
              onClick={toggleAdvFilters}
              title="Filtros avanzados: clase eCSIRT, rango de fechas, tamaño de página"
              style={{
                ...filterBtnStyle, marginLeft: "auto",
                display: "inline-flex", alignItems: "center", gap: 5,
                background: showAdvFilters || advCount > 0 ? alpha(C.cyan, 10) : "transparent",
                borderColor: showAdvFilters || advCount > 0 ? alpha(C.cyan, 38) : C.border,
                color: showAdvFilters || advCount > 0 ? C.cyan : C.textDim,
              }}
            >
              <ChevronDown size={12} style={{ transform: showAdvFilters ? "rotate(180deg)" : undefined, transition: "transform 0.15s" }} />
              Más filtros
              {advCount > 0 && (
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "0 5px", borderRadius: 8,
                  background: alpha(C.cyan, 25), color: C.cyan,
                }}>{advCount}</span>
              )}
            </button>
          );
        })()}
      </div>

      {/* Fila de filtros avanzados (colapsable) */}
      {showAdvFilters && (
        <div style={{
          display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap", alignItems: "center",
          padding: "10px 12px", borderRadius: 8, background: C.card, border: `1px solid ${C.border}`,
        }}>
          {/* Clase eCSIRT/MISP filter (mig 088) */}
          <select
            value={classFilter}
            onChange={(e) => applyClassFilter(e.target.value)}
            title="Clase eCSIRT/MISP (taxonomía estándar CSIRT)"
            style={{
              background: C.bg, border: `1px solid ${C.border}`,
              borderRadius: 6, padding: "6px 10px", color: C.text, fontSize: 12,
            }}
          >
            {CLASS_OPTIONS.map((o) => (
              <option key={o.key} value={o.key}>
                {o.key === "ALL" ? "Clase: todas" : o.label}
              </option>
            ))}
          </select>

          {/* Date range filter */}
          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ fontSize: 11, color: C.textDim, whiteSpace: "nowrap" }}>Desde</span>
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => applyDateFrom(e.target.value)}
              style={{
                background: C.bg, border: `1px solid ${C.border}`,
                borderRadius: 6, padding: "5px 8px", color: C.text, fontSize: 12,
              }}
            />
            <span style={{ fontSize: 11, color: C.textDim }}>—</span>
            <input
              type="date"
              value={dateTo}
              onChange={(e) => applyDateTo(e.target.value)}
              style={{
                background: C.bg, border: `1px solid ${C.border}`,
                borderRadius: 6, padding: "5px 8px", color: C.text, fontSize: 12,
              }}
            />
            {(dateFrom || dateTo) && (
              <button
                onClick={clearDateRange}
                title="Limpiar rango de fechas"
                style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim, fontSize: 14, padding: "0 2px", lineHeight: 1 }}
              >
                ×
              </button>
            )}
          </div>

          {/* Page size selector */}
          <div style={{ display: "flex", alignItems: "center", gap: 4, marginLeft: "auto" }}>
            <span style={{ fontSize: 11, color: C.textDim, whiteSpace: "nowrap" }}>Filas</span>
            <select
              value={pageSize}
              onChange={(e) => applyPageSize(Number(e.target.value))}
              style={{
                background: C.bg, border: `1px solid ${C.border}`,
                borderRadius: 6, padding: "5px 8px", color: C.text, fontSize: 12,
              }}
            >
              {PAGE_SIZE_OPTIONS.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </div>
        </div>
      )}

      {/* Loading state */}
      {/* Chips de filtros activos — visibles cuando al menos uno diverge del default.
          Evita al operador recorrer los controles para saber "qué estoy filtrando";
          cada pill tiene ✕ que limpia sólo ese filtro. */}
      {activeFilters.length > 0 && (
        <div style={{
          display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6,
          marginBottom: 10, padding: "6px 10px", borderRadius: 6,
          background: C.card, border: `1px solid ${C.border}`,
        }}>
          <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.08em", textTransform: "uppercase", marginRight: 2 }}>
            Filtros ({activeFilters.length}):
          </span>
          {activeFilters.map((f) => (
            <button
              key={f.key}
              onClick={f.clear}
              title="Quitar este filtro"
              style={{
                display: "inline-flex", alignItems: "center", gap: 4,
                fontSize: 10, padding: "2px 8px", borderRadius: 4, cursor: "pointer",
                background: alpha(C.cyan, 8), border: `1px solid ${alpha(C.cyan, 25)}`, color: C.cyan,
                fontFamily: "monospace",
              }}
            >
              <span>{f.label}</span>
              <span style={{ opacity: 0.7, fontWeight: 700 }}>×</span>
            </button>
          ))}
          <button
            onClick={clearAllFilters}
            style={{
              fontSize: 10, padding: "2px 8px", borderRadius: 4, cursor: "pointer",
              background: "transparent", border: `1px solid ${C.border}`, color: C.textDim,
              marginLeft: "auto",
            }}
          >
            ✕ Limpiar todo
          </button>
        </div>
      )}

      {/* Error state — solo para primer load; refetches errados se propagan
          desde la tabla sin romper la vista existente. */}
      {isError && !isLoading && (
        <div style={{ textAlign: "center", padding: 48, color: C.red }}>
          <AlertCircle size={24} style={{ margin: "0 auto 8px", display: "block" }} />
          <div style={{ marginBottom: 12 }}>{errorMessage ?? "Error al cargar incidentes"}</div>
          <button onClick={refetch} style={{ ...btnStyle, color: C.red, borderColor: alpha(C.red, 25) }}>
            Reintentar
          </button>
        </div>
      )}

      {/* Backlog sin asignar — visible para LEADER/ADMIN. Ofrece filtro
          rápido para revisar la cola sin owner. */}
      {!isLoadingKpis && (kpis?.unassignedOpen ?? 0) > 0 && (operatorRole === "LEADER" || operatorRole === "ADMIN") && (
        <div style={{
          marginBottom: 12,
          padding: "8px 14px",
          borderRadius: 8,
          background: alpha(C.orange, 14),
          border: `1px solid ${alpha(C.orange, 38)}`,
          display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <AlertCircle size={14} color={C.orange} />
            <span style={{ fontSize: 12, color: C.orange, fontWeight: 700 }}>
              {kpis!.unassignedOpen} caso{kpis!.unassignedOpen !== 1 ? "s" : ""} sin asignar
            </span>
            <span style={{ fontSize: 11, color: alpha(C.orange, 56) }}>
              Backlog huérfano — asignar antes del SLA
            </span>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            {/* P1.6 — Acción directa: distribuir backlog al SM activo. Sólo
                visible si hay SM. Si no, queda sólo "Ver sin asignar". */}
            {currentShiftMgr?.id && (
              <button
                onClick={() => void handleBulkAssignToSM()}
                disabled={bulkAssignSmBusy}
                title={`Asignar al SM activo (${currentShiftMgr.name ?? currentShiftMgr.id})`}
                style={{
                  fontSize: 11, padding: "4px 12px", borderRadius: 5,
                  cursor: bulkAssignSmBusy ? "wait" : "pointer",
                  background: bulkAssignSmBusy ? alpha(C.orange, 6) : C.orange,
                  border: `1px solid ${C.orange}`,
                  color: "#000", fontWeight: 700, whiteSpace: "nowrap",
                  opacity: bulkAssignSmBusy ? 0.6 : 1,
                }}
              >
                {bulkAssignSmBusy ? "Asignando…" : "Asignar a SM"}
              </button>
            )}
            <button
              onClick={() => applyAssignedTo("__unassigned__")}
              style={{
                fontSize: 11, padding: "4px 12px", borderRadius: 5, cursor: "pointer",
                background: alpha(C.orange, 12), border: `1px solid ${alpha(C.orange, 31)}`, color: C.orange, fontWeight: 600,
                whiteSpace: "nowrap",
              }}
            >
              Ver sin asignar
            </button>
          </div>
        </div>
      )}

      {/* Critical unadopted alert banner */}
      {!isLoadingKpis && (kpis?.criticalUnadopted ?? 0) > 0 && (
        <div style={{
          marginBottom: 12,
          padding: "10px 16px",
          borderRadius: 8,
          background: alpha(C.red, 14),
          border: `1px solid ${alpha(C.red, 44)}`,
          display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <AlertCircle size={16} color={C.red} />
            <span style={{ fontSize: 13, color: C.red, fontWeight: 700 }}>
              {kpis!.criticalUnadopted} caso{kpis!.criticalUnadopted !== 1 ? "s" : ""} CRITICAL sin adoptar
            </span>
            <span style={{ fontSize: 11, color: alpha(C.red, 56) }}>
              Requieren atención inmediata
            </span>
          </div>
          <button
            onClick={() => {
              // Fix audit 2026-05-13: el KPI criticalUnadopted cuenta CRITICAL
              // sin owner en cualquier status (NUEVO/EN_ANALISIS/CONFIRMADO/
              // ESCALADO/MONITOREADO). El filtro anterior `status=NUEVO`
              // devolvía 0 casos porque los CRITICAL sin owner viven
              // típicamente en ESCALADO. Ahora filtra por sev + unassigned y
              // deja status libre para que el conteo coincida con la vista.
              applySevFilter("CRITICAL");
              applyStatusFilter("ALL");
              applyAssignedTo("__unassigned__");
              applyIncludeClosed(false);
            }}
            style={{
              fontSize: 11, padding: "4px 12px", borderRadius: 5, cursor: "pointer",
              background: alpha(C.red, 15), border: `1px solid ${alpha(C.red, 31)}`, color: C.red, fontWeight: 600,
              whiteSpace: "nowrap",
            }}
          >
            Ver críticos sin adoptar
          </button>
        </div>
      )}

      {/* Cases table — siempre visible (excepto en error de primer load).
          Durante isLoading muestra skeleton rows en vez del spinner full-page
          para preservar layout y dar sensación de responsividad a los filtros. */}
      {!isError && (
        <>
          {/* C4 — En viewport <800px reemplazamos la tabla por MobileCaseList.
              Las features avanzadas (agrupar por IOC, sorts por columna,
              focus con J/K) son desktop-only — no caben razonablemente. */}
          {isMobile ? (
            <MobileCaseList
              cases={displayCases}
              isLoading={isLoading}
              myOperatorCi={operatorCi}
              onSelect={handleSelectCase}
              onAdopt={handleAdoptCase}
            />
          ) : (
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden", position: "relative" }}>
            {/* Barra superior: "refrescando…" sutil cuando hay datos cached
                pero React Query está refetcheando. No bloquea ni tapa filas. */}
            {isLoading && cases.length > 0 && (
              <div style={{
                position: "absolute", top: 0, left: 0, right: 0, height: 2,
                background: `linear-gradient(90deg, transparent, ${C.cyan}, transparent)`,
                animation: "lh-shimmer 1.2s linear infinite",
                pointerEvents: "none",
              }} />
            )}

            {/* Toolbar de agrupación por activo */}
            <div style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "6px 4px 8px", fontSize: 11, color: C.textDim,
            }}>
              <span style={{ fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase" }}>Agrupar</span>
              <div style={{ display: "inline-flex", border: `1px solid ${C.border}`, borderRadius: 6, overflow: "hidden" }}>
                {([
                  ["none",   "Ninguno"],
                  ["activo", "Activo"],
                ] as Array<[GroupMode, string]>).map(([mode, label], i) => {
                  const active = groupMode === mode;
                  return (
                    <button
                      key={mode}
                      onClick={() => { setGroupMode(mode); setExpandedGroups(new Set()); }}
                      title={
                        mode === "activo" ? "Agrupar incidentes del mismo activo"
                        : "Sin agrupar (lista plana)"
                      }
                      style={{
                        display: "inline-flex", alignItems: "center", gap: 5,
                        fontSize: 11, padding: "4px 10px", cursor: "pointer", fontWeight: active ? 700 : 500,
                        background: active ? alpha(C.cyan, 16) : "transparent",
                        color: active ? C.cyan : C.textDim, border: "none",
                        borderLeft: i > 0 ? `1px solid ${C.border}` : "none",
                      }}
                    >
                      {mode === "activo" && <Layers size={11} />}
                      {label}
                    </button>
                  );
                })}
              </div>
              {groupMode !== "none" && (
                <span style={{ fontSize: 10, color: C.textDim }}>
                  · click en una cabecera para expandir
                </span>
              )}
            </div>

            {/* Table header */}
            <div style={{ ...tableRowStyle, borderBottom: `1px solid ${C.border}`, color: C.textDim, fontSize: 10, letterSpacing: "0.1em" }}>
              {/* Seleccionar todos los casos de la página (alineado con el checkbox de cada fila). */}
              <input
                type="checkbox"
                aria-label="Seleccionar todos los casos de la página"
                title="Seleccionar todos los casos de esta página"
                checked={allPageSelected}
                ref={(el) => { if (el) el.indeterminate = somePageSelected; }}
                onChange={toggleSelectAllPage}
                style={{ flexShrink: 0, width: 15, height: 15, cursor: "pointer", accentColor: C.cyan }}
              />
              <SortHeader label="# CASO"    col="id"       sort={sort} sortDir={sortDir} onSort={applySort} style={{ width: 72 }} />
              <SortHeader label="ACTIVO / ORIGEN" col="ioc"  sort={sort} sortDir={sortDir} onSort={applySort} style={{ flex: 2 }} />
              <SortHeader label="SEVERITY"  col="severity" sort={sort} sortDir={sortDir} onSort={applySort} style={{ width: 80 }} />
              <SortHeader label="ESTADO"    col="status"   sort={sort} sortDir={sortDir} onSort={applySort} style={{ width: 110 }} />
              <SortHeader label="DETECTADO" col="detectado" sort={sort} sortDir={sortDir} onSort={applySort} style={{ width: 120, textAlign: "right" }} />
              <SortHeader label="CREADO"    col="creado"   sort={sort} sortDir={sortDir} onSort={applySort} style={{ width: 110, textAlign: "right" }} />
              <SortHeader label="SLA"       col="sla"      sort={sort} sortDir={sortDir} onSort={applySort} style={{ width: 80, textAlign: "right" }} />
            </div>

            {isLoading && cases.length === 0 ? (
              // Primer load sin datos cached: skeleton rows pintan la estructura.
              <>
                {Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={`sk-${i}`} />)}
              </>
            ) : cases.length === 0 ? (
              <div style={{ padding: "32px 16px", textAlign: "center", color: C.textDim }}>
                Sin casos para los filtros actuales.
                {activeFilters.length > 0 && (
                  <button
                    onClick={clearAllFilters}
                    style={{
                      marginLeft: 10, fontSize: 11, padding: "3px 10px", borderRadius: 4,
                      cursor: "pointer", background: alpha(C.cyan, 8),
                      border: `1px solid ${alpha(C.cyan, 25)}`, color: C.cyan,
                    }}
                  >
                    ✕ Limpiar filtros
                  </button>
                )}
              </div>
            ) : (
              renderedCases.map((item) => {
                if (item.kind === "single") {
                  const focusedId = focusIdx >= 0 ? displayCases[focusIdx]?.id : null;
                  return (
                    <CaseRow
                      key={item.case.id}
                      case={item.case}
                      profiles={profiles}
                      myOperatorCi={operatorCi}
                      operatorNames={operatorNames}
                      onSelect={handleSelectCase}
                      onAdopt={handleAdoptCase}
                      onChanged={handleCaseChanged}
                      isFocused={item.case.id === focusedId}
                      selected={selectedIds.has(item.case.id)}
                      onToggleSelect={toggleSelect}
                    />
                  );
                }
                // kind === "group": header clickeable + (opcionalmente) hijas expandidas.
                const groupKey = item.groupKey;
                return (
                  <Fragment key={`g-${groupKey}`}>
                    <div
                      onClick={() => toggleGroup(groupKey)}
                      style={{
                        cursor: "pointer", display: "flex", alignItems: "center", gap: 8,
                        padding: "4px 10px", fontSize: 11,
                        background: item.expanded ? alpha(C.cyan, 3) : alpha(C.cyan, 7),
                        borderBottom: `1px solid ${C.border}`,
                        color: C.textDim,
                      }}
                      title={`${item.members.length} incidente(s) del mismo activo — click para ${item.expanded ? "colapsar" : "expandir"}`}
                    >
                      <span style={{
                        fontSize: 10, fontWeight: 700, letterSpacing: "0.05em",
                        padding: "1px 6px", borderRadius: 3,
                        background: alpha(C.cyan, 19), color: C.cyan,
                        border: `1px solid ${alpha(C.cyan, 38)}`,
                      }}>
                        {item.expanded ? "▼" : "▶"} {item.members.length}×
                      </span>
                      <span style={{
                        fontFamily: "ui-monospace, monospace",
                        color: C.text, fontWeight: 600,
                      }}>
                        {item.label}
                      </span>
                      <span style={{
                        fontSize: 10, padding: "1px 5px", borderRadius: 3,
                        background: alpha(SEV_COLOR[item.leader.severity] ?? C.textDim, 12),
                        color: SEV_COLOR[item.leader.severity] ?? C.textDim,
                        fontWeight: 600,
                      }}>
                        max {item.leader.severity}
                      </span>
                      <span style={{ marginLeft: "auto", fontSize: 10 }}>
                        ({item.members.filter((m) => !isResolvedCase(m)).length} abiertos ·
                        {" "}{item.members.filter((m) => !m.operatorCi).length} sin owner)
                      </span>
                    </div>
                    {item.expanded && item.members.map((c) => {
                      const focusedId = focusIdx >= 0 ? displayCases[focusIdx]?.id : null;
                      return (
                        <CaseRow
                          key={c.id}
                          case={c}
                          profiles={profiles}
                          myOperatorCi={operatorCi}
                          operatorNames={operatorNames}
                          onSelect={handleSelectCase}
                          onAdopt={handleAdoptCase}
                          onChanged={handleCaseChanged}
                          isFocused={c.id === focusedId}
                          selected={selectedIds.has(c.id)}
                          onToggleSelect={toggleSelect}
                        />
                      );
                    })}
                  </Fragment>
                );
              })
            )}
          </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, marginTop: 16 }}>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                style={{ ...btnStyle, padding: "5px 8px" }}
              >
                <ChevronLeft size={14} />
              </button>
              <span style={{ color: C.textDim, fontSize: 12 }}>
                Página {page} de {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                style={{ ...btnStyle, padding: "5px 8px" }}
              >
                <ChevronRight size={14} />
              </button>
            </div>
          )}
        </>
      )}

      {/* Case detail sheet */}
      {selectedCase && (
        <CaseDetailSheet
          case={selectedCase}
          onClose={() => setSelectedCase(null)}
          onAcknowledged={() => void refetch()}
        />
      )}

      {/* Adoption modal */}
      {adoptingCase && (
        <CaseAdoptionModal
          case={adoptingCase}
          triggeringProfiles={getTriggeringProfiles(adoptingCase, profiles)}
          onAdopt={async (ci, force) => {
            await adoptCase(adoptingCase.id, ci, force ?? false);
            setAdoptingCase(null);
          }}
          onClose={() => setAdoptingCase(null)}
        />
      )}

      {/* Hotkeys help overlay (toggle: tecla "?") */}
      {showHotkeysHelp && (
        <div
          onClick={() => setShowHotkeysHelp(false)}
          style={{
            position: "fixed", inset: 0, zIndex: 100,
            background: alpha("#000000", 60),
            display: "flex", alignItems: "center", justifyContent: "center",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: C.card, border: `1px solid ${C.border}`,
              borderRadius: 8, padding: 20, minWidth: 320, maxWidth: 440,
              boxShadow: `0 8px 32px ${alpha("#000000", 50)}`,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: C.text }}>Atajos de teclado</h3>
              <button
                onClick={() => setShowHotkeysHelp(false)}
                style={{ ...btnStyle, padding: "2px 8px", fontSize: 11 }}
              >Esc</button>
            </div>
            <table style={{ fontSize: 12, color: C.text, width: "100%", borderCollapse: "collapse" }}>
              <tbody>
                {[
                  ["j  /  ↓",  "Siguiente caso"],
                  ["k  /  ↑",  "Caso anterior"],
                  ["Enter",    "Abrir detalle del caso enfocado"],
                  ["a",        "Adoptar caso enfocado"],
                  ["?",        "Mostrar / ocultar esta ayuda"],
                ].map(([k, desc]) => (
                  <tr key={k}>
                    <td style={{ padding: "4px 12px 4px 0", whiteSpace: "nowrap" }}>
                      <kbd style={{
                        fontFamily: "ui-monospace, monospace", fontSize: 11,
                        padding: "1px 6px", borderRadius: 3,
                        background: alpha(C.cyan, 8), color: C.cyan,
                        border: `1px solid ${alpha(C.cyan, 25)}`,
                      }}>{k}</kbd>
                    </td>
                    <td style={{ padding: "4px 0", color: C.textDim }}>{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p style={{ fontSize: 10, color: C.textDim, marginTop: 12, marginBottom: 0 }}>
              Los atajos no se activan cuando estás tipeando en un campo o con un modal abierto.
            </p>
          </div>
        </div>
      )}
      </div>{/* /padding wrapper */}
    </div>
  );
}

// ── SuppressionPanel ──────────────────────────────────────────────────────────

interface SuppressionRow {
  dedup_key: string;
  reason: string;
  severity: string;
  suppressed_until: string;
  suppressed_by: string;
  original_case_id: string;
  original_ioc: string;
  created_at: string;
  active: boolean;
}

function SuppressionPanel({ onClose }: { onClose: () => void }) {
  const [rows,    setRows]    = React.useState<SuppressionRow[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error,   setError]   = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  async function load() {
    setLoading(true); setError(null);
    try {
      const { data: d } = await api.get<{ ok: boolean; rows?: typeof rows; error?: string }>(
        "/api/incidents/suppressions",
      );
      if (d.ok) setRows(d.rows ?? []);
      else setError(d.error ?? "Error al cargar supresiones");
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  React.useEffect(() => { void load(); }, []);

  async function remove(dk: string) {
    setDeleting(dk);
    try {
      await api.delete(`/api/incidents/suppressions/${encodeURIComponent(dk)}`);
      setRows((prev) => prev.filter((r) => r.dedup_key !== dk));
    } catch { /* ignorar */ } finally { setDeleting(null); }
  }

  const active   = rows.filter((r) => r.active);
  const expired  = rows.filter((r) => !r.active);

  const REASON_COLOR: Record<string, string> = {
    FALSO_POSITIVO: C.green,
    CERRADO:        C.textDim,
    AUTO_CLOSED:    C.neutral,
    OPERATOR:       C.orange,
  };

  function fmt(ts: string) {
    try { return formatDatePy(ts); }
    catch { return ts; }
  }

  return (
    <div style={{
      background: C.card, border: `1px solid ${alpha(C.orange, 25)}`,
      borderRadius: 10, padding: 16, marginBottom: 20,
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
        <div>
          <span style={{ fontSize:13, fontWeight:700, color:C.orange }}>Supresiones activas</span>
          <span style={{ fontSize:11, color:C.textDim, marginLeft:8 }}>
            IOCs que no generarán nuevos casos mientras la supresión esté vigente
          </span>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          <button onClick={load} style={{ ...btnStyle, fontSize:11 }}>Refrescar</button>
          <button onClick={onClose} style={{ ...btnStyle, fontSize:11 }}>Cerrar</button>
        </div>
      </div>

      {loading && <div style={{ color:C.textDim, fontSize:12 }}>Cargando…</div>}
      {error   && <div style={{ color:C.red,     fontSize:12 }}>{error}</div>}

      {!loading && active.length === 0 && (
        <div style={{ color:C.textDim, fontSize:12, padding:"8px 0" }}>
          Sin supresiones activas — todos los IOCs cerrados pueden generar nuevos casos.
        </div>
      )}

      {active.length > 0 && (
        <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
          <thead>
            <tr style={{ color:C.textDim, textAlign:"left" }}>
              <th style={{ padding:"4px 8px" }}>IOC</th>
              <th style={{ padding:"4px 8px" }}>Motivo</th>
              <th style={{ padding:"4px 8px" }}>Severidad</th>
              <th style={{ padding:"4px 8px" }}>Vigente hasta</th>
              <th style={{ padding:"4px 8px" }}>Por</th>
              <th style={{ padding:"4px 8px" }}>Caso original</th>
              <th style={{ padding:"4px 8px" }}></th>
            </tr>
          </thead>
          <tbody>
            {active.map((s) => (
              <tr key={s.dedup_key} style={{ borderTop:`1px solid ${C.border}` }}>
                <td style={{ padding:"6px 8px", fontFamily:"monospace" }}>{s.original_ioc || "—"}</td>
                <td style={{ padding:"6px 8px" }}>
                  <span style={{
                    fontSize:10, padding:"2px 6px", borderRadius:4,
                    background: alpha(REASON_COLOR[s.reason] ?? C.cyan, 9),
                    color: REASON_COLOR[s.reason] ?? C.cyan,
                    fontWeight:600,
                  }}>{s.reason}</span>
                </td>
                <td style={{ padding:"6px 8px", color: SEV_COLOR[s.severity] ?? C.textDim }}>
                  {s.severity}
                </td>
                <td style={{ padding:"6px 8px", color:C.orange }}>{fmt(s.suppressed_until)}</td>
                <td style={{ padding:"6px 8px", color:C.textDim }}>{s.suppressed_by || "system"}</td>
                <td style={{ padding:"6px 8px", fontFamily:"monospace", fontSize:10, color:C.textDim }}>
                  {s.original_case_id ? `#${s.original_case_id.slice(0,7).toUpperCase()}` : "—"}
                </td>
                <td style={{ padding:"6px 8px" }}>
                  <button
                    onClick={() => remove(s.dedup_key)}
                    disabled={deleting === s.dedup_key}
                    title="Eliminar supresión — el IOC podrá generar un nuevo caso"
                    style={{
                      fontSize:10, padding:"2px 8px", borderRadius:4,
                      background: alpha(C.red, 9), border: `1px solid ${alpha(C.red, 25)}`,
                      color:C.red, cursor:"pointer",
                    }}
                  >
                    {deleting === s.dedup_key ? "…" : "Liberar"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {expired.length > 0 && (
        <details style={{ marginTop:12 }}>
          <summary style={{ fontSize:11, color:C.textDim, cursor:"pointer" }}>
            {expired.length} supresión{expired.length !== 1 ? "es" : ""} vencida{expired.length !== 1 ? "s" : ""} (historial)
          </summary>
          <div style={{ marginTop:8, fontSize:10, color:C.textDim }}>
            {expired.map((s) => (
              <div key={s.dedup_key} style={{ padding:"3px 8px" }}>
                {s.original_ioc} · {s.reason} · venció {fmt(s.suppressed_until)}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

// ── SortHeader ─────────────────────────────────────────────────────────────────

function SortHeader({
  label, col, sort, sortDir, onSort, style,
}: {
  label: string; col: string; sort: string; sortDir: "asc" | "desc";
  onSort: (col: string) => void; style?: React.CSSProperties;
}) {
  const active = sort === col;
  return (
    <button
      onClick={() => onSort(col)}
      style={{
        ...style,
        background: "none", border: "none", cursor: "pointer",
        color: active ? C.cyan : C.textDim,
        fontSize: 10, letterSpacing: "0.1em", fontWeight: active ? 700 : 400,
        display: "inline-flex", alignItems: "center", gap: 3, padding: 0,
        textAlign: (style?.textAlign as React.CSSProperties["textAlign"]) ?? "left",
        justifyContent: style?.textAlign === "right" ? "flex-end" : "flex-start",
      }}
    >
      {label}
      {active
        ? (sortDir === "asc"
            ? <ChevronUp size={9} />
            : <ChevronDown size={9} />)
        : <ChevronUp size={9} style={{ opacity: 0.2 }} />}
    </button>
  );
}

// ── CaseRow ────────────────────────────────────────────────────────────────────

const CaseRow = memo(function CaseRow({
  case: c,
  profiles,
  myOperatorCi,
  operatorNames,
  onSelect,
  onAdopt,
  onChanged,
  isFocused = false,
  selected = false,
  onToggleSelect,
}: {
  case: SocCase;
  profiles: ReturnType<typeof loadProfiles>;
  /** CI del operador actual, para marcar las filas adoptadas por él. null si
   *  el operador no configuró aún su CI (lab sin auth, etc.). */
  myOperatorCi: string | null;
  /** Mapa CI → nombre completo (soc_operators). Permite mostrar "Roberto
   *  Insfran" en lugar de "3988739" sin cambiar la API ni el modelo de datos. */
  operatorNames: Record<string, string>;
  onSelect:      (c: SocCase) => void;
  onAdopt:       (c: SocCase) => void;
  /** Refresca la cola tras una transición inline de estado. */
  onChanged?:    () => void;
  /** Fila enfocada por teclado (j/k). Acent visual + scroll-into-view. */
  isFocused?: boolean;
  /** Multi-select (P0 #12): fila marcada para acción masiva. */
  selected?: boolean;
  onToggleSelect?: (id: string) => void;
}) {
  const operatorDisplay = c.operatorCi
    ? (operatorNames[c.operatorCi] ?? c.operatorCi)
    : null;
  const sevColor     = SEV_COLOR[c.severity] ?? C.cyan;
  const triggering   = getTriggeringProfiles(c, profiles);
  const isMine       = Boolean(myOperatorCi) && c.operatorCi === myOperatorCi;

  /* Nombre del activo monitoreado (hostname o identificador). */
  const assetName = c.hostname || c.srcIp || "—";
  const isActionable = triggering.length > 0 && !c.adoptedAt;

  const escalated   = isEscalatedCase(c);
  const resolved    = isResolvedCase(c);
  const adoptedOpen = Boolean(c.adoptedAt) && !resolved;

  /** Caso CRITICAL abierto y sin adoptar — necesita resaltado urgente. */
  const isCriticalUnadopted =
    c.severity === "CRITICAL" &&
    !c.adoptedAt &&
    !resolved;

  const slaPct  = calcSlaPct(c.detectedAt, c.slaSec);
  const slaClr  = slaPct == null ? C.textDim : slaColor(slaPct);

  /** SLA en brecha para caso sin owner (>=90% consumido). Alimenta el pulse
   *  izquierdo — cubre HIGH/MEDIUM/LOW que se pasan del SLA en silencio. */
  const isSlaBreachUnadopted = slaPct != null && slaPct >= 90 && !c.adoptedAt && !resolved;

  /** Estados urgentes: escalado abierto, CRITICAL sin dueño, o SLA breach.
   *  Disparan el pulse bar izquierdo (única señal de color en la fila). */
  const isHighPriority = (escalated && !resolved) || isCriticalUnadopted || isSlaBreachUnadopted;
  const priorityColor  = escalated ? C.orange
                        : isSlaBreachUnadopted && !isCriticalUnadopted ? C.orange
                        : C.red;

  return (
    <div style={{ position: "relative", opacity: resolved ? 0.55 : 1 }}>
      {/* Pulsing left border for high-priority cases (critical unadopted or escalated) */}
      {isHighPriority && (
        <div
          className="lh-critical-pulse-bar"
          style={{
            position: "absolute", left: 0, top: 0, bottom: 0,
            width: 4, borderRadius: "2px 0 0 2px",
            background: priorityColor,
            animation: "lh-critical-pulse 1.8s ease-in-out infinite",
            zIndex: 2,
          }}
        />
      )}

      {/* Profile badge — shown above the row */}
      {triggering.length > 0 && (
        <div style={{
          position: "absolute", top: 2, right: 8,
          display: "flex", gap: 4, zIndex: 1,
        }}>
          {triggering.map((p) => (
            <span
              key={p.id}
              title={`Perfil: ${p.name}`}
              style={{
                fontSize: 9, padding: "1px 5px", borderRadius: 3,
                background: alpha(C.cyan, 6), border: `1px solid ${alpha(C.cyan, 15)}`,
                color: C.cyan, letterSpacing: "0.04em",
                fontWeight: 600, whiteSpace: "nowrap",
              }}
            >
              {p.name}
            </span>
          ))}
        </div>
      )}

    <div
      id={`lh-case-row-${c.id}`}
      onClick={() => onSelect(c)}
      style={{
        ...tableRowStyle,
        cursor: "pointer",
        borderBottom: `1px solid ${C.border}`,
        paddingLeft: isHighPriority ? 12 : undefined,
        outline: isFocused ? `2px solid ${C.cyan}` : "none",
        outlineOffset: isFocused ? -2 : 0,
        // Filas críticas sin adoptar: tinte rose-50 en claro (~5% rose-800
        // sobre blanco) / rojo tenue en oscuro. Refuerza el pulse izquierdo
        // y permite localizar la fila al hacer scan vertical sin colorear
        // todo el listado. Las filas escaladas/breach se quedan transparentes
        // para no saturar la grilla.
        background: isCriticalUnadopted ? alpha(C.red, 5) : "transparent",
      }}
      onMouseEnter={(e) => {
        // Hover sutil: 4% del color de texto sobre la fila. En claro tinta
        // hacia gris oscuro; en oscuro tinta hacia blanco — funciona en todos
        // los temas sin invertir contraste.
        (e.currentTarget as HTMLDivElement).style.background = isCriticalUnadopted
          ? alpha(C.red, 9)
          : alpha(C.text, 4);
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.background = isCriticalUnadopted
          ? alpha(C.red, 5)
          : "transparent";
      }}
    >
      {/* Multi-select (P0 #12): checkbox para acción masiva. stopPropagation
          evita que el click abra el detalle del caso. */}
      {onToggleSelect && (
        <input
          type="checkbox"
          checked={selected}
          aria-label="Seleccionar caso"
          onClick={(e) => { e.stopPropagation(); }}
          onChange={() => onToggleSelect(c.id)}
          style={{ flexShrink: 0, width: 15, height: 15, cursor: "pointer", accentColor: C.cyan }}
        />
      )}
      {/* Case ID + owner: siempre se ve QUIÉN es el dueño del caso.
          - Adoptado por otro   → "@<ci>" en gris (sabés a quién pedir handoff)
          - Adoptado por vos    → "TÚ"    en cyan tenue (identificación rápida)
          - Sin adoptar         → nada    (el pulse izquierdo ya marca urgencia)
          El chip de edad (⏱) se removió — es redundante con las columnas
          DETECTADO + SLA que muestran la misma info con más precisión. */}
      <div style={{ width: 72, flexShrink: 0, display: "flex", flexDirection: "column", gap: 2 }}>
        <span style={{ fontFamily: "monospace", fontSize: 10, color: C.textDim, background: alpha(C.border, 50), borderRadius: 3, padding: "1px 5px", width: "fit-content" }} title={c.id}>
          {caseCode(c)}
        </span>
        {isMine && (
          <span
            title="Vos sos el owner de este caso"
            style={{
              fontFamily: "monospace", fontSize: 9, fontWeight: 700,
              color: C.cyan, border: `1px solid ${alpha(C.cyan, 33)}`,
              borderRadius: 3, padding: "0 5px", letterSpacing: "0.08em",
              width: "fit-content",
            }}
          >
            TÚ
          </span>
        )}
        {!isMine && c.operatorCi && !resolved && (
          <span
            // Tooltip conserva el CI para trazabilidad / auditoría; el chip
            // muestra el nombre humano resuelto desde soc_operators.
            title={`Adoptado por ${operatorDisplay} · CI ${c.operatorCi}${c.adoptedAt ? ` · ${relativeTime(c.adoptedAt)}` : ""}`}
            style={{
              fontSize: 10, color: C.textDim,
              border: `1px solid ${C.border}`, borderRadius: 3, padding: "0 5px",
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              width: "fit-content", maxWidth: 140,
            }}
          >
            {operatorDisplay}
          </span>
        )}
        {/* P1.4 (audit 2026-05-27): chip explícito "sin owner" para huérfanos
            abiertos. Antes la ausencia del chip era ambigua (¿mío? ¿de nadie?);
            ahora el LEADER barre la grilla y ve los candidatos a adoptar/asignar
            sin necesidad de filtrar. */}
        {!isMine && !c.operatorCi && !resolved && (
          <span
            title="Caso sin owner — adoptar o asignar antes del SLA"
            style={{
              fontSize: 9, fontWeight: 700, letterSpacing: "0.06em",
              color: C.orange, border: `1px solid ${alpha(C.orange, 38)}`,
              background: alpha(C.orange, 8),
              borderRadius: 3, padding: "0 5px", width: "fit-content",
            }}
          >
            SIN OWNER
          </span>
        )}
        {/* Badge de fusión (R1 audit 2026-05-13): caso CERRADO por merge en otro
            canónico. El click copia el ID canónico al clipboard para que el
            operador lo pegue en el buscador. Navegación directa queda como
            follow-up (requiere router con deep-link a caso individual). */}
        {c.mergedIntoCaseId && (
          <span
            onClick={(e) => {
              e.stopPropagation();
              navigator.clipboard?.writeText(c.mergedIntoCaseId ?? "").catch(() => {});
            }}
            title={`Este caso fue fusionado en ${c.mergedIntoCaseId} · click copia el ID al portapapeles`}
            style={{
              fontFamily: "monospace", fontSize: 9, fontWeight: 600,
              color: C.cyan, border: `1px solid ${alpha(C.cyan, 33)}`,
              background: alpha(C.cyan, 6),
              borderRadius: 3, padding: "0 5px", letterSpacing: "0.04em",
              width: "fit-content", cursor: "pointer",
            }}
          >
            🔗 Fusionado en #{c.mergedIntoCaseId.slice(0, 7).toUpperCase()}
          </span>
        )}
      </div>

      {/* Sensor */}
      <div style={{ flex: 2, minWidth: 0 }}>
        <div style={{ fontFamily: "monospace", fontSize: 13, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 5 }}>
          {(() => {
            const Icon = iocTypeIcon(c.iocType);
            return <Icon size={11} style={{ flexShrink: 0, color: C.textDim }} aria-label={c.iocType} />;
          })()}
          {assetName}
        </div>
        <div style={{ fontSize: 11, color: C.textDim, display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
          <span>{c.sourceLabel || c.source || "—"}</span>
          {c.assetsCount > 0 && (
            <span
              title={`${c.assetsCount} activo(s) asociado(s)`}
              style={{
                display: "inline-flex", alignItems: "center", gap: 2,
                fontSize: 10, fontWeight: 600,
                color: c.assetsCount >= 3 ? C.text : C.textDim,
              }}
            >
              · {c.assetsCount} host{c.assetsCount === 1 ? "" : "s"}
            </span>
          )}
        </div>
        {/* Línea 3: acción recomendada si existe. Texto gris compacto — es la
            info operativa más útil del row ("qué hago con esto"). Truncada a
            1 línea vía ellipsis para no romper la grilla. */}
        {c.recommendedAction && (
          <div
            title={c.recommendedAction}
            style={{
              fontSize: 10, color: C.textDim, fontStyle: "italic",
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              marginTop: 2,
            }}
          >
            → {c.recommendedAction}
          </div>
        )}
      </div>

      <div style={{ width: 80 }}>
        <span style={{
          fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
          background: alpha(sevColor, 22), color: sevColor, border: `1px solid ${alpha(sevColor, 31)}`,
        }}>
          {c.severity}
        </span>
      </div>

      <div style={{ width: 110 }}>
        <StatusMenu c={c} onChanged={onChanged} onOpen={() => onSelect(c)} />
        {escalated && !resolved && (
          <span
            title={
              c.escalation
                ? `Escalado a ${c.escalation.escalatedTo ?? c.escalation.level}${c.escalation.reason ? ` — ${c.escalation.reason}` : ""}`
                : "Caso en estado ESCALADO"
            }
            style={{
              display: "inline-block", marginTop: 3, fontSize: 8, padding: "1px 5px",
              borderRadius: 3, fontWeight: 700, letterSpacing: "0.05em",
              background: alpha(C.orange, 22), color: C.orange, border: `1px solid ${alpha(C.orange, 44)}`,
            }}
          >
            ⬆ ESCALADO
          </span>
        )}
        {isCriticalUnadopted && (
          <span title="Caso crítico sin operador asignado" style={{
            display: "inline-block", marginTop: 3, fontSize: 8, padding: "1px 5px",
            borderRadius: 3, fontWeight: 700, letterSpacing: "0.05em",
            background: alpha(C.red, 22), color: C.red, border: `1px solid ${alpha(C.red, 44)}`,
          }}>
            ⚠ SIN ADOPTAR
          </span>
        )}
        {adoptedOpen && (
          <span
            title={`Adoptado por ${operatorDisplay ?? "—"}${c.operatorCi ? ` · CI ${c.operatorCi}` : ""}${c.adoptedAt ? ` · ${formatDateTimePy(c.adoptedAt)}` : ""}`}
            style={{
              display: "inline-block", marginTop: 3, fontSize: 9, padding: "1px 5px",
              borderRadius: 3, fontWeight: 700, letterSpacing: "0.02em",
              background: alpha(C.green, 22), color: C.green, border: `1px solid ${alpha(C.green, 44)}`,
              maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}
          >
            ✓ {operatorDisplay ?? "ADOPTADO"}
          </span>
        )}
        {c.status === "CERRADO" && c.closureReason?.includes("auto-closed") && (
          <span title={c.closureReason ?? ""} style={{
            display: "inline-block", marginTop: 3, fontSize: 8, padding: "1px 5px",
            borderRadius: 3, fontWeight: 600, letterSpacing: "0.04em",
            background: alpha(C.neutral, 22), color: C.neutral, border: `1px solid ${alpha(C.neutral, 44)}`,
          }}>
            AUTO
          </span>
        )}
        {/* Tiempo en estado actual — detecta casos estancados a simple vista.
            Ahora cubre TODOS los estados vía statusEnteredAt (stage_entered_at,
            poblado por transitionCase); fallback por estado para casos pre-fix.
            Resalta en rojo cuando supera el umbral de frescura por severidad. */}
        {(() => {
          const sinceTs = c.statusEnteredAt ?? (
            c.status === "NUEVO"       ? c.createdAt :
            c.status === "EN_ANALISIS" ? (c.adoptedAt ?? c.createdAt) :
            (c.status === "CERRADO" || c.status === "FALSO_POSITIVO")
              ? (c.resolvedAt ?? c.createdAt)
              : c.createdAt
          );
          if (!sinceTs) return null;
          const ageMin = (Date.now() - Date.parse(sinceTs)) / 60000;
          const thresh = c.severity === "CRITICAL" ? 15 : c.severity === "HIGH" ? 60
                       : c.severity === "MEDIUM" ? 240 : 1440;
          const stale = !resolved && Number.isFinite(ageMin) && ageMin > thresh;
          return (
            <span title={`En ${STATUS_LABEL[c.status] ?? c.status} desde ${formatDateTimePy(sinceTs)}`} style={{
              display: "block", marginTop: 3, fontSize: 9,
              color: stale ? C.red : C.textDim, fontWeight: stale ? 700 : 400,
              fontVariantNumeric: "tabular-nums",
            }}>
              {stale ? "⏱ " : ""}{relativeTime(sinceTs)}
            </span>
          );
        })()}
      </div>

      {/* Lifecycle stage */}
      <div style={{ width: 100 }}>
        {(c as SocCase & { lifecycle_stage?: string }).lifecycle_stage && (
          <LifecycleStageBadge stage={(c as SocCase & { lifecycle_stage?: string }).lifecycle_stage!} />
        )}
        {(c as SocCase & { escalation_suggested?: boolean }).escalation_suggested && (
          <span style={{
            display: "block", marginTop: 2, fontSize: 9, color: C.orange,
            fontWeight: 600,
          }}>▲ Escalar</span>
        )}
      </div>

      <div style={{ width: 120, textAlign: "right", fontSize: 11, color: C.textDim,
                    display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2 }}
           title={c.detectedAt ? formatDateTimePy(c.detectedAt) : ""}>
        <span>
          {c.detectedAt
            ? formatDateTimePy(c.detectedAt, {
                year: undefined, second: undefined,
                day: "2-digit", month: "2-digit",
                hour: "2-digit", minute: "2-digit",
              })
            : "—"}
        </span>
        {!resolved && <AgeChip detectedAt={c.detectedAt} slaSec={c.slaSec} />}
      </div>

      {/* Creado: timestamp de inserción del caso en la cola SOC (PG.created_at) */}
      <div style={{ width: 110, textAlign: "right", fontSize: 11, color: C.textDim }}
           title={c.createdAt ? formatDateTimePy(c.createdAt) : ""}>
        {c.createdAt ? relativeTime(c.createdAt) : "—"}
      </div>

      <div style={{ width: 80, textAlign: "right" }}>
        {slaPct != null ? (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2 }}
               title={`SLA consumido: ${slaPct}%`}>
            <span style={{
              fontSize: 11, color: slaClr, fontWeight: 700,
              fontVariantNumeric: "tabular-nums", fontFamily: "monospace",
            }}>
              {formatSlaRemaining(c.detectedAt, c.slaSec) ?? "—"}
            </span>
            <div style={{ width: 52, height: 3, borderRadius: 2, background: C.border, overflow: "hidden" }}>
              <div style={{
                height: "100%", borderRadius: 2, transition: "width 0.3s",
                width: `${Math.min(100, slaPct)}%`,
                background: slaPct >= 100 ? C.red : slaPct >= 80 ? C.orange : slaPct >= 60 ? C.orange : C.green,
              }} />
            </div>
          </div>
        ) : "—"}
        {isActionable && (
          <button
            onClick={(e) => { e.stopPropagation(); onAdopt(c); }}
            style={{
              marginLeft: 6, fontSize: 10, padding: "2px 7px", borderRadius: 4,
              background: alpha(sevColor, 12), border: `1px solid ${alpha(sevColor, 25)}`,
              color: sevColor, cursor: "pointer",
            }}
          >
            Adoptar
          </button>
        )}
      </div>
    </div>
    </div>
  );
});


// ── KPI Strip ──────────────────────────────────────────────────────────────────

const STATUS_DIST_COLORS: Record<string, string> = {
  NUEVO:          C.blue,
  EN_ANALISIS:    C.orange,
  CONFIRMADO:     C.red,
  ESCALADO:       C.orange,
  MONITOREADO:    C.info,
  FALSO_POSITIVO: C.green,
  CERRADO:        C.neutral,
};

function KpiStrip({
  kpis,
  isLoading,
  statusDist,
  onStatusFilter,
  activeStatus,
  onSevFilter,
  onIncludeClosed,
}: {
  kpis: DashboardKpis | undefined;
  isLoading: boolean;
  statusDist?: Array<{ status: string; severity: string; cnt: string | number }>;
  onStatusFilter: (s: CaseStatus | "ALL") => void;
  activeStatus: CaseStatus | "ALL";
  onSevFilter?: (s: Severity | "ALL") => void;
  onIncludeClosed?: (b: boolean) => void;
}) {
  const loading = isLoading || !kpis;
  const slaRate = kpis && kpis.criticalSlaTotal > 0
    ? Math.round((kpis.criticalSlaOk / kpis.criticalSlaTotal) * 100)
    : null;
  // Bloque (4): texto de ventana usado en los tooltips de Resueltos hoy /
  // Ack promedio. "Hoy" en backend = hora local del proceso desde 00:00.
  const todayHint = "ventana: desde las 00:00 hora local del servidor";

  // Aggregate by status
  const byStatus: Record<string, number> = {};
  for (const row of statusDist ?? []) {
    byStatus[row.status] = (byStatus[row.status] ?? 0) + Number(row.cnt);
  }
  const statusEntries = Object.entries(byStatus).sort(
    ([a], [b]) =>
      ["NUEVO","EN_ANALISIS","CONFIRMADO","ESCALADO","MONITOREADO","FALSO_POSITIVO","CERRADO"].indexOf(a)
      - ["NUEVO","EN_ANALISIS","CONFIRMADO","ESCALADO","MONITOREADO","FALSO_POSITIVO","CERRADO"].indexOf(b)
  );

  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <KpiCard
          label="Casos abiertos"
          value={loading ? "…" : String(kpis!.openCases)}
          color={C.cyan}
          icon={Shield}
          title="Total de casos no cerrados ni FP (estado ≠ CERRADO/FP) · click: ver todos abiertos"
          onClick={() => { onStatusFilter("ALL"); onIncludeClosed?.(false); }}
        />
        {/* (3) SLA Critical: distinguimos "no hay denominador" ("—") de "0%
            real". El primero pasa cuando no hay críticos en ventana y NO debe
            renderizarse rojo. Tooltip explicita el cociente para auditoría. */}
        <KpiCard
          label="SLA Critical"
          value={loading
            ? "…"
            : slaRate == null
              ? "—"
              : `${slaRate}%`}
          color={slaRate == null
            ? C.textDim
            : slaRate >= 80 ? C.green
            : slaRate >= 60 ? C.orange
            : C.red}
          icon={Clock}
          title={
            loading || !kpis
              ? "Cargando…"
              : kpis.criticalSlaTotal === 0
                ? "Sin casos CRITICAL en ventana — no hay denominador (n/d, no 0%)"
                : `${kpis.criticalSlaOk}/${kpis.criticalSlaTotal} críticos dentro del SLA · click: filtrar CRITICAL abiertos`
          }
          sub={!loading && kpis && kpis.criticalSlaTotal > 0
            ? `${kpis.criticalSlaOk}/${kpis.criticalSlaTotal} en SLA`
            : undefined}
          onClick={() => { onSevFilter?.("CRITICAL"); onIncludeClosed?.(false); }}
        />
        {/* (4) Tooltip exacto de ventana para Ack promedio + Resueltos hoy. */}
        <KpiCard
          label="Ack promedio (min)"
          value={loading || kpis!.criticalAvgAckMin == null ? "—" : String(kpis!.criticalAvgAckMin)}
          color={C.orange}
          icon={Clock}
          title={`Minutos promedio entre creación del caso y primera adopción (críticos) · ${todayHint}`}
        />
        <KpiCard
          label="Resueltos hoy"
          value={loading ? "…" : String(kpis!.resolvedToday)}
          color={C.green}
          icon={CheckCircle}
          title={`Casos cerrados manualmente (no auto) · ${todayHint}`}
        />
        <KpiCard
          label="En monitoreo"
          value={loading ? "…" : String(kpis!.monitoring)}
          color={C.cyan}
          icon={Shield}
          title="Casos en estado MONITOREADO (sospechosos sin confirmar) · click: filtrar"
          onClick={() => { onStatusFilter("MONITOREADO"); onIncludeClosed?.(false); }}
        />
        <KpiCard
          label="Auto FP (7d)"
          value={loading ? "…" : String(kpis!.autoFp)}
          color={C.textDim}
          icon={CheckCircle}
          title="Casos auto-marcados como Falso Positivo por el sistema en los últimos 7 días · click: filtrar FP"
          onClick={() => { onStatusFilter("FALSO_POSITIVO"); onIncludeClosed?.(true); }}
        />
        <KpiCard
          label="Auto-cerrados LOW/NEG (7d)"
          value={loading ? "…" : String(kpis!.autoClosedLow ?? 0)}
          color={C.neutral}
          icon={CheckCircle}
          title="Casos LOW o NEGLIGIBLE cerrados automáticamente por el sistema en los últimos 7 días · click: ver cerrados"
          onClick={() => { onStatusFilter("CERRADO"); onIncludeClosed?.(true); }}
        />
      </div>

      {/* Status distribution pills — clickable to filter */}
      {statusEntries.length > 0 && (
        <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
          {/* "All" pill */}
          <button
            onClick={() => onStatusFilter("ALL")}
            style={{
              display: "flex", alignItems: "center", gap: 5,
              background: activeStatus === "ALL" ? alpha(C.text, 9) : "transparent",
              border: `1px solid ${activeStatus === "ALL" ? alpha(C.text, 25) : C.border}`,
              borderRadius: 6, padding: "4px 10px", cursor: "pointer",
            }}
          >
            <span style={{ fontSize: 10, color: activeStatus === "ALL" ? C.text : C.textDim, letterSpacing: "0.04em" }}>
              Todos
            </span>
          </button>

          {statusEntries.map(([status, cnt]) => {
            const color = STATUS_DIST_COLORS[status] ?? C.textDim;
            const isActive = activeStatus === status;
            return (
              <button
                key={status}
                onClick={() => onStatusFilter(status as CaseStatus)}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  background: isActive ? alpha(color, 26) : alpha(color, 14),
                  border: `1px solid ${isActive ? alpha(color, 55) : alpha(color, 31)}`,
                  borderRadius: 6, padding: "4px 10px",
                  cursor: "pointer",
                  boxShadow: isActive ? `0 0 0 1px ${alpha(color, 28)}` : undefined,
                  transition: "all 0.12s",
                }}
              >
                <span style={{ fontSize: 16, fontWeight: 700, color }}>{cnt}</span>
                <span style={{ fontSize: 10, color: isActive ? color : C.textDim, letterSpacing: "0.04em" }}>
                  {STATUS_LABEL[status] ?? status}
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function KpiCard({
  label, value, color, icon: Icon, title, onClick, sub,
}: {
  label: string; value: string; color: string; icon: React.ElementType;
  title?: string; onClick?: () => void; sub?: React.ReactNode;
}) {
  const isClickable = !!onClick;
  return (
    <div
      title={title}
      onClick={onClick}
      role={isClickable ? "button" : undefined}
      tabIndex={isClickable ? 0 : undefined}
      onKeyDown={isClickable ? (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick!(); }
      } : undefined}
      style={{
        background: C.card, border: `1px solid ${C.border}`,
        borderRadius: 8, padding: "12px 16px", flex: "1 1 120px",
        cursor: isClickable ? "pointer" : title ? "help" : undefined,
        transition: "border-color 0.12s, background 0.12s",
        ...(isClickable ? {
          // Borde sutil cambia al hover — usamos box-shadow porque inline styles
          // no soportan :hover. CSS-in-JS sería overkill; nos quedamos con
          // hover via JSX onMouseEnter/Leave ⇒ overhead. En cambio:
        } : {}),
      }}
      onMouseEnter={isClickable ? (e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = alpha(color, 50);
      } : undefined}
      onMouseLeave={isClickable ? (e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = C.border;
      } : undefined}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
        <Icon size={12} color={color} />
        <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.05em" }}>{label}</span>
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value}</div>
      {sub != null && (
        <div style={{ fontSize: 9, color: C.textDim, marginTop: 2 }}>{sub}</div>
      )}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// Transiciones NO terminales ofrecidas inline (espejo de VALID_TRANSITIONS del
// backend, sin CERRADO/FALSO_POSITIVO — esos exigen clasificación NIST y se
// resuelven abriendo el caso). El backend revalida con RBAC + state machine.
const INLINE_TRANSITIONS: Record<string, string[]> = {
  NUEVO:       ["EN_ANALISIS", "MONITOREADO"],
  EN_ANALISIS: ["CONFIRMADO", "ESCALADO", "MONITOREADO"],
  CONFIRMADO:  ["ESCALADO", "MONITOREADO"],
  MONITOREADO: ["EN_ANALISIS", "ESCALADO"],
  ESCALADO:    ["CONFIRMADO"],
  FALSO_POSITIVO: [],
  CERRADO:     [],
};

/**
 * StatusMenu — badge de estado con transición rápida inline (P estado 2026-06-07).
 * Click en el badge → menú con las transiciones válidas del estado actual; aplica
 * vía PATCH /api/incidents/:id/status (el backend valida RBAC + máquina de estados).
 * CERRADO/FP y reapertura se delegan a "Abrir caso" (flujo con clasificación).
 */
function StatusMenu({ c, onChanged, onOpen }: { c: SocCase; onChanged?: () => void; onOpen: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState<string | null>(null);
  const targets  = INLINE_TRANSITIONS[c.status] ?? [];
  const resolved = c.status === "CERRADO" || c.status === "FALSO_POSITIVO";

  async function go(toStatus: string) {
    setBusy(true); setErr(null);
    try {
      await api.patch(`/api/incidents/${c.id}/status`, {
        status: toStatus, reason: "Triaje rápido desde la cola",
      });
      setOpen(false);
      onChanged?.();
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Error al cambiar estado";
      setErr(msg.length > 60 ? msg.slice(0, 60) + "…" : msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <span style={{ position: "relative", display: "inline-block" }}>
      <button
        onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
        title="Cambiar estado"
        style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}
      >
        <StatusBadge status={c.status} />
        <span style={{ fontSize: 8, marginLeft: 2, color: C.textDim }}>▾</span>
      </button>
      {open && (
        <>
          {/* backdrop para cerrar al click afuera */}
          <span onClick={(e) => { e.stopPropagation(); setOpen(false); }}
            style={{ position: "fixed", inset: 0, zIndex: 40 }} />
          <div onClick={(e) => e.stopPropagation()} style={{
            position: "absolute", top: "100%", left: 0, marginTop: 4, zIndex: 41,
            minWidth: 150, background: C.card,
            border: `1px solid ${alpha(C.textDim, 44)}`, borderRadius: 6,
            boxShadow: "0 8px 24px rgba(0,0,0,.4)", padding: 4,
          }}>
            <div style={{ fontSize: 8, textTransform: "uppercase", color: C.textDim, padding: "2px 6px", letterSpacing: "0.05em" }}>
              Cambiar a
            </div>
            {targets.map((t) => (
              <button key={t} disabled={busy} onClick={() => void go(t)} style={{
                display: "block", width: "100%", textAlign: "left", background: "none",
                border: "none", color: C.text, fontSize: 11, padding: "5px 8px",
                borderRadius: 4, cursor: busy ? "wait" : "pointer",
              }}
                onMouseEnter={(e) => (e.currentTarget.style.background = alpha(C.textDim, 18))}
                onMouseLeave={(e) => (e.currentTarget.style.background = "none")}
              >
                {STATUS_LABEL[t] ?? t}
              </button>
            ))}
            <div style={{ borderTop: `1px solid ${alpha(C.textDim, 22)}`, margin: "4px 0" }} />
            <button disabled={busy} onClick={() => { setOpen(false); onOpen(); }} style={{
              display: "block", width: "100%", textAlign: "left", background: "none",
              border: "none", color: C.cyan, fontSize: 11, padding: "5px 8px",
              borderRadius: 4, cursor: "pointer",
            }}>
              {resolved ? "Reabrir / ver caso…" : "Cerrar / FP / ver caso…"}
            </button>
            {err && <div style={{ fontSize: 9, color: C.red, padding: "3px 8px" }}>{err}</div>}
          </div>
        </>
      )}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const COLORS: Record<string, string> = {
    NUEVO: C.blue, EN_ANALISIS: C.orange, CONFIRMADO: C.red,
    ESCALADO: C.orange, MONITOREADO: C.info, FALSO_POSITIVO: C.green, CERRADO: C.neutral,
  };
  const c = COLORS[status] ?? C.textDim;
  return (
    <span style={{
      fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 600,
      background: alpha(c, 22), color: c, border: `1px solid ${alpha(c, 31)}`,
    }}>
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

// ── DuplicatePanel ────────────────────────────────────────────────────────────

interface DupCase {
  case_id:          string;
  source_log:       string;
  severity_text:    string;
  severity_score:   number;
  status:           string;
  assigned_to:      string | null;
  first_seen:       string | null;
  occurrence_count: number;
  dedup_key:        string;
}

interface DupGroup {
  ioc_value:         string;
  ioc_type:          string;
  group_count:       number;
  total_occurrences: number;
  is_internal:       boolean;
  cases:             DupCase[];
}

function DuplicatePanel({
  operatorCi,
  onClose,
  onMerged,
}: { operatorCi: string; onClose: () => void; onMerged: () => void }) {
  const [groups,      setGroups]      = React.useState<DupGroup[]>([]);
  const [loading,     setLoading]     = React.useState(true);
  const [error,       setError]       = React.useState<string | null>(null);
  const [merging,     setMerging]     = React.useState<string | null>(null);
  const [mergingAll,  setMergingAll]  = React.useState(false);
  const [mergeMsg,    setMergeMsg]    = React.useState<Record<string, string>>({});
  const [allMsg,      setAllMsg]      = React.useState<string | null>(null);
  const [expanded,    setExpanded]    = React.useState<Record<string, boolean>>({});
  // B5 — Modo de agrupamiento. `ioc_value` da radio de impacto (misma IP en
  // varias tácticas aparece junta); `dedup_key` se alinea con la política
  // de deduplicación del DAG y sólo agrupa los duplicados "verdaderos".
  const [groupBy, setGroupBy] = React.useState<"ioc_value" | "dedup_key">("ioc_value");

  async function load() {
    setLoading(true); setError(null);
    try {
      const { data: d } = await api.get<{ ok: boolean; groups?: DupGroup[]; error?: string }>(
        `/api/incidents/duplicates?groupBy=${groupBy}`,
      );
      if (!d.ok) throw new Error(d.error ?? "Error cargando duplicados");
      setGroups(d.groups ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setLoading(false); }
  }

  // Re-load cuando cambia el eje de agrupamiento.
  React.useEffect(() => { void load(); }, [groupBy]);

  // Select canonical: highest severity then oldest first_seen
  function selectCanonical(cases: DupCase[]): string {
    const rank: Record<string, number> = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NEGLIGIBLE: 5 };
    return [...cases].sort((a, b) => {
      const ra = rank[a.severity_text] ?? 6;
      const rb = rank[b.severity_text] ?? 6;
      if (ra !== rb) return ra - rb;
      return (a.first_seen ?? "").localeCompare(b.first_seen ?? "");
    })[0]?.case_id ?? cases[0].case_id;
  }

  async function mergeGroup(group: DupGroup, canonicalId: string): Promise<boolean> {
    const dupIds = group.cases.map((c) => c.case_id).filter((id) => id !== canonicalId);
    if (dupIds.length === 0) return true;
    const { data: d } = await api.post<{ ok: boolean; merged?: number; newOccurrenceCount?: number; error?: string }>(
      "/api/incidents/merge",
      { canonicalCaseId: canonicalId, duplicateCaseIds: dupIds, operatorCi },
    );
    if (!d.ok) throw new Error(d.error ?? "merge failed");
    return true;
  }

  async function merge(group: DupGroup, canonicalId: string) {
    const key = group.ioc_value;
    setMerging(key); setMergeMsg((p) => ({ ...p, [key]: "" }));
    try {
      await mergeGroup(group, canonicalId);
      const dupCount = group.cases.length - 1;
      const summary = `${dupCount} duplicado${dupCount !== 1 ? "s" : ""} fusionado${dupCount !== 1 ? "s" : ""}`;
      setMergeMsg((p) => ({ ...p, [key]: `✓ ${summary}` }));
      toast.success(`Casos fusionados: ${summary}`, { description: `IOC: ${key}` });
      setGroups((prev) => prev.filter((g) => g.ioc_value !== key));
      onMerged();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setMergeMsg((p) => ({ ...p, [key]: `Error: ${msg}` }));
      toast.error("No se pudo fusionar el grupo", { description: msg });
    } finally { setMerging(null); }
  }

  async function mergeAll() {
    if (groups.length === 0) return;
    setMergingAll(true); setAllMsg(null);
    let ok = 0; let fail = 0;
    const pending = [...groups];
    for (const g of pending) {
      const canon = selectCanonical(g.cases);
      try {
        await mergeGroup(g, canon);
        setMergeMsg((p) => ({ ...p, [g.ioc_value]: `✓ fusionado` }));
        setGroups((prev) => prev.filter((x) => x.ioc_value !== g.ioc_value));
        ok++;
      } catch (e) {
        setMergeMsg((p) => ({ ...p, [g.ioc_value]: `Error: ${e instanceof Error ? e.message : String(e)}` }));
        fail++;
      }
    }
    setAllMsg(`✓ ${ok} grupo${ok !== 1 ? "s" : ""} fusionado${ok !== 1 ? "s" : ""}${fail > 0 ? ` · ${fail} con error` : ""}`);
    if (ok > 0) onMerged();
    setMergingAll(false);
  }

  return (
    <div style={{
      background: C.card, border: `1px solid ${alpha(C.orange, 25)}`,
      borderRadius: 10, padding: 16, marginBottom: 20,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div>
          <span style={{ fontSize: 13, fontWeight: 700, color: C.orange }}>Duplicados detectados</span>
          <span style={{ fontSize: 11, color: C.textDim, marginLeft: 8 }}>
            {groupBy === "dedup_key"
              ? "Casos con el mismo dedup_key — misma táctica/categoría según la política del DAG"
              : "Casos activos con el mismo IOC — radio de impacto del indicador"}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {/* B5 — Toggle de eje de agrupamiento */}
          <div style={{
            display: "inline-flex", border: `1px solid ${C.border}`, borderRadius: 6,
            overflow: "hidden", fontSize: 11,
          }}>
            <button
              onClick={() => setGroupBy("ioc_value")}
              disabled={loading || mergingAll || merging !== null}
              title="Agrupa por valor del IOC — útil para ver el radio de impacto"
              style={{
                padding: "4px 10px", border: "none", cursor: "pointer",
                background: groupBy === "ioc_value" ? alpha(C.orange, 15) : "transparent",
                color: groupBy === "ioc_value" ? C.orange : C.textDim,
                fontWeight: groupBy === "ioc_value" ? 700 : 400,
              }}
            >
              por IOC
            </button>
            <button
              onClick={() => setGroupBy("dedup_key")}
              disabled={loading || mergingAll || merging !== null}
              title="Agrupa por dedup_key canónico — solo duplicados verdaderos según el DAG"
              style={{
                padding: "4px 10px", border: "none", cursor: "pointer",
                borderLeft: `1px solid ${C.border}`,
                background: groupBy === "dedup_key" ? alpha(C.orange, 15) : "transparent",
                color: groupBy === "dedup_key" ? C.orange : C.textDim,
                fontWeight: groupBy === "dedup_key" ? 700 : 400,
              }}
            >
              por dedup_key
            </button>
          </div>
          {!loading && groups.length > 0 && (
            <button
              onClick={() => void mergeAll()}
              disabled={mergingAll || merging !== null}
              style={{
                ...btnStyle, fontSize: 11,
                color: C.orange, borderColor: alpha(C.orange, 31),
                background: alpha(C.orange, 7),
                display: "flex", alignItems: "center", gap: 5,
                fontWeight: 600,
              }}
              title={`Fusionar automáticamente los ${groups.length} grupos de duplicados`}
            >
              {mergingAll && <RefreshCw size={11} style={{ animation: "spin 0.8s linear infinite" }} />}
              {mergingAll ? "Fusionando…" : `Fusionar todo (${groups.length})`}
            </button>
          )}
          <button onClick={load} style={{ ...btnStyle, fontSize: 11 }}>Actualizar</button>
          <button onClick={onClose} style={{ ...btnStyle, fontSize: 11 }}>Cerrar</button>
        </div>
      </div>

      {loading && <div style={{ color: C.textDim, fontSize: 12 }}>Consultando Trino…</div>}
      {error   && <div style={{ color: C.red,     fontSize: 12 }}>{error}</div>}

      {allMsg && (
        <div style={{
          marginBottom: 10, padding: "6px 12px", borderRadius: 6, fontSize: 12,
          background: allMsg.startsWith("✓") ? alpha(C.green, 8) : alpha(C.red, 8),
          border: `1px solid ${allMsg.startsWith("✓") ? alpha(C.green, 19) : alpha(C.red, 19)}`,
          color: allMsg.startsWith("✓") ? C.green : C.red,
          display: "flex", justifyContent: "space-between", alignItems: "center",
        }}>
          <span>{allMsg}</span>
          <button onClick={() => setAllMsg(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "inherit", fontSize: 14 }}>×</button>
        </div>
      )}

      {!loading && groups.length === 0 && !allMsg && (
        <div style={{ color: C.textDim, fontSize: 12, padding: "8px 0" }}>
          Sin duplicados detectados — todos los IOCs activos tienen un único caso.
        </div>
      )}

      {groups.map((g) => {
        const canon  = selectCanonical(g.cases);
        const isExp  = expanded[g.ioc_value] ?? false;
        const msg    = mergeMsg[g.ioc_value];
        const isBusy = merging === g.ioc_value;

        return (
          <div
            key={g.ioc_value}
            style={{
              marginBottom: 8, padding: "10px 12px", borderRadius: 8,
              background: C.bg, border: `1px solid ${C.border}`,
            }}
          >
            {/* Group header */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span style={{ fontFamily: "monospace", fontSize: 13, color: C.text, fontWeight: 600 }}>{g.ioc_value}</span>
              {g.is_internal && (
                <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: alpha(C.orange, 12), color: C.orange, border: `1px solid ${alpha(C.orange, 19)}`, fontWeight: 700 }}>RFC1918</span>
              )}
              <span style={{ fontSize: 11, color: C.textDim }}>{g.ioc_type}</span>
              <span style={{
                fontSize: 10, padding: "1px 7px", borderRadius: 4,
                background: alpha(C.orange, 12), color: C.orange, border: `1px solid ${alpha(C.orange, 25)}`,
              }}>
                {g.group_count} casos · {g.total_occurrences} ocurrencias
              </span>

              <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                <button
                  onClick={() => setExpanded((p) => ({ ...p, [g.ioc_value]: !isExp }))}
                  style={{ ...btnStyle, fontSize: 10, padding: "3px 8px" }}
                >
                  {isExp ? "Colapsar" : "Expandir"}
                </button>
                {!msg && (
                  <button
                    onClick={() => void merge(g, canon)}
                    disabled={isBusy}
                    style={{
                      ...btnStyle, fontSize: 10, padding: "3px 10px",
                      color: C.orange, borderColor: alpha(C.orange, 25),
                      background: alpha(C.orange, 6),
                    }}
                  >
                    {isBusy ? "Fusionando…" : "Fusionar"}
                  </button>
                )}
              </div>
            </div>

            {/* Merge result message */}
            {msg && (
              <div style={{
                marginTop: 6, padding: "4px 10px", borderRadius: 4, fontSize: 11,
                background: msg.startsWith("✓") ? alpha(C.green, 8) : alpha(C.red, 8),
                color: msg.startsWith("✓") ? C.green : C.red,
                border: `1px solid ${msg.startsWith("✓") ? alpha(C.green, 19) : alpha(C.red, 19)}`,
              }}>
                {msg}
              </div>
            )}

            {/* Expanded case list */}
            {isExp && (
              <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                <div style={{ fontSize: 10, color: C.textDim, marginBottom: 2 }}>
                  Caso canónico: <code style={{ color: C.cyan }}>{canon.slice(0, 8).toUpperCase()}</code>
                  {" "}(mayor severidad · más antiguo)
                </div>
                {g.cases.map((cas) => {
                  const isCanon = cas.case_id === canon;
                  const sevColor = SEV_COLOR[cas.severity_text] ?? C.textDim;
                  return (
                    <div
                      key={cas.case_id}
                      style={{
                        display: "flex", alignItems: "center", gap: 8, padding: "5px 8px",
                        borderRadius: 5, background: isCanon ? alpha(C.cyan, 5) : C.card,
                        border: `1px solid ${isCanon ? alpha(C.cyan, 15) : C.border}`,
                        fontSize: 11,
                      }}
                    >
                      <code style={{ fontSize: 10, color: isCanon ? C.cyan : C.textDim, minWidth: 64 }}>
                        #{cas.case_id.slice(0, 7).toUpperCase()}
                      </code>
                      <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, background: alpha(sevColor, 12), color: sevColor }}>
                        {cas.severity_text}
                      </span>
                      <span style={{ color: C.textDim }}>{cas.source_log}</span>
                      <span style={{ color: C.textDim }}>occ={cas.occurrence_count}</span>
                      {cas.assigned_to && (
                        <span style={{ color: C.textDim, fontFamily: "monospace" }}>{cas.assigned_to}</span>
                      )}
                      {isCanon && (
                        <span style={{ marginLeft: "auto", fontSize: 9, padding: "1px 5px", borderRadius: 3, background: alpha(C.cyan, 12), color: C.cyan, border: `1px solid ${alpha(C.cyan, 25)}` }}>
                          CANÓNICO
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── HandoverPanel ─────────────────────────────────────────────────────────────

interface HandoverReport {
  id: string;
  outgoing_manager_ci: string;
  incoming_manager_ci: string | null;
  shift: string;
  open_cases_count: number;
  critical_open_count: number;
  sla_breached_count: number;
  cases_closed_shift: number;
  mtta_shift_min: number | null;
  mttr_shift_min: number | null;
  notes: string | null;
  pending_actions: string | null;
  created_at: string;
  acknowledged_at: string | null;
}

// Infiere el turno actual a partir de la hora local del navegador.
function currentShift(): "MORNING" | "AFTERNOON" | "NIGHT" {
  const h = new Date().getHours();
  if (h >= 6  && h < 14) return "MORNING";
  if (h >= 14 && h < 22) return "AFTERNOON";
  return "NIGHT";
}

function HandoverPanel({ operatorCi, onClose }: { operatorCi: string; onClose: () => void }) {
  const [reports, setReports]   = React.useState<HandoverReport[]>([]);
  const [loading, setLoading]   = React.useState(true);
  const [error,   setError]     = React.useState<string | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [showForm, setShowForm] = React.useState(false);
  const [notes,    setNotes]    = React.useState("");
  const [pending,  setPending]  = React.useState("");
  const [incoming, setIncoming] = React.useState("");
  const [shift,    setShift]    = React.useState<string>(currentShift());

  // Candidatos a Manager entrante: solo LEADER/ADMIN activos distintos del saliente.
  const { data: allOperators = [] } = useSocOperators();
  const { data: currentShiftMgr }   = useShiftManager();
  const outgoingCi = currentShiftMgr?.id ?? operatorCi;
  const incomingCandidates = React.useMemo(
    () => allOperators
      .filter(o => o.is_active && ["LEADER","ADMIN"].includes(o.role_id) && o.id !== outgoingCi)
      .sort((a,b) => a.name.localeCompare(b.name)),
    [allOperators, outgoingCi],
  );

  async function load() {
    setLoading(true); setError(null);
    try {
      const { data: d } = await api.get<{ ok?: boolean; reports?: HandoverReport[]; error?: string }>(
        "/api/workflow/handover?limit=10",
      );
      if (d.ok) setReports(d.reports ?? []);
      else setError(d.error ?? "Error al cargar reportes");
    } catch (e) { setError(String(e)); } finally { setLoading(false); }
  }

  React.useEffect(() => { void load(); }, []);

  async function createReport() {
    setCreating(true); setError(null);
    try {
      const { data: d } = await api.post<{ ok?: boolean; id?: string; error?: string }>(
        "/api/workflow/handover",
        {
          outgoingManagerCi: outgoingCi,
          incomingManagerCi: incoming.trim() || undefined,
          shift, notes: notes.trim() || undefined,
          pendingActions: pending.trim() || undefined,
        },
        { headers: { "x-operator-ci": outgoingCi } },
      );
      if (!d.ok) throw new Error(d.error ?? "handover create failed");
      setShowForm(false); setNotes(""); setPending(""); setIncoming("");
      void load();
    } catch (e) { setError(String(e)); } finally { setCreating(false); }
  }

  async function acknowledge(reportId: string) {
    try {
      await api.post(
        `/api/workflow/handover/${reportId}/acknowledge`,
        null,
        { headers: { "x-operator-ci": outgoingCi } },
      );
      void load();
    } catch { /* ignorar */ }
  }

  function fmtDate(ts: string) {
    try { return formatDateTimePy(ts, { year: undefined, second: undefined, day:"2-digit", month:"2-digit", hour:"2-digit", minute:"2-digit" }); }
    catch { return ts; }
  }

  return (
    <div style={{ background: C.card, border: `1px solid ${alpha(C.green, 25)}`, borderRadius: 10, padding: 16, marginBottom: 20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom: 12 }}>
        <div>
          <span style={{ fontSize: 13, fontWeight: 700, color: C.green }}>Handover de turno</span>
          <span style={{ fontSize: 11, color: C.textDim, marginLeft: 8 }}>Últimos 10 reportes</span>
        </div>
        <div style={{ display:"flex", gap: 8 }}>
          <button onClick={() => setShowForm((v) => !v)} style={{ ...btnStyle, color:C.green, borderColor: alpha(C.green, 25), fontSize:11 }}>
            {showForm ? "Cancelar" : "+ Crear reporte"}
          </button>
          <button onClick={load}    style={{ ...btnStyle, fontSize:11 }}>Refrescar</button>
          <button onClick={onClose} style={{ ...btnStyle, fontSize:11 }}>Cerrar</button>
        </div>
      </div>

      {showForm && (
        <div style={{ background:C.bg, border:`1px solid ${C.border}`, borderRadius:8, padding:12, marginBottom:16, display:"flex", flexDirection:"column", gap:8 }}>
          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
            <div style={{ display:"flex", flexDirection:"column", gap:3, flex:1 }}>
              <label style={{ fontSize:10, color:C.textDim }}>Manager entrante (LEADER/ADMIN activo)</label>
              <select value={incoming} onChange={e => setIncoming(e.target.value)}
                style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:4, padding:"5px 8px", color:C.text, fontSize:12 }}>
                <option value="">— Sin asignar —</option>
                {incomingCandidates.map(o => (
                  <option key={o.id} value={o.id}>
                    {o.name} · {o.role_id} · {o.id}{o.shift ? ` · ${o.shift}` : ""}
                  </option>
                ))}
              </select>
              {incomingCandidates.length === 0 && (
                <span style={{ fontSize:10, color:C.textDim }}>No hay otros LEADER/ADMIN activos disponibles.</span>
              )}
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:3 }}>
              <label style={{ fontSize:10, color:C.textDim }}>Turno</label>
              <select value={shift} onChange={e => setShift(e.target.value)}
                style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:4, padding:"5px 8px", color:C.text, fontSize:12 }}>
                {["MORNING","AFTERNOON","NIGHT","ON_CALL"].map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:3 }}>
            <label style={{ fontSize:10, color:C.textDim }}>Notas del turno</label>
            <textarea rows={2} value={notes} onChange={e => setNotes(e.target.value)} placeholder="Resumen del turno saliente…"
              style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:4, padding:"6px 8px", color:C.text, fontSize:12, resize:"vertical" }} />
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:3 }}>
            <label style={{ fontSize:10, color:C.textDim }}>Acciones pendientes para el turno entrante</label>
            <textarea rows={2} value={pending} onChange={e => setPending(e.target.value)} placeholder="Acciones que requieren seguimiento…"
              style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:4, padding:"6px 8px", color:C.text, fontSize:12, resize:"vertical" }} />
          </div>
          <button onClick={createReport} disabled={creating}
            style={{ ...btnStyle, color:C.green, borderColor: alpha(C.green, 25), alignSelf:"flex-end" }}>
            {creating ? "Creando…" : "Crear reporte"}
          </button>
        </div>
      )}

      {error && <div style={{ color:C.red, fontSize:12, marginBottom:8 }}>{error}</div>}
      {loading && <div style={{ color:C.textDim, fontSize:12 }}>Cargando…</div>}
      {!loading && reports.length === 0 && (
        <div style={{ color:C.textDim, fontSize:12 }}>Sin reportes de handover disponibles.</div>
      )}

      <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
        {reports.map((rpt) => {
          const ageMin = (Date.now() - new Date(rpt.created_at).getTime()) / 60000;
          const isStale = !rpt.acknowledged_at && ageMin > 120; // SLA: 2 h sin ack
          const borderColor = rpt.acknowledged_at ? C.border : (isStale ? C.red : alpha(C.green, 25));
          return (
          <div key={rpt.id} style={{
            background: isStale ? alpha(C.red, 3) : C.bg,
            border: `1px solid ${borderColor}`,
            borderRadius:8, padding:"10px 12px",
          }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
              <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                <span style={{ fontSize:11, fontWeight:600, color:C.green }}>{rpt.shift}</span>
                <span style={{ fontSize:11, color:C.textDim }}>{rpt.outgoing_manager_ci} → {rpt.incoming_manager_ci ?? "—"}</span>
                <span style={{ fontSize:10, color:C.textDim }}>{fmtDate(rpt.created_at)}</span>
                {isStale && (
                  <span style={{ fontSize:10, color:C.red, fontWeight:700 }}>
                    ⚠ SIN CONFIRMAR · {Math.round(ageMin/60)}h
                  </span>
                )}
              </div>
              {!rpt.acknowledged_at && rpt.incoming_manager_ci === operatorCi && (
                <button onClick={() => acknowledge(rpt.id)}
                  style={{ ...btnStyle, fontSize:10, padding:"3px 10px", color:C.green, borderColor: alpha(C.green, 25) }}>
                  ✓ Confirmar recepción
                </button>
              )}
              {rpt.acknowledged_at && (
                <span style={{ fontSize:10, color:C.green }}>✓ Confirmado {fmtDate(rpt.acknowledged_at)}</span>
              )}
            </div>
            <div style={{ display:"flex", gap:16, flexWrap:"wrap", fontSize:11, color:C.textDim }}>
              <span>🔓 Abiertos: <b style={{ color:C.text }}>{rpt.open_cases_count}</b></span>
              <span style={{ color: rpt.critical_open_count > 0 ? C.red : C.textDim }}>
                🔴 Críticos: <b>{rpt.critical_open_count}</b>
              </span>
              <span style={{ color: rpt.sla_breached_count > 0 ? C.orange : C.textDim }}>
                ⏱ SLA vencidos: <b>{rpt.sla_breached_count}</b>
              </span>
              <span>✅ Cerrados: <b style={{ color:C.text }}>{rpt.cases_closed_shift}</b></span>
              {rpt.mtta_shift_min != null && <span>MTTA: <b>{rpt.mtta_shift_min}m</b></span>}
              {rpt.mttr_shift_min != null && <span>MTTR: <b>{rpt.mttr_shift_min}m</b></span>}
            </div>
            {rpt.notes && (
              <div style={{ marginTop:6, fontSize:11, color:C.textDim, borderTop:`1px solid ${C.border}`, paddingTop:6 }}>
                <b style={{ color:C.text }}>Notas:</b> {rpt.notes}
              </div>
            )}
            {rpt.pending_actions && (
              <div style={{ marginTop:4, fontSize:11, color:C.orange }}>
                <b>Pendiente:</b> {rpt.pending_actions}
              </div>
            )}
          </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Skeleton row ───────────────────────────────────────────────────────────
// Simula un row de la tabla durante isLoading cuando aún no hay datos cached.
// Los widths coinciden con la cabecera (# CASO 72, ACTIVO flex:2, SEVERITY 80,
// ESTADO 110, DETECTADO 120, CREADO 110, SLA 80).

function SkeletonRow() {
  const bar = (w: number | string, h = 11) => (
    <div style={{
      width: w, height: h, borderRadius: 3,
      background: `linear-gradient(90deg, ${alpha(C.border, 25)} 0%, ${alpha(C.border, 50)} 50%, ${alpha(C.border, 25)} 100%)`,
      backgroundSize: "200% 100%",
      animation: "lh-shimmer 1.4s linear infinite",
    }} />
  );
  return (
    <div style={{ ...tableRowStyle, borderBottom: `1px solid ${C.border}` }}>
      <div style={{ width: 72 }}>{bar(52)}</div>
      <div style={{ flex: 2, minWidth: 0 }}>
        {bar("60%", 13)}
        <div style={{ height: 3 }} />
        {bar("40%", 9)}
      </div>
      <div style={{ width: 80 }}>{bar(60, 16)}</div>
      <div style={{ width: 110 }}>{bar(86, 16)}</div>
      <div style={{ width: 120, display: "flex", justifyContent: "flex-end" }}>{bar(78)}</div>
      <div style={{ width: 110, display: "flex", justifyContent: "flex-end" }}>{bar(70)}</div>
      <div style={{ width: 80, display: "flex", justifyContent: "flex-end" }}>{bar(50)}</div>
    </div>
  );
}

// ── Inline styles ─────────────────────────────────────────────────────────────

const tableRowStyle: React.CSSProperties = {
  display: "flex", alignItems: "center",
  padding: "10px 16px", gap: 8,
};

const btnStyle: React.CSSProperties = {
  background: "transparent",
  border: `1px solid ${C.border}`,
  borderRadius: 6, padding: "6px 12px",
  color: C.textDim, cursor: "pointer", fontSize: 12,
};

const filterBtnStyle: React.CSSProperties = {
  fontSize: 11, padding: "4px 10px", borderRadius: 4,
  border: "1px solid", cursor: "pointer",
  background: "transparent",
};
