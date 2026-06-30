/**
 * TriageQueue.tsx
 * ================================================================
 * Cola priorizada de casos pendientes de triage — diseñada para que
 * el operador L1/L2 no decida "¿qué casos miro ahora?", sino que
 * trabaje linealmente sobre una lista ordenada por severidad × tiempo.
 *
 * Reglas de la cola:
 *  - Solo casos SIN operador asignado (operator_id IS NULL).
 *  - Oculta CERRADO y FALSO_POSITIVO automáticamente.
 *  - Orden: severidad (CRITICAL→…→NEGLIGIBLE) y, dentro de cada
 *    nivel, más viejo primero (para no dejar casos olvidados).
 *
 * Ergonomía de teclado:
 *   J / ↓     navega al siguiente caso
 *   K / ↑     navega al anterior
 *   Enter     abre la vista de investigación del caso focado
 *   A         adopta el caso focado (1-click si hay CI guardado)
 *   F         marca como Falso Positivo (prompt con motivo)
 *   E         escala a TIER2 (prompt con motivo)
 *   ?         muestra/oculta la ayuda de atajos
 *
 * Reutiliza useCaseManagement con filtros fijos — sin endpoint nuevo.
 */

import { forwardRef, useEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, ArrowUpCircle, CheckCircle2, Keyboard, Microscope,
  ShieldCheck, Clock, Server, RefreshCw, ArrowRight, Activity, Shield,
  Globe2, BrainCircuit, ExternalLink, Inbox,
} from "lucide-react";
import { useCaseManagement } from "@/components/case-management/useCaseManagement";
import type { SocCase, Severity, DashboardKpis } from "@/components/case-management/types";
import { loadOperatorCi, saveOperatorCi, validateCi } from "@/lib/operator-ci";
import { useOperatorIdentity } from "@/hooks/useOperatorIdentity";
import { formatSlaRemaining, relativeTime } from "@/lib/sla-calc";
import { api } from "@/api/client";
import { useAuth } from "@/auth/useAuth";
import { useSocTier } from "@/auth/useSocTier";

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL:   "#ff3b5c",
  HIGH:       "#ff9500",
  MEDIUM:     "#00f5ff",
  LOW:        "#22c55e",
  NEGLIGIBLE: "#64748b",
};

const C = {
  bg:      "#0a0a0f",
  card:    "#0d1117",
  border:  "#1e2a3a",
  text:    "#e2e8f0",
  textDim: "#64748b",
};

export function TriageQueuePage() {
  const navigate = useNavigate();
  const { preferredUsername } = useAuth();
  const { tier } = useSocTier();
  const [operatorCi, setOperatorCi] = useState(loadOperatorCi);
  // P1 #13: sembrar el CI desde la sesión (JWT → soc_operators) → evita el
  // window.prompt en cada acción. La sesión es autoritativa.
  const sessionIdentity = useOperatorIdentity();
  useEffect(() => {
    if (sessionIdentity?.ci && sessionIdentity.ci !== operatorCi) {
      setOperatorCi(sessionIdentity.ci);
    }
  }, [sessionIdentity?.ci]);   // eslint-disable-line react-hooks/exhaustive-deps
  // CI efectivo para los widgets L1/L2: KC username manda; fallback al CI
  // guardado para usuarios pre-OIDC. Sin esto los hooks "mis casos" y
  // "escalados a mí" no podrían consultar nada en lab mode.
  const effectiveCi = preferredUsername ?? operatorCi;
  const showL2Widgets = tier === "L2L3" || tier === "LEADER";
  const [focusIdx, setFocusIdx]     = useState(0);
  const [showHelp, setShowHelp]     = useState(false);
  const [busy, setBusy]             = useState<string | null>(null);   // id en curso
  const [error, setError]           = useState<string | null>(null);
  const [flash, setFlash]           = useState<string | null>(null);   // mensaje éxito efímero
  const cardsRef = useRef<Array<HTMLDivElement | null>>([]);

  const {
    cases,
    isLoading,
    refetch,
    adoptCase,
    changeStatus,
    escalateCase,
  } = useCaseManagement({
    severity:    "ALL",
    status:      "ALL",
    search:      "",
    page:        1,
    pageSize:    50,
    sort:        "severity",
    sortDir:     "asc",
    assignedTo:  "__unassigned__",
    includeClosed: false,
  });

  // Auto-clear del flash tras 2.5s
  useEffect(() => {
    if (!flash) return;
    const t = setTimeout(() => setFlash(null), 2500);
    return () => clearTimeout(t);
  }, [flash]);

  // Si la cola se recorta bajo el índice activo, lo ajustamos.
  useEffect(() => {
    if (focusIdx >= cases.length && cases.length > 0) {
      setFocusIdx(cases.length - 1);
    }
  }, [cases.length, focusIdx]);

  // Scroll-into-view del caso focado al navegar con teclado.
  useEffect(() => {
    const el = cardsRef.current[focusIdx];
    if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [focusIdx]);

  // Handlers de acción — usados por teclado y por los botones inline.
  async function onAdopt(c: SocCase): Promise<void> {
    let ci = operatorCi;
    if (!ci || validateCi(ci)) {
      const prompted = window.prompt("CI del operador (mín. 5 caracteres):", "");
      if (!prompted) return;
      const trimmed = prompted.trim();
      if (validateCi(trimmed)) {
        setError("CI inválido.");
        return;
      }
      saveOperatorCi(trimmed);
      setOperatorCi(trimmed);
      ci = trimmed;
    }
    setBusy(c.id); setError(null);
    try {
      await adoptCase(c.id, ci);
      setFlash(`Adoptado: ${c.id.slice(0, 8)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error al adoptar.");
    } finally {
      setBusy(null);
    }
  }

  async function onFalsePositive(c: SocCase): Promise<void> {
    const reason = window.prompt(
      `Marcar ${c.id.slice(0, 8)} (${c.severity}) como FALSO POSITIVO.\nMotivo obligatorio:`,
      "",
    );
    if (!reason || reason.trim().length < 5) return;
    setBusy(c.id); setError(null);
    try {
      await changeStatus(c.id, "FALSO_POSITIVO", reason.trim(), operatorCi || undefined);
      setFlash(`FP: ${c.id.slice(0, 8)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error al marcar FP.");
    } finally {
      setBusy(null);
    }
  }

  async function onEscalate(c: SocCase): Promise<void> {
    let ci = operatorCi;
    if (!ci || validateCi(ci)) {
      setError("Registra tu CI antes de escalar.");
      return;
    }
    ci = ci.trim();
    const reason = window.prompt(
      `Escalar ${c.id.slice(0, 8)} (${c.severity}) a TIER2.\nMotivo obligatorio:`,
      "",
    );
    if (!reason || reason.trim().length < 5) return;
    setBusy(c.id); setError(null);
    try {
      await escalateCase(c.id, "TIER2", "", reason.trim(), ci);
      setFlash(`Escalado: ${c.id.slice(0, 8)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error al escalar.");
    } finally {
      setBusy(null);
    }
  }

  function onInvestigate(c: SocCase): void {
    // Pasa el ID por query param; CaseManagementDashboard puede leerlo si se
    // añade support más adelante. Mientras tanto redirige al listado donde
    // el operador encontrará el caso en la primera fila.
    navigate(`/gestion?investigate=${encodeURIComponent(c.id)}`);
  }

  // Keyboard shortcuts globales para esta vista.
  useEffect(() => {
    function handler(e: KeyboardEvent) {
      // Ignorar cuando el operador está tipeando en un input o textarea
      const tag = (e.target as HTMLElement | null)?.tagName?.toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;

      const c = cases[focusIdx];
      switch (e.key) {
        case "j":
        case "ArrowDown":
          if (cases.length > 0) {
            e.preventDefault();
            setFocusIdx(i => Math.min(i + 1, cases.length - 1));
          }
          break;
        case "k":
        case "ArrowUp":
          if (cases.length > 0) {
            e.preventDefault();
            setFocusIdx(i => Math.max(i - 1, 0));
          }
          break;
        case "Enter":
          if (c) { e.preventDefault(); onInvestigate(c); }
          break;
        case "a":
        case "A":
          if (c && busy !== c.id) { e.preventDefault(); void onAdopt(c); }
          break;
        case "f":
        case "F":
          if (c && busy !== c.id) { e.preventDefault(); void onFalsePositive(c); }
          break;
        case "e":
        case "E":
          if (c && busy !== c.id) { e.preventDefault(); void onEscalate(c); }
          break;
        case "?":
          e.preventDefault();
          setShowHelp(h => !h);
          break;
      }
    }
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cases, focusIdx, busy]);

  // Breakdown por severidad para mostrar en el header.
  const bySev = useMemo(() => {
    const out: Record<string, number> = {};
    for (const c of cases) out[c.severity] = (out[c.severity] ?? 0) + 1;
    return out;
  }, [cases]);

  // ── C2.4 — KPIs del turno (últimas 8h, no la ventana operacional 7d) ────
  // El endpoint /api/cases/kpis ya acepta ?hours=N. 8h ≈ 1 turno SOC; los
  // analistas comparan vs lo que pasó "en mi shift", no vs la semana.
  const shiftKpis = useQuery<DashboardKpis>({
    queryKey: ["triage-shift-kpis"],
    queryFn: async () => {
      const { data } = await api.get<DashboardKpis>("/api/cases/kpis?hours=8");
      return data;
    },
    staleTime: 60_000,
    refetchInterval: 60_000,
    refetchOnWindowFocus: false,
  });

  // ── C2.5 — "Mis casos en análisis" (L1) ─────────────────────────────────
  // Lo que tomé y aún no cerré. Aliado de la cola de triage: el analyst ve
  // qué tiene pendiente antes de seguir adoptando más casos.
  const myInAnalysis = useQuery<{ cases: SocCase[]; total: number }>({
    queryKey: ["triage-my-analysis", effectiveCi],
    queryFn: async () => {
      if (!effectiveCi) return { cases: [], total: 0 };
      const params = new URLSearchParams({
        severity:   "ALL",
        status:     "EN_ANALISIS",
        page:       "1",
        pageSize:   "8",
        sort:       "sla",
        sortDir:    "desc",
        assignedTo: effectiveCi,
      });
      const { data } = await api.get<{ cases: SocCase[]; total: number }>(
        `/api/incidents/open?${params}`,
      );
      return data;
    },
    enabled: !!effectiveCi,
    staleTime: 60_000,
    refetchInterval: 90_000,
    refetchOnWindowFocus: false,
  });

  // ── C2.6 — "Escalados a mí" (L2/Hunter+) ────────────────────────────────
  // Status=ESCALADO + assignedTo=miCI. El hunter ve rápido qué le llegó por
  // escalación L1→L2 sin tener que filtrar manualmente en /gestion.
  const escalatedToMe = useQuery<{ cases: SocCase[]; total: number }>({
    queryKey: ["triage-escalated-to-me", effectiveCi, showL2Widgets],
    queryFn: async () => {
      if (!effectiveCi || !showL2Widgets) return { cases: [], total: 0 };
      const params = new URLSearchParams({
        severity:   "ALL",
        status:     "ESCALADO",
        page:       "1",
        pageSize:   "8",
        sort:       "severity",
        sortDir:    "asc",
        assignedTo: effectiveCi,
      });
      const { data } = await api.get<{ cases: SocCase[]; total: number }>(
        `/api/incidents/open?${params}`,
      );
      return data;
    },
    enabled: !!effectiveCi && showL2Widgets,
    staleTime: 60_000,
    refetchInterval: 90_000,
    refetchOnWindowFocus: false,
  });

  // ── Render ────────────────────────────────────────────────────────────
  return (
    <div style={{ padding: "16px 20px", color: C.text, background: C.bg, minHeight: "100%" }}>
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap",
        marginBottom: 14, paddingBottom: 12, borderBottom: `1px solid ${C.border}`,
      }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, margin: 0, letterSpacing: "-0.01em" }}>
            Cola de Triage
          </h1>
          <p style={{ fontSize: 11, color: C.textDim, margin: "3px 0 0" }}>
            Casos sin adoptar, priorizados por severidad y antigüedad.
          </p>
        </div>
        <div style={{ display: "flex", gap: 6, marginLeft: "auto", alignItems: "center", flexWrap: "wrap" }}>
          {/* Contadores por severidad */}
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"] as const).map(sev => (
            bySev[sev] > 0 && (
              <span key={sev} style={{
                fontSize: 10, fontWeight: 700, padding: "3px 9px", borderRadius: 4,
                background: SEV_COLOR[sev] + "25",
                color:      SEV_COLOR[sev],
                border:    `1px solid ${SEV_COLOR[sev]}50`,
                letterSpacing: "0.04em",
              }}>
                {sev}: {bySev[sev]}
              </span>
            )
          ))}
          {cases.length === 0 && !isLoading && (
            <span style={{ fontSize: 12, color: "#22c55e", fontWeight: 600 }}>
              ✓ Bandeja limpia
            </span>
          )}
          <button
            onClick={() => setShowHelp(h => !h)}
            title="Mostrar atajos (?)"
            style={{
              background: "transparent", border: `1px solid ${C.border}`,
              borderRadius: 4, padding: "4px 10px", color: C.textDim,
              cursor: "pointer", display: "flex", alignItems: "center", gap: 5, fontSize: 11,
            }}
          >
            <Keyboard size={12} /> Atajos
          </button>
          <button
            onClick={refetch}
            disabled={isLoading}
            style={{
              background: "transparent", border: `1px solid ${C.border}`,
              borderRadius: 4, padding: "4px 10px", color: C.textDim,
              cursor: isLoading ? "not-allowed" : "pointer",
              display: "flex", alignItems: "center", gap: 5, fontSize: 11,
            }}
          >
            <RefreshCw size={12} style={isLoading ? { animation: "spin 0.8s linear infinite" } : undefined} />
            Refrescar
          </button>
        </div>
      </div>

      {/* Help de atajos */}
      {showHelp && (
        <div style={{
          marginBottom: 12, padding: "10px 14px", borderRadius: 6, fontSize: 11,
          background: "#1e2a3a60", border: `1px solid ${C.border}`,
          display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8,
        }}>
          <KbdHint k="J / ↓"  label="siguiente caso" />
          <KbdHint k="K / ↑"  label="caso anterior" />
          <KbdHint k="⏎"      label="investigar caso focado" />
          <KbdHint k="A"      label="adoptar" />
          <KbdHint k="F"      label="falso positivo" />
          <KbdHint k="E"      label="escalar a TIER2" />
          <KbdHint k="?"      label="ocultar esta ayuda" />
        </div>
      )}

      {/* Flash / error */}
      {flash && (
        <div style={{
          marginBottom: 10, padding: "6px 12px", borderRadius: 5, fontSize: 12,
          background: "#22c55e15", border: "1px solid #22c55e40", color: "#22c55e",
        }}>✓ {flash}</div>
      )}
      {error && (
        <div style={{
          marginBottom: 10, padding: "6px 12px", borderRadius: 5, fontSize: 12,
          background: "#ff3b5c15", border: "1px solid #ff3b5c40", color: "#ff3b5c",
          display: "flex", justifyContent: "space-between", alignItems: "center",
        }}>
          <span>✕ {error}</span>
          <button onClick={() => setError(null)} style={{
            background: "none", border: "none", color: "inherit", cursor: "pointer", fontSize: 14,
          }}>×</button>
        </div>
      )}

      {/* C2.4 — KPI strip del turno */}
      <ShiftKpiStrip kpis={shiftKpis.data} queueSize={cases.length} loading={shiftKpis.isLoading} />

      {/* Empty state */}
      {cases.length === 0 && !isLoading && (
        <div style={{
          padding: "48px 16px", textAlign: "center",
          background: C.card, border: `1px solid ${C.border}`, borderRadius: 8,
        }}>
          <CheckCircle2 size={36} color="#22c55e" style={{ margin: "0 auto 10px" }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: "#22c55e", marginBottom: 4 }}>
            Bandeja limpia
          </div>
          <div style={{ fontSize: 12, color: C.textDim }}>
            Todos los casos tienen operador asignado. Buen trabajo.
          </div>
        </div>
      )}

      {isLoading && cases.length === 0 && (
        <div style={{
          padding: "32px 16px", textAlign: "center", color: C.textDim,
          background: C.card, border: `1px solid ${C.border}`, borderRadius: 8,
        }}>
          Cargando cola…
        </div>
      )}

      {/* Cards */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {cases.map((c, idx) => (
          <TriageCard
            key={c.id}
            ref={(el) => { cardsRef.current[idx] = el; }}
            case_={c}
            focused={idx === focusIdx}
            busy={busy === c.id}
            onFocus={() => setFocusIdx(idx)}
            onAdopt={() => void onAdopt(c)}
            onFP={() => void onFalsePositive(c)}
            onEscalate={() => void onEscalate(c)}
            onInvestigate={() => onInvestigate(c)}
          />
        ))}
      </div>

      {/* ── C2.5 — Mis casos EN_ANALISIS (L1) ───────────────────────────── */}
      <CaseStrip
        title="Mis casos en análisis"
        hint="Tomé y aún no cerré. Cerralos antes de seguir adoptando."
        icon={Microscope}
        iconColor="#60a5fa"
        cases={myInAnalysis.data?.cases ?? []}
        total={myInAnalysis.data?.total ?? 0}
        loading={myInAnalysis.isLoading}
        emptyText={effectiveCi ? "Sin pendientes — todo cerrado o sin tomar." : "Iniciá sesión o registrá tu CI para ver tus casos."}
        seeAllHref={effectiveCi ? `/gestion?preset=mine` : null}
      />

      {/* ── C2.6 — Widgets L2 (visible para hunter+) ─────────────────────── */}
      {showL2Widgets && (
        <>
          <CaseStrip
            title="Escalados a mí"
            hint="Casos que llegaron por escalación L1→L2."
            icon={ArrowUpCircle}
            iconColor="#f59e0b"
            cases={escalatedToMe.data?.cases ?? []}
            total={escalatedToMe.data?.total ?? 0}
            loading={escalatedToMe.isLoading}
            emptyText="Nada en cola de escalación — buen trabajo del L1."
            seeAllHref={`/gestion?preset=escalated-to-me`}
          />

          <QuickLinksL2 />
        </>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// C2.4 — ShiftKpiStrip: KPIs del turno (8h) con foco analyst
// ─────────────────────────────────────────────────────────────────────────────

function ShiftKpiStrip({
  kpis, queueSize, loading,
}: { kpis: DashboardKpis | undefined; queueSize: number; loading: boolean }) {
  const tiles: Array<{ label: string; value: string; color: string; title?: string; icon: ReactNode }> = [
    {
      label: "Cola pendiente",
      value: loading ? "…" : String(queueSize),
      color: queueSize > 10 ? "#ff9500" : queueSize > 0 ? "#60a5fa" : "#22c55e",
      icon: <Inbox size={11} />,
      title: "Casos sin asignar visibles ahora — los que estás trabajando arriba.",
    },
    {
      label: "Críticos sin adoptar",
      value: loading || !kpis ? "…" : String(kpis.criticalUnadopted),
      color: kpis && kpis.criticalUnadopted > 0 ? "#ff3b5c" : "#22c55e",
      icon: <AlertTriangle size={11} />,
      title: "CRITICAL abiertos sin operador — atención inmediata.",
    },
    {
      label: "MTTA turno",
      value: loading || !kpis?.mttaMin ? "…" : fmtMinShort(kpis.mttaMin),
      color: !kpis?.mttaMin ? "#64748b" : kpis.mttaMin < 10 ? "#22c55e" : kpis.mttaMin < 20 ? "#ff9500" : "#ff3b5c",
      icon: <Activity size={11} />,
      title: "Mean Time To Acknowledge — minutos entre creación y adopción. Objetivo <10m. Ventana: 8h.",
    },
    {
      label: "Resueltos 8h",
      value: loading || !kpis ? "…" : String(kpis.resolvedToday ?? 0),
      color: "#22c55e",
      icon: <CheckCircle2 size={11} />,
      title: "Casos cerrados manualmente en las últimas 8 horas.",
    },
    {
      label: "FP rate turno",
      value: loading || kpis?.fpRate == null ? "…" : `${Math.round(kpis.fpRate)}%`,
      color: kpis?.fpRate == null ? "#64748b" : kpis.fpRate < 10 ? "#22c55e" : kpis.fpRate < 25 ? "#ff9500" : "#ff3b5c",
      icon: <Shield size={11} />,
      title: "Falsos positivos / cerrados (8h). Objetivo <10% — métrica de calidad de detección.",
    },
    {
      label: "Sin asignar",
      value: loading || !kpis ? "…" : String(kpis.unassignedOpen ?? 0),
      color: kpis && (kpis.unassignedOpen ?? 0) > 5 ? "#ff9500" : "#60a5fa",
      icon: <Inbox size={11} />,
      title: "Backlog total sin owner (no solo del turno). Cuanto más alto, más cola hay.",
    },
  ];
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
      gap: 8, marginBottom: 12,
    }}>
      {tiles.map((t) => (
        <div
          key={t.label}
          title={t.title}
          style={{
            background: C.card, border: `1px solid ${C.border}`,
            borderRadius: 6, padding: "8px 12px",
            cursor: t.title ? "help" : undefined,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 2 }}>
            <span style={{ color: t.color }}>{t.icon}</span>
            <span style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.05em", textTransform: "uppercase" }}>
              {t.label}
            </span>
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, color: t.color, lineHeight: 1.1 }}>{t.value}</div>
        </div>
      ))}
    </div>
  );
}

function fmtMinShort(n: number): string {
  if (n < 1) return "<1m";
  if (n < 60) return `${Math.round(n)}m`;
  const h = Math.floor(n / 60);
  const m = Math.round(n % 60);
  return m === 0 ? `${h}h` : `${h}h${m}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// C2.5 — CaseStrip: tabla compacta reutilizable (Mis EN_ANALISIS, Escalados…)
// ─────────────────────────────────────────────────────────────────────────────

interface CaseStripProps {
  title:      string;
  hint:       string;
  icon:       React.ElementType;
  iconColor:  string;
  cases:      SocCase[];
  total:      number;
  loading:    boolean;
  emptyText:  string;
  seeAllHref: string | null;
}

function CaseStrip({
  title, hint, icon: Icon, iconColor, cases, total, loading, emptyText, seeAllHref,
}: CaseStripProps) {
  return (
    <section style={{ marginTop: 18 }}>
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "baseline",
        marginBottom: 6,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Icon size={13} color={iconColor} />
          <h2 style={{ fontSize: 12, fontWeight: 700, color: C.text, margin: 0 }}>
            {title}
          </h2>
          {total > 0 && (
            <span style={{
              fontSize: 10, fontWeight: 700, padding: "1px 6px", borderRadius: 3,
              background: iconColor + "20", color: iconColor, border: `1px solid ${iconColor}40`,
            }}>{total}</span>
          )}
        </div>
        {seeAllHref && cases.length > 0 && (
          <Link to={seeAllHref} style={{
            fontSize: 10, color: C.textDim, textDecoration: "none",
            display: "inline-flex", alignItems: "center", gap: 3,
          }}>
            ver lista completa <ArrowRight size={10} />
          </Link>
        )}
      </div>
      <p style={{ fontSize: 10, color: C.textDim, margin: "0 0 6px" }}>{hint}</p>
      {loading ? (
        <div style={{
          padding: "12px 14px", borderRadius: 5, background: C.card,
          border: `1px solid ${C.border}`, fontSize: 11, color: C.textDim,
        }}>Cargando…</div>
      ) : cases.length === 0 ? (
        <div style={{
          padding: "12px 14px", borderRadius: 5, background: C.card,
          border: `1px dashed ${C.border}`, fontSize: 11, color: C.textDim,
          textAlign: "center",
        }}>{emptyText}</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {cases.map((c) => <CaseStripRow key={c.id} c={c} />)}
        </div>
      )}
    </section>
  );
}

function CaseStripRow({ c }: { c: SocCase }) {
  const sevColor = SEV_COLOR[c.severity as Severity] ?? "#94a3b8";
  const slaText  = formatSlaRemaining(c.detectedAt, c.slaSec);
  // Tone derivado: si el SLA viene con signo negativo (breach) o estamos
  // dentro del último 10% de margen, lo mostramos en rojo. >70% → ámbar.
  const slaPct = (() => {
    if (!c.detectedAt || c.slaSec <= 0) return 0;
    const elapsed = (Date.now() - new Date(c.detectedAt).getTime()) / 1000;
    return (elapsed / c.slaSec) * 100;
  })();
  const slaColor = slaPct >= 100 ? "#ff3b5c" : slaPct >= 90 ? "#ff3b5c" : slaPct >= 70 ? "#ff9500" : C.textDim;
  return (
    <Link
      to={`/gestion?investigate=${encodeURIComponent(c.id)}`}
      style={{
        textDecoration: "none", color: C.text,
        background: C.card, border: `1px solid ${C.border}`, borderLeft: `2px solid ${sevColor}`,
        borderRadius: 5, padding: "7px 10px",
        display: "grid", gridTemplateColumns: "auto 1fr auto auto", gap: 8,
        alignItems: "center", fontSize: 11,
      }}
    >
      <span style={{
        fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 3,
        background: sevColor + "25", color: sevColor, letterSpacing: "0.04em",
      }}>
        {c.severity}
      </span>
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        <span style={{ fontFamily: "monospace", color: C.textDim, marginRight: 6 }}>
          #{c.id.slice(0, 8)}
        </span>
        {c.srcIp || "(sin IOC)"}
        <span style={{ color: C.textDim, marginLeft: 6, fontSize: 10 }}>
          · {c.sourceLabel || c.source}
        </span>
      </span>
      <span style={{ color: slaColor, fontSize: 10 }}>
        SLA {slaText ?? "—"}
      </span>
      <ArrowRight size={11} color={C.textDim} />
    </Link>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// C2.6 — QuickLinksL2: accesos rápidos a vigilancia / threat intel / fuentes
// ─────────────────────────────────────────────────────────────────────────────

function QuickLinksL2() {
  const links: Array<{ to: string; icon: React.ElementType; label: string; hint: string; color: string }> = [
    { to: "/vigilancia",   icon: Globe2,       label: "Vigilancia digital", hint: "Dark web + Brand24 + correlaciones", color: "#60a5fa" },
    { to: "/intel",        icon: BrainCircuit, label: "Fuentes Externas",   hint: "Credenciales, Shadowserver, PCAP",     color: "#22c55e" },
  ];
  return (
    <section style={{ marginTop: 18 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <ExternalLink size={13} color="#a87bd6" />
        <h2 style={{ fontSize: 12, fontWeight: 700, color: C.text, margin: 0 }}>
          Investigación profunda
        </h2>
      </div>
      <p style={{ fontSize: 10, color: C.textDim, margin: "0 0 6px" }}>
        Accesos al stack de análisis sin pasar por el sidebar.
      </p>
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
        gap: 8,
      }}>
        {links.map((l) => (
          <Link
            key={l.to}
            to={l.to}
            style={{
              textDecoration: "none", color: C.text,
              background: C.card, border: `1px solid ${C.border}`,
              borderRadius: 6, padding: "10px 12px",
              display: "flex", flexDirection: "column", gap: 4,
              transition: "border-color 0.12s",
            }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLAnchorElement).style.borderColor = l.color + "60"; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLAnchorElement).style.borderColor = C.border; }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <l.icon size={12} color={l.color} />
              <span style={{ fontSize: 11, fontWeight: 600 }}>{l.label}</span>
              <ArrowRight size={10} color={C.textDim} style={{ marginLeft: "auto" }} />
            </div>
            <span style={{ fontSize: 9, color: C.textDim }}>{l.hint}</span>
          </Link>
        ))}
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TriageCard — tarjeta densa con toda la info crítica para decidir
// ─────────────────────────────────────────────────────────────────────────────

interface TriageCardProps {
  case_:         SocCase;
  focused:       boolean;
  busy:          boolean;
  onFocus:       () => void;
  onAdopt:       () => void;
  onFP:          () => void;
  onEscalate:    () => void;
  onInvestigate: () => void;
}

const TriageCard = forwardRef<HTMLDivElement, TriageCardProps>(function TriageCard(
  { case_: c, focused, busy, onFocus, onAdopt, onFP, onEscalate, onInvestigate },
  ref,
) {
  const sevColor = SEV_COLOR[c.severity as Severity] ?? "#94a3b8";
  const slaText  = formatSlaRemaining(c.detectedAt, c.slaSec);
  const sinceTs  = c.createdAt ?? c.detectedAt;

  return (
    <div
      ref={ref}
      onClick={onFocus}
      style={{
        background: C.card,
        border: `1px solid ${focused ? sevColor + "80" : C.border}`,
        borderLeft: `3px solid ${sevColor}`,
        borderRadius: 6, padding: "12px 14px",
        cursor: "pointer", transition: "border-color 0.12s",
        boxShadow: focused ? `0 0 0 1px ${sevColor}30, 0 4px 16px ${sevColor}15` : undefined,
      }}
    >
      {/* Línea 1: severity · status · ID · SLA */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <span style={{
          fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
          background: sevColor + "25", color: sevColor, letterSpacing: "0.04em",
          display: "inline-flex", alignItems: "center", gap: 4,
        }}>
          {c.severity === "CRITICAL" && (
            <span style={{
              width: 6, height: 6, borderRadius: "50%",
              background: sevColor, display: "inline-block",
            }} />
          )}
          {c.severity}
        </span>
        <span style={{
          fontSize: 10, fontWeight: 600, padding: "2px 7px", borderRadius: 4,
          background: "#3b82f620", color: "#60a5fa", border: "1px solid #3b82f640",
        }}>
          {c.status}
        </span>
        <span style={{ fontFamily: "monospace", fontSize: 11, color: C.textDim }}>
          #{c.id.slice(0, 8)}
        </span>
        {sinceTs && (
          <span style={{ fontSize: 11, color: C.textDim, display: "inline-flex", alignItems: "center", gap: 3 }}>
            <Clock size={10} /> {relativeTime(sinceTs)}
          </span>
        )}
        {slaText && (
          <span style={{
            marginLeft: "auto", fontFamily: "monospace", fontSize: 12,
            fontWeight: 700, padding: "2px 8px", borderRadius: 4,
            background: slaText.startsWith("−") ? "#ff3b5c15" : "#f59e0b15",
            color:      slaText.startsWith("−") ? "#ff3b5c"   : "#f59e0b",
            border:    `1px solid ${slaText.startsWith("−") ? "#ff3b5c40" : "#f59e0b30"}`,
          }}>
            SLA {slaText}
          </span>
        )}
      </div>

      {/* Línea 2: IOC grande + score */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginTop: 8, flexWrap: "wrap" }}>
        <span style={{
          fontFamily: "monospace", fontSize: 16, color: C.text, fontWeight: 600,
        }}>
          {c.srcIp}
        </span>
        {c.isInternal && (
          <span style={{
            fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 3,
            background: "#f59e0b15", color: "#f59e0b", border: "1px solid #f59e0b30",
          }}>RFC1918</span>
        )}
        <span style={{ fontSize: 11, color: C.textDim }}>
          {c.iocType} · {c.source}
        </span>
        {c.mitre.tacticName && (
          <span style={{ fontSize: 11, color: "#a78bfa" }}>
            · {c.mitre.tacticId} {c.mitre.tacticName}
          </span>
        )}
        {c.assetsCount > 0 && (
          <span style={{
            fontSize: 10, fontWeight: 700, padding: "1px 6px", borderRadius: 3,
            background: c.assetsCount >= 3 ? "#ff3b5c20" : "#f59e0b15",
            color:      c.assetsCount >= 3 ? "#ff3b5c"   : "#f59e0b",
            border:    `1px solid ${c.assetsCount >= 3 ? "#ff3b5c40" : "#f59e0b30"}`,
          }}>
            {c.assetsCount} host{c.assetsCount === 1 ? "" : "s"}
          </span>
        )}
        <span style={{
          marginLeft: "auto", fontSize: 13, fontWeight: 700, color: sevColor,
          fontFamily: "monospace",
        }}
        title={`MITRE: ${c.scoreBreakdown.mitre}/40  Evidencia: ${c.scoreBreakdown.evidence}/35  Wazuh: ${c.scoreBreakdown.wazuh}/25  MISP: ${c.scoreBreakdown.misp}/20  Contexto: ${c.scoreBreakdown.context}/10`}>
          score {c.score}
        </span>
      </div>

      {/* Línea 3 (opcional): sensor + next action */}
      {(c.sensorKey || c.recommendedAction) && (
        <div style={{
          display: "flex", gap: 12, flexWrap: "wrap",
          marginTop: 6, fontSize: 11, color: C.textDim,
        }}>
          {c.sensorKey && (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 3 }}>
              <Server size={10} /> {c.sourceLabel} · {c.sensorKey}
            </span>
          )}
          {c.recommendedAction && (
            <span style={{ color: "#cbd5e1", flex: 1, minWidth: 0 }}>
              💡 {c.recommendedAction.length > 120
                  ? c.recommendedAction.slice(0, 118) + "…"
                  : c.recommendedAction}
            </span>
          )}
        </div>
      )}

      {/* Botonera */}
      <div style={{
        display: "flex", gap: 6, marginTop: 10, paddingTop: 8,
        borderTop: `1px dashed ${C.border}`, flexWrap: "wrap",
      }}>
        <ActionButton
          onClick={(e) => { e.stopPropagation(); onAdopt(); }}
          disabled={busy}
          color="#22c55e"
          shortcut="A"
          icon={<ShieldCheck size={12} />}
          label={busy ? "Adoptando…" : "Adoptar"}
        />
        <ActionButton
          onClick={(e) => { e.stopPropagation(); onFP(); }}
          disabled={busy}
          color="#22c55e"
          shortcut="F"
          icon={<CheckCircle2 size={12} />}
          label="Falso positivo"
        />
        <ActionButton
          onClick={(e) => { e.stopPropagation(); onEscalate(); }}
          disabled={busy}
          color="#f59e0b"
          shortcut="E"
          icon={<ArrowUpCircle size={12} />}
          label="Escalar"
        />
        <ActionButton
          onClick={(e) => { e.stopPropagation(); onInvestigate(); }}
          disabled={false}
          color="#a78bfa"
          shortcut="⏎"
          icon={<Microscope size={12} />}
          label="Investigar"
          marginLeft="auto"
        />
      </div>

      {/* Escalation suggested hint */}
      {c.escalationSuggested && (
        <div style={{
          marginTop: 8, padding: "5px 10px", borderRadius: 4,
          background: "#f59e0b15", border: "1px solid #f59e0b30",
          fontSize: 11, color: "#f59e0b",
          display: "flex", alignItems: "center", gap: 6,
        }}>
          <AlertTriangle size={11} />
          Escalación sugerida: {c.escalationReasonAuto ?? "revisar criterios automáticos"}
        </div>
      )}
    </div>
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function ActionButton({
  onClick, disabled, color, shortcut, icon, label, marginLeft,
}: {
  onClick:    (e: MouseEvent<HTMLButtonElement>) => void;
  disabled:   boolean;
  color:      string;
  shortcut:   string;
  icon:       ReactNode;
  label:      string;
  marginLeft?: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        background: color + "15", border: `1px solid ${color}50`, borderRadius: 4,
        padding: "5px 10px", fontSize: 11, color, fontWeight: 600,
        cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.5 : 1,
        display: "inline-flex", alignItems: "center", gap: 5,
        marginLeft,
      }}
    >
      {icon} {label}
      <kbd style={{
        fontFamily: "monospace", fontSize: 9, padding: "0 4px", borderRadius: 2,
        background: "#00000040", border: "1px solid #ffffff20", marginLeft: 3,
      }}>
        {shortcut}
      </kbd>
    </button>
  );
}

function KbdHint({ k, label }: { k: string; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <kbd style={{
        fontFamily: "monospace", fontSize: 10, padding: "2px 6px", borderRadius: 3,
        background: "#0a0a0f", border: `1px solid ${C.border}`,
        minWidth: 44, textAlign: "center",
      }}>{k}</kbd>
      <span style={{ color: C.textDim }}>{label}</span>
    </div>
  );
}

