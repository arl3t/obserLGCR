/**
 * ScoringDetailPanel.tsx
 *
 * Panel de detalle de scoring para casos en investigación.
 * Muestra:
 *   1. Brief del analista (resumen narrativo auto-generado)
 *   2. Taxonomía auto-clasificada (NIST SP 800-61 + ataque)
 *   3. Proceso de scoring documentado (componentes base + bonus log)
 *   4. Datos raw de enriquecimiento (expandible)
 *
 * Se monta dentro de CaseDetailSheet cuando status ∈ {EN_ANALISIS, CONFIRMADO, ESCALADO}.
 * Los datos se cargan perezosamente con fetch() para no bloquear la apertura del sheet.
 */

import { useEffect, useState } from "react";
import {
  AlertTriangle, BookOpen, ChevronDown, ChevronRight,
  Code2, Cpu, ExternalLink, FlaskConical, ShieldCheck,
} from "lucide-react";
import type { ScoringDetail, BonusLogEntry } from "./types";
import { api } from "@/api/client";
import { C, alpha } from "@/lib/cm-theme";

// ── Paleta de colores por bonus_type ─────────────────────────────────────────

const BONUS_COLOR: Record<string, { bg: string; fg: string; border: string }> = {
  kill_chain_depth: { bg: alpha(C.purple, 12), fg: C.purple, border: alpha(C.purple, 25) },
  temporal_fresh:   { bg: alpha(C.cyan,   12), fg: C.cyan,   border: alpha(C.cyan,   25) },
  fp_penalty:       { bg: alpha(C.red,    12), fg: C.red,    border: alpha(C.red,    25) },
  score_decay:      { bg: alpha(C.orange, 12), fg: C.orange, border: alpha(C.orange, 25) },
  geo_risk:         { bg: alpha(C.orange, 12), fg: C.orange, border: alpha(C.orange, 25) },
  asset_criticality:{ bg: alpha(C.green,  12), fg: C.green,  border: alpha(C.green,  25) },
};
const DEFAULT_BONUS_COLOR = { bg: alpha(C.textDim, 12), fg: C.textDim, border: alpha(C.textDim, 25) };

const BONUS_LABEL: Record<string, string> = {
  kill_chain_depth:  "Kill-chain depth",
  temporal_fresh:    "Multiplicador temporal",
  fp_penalty:        "Penalización FP histórico",
  score_decay:       "Decay de score histórico",
  geo_risk:          "Riesgo geográfico",
  asset_criticality: "Criticidad de activo",
};

// ── NIST category → color ─────────────────────────────────────────────────────

const NIST_COLOR: Record<string, { fg: string; border: string }> = {
  UNAUTHORIZED_ACCESS: { fg: C.red,     border: alpha(C.red,     25) },
  DENIAL_OF_SERVICE:   { fg: C.orange,  border: alpha(C.orange,  25) },
  MALICIOUS_CODE:      { fg: C.purple,  border: alpha(C.purple,  25) },
  IMPROPER_USAGE:      { fg: C.orange,  border: alpha(C.orange,  25) },
  SCANS_PROBES:        { fg: C.cyan,    border: alpha(C.cyan,    25) },
  INVESTIGATION:       { fg: C.textDim, border: alpha(C.textDim, 25) },
  OTHER:               { fg: C.textDim, border: alpha(C.textDim, 25) },
};
const DEFAULT_NIST_COLOR = { fg: C.textDim, border: alpha(C.textDim, 25) };

// ── Section wrapper ───────────────────────────────────────────────────────────

function PanelSection({
  label, icon: Icon, children, defaultOpen = true,
}: {
  label: string;
  icon: typeof BookOpen;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          width: "100%", padding: "8px 12px",
          background: C.bg, border: "none", cursor: "pointer",
          color: C.textDim,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <Icon size={12} color={C.cyan} />
          <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: C.cyan }}>
            {label.toUpperCase()}
          </span>
        </div>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>
      {open && (
        <div style={{ padding: "10px 12px", background: C.bg }}>
          {children}
        </div>
      )}
    </div>
  );
}

// ── Bonus chip ────────────────────────────────────────────────────────────────

function BonusChip({ entry }: { entry: BonusLogEntry }) {
  const [expanded, setExpanded] = useState(false);
  const colors = BONUS_COLOR[entry.bonus_type] ?? DEFAULT_BONUS_COLOR;
  const isMultiplier = entry.multiplier != null && entry.bonus_value === 0;

  const valueLabel = isMultiplier
    ? `×${entry.multiplier}`
    : entry.bonus_value != null && entry.bonus_value !== 0
      ? (entry.bonus_value > 0 ? `+${entry.bonus_value}` : String(entry.bonus_value))
      : "—";

  return (
    <div style={{ marginBottom: 6 }}>
      <button
        onClick={() => setExpanded((v) => !v)}
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          width: "100%", textAlign: "left",
          background: colors.bg, border: `1px solid ${colors.border}`,
          borderRadius: 6, padding: "5px 9px", cursor: "pointer",
        }}
      >
        <span style={{ fontSize: 11, fontWeight: 600, color: colors.fg }}>
          {BONUS_LABEL[entry.bonus_type] ?? entry.bonus_type}
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{
            fontFamily: "monospace", fontSize: 12, fontWeight: 700, color: colors.fg,
          }}>
            {valueLabel}
          </span>
          {expanded ? <ChevronDown size={10} color={colors.fg} /> : <ChevronRight size={10} color={colors.fg} />}
        </div>
      </button>
      {expanded && entry.detail && (
        <div style={{
          background: C.bg, border: `1px solid ${colors.border}`,
          borderTop: "none", borderRadius: "0 0 6px 6px",
          padding: "7px 9px",
        }}>
          {Object.entries(entry.detail).map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "1px 0" }}>
              <span style={{ color: C.textDim, fontSize: 10 }}>{k}</span>
              <span style={{ fontFamily: "monospace", fontSize: 10, color: C.textDim, maxWidth: "60%", textAlign: "right", overflowWrap: "anywhere" }}>
                {typeof v === "object" ? JSON.stringify(v) : String(v)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Confidence bar ────────────────────────────────────────────────────────────

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 75 ? C.green : pct >= 50 ? C.orange : C.orange;
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
        <span style={{ fontSize: 10, color: C.textDim }}>Confianza de clasificación</span>
        <span style={{ fontSize: 11, fontWeight: 700, color }}>{pct}%</span>
      </div>
      <div style={{ height: 4, background: C.border, borderRadius: 2 }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 2, transition: "width 0.4s" }} />
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

interface Props {
  caseId:  string;
  baseScore: number;
}

export function ScoringDetailPanel({ caseId, baseScore }: Props) {
  const [detail, setDetail] = useState<ScoringDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.get<ScoringDetail>(`/api/incidents/${encodeURIComponent(caseId)}/scoring-detail`)
      .then(({ data }) => { if (!cancelled) { setDetail(data); setLoading(false); } })
      .catch((e) => {
        if (cancelled) return;
        const msg = (e?.response?.data?.error) ?? (e?.message) ?? "Error";
        setError(String(msg));
        setLoading(false);
      });
    return () => { cancelled = true; };
  }, [caseId]);

  if (loading) {
    return (
      <div style={{ padding: "16px 0", textAlign: "center", color: C.textDim, fontSize: 11 }}>
        Cargando análisis de scoring…
      </div>
    );
  }
  if (error || !detail) {
    return (
      <div style={{
        padding: "10px 12px", background: alpha(C.red, 6), border: `1px solid ${alpha(C.red, 19)}`,
        borderRadius: 8, fontSize: 11, color: C.red,
        display: "flex", alignItems: "center", gap: 6,
      }}>
        <AlertTriangle size={12} />
        {error ?? "No se pudo cargar el detalle de scoring."}
      </div>
    );
  }

  const { analystBrief, autoTaxonomy, bonusLog, rawData } = detail;
  const nistColors = NIST_COLOR[autoTaxonomy.nistCategory] ?? DEFAULT_NIST_COLOR;
  const bonusTotal = bonusLog.reduce((acc, e) => acc + (e.bonus_value ?? 0), 0);
  const multTotal  = bonusLog.reduce((acc, e) => acc * (e.multiplier ?? 1), 1);
  const finalScore = Math.min(200, Math.max(0, Math.round((baseScore + bonusTotal) * multTotal)));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>

      {/* ── 1. Analyst brief ─────────────────────────────────────────────────── */}
      <PanelSection label="Resumen para el analista" icon={BookOpen}>
        <p style={{ fontSize: 12, color: C.border, lineHeight: 1.65, margin: 0 }}>
          {analystBrief}
        </p>
      </PanelSection>

      {/* ── 2. Auto-taxonomy ─────────────────────────────────────────────────── */}
      <PanelSection label="Taxonomía auto-clasificada" icon={ShieldCheck}>
        {/* NIST category */}
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 10, color: C.textDim, marginBottom: 4, letterSpacing: "0.08em" }}>
            CATEGORÍA NIST SP 800-61
          </div>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            background: alpha(nistColors.fg, 9), border: `1px solid ${nistColors.border}`,
            borderRadius: 6, padding: "4px 10px",
          }}>
            <ShieldCheck size={11} color={nistColors.fg} />
            <span style={{ fontSize: 12, fontWeight: 700, color: nistColors.fg }}>
              {autoTaxonomy.nistLabel}
            </span>
            <span style={{ fontSize: 10, color: C.textDim }}>· {autoTaxonomy.nistCategory}</span>
          </div>
        </div>

        {/* Attack category */}
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 10, color: C.textDim, marginBottom: 4, letterSpacing: "0.08em" }}>
            TIPO DE ATAQUE
          </div>
          <div style={{ fontSize: 12, color: C.border, fontWeight: 600 }}>
            {autoTaxonomy.attackCategory}
          </div>
        </div>

        {/* Confidence */}
        <ConfidenceBar value={autoTaxonomy.confidence} />

        {/* Rationale */}
        {autoTaxonomy.rationale.length > 0 && (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 10, color: C.textDim, marginBottom: 4, letterSpacing: "0.08em" }}>
              EVIDENCIAS DE CLASIFICACIÓN
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              {autoTaxonomy.rationale.map((r, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <div style={{ width: 4, height: 4, borderRadius: "50%", background: C.cyan, flexShrink: 0 }} />
                  <span style={{ fontSize: 10, color: C.textDim }}>{r}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </PanelSection>

      {/* ── 3. Scoring process ───────────────────────────────────────────────── */}
      <PanelSection label="Proceso de scoring documentado" icon={Cpu}>
        {/* Score summary */}
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "6px 10px", background: C.bg, borderRadius: 6, marginBottom: 10,
        }}>
          <span style={{ fontSize: 11, color: C.textDim }}>Score base</span>
          <span style={{ fontFamily: "monospace", fontSize: 14, fontWeight: 700, color: C.border }}>{baseScore}</span>
        </div>

        {/* Bonus entries */}
        {bonusLog.length === 0 ? (
          <div style={{ fontSize: 11, color: C.textDim, textAlign: "center", padding: "8px 0" }}>
            Sin bonos adicionales registrados para este caso.
          </div>
        ) : (
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, letterSpacing: "0.08em" }}>
              BONOS APLICADOS ({bonusLog.length})
            </div>
            {bonusLog.map((e, i) => <BonusChip key={i} entry={e} />)}
          </div>
        )}

        {/* Final score */}
        {bonusLog.length > 0 && (
          <div style={{
            display: "flex", justifyContent: "space-between", alignItems: "center",
            padding: "8px 10px",
            background: finalScore >= 90 ? alpha(C.red, 8) : finalScore >= 70 ? alpha(C.orange, 8) : alpha(C.cyan, 8),
            border: `1px solid ${finalScore >= 90 ? alpha(C.red, 19) : finalScore >= 70 ? alpha(C.orange, 19) : alpha(C.cyan, 19)}`,
            borderRadius: 6, marginTop: 4,
          }}>
            <div>
              <div style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.08em" }}>SCORE FINAL (con bonos)</div>
              {bonusTotal !== 0 && (
                <div style={{ fontSize: 10, color: C.textDim, marginTop: 1 }}>
                  base {baseScore} {bonusTotal > 0 ? "+" : ""}{bonusTotal} pts
                  {multTotal !== 1 ? ` × ${multTotal.toFixed(2)}` : ""}
                </div>
              )}
            </div>
            <span style={{
              fontFamily: "monospace", fontSize: 20, fontWeight: 800,
              color: finalScore >= 90 ? C.red : finalScore >= 70 ? C.orange : C.cyan,
            }}>
              {finalScore}
            </span>
          </div>
        )}
      </PanelSection>

      {/* ── 4. Raw enrichment data ───────────────────────────────────────────── */}
      {rawData && Object.keys(rawData).length > 0 && (
        <PanelSection label="Datos de enriquecimiento (raw)" icon={Code2} defaultOpen={false}>
          <div style={{ marginBottom: 6 }}>
            {Object.entries(rawData).map(([k, v]) => (
              <div key={k} style={{
                display: "flex", justifyContent: "space-between", alignItems: "flex-start",
                padding: "3px 0", borderBottom: `1px solid ${C.border}`,
              }}>
                <span style={{ fontSize: 10, color: C.textDim, fontFamily: "monospace", flexShrink: 0, marginRight: 8 }}>{k}</span>
                <span style={{ fontSize: 10, color: C.textDim, fontFamily: "monospace", textAlign: "right", overflowWrap: "anywhere" }}>
                  {typeof v === "object" ? JSON.stringify(v) : String(v ?? "—")}
                </span>
              </div>
            ))}
          </div>

          {/* Full JSON toggle */}
          <button
            onClick={() => setShowRaw((v) => !v)}
            style={{
              display: "flex", alignItems: "center", gap: 5, marginTop: 6,
              background: "none", border: `1px solid ${C.border}`, borderRadius: 5,
              padding: "4px 9px", cursor: "pointer", color: C.textDim, fontSize: 10,
            }}
          >
            <FlaskConical size={10} />
            {showRaw ? "Ocultar JSON completo" : "Ver JSON completo"}
            <ExternalLink size={9} />
          </button>
          {showRaw && (
            <pre style={{
              marginTop: 8, padding: 10, background: C.bg,
              border: `1px solid ${C.border}`, borderRadius: 6,
              fontSize: 9, color: C.textDim, overflowX: "auto",
              maxHeight: 200, overflowY: "auto", lineHeight: 1.5,
            }}>
              {JSON.stringify(rawData, null, 2)}
            </pre>
          )}
        </PanelSection>
      )}
    </div>
  );
}
