/**
 * ProfileSelector.tsx
 * Gestor de perfiles de apertura de casos SOC.
 *
 * - Carga perfiles desde el servidor al montar (compartidos entre operadores).
 * - Sincroniza al servidor (Postgres) en cada cambio.
 * - Muestra la fórmula de scoring activa y sus umbrales de severidad.
 */

import { useEffect, useState } from "react";
import { Plus, Trash2, ToggleLeft, ToggleRight, RefreshCw, Info } from "lucide-react";
import {
  loadProfiles,
  saveProfiles,
  resetProfiles,
  loadProfilesFromServer,
  syncProfilesToServer,
  loadActiveFormula,
} from "./scoringProfiles";
import type { ScoringProfile, ActiveFormulaProfile } from "./scoringProfiles";
import type { Severity } from "./types";
import { C, alpha } from "@/lib/cm-theme";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"];

const SEV_COLOR: Record<string, string> = {
  CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.cyan,
  LOW: C.green, NEGLIGIBLE: C.textDim,
};

export function ProfileSelector() {
  const [profiles,       setProfiles]       = useState<ScoringProfile[]>(loadProfiles);
  const [activeFormula,  setActiveFormula]  = useState<ActiveFormulaProfile | null>(null);
  const [syncing,        setSyncing]        = useState(false);
  const [syncMsg,        setSyncMsg]        = useState<{ ok: boolean; text: string } | null>(null);
  const [loadingServer,  setLoadingServer]  = useState(true);

  // ── Carga inicial desde servidor ──────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;

    async function init() {
      setLoadingServer(true);
      const [serverProfiles, formula] = await Promise.all([
        loadProfilesFromServer(),
        loadActiveFormula(),
      ]);
      if (cancelled) return;
      if (serverProfiles.length) setProfiles(serverProfiles);
      setActiveFormula(formula);
      setLoadingServer(false);
    }

    void init();
    return () => { cancelled = true; };
  }, []);

  // ── Persistir: localStorage + servidor ───────────────────────────────────
  async function persist(updated: ScoringProfile[]) {
    setProfiles(updated);
    saveProfiles(updated);   // caché local inmediato

    setSyncing(true);
    setSyncMsg(null);
    const result = await syncProfilesToServer(updated);
    setSyncing(false);
    setSyncMsg(
      result.ok
        ? { ok: true,  text: `Sincronizados ${result.synced} perfil(es) al servidor` }
        : { ok: false, text: `Error al sincronizar: ${result.error}` },
    );
    setTimeout(() => setSyncMsg(null), 4000);
  }

  function toggle(id: string) {
    void persist(profiles.map((p) => p.id === id ? { ...p, enabled: !p.enabled } : p));
  }

  function remove(id: string) {
    void persist(profiles.filter((p) => p.id !== id));
  }

  function addBlank() {
    const blank: ScoringProfile = {
      id:          `profile-${Date.now()}`,
      name:        "Nuevo perfil",
      description: "",
      enabled:     false,
      severities:  ["HIGH"],
      minScore:    60,
      skipAdopted: true,
    };
    void persist([...profiles, blank]);
  }

  function update(id: string, field: keyof ScoringProfile, value: unknown) {
    void persist(profiles.map((p) => p.id === id ? { ...p, [field]: value } : p));
  }

  function toggleSeverity(id: string, sev: Severity) {
    const p = profiles.find((x) => x.id === id);
    if (!p) return;
    const sevs = p.severities.includes(sev)
      ? p.severities.filter((s) => s !== sev)
      : [...p.severities, sev];
    update(id, "severities", sevs);
  }

  async function handleReset() {
    const defaults = resetProfiles();
    await persist(defaults);
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div style={{ color: C.text, fontSize: 13 }}>

      {/* ── Fórmula de scoring activa ─────────────────────────────────────── */}
      {activeFormula && (
        <div style={{
          marginBottom: 16,
          padding: "10px 14px",
          background: C.bg,
          border: `1px solid ${C.border}`,
          borderRadius: 8,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
            <Info size={12} color={C.cyan} />
            <span style={{ fontSize: 11, color: C.cyan, fontWeight: 600, letterSpacing: "0.06em" }}>
              FÓRMULA DE SCORING ACTIVA
            </span>
            <span style={{
              marginLeft: "auto", fontSize: 10, color: C.textDim,
              padding: "1px 6px", borderRadius: 3, background: C.border,
            }}>
              {activeFormula.profileName}
            </span>
          </div>

          {/* Umbrales */}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {(
              [
                ["CRITICAL", activeFormula.thresholds.critical,  C.red],
                ["HIGH",     activeFormula.thresholds.high,      C.orange],
                ["MEDIUM",   activeFormula.thresholds.medium,    C.cyan],
                ["LOW",      activeFormula.thresholds.low,       C.green],
              ] as [string, number, string][]
            ).map(([label, thr, color]) => (
              <div key={label} style={{
                fontSize: 10, padding: "3px 8px", borderRadius: 4,
                background: alpha(color, 8), border: `1px solid ${alpha(color, 25)}`,
                color,
              }}>
                {label} ≥ {thr}
              </div>
            ))}
          </div>

          {/* Pesos */}
          <div style={{ marginTop: 6, fontSize: 10, color: C.textDim }}>
            Pesos: MITRE×{activeFormula.weights.wMitre} · Evidencia×{activeFormula.weights.wEvidence} ·
            Wazuh×{activeFormula.weights.wWazuh} · Contexto×{activeFormula.weights.wContext} ·
            MISP×{activeFormula.weights.wMisp}
            {activeFormula.appliedBy && activeFormula.appliedBy !== "system-default" && (
              <span style={{ marginLeft: 6 }}>· aplicado por {activeFormula.appliedBy}</span>
            )}
          </div>

          {/* Ayuda contextual */}
          <div style={{ marginTop: 8, fontSize: 10, color: C.textDim, lineHeight: 1.5 }}>
            Los perfiles de apertura abajo deben usar <strong style={{ color: C.text }}>minScore</strong> coherente con estos umbrales.
            Por ejemplo, para "HIGH" con la fórmula activa el score debe ser ≥ {activeFormula.thresholds.high}.
          </div>
        </div>
      )}

      {/* ── Cabecera perfiles ─────────────────────────────────────────────── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: C.textDim, fontSize: 11, letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Perfiles de apertura
          </span>
          {loadingServer && (
            <RefreshCw size={11} color={C.textDim} style={{ animation: "spin 1s linear infinite" }} />
          )}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {syncMsg && (
            <span style={{ fontSize: 11, color: syncMsg.ok ? C.green : C.red }}>
              {syncMsg.text}
            </span>
          )}
          {syncing && <RefreshCw size={11} color={C.cyan} style={{ animation: "spin 0.8s linear infinite" }} />}
          <button
            onClick={() => void handleReset()}
            style={{ fontSize: 11, color: C.textDim, background: "none", border: "none", cursor: "pointer" }}
          >
            Restablecer
          </button>
          <button
            onClick={addBlank}
            style={{
              display: "flex", alignItems: "center", gap: 4,
              fontSize: 12, color: C.cyan,
              background: alpha(C.cyan, 6), border: `1px solid ${alpha(C.cyan, 19)}`,
              borderRadius: 6, padding: "4px 10px", cursor: "pointer",
            }}
          >
            <Plus size={12} /> Añadir
          </button>
        </div>
      </div>

      {/* ── Lista de perfiles ─────────────────────────────────────────────── */}
      {profiles.map((p) => (
        <div
          key={p.id}
          style={{
            background: C.card,
            border: `1px solid ${p.enabled ? C.border : alpha(C.border, 50)}`,
            borderRadius: 8,
            padding: "12px 14px",
            marginBottom: 10,
            opacity: p.enabled ? 1 : 0.6,
          }}
        >
          {/* Nombre + toggle + eliminar */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => toggle(p.id)}
              title={p.enabled ? "Deshabilitar perfil" : "Habilitar perfil"}
              style={{ background: "none", border: "none", cursor: "pointer", padding: 0, color: p.enabled ? C.green : C.textDim }}
            >
              {p.enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
            </button>
            <input
              value={p.name}
              onChange={(e) => update(p.id, "name", e.target.value)}
              style={{
                flex: 1, background: "transparent", border: "none", outline: "none",
                color: C.text, fontWeight: 600, fontSize: 13,
              }}
            />
            <button
              onClick={() => remove(p.id)}
              title="Eliminar perfil"
              style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim }}
            >
              <Trash2 size={13} />
            </button>
          </div>

          {/* Descripción */}
          {p.description && (
            <div style={{ fontSize: 11, color: C.textDim, marginBottom: 8 }}>{p.description}</div>
          )}

          {/* Severidades */}
          <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: 8 }}>
            {SEVERITIES.map((sev) => {
              const active = p.severities.includes(sev);
              const color  = SEV_COLOR[sev] ?? C.cyan;
              // Mostrar si el minScore cubre esta severidad dado el umbral activo
              const formulaThreshold = activeFormula?.thresholds[sev.toLowerCase() as keyof typeof activeFormula.thresholds];
              const coherent = formulaThreshold == null || p.minScore <= formulaThreshold;
              return (
                <button
                  key={sev}
                  onClick={() => toggleSeverity(p.id, sev)}
                  title={
                    active && formulaThreshold != null && !coherent
                      ? `⚠ minScore (${p.minScore}) > umbral ${sev} (${formulaThreshold}) — ningún caso de esta severidad pasará`
                      : undefined
                  }
                  style={{
                    fontSize: 10, padding: "2px 8px", borderRadius: 4, cursor: "pointer",
                    background: active ? alpha(color, 15) : "transparent",
                    border:     `1px solid ${active ? alpha(color, 38) : C.border}`,
                    color:      active ? color : C.textDim,
                    position:   "relative",
                  }}
                >
                  {sev}
                  {active && formulaThreshold != null && !coherent && (
                    <span style={{ marginLeft: 4, color: C.orange }}>⚠</span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Score mínimo */}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ color: C.textDim, fontSize: 11 }}>Score mín.</span>
            <input
              type="number"
              min={0}
              max={100}
              value={p.minScore}
              onChange={(e) => update(p.id, "minScore", Number(e.target.value))}
              style={{
                width: 56, background: C.bg, border: `1px solid ${C.border}`,
                borderRadius: 4, padding: "2px 6px", color: C.text, fontSize: 12,
              }}
            />
            {/* Indicador de coherencia con fórmula activa */}
            {activeFormula && p.severities.length > 0 && (() => {
              const lowestSevThr = Math.min(
                ...p.severities.map((s) => activeFormula.thresholds[s.toLowerCase() as keyof typeof activeFormula.thresholds] ?? 100),
              );
              if (p.minScore > lowestSevThr) {
                return (
                  <span style={{ fontSize: 10, color: C.orange }}>
                    ⚠ minScore &gt; umbral {p.severities.join("/")} ({lowestSevThr}) — casos no pasarán
                  </span>
                );
              }
              return (
                <span style={{ fontSize: 10, color: C.green }}>
                  ✓ coherente con fórmula activa
                </span>
              );
            })()}
          </div>
        </div>
      ))}

      {profiles.length === 0 && (
        <div style={{ color: C.textDim, textAlign: "center", padding: "24px 0" }}>
          Sin perfiles. Haz clic en "Añadir" para crear uno.
        </div>
      )}

      <div style={{ marginTop: 8, fontSize: 10, color: C.textDim }}>
        Los perfiles se sincronizan automáticamente al servidor y son compartidos entre todos los operadores.
        El backend valida estos criterios al abrir un caso manualmente.
      </div>
    </div>
  );
}
