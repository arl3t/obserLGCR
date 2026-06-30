/**
 * scoringProfiles.ts
 * Perfiles de apertura de casos SOC.
 *
 * Persistencia dual:
 *  - localStorage (lh_scoring_profiles_v1): caché local para acceso síncrono
 *  - Postgres vía /api/scoring-profiles/opening: fuente de verdad compartida
 *
 * La apertura de un caso se VALIDA también en el backend (open-from-flow),
 * por lo que estos perfiles actúan como pre-filtro de UX coherente con el servidor.
 */

import type { Severity, SocCase } from "./types";

const STORAGE_KEY = "lh_scoring_profiles_v1";

export interface ScoringProfile {
  id:          string;
  name:        string;
  description: string;
  enabled:     boolean;
  /** Severidades que disparan la apertura automática */
  severities:  Severity[];
  /** Puntuación mínima para abrir */
  minScore:    number;
  /** Si el caso ya tiene adopted_at, no aplica */
  skipAdopted: boolean;
}

export interface ActiveFormulaProfile {
  profileId:   string;
  profileName: string;
  appliedBy:   string;
  appliedAt:   string | null;
  thresholds:  { critical: number; high: number; medium: number; low: number };
  weights:     { wMitre: number; wEvidence: number; wWazuh: number; wContext: number; wMisp: number };
}

const DEFAULT_PROFILES: ScoringProfile[] = [
  {
    id:          "critical-auto",
    name:        "CRITICAL automático",
    description: "Abre todos los casos CRITICAL con score ≥ 70",
    enabled:     true,
    severities:  ["CRITICAL"],
    minScore:    70,
    skipAdopted: true,
  },
  {
    id:          "high-urlhaus",
    name:        "HIGH con feeds activos",
    description: "Abre HIGH si está en URLhaus u OpenPhish",
    enabled:     true,
    severities:  ["HIGH"],
    minScore:    50,
    skipAdopted: true,
  },
];

// ── localStorage (caché local) ────────────────────────────────────────────────

export function loadProfiles(): ScoringProfile[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_PROFILES;
    const parsed = JSON.parse(raw) as ScoringProfile[];
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : DEFAULT_PROFILES;
  } catch {
    return DEFAULT_PROFILES;
  }
}

export function saveProfiles(profiles: ScoringProfile[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(profiles));
}

export function resetProfiles(): ScoringProfile[] {
  localStorage.removeItem(STORAGE_KEY);
  return DEFAULT_PROFILES;
}

// ── Lógica de evaluación ──────────────────────────────────────────────────────

/**
 * Devuelve los perfiles que harían que un caso se abra automáticamente.
 * Si el array está vacío, el caso no cumple ningún perfil activo.
 */
export function getTriggeringProfiles(
  c: SocCase,
  profiles = loadProfiles(),
): ScoringProfile[] {
  if (c.adoptedAt) return [];
  return profiles.filter(
    (p) =>
      p.enabled &&
      p.severities.includes(c.severity) &&
      c.score >= p.minScore &&
      !(p.skipAdopted && c.adoptedAt),
  );
}

/**
 * Retorna true si algún perfil activo indica que este caso debe mostrarse
 * en el modal de adopción obligatoria.
 */
export function shouldOpenCase(c: SocCase, profiles = loadProfiles()): boolean {
  return getTriggeringProfiles(c, profiles).length > 0;
}

// ── API server (Postgres shared) ──────────────────────────────────────────────

/**
 * Carga perfiles de apertura desde el servidor (compartidos entre operadores).
 * Actualiza el caché local si tiene éxito.
 */
export async function loadProfilesFromServer(): Promise<ScoringProfile[]> {
  try {
    const res = await fetch("/api/scoring-profiles/opening");
    if (!res.ok) return loadProfiles();
    const data = await res.json() as { profiles: ScoringProfile[] };
    const profiles = data.profiles;
    if (Array.isArray(profiles) && profiles.length > 0) {
      saveProfiles(profiles);   // actualizar caché local
      return profiles;
    }
    return loadProfiles();
  } catch {
    return loadProfiles();
  }
}

/**
 * Sincroniza los perfiles de apertura al servidor (Postgres).
 * Los cambios quedan disponibles para todos los operadores.
 */
export async function syncProfilesToServer(
  profiles: ScoringProfile[],
  updatedBy?: string,
): Promise<{ ok: boolean; synced?: number; error?: string }> {
  try {
    const res = await fetch("/api/scoring-profiles/sync", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ profiles, updatedBy: updatedBy ?? "dashboard" }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as { error?: string };
      return { ok: false, error: err.error ?? `HTTP ${res.status}` };
    }
    const data = await res.json() as { synced: number };
    saveProfiles(profiles);   // actualizar caché local también
    return { ok: true, synced: data.synced };
  } catch (err) {
    return { ok: false, error: String((err as Error).message ?? err) };
  }
}

/**
 * Carga la fórmula de scoring activa desde el servidor.
 * Incluye umbrales para mostrar contexto en el ProfileSelector.
 */
export async function loadActiveFormula(): Promise<ActiveFormulaProfile | null> {
  try {
    const res = await fetch("/api/scoring-profiles/active-formula");
    if (!res.ok) return null;
    return await res.json() as ActiveFormulaProfile;
  } catch {
    return null;
  }
}
